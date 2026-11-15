"""Real OAuth/MCP and checkpoint process; all EMS responses are synthetic."""
import json
import os
from pathlib import Path
import subprocess
import ssl
import sys

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.ems_tag_authority import EmsTagCreateAuthority
from fortipam_mcp.ems_tag_mcp_action import EmsTagMcpAction, EmsTagPreparedContext
from fortipam_mcp.ems_tag_original_binding import load_original_binding, load_original_fpa_binding, retain_original_binding
from fortipam_mcp.ems_tag_recovery_authority import EmsTagRecoveryAuthority
from fortipam_mcp.ems_tag_recovery_contract import EmsTagOwnedRecoveryScope
from fortipam_mcp.ems_tag_sources import METADATA_PATH
from fortipam_mcp.ems_tag_fpa_sources import EmsTagFpaSources, EmsTagFpaAdmission
from fortipam_mcp.http_server import create_http_app, HttpConfigurationError, HttpServerSettings
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.planning_checkpoint_sidecar import UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings
from fortipam_mcp.secret_bulk_import_runtime import _M4PlanningCheckpoint
from test_ems_tag_contract import full_scope
from test_ems_tag_create_m4_adapter import make as create_components
from test_ems_tag_http_transport import make as source_transport, reply
from test_http_server import (_authorize_and_login, _bearer_environment, _register_public_client,
    _request_headers, _v4_controlled_environment, V4_FOLDER_ACTION_FEATURE_ENV)
from test_planning_checkpoint_sidecar import checkpoint_paths, _start_sidecar, _stop_sidecar
from test_ems_tag_fpa_sources import Peer as FpaPeer, OWNER as FPA_OWNER, FPA_SERIAL
from test_ems_tag_fpa_mapping import row as fpa_row
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

LAB = dict(environment_ref="ems-disposable-lab", scope_ref="original-ems-tag", audience_ref="private-ems-client")
CREATE_REF = "ems-tag-mcp-create-store"
RECOVER_REF = "ems-tag-mcp-recover-store"
AUTHORITY_REF = "ems-tag-test-checkpoint"


def checkpoint(socket, store_ref):
    return _M4PlanningCheckpoint(UnixPlanningCheckpointClient(
        UnixPlanningCheckpointClientSettings(socket, AUTHORITY_REF)), store_ref)


def headers(client, scope):
    client_id = _register_public_client(client, scope)
    code, verifier = _authorize_and_login(client, client_id, scope)
    response = client.post("/fpamcp/oauth/token", data={"grant_type": "authorization_code", "client_id": client_id,
        "code": code, "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
        "resource": "https://mcp.example.com/fpamcp"})
    assert response.status_code == 200
    return {**_request_headers(response.json()["access_token"]), "host": "mcp.example.com"}


def rpc(client, token, method, params=None):
    response = client.post("/fpamcp", headers=token, json={"jsonrpc": "2.0", "id": "ems-test",
        "method": method, **({"params": params} if params is not None else {})})
    assert response.status_code == 200
    return response.json()["result"]


def call(client, token, phase, operation, **arguments):
    return rpc(client, token, "tools/call", {"name": f"{operation}_v4_ems_original_tag_{phase}_748", "arguments": arguments})


def data(result):
    assert not result.get("isError"), result
    return result["structuredContent"]


def fpa_admission(transport, source, channel, monkeypatch, *, original=None, packet=None):
    monkeypatch.setattr("fortipam_mcp.owner_session_metadata._ssl_context", lambda config: ssl.create_default_context())
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "unused-bearer", 5, str(transport._config.ca_file))
    peer = FpaPeer(config, transport._config.hostname)
    handle = peer.handle
    def response(request):
        peer.rows = [fpa_row()]
        after_delete = channel.scope.catalog.count != 2
        pending = after_delete and getattr(peer, "pending_post_delete_windows", 0) > 0
        if not after_delete or pending:
            peer.rows.append(fpa_row(source._draft._name))
        if after_delete and getattr(peer, "post_delete_fault", None):
            peer.fault = peer.post_delete_fault
        result = handle(request)
        if pending and request.url.path == "/api/v2/cmdb/firewall/address" and peer.mapping_gets % 2 == 0:
            peer.pending_post_delete_windows -= 1
        return result
    monkeypatch.setattr(peer, "handle", response)
    fpa = EmsTagFpaSources(transport=transport, sources=source, owner_factory=peer.owner, config=config,
        owner_name=FPA_OWNER, expected_serial=FPA_SERIAL, source_key=b"f" * 32)
    fpa.observe()
    admission = EmsTagFpaAdmission(fpa, phase="create" if original is None else "recover",
        original=original, original_binding_file=packet)
    return admission, peer


def create_action(root, monkeypatch, *, real_checkpoint=None, enabled=True, fault=None, with_fpa=True):
    root.mkdir(mode=0o700)
    trace = {}
    def prepare(principal):
        real_ssl = ssl.create_default_context
        try:
            adapter, _, _, old_custody, transport, source, channel, connections, writes, _, old_authority = create_components(
                root, monkeypatch, fault=fault)
        finally:
            monkeypatch.setattr(ssl, "create_default_context", real_ssl)
        adapter.close(); old_authority.close()
        store = old_custody._store
        if real_checkpoint is not None:
            store = PersistentM4ExecutionStateStore(store._path, store._key_path,
                monotonic_checkpoint=real_checkpoint, checkpoint_store_ref=CREATE_REF)
        admission, fpa_peer = fpa_admission(transport, source, channel, monkeypatch) if with_fpa else (None, None)
        authority = EmsTagCreateAuthority(source, authority_key=b"k" * 32, execution_enabled=True,
            requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest,
            fpa_admission=admission, **LAB)
        context = EmsTagPreparedContext(authority=authority, store=store, custody_directory=root / "custody",
            witness_key_file=root / "custody.key", original_binding_file=root / "original.binding.json")
        trace.update(context=context, writes=writes, connections=connections, channel=channel,
            principal=principal, fpa_peer=fpa_peer)
        return context
    return EmsTagMcpAction(phase="create", prepare=prepare, execution_enabled=enabled), trace


def recover_action(root, original_root, socket, monkeypatch):
    root.mkdir(mode=0o700)
    trace = {}
    def prepare(principal):
        original = load_original_binding(original_root / "original.binding.json", original_root / "custody.key",
            monotonic_checkpoint=checkpoint(socket, CREATE_REF), checkpoint_store_ref=CREATE_REF)
        real_ssl = ssl.create_default_context
        try:
            transport, channel, connections, _, _, _ = source_transport(original_root, monkeypatch)
        finally:
            monkeypatch.setattr(ssl, "create_default_context", real_ssl)
        channel.session_value = "independent-process-session"
        channel.scope = full_scope(add=True)
        transport.authenticate()
        source = transport.make_sources(original._draft, source_key=b"s" * 32)
        source.observe()
        scope = EmsTagOwnedRecoveryScope(transport=transport, sources=source, original=original,
            requester_digest=principal.requester.digest, caller_transport_digest=principal.transport_namespace_digest)
        admission, fpa_peer = fpa_admission(transport, source, channel, monkeypatch,
            original=original, packet=original_root / "original.binding.json")
        authority = EmsTagRecoveryAuthority(scope, authority_key=b"r" * 32, execution_enabled=True,
            fpa_admission=admission, **LAB)
        for name, key in (("execution.key", b"n" * 32), ("custody.key", b"w" * 32)):
            (root / name).write_bytes(key); (root / name).chmod(0o600)
        (root / "custody").mkdir(mode=0o700)
        store = PersistentM4ExecutionStateStore(root / "execution.sqlite", root / "execution.key",
            monotonic_checkpoint=checkpoint(socket, RECOVER_REF), checkpoint_store_ref=RECOVER_REF)
        connect = transport._connect
        writes = []
        def connected():
            connection = connect()
            receive = connection.getresponse
            def response():
                if connection.path != "/api/v1/tags/zero_trust/delete": return receive()
                assert json.loads(connection.body) == {"ids": [101]}
                writes.append(1); channel.scope = full_scope()
                return reply({"result": {"retval": 1, "message": "Deleted"}})
            connection.getresponse = response
            return connection
        monkeypatch.setattr(transport, "_connect", connected)
        trace.update(scope=scope, store=store, writes=writes, connections=connections, principal=principal, fpa_peer=fpa_peer)
        return EmsTagPreparedContext(authority=authority, store=store, custody_directory=root / "custody",
            witness_key_file=root / "custody.key")
    return EmsTagMcpAction(phase="recover", prepare=prepare, execution_enabled=True), trace


def test_controlled_di_default_closed_scopes_refs_and_original_binding(tmp_path, monkeypatch):
    environment = _v4_controlled_environment(tmp_path)
    environment[V4_FOLDER_ACTION_FEATURE_ENV] = "false"
    settings = HttpServerSettings.from_environment(environment)
    action, trace = create_action(tmp_path / "create", monkeypatch, enabled=False)
    with pytest.raises(HttpConfigurationError, match="Original EMS Tag requires"):
        create_http_app(HttpServerSettings.from_environment(_bearer_environment()), v4_ems_tag_candidate_action=action)
    with TestClient(create_http_app(settings), base_url="https://mcp.example.com") as client:
        token = headers(client, "fortipam:read fortipam:plan")
        ordinary = rpc(client, token, "tools/list")["tools"]
        assert not any("ems_original_tag" in tool["name"] for tool in ordinary)
    try:
        with TestClient(create_http_app(settings, v4_ems_tag_candidate_action=action), base_url="https://mcp.example.com") as client:
            plan = headers(client, "fortipam:read fortipam:plan")
            operate = headers(client, "fortipam:read fortipam:plan fortipam:operate")
            tools = [tool for tool in rpc(client, plan, "tools/list")["tools"] if "ems_original_tag" in tool["name"]]
            assert len(tools) == 3
            assert all(tool["inputSchema"]["additionalProperties"] is False for tool in tools)
            assert [set(tool["inputSchema"].get("properties", {})) for tool in tools] == [set(), {"preview_ref"}, {"authorization_ref"}]
            assert call(client, plan, "create", "preview", requester_digest="a" * 64)["isError"]
            assert not trace
            preview = data(call(client, operate, "create", "preview"))
            assert call(client, plan, "create", "authorize", preview_ref=preview["preview_ref"])["isError"]
            assert call(client, operate, "create", "authorize", preview_ref=preview["preview_ref"])["isError"]
            assert not trace["writes"] and trace["context"].store.claim_count == 0
            assert not (tmp_path / "create" / "original.binding.json").exists()
    finally:
        action.close()


def test_request_loss_during_final_source_refuses_before_original_send(tmp_path, monkeypatch):
    environment = _v4_controlled_environment(tmp_path)
    environment[V4_FOLDER_ACTION_FEATURE_ENV] = "false"
    action, trace = create_action(tmp_path / "create", monkeypatch)
    try:
        with TestClient(create_http_app(HttpServerSettings.from_environment(environment),
                v4_ems_tag_candidate_action=action), base_url="https://mcp.example.com") as client:
            operator = headers(client, "fortipam:read fortipam:plan fortipam:operate")
            preview = data(call(client, operator, "create", "preview"))
            auth = data(call(client, operator, "create", "authorize", preview_ref=preview["preview_ref"]))
        principal = trace["principal"]
        valid = [True]; metadata = [0]
        original_get = trace["channel"].get
        def get(path):
            value = original_get(path)
            if path == METADATA_PATH:
                metadata[0] += 1
                if metadata[0] == 4: valid[0] = False
            return value
        monkeypatch.setattr(trace["channel"], "get", get)
        def current():
            if not valid[0]: raise ValueError
            return principal
        result = action.call("execute", principal, auth["authorization_ref"], current_principal=current)
        assert metadata[0] == 4 and result["verification"] != "verified" and result["session_closed"]
        assert not trace["writes"] and trace["context"].store.claim_count == 1
        assert not (trace["context"].directory / "send.claim.json").exists()
    finally:
        action.close()


def test_no_fpa_source_can_preview_but_cannot_issue_an_ems_write(tmp_path, monkeypatch):
    environment = _v4_controlled_environment(tmp_path)
    environment[V4_FOLDER_ACTION_FEATURE_ENV] = "false"
    action, trace = create_action(tmp_path / "create", monkeypatch, with_fpa=False)
    try:
        with TestClient(create_http_app(HttpServerSettings.from_environment(environment),
                v4_ems_tag_candidate_action=action), base_url="https://mcp.example.com") as client:
            operator = headers(client, "fortipam:read fortipam:plan fortipam:operate")
            preview = data(call(client, operator, "create", "preview"))
            assert preview["Expected State"]["fortipam_tag_admission"] == "unassessed"
            assert call(client, operator, "create", "authorize", preview_ref=preview["preview_ref"])["isError"]
            assert trace["context"].store.claim_count == 0 and not trace["writes"]
    finally:
        action.close()


@pytest.mark.parametrize("fault", ["mapping_after", "usage", "post_create_connector_counter"])
def test_fpa_prewrite_or_postcondition_failure_does_not_grant_original_recovery(tmp_path, monkeypatch, fault):
    environment = _v4_controlled_environment(tmp_path)
    environment[V4_FOLDER_ACTION_FEATURE_ENV] = "false"
    root = tmp_path / "create"
    action, trace = create_action(root, monkeypatch)
    try:
        with TestClient(create_http_app(HttpServerSettings.from_environment(environment),
                v4_ems_tag_candidate_action=action), base_url="https://mcp.example.com") as client:
            operator = headers(client, "fortipam:read fortipam:plan fortipam:operate")
            preview = data(call(client, operator, "create", "preview"))
            auth = data(call(client, operator, "create", "authorize", preview_ref=preview["preview_ref"]))
            peer = trace["fpa_peer"]
            if fault == "post_create_connector_counter":
                handle = peer.handle
                def drift_after_create(request):
                    if trace["channel"].scope.catalog.count == 2 and request.url.path == "/api/v2/cmdb/firewall/address":
                        peer.connector_references = 1
                    return handle(request)
                monkeypatch.setattr(peer, "handle", drift_after_create)
            else:
                peer.fault = fault
            result = data(call(client, operator, "create", "execute", authorization_ref=auth["authorization_ref"]))
            assert result["verification"] != "verified" and result["fortipam_tag_admission"] == "unverified"
            assert len(trace["writes"]) == (0 if fault == "mapping_after" else 1)
            if fault != "mapping_after":
                assert result["verification"] == "unknown"
                failures = list(root.glob("execution.sqlite.ems-create-failure.*.json"))
                assert len(failures) == 1
                failure = json.loads(failures[0].read_bytes())
                assert failure["stage"] == "fpa_postcondition"
                assert failure["fpa_source_stage"] == ("candidate_usage" if fault == "usage" else "connectors_after")
                assert failure["fpa_observation_completed"] is False
                assert failure["fpa_connector_configuration_unchanged"] is (True if fault == "post_create_connector_counter" else None)
                assert failure["fpa_connector_counter_unchanged"] is (False if fault == "post_create_connector_counter" else None)
            count = len(trace["connections"])
            assert data(call(client, operator, "create", "execute", authorization_ref=auth["authorization_ref"]))["idempotent_replay"]
            assert len(trace["connections"]) == count
        store = trace["context"].store
        with pytest.raises(ValueError):
            load_original_binding(root / "original.binding.json", root / "custody.key",
                monotonic_checkpoint=store._monotonic_checkpoint, checkpoint_store_ref=store._checkpoint_store_ref)
    finally:
        action.close()


def test_legacy_original_packet_reopens_readonly_but_cannot_supply_fpa_recovery_scope(tmp_path, monkeypatch):
    adapter, kernel, issued, custody, transport, source, _, _, _, _, authority = create_components(tmp_path, monkeypatch)
    packet = tmp_path / "original.binding.json"
    retain_original_binding(packet, custody)
    assert kernel.execute(issued.plan, issued.authorization).verification == "verified"
    assert transport.close().next_session_check_401
    adapter.close(); source.close(); authority.close()
    original = load_original_binding(packet, custody._key_file,
        monotonic_checkpoint=custody._store._monotonic_checkpoint,
        checkpoint_store_ref=custody._store._checkpoint_store_ref)
    with pytest.raises(ValueError): load_original_fpa_binding(packet, custody._key_file, original=original)


@pytest.mark.parametrize("propagation", ["settles", "pending", "expiry", "usage"])
def test_recovery_waits_only_for_unused_pending_mappings_without_replaying_delete(tmp_path, monkeypatch, propagation):
    from test_m4_execution_store import _ExternalM4Checkpoint
    checkpoints = {ref: _ExternalM4Checkpoint(ref) for ref in (CREATE_REF, RECOVER_REF)}
    monkeypatch.setattr(sys.modules[__name__], "checkpoint", lambda socket, store_ref: checkpoints[store_ref])
    environment = _v4_controlled_environment(tmp_path)
    environment[V4_FOLDER_ACTION_FEATURE_ENV] = "false"
    settings = HttpServerSettings.from_environment(environment)
    original_root = tmp_path / "create"
    creator, _ = create_action(original_root, monkeypatch, real_checkpoint=checkpoints[CREATE_REF])
    try:
        with TestClient(create_http_app(settings, v4_ems_tag_candidate_action=creator), base_url="https://mcp.example.com") as client:
            operator = headers(client, "fortipam:read fortipam:plan fortipam:operate")
            preview = data(call(client, operator, "create", "preview"))
            auth = data(call(client, operator, "create", "authorize", preview_ref=preview["preview_ref"]))
            assert data(call(client, operator, "create", "execute", authorization_ref=auth["authorization_ref"]))["verification"] == "verified"
    finally:
        creator.close()
    original_files = {path: path.read_bytes() for path in (original_root / "custody").iterdir()}
    original_files[original_root / "execution.sqlite"] = (original_root / "execution.sqlite").read_bytes()
    action, trace = recover_action(tmp_path / "recover", original_root, None, monkeypatch)
    waits = []
    def wait(seconds):
        waits.append(seconds)
        if propagation == "expiry":
            action._context.authority._clock = lambda: action._issued.authorization.expires_at
    monkeypatch.setattr("fortipam_mcp.ems_tag_recovery_m4_adapter._wait_for_fpa", wait)
    try:
        with TestClient(create_http_app(settings, v4_ems_tag_candidate_action=action), base_url="https://mcp.example.com") as client:
            operator = headers(client, "fortipam:read fortipam:plan fortipam:operate")
            preview = data(call(client, operator, "recover", "preview"))
            auth = data(call(client, operator, "recover", "authorize", preview_ref=preview["preview_ref"]))
            peer = trace["fpa_peer"]
            peer.pending_post_delete_windows = 2 if propagation == "settles" else 99
            if propagation == "usage": peer.post_delete_fault = "usage"
            result = data(call(client, operator, "recover", "execute", authorization_ref=auth["authorization_ref"]))
            assert len(trace["writes"]) == 1 and trace["store"].claim_count == 1
            assert result["session_closed"] and all(owner.logout_verified for owner in peer.sessions)
            if propagation == "settles":
                assert result["verification"] == "verified" and waits == [5, 5]
            else:
                assert result["verification"] == "unknown" and result["outcome"] == "reconciliation_required"
                assert len(waits) == {"pending": 5, "expiry": 1, "usage": 0}[propagation]
                failure = json.loads((tmp_path / "recover/custody/recover.failure.json").read_bytes())
                assert failure["stage"] == ("fpa_postcondition" if propagation == "usage" else "fpa_sync_pending")
                assert failure["request_replayable"] is False and failure["original_ack_attempt"]["reply_complete"]
            connections = len(trace["connections"])
            before = {path: path.read_bytes() for path in (tmp_path / "recover/custody").iterdir()}
            assert data(call(client, operator, "recover", "execute", authorization_ref=auth["authorization_ref"]))["idempotent_replay"]
            assert len(trace["writes"]) == 1 and len(trace["connections"]) == connections
            assert all(path.read_bytes() == raw for path, raw in before.items())
        assert all(path.read_bytes() == raw for path, raw in original_files.items())
    finally:
        action.close()


@pytest.mark.parametrize("fault", [None, "partial_frame"])
def test_real_checkpoint_oauth_create_and_independent_process_recovery(tmp_path, monkeypatch, checkpoint_paths, fault):
    database, key, socket = checkpoint_paths
    key.write_bytes(b"z" * 32)
    environment = {"PATH": os.defpath, "FORTIPAM_MCP_V4_CHECKPOINT_DATABASE": str(database),
        "FORTIPAM_MCP_V4_CHECKPOINT_HMAC_KEY_FILE": str(key), "FORTIPAM_MCP_V4_CHECKPOINT_AUTHORITY_REF": AUTHORITY_REF,
        "FORTIPAM_MCP_V4_CHECKPOINT_SOCKET": str(socket), "PYTHONPATH": "src:tests:."}
    process = _start_sidecar(environment, socket)
    action = None
    try:
        auth_environment = _v4_controlled_environment(tmp_path)
        auth_environment[V4_FOLDER_ACTION_FEATURE_ENV] = "false"
        settings = HttpServerSettings.from_environment(auth_environment)
        root = tmp_path / "create"
        action, trace = create_action(root, monkeypatch, real_checkpoint=checkpoint(socket, CREATE_REF), fault=fault)
        with TestClient(create_http_app(settings, v4_ems_tag_candidate_action=action), base_url="https://mcp.example.com") as client:
            operator = headers(client, "fortipam:read fortipam:plan fortipam:operate")
            other_client = headers(client, "fortipam:read fortipam:plan fortipam:operate")
            preview = data(call(client, operator, "create", "preview"))
            refreshed = data(call(client, operator, "create", "preview"))
            assert refreshed["preview_ref"] != preview["preview_ref"]
            assert call(client, operator, "create", "authorize", preview_ref=preview["preview_ref"])["isError"]
            preview = refreshed
            assert call(client, other_client, "create", "authorize", preview_ref=preview["preview_ref"])["isError"]
            auth = data(call(client, operator, "create", "authorize", preview_ref=preview["preview_ref"]))
            assert call(client, other_client, "create", "execute", authorization_ref=auth["authorization_ref"])["isError"]
            result = data(call(client, operator, "create", "execute", authorization_ref=auth["authorization_ref"]))
            assert result["session_closed"] and result["verification"] == ("verified" if fault is None else "unknown")
            before = len(trace["connections"])
            assert data(call(client, operator, "create", "execute", authorization_ref=auth["authorization_ref"]))["idempotent_replay"]
            assert len(trace["connections"]) == before and len(trace["writes"]) == 1
        original_bytes = {path: path.read_bytes() for path in (root / "custody").iterdir()}
        original_bytes[root / "execution.sqlite"] = (root / "execution.sqlite").read_bytes()
        original_bytes[root / "original.binding.json"] = (root / "original.binding.json").read_bytes()
        if fault:
            with pytest.raises(ValueError, match="original EMS binding"):
                load_original_binding(root / "original.binding.json", root / "custody.key",
                    monotonic_checkpoint=checkpoint(socket, CREATE_REF), checkpoint_store_ref=CREATE_REF)
            return
        original = load_original_binding(root / "original.binding.json", root / "custody.key",
            monotonic_checkpoint=checkpoint(socket, CREATE_REF), checkpoint_store_ref=CREATE_REF)
        packet = json.loads((root / "original.binding.json").read_bytes())
        assert packet["value"]["contract"] == "ems-tag-original-recovery-input-v2"
        assert set(packet["value"]["fpa_binding"]) == {"source_context_digest", "baseline_digest", "source_key_digest"}
        assert original._store._read_only and "sessionid" not in json.dumps(packet)
        env_file = tmp_path / "synthetic-http-environment.json"
        env_file.write_text(json.dumps(auth_environment)); env_file.chmod(0o600)
        proof = tmp_path / "child-proof.json"
        script = """
import json,sys
from pathlib import Path
import pytest
from test_ems_tag_mcp_oauth import run_child_recovery
run_child_recovery(*(Path(value) for value in sys.argv[1:]))
"""
        child = subprocess.run([sys.executable, "-c", script, str(tmp_path / "recovery"), str(root), str(socket), str(env_file), str(proof)],
            env={"PATH": os.defpath, "PYTHONPATH": "src:tests:."}, capture_output=True, timeout=35)
        assert child.returncode == 0, child.stderr.decode()
        assert json.loads(proof.read_bytes()) == {"verified": True, "same_human": True, "different_transport": True, "writes": 1}
        assert all(path.read_bytes() == raw for path, raw in original_bytes.items())
        copied = root / "copied.binding.json"; copied.write_bytes((root / "original.binding.json").read_bytes()); copied.chmod(0o600)
        with pytest.raises(ValueError):
            load_original_binding(copied, root / "custody.key", monotonic_checkpoint=checkpoint(socket, CREATE_REF), checkpoint_store_ref=CREATE_REF)
        packet["value"]["fpa_binding"]["baseline_digest"] = "0" * 64
        (root / "original.binding.json").write_text(json.dumps(packet))
        with pytest.raises(ValueError):
            load_original_fpa_binding(root / "original.binding.json", root / "custody.key", original=original)
    finally:
        if action is not None: action.close()
        _stop_sidecar(process, socket)


def run_child_recovery(root, original_root, socket, env_file, proof):
    with pytest.MonkeyPatch.context() as monkeypatch:
        action, trace = recover_action(root, original_root, socket, monkeypatch)
        settings = HttpServerSettings.from_environment(json.loads(env_file.read_bytes()))
        try:
            with TestClient(create_http_app(settings, v4_ems_tag_candidate_action=action), base_url="https://mcp.example.com") as client:
                operator = headers(client, "fortipam:read fortipam:plan fortipam:operate")
                preview = data(call(client, operator, "recover", "preview"))
                auth = data(call(client, operator, "recover", "authorize", preview_ref=preview["preview_ref"]))
                result = data(call(client, operator, "recover", "execute", authorization_ref=auth["authorization_ref"]))
                assert result["session_closed"] and result["fortipam_tag_admission"] == "verified"
                scope = trace["scope"]
                proof.write_text(json.dumps({"verified": result["verification"] == "verified",
                    "same_human": trace["principal"].requester.digest == scope._original._plan.requester_digest,
                    "different_transport": trace["principal"].transport_namespace_digest != scope._original._actor_binding.caller_transport_digest,
                    "writes": len(trace["writes"])}))
        finally:
            action.close()
