"""Real persistent M4 and native transport composition with synthetic SSH I/O."""
import asyncio
import hashlib
import os
from types import SimpleNamespace
import time

import pytest

from fortipam_mcp import ztna_wad_debug_ssh_transport as native
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.ztna_wad_debug_m4_action import ProtectedBuild29WadDebugM4Action, WadDebugM4Error
from test_v4_m3 import _requester


def make(tmp_path, monkeypatch, *, fault=None, enabled=True):
    original_sleep = asyncio.sleep
    tmp_path.chmod(0o700)
    pin = tmp_path / "known-hosts"
    pin.write_text("synthetic host pin\n"); pin.chmod(0o600)
    config = native.ZtnaWadDebugSshTransportConfig("fpa.example", 22, "operator",
        "synthetic-password", pin, 20, 10)
    serial = b"unit-debug-appliance"
    transport = native.FortiPamZtnaWadDebugSshTransport(config,
        build29_serial_digest=hashlib.sha256(serial).hexdigest())
    peer = SimpleNamespace(commands=[], connections=0, disconnects=0, closes=0,
        enabled=False, now=[1000])

    class Connection:
        async def __aenter__(self):
            peer.connections += 1
            if peer.connections == 4 and fault == "expiry-before-enable": peer.now[0] += 61
            if peer.connections == 5 and fault == "postcondition-drift": peer.enabled = True
            return self

        async def __aexit__(self, *args):
            peer.disconnects += 1

    async def open_cli(connection):
        return peer, b"synthetic #", time.monotonic() + 20

    async def send(process, command, prompt, deadline):
        assert process is peer and deadline > time.monotonic()
        peer.commands.append(command)
        if command == native._source_reader._SERIAL:
            lines = [b"Serial-Number: " + serial]
        elif command == native._source_reader._VERSION:
            lines = [b"Version: FortiPAM-VM v7.0.0,build0029, synthetic"]
        elif command == native._BUILD29_DEBUG_STATE_COMMAND:
            lines = [b"debug output:    " + (b"enable" if peer.enabled else b"disable")]
        elif command in native._DEBUG_ENABLE_COMMANDS:
            if command == "diagnose debug enable":
                peer.enabled = fault != "enable-no-effect"
                if fault == "enable-response-loss": raise OSError("synthetic response loss")
            lines = []
        else:
            assert command == native._DEBUG_DISABLE_COMMAND
            peer.enabled = False
            if fault == "disable-response-loss": raise OSError("synthetic response loss")
            lines = []
        return command.encode() + b"\r\r\n" + b"".join(line + b"\r\n" for line in lines) + prompt

    async def close_cli(process):
        peer.closes += 1

    async def capture_wait(seconds):
        if seconds != 10:
            await original_sleep(seconds)
            return
        if fault == "cancel-capture": raise asyncio.CancelledError
        if fault == "operation-timeout": await asyncio.Event().wait()

    monkeypatch.setattr(transport, "_connection", Connection)
    monkeypatch.setattr(transport, "_open_cli", open_cli)
    monkeypatch.setattr(native, "_send_and_read", send)
    monkeypatch.setattr(native, "_close_cli", close_cli)
    monkeypatch.setattr(native.asyncio, "sleep", capture_wait)
    if fault == "unqualified-readback":
        monkeypatch.setattr(transport, "capture_m4_owned", lambda *args, **kwargs:
            native.ZtnaWadDebugReadback(True, True, "private-value-must-not-escape", "matched", "allowed"))
    key = tmp_path / "execution.key"
    key.write_bytes(b"e" * 32); key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(tmp_path / "execution.sqlite", key)
    directory = tmp_path / "capture"; directory.mkdir(mode=0o700)
    principal = V4PlanningPrincipal(_requester(), "c" * 64)
    arguments = dict(execution_store=store, authority_key=b"a" * 32, state_directory=directory,
        requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest,
        environment_ref="synthetic-wad-environment", scope_ref="synthetic-wad-scope",
        audience_ref="synthetic-wad-audience", clock=lambda: peer.now[0])
    action = ProtectedBuild29WadDebugM4Action(transport, execution_enabled=enabled, **arguments)
    return SimpleNamespace(action=action, principal=principal, peer=peer, store=store, transport=transport,
        directory=directory, key=key, arguments=arguments)


def authorize(c):
    preview = c.action.preview(c.principal)
    return c.action.confirm(preview["preview_ref"], c.principal)["authorization_ref"]


def test_capture_time_shortcut_keeps_cooperative_scheduler_waits(tmp_path, monkeypatch):
    make(tmp_path, monkeypatch)

    async def exercise():
        await asyncio.sleep(0)
        import anyio
        await anyio.lowlevel.checkpoint()

    asyncio.run(exercise())


def test_complete_m4_window_cleanup_audit_and_restart_refusal(tmp_path, monkeypatch):
    c = make(tmp_path, monkeypatch)
    authorization = authorize(c)
    result = c.action.execute(authorization, c.principal)
    assert result["outcome"] == "succeeded" and result["verification"] == "verified"
    assert result["global_debug_cleanup_confirmed"] is True
    assert result["device_context_state"] == "inconclusive" and not c.peer.enabled
    assert c.peer.commands.count("diagnose debug enable") == c.peer.commands.count(native._DEBUG_DISABLE_COMMAND) == 1
    assert c.peer.connections == c.peer.disconnects == c.peer.closes == 5
    assert c.store.claim_count == 1 and len(c.store.audit_events) == 1
    marker = (c.directory / "capture.attempt").read_bytes()
    before = list(c.peer.commands)
    with pytest.raises(WadDebugM4Error): c.action.execute(authorization, c.principal)
    restarted = ProtectedBuild29WadDebugM4Action(c.transport, execution_enabled=True, **c.arguments)
    with pytest.raises(WadDebugM4Error): restarted.preview(c.principal)
    assert c.peer.commands == before and (c.directory / "capture.attempt").read_bytes() == marker
    audit = PersistentM4ExecutionStateStore(tmp_path / "execution.sqlite", c.key, read_only=True)
    assert audit.claim_count == 1 and len(audit.audit_events) == 1
    c.action.close(); restarted.close()


def test_closed_gate_and_cross_client_refuse_before_claim_or_capture(tmp_path, monkeypatch):
    c = make(tmp_path, monkeypatch, enabled=False)
    other = V4PlanningPrincipal(c.principal.requester, "d" * 64)
    with pytest.raises(WadDebugM4Error): c.action.preview(other)
    assert c.peer.commands == []
    preview = c.action.preview(c.principal)
    before = list(c.peer.commands)
    with pytest.raises(WadDebugM4Error): c.action.confirm(preview["preview_ref"], c.principal)
    assert c.peer.commands == before and c.store.claim_count == 0
    assert not (c.directory / "capture.attempt").exists()


def test_private_capture_needs_original_active_kernel_not_only_plan_and_authorization(tmp_path, monkeypatch):
    c = make(tmp_path, monkeypatch)
    authorize(c)
    phase = c.action._phase
    before = list(c.peer.commands)
    with pytest.raises(native.ZtnaWadDebugSshTransportError): c.transport.capture_and_cleanup()
    with pytest.raises(native.ZtnaWadDebugSshTransportError):
        c.transport.capture_m4_owned(phase.plan, phase.authorization, c.store, clock=lambda: 1000)
    assert c.peer.commands == before and c.store.claim_count == 0


def test_confirmation_drift_invalidates_its_preview(tmp_path, monkeypatch):
    c = make(tmp_path, monkeypatch)
    preview = c.action.preview(c.principal)
    c.peer.enabled = True
    with pytest.raises(WadDebugM4Error): c.action.confirm(preview["preview_ref"], c.principal)
    c.peer.enabled = False
    before = list(c.peer.commands)
    with pytest.raises(WadDebugM4Error): c.action.confirm(preview["preview_ref"], c.principal)
    assert c.peer.commands == before and c.store.claim_count == 0


def test_current_drift_never_disables_someone_elses_active_debug(tmp_path, monkeypatch):
    c = make(tmp_path, monkeypatch)
    authorization = authorize(c)
    c.peer.enabled = True
    result = c.action.execute(authorization, c.principal)
    assert result["outcome"] == "precondition_failed" and result["device_write_executed"] is False
    assert c.peer.enabled and native._DEBUG_DISABLE_COMMAND not in c.peer.commands
    assert c.store.claim_count == 1 and len(c.store.audit_events) == 1


@pytest.mark.parametrize("fault", ["enable-response-loss", "disable-response-loss", "expiry-before-enable", "unqualified-readback", "enable-no-effect"])
def test_unknown_effect_or_unqualified_result_never_succeeds_or_redispatches(tmp_path, monkeypatch, fault):
    c = make(tmp_path, monkeypatch, fault=fault)
    authorization = authorize(c)
    result = c.action.execute(authorization, c.principal)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert "private-value" not in str(result)
    if fault == "expiry-before-enable":
        assert "diagnose debug enable" not in c.peer.commands and native._DEBUG_DISABLE_COMMAND not in c.peer.commands
    if fault in {"enable-response-loss", "disable-response-loss"}:
        assert not c.peer.enabled and c.peer.commands.count(native._DEBUG_DISABLE_COMMAND) == 1
    before = list(c.peer.commands)
    with pytest.raises(WadDebugM4Error): c.action.execute(authorization, c.principal)
    assert c.peer.commands == before and c.store.claim_count == 1


def test_postcondition_drift_is_not_success_and_never_causes_another_disable(tmp_path, monkeypatch):
    c = make(tmp_path, monkeypatch, fault="postcondition-drift")
    result = c.action.execute(authorize(c), c.principal)
    assert result["outcome"] == "verification_failed" and result["verification"] == "failed"
    assert c.peer.enabled and c.peer.commands.count(native._DEBUG_DISABLE_COMMAND) == 1


@pytest.mark.parametrize("fault", ["content", "inode", "symlink", "hardlink"])
def test_consumed_attempt_marker_cannot_be_changed_or_imported_before_current_read(tmp_path, monkeypatch, fault):
    from v4_planning import M4AdapterDenied
    c = make(tmp_path, monkeypatch)
    authorize(c)
    phase = c.action._phase
    phase.reserve()
    path = c.directory / "capture.attempt"
    payload = path.read_bytes()
    if fault == "content": path.write_bytes(b"0" * len(payload))
    elif fault == "hardlink": os.link(path, c.directory / "alias")
    else:
        path.unlink()
        if fault == "inode": path.write_bytes(payload); path.chmod(0o600)
        else: path.symlink_to(c.key)
    before = list(c.peer.commands)
    with pytest.raises(M4AdapterDenied): phase.read_current(phase.plan)
    assert c.peer.commands == before and c.store.claim_count == 0


def test_operation_timeout_still_finishes_one_cleanup_and_consumes_its_window(tmp_path, monkeypatch):
    c = make(tmp_path, monkeypatch, fault="operation-timeout")
    real_timeout = asyncio.timeout
    monkeypatch.setattr(native.asyncio, "timeout", lambda seconds: real_timeout(0.01 if seconds == 20 else seconds))
    result = c.action.execute(authorize(c), c.principal)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert not c.peer.enabled and c.peer.commands.count(native._DEBUG_DISABLE_COMMAND) == 1
    assert c.peer.connections == c.peer.disconnects == c.peer.closes == 4
    assert c.store.claim_count == 1


def test_cancelled_capture_cleans_up_and_retains_nonreplayable_in_progress_claim(tmp_path, monkeypatch):
    c = make(tmp_path, monkeypatch, fault="cancel-capture")
    authorization = authorize(c)
    with pytest.raises(asyncio.CancelledError): c.action.execute(authorization, c.principal)
    assert not c.peer.enabled and c.peer.commands.count(native._DEBUG_DISABLE_COMMAND) == 1
    assert c.peer.connections == c.peer.disconnects == c.peer.closes == 4
    before = list(c.peer.commands)
    with pytest.raises(WadDebugM4Error): c.action.execute(authorization, c.principal)
    assert c.peer.commands == before and c.store.claim_count == 1


def test_real_oauth_http_preserves_scope_client_and_reference_only_boundaries(tmp_path, monkeypatch):
    from mcp.server.auth.provider import AccessToken
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.v4_plan_runtime import (
        planning_authorization_settings_from_environment, planning_principal_from_access_token)
    from fortipam_mcp.ztna_wad_debug_mcp_action import V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV
    from test_http_server import (_v4_controlled_environment, _register_public_client,
        _authorize_and_login, _request_headers)

    c = make(tmp_path, monkeypatch)
    env = _v4_controlled_environment(tmp_path / "http")
    env[V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(env)
    all_scopes = "fortipam:read fortipam:plan fortipam:operate"
    with TestClient(create_http_app(settings, v4_folder_action=object(), v4_ztna_wad_debug_action=object()),
            base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, all_scopes)
        other_id = _register_public_client(client, all_scopes)

        def token(identity, scopes):
            code, verifier = _authorize_and_login(client, identity, scopes)
            response = client.post("/fpamcp/oauth/token", data=dict(grant_type="authorization_code",
                client_id=identity, code=code, code_verifier=verifier,
                redirect_uri="https://client.example/callback", resource="https://mcp.example.com/fpamcp"))
            assert response.status_code == 200
            return response.json()["access_token"]

        full, plan, other = token(client_id, all_scopes), token(client_id, "fortipam:read fortipam:plan"), token(other_id, all_scopes)
    authorization_settings = planning_authorization_settings_from_environment(env,
        expected_resource="https://mcp.example.com/fpamcp")
    principal = planning_principal_from_access_token(AccessToken(token=full, client_id=client_id,
        scopes=all_scopes.split(), expires_at=2_000_000_000, resource="https://mcp.example.com/fpamcp",
        subject="operator", claims={"iss": "https://mcp.example.com/fpamcp/oauth"}), authorization_settings)
    arguments = dict(c.arguments, requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest)
    action = ProtectedBuild29WadDebugM4Action(c.transport, execution_enabled=True, **arguments)
    with TestClient(create_http_app(settings, v4_folder_action=object(), v4_ztna_wad_debug_action=action),
            base_url="https://mcp.example.com") as client:
        def call(access, name, arguments):
            headers = {**_request_headers(access), "host": "mcp.example.com"}
            response = client.post("/fpamcp", headers=headers, json=dict(jsonrpc="2.0",
                id="wad-m4-boundary", method="tools/call", params=dict(name=name, arguments=arguments)))
            assert response.status_code == 200
            return response.json()["result"]

        preview_tool = "preview_v4_ztna_wad_debug_diagnostic"
        confirm_tool = "confirm_v4_ztna_wad_debug_diagnostic"
        execute_tool = "execute_confirmed_v4_ztna_wad_debug_diagnostic"
        assert call(other, preview_tool, {})["isError"] is True
        assert c.peer.commands == []
        extra = call(full, preview_tool, {"unexpected": "NONSECRET_UNEXPECTED"})
        assert extra["isError"] is True and "NONSECRET_UNEXPECTED" not in str(extra)
        assert c.peer.commands == []
        preview = call(plan, preview_tool, {})["structuredContent"]
        before = list(c.peer.commands)
        assert call(plan, confirm_tool, {"preview_ref": preview["preview_ref"]})["isError"] is True
        assert call(other, confirm_tool, {"preview_ref": preview["preview_ref"]})["isError"] is True
        assert c.peer.commands == before
        confirmed = call(full, confirm_tool, {"preview_ref": preview["preview_ref"]})["structuredContent"]
        before = list(c.peer.commands)
        assert call(plan, execute_tool, {"authorization_ref": confirmed["authorization_ref"]})["isError"] is True
        assert call(other, execute_tool, {"authorization_ref": confirmed["authorization_ref"]})["isError"] is True
        assert c.peer.commands == before
        result = call(full, execute_tool, {"authorization_ref": confirmed["authorization_ref"]})["structuredContent"]
        assert result["outcome"] == "succeeded" and result["global_debug_cleanup_confirmed"] is True
        assert c.store.claim_count == 1
        before = list(c.peer.commands)
        assert call(full, execute_tool, {"authorization_ref": confirmed["authorization_ref"]})["isError"] is True
        assert c.peer.commands == before
