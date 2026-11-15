"""Real persistent M4 role fixture lifecycle; all native HTTP is synthetic."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import http.client
import json

import pytest
from v4_planning import M4AuthorizationDenied, M4ExecutionKernel

from fortipam_mcp.ems_tag_role_contract import ProspectiveEmsTagManagerRole
from fortipam_mcp.ems_tag_role_fixture_authority import EmsRoleFixtureAuthority
from fortipam_mcp.ems_tag_role_fixture_adapter import NativeEmsRoleFixtureM4Adapter
from fortipam_mcp.ems_tag_role_fixture_custody import EmsRoleFixtureCustody
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_tag_identity_sources import make as identity_source
from test_ems_tag_http_transport import reply, framed
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF

SCOPE = dict(environment_ref="ems-home-lab", scope_ref="ems-tag-role-fixture-lab", audience_ref="local-role-fixture")
CALLER = dict(requester_digest="1" * 64, transport_digest="2" * 64)


def make(tmp_path, monkeypatch, *, fault=None, original=None, current_data=None, config=None,
         authority_enabled=True, adapter_enabled=True, same_session=False, caller=None):
    tmp_path.mkdir(mode=0o700, exist_ok=True);tmp_path.chmod(0o700)
    recovery = original is not None
    caller = caller or (dict(CALLER, transport_digest="3" * 64) if recovery else CALLER)
    source, transport, calls, connections, data, now = identity_source(tmp_path, monkeypatch,
        shared_config=config, source_key=(b"t" if recovery else b"s") * 32,
        session_value="synthetic" if same_session or not recovery else "independent-synthetic-session")
    if current_data is not None:data.update(deepcopy(current_data))
    observed = source.observe()
    draft = original._draft if recovery else ProspectiveEmsTagManagerRole(observed.full_scope.schema, "b" * 32)
    try:
        authority = EmsRoleFixtureAuthority(source, draft, authority_key=(b"b" if recovery else b"a") * 32,
            execution_enabled=authority_enabled, original=original, clock=lambda: now[0], **SCOPE, **caller)
        preview = authority.preview(observed, **caller)
    except Exception:
        source.close();assert transport.close().next_session_check_401
        raise
    if not authority_enabled:
        return dict(authority=authority, preview=preview, observed=observed, source=source, transport=transport, calls=calls, connections=connections)
    issued = authority.issue(preview, observed, **caller)
    for name, raw in [("store.key", (b"f" if recovery else b"e") * 32), ("custody.key", (b"d" if recovery else b"c") * 32)]:
        (tmp_path / name).write_bytes(raw);(tmp_path / name).chmod(0o600)
    checkpoint = _ExternalM4Checkpoint()
    store = PersistentM4ExecutionStateStore(tmp_path / "execution.sqlite", tmp_path / "store.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
    directory = tmp_path / "custody";directory.mkdir(mode=0o700)
    custody = EmsRoleFixtureCustody(directory, tmp_path / "custody.key", store, authority, clock=lambda: now[0])
    custody.retain_before_dispatch()
    adapter = NativeEmsRoleFixtureM4Adapter(authority, custody, execution_enabled=adapter_enabled)
    original_connect = transport._connect
    writes, bodies = [], []
    born_uid = "synthetic-born-role"
    def connect():
        connection = original_connect()
        old_request, old_response, old_close = connection.request, connection.getresponse, connection.close
        def request(method, path, *, body, headers):
            old_request(method, path, body=body, headers=headers)
            if path == "/api/v1/roles/create" or method == "DELETE":
                writes.append((method, path));bodies.append(body)
                assert method == ("DELETE" if recovery else "POST")
                if recovery:assert body is None
                else:assert json.loads(body) == draft._body
        def response():
            if connection.path != "/api/v1/roles/create" and connection.method != "DELETE":return old_response()
            if recovery:
                uid = original.inspect_verified_original().role_uid
                data["roles"] = [row for row in data["roles"] if row["uid"] != uid]
                data["details"].pop(uid)
            else:
                row = dict(draft._body, id=17, uid=born_uid, is_super=False, is_built_in=False)
                data["details"][born_uid] = row
                data["roles"].append({k: row[k] for k in ("uid", "name", "description", "is_built_in", "is_super")})
            if fault == "old_role_drift":data["details"]["synthetic-role"]["manage_server_settings"] = True
            if fault == "admin_drift":data["user"]["other_config"]["enabled"] = True
            if fault == "lost_response":raise http.client.RemoteDisconnected()
            payload = {"result": {"retval": 1, "message": None}}
            if fault == "wrong_selector":payload["data"] = {"uid": "foreign-role"}
            if fault == "selector":payload["data"] = {"uid": born_uid, "id": 17}
            if fault == "partial_frame":
                raw = json.dumps(payload).encode()
                return framed(f"Content-Length: {len(raw)+1}\r\n".encode(), raw)
            if fault == "duplicate_json":return reply(body=b'{"result":{"retval":1,"retval":0,"message":null}}')
            if fault == "expiry_after_send":now[0] = 1060
            return reply(payload)
        def close():
            old_close()
            if fault == "close_failure" and (getattr(connection, "path", None) == "/api/v1/roles/create" or getattr(connection, "method", None) == "DELETE"):
                raise OSError("Synthetic close failure")
        connection.request, connection.getresponse, connection.close = request, response, close
        return connection
    monkeypatch.setattr(transport, "_connect", connect)
    kernel = M4ExecutionKernel(adapter, authority, store, clock=lambda: now[0])
    return dict(source=source, transport=transport, calls=calls, connections=connections, data=data, now=now, draft=draft,
        observed=observed, authority=authority, issued=issued, custody=custody, store=store, checkpoint=checkpoint,
        adapter=adapter, kernel=kernel, writes=writes, bodies=bodies)


def execute(env):return env["kernel"].execute(env["issued"].plan, env["issued"].authorization)


def readonly_original(env):
    store = env["store"]
    reader = PersistentM4ExecutionStateStore(store._path, store._key_path, monotonic_checkpoint=env["checkpoint"],
        checkpoint_store_ref=CHECKPOINT_STORE_REF, read_only=True)
    return EmsRoleFixtureCustody.open_original(env["custody"]._directory, env["custody"]._key_file, reader)


def close(env):
    for key in ("adapter", "authority", "custody", "source"):
        if key in env:env[key].close()
    assert env["transport"].close().next_session_check_401


@pytest.mark.parametrize("selector", [False, True])
def test_original_role_create_and_independent_recovery_preserve_full_graph_and_never_replay(tmp_path, monkeypatch, selector):
    create = make(tmp_path / "create", monkeypatch, fault="selector" if selector else None)
    baseline = create["observed"].full_scope.digest
    assert str(execute(create).outcome) == "succeeded"
    original = create["custody"].inspect_verified_original()
    assert original.baseline_digest == baseline and len(create["writes"]) == 1
    assert all(not body for body in create["bodies"])
    count = len(create["connections"])
    assert execute(create).idempotent_replay and len(create["connections"]) == count
    reader = readonly_original(create)
    protected = {p:hashlib.sha256(p.read_bytes()).hexdigest() for p in create["custody"]._directory.iterdir()}
    close(create)
    recover = make(tmp_path / "recover", monkeypatch, original=reader, current_data=create["data"], config=create["transport"]._config)
    result = execute(recover)
    assert str(result.outcome) == "succeeded" and str(result.verification) == "verified"
    assert recover["adapter"]._post.full_scope.digest == baseline
    assert recover["writes"] == [("DELETE", "/api/v1/roles/" + original.role_uid + "/delete")]
    assert recover["custody"].inspect_effect()["scope_digest"] == baseline
    count = len(recover["connections"])
    assert execute(recover).idempotent_replay and len(recover["connections"]) == count
    assert all(hashlib.sha256(p.read_bytes()).hexdigest() == sha for p, sha in protected.items())
    with pytest.raises(ValueError):recover["custody"].inspect_verified_original()
    close(recover);reader.close()


@pytest.mark.parametrize("fault", ["partial_frame", "duplicate_json", "lost_response", "wrong_selector", "old_role_drift", "admin_drift", "close_failure", "expiry_after_send"])
def test_unknown_original_is_consumed_and_cannot_be_reopened_or_late_sealed(tmp_path, monkeypatch, fault):
    env = make(tmp_path, monkeypatch, fault=fault)
    result = execute(env)
    assert str(result.outcome) == "reconciliation_required" and str(result.verification) == "unknown"
    assert len(env["writes"]) == 1 and all(not body for body in env["bodies"])
    with pytest.raises(ValueError):readonly_original(env)
    with pytest.raises(ValueError):env["custody"].inspect_verified_original()
    paths = list(env["custody"]._directory.iterdir());before = {p:p.read_bytes() for p in paths}
    with pytest.raises(ValueError):env["custody"].capture_effect(env["observed"].full_scope, env["observed"].full_scope)
    raw = bytearray(b'{"result":{"retval":1,"message":null}}')
    with pytest.raises(ValueError):env["custody"].capture_ack(raw, status=200, content_type="application/json", complete=True)
    assert not raw and all(p.read_bytes() == value for p,value in before.items())
    if fault != "expiry_after_send":
        count = len(env["connections"])
        assert execute(env).idempotent_replay and len(env["connections"]) == count
    close(env)


@pytest.mark.parametrize('fault',['ack_signature','reservation_link','effect_link','closing_witness_key','closing_store_key'])
def test_original_read_chain_rejects_record_links_and_closing_boundary_drift(tmp_path,monkeypatch,fault):
    env=make(tmp_path,monkeypatch);assert str(execute(env).verification)=='verified'
    original=readonly_original(env);count=len(env['connections']);restore=None
    if fault.startswith('closing_'):
        path=original._key_file if fault=='closing_witness_key' else original._store._key_path
        restore=(path,path.read_bytes());check_time=original._time
        def change_key(value):
            result=check_time(value);path.write_bytes(b'changed-original-read-key-value!!');return result
        monkeypatch.setattr(original,'_time',change_key)
    else:
        name={'ack_signature':'ack.json','reservation_link':'send.json','effect_link':'effect.json'}[fault]
        path=original._directory/name;restore=(path,path.read_bytes());packet=json.loads(path.read_bytes())
        if fault=='ack_signature':packet['signature']='0'*64
        else:
            field='reservation_digest' if fault=='reservation_link' else 'attempt_digest'
            packet['value'][field]='0'*64;packet['signature']=original._mac(name,packet['value'])
        path.write_text(json.dumps(packet))
    try:
        with pytest.raises(ValueError):original.inspect_verified_original()
        assert len(env['connections'])==count and len(env['writes'])==1
    finally:
        if restore is not None:restore[0].write_bytes(restore[1])
        original.close();close(env)


def test_closed_gates_and_prewrite_drift_never_dispatch(tmp_path, monkeypatch):
    disabled = make(tmp_path / "authority-disabled", monkeypatch, authority_enabled=False)
    with pytest.raises(M4AuthorizationDenied):disabled["authority"].issue(disabled["preview"], disabled["observed"], **CALLER)
    close(disabled)
    for name, enabled in [("adapter-disabled", False), ("drift", True)]:
        env = make(tmp_path / name, monkeypatch, adapter_enabled=enabled)
        if enabled:env["data"]["user"]["other_config"]["enabled"] = True
        assert str(execute(env).outcome) == "denied" and not env["writes"]
        close(env)


def test_recovery_requires_readonly_verified_original_same_human_and_different_real_session_and_channel(tmp_path, monkeypatch):
    create = make(tmp_path / "create", monkeypatch);assert str(execute(create).outcome) == "succeeded"
    with pytest.raises(ValueError):create["custody"].require_recovery_source(create["source"], CALLER["requester_digest"])
    reader = readonly_original(create)
    for name, kwargs in [("same-session",dict(same_session=True)), ("other-human",dict(caller=dict(CALLER, requester_digest="9"*64, transport_digest="3"*64))),
                         ("same-channel",dict(caller=CALLER))]:
        with pytest.raises(M4AuthorizationDenied):
            make(tmp_path / name, monkeypatch, original=reader, current_data=create["data"], config=create["transport"]._config, **kwargs)
    close(create);reader.close()


def test_preview_replacement_and_readonly_packet_copy_do_not_expand_authority(tmp_path, monkeypatch):
    env = make(tmp_path / "create", monkeypatch)
    with pytest.raises(M4AuthorizationDenied):env["authority"].issue(replace(env["authority"]._preview), env["observed"], **CALLER)
    assert str(execute(env).outcome) == "succeeded"
    copied = tmp_path / "copied";copied.mkdir(mode=0o700)
    for p in env["custody"]._directory.iterdir():
        target=copied/p.name;target.write_bytes(p.read_bytes());target.chmod(0o600)
    store = env["store"]
    reader = PersistentM4ExecutionStateStore(store._path, store._key_path, monotonic_checkpoint=env["checkpoint"],
        checkpoint_store_ref=CHECKPOINT_STORE_REF, read_only=True)
    with pytest.raises(ValueError):EmsRoleFixtureCustody.open_original(copied, env["custody"]._key_file, reader)
    close(env)


@pytest.mark.parametrize("field", ["environment_ref", "scope_ref", "audience_ref"])
def test_unnamed_policy_scope_cannot_issue_a_role_fixture_authority(tmp_path, monkeypatch, field):
    env = make(tmp_path, monkeypatch)
    with pytest.raises(M4AuthorizationDenied):
        EmsRoleFixtureAuthority(env["source"], env["draft"], authority_key=b"z"*32,
            execution_enabled=True, **dict(SCOPE, **{field:"another-scope"}), **CALLER)
    assert not env["writes"]
    close(env)
