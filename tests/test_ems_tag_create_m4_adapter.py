"""Real M4/store and fixed HTTP adapter with synthetic product replies only."""
from dataclasses import replace
import hashlib
import hmac
import http.client
import json

import pytest
from v4_planning import M4AdapterDenied, M4ExecutionKernel

from fortipam_mcp.ems_tag_authority import EmsTagCreateAuthority
from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag, EmsTagFullScope, qualify_tag_detail
from fortipam_mcp.ems_tag_create_m4_adapter import NativeEmsTagCreateM4Adapter
from fortipam_mcp.ems_tag_custody import EmsTagOriginalCustody, EmsTagCustodyError, EmsTagOriginalActorBinding
from fortipam_mcp.ems_tag_sources import CATALOG_PATH
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_tag_authority import IDENTITY, CALLER
from test_ems_tag_contract import detail, envelope, full_scope
from test_ems_tag_http_transport import make as http_transport, reply, framed
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF


def make(tmp_path, monkeypatch, *, enabled=True, fault=None, ack_data=False):
    tmp_path.chmod(0o700)
    transport, channel, connections, _, _, _ = http_transport(tmp_path, monkeypatch)
    transport.authenticate()
    source = transport.make_sources(DisabledLinuxProcessTag("a" * 32), source_key=b"s" * 32)
    observed = source.observe()
    authority = EmsTagCreateAuthority(source, authority_key=b"k" * 32, execution_enabled=True, **IDENTITY)
    preview = authority.preview(observed, **CALLER)
    issued = authority.issue(preview, observed, **CALLER)
    for name, value in (("execution.key", b"e" * 32), ("custody.key", b"c" * 32)):
        (tmp_path / name).write_bytes(value);(tmp_path / name).chmod(0o600)
    (tmp_path / "custody").mkdir(mode=0o700)
    store = PersistentM4ExecutionStateStore(tmp_path / "execution.sqlite", tmp_path / "execution.key",
        monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
    custody = EmsTagOriginalCustody(tmp_path / "custody", tmp_path / "custody.key", source._draft,
        observed.full_scope.digest, issued.plan, issued.authorization, store,
        source_context_digest=source.source_context_digest, actor_binding=EmsTagOriginalActorBinding(
            transport.session_binding_digest(source._key),CALLER["transport_digest"],hashlib.sha256(authority._key).hexdigest()))
    original_connect = transport._connect
    writes, bodies = [], []

    def connect():
        connection = original_connect()
        original_request, original_response, original_close = connection.request, connection.getresponse, connection.close
        def request(method, path, *, body, headers):
            original_request(method, path, body=body, headers=headers)
            if path == "/api/v1/tags/zero_trust/create":
                writes.append((method, path));bodies.append(body)
                assert json.loads(body) == source._draft._body
        def response():
            if connection.path != "/api/v1/tags/zero_trust/create": return original_response()
            channel.scope = full_scope(prior_change=fault == "old_rule_drift", add=True,
                                       shared_rule_set=fault == "shared_rule_set")
            if fault == "assigned":
                row = detail(source._draft);row["client_count"] = 1
                channel.scope = EmsTagFullScope(channel.scope.catalog,
                    (channel.scope.details[0], qualify_tag_detail(envelope(row))))
            if fault == "lost_response": raise http.client.RemoteDisconnected()
            payload = {"result": {"retval": 1, "message": "Created"}}
            if ack_data: payload["data"] = {"tag_id": 909 if fault == "wrong_selector" else 101}
            if fault == "partial_frame":
                raw = json.dumps(payload).encode()
                return framed(f"Content-Length: {len(raw)+1}\r\n".encode(), raw)
            if fault == "duplicate_json":
                return reply(body=b'{"result":{"retval":1,"retval":0,"message":"x"}}')
            return reply(payload)
        def close():
            original_close()
            if fault == "close_failure" and getattr(connection, "path", None) == "/api/v1/tags/zero_trust/create":
                raise OSError
        connection.request, connection.getresponse, connection.close = request, response, close
        return connection
    monkeypatch.setattr(transport, "_connect", connect)
    adapter = NativeEmsTagCreateM4Adapter(transport=transport, sources=source, authority=authority,
        issued=issued, store=store, custody=custody, execution_enabled=enabled)
    kernel = M4ExecutionKernel(adapter, authority, store)
    return adapter, kernel, issued, custody, transport, source, channel, connections, writes, bodies, authority


@pytest.mark.parametrize("ack_data", [False, True])
def test_exact_create_posts_once_and_seals_original_full_birth_without_leaking_or_replay(tmp_path, monkeypatch, ack_data):
    adapter, kernel, issued, custody, transport, source, _, connections, writes, bodies, authority = make(
        tmp_path, monkeypatch, ack_data=ack_data)
    result = kernel.execute(issued.plan, issued.authorization)
    assert result.outcome == "succeeded" and result.verification == "verified"
    assert len(writes) == 1 and all(not body for body in bodies)
    original = custody.inspect_created_scope()
    assert original.created_state_digest and original.created_scope_digest
    assert custody.inspect_ack_attempt()["data_field_present"] is ack_data
    count = len(connections)
    replay = kernel.execute(issued.plan, issued.authorization)
    assert replay.idempotent_replay and len(writes) == 1 and len(connections) == count
    assert not list(tmp_path.glob("*.ems-create-failure.*.json"))
    assert transport.close().next_session_check_401
    adapter.close();authority.close();source.close();custody.close()


@pytest.mark.parametrize("fault", ["partial_frame", "duplicate_json", "lost_response", "old_rule_drift",
    "shared_rule_set", "assigned", "wrong_selector", "close_failure"])
def test_ambiguous_write_retains_original_diagnostic_but_never_allows_ownership_or_replay(tmp_path, monkeypatch, fault):
    adapter, kernel, issued, custody, transport, source, _, connections, writes, bodies, authority = make(
        tmp_path, monkeypatch, fault=fault, ack_data=fault == "wrong_selector")
    result = kernel.execute(issued.plan, issued.authorization)
    assert result.outcome == "reconciliation_required" and result.verification == "unknown"
    assert len(writes) == 1 and all(not body for body in bodies)
    with pytest.raises(EmsTagCustodyError): custody.inspect_created_scope()
    with pytest.raises(EmsTagCustodyError): custody.capture_created_scope(full_scope(), full_scope(add=True))
    records = list(tmp_path.glob("*.ems-create-failure.*.json"));assert len(records) == 1
    raw = records[0].read_bytes();assert source._draft._name.encode() not in raw
    record = json.loads(raw);signature = record.pop("signature")
    expected = hmac.new(custody._key, b"ems-tag-original-create-diagnostic/v1\x00" +
        json.dumps(record,sort_keys=True,separators=(',',':')).encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(signature,expected) and record["request_replayable"] is False
    if fault == "partial_frame":
        assert record["response_error_type"] == "ValueError"
        assert record["original_ack_attempt"]["json_object_complete"] is True
        assert record["original_ack_attempt"]["native_envelope_valid"] is True
        assert record["original_ack_attempt"]["reply_complete"] is False
    if fault == "lost_response":
        assert record["response_error_type"] == "RemoteDisconnected" and record["http_status"] == 0
    count = len(connections)
    replay = kernel.execute(issued.plan, issued.authorization)
    assert replay.idempotent_replay and len(writes) == 1 and len(connections) == count
    assert records[0].read_bytes() == raw
    assert transport.close().next_session_check_401
    adapter.close();authority.close();source.close();custody.close()


def test_default_closed_adapter_and_direct_dispatch_never_post(tmp_path, monkeypatch):
    adapter, kernel, issued, _, transport, _, _, connections, writes, _, _ = make(tmp_path, monkeypatch, enabled=False)
    count = len(connections)
    result = kernel.execute(issued.plan, issued.authorization)
    assert result.outcome == "denied" and not writes and len(connections) == count
    with pytest.raises(M4AdapterDenied): adapter.dispatch(issued.plan)
    assert len(connections) == count
    assert transport.close().next_session_check_401


def test_prewrite_full_rule_drift_after_connect_is_denied_without_send_reservation(tmp_path, monkeypatch):
    adapter, kernel, issued, custody, transport, source, channel, _, writes, _, _ = make(tmp_path, monkeypatch)
    def drift(current, path):
        # Initial, kernel-current, then final pre-write source windows.
        if path == CATALOG_PATH and current.calls.count(path) == 7:
            current.scope = full_scope(prior_change=True)
    channel.mutate = drift
    result = kernel.execute(issued.plan, issued.authorization)
    assert result.outcome == "denied" and not writes
    assert not list(custody._directory.iterdir()) and not list(tmp_path.glob("*.ems-send.*.json"))
    assert transport.close().next_session_check_401


def test_copied_issue_or_detached_channel_is_not_a_writer_binding(tmp_path, monkeypatch):
    adapter, _, issued, custody, transport, source, _, connections, writes, _, authority = make(tmp_path, monkeypatch)
    count = len(connections)
    with pytest.raises(M4AdapterDenied): adapter.dispatch(issued.plan)
    with pytest.raises(M4AdapterDenied):
        NativeEmsTagCreateM4Adapter(transport=transport,sources=source,authority=authority,
            issued=replace(issued),store=custody._store,custody=custody,execution_enabled=True)
    source._get = lambda path: {}
    with pytest.raises(M4AdapterDenied):
        NativeEmsTagCreateM4Adapter(transport=transport,sources=source,authority=authority,
            issued=issued,store=custody._store,custody=custody,execution_enabled=True)
    assert not writes and len(connections) == count
    assert transport.close().next_session_check_401


def test_session_rotation_after_issue_denies_without_dispatch_or_late_actor_rebinding(tmp_path, monkeypatch):
    adapter, kernel, issued, custody, transport, _, _, connections, writes, _, _ = make(tmp_path, monkeypatch)
    count = len(connections)
    for cookie in transport._jar:
        if cookie.name == "sessionid": cookie.value = "changed-synthetic-session"
    result = kernel.execute(issued.plan,issued.authorization)
    assert result.outcome == "denied" and not writes and len(connections) == count
    assert not list(custody._directory.iterdir())
    assert transport.close().next_session_check_401


@pytest.mark.parametrize("field",["owner_session_digest","caller_transport_digest","issuer_key_digest"])
def test_original_actor_binding_cannot_be_relabelled_for_the_real_create_adapter(tmp_path,monkeypatch,field):
    _,_,issued,custody,transport,source,_,connections,writes,_,authority=make(tmp_path,monkeypatch)
    count=len(connections)
    changed=EmsTagOriginalCustody(custody._directory,custody._key_file,source._draft,custody._baseline,
        issued.plan,issued.authorization,custody._store,source_context_digest=custody._source,
        actor_binding=replace(custody._actor_binding,**{field:"f"*64}))
    with pytest.raises(M4AdapterDenied):
        NativeEmsTagCreateM4Adapter(transport=transport,sources=source,authority=authority,issued=issued,
            store=custody._store,custody=changed,execution_enabled=True)
    assert not writes and len(connections)==count and not list(custody._directory.iterdir())
    assert transport.close().next_session_check_401
