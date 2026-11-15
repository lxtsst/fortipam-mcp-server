"""Independent readonly original ledger and synthetic fresh recovery sources."""
from dataclasses import replace
import json

import pytest

from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag, EmsTagFullScope, qualify_tag_detail
from fortipam_mcp.ems_tag_custody import EmsTagOriginalCustody
from fortipam_mcp.ems_tag_http_transport import NativeEmsTagHttpTransport
from fortipam_mcp.ems_tag_recovery_contract import EmsTagOwnedRecoveryScope, EmsTagRecoveryError
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_tag_authority import CALLER
from test_ems_tag_contract import detail, envelope, full_scope
from test_ems_tag_create_m4_adapter import make as original_create
from test_ems_tag_http_transport import make as http_transport


def make(tmp_path, monkeypatch, *, fault=None):
    adapter, kernel, issued, custody, transport, source, _, _, writes, _, authority = original_create(tmp_path,monkeypatch,
        fault="close_failure" if fault == "original_unknown" else None)
    result = kernel.execute(issued.plan,issued.authorization)
    assert len(writes) == 1
    assert (result.verification == "unknown") is (fault == "original_unknown")
    original_key, original_actor = source._key, custody._actor_binding
    assert transport.close().next_session_check_401
    adapter.close();authority.close();source.close();custody.close()
    read_only = PersistentM4ExecutionStateStore(custody._store._path,custody._store._key_path,
        monotonic_checkpoint=custody._store._monotonic_checkpoint,
        checkpoint_store_ref=custody._store._checkpoint_store_ref,read_only=fault != "writable_original")
    reopened = EmsTagOriginalCustody(custody._directory,custody._key_file,DisabledLinuxProcessTag("a"*32),
        custody._baseline,issued.plan,issued.authorization,read_only,source_context_digest=custody._source,
        actor_binding=original_actor)
    current, channel, connections, _, _, _ = http_transport(tmp_path,monkeypatch)
    channel.session_value = "synthetic" if fault == "same_session" else "independent-synthetic-session"
    channel.scope = full_scope(add=True)
    if fault == "prior_drift": channel.scope = full_scope(prior_change=True,add=True)
    elif fault == "assigned":
        row = detail(DisabledLinuxProcessTag("a"*32));row["client_count"] = 1
        channel.scope = EmsTagFullScope(channel.scope.catalog,(channel.scope.details[0],qualify_tag_detail(envelope(row))))
    current.authenticate()
    current_source = current.make_sources(DisabledLinuxProcessTag("a"*32),source_key=b"x"*32 if fault == "source_key" else original_key)
    current_source.observe()
    caller = dict(requester_digest="d"*64 if fault == "requester" else issued.plan.requester_digest,
                  caller_transport_digest=CALLER["transport_digest"] if fault == "same_transport" else "c"*64)
    return reopened,current,current_source,channel,connections,caller


def test_new_session_rejoins_original_full_state_readonly_and_proves_only_api_graph_restoration(tmp_path,monkeypatch):
    original,transport,source,channel,connections,caller = make(tmp_path,monkeypatch)
    ledger = original._store._path.read_bytes()
    records = {p.name:p.read_bytes()for p in original._directory.iterdir()}
    scope = EmsTagOwnedRecoveryScope(transport=transport,sources=source,original=original,**caller)
    observed = scope.observe_owned();scope.check_current(observed)
    assert observed.owner_session_digest != original._actor_binding.owner_session_digest
    assert observed.full_scope.digest == original.inspect_created_scope().created_scope_digest
    assert source._draft._name not in repr(scope)+repr(observed)
    channel.scope = full_scope()
    assert scope.observe_restored_api_graph() == observed.expected_digest
    assert original._store._path.read_bytes() == ledger
    assert records == {p.name:p.read_bytes()for p in original._directory.iterdir()}
    assert all(c.method == "GET"or c.path in("/api/v1/auth/signin",)for c in connections)
    assert transport.close().next_session_check_401
    scope.close();source.close()


@pytest.mark.parametrize("fault",["original_unknown","writable_original","same_session","same_transport","source_key","requester"])
def test_unverified_original_or_relabelled_identity_cannot_admit_recovery(tmp_path,monkeypatch,fault):
    original,transport,source,_,connections,caller = make(tmp_path,monkeypatch,fault=fault)
    count=len(connections)
    with pytest.raises(EmsTagRecoveryError):
        EmsTagOwnedRecoveryScope(transport=transport,sources=source,original=original,**caller)
    assert len(connections)==count
    assert transport.close().next_session_check_401
    source.close()


@pytest.mark.parametrize("fault",["prior_drift","assigned"])
def test_current_tag_and_every_prior_full_state_must_match_original_birth(tmp_path,monkeypatch,fault):
    original,transport,source,_,_,caller=make(tmp_path,monkeypatch,fault=fault)
    scope=EmsTagOwnedRecoveryScope(transport=transport,sources=source,original=original,**caller)
    with pytest.raises(EmsTagRecoveryError):scope.observe_owned()
    assert transport.close().next_session_check_401


@pytest.mark.parametrize("fault",["clone","tamper","session_rotation","caller_change","source_refresh"])
def test_qualified_recovery_observation_is_exact_live_and_session_bound(tmp_path,monkeypatch,fault):
    original,transport,source,_,_,caller=make(tmp_path,monkeypatch)
    scope=EmsTagOwnedRecoveryScope(transport=transport,sources=source,original=original,**caller)
    observed=scope.observe_owned()
    if fault=="clone":observed=replace(observed)
    elif fault=="tamper":object.__setattr__(observed,"full_scope",full_scope(prior_change=True,add=True))
    elif fault=="caller_change":scope._caller_transport="e"*64
    elif fault=="source_refresh":source.observe()
    else:
        for cookie in transport._jar:
            if cookie.name=="sessionid":cookie.value="another-synthetic-session"
    with pytest.raises(EmsTagRecoveryError):scope.check_current(observed)
    assert transport.close().next_session_check_401


def test_incomplete_api_restore_cannot_be_reported_as_original_baseline(tmp_path,monkeypatch):
    original,transport,source,channel,_,caller=make(tmp_path,monkeypatch)
    scope=EmsTagOwnedRecoveryScope(transport=transport,sources=source,original=original,**caller)
    scope.observe_owned();channel.scope=full_scope(prior_change=True)
    with pytest.raises(EmsTagRecoveryError):scope.observe_restored_api_graph()
    assert transport.close().next_session_check_401
