"""Real source-bound lab issuers joined to synthetic product HTTP and persistent M4."""
import pytest
from v4_planning import M4AuthorizationDenied, M4ExecutionKernel

from fortipam_mcp.jwt_manual_key_lab_authority import JwtManualKeyCreateLabAuthority, JwtManualKeyRemovalLabAuthority
from fortipam_mcp.jwt_manual_key_response_custody import JwtManualKeyResponseCustody
from fortipam_mcp.jwt_manual_key_create_http_transport import JwtManualKeyCreateHttpTransport
from fortipam_mcp.jwt_manual_key_recovery import JwtManualKeyRecovery
from test_jwt_manual_key_create_http_transport import Lab
from test_jwt_manual_key_recovery import RecoveryLab, synthetic_recovery_tls
from test_jwt_manual_key_contract import synthetic_key
from test_jwt_manual_key_owned_state import request as fresh_request
from test_v4_execution_kernel import REQUESTER

TRANSPORT='d'*64
IDENTITY=dict(environment_ref='synthetic-jwt-lab',scope_ref='synthetic-jwt-scope',audience_ref='synthetic-jwt-audience',
    requester_digest=REQUESTER,transport_digest=TRANSPORT)


def creator(root,lab,*,enabled=True,guard=True):
    path=root/'authority.key';path.write_bytes(b'a'*32);path.chmod(0o600)
    return JwtManualKeyCreateLabAuthority(lab.reader,lab.request,execution_store=lab.store,directory=root/'custody',
        authority_key_file=path,witness_key_file=root/'witness.key',**IDENTITY,
        execution_enabled=enabled,source_guard=(lambda:lab.source)if guard else None,clock=lambda:lab.epoch)


def create_binding(root,lab,authority):
    issued=authority.issue(requester_digest=REQUESTER,transport_digest=TRANSPORT)
    lab.plan,lab.auth,lab.baseline=issued.plan,issued.authorization,issued.baseline
    lab.custody=JwtManualKeyResponseCustody(root/'custody',root/'witness.key',lab.request,issued.baseline.actor,
        issued.baseline.source_digest,issued.baseline.state.state_digest,issued.plan,issued.authorization,lab.store,
        execution_enabled=authority.execution_gate,source_guard=authority.source_guard,
        actor_reader=lab.reader.observe_actor,clock=lambda:lab.epoch)
    lab.transport=JwtManualKeyCreateHttpTransport(lab.config,lab.custody,lab.reader,issued.baseline,
        execution_enabled=authority.execution_gate,source_guard=authority.source_guard,
        connection_factory=lambda *args,**kwargs:lab.connect('writer',*args,**kwargs),http_clock=lambda:lab.mono)
    authority.bind_runtime(lab.transport)
    return issued


def removal(root,lab,recovery,*,enabled=True):
    path=recovery.directory/'authority.key';path.write_bytes(b'b'*32);path.chmod(0o600)
    policy=JwtManualKeyRemovalLabAuthority(lab.reader,execution_store=recovery.store,authority_key_file=path,
        witness_key_file=recovery.directory/'witness.key',creation_authority_key_file=root/'authority.key',
        **IDENTITY,execution_enabled=enabled,source_guard=lambda:recovery.source,clock=lambda:recovery.now)
    recovery.runtime=JwtManualKeyRecovery(lab.config,lab.custody,lab.reader,lab.baseline,execution_store=recovery.store,
        witness_key_file=recovery.directory/'witness.key',execution_enabled=True,authorization_verifier=policy,
        source_guard=policy.source_guard,connection_factory=recovery.connect,clock=lambda:recovery.now,http_clock=lambda:recovery.mono)
    return policy


@pytest.mark.parametrize('fault',['none','close-post'])
def test_both_real_lab_grants_complete_create_and_independent_remove_without_rewriting_creator(tmp_path,monkeypatch,synthetic_key,fault):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);authority=creator(tmp_path,lab)
    issued=create_binding(tmp_path,lab,authority);lab.fault=fault
    result=M4ExecutionKernel(lab.transport,authority,lab.store,clock=lambda:lab.epoch).execute(issued.plan,issued.authorization)
    assert result.outcome==('succeeded'if fault=='none'else'reconciliation_required')and authority._consumed
    assert lab.post_count==1 and lab.request._closed
    original=lab.custody.inspect_original_response();original_tail=lab.checkpoint.tail
    authority.close();lab.fault='none'
    recovery=RecoveryLab(tmp_path,lab)
    policy=removal(tmp_path,lab,recovery)
    removed=policy.issue(recovery.runtime,requester_digest=REQUESTER,transport_digest=TRANSPORT)
    restored=recovery.runtime.execute(removed.plan,removed.authorization)
    assert restored.outcome=='succeeded'and policy._consumed and recovery.deletes==1
    assert lab.custody.inspect_original_response()==original and lab.checkpoint.tail==original_tail
    observed=recovery.runtime.inspect_result(removed.plan,removed.authorization)
    policy.close();recovery.now=3000
    assert recovery.runtime.inspect_result(removed.plan,removed.authorization)==observed
    assert not policy.source_guard()and not authority.execution_gate()


@pytest.mark.parametrize('fault',['default-off','no-source','wrong-requester','wrong-transport'])
def test_create_policy_denies_missing_scope_or_authenticated_identity_before_device_reads(tmp_path,monkeypatch,synthetic_key,fault):
    lab=Lab(tmp_path,synthetic_key,monkeypatch)
    authority=creator(tmp_path,lab,enabled=fault!='default-off',guard=fault!='no-source')
    before=list(lab.calls)
    with pytest.raises(M4AuthorizationDenied):
        authority.issue(requester_digest='f'*64 if fault=='wrong-requester'else REQUESTER,
            transport_digest='f'*64 if fault=='wrong-transport'else TRANSPORT)
    assert lab.calls==before and lab.store.claim_count==0 and lab.post_count==0


def test_grant_cannot_be_consumed_before_original_claim_or_bound_to_another_runtime(tmp_path,monkeypatch,synthetic_key):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);authority=creator(tmp_path,lab)
    issued=create_binding(tmp_path,lab,authority)
    with pytest.raises(M4AuthorizationDenied):authority.verify(issued.plan,issued.authorization,now_epoch=1000)
    assert not authority._consumed and lab.store.claim_count==0
    with pytest.raises(M4AuthorizationDenied):authority.bind_runtime(lab.transport)
    result=M4ExecutionKernel(lab.transport,authority,lab.store,clock=lambda:1000).execute(issued.plan,issued.authorization)
    assert result.outcome=='succeeded'and authority._consumed


@pytest.mark.parametrize('fault',['source','authority-key','witness-key','context','expiry'])
def test_issued_source_or_binding_drift_denies_before_post(tmp_path,monkeypatch,synthetic_key,fault):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);authority=creator(tmp_path,lab);issued=create_binding(tmp_path,lab,authority)
    before=list(lab.calls)
    if fault=='source':lab.source=False
    if fault=='authority-key':(tmp_path/'authority.key').write_bytes(b'x'*32)
    if fault=='witness-key':(tmp_path/'witness.key').write_bytes(b'x'*32)
    if fault=='context':authority._context['current']='f'*64
    if fault=='expiry':lab.epoch=issued.authorization.expires_at
    with pytest.raises(M4AuthorizationDenied):
        M4ExecutionKernel(lab.transport,authority,lab.store,clock=lambda:lab.epoch).execute(issued.plan,issued.authorization)
    assert lab.calls==before and lab.post_count==0 and not authority._consumed


@pytest.mark.parametrize('fault',['wrong-requester','wrong-transport','closed-policy','recovery-key','source-drift'])
def test_removal_policy_is_separate_and_cannot_reissue_or_bypass_source_checks(tmp_path,monkeypatch,synthetic_key,fault):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);authority=creator(tmp_path,lab);issued=create_binding(tmp_path,lab,authority)
    M4ExecutionKernel(lab.transport,authority,lab.store,clock=lambda:1000).execute(issued.plan,issued.authorization)
    recovery=RecoveryLab(tmp_path,lab);policy=removal(tmp_path,lab,recovery);before=list(lab.calls)
    if fault=='closed-policy':policy.close()
    if fault=='recovery-key':(recovery.directory/'authority.key').write_bytes(b'x'*32)
    if fault=='source-drift':recovery.source=False
    with pytest.raises(M4AuthorizationDenied):
        policy.issue(recovery.runtime,requester_digest='f'*64 if fault=='wrong-requester'else REQUESTER,
            transport_digest='f'*64 if fault=='wrong-transport'else TRANSPORT)
    assert lab.calls==before and recovery.store.claim_count==0 and recovery.deletes==0


def test_consumed_creation_grant_cannot_be_renewed_with_a_new_authority_instance(tmp_path,monkeypatch,synthetic_key):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);authority=creator(tmp_path,lab);issued=create_binding(tmp_path,lab,authority)
    M4ExecutionKernel(lab.transport,authority,lab.store,clock=lambda:1000).execute(issued.plan,issued.authorization)
    fresh=fresh_request(synthetic_key)
    clone=JwtManualKeyCreateLabAuthority(lab.reader,fresh,execution_store=lab.store,directory=tmp_path/'custody',
        authority_key_file=tmp_path/'authority.key',witness_key_file=tmp_path/'witness.key',**IDENTITY,
        execution_enabled=True,source_guard=lambda:True,clock=lambda:1000)
    try:
        with pytest.raises(M4AuthorizationDenied):clone.issue(requester_digest=REQUESTER,transport_digest=TRANSPORT)
    finally:fresh.close()
