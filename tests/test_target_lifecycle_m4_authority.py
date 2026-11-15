"""Fixed Target phase authority joined to the real durable M4 kernel."""
from dataclasses import replace

import pytest

from fortipam_mcp import target_lifecycle_m4_authority as a
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from v4_planning import M4AuthorizationDenied, M4ExecutionKernel, M4ExecutionPlan, canonical_digest

IDENTITY=dict(requester_digest='1'*64,transport_digest='2'*64)
OBSERVATION=dict(current_digest='7'*64,expected_digest='8'*64,dependency_digest='9'*64,source_context_digest='4'*64)


def make(phase='create',**overrides):
    now=[100]
    values=dict(phase=phase,input_digest='3'*64,source_context_digest='4'*64,
        original_creation_digest=None if phase=='create' else '5'*64,
        verified_update_digest='6'*64 if phase=='restore' else None,
        authority_key=b'k'*32,environment_ref='synthetic-environment',scope_ref='synthetic-scope',
        audience_ref='synthetic-audience',execution_enabled=True,clock=lambda:now[0],**IDENTITY)
    values.update(overrides)
    return a.TargetLifecycleM4Authority(**values),now


def preview(authority,**changes):
    values={key:value for key,value in OBSERVATION.items() if key!='source_context_digest'}
    values.update(IDENTITY);values.update(changes)
    return authority.preview(**values)


def issue(authority,value=None,**changes):
    values={**OBSERVATION,**IDENTITY};values.update(changes)
    return authority.issue(preview(authority) if value is None else value,**values)


@pytest.mark.parametrize('phase',['create','update','restore','recover'])
def test_phase_plan_actual_persistent_m4_and_replay(tmp_path,phase):
    authority,now=make(phase)
    issued=issue(authority)
    assert issued.plan.action_id=='target-lifecycle-'+phase
    assert issued.plan.compensation_ref is None
    directory=tmp_path/phase;directory.mkdir(mode=0o700)
    key=directory/'key';key.write_bytes(b's'*32);key.chmod(0o600)
    store=PersistentM4ExecutionStateStore(directory/'ledger.sqlite',key)
    class Adapter:
        dispatches=0
        def read_current(self,plan):
            authority.check_current(issued,**OBSERVATION)
            return plan.expected_current_digest
        def dispatch(self,plan):
            authority.check_current(issued,**OBSERVATION)
            self.dispatches+=1
        def read_postcondition(self,plan):return plan.expected_state_digest
    adapter=Adapter()
    kernel=M4ExecutionKernel(adapter,authority,store,clock=lambda:now[0])
    result=kernel.execute(issued.plan,issued.authorization)
    assert result.as_dict()['outcome']=='succeeded'
    assert result.as_dict()['verification']=='verified'
    # Reopen the durable ledger, keeping the still-current volatile authority.
    reopened=PersistentM4ExecutionStateStore(directory/'ledger.sqlite',key)
    result=M4ExecutionKernel(adapter,authority,reopened,clock=lambda:now[0]).execute(issued.plan,issued.authorization)
    assert adapter.dispatches==1 and result.idempotent_replay and reopened.claim_count==1


@pytest.mark.parametrize('phase',['update','restore','recover'])
def test_creation_and_update_provenance_required(phase):
    with pytest.raises(M4AuthorizationDenied):make(phase,original_creation_digest=None)
    if phase=='restore':
        with pytest.raises(M4AuthorizationDenied):make(phase,verified_update_digest=None)
    else:
        with pytest.raises(M4AuthorizationDenied):make(phase,verified_update_digest='a'*64)


@pytest.mark.parametrize('field',['input_digest','source_context_digest','requester_digest','transport_digest'])
def test_invalid_binding_denied(field):
    with pytest.raises(M4AuthorizationDenied):make(**{field:'private invalid value'})


def test_create_cannot_adopt_creation_evidence():
    with pytest.raises(M4AuthorizationDenied):make(original_creation_digest='a'*64)


@pytest.mark.parametrize('field',['current_digest','expected_digest','dependency_digest','source_context_digest','requester_digest','transport_digest'])
def test_fresh_issue_observation_and_identity_drift_denied(field):
    authority,now=make();value=preview(authority)
    with pytest.raises(M4AuthorizationDenied):issue(authority,value,**{field:'a'*64})


@pytest.mark.parametrize('field',list(OBSERVATION))
def test_predispatch_drift_denied(field):
    authority,now=make();issued=issue(authority)
    with pytest.raises(M4AuthorizationDenied):authority.check_current(issued,**{**OBSERVATION,field:'a'*64})


@pytest.mark.parametrize('field',['input_digest','source_context_digest','environment_ref','scope_ref','audience_ref','requester_digest','transport_digest','authority_key'])
def test_cross_binding_or_key_cannot_verify(field):
    authority,now=make();issued=issue(authority)
    changed=b'x'*32 if field=='authority_key' else 'other-namespace' if field.endswith('_ref') else 'a'*64
    other,_=make(**{field:changed})
    identity={**IDENTITY}
    if field in identity:identity[field]=changed
    other_preview=preview(other,**identity)
    other_issued=issue(other,other_preview,**identity,
        source_context_digest='a'*64 if field=='source_context_digest' else OBSERVATION['source_context_digest'])
    other.verify(other_issued.plan,other_issued.authorization,now_epoch=100)
    with pytest.raises(M4AuthorizationDenied):other.verify(issued.plan,issued.authorization,now_epoch=100)


def test_phase_separation_and_tampering():
    authority,now=make('update');issued=issue(authority)
    other,_=make('recover');issue(other)
    with pytest.raises(M4AuthorizationDenied):other.verify(issued.plan,issued.authorization,now_epoch=100)
    content=issued.plan.canonical_content();content['parameters_digest']='a'*64
    forged=M4ExecutionPlan(**content,plan_digest=canonical_digest(content))
    with pytest.raises(M4AuthorizationDenied):authority.verify(forged,issued.authorization,now_epoch=100)
    with pytest.raises(M4AuthorizationDenied):authority.verify(replace(issued.plan),issued.authorization,now_epoch=100)


def test_default_gate_close_and_new_preview_invalidate_authorization():
    disabled,now=make(execution_enabled=False)
    with pytest.raises(M4AuthorizationDenied):issue(disabled)
    authority,now=make();old=preview(authority);issued=issue(authority,old)
    with pytest.raises(M4AuthorizationDenied):issue(authority,old)
    preview(authority)
    with pytest.raises(M4AuthorizationDenied):authority.verify(issued.plan,issued.authorization,now_epoch=100)
    with pytest.raises(M4AuthorizationDenied):issue(authority,old)
    fresh=issue(authority)
    authority.close()
    with pytest.raises(M4AuthorizationDenied):authority.verify(fresh.plan,fresh.authorization,now_epoch=100)
    with pytest.raises(M4AuthorizationDenied):issue(authority)


@pytest.mark.parametrize('fault',['expired','rollback','bool','future-epoch','old-epoch'])
def test_time_boundary_and_backdating(fault):
    authority,now=make();issued=issue(authority)
    epoch=100
    if fault=='expired':now[0]=160
    elif fault=='rollback':now[0]=99
    elif fault=='bool':now[0]=True
    elif fault=='future-epoch':epoch=101
    elif fault=='old-epoch':epoch=99
    with pytest.raises(M4AuthorizationDenied) as error:authority.verify(issued.plan,issued.authorization,now_epoch=epoch)
    assert str(error.value)==a._ERROR and error.value.__suppress_context__
    if fault in ('rollback','bool'):
        now[0]=100
        with pytest.raises(M4AuthorizationDenied):authority.verify(issued.plan,issued.authorization,now_epoch=100)
