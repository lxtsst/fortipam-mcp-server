"""Local workflow authority, identity and single-use behavior; no appliance."""
import json

import pytest

from fortipam_mcp.system_email_local_workflow import SystemEmailLocalWorkflow
from fortipam_mcp.system_email_m4_adapter import CONTRACT as ADAPTER_CONTRACT
from test_system_email_m4_adapter import (
    BINDING,REQUESTER,Backend,Clock,store_at,transition,
)
from v4_planning import (
    M4AuthorizationDenied,M4ExecutionAuthorization,M4ExecutionPlan,canonical_digest,
)

IDENTITY=dict(requester_digest=REQUESTER,transport_digest='7'*64)


class Authority:
    """Synthetic independent authority; never a production issuer."""
    def __init__(self,fault=None):self.requests=[];self.pairs=[];self.fault=fault
    def authorize(self,request):
        self.requests.append(request)
        phase=request.phase
        fields=dict(plan_ref='system-email-'+phase+'-'+request.parameters_digest,revision=1,
            action_id='system-email-'+phase,action_version='1.0.0',adapter_ref=request.adapter_ref,
            target_ref=request.target_ref,requester_digest=request.requester_digest,
            summary_digest=request.summary_digest,confirmation_digest='4'*64,approval_digest='5'*64,
            parameters_digest=request.parameters_digest,expected_current_digest=request.expected_current_digest,
            expected_state_digest=request.expected_state_digest,
            idempotency_digest=canonical_digest({'binding':request.parameters_digest,'phase':phase}),
            expires_at=request.expires_at,compensation_ref=None)
        if self.fault:fields.update(self.fault)
        plan=M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
        fields=dict(authorization_ref='local-email-auth-'+str(len(self.requests)),plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest,requester_digest=plan.requester_digest,
            confirmation_ref='local-email-intent-ref',confirmation_digest=plan.confirmation_digest,
            approval_ref='local-email-approval-ref',approval_digest=plan.approval_digest,
            approver_digest='6'*64,issued_at=request.created_at,expires_at=plan.expires_at,
            one_time=True,execution_authorized=True)
        authorization=M4ExecutionAuthorization(**fields,authorization_digest=canonical_digest(fields))
        self.pairs.append((plan,authorization));return plan,authorization
    def verify(self,plan,authorization,*,now_epoch):
        if not any(plan is p and authorization is a for p,a in self.pairs):
            raise M4AuthorizationDenied('denied')


def make(tmp_path,*,authority=None,update=True,restore=True,fault='none'):
    clock=Clock();backend=Backend(fault,clock);change=transition(backend);store=store_at(tmp_path)
    workflow=SystemEmailLocalWorkflow(change,backend,store,binding_digest=BINDING,
        allowed_requester_digest=REQUESTER,allowed_transport_digest=IDENTITY['transport_digest'],
        authority=authority,update_enabled=update,restore_enabled=restore,clock=clock)
    return workflow,backend,store,clock,change


def run(workflow,phase):
    preview=workflow.preview(phase,**IDENTITY)
    authorization=workflow.authorize(phase,preview['preview_ref'],**IDENTITY)
    return workflow.execute(phase,authorization['authorization_ref'],**IDENTITY),authorization


def test_complete_local_workflow_uses_two_independent_m4_claims(tmp_path):
    authority=Authority();workflow,backend,store,_,_=make(tmp_path,authority=authority)
    result,authorization=run(workflow,'update')
    assert result['outcome']=='succeeded'and result['native_backend_qualified']is False
    assert workflow.execute('update',authorization['authorization_ref'],**IDENTITY)['idempotent_replay']
    result,authorization=run(workflow,'restore')
    assert result['outcome']=='succeeded'
    assert workflow.execute('restore',authorization['authorization_ref'],**IDENTITY)['idempotent_replay']
    assert len(backend.submissions)==2 and store.claim_count==2
    assert len(authority.requests)==2 and authority.requests[0].phase=='update'
    assert authority.requests[1].phase=='restore'
    with pytest.raises(ValueError):workflow.preview('update',**IDENTITY)
    with pytest.raises(ValueError):workflow.preview('restore',**IDENTITY)
    workflow.close()
    assert store.claim_count==2
    with pytest.raises(ValueError):workflow.execute('restore',authorization['authorization_ref'],**IDENTITY)


@pytest.mark.parametrize('field',['requester_digest','transport_digest'])
def test_wrong_identity_is_refused_before_sources_or_authority(tmp_path,field):
    authority=Authority();workflow,backend,store,_,_=make(tmp_path,authority=authority)
    identity={**IDENTITY,field:'f'*64}
    with pytest.raises(ValueError):workflow.preview('update',**identity)
    assert backend.reads==0 and authority.requests==[]and store.claim_count==0


def test_default_authority_does_not_promote_preview_into_authorization(tmp_path):
    workflow,backend,store,_,_=make(tmp_path)
    preview=workflow.preview('update',**IDENTITY)
    assert preview['configuration_write_authorized']is False
    assert preview['smtp_send_authorized']is False
    assert 'capture.example.test'not in json.dumps(preview)
    with pytest.raises(ValueError):workflow.authorize('update',preview['preview_ref'],**IDENTITY)
    assert backend.submissions==[]and store.claim_count==0


def test_closed_update_gate_never_calls_authority(tmp_path):
    authority=Authority();workflow,backend,store,_,_=make(tmp_path,authority=authority,update=False)
    preview=workflow.preview('update',**IDENTITY)
    with pytest.raises(ValueError):workflow.authorize('update',preview['preview_ref'],**IDENTITY)
    assert authority.requests==[]and backend.submissions==[]and store.claim_count==0


def test_unused_authorization_is_invalidated_by_a_new_preview(tmp_path):
    authority=Authority();workflow,backend,store,_,_=make(tmp_path,authority=authority)
    first=workflow.preview('update',**IDENTITY)
    old=workflow.authorize('update',first['preview_ref'],**IDENTITY)
    second=workflow.preview('update',**IDENTITY)
    with pytest.raises(ValueError):workflow.execute('update',old['authorization_ref'],**IDENTITY)
    with pytest.raises(ValueError):workflow.authorize('update',first['preview_ref'],**IDENTITY)
    new=workflow.authorize('update',second['preview_ref'],**IDENTITY)
    with pytest.raises(ValueError):workflow.authorize('update',second['preview_ref'],**IDENTITY)
    assert workflow.execute('update',new['authorization_ref'],**IDENTITY)['outcome']=='succeeded'
    assert len(backend.submissions)==1 and store.claim_count==1


def test_expired_unconsumed_preview_can_only_be_replaced_by_fresh_observation(tmp_path):
    workflow,backend,store,clock,_=make(tmp_path,authority=Authority())
    first=workflow.preview('update',**IDENTITY);clock.value=first['expires_at']
    with pytest.raises(ValueError):workflow.authorize('update',first['preview_ref'],**IDENTITY)
    fresh=workflow.preview('update',**IDENTITY)
    assert fresh['preview_ref']!=first['preview_ref']and backend.reads==2
    assert store.claim_count==0


@pytest.mark.parametrize('fault',[
    {'summary_digest':'f'*64},{'parameters_digest':'f'*64},{'expected_current_digest':'f'*64},
    {'expected_state_digest':'f'*64},{'target_ref':'foreign-system-email-target'},
    {'requester_digest':'f'*64},{'expires_at':2000},
])
def test_authority_response_must_match_the_exact_preview_tuple(tmp_path,fault):
    workflow,backend,store,_,_=make(tmp_path,authority=Authority(fault))
    preview=workflow.preview('update',**IDENTITY)
    with pytest.raises(ValueError):workflow.authorize('update',preview['preview_ref'],**IDENTITY)
    assert backend.submissions==[]and store.claim_count==0


@pytest.mark.parametrize('fault',['timeout','post-read','partial','receipt-missing'])
def test_failed_update_cannot_start_another_update_or_restore(tmp_path,fault):
    workflow,backend,store,_,_=make(tmp_path,authority=Authority(),fault=fault)
    result,authorization=run(workflow,'update')
    assert result['outcome']!='succeeded'
    assert workflow.execute('update',authorization['authorization_ref'],**IDENTITY)['idempotent_replay']
    with pytest.raises(ValueError):workflow.preview('update',**IDENTITY)
    with pytest.raises(ValueError):workflow.preview('restore',**IDENTITY)
    assert len(backend.submissions)==1 and store.claim_count==1


def test_successful_ledger_alone_cannot_import_restore_ownership(tmp_path):
    authority=Authority();workflow,backend,store,clock,change=make(tmp_path,authority=authority)
    assert run(workflow,'update')[0]['outcome']=='succeeded'
    other=SystemEmailLocalWorkflow(change,backend,store,binding_digest=BINDING,
        allowed_requester_digest=REQUESTER,allowed_transport_digest=IDENTITY['transport_digest'],
        authority=authority,update_enabled=True,restore_enabled=True,clock=clock)
    reads=backend.reads
    with pytest.raises(ValueError):other.preview('restore',**IDENTITY)
    with pytest.raises(ValueError):other.preview('update',**IDENTITY)
    assert backend.reads==reads and len(backend.submissions)==1


def test_restore_gate_is_separate_and_clock_rollback_closes_the_workflow(tmp_path):
    workflow,backend,store,clock,_=make(tmp_path,authority=Authority(),restore=False)
    run(workflow,'update')
    preview=workflow.preview('restore',**IDENTITY)
    with pytest.raises(ValueError):workflow.authorize('restore',preview['preview_ref'],**IDENTITY)
    clock.value=999
    with pytest.raises(ValueError):workflow.preview('restore',**IDENTITY)
    clock.value=1000
    with pytest.raises(ValueError):workflow.preview('restore',**IDENTITY)
    assert len(backend.submissions)==1 and store.claim_count==1
