"""Configuration, selected capture and cleanup through separate local M4 domains."""
from dataclasses import replace

import pytest

from fortipam_mcp.system_email_delivery_contract import SystemEmailCaptureObservation,SystemEmailDeliveryBinding
from fortipam_mcp.system_email_delivery_m4_adapter import (
    SystemEmailDeliveryInspection,SystemEmailDeliveryM4Adapter,delivery_execution_digests,
)
from fortipam_mcp.system_email_local_workflow import SystemEmailLocalWorkflow
from fortipam_mcp.system_email_m4_adapter import SystemEmailBackendReceipt,system_email_execution_digests
from test_system_email_local_workflow import Authority,IDENTITY,run
from test_system_email_m4_adapter import BINDING,REQUESTER,Backend,Clock,store_at,transition
from v4_planning import canonical_digest


class DeliveryBackend:
    """Synthetic capture/queue; no mail client or native receiver source."""
    def __init__(self,configuration,clock,fault='none'):
        self.configuration=configuration;self.clock=clock;self.fault=fault
        self.reads=0;self.sends=0;self.messages=0;self.pending=0;self.guards=[]
    def inspect(self,binding):
        self.reads+=1
        if self.fault=='late-capture'and self.reads==3:self.messages=1
        capture=SystemEmailCaptureObservation(binding.capture_scope_digest,binding.recipient_digest,
            'e'*64,self.messages,not(self.sends and self.fault=='incomplete'))
        if self.sends and self.fault=='foreign-capture':capture=replace(capture,capture_scope_digest='f'*64)
        return SystemEmailDeliveryInspection(self.configuration.peer.source().read_empty_auth_payload(),
            capture,self.pending,True)
    def send_test(self,binding,*,before_send,timeout_seconds):
        assert timeout_seconds>0
        self.guards.append(before_send)
        if self.fault=='expired-send':self.clock.value+=60
        if self.fault!='skip-guard':assert before_send()>0
        self.sends+=1
        self.messages=0 if self.fault=='empty'else 2 if self.fault=='duplicate'else 1
        if self.fault=='inflight':self.pending=1
        if self.fault=='timeout':raise TimeoutError('SYNTHETIC_PRIVATE_MAIL_ERROR')
        if self.fault=='receipt':return SystemEmailBackendReceipt('f'*64,binding.request_digest)
        return SystemEmailBackendReceipt(binding.source_serial_digest,binding.request_digest)


def make_delivery(tmp_path,*,fault='none',enabled=True,store_fault=None):
    configuration=Backend();clock=Clock();change=transition(configuration)
    store=store_at(tmp_path)
    root=tmp_path/'delivery';root.mkdir(mode=0o700)
    if store_fault=='same-store':delivery_store=store
    else:
        delivery_store=store_at(root,
            key_material=b'synthetic-system-email-state-key-01'if store_fault=='same-key'else b'synthetic-mail-delivery-state-key-02',
            store_ref='system-email-local-test-ledger'if store_fault=='same-ref'else'system-email-local-delivery-ledger')
    context=canonical_digest({'binding':BINDING,'requester':REQUESTER,'transport':IDENTITY['transport_digest']})
    binding=SystemEmailDeliveryBinding('a'*48,'b'*64,change.original.source_serial_digest,
        system_email_execution_digests(change,context)[1])
    delivery=DeliveryBackend(configuration,clock,fault)
    authority=Authority()
    workflow=SystemEmailLocalWorkflow(change,configuration,store,binding_digest=BINDING,
        allowed_requester_digest=REQUESTER,allowed_transport_digest=IDENTITY['transport_digest'],
        authority=authority,update_enabled=True,restore_enabled=True,clock=clock,
        delivery_binding=binding,delivery_backend=delivery,delivery_store=delivery_store,
        delivery_enabled=enabled)
    return workflow,configuration,delivery,store,delivery_store,clock


def test_configure_send_restore_parent_is_locally_verified_only(tmp_path):
    workflow,configuration,delivery,store,send_store,_=make_delivery(tmp_path)
    assert workflow.outcome(**IDENTITY)['workflow_outcome']=='incomplete'
    for phase in('update','test-delivery','restore'):
        result,authorization=run(workflow,phase)
        assert result['outcome']=='succeeded'and result['native_backend_qualified']is False
        assert workflow.execute(phase,authorization['authorization_ref'],**IDENTITY)['idempotent_replay']
    result=workflow.outcome(**IDENTITY)
    assert result['workflow_outcome']=='verified_locally'
    assert result['phase_verified_locally']=={'update':True,'test-delivery':True,'restore':True}
    assert result['native_delivery_qualified']is False and result['raw_message_content_returned']is False
    assert store.claim_count==2 and send_store.claim_count==1
    assert len(configuration.submissions)==2 and delivery.sends==1
    assert len(store.audit_events)==2 and len(send_store.audit_events)==1
    for phase in('update','test-delivery','restore'):
        with pytest.raises(ValueError):workflow.preview(phase,**IDENTITY)


def test_delivery_requires_original_verified_configuration_before_capture_reads(tmp_path):
    workflow,_,delivery,_,send_store,_=make_delivery(tmp_path)
    with pytest.raises(ValueError):workflow.preview('test-delivery',**IDENTITY)
    assert delivery.reads==0 and delivery.sends==0 and send_store.claim_count==0


@pytest.mark.parametrize('foreign_binding',['requester','context'])
def test_delivery_grant_cannot_switch_original_operator_or_client_namespace(tmp_path,foreign_binding):
    from v4_planning import M4AdapterDenied
    workflow,_,delivery,_,send_store,clock=make_delivery(tmp_path)
    run(workflow,'update');workflow.preview('test-delivery',**IDENTITY)
    request=workflow._previews['test-delivery']
    requester=REQUESTER;context=workflow._binding
    if foreign_binding=='requester':
        requester='f'*64;request=replace(request,requester_digest=requester)
    else:
        context='f'*64
        current,expected,parameters=delivery_execution_digests(
            workflow._delivery_binding,workflow._delivery_baseline,context)
        request=replace(request,parameters_digest=parameters,
            expected_current_digest=current,expected_state_digest=expected)
    # The synthetic independent authority issues an internally consistent grant
    # for the foreign context; it cannot adopt the original configuration receipt.
    authority=Authority();plan,authorization=authority.authorize(request)
    reads=delivery.reads
    with pytest.raises(M4AdapterDenied):
        SystemEmailDeliveryM4Adapter(workflow._delivery_binding,workflow._delivery_baseline,
            workflow._original_update(),delivery,plan,authorization,send_store,
            context_digest=context,allowed_requester_digest=requester,
            authorization_verifier=authority,execution_enabled=True,clock=clock)
    assert delivery.reads==reads and delivery.sends==0 and send_store.claim_count==0


def test_delivery_has_its_own_closed_gate(tmp_path):
    workflow,_,delivery,_,send_store,_=make_delivery(tmp_path,enabled=False)
    run(workflow,'update');preview=workflow.preview('test-delivery',**IDENTITY)
    with pytest.raises(ValueError):workflow.authorize('test-delivery',preview['preview_ref'],**IDENTITY)
    assert delivery.sends==0 and send_store.claim_count==0
    assert run(workflow,'restore')[0]['outcome']=='succeeded'


@pytest.mark.parametrize('fault',['same-store','same-key','same-ref'])
def test_configuration_and_delivery_cannot_share_ledger_key_or_anchor_namespace(tmp_path,fault):
    with pytest.raises(ValueError):make_delivery(tmp_path,store_fault=fault)


@pytest.mark.parametrize('fault',['timeout','receipt','empty','duplicate','incomplete','skip-guard'])
def test_failed_delivery_is_not_replayed_or_promoted_by_independent_cleanup(tmp_path,fault):
    workflow,configuration,delivery,store,send_store,_=make_delivery(tmp_path,fault=fault)
    run(workflow,'update');result,authorization=run(workflow,'test-delivery')
    assert result['outcome']!='succeeded'and delivery.sends==1
    assert workflow.execute('test-delivery',authorization['authorization_ref'],**IDENTITY)['idempotent_replay']
    with pytest.raises(ValueError):workflow.preview('test-delivery',**IDENTITY)
    assert run(workflow,'restore')[0]['outcome']=='succeeded'
    result=workflow.outcome(**IDENTITY)
    assert result['workflow_outcome']=='reconciliation_required'
    assert result['phase_verified_locally']['restore']is True
    assert result['phase_verified_locally']['test-delivery']is False
    assert store.claim_count==2 and send_store.claim_count==1
    assert len(configuration.submissions)==2 and delivery.sends==1


def test_unknown_send_requires_independently_observed_quiescence_before_cleanup(tmp_path):
    workflow,_,delivery,store,send_store,_=make_delivery(tmp_path,fault='inflight')
    run(workflow,'update');result,_=run(workflow,'test-delivery')
    assert result['outcome']=='reconciliation_required'
    with pytest.raises(ValueError):workflow.preview('restore',**IDENTITY)
    assert store.claim_count==1
    delivery.pending=0
    assert run(workflow,'restore')[0]['outcome']=='succeeded'
    assert workflow.outcome(**IDENTITY)['phase_verified_locally']['test-delivery']is False
    assert send_store.claim_count==1 and delivery.sends==1


def test_restore_rechecks_queue_at_egress_and_never_retries_consumed_restore(tmp_path):
    workflow,configuration,delivery,store,send_store,_=make_delivery(tmp_path)
    run(workflow,'update');run(workflow,'test-delivery')
    preview=workflow.preview('restore',**IDENTITY)
    authorization=workflow.authorize('restore',preview['preview_ref'],**IDENTITY)
    delivery.pending=1
    result=workflow.execute('restore',authorization['authorization_ref'],**IDENTITY)
    assert result['outcome']!='succeeded'and len(configuration.submissions)==1
    delivery.pending=0
    assert workflow.execute('restore',authorization['authorization_ref'],**IDENTITY)['idempotent_replay']
    with pytest.raises(ValueError):workflow.preview('restore',**IDENTITY)
    assert store.claim_count==2 and send_store.claim_count==1


def test_foreign_capture_source_blocks_cleanup_instead_of_guessing_quiescence(tmp_path):
    workflow,_,delivery,store,_,_=make_delivery(tmp_path,fault='foreign-capture')
    run(workflow,'update');assert run(workflow,'test-delivery')[0]['outcome']!='succeeded'
    with pytest.raises(ValueError):workflow.preview('restore',**IDENTITY)
    assert delivery.sends==1 and store.claim_count==1


def test_saved_send_guard_cannot_leave_original_kernel_scope(tmp_path):
    from v4_planning import M4AuthorizationDenied
    workflow,_,delivery,_,_,_=make_delivery(tmp_path)
    run(workflow,'update');run(workflow,'test-delivery')
    with pytest.raises(M4AuthorizationDenied):delivery.guards[0]()
    assert delivery.sends==1


def test_delivery_cannot_dispatch_directly_without_kernel_claim(tmp_path):
    from v4_planning import M4AuthorizationDenied
    workflow,_,delivery,_,send_store,_=make_delivery(tmp_path)
    run(workflow,'update')
    preview=workflow.preview('test-delivery',**IDENTITY)
    authorization=workflow.authorize('test-delivery',preview['preview_ref'],**IDENTITY)
    adapter=workflow._adapters['test-delivery'];plan,_=workflow._issued['test-delivery']
    with pytest.raises(M4AuthorizationDenied):adapter.dispatch(plan)
    assert delivery.sends==0 and send_store.claim_count==0
    assert workflow.execute('test-delivery',authorization['authorization_ref'],**IDENTITY)['outcome']=='succeeded'
    assert delivery.sends==1 and send_store.claim_count==1


@pytest.mark.parametrize('fault',['late-capture','expired-send'])
def test_delivery_rechecks_capture_and_expiry_immediately_before_send(tmp_path,fault):
    workflow,_,delivery,_,send_store,_=make_delivery(tmp_path,fault=fault)
    run(workflow,'update');result,_=run(workflow,'test-delivery')
    assert result['outcome']!='succeeded'and delivery.sends==0
    assert send_store.claim_count==1


def test_delivery_checkpoint_prevents_valid_old_state_from_reopening_send_slot(tmp_path):
    from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStoreError
    workflow,_,delivery,_,send_store,_=make_delivery(tmp_path)
    run(workflow,'update')
    saved={p:p.read_bytes()for p in send_store._path.parent.iterdir()if p.is_file()}
    run(workflow,'test-delivery')
    for path,raw in saved.items():path.write_bytes(raw)
    with pytest.raises(ValueError):workflow.preview('test-delivery',**IDENTITY)
    with pytest.raises(ValueError):workflow.outcome(**IDENTITY)
    with pytest.raises(PersistentM4ExecutionStoreError):send_store.verify_ready()
    assert delivery.sends==1
