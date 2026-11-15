"""Folder custody writes only inside the real original persistent M4 dispatch."""
import json

import pytest
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4ExecutionPlan, canonical_digest

from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.windows_execution_folder_custody import (
    ACTION_ID, ADAPTER_REF, WindowsExecutionFolderCustody, WindowsExecutionFolderCustodyError,
)
from fortipam_mcp.windows_execution_folder_sources import WindowsFolderSourceError
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier, REQUESTER, CONFIRMATION, APPROVAL
from test_windows_execution_folder_sources import make
from test_windows_execution_policy_contract import envelope


def prepare(tmp_path,monkeypatch):
    source,api,policy,*_=make(tmp_path,monkeypatch)
    observed=source.observe_absence()
    root=tmp_path/'folder-original';root.mkdir(mode=0o700)
    (root/'state').mkdir(mode=0o700)
    for name,value in (('execution.key',b't'*32),('witness.key',b'k'*32)):
        (root/name).write_bytes(value);(root/name).chmod(0o600)
    checkpoint=_ExternalM4Checkpoint()
    store=PersistentM4ExecutionStateStore(root/'execution.sqlite',root/'execution.key',
        monotonic_checkpoint=checkpoint,checkpoint_store_ref=CHECKPOINT_STORE_REF)
    fields=dict(plan_ref='explicit-folder-original-plan-01',revision=1,action_id=ACTION_ID,action_version='1.0.0',
        adapter_ref=ADAPTER_REF,target_ref='bound-explicit-windows-folder',requester_digest=REQUESTER,
        summary_digest='9'*64,confirmation_digest=CONFIRMATION,approval_digest=APPROVAL,
        parameters_digest=source._request.request_digest,expected_current_digest=observed.current_digest,
        expected_state_digest=source._request.expected_state_digest,idempotency_digest='3'*64,
        expires_at=1300,compensation_ref=None)
    plan=M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields));auth=_authorization(plan)
    custody=WindowsExecutionFolderCustody(root/'state',root/'witness.key',source._request,observed.current_digest,
        plan,auth,store,sources=source,clock=lambda:1000)
    return source,api,policy,custody,store,plan,auth


class Adapter:
    def __init__(self,source,api,custody,*,fault=None):
        self.source,self.api,self.custody,self.fault=source,api,custody,fault;self.sends=0

    def read_current(self,plan):
        return self.source.observe_absence().current_digest

    def dispatch(self,plan):
        try:
            self.custody.begin_original_send();self.sends+=1;self.api.present=True
            if self.fault=='lost-ack':raise M4AdapterAmbiguous('Synthetic missing original ACK.')
            raw=envelope([],name='folder',http_method='POST',status='OK',mkey=41,error=0)
            self.custody.capture_original_ack(raw,http_status=200,content_type='application/json')
            if self.fault=='after-ack':raise M4AdapterAmbiguous('Synthetic original state unavailable.')
            self.source.observe_candidate_presence(41)
            self.custody.capture_created_state()
            if self.fault=='after-seal':raise M4AdapterAmbiguous('Synthetic original postcondition unavailable.')
        except (WindowsExecutionFolderCustodyError,WindowsFolderSourceError):
            raise M4AdapterAmbiguous('Synthetic original Folder custody failure.') from None

    def read_postcondition(self,plan):
        self.source.check_current(self.source._current)
        assert self.custody.inspect_created_state().created_state_digest==self.source._current.state_digest
        return plan.expected_state_digest


def execute(source,api,custody,store,plan,auth,*,fault=None):
    adapter=Adapter(source,api,custody,fault=fault)
    result=M4ExecutionKernel(adapter,_Verifier(),store,clock=lambda:1000).execute(plan,auth)
    return adapter,result


def test_original_numeric_id_ack_and_complete_state_are_sealed_and_readable_after_close(tmp_path,monkeypatch):
    source,api,policy,custody,store,plan,auth=prepare(tmp_path,monkeypatch)
    adapter,result=execute(source,api,custody,store,plan,auth)
    assert str(result.outcome)=='succeeded' and str(result.verification)=='verified' and adapter.sends==1
    original=custody.inspect_created_state()
    assert original.native_folder_id==41 and original.native_ack_status=='OK' and original.created_state_digest
    before={p.name:p.read_bytes() for p in custody._directory.iterdir()}
    assert set(before)=={'send.claim.json','create-ack.json','created-state.json'}
    assert not any(source._raw)
    owned=source.observe_owned(custody)
    assert owned.state_digest==original.created_state_digest and not any(source._raw)
    custody.close();source.close();policy.close()
    assert custody.inspect_created_state()==original
    assert {p.name:p.read_bytes() for p in custody._directory.iterdir()}==before
    with pytest.raises(WindowsExecutionFolderCustodyError):custody.begin_original_send()


@pytest.mark.parametrize('fault',['lost-ack','after-ack','after-seal'])
def test_unknown_cannot_replay_or_backfill_original_records(tmp_path,monkeypatch,fault):
    source,api,policy,custody,store,plan,auth=prepare(tmp_path,monkeypatch)
    adapter,result=execute(source,api,custody,store,plan,auth,fault=fault)
    assert str(result.outcome)=='reconciliation_required' and str(result.verification)=='unknown'
    before={p.name:p.read_bytes() for p in custody._directory.iterdir()}
    if fault=='after-seal':
        assert custody.inspect_created_state().original_outcome=='reconciliation_required'
    else:
        with pytest.raises(WindowsExecutionFolderCustodyError):custody.inspect_created_state()
        with pytest.raises(WindowsFolderSourceError):source.observe_owned(custody)
    if fault=='after-ack':
        assert custody.inspect_original_ack().native_folder_id==41
    with pytest.raises(WindowsExecutionFolderCustodyError):custody.capture_created_state()
    second=M4ExecutionKernel(adapter,_Verifier(),store,clock=lambda:1000).execute(plan,auth)
    assert str(second.outcome)!='succeeded' and adapter.sends==1 and store.claim_count==1
    assert {p.name:p.read_bytes() for p in custody._directory.iterdir()}==before
    custody.close();source.close();policy.close()


def test_no_active_m4_or_forged_native_id_can_establish_ownership(tmp_path,monkeypatch):
    source,api,policy,custody,store,plan,auth=prepare(tmp_path,monkeypatch)
    with pytest.raises(WindowsExecutionFolderCustodyError):custody.begin_original_send()
    assert not list(custody._directory.iterdir()) and store.claim_count==0
    source.close();policy.close()


def test_original_signed_selector_and_source_context_rebinding_refuse(tmp_path,monkeypatch):
    source,api,policy,custody,store,plan,auth=prepare(tmp_path,monkeypatch)
    _,result=execute(source,api,custody,store,plan,auth)
    assert str(result.outcome)=='succeeded'
    path=custody._directory/'create-ack.json';before=path.read_bytes()
    value=json.loads(before);value['native_folder_id']=42;path.write_text(json.dumps(value));path.chmod(0o600)
    with pytest.raises(WindowsExecutionFolderCustodyError):custody.inspect_original_ack()
    path.write_bytes(before);path.chmod(0o600)
    source._source='f'*64
    with pytest.raises(WindowsExecutionFolderCustodyError):custody.inspect_created_state()
    custody.close();source.close();policy.close()
