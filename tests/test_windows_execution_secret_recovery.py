"""Independent M4 removal with complete synthetic private-source evidence."""
from dataclasses import replace
import ssl

import pytest

from fortipam_mcp import windows_execution_secret_recovery as r
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_m4_execution_store import _ExternalM4Checkpoint
from test_windows_execution_secret_preservation import setup as source_setup, reader, Source
from test_windows_execution_secret_contract import SERIAL, raw
from test_windows_execution_secret_ack import fixture
from test_windows_execution_secret_material import execute
from test_secret_create_m4_runtime import _Reader
from fortipam_mcp import windows_execution_secret_preservation as p
from test_web_secret_create_ack import AckResponse
from test_secret_create_m4_runtime import _secret_plan, _authorization
from v4_planning import M4Outcome, M4AdapterAmbiguous, canonical_digest


class Verifier:
    def __init__(self): self.calls=0
    def verify(self,plan,authorization,*,now_epoch):
        assert authorization.plan_digest==plan.plan_digest
        assert authorization.issued_at<=now_epoch<authorization.expires_at
        self.calls+=1


class Socket:
    def settimeout(self,value): assert 0<value<=10


class Connection:
    def __init__(self, owner, fault=None):
        self.owner,self.fault=owner,fault
        self.sock=None;self.closed=False;self.method=None
    def connect(self): self.sock=Socket()
    def request(self,method,path,headers):
        assert method in ('DELETE','GET')
        assert path==('/api/v2/cmdb/secret/database/43?format=id&vdom=root' if method=='GET' else '/api/v2/cmdb/secret/database/43?vdom=root')
        assert headers['Authorization']=='Bearer synthetic-api-token'
        self.owner.append(method);self.method=method
        if self.fault=='send':raise OSError('Synthetic send uncertainty.')
        if self.fault=='crash':raise KeyboardInterrupt
    def getresponse(self):
        method=self.method
        value=dict(version='v7.0.0',build=29,http_method=method,http_status=404 if method=='GET' else 200,
            status='Not Found' if method=='GET' else 'success',path='secret',name='database',vdom='root',serial=SERIAL)
        if method=='GET':value['error']=2
        else:value.update(mkey=43,error=0)
        response=AckResponse(raw(value));response.status=value['http_status']
        if self.fault=='delete-status' and method=='DELETE':response.status=500
        if self.fault=='absence-status' and method=='GET':response.status=200
        if self.fault=='wrong-id' and method=='DELETE':value['mkey']=44;response.payload=raw(value)
        if self.fault=='chunked':response.headers['Transfer-Encoding']='chunked'
        if self.fault=='close-response':response.failure='response_close'
        return response
    def close(self): self.closed=True


def components(tmp_path,monkeypatch,*,enabled=True,fault=None,verifier=True,now=2000,original_unknown=False):
    if original_unknown:
        missing=_Reader()
        missing.read_postcondition=lambda plan:(_ for _ in ()).throw(M4AdapterAmbiguous('Synthetic missing read.'))
        cmp=fixture(tmp_path,reader=missing)
        assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
        monkeypatch.setattr(p,'_ssl_context',lambda config:ssl.create_default_context())
    else:
        cmp=source_setup(tmp_path,monkeypatch)
    cmp['now'][0]=now
    original=cmp['custody'].inspect_original_creation()
    source=Source();reader(cmp,source).read_once()
    for name,key in (('remove.key',b'r'*32),('remove-witness.key',b'w'*32)):
        path=tmp_path/name;path.write_bytes(key);path.chmod(0o600)
    store=PersistentM4ExecutionStateStore(tmp_path/'remove.sqlite',tmp_path/'remove.key',
        monotonic_checkpoint=_ExternalM4Checkpoint('windows-removal-state'),checkpoint_store_ref='windows-removal-state')
    methods,connections=[],[]
    def factory(*args,**kwargs):
        assert kwargs['context'].check_hostname and kwargs['context'].verify_mode==ssl.CERT_REQUIRED
        connection=Connection(methods,fault);connections.append(connection);return connection
    monkeypatch.setattr(r,'_ssl_context',lambda config:ssl.create_default_context())
    auth_verifier=Verifier() if verifier else None
    kwargs=dict(execution_store=store,witness_key_file=tmp_path/'remove-witness.key',
        authorization_verifier=auth_verifier,execution_enabled=enabled,client_factory=source.factory,
        connection_factory=factory,clock=lambda:now,http_clock=lambda:0)
    recovery=r.WindowsExecutionSecretRecovery(cmp['custody'],**kwargs)
    cmp.update(recovery=recovery,recovery_kwargs=kwargs,remove_store=store,source=source,
        methods=methods,connections=connections,original=original,epoch=now,verifier=auth_verifier)
    return cmp


def authorize(cmp):
    preview=cmp['recovery'].preview()
    base=_secret_plan()
    fields={**base.canonical_content(),'action_id':r.ACTION_ID,'action_version':'1.0.0',
        'adapter_ref':r.ADAPTER_REF,'target_ref':r.TARGET_REF,'parameters_digest':preview.parameters_digest,
        'expected_current_digest':preview.current_digest,'expected_state_digest':preview.expected_digest,
        'expires_at':preview.expires_at}
    plan=replace(base,**{key:fields[key] for key in ('action_id','action_version','adapter_ref','target_ref',
        'parameters_digest','expected_current_digest','expected_state_digest','expires_at')},plan_digest=canonical_digest(fields))
    authorization=_authorization(plan)
    values={**authorization.canonical_content(),'issued_at':cmp['epoch']-1,'expires_at':plan.expires_at}
    authorization=replace(authorization,issued_at=values['issued_at'],expires_at=values['expires_at'],
        authorization_digest=canonical_digest(values))
    return plan,authorization


def test_expired_original_create_has_independent_recovery_without_material_reload_or_original_promotion(tmp_path,monkeypatch):
    cmp=components(tmp_path,monkeypatch)
    plan,auth=authorize(cmp)
    result=cmp['recovery'].execute(plan,auth)
    assert result.outcome is M4Outcome.SUCCEEDED
    assert cmp['methods']==['DELETE','GET'] and all(conn.closed for conn in cmp['connections'])
    assert len(cmp['source'].requests)==21 and cmp['source'].passwords==6
    assert cmp['loader'].loads==1 and cmp['execution'].claim_count==cmp['material'].claim_count==1
    assert cmp['remove_store'].claim_count==1 and cmp['verifier'].calls==1
    assert cmp['custody'].inspect_original_creation()==cmp['original']
    count=len(cmp['source'].requests)
    with pytest.raises(r.WindowsExecutionSecretRecoveryError):cmp['recovery'].execute(plan,auth)
    rebuilt=r.WindowsExecutionSecretRecovery(cmp['custody'],**cmp['recovery_kwargs'])
    with pytest.raises(r.WindowsExecutionSecretRecoveryError):rebuilt.preview()
    assert cmp['methods']==['DELETE','GET'] and len(cmp['source'].requests)==count


@pytest.mark.parametrize('fault',['delete-status','absence-status','wrong-id','chunked','close-response','send'])
def test_uncertain_delete_or_absence_never_replays_or_reports_success(tmp_path,monkeypatch,fault):
    cmp=components(tmp_path,monkeypatch,fault=fault)
    plan,auth=authorize(cmp)
    result=cmp['recovery'].execute(plan,auth)
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert cmp['methods'].count('DELETE')==1 and all(conn.closed for conn in cmp['connections'])
    before=list(cmp['methods'])
    with pytest.raises(r.WindowsExecutionSecretRecoveryError):cmp['recovery'].execute(plan,auth)
    assert cmp['methods']==before and cmp['loader'].loads==1
    assert cmp['custody'].inspect_original_creation()==cmp['original']


def test_fresh_full_row_drift_stops_before_delete(tmp_path,monkeypatch):
    cmp=components(tmp_path,monkeypatch)
    plan,auth=authorize(cmp)
    cmp['source'].fault='stable-row-drift'
    result=cmp['recovery'].execute(plan,auth)
    assert result.outcome is not M4Outcome.SUCCEEDED and not cmp['methods']
    assert all(conn.closed for conn in cmp['connections'])
    assert not (cmp['directory']/r._SEND).exists()


@pytest.mark.parametrize('blocked',['disabled','default-verifier','wrong-plan'])
def test_default_closed_or_untrusted_context_cannot_dispatch(tmp_path,monkeypatch,blocked):
    cmp=components(tmp_path,monkeypatch,enabled=blocked!='disabled',verifier=blocked!='default-verifier')
    if blocked=='disabled':
        with pytest.raises(r.WindowsExecutionSecretRecoveryError):cmp['recovery'].preview()
    else:
        plan,auth=authorize(cmp)
        if blocked=='wrong-plan':
            fields={**plan.canonical_content(),'parameters_digest':'f'*64}
            plan=replace(plan,parameters_digest='f'*64,plan_digest=canonical_digest(fields))
        with pytest.raises(r.WindowsExecutionSecretRecoveryError):cmp['recovery'].execute(plan,auth)
    assert not cmp['methods'] and cmp['remove_store'].claim_count==0


def test_direct_private_delete_request_has_no_authority_from_preview_or_open_tls_socket(tmp_path,monkeypatch):
    cmp=components(tmp_path,monkeypatch)
    authorize(cmp)
    cmp['recovery']._connect()
    with pytest.raises(Exception):cmp['recovery']._request('DELETE')
    assert not cmp['methods'] and all(conn.closed for conn in cmp['connections'])


def test_tampered_delete_ack_refuses_absence_read_instead_of_treating_presence_as_success(tmp_path,monkeypatch):
    cmp=components(tmp_path,monkeypatch)
    plan,auth=authorize(cmp)
    write=cmp['recovery']._write
    def tamper(name,value):
        write(name,value)
        if name==r._ACK:
            path=cmp['directory']/name;path.write_text('{}')
    monkeypatch.setattr(cmp['recovery'],'_write',tamper)
    assert cmp['recovery'].execute(plan,auth).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert cmp['methods']==['DELETE']


def test_creation_ledger_or_key_cannot_be_reused_as_removal_authority(tmp_path,monkeypatch):
    cmp=components(tmp_path,monkeypatch)
    kwargs={**cmp['recovery_kwargs'],'execution_store':cmp['execution']}
    with pytest.raises(r.WindowsExecutionSecretRecoveryError):r.WindowsExecutionSecretRecovery(cmp['custody'],**kwargs)
    assert not cmp['methods']


def test_sealed_unknown_creation_can_be_independently_removed_without_rewriting_its_result(tmp_path,monkeypatch):
    cmp=components(tmp_path,monkeypatch,original_unknown=True)
    plan,auth=authorize(cmp)
    assert cmp['recovery'].execute(plan,auth).outcome is M4Outcome.SUCCEEDED
    assert cmp['original'].original_outcome=='reconciliation_required'
    assert cmp['custody'].inspect_original_creation()==cmp['original']
    assert cmp['loader'].loads==1 and cmp['methods']==['DELETE','GET']


def test_interrupted_delete_retains_unfinished_removal_claim_without_replay(tmp_path,monkeypatch):
    cmp=components(tmp_path,monkeypatch,fault='crash')
    plan,auth=authorize(cmp)
    with pytest.raises(KeyboardInterrupt):cmp['recovery'].execute(plan,auth)
    assert cmp['methods']==['DELETE'] and all(conn.closed for conn in cmp['connections'])
    assert cmp['remove_store'].claim_count==1
    rebuilt=r.WindowsExecutionSecretRecovery(cmp['custody'],**cmp['recovery_kwargs'])
    with pytest.raises(r.WindowsExecutionSecretRecoveryError):rebuilt.preview()
    assert cmp['methods']==['DELETE'] and cmp['custody'].inspect_original_creation()==cmp['original']


def test_a_second_wire_delete_is_denied_even_inside_the_same_active_m4_dispatch(tmp_path,monkeypatch):
    cmp=components(tmp_path,monkeypatch)
    plan,auth=authorize(cmp)
    request=cmp['recovery']._request
    blocked=[]
    def duplicate(method):
        digest=request(method)
        if method=='DELETE':
            cmp['recovery']._connect()
            try:request('DELETE')
            except Exception:blocked.append(True)
        return digest
    monkeypatch.setattr(cmp['recovery'],'_request',duplicate)
    cmp['recovery'].execute(plan,auth)
    assert blocked==[True] and cmp['methods'].count('DELETE')==1
