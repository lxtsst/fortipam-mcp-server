"""Original seals, independent M4 and privileged/global absence with fake IO."""
from dataclasses import replace
import io
import json
import ssl

import httpx
import pytest

from fortipam_mcp import target_creation_http_transport as creator_module
from fortipam_mcp import target_recovery_lifecycle as lifecycle
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig, SYSTEM_STATUS_PATH
from fortipam_mcp.windows_target_owner_source import WindowsTargetOwnerSource
from fortipam_mcp.windows_target_owner_recovery import WindowsTargetOwnerRecovery, WindowsTargetOwnerRecoveryError
from fortipam_mcp.target_creation_serializer import compile_windows_execution_target_request
from fortipam_mcp.target_api_dependency_reader import TargetApiDependencyReader
from fortipam_mcp.target_namespace_preflight import TargetNamespacePreflight
from fortipam_mcp.target_qualified_namespace_reader import FortiPamTargetQualifiedNamespaceReader
from fortipam_mcp.target_qualified_reference_reader import FortiPamTargetQualifiedReferenceReader
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_windows_execution_target_serializer import windows, NAME
from test_windows_execution_secret_preflight import TargetPeer
from test_target_creation_evidence import envelope
from test_target_preservation_contract import response, SERIAL, DIGEST
from test_target_namespace_preflight import BracketHarness

OWNER='synthetic-owner'


@pytest.fixture
def fixture(tmp_path,monkeypatch):
    trust=ssl.create_default_context()
    monkeypatch.setattr(ssl,'create_default_context',lambda **kwargs:trust)
    ca=tmp_path/'ca.pem';ca.write_bytes(b'Synthetic pinned public CA')
    config=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-api-token',30,str(ca))
    acl=[{'id':1,'user-name':[{'name':OWNER,'q_origin_key':OWNER}],'permission':'owner','q_origin_key':1}]
    value,proposal,expected=windows(**{'user-permission':acl})
    peer=TargetPeer(value)
    state=dict(active=False,super_admin=True,global_admin=True,admin_enabled=True,ghost=False,
        keep_target=False,lost_ack=False,role_drift=False,gate_drift=False,delete_count=0,connected=False)
    state.update(csrf_missing=False,role_after_connect=False,string_profile=False)
    clients=[];connections=[];all_calls=[]
    def streaming(payload,status=200):
        return httpx.Response(status,stream=httpx.ByteStream(json.dumps(payload).encode()),headers={'content-type':'application/json'})
    def owner(request):
        path=request.url.path;all_calls.append(('owner',request.method,path))
        assert 'authorization' not in request.headers
        if path=='/remote/login':return httpx.Response(200,text='<form action="/XX/YY/ZZ/AUTH">')
        if path=='/XX/YY/ZZ/AUTH':
            state['active']=True
            return httpx.Response(303,headers={'location':'/','set-cookie':
                'session=synthetic; Secure; Path=/' if state['csrf_missing'] else 'ccsrftoken="synthetic-csrf"; Secure; Path=/'})
        if path=='/':return httpx.Response(200)
        if path=='/logout':state['active']=False;return httpx.Response(200)
        if not state['active']:return streaming({},401)
        if path==SYSTEM_STATUS_PATH:return streaming({'version':'v7.0.0','build':29})
        if path=='/api/v2/monitor/web-ui/state':
            return streaming(dict(version='v7.0.0',build=29,status='success',http_method='GET',path='web-ui',name='state',
                serial=SERIAL,results={'admin':dict(name=OWNER,login_name=OWNER,sponsored_group_name='',guest_admin=False,
                    super_admin=state['super_admin'],global_admin=state['global_admin'],
                    profile='super_admin' if state['string_profile'] else {'name':'super_admin'})}))
        if path=='/api/v2/cmdb/system/admin/'+OWNER:
            return streaming(dict(version='v7.0.0',build=29,status='success',http_method='GET',http_status=200,
                path='system',name='admin',serial=SERIAL,vdom='root',results=[dict(name=OWNER,accprofile='super_admin',
                    status='enable' if state['admin_enabled'] else 'disable',**{'remote-auth':'disable','wildcard':'disable'})]))
        assert path=='/api/v2/cmdb/secret/target/'+NAME and request.method=='GET'
        if peer.created is None:
            payload=json.loads(envelope(absent=True));payload['mkey']=NAME;return streaming(payload,404)
        payload=json.loads(response(peer.created));payload['mkey']=NAME;return streaming(payload)
    def owner_factory(**kwargs):
        client=httpx.Client(**kwargs,transport=httpx.MockTransport(owner));clients.append(client);return client
    source=WindowsTargetOwnerSource(config,target_name=NAME,owner_name=OWNER,serial_digest=DIGEST,
        credentials=lambda:(OWNER,'synthetic-password'),client_factory=owner_factory,clock=lambda:100.0)
    directory=tmp_path/'target';directory.mkdir(mode=0o700)
    creator=creator_module.TargetCreationHttpTransport(config,proposal,
        compile_windows_execution_target_request(proposal,bytearray(expected)),expected_material=expected,
        state_directory=directory,provenance_key=b'k'*32,execution_enabled=True,clock=lambda:100,
        connection_factory=peer.factory,owner_read_source=source)
    creator.create(plan_digest='a'*64,authorization_digest='b'*64,expires_at=150,before_send=lambda:None)
    original=creator.load_creation_evidence()
    object.__setattr__(creator,'_recovery_enabled',True)
    def reader():
        harness=BracketHarness()
        harness.values[3]['results'][0].update(name='Windows Machine')
        return TargetApiDependencyReader(config,serial_digest=DIGEST,clock=lambda:harness.now,client_factory=harness.factory)
    api=reader();absence_api=reader()
    pin=tmp_path/'known_hosts';pin.write_text('synthetic host pin');pin.chmod(0o600)
    ssh_config=TargetSshTransportConfig('synthetic.invalid',22,OWNER,'synthetic-password',pin,30)
    names=FortiPamTargetQualifiedNamespaceReader(ssh_config,serial_digest=DIGEST,clock=lambda:1000.0)
    async def namespace(witnesses):
        return witnesses+((NAME,) if peer.created is not None or state['ghost'] else ())
    monkeypatch.setattr(names,'_bounded_read',namespace)
    namespace_source=TargetNamespacePreflight(absence_api,names)
    references=FortiPamTargetQualifiedReferenceReader(ssh_config,serial_digest=DIGEST)
    async def reference(name):return 0
    monkeypatch.setattr(references,'_read',reference)
    class Connection:
        def __init__(self,*args,**kwargs):self.closed=False;self.sock=None;connections.append(self)
        def connect(self):
            state['connected']=True
            if state['role_after_connect']:state['super_admin']=False
        def request(self,method,path,body,headers):
            assert state['connected'] and method=='DELETE' and path=='/api/v2/cmdb/secret/target/'+NAME
            assert body is None and headers['Content-Length']=='0' and headers['X-CSRFTOKEN']=='synthetic-csrf'
            assert 'Authorization' not in headers and 'Cookie' in headers
            state['delete_count']+=1;all_calls.append(('owner-raw',method,path))
            if not state['keep_target']:peer.created=None
            if state['lost_ack']:raise OSError('synthetic lost ACK')
            payload=json.loads(envelope());payload.update(http_method='DELETE',mkey=NAME)
            self.raw=io.BytesIO(json.dumps(payload).encode())
        def getresponse(self):return self
        status=200
        def getheader(self,name,default=''):return 'application/json' if name.lower()=='content-type' else default
        def read(self,count):return self.raw.read(count)
        def close(self):self.closed=True
    bridge=WindowsTargetOwnerRecovery(creator,namespace_source,execution_enabled=True,connection_factory=Connection)
    key=tmp_path/'ledger.key';key.write_bytes(b'l'*32);key.chmod(0o600)
    store=PersistentM4ExecutionStateStore(tmp_path/'ledger.sqlite',key)
    def make(**changes):
        args=dict(creator=creator,expected_current=original.created,reader=api,references=references,store=store,
            authority_key=b'a'*32,environment_ref='synthetic-environment',scope_ref='synthetic-owner-recovery',
            audience_ref='synthetic-audience',requester_digest='1'*64,transport_digest='2'*64,
            execution_enabled=True,owner_recovery=bridge)
        args.update(changes);return lifecycle.TargetRecoveryLifecycle(**args)
    return make,creator,bridge,peer,state,store,directory,clients,connections,all_calls


def test_independent_real_m4_owner_delete_and_privileged_global_absence(fixture):
    make,creator,bridge,peer,state,store,directory,clients,connections,calls=fixture
    owner=make();issued=owner.issue(owner.preview());result=owner.execute(issued)
    assert result.as_dict()['outcome']=='succeeded' and result.as_dict()['verification']=='verified'
    assert state['delete_count']==1 and store.claim_count==1 and peer.created is None
    assert (directory/'delete.ack.json').exists() and (directory/'delete.verified.json').exists()
    record=json.loads((directory/'delete.verified.json').read_bytes())
    assert len(record['owner_global_absence_digest'])==64 and bridge.logout_verified
    assert all(client.is_closed for client in clients) and all(connection.closed for connection in connections)
    before=list(calls)
    for operation in (owner.preview,lambda:owner.execute(issued),make):
        with pytest.raises(lifecycle.TargetRecoveryLifecycleError):operation()
    assert calls==before
    owner.close();assert not bridge._enabled and not creator._recovery_enabled


@pytest.mark.parametrize('fault',['super_admin','global_admin','admin_disabled','string_profile','ghost','still_present','lost_ack',
    'late_gate','csrf_missing','role_after_connect'])
def test_role_or_absence_uncertainty_never_retries_or_seals(fixture,fault):
    make,creator,bridge,peer,state,store,directory,clients,connections,calls=fixture
    owner=make()
    if fault in ('super_admin','global_admin','admin_disabled','string_profile'):
        state['admin_enabled' if fault=='admin_disabled' else fault]=False if fault!='string_profile' else True
        with pytest.raises(lifecycle.TargetRecoveryLifecycleError):owner.preview()
        assert not (directory/'delete.claim.json').exists() and state['delete_count']==0
    else:
        issued=owner.issue(owner.preview())
        if fault=='ghost':state['ghost']=True
        if fault=='still_present':state['keep_target']=True
        if fault=='lost_ack':state['lost_ack']=True
        if fault in ('csrf_missing','role_after_connect'):state[fault]=True
        if fault=='late_gate':
            guard=bridge._guard
            def drift(deadline,callback):
                result=guard(deadline,callback)
                if state['connected']:bridge._enabled=False
                return result
            bridge._guard=drift
        result=owner.execute(issued)
        assert result.as_dict()['outcome']=='reconciliation_required'
        assert state['delete_count']==(0 if fault in ('late_gate','csrf_missing','role_after_connect') else 1)
        assert not (directory/'delete.verified.json').exists()
        if fault in ('ghost','still_present'):assert (directory/'delete.ack.json').exists()
        with pytest.raises(lifecycle.TargetRecoveryLifecycleError):make()
    assert all(client.is_closed for client in clients) and all(connection.closed for connection in connections)
    owner.close()


def test_missing_original_seal_or_bridge_or_shared_namespace_reader_refuses(fixture):
    make,creator,bridge,peer,state,store,directory,*_=fixture
    with pytest.raises(lifecycle.TargetRecoveryLifecycleError):make(owner_recovery=None)
    with pytest.raises(lifecycle.TargetRecoveryLifecycleError):make(reader=bridge._namespace._api)
    with pytest.raises(lifecycle.TargetRecoveryLifecycleError):make(expected_current=replace(bridge._original.created,state_digest='f'*64))
    (directory/'create.verified.json').unlink()
    with pytest.raises(WindowsTargetOwnerRecoveryError):WindowsTargetOwnerRecovery(creator,bridge._namespace)
    assert state['delete_count']==0 and not (directory/'delete.claim.json').exists()


def test_closed_owner_bridge_gate_denies_before_m4_claim(fixture):
    make,creator,bridge,peer,state,store,directory,*_=fixture
    owner=make();issued=owner.issue(owner.preview());bridge._enabled=False
    with pytest.raises(lifecycle.TargetRecoveryLifecycleError):owner.execute(issued)
    assert store.claim_count==0 and state['delete_count']==0
    assert not (directory/'delete.coordinator.claim.json').exists()
    assert not (directory/'delete.claim.json').exists()
    owner.close()
