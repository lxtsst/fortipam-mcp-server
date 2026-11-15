"""Explicit Windows Owner reads retain full state and never replace API writes."""
import json

import httpx
import pytest

from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig, SYSTEM_STATUS_PATH
from fortipam_mcp.windows_target_owner_source import WindowsTargetOwnerSource, WindowsTargetOwnerSourceError
from fortipam_mcp.target_creation_inputs import TargetCreationInputStore
from fortipam_mcp.target_creation_serializer import compile_windows_execution_target_request
from fortipam_mcp import target_preservation_contract as c
from test_windows_execution_target_serializer import windows, NAME
from test_target_preservation_contract import response, DIGEST, SERIAL

OWNER='synthetic-owner'


@pytest.mark.parametrize('failure', [None, 'actor', 'serial', 'acl', 'origin', 'logout', 'expiry', 'source_drift'])
def test_fixed_owner_source_brackets_and_closes_or_returns_no_partial_result(failure):
    calls=[];clients=[];active=False;now=[100.0]
    value,_,_=windows()
    value['user-permission']=[{'id':1,'user-name':[{'name':OWNER,'q_origin_key':OWNER}],
        'permission':'owner','q_origin_key':1}]
    def streaming(payload):
        return httpx.Response(200,stream=httpx.ByteStream(json.dumps(payload).encode()),
            headers={'content-type':'application/json'})
    def respond(request):
        nonlocal active
        calls.append((request.method,request.url.path))
        assert 'authorization' not in request.headers
        if request.url.path=='/remote/login':return httpx.Response(200,text='<form action="/XX/YY/ZZ/AUTH">')
        if request.url.path=='/XX/YY/ZZ/AUTH':
            active=True;return httpx.Response(303,headers={'location':'/'})
        if request.url.path=='/':return httpx.Response(200)
        if request.url.path=='/logout':
            active=failure=='logout';return httpx.Response(200)
        if not active:return httpx.Response(401,json={})
        if request.url.path==SYSTEM_STATUS_PATH:return httpx.Response(200,json={'version':'v7.0.0','build':29})
        if request.url.path=='/api/v2/monitor/web-ui/state':
            return streaming(dict(version='v7.0.0',build=29,status='success',http_method='GET',
                path='web-ui',name='state',serial=SERIAL,results={'admin':dict(name='other' if failure=='actor' else OWNER,
                    login_name=OWNER,sponsored_group_name='',guest_admin=False)}))
        assert request.method=='GET' and request.url.path=='/api/v2/cmdb/secret/target/'+NAME
        assert request.url.query==b'with_meta=true&vdom=root'
        payload=json.loads(response(value));payload['mkey']=NAME
        if failure=='serial':payload['serial']='DIFFERENT_DEVICE'
        if failure=='acl':payload['results'][0]['user-permission'][0]['permission']='create-secret'
        if failure=='origin':payload['results'][0]['user-permission'][0]['q_origin_key']=True
        if failure=='expiry':now[0]=151.0
        return streaming(payload)
    def factory(**kwargs):
        client=httpx.Client(**kwargs,transport=httpx.MockTransport(respond));clients.append(client);return client
    config=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-api-token',30,None)
    source=WindowsTargetOwnerSource(config,target_name=NAME,owner_name=OWNER,serial_digest=DIGEST,
        credentials=lambda:(OWNER,'synthetic-password'),client_factory=factory,clock=lambda:now[0])
    original_context=source.check_binding(config,target_name=NAME,serial_digest=DIGEST)
    def guard():
        if failure=='source_drift':source.close()
    if failure:
        with pytest.raises(WindowsTargetOwnerSourceError):source.read(expires_at=150,before_send=guard)
        before=list(calls)
        with pytest.raises(WindowsTargetOwnerSourceError):source.read(expires_at=150,before_send=lambda:None)
        assert calls==before
    else:
        raw=source.read(expires_at=150,before_send=guard)
        state=c.capture_target_state(raw,expected_name=NAME,expected_serial_digest=DIGEST)
        assert state.coordinates.template=='Windows Machine' and not any(raw)
        assert source.check_binding(config,target_name=NAME,serial_digest=DIGEST)==original_context
        assert sum(path=='/api/v2/monitor/web-ui/state' for _,path in calls)==2
    assert source.logout_verified is (failure not in ('logout','source_drift'))
    if failure=='source_drift':assert calls==[]
    assert all(client.is_closed for client in clients)
    assert all(method=='GET' or path=='/XX/YY/ZZ/AUTH' for method,path in calls)


def test_creator_pins_explicit_owner_source_across_durable_input_reload(tmp_path):
    config=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-api-token',5,None)
    source=WindowsTargetOwnerSource(config,target_name=NAME,owner_name=OWNER,serial_digest=DIGEST,
        credentials=lambda:(OWNER,'synthetic-password'),clock=lambda:100.0)
    _,proposal,expected=windows()
    body=compile_windows_execution_target_request(proposal,bytearray(expected))
    root=tmp_path/'inputs';root.mkdir(mode=0o700)
    state=tmp_path/'state';state.mkdir(mode=0o700)
    inputs=TargetCreationInputStore(root);digest=inputs.provision(proposal,body,expected_material=expected)
    args=dict(input_digest=digest,state_directory=state,connection_factory=lambda *a,**k:pytest.fail('API fallback'))
    creator=inputs.open_creator(config,owner_read_source=source,**args)
    legacy=inputs.open_creator(config,**args)
    assert creator._namespace!=legacy._namespace and creator._source_context_digest==legacy._source_context_digest
    source.read=lambda **kwargs:bytearray(b'qualified-source-test')
    assert creator._exchange('GET',deadline=150,guard=lambda:None)==bytearray(b'qualified-source-test')
    assert not creator._enabled and not creator._recovery_enabled
    source.close()
    with pytest.raises(WindowsTargetOwnerSourceError):creator._exchange('GET',deadline=150,guard=lambda:None)
    creator.close();legacy.close()


def test_creator_rejects_a_different_owner_before_claim_or_network(tmp_path):
    from fortipam_mcp.target_creation_http_transport import TargetCreationHttpTransport, TargetCreationTransportError
    config=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-api-token',5,None)
    source=WindowsTargetOwnerSource(config,target_name=NAME,owner_name='different-owner',serial_digest=DIGEST,
        credentials=lambda:('different-owner','synthetic-password'))
    _,proposal,expected=windows()
    body=compile_windows_execution_target_request(proposal,bytearray(expected))
    tmp_path.chmod(0o700)
    with pytest.raises(TargetCreationTransportError):
        TargetCreationHttpTransport(config,proposal,body,state_directory=tmp_path,provenance_key=b'k'*32,
            expected_material=expected,owner_read_source=source,execution_enabled=True,
            connection_factory=lambda *a,**k:pytest.fail('network'))
    assert not any(body) and not any(expected) and not list(tmp_path.iterdir())


def test_original_creation_seal_uses_api_ack_and_complete_owner_readback(tmp_path):
    from test_windows_execution_secret_preflight import TargetPeer
    from test_target_creation_http_transport import create
    acl=[{'id':1,'user-name':[{'name':OWNER,'q_origin_key':OWNER}],
        'permission':'owner','q_origin_key':1}]
    value,proposal,expected=windows(**{'user-permission':acl})
    peer=TargetPeer(value);active=False;clients=[];owner_reads=[]
    def respond(request):
        nonlocal active
        path=request.url.path
        assert 'authorization' not in request.headers
        if path=='/remote/login':return httpx.Response(200,text='<form action="/XX/YY/ZZ/AUTH">')
        if path=='/XX/YY/ZZ/AUTH':
            active=True;return httpx.Response(303,headers={'location':'/'})
        if path=='/':return httpx.Response(200)
        if path=='/logout':active=False;return httpx.Response(200)
        if not active:return httpx.Response(401,json={})
        if path==SYSTEM_STATUS_PATH:return httpx.Response(200,json={'version':'v7.0.0','build':29})
        owner_reads.append(path)
        if path=='/api/v2/monitor/web-ui/state':
            payload=dict(version='v7.0.0',build=29,status='success',http_method='GET',path='web-ui',name='state',
                serial=SERIAL,results={'admin':dict(name=OWNER,login_name=OWNER,sponsored_group_name='',guest_admin=False)})
        else:
            assert path=='/api/v2/cmdb/secret/target/'+NAME and peer.created is not None
            payload=json.loads(response(peer.created));payload['mkey']=NAME
        return httpx.Response(200,stream=httpx.ByteStream(json.dumps(payload).encode()),headers={'content-type':'application/json'})
    def factory(**kwargs):
        client=httpx.Client(**kwargs,transport=httpx.MockTransport(respond));clients.append(client);return client
    def api_factory(*args,**kwargs):
        connection=peer.factory(*args,**kwargs);request=connection.request
        def send(method,*args):
            assert not (method=='GET' and peer.created is not None), 'private Target must use explicit Owner source'
            return request(method,*args)
        connection.request=send
        return connection
    config=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-api-token',30,None)
    def owner_source():
        return WindowsTargetOwnerSource(config,target_name=NAME,owner_name=OWNER,serial_digest=DIGEST,
            credentials=lambda:(OWNER,'synthetic-password'),client_factory=factory,clock=lambda:100.0)
    root=tmp_path/'inputs';root.mkdir(mode=0o700)
    state=tmp_path/'state';state.mkdir(mode=0o700)
    body=compile_windows_execution_target_request(proposal,bytearray(expected))
    inputs=TargetCreationInputStore(root);digest=inputs.provision(proposal,body,expected_material=expected)
    source=owner_source()
    creator=inputs.open_creator(config,input_digest=digest,state_directory=state,clock=lambda:100,
        owner_read_source=source,execution_enabled=True,connection_factory=api_factory)
    evidence=create(creator)
    assert peer.calls==['GET','POST'] and len(owner_reads)==3 and source.logout_verified
    assert evidence.created.field_digests!=proposal.field_digests
    assert dict(evidence.created.field_digests)['user-permission']==dict(proposal.field_digests)['user-permission']
    assert (state/'create.ack.json').exists() and (state/'create.verified.json').exists()
    assert not creator._enabled and not creator._recovery_enabled
    reopened=inputs.open_creator(config,input_digest=digest,state_directory=state,owner_read_source=owner_source(),
        clock=lambda:100,connection_factory=api_factory)
    assert reopened._namespace==creator._namespace and reopened.load_creation_evidence()==evidence
    assert peer.calls==['GET','POST'] and all(client.is_closed for client in clients)
    creator.close();reopened.close()
