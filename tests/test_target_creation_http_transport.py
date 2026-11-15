"""Synthetic fixed Target creation, sealed provenance and uncertain dispatch denial."""
import io
import json
from pathlib import Path
import ssl
import hashlib
import hmac

import pytest

from fortipam_mcp import target_creation_http_transport as t
from fortipam_mcp import target_preservation_contract as c
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_target_preservation_contract import row, response, capture
from test_target_creation_evidence import envelope


class Peer:
    def __init__(self):
        self.created = None; self.calls = []; self.connections = []; self.responses = []; self.body_views = []
        self.now = 100; self.hook = lambda:None; self.lost_ack = False; self.wrong_ack = False
        self.lost_delete_ack = False; self.keep_after_delete = False; self.readback_failure = False; self.drift = False; self.already_exists = False
    def factory(self, host, port, **kwargs):
        assert host == 'pam.example' and port == 443 and kwargs['context'].check_hostname
        peer = self
        class Response:
            def __init__(self,raw,status): self.status=status; self.raw=io.BytesIO(raw); self.closed=False
            def readinto(self,buffer): return self.raw.readinto(buffer)
            def getheader(self,key,default=''): return 'application/json' if key=='Content-Type' else default
            def close(self): self.closed=True
        class Connection:
            closed=False
            def connect(self): peer.hook()
            def request(self,method,path,body,headers):
                assert headers['Authorization']=='Bearer synthetic-token'
                peer.calls.append(method)
                if method=='POST':
                    assert path=='/api/v2/cmdb/secret/target?vdom=root'
                    peer.body_views.append(body.obj)
                    value=json.loads(bytes(body)); value.pop('$originalName')
                    peer.created=dict(value,id=10,uuid='synthetic-uuid',**{'creation-time':1234,'q_ref':0})
                    if peer.drift: peer.created['description']='unexpected'
                    if peer.lost_ack: raise OSError('private response missing')
                    raw=envelope(mkey='wrong') if peer.wrong_ack else envelope(); status=200
                elif method=='DELETE':
                    assert path=='/api/v2/cmdb/secret/target/synthetic-target?with_meta=true&vdom=root' and body is None
                    if not peer.keep_after_delete: peer.created=None
                    if peer.lost_delete_ack: raise OSError('private delete acknowledgement missing')
                    raw=envelope(http_method='DELETE');status=200
                else:
                    assert path=='/api/v2/cmdb/secret/target/synthetic-target?with_meta=true&vdom=root'
                    if peer.created is None:
                        raw=envelope(absent=True);status=200 if peer.already_exists else 404
                    else:
                        if peer.readback_failure: raise OSError('private readback missing')
                        raw=response(peer.created);status=200
                self.response=Response(raw,status);peer.responses.append(self.response)
            def getresponse(self):return self.response
            def close(self):self.closed=True
        conn=Connection();self.connections.append(conn);return conn


def setup(tmp_path:Path,**options):
    tmp_path.chmod(0o700);peer=Peer();proposal=capture(row())
    def make(**overrides):
        body={key:row()[key] for key in c.TARGET_STATE_FIELDS-t.e._GENERATED};body['$originalName']=proposal.name
        raw=bytearray(json.dumps(body).encode())
        value=t.TargetCreationHttpTransport(SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,options.get('ca_file')),
            proposal,raw,state_directory=tmp_path,provenance_key=overrides.pop('provenance_key',b'k'*32),
            clock=lambda:peer.now,connection_factory=peer.factory,**overrides)
        assert not any(raw)
        return value
    return peer,make


def create(transport,guard=lambda:None):
    return transport.create(plan_digest='a'*64,authorization_digest='b'*64,expires_at=150,before_send=guard)


def test_close_erases_request_and_disables_both_execution_gates(tmp_path):
    peer, make = setup(tmp_path)
    transport = make(execution_enabled=True, recovery_enabled=True)
    transport.close()
    transport.close()
    assert not transport._enabled and not transport._recovery_enabled
    assert not any(transport._body)
    with pytest.raises(t.TargetCreationTransportError):
        create(transport)
    assert peer.calls == []


def test_failed_native_response_keeps_only_original_code_and_cannot_supply_ownership(tmp_path):
    peer,make=setup(tmp_path);factory=peer.factory
    def failed(*args,**kwargs):
        connection=factory(*args,**kwargs);original=connection.getresponse
        def getresponse():
            response=original()
            if peer.calls[-1]=='POST':
                data=json.loads(envelope());data.update(http_status=500,status='error',error=-651,
                    cli_error='invalid template PRIVATE_NEVER_RETAIN')
                response.status=500;response.raw=io.BytesIO(json.dumps(data).encode())
            return response
        connection.getresponse=getresponse;return connection
    peer.factory=failed;creator=make(execution_enabled=True)
    with pytest.raises(t.TargetCreationTransportError):create(creator)
    value=json.loads((tmp_path/'create.failure.json').read_bytes());seal=value.pop('seal')
    assert value['envelope_verified'] and value['native_error_code']==-651
    assert value['message_mentions']['template'] and value['message_mentions']['invalid']
    assert not value['success_ack_qualified'] and not value['raw_response_stored']
    assert seal==hmac.new(creator._key,t._DOMAIN+b'native-failure-observation\x00'+t._canonical(value),hashlib.sha256).hexdigest()
    assert not(tmp_path/'create.ack.json').exists()
    assert b'PRIVATE_NEVER_RETAIN' not in b''.join(p.read_bytes() for p in tmp_path.iterdir() if p.is_file())
    with pytest.raises(t.TargetCreationTransportError):create(creator)
    assert peer.calls.count('POST')==1


@pytest.mark.parametrize('failure',['http_reject','unqualified_body'])
def test_native_header_observation_is_signed_minimized_and_never_an_ack(tmp_path,failure):
    peer,make=setup(tmp_path)
    peer.wrong_ack=failure=='unqualified_body'
    factory=peer.factory
    def observed_factory(*args,**kwargs):
        connection=factory(*args,**kwargs);get=connection.getresponse
        def response():
            result=get()
            if peer.calls[-1]=='POST':
                if failure=='http_reject':result.status=403
                header=result.getheader
                result.getheader=lambda key,default='':('application/json; private=HEADER_SENTINEL' if key=='Content-Type' else header(key,default))
            return result
        connection.getresponse=response
        return connection
    peer.factory=observed_factory
    creator=make(execution_enabled=True)
    with pytest.raises(t.TargetCreationTransportError):create(creator)
    value=json.loads((tmp_path/'create.response.json').read_bytes());seal=value.pop('seal')
    assert seal==hmac.new(creator._key,t._DOMAIN+b'header-observation\x00'+t._canonical(value),hashlib.sha256).hexdigest()
    assert value['http_status']==(403 if failure=='http_reject' else 200)
    assert value['json_content_type'] and value['identity_encoding']
    assert not value['success_ack_qualified'] and not value['raw_response_stored']
    assert value['claim_digest']==t._digest(json.loads((tmp_path/'create.claim.json').read_bytes()))
    assert 'HEADER_SENTINEL' not in (tmp_path/'create.response.json').read_text()
    assert not (tmp_path/'create.ack.json').exists() and not (tmp_path/'create.verified.json').exists()
    assert peer.calls.count('POST')==1 and all(item.closed for item in peer.connections+peer.responses)


def test_create_seal_reload_and_terminal_claim(tmp_path):
    peer,make=setup(tmp_path); creator=make(execution_enabled=True)
    evidence=create(creator)
    assert peer.calls==['GET','POST','GET']
    assert creator.load_creation_evidence()==evidence
    assert make().load_creation_evidence()==evidence
    with pytest.raises(t.TargetCreationTransportError):create(make(execution_enabled=True))
    assert peer.calls==['GET','POST','GET']
    assert all(not any(body) for body in peer.body_views)
    assert all(obj.closed for obj in peer.connections+peer.responses)
    assert all(p.stat().st_mode & 0o777==0o600 for p in tmp_path.iterdir())


@pytest.mark.parametrize('fault',['disabled','existing','lost_ack','wrong_ack','readback','drift','expiry','rollback','authority'])
def test_failures_are_terminal_without_adoption(tmp_path,fault):
    peer,make=setup(tmp_path)
    peer.already_exists=fault=='existing';peer.lost_ack=fault=='lost_ack';peer.wrong_ack=fault=='wrong_ack'
    peer.readback_failure=fault=='readback';peer.drift=fault=='drift'
    allowed=[True]
    def hook():
        if peer.calls==['GET']:
            if fault=='expiry':peer.now=150
            if fault=='rollback':peer.now=99
            if fault=='authority':allowed[0]=False
    peer.hook=hook
    def guard():
        if not allowed[0]:raise ValueError('private authority')
    with pytest.raises(t.TargetCreationTransportError) as caught:create(make(execution_enabled=fault!='disabled'),guard)
    assert str(caught.value)=='Protected Target creation transport unavailable.'
    writes=peer.calls.count('POST')
    assert writes==(1 if fault in ('lost_ack','wrong_ack','readback','drift') else 0)
    assert not (tmp_path/'create.verified.json').exists()
    if fault in ('readback','drift'):assert (tmp_path/'create.ack.json').exists()
    with pytest.raises(t.TargetCreationTransportError):make().load_creation_evidence()
    if (tmp_path/'create.claim.json').exists():
        with pytest.raises(t.TargetCreationTransportError):create(make(execution_enabled=True))
        assert peer.calls.count('POST')==writes
    assert all(not any(body) for body in peer.body_views)
    assert all(obj.closed for obj in peer.connections+peer.responses)


@pytest.mark.parametrize('file',['create.claim.json','create.absent.json','create.ack.json','create.verified.json'])
def test_changed_original_records_reject_reload(tmp_path,file):
    _,make=setup(tmp_path);create(make(execution_enabled=True))
    path=tmp_path/file;value=json.loads(path.read_text());value['tampered']=True;path.write_text(json.dumps(value))
    with pytest.raises(t.TargetCreationTransportError):make().load_creation_evidence()


def test_wrong_key_cannot_authenticate_original_creation(tmp_path):
    _,make=setup(tmp_path);create(make(execution_enabled=True))
    with pytest.raises(t.TargetCreationTransportError):make(provenance_key=b'x'*32).load_creation_evidence()


@pytest.mark.parametrize('fault',['missing','extra','generated','name','nested','duplicate'])
def test_request_body_must_match_complete_proposal_and_is_consumed(tmp_path,fault):
    tmp_path.chmod(0o700);proposal=capture(row())
    body={key:row()[key] for key in c.TARGET_STATE_FIELDS-t.e._GENERATED};body['$originalName']=proposal.name
    if fault=='missing':body.pop('class')
    if fault=='extra':body['other']='unknown'
    if fault=='generated':body['uuid']='caller-assigned'
    if fault=='name':body['$originalName']='other'
    if fault=='nested':body['web-proxy']={}
    raw=bytearray(json.dumps(body).encode())
    if fault=='duplicate':raw[-1:]=b',"name":"synthetic-target"}'
    with pytest.raises(t.TargetCreationTransportError):
        t.TargetCreationHttpTransport(SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,None),
            proposal,raw,state_directory=tmp_path,provenance_key=b'k'*32)
    assert not any(raw) and not list(tmp_path.iterdir())


def test_same_configured_ca_snapshot_used_for_all_requests(tmp_path,monkeypatch):
    ca=tmp_path.parent/'synthetic-create-ca.pem';ca.write_text('INITIAL')
    loaded=[]
    def context(*,cadata):loaded.append(cadata);return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(t.ssl,'create_default_context',context)
    peer,make=setup(tmp_path,ca_file=str(ca));creator=make(execution_enabled=True)
    ca.write_text('REPLACED');create(creator)
    assert loaded==['INITIAL'] and peer.calls==['GET','POST','GET']


def test_original_name_escaped_duplicate_rejected(tmp_path):
    tmp_path.chmod(0o700);proposal=capture(row())
    body={key:row()[key] for key in c.TARGET_STATE_FIELDS-t.e._GENERATED};body['$originalName']=proposal.name
    raw=bytearray(json.dumps(body).encode());raw[-1:]=b',"\\u0024originalName":"synthetic-target"}'
    with pytest.raises(t.TargetCreationTransportError):
        t.TargetCreationHttpTransport(SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,None),
            proposal,raw,state_directory=tmp_path,provenance_key=b'k'*32)
    assert not any(raw) and not list(tmp_path.iterdir())


def test_record_write_cannot_persist_an_unreadable_oversized_witness(tmp_path):
    _,make=setup(tmp_path);creator=make()
    with creator._lock() as directory:
        with pytest.raises(ValueError):
            creator._write(directory,'create.verified.json',{'namespace':creator._namespace,'oversized':'x'*16384})
    assert not (tmp_path/'create.verified.json').exists()
