"""One cookie-bound GET; every Owner window and response below is synthetic."""
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.glass_break_contract import STATE_PATH,GlassBreakIncident
from fortipam_mcp.glass_break_source import GlassBreakSource
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport,SecretMetadataHttpTransportConfig
from test_glass_break_contract import fixture,ACTOR,SERIAL,PRIVATE,REASON
from test_saml_server_native_source import Socket
from test_system_email_m4_adapter import Clock

COOKIE='SYNTHETIC_VOLATILE_COOKIE_MUST_NEVER_BE_HASHED'


class Peer:
    def __init__(self):
        self.clock=Clock(); self.time=10.0; self.schema,self.body,self.binding=fixture()
        self.cookie=COOKIE; self.calls=[]; self.resources=[]; self.buffers=[]; self.fault=None; self.credentials=0
    def http_clock(self): return self.time
    def login(self): self.credentials+=1; raise AssertionError('The source must borrow a window without login.')
    def client(self):
        peer=self
        class Client:
            def build_request(self,method,url):
                assert method=='GET' and url=='https://pam.example.test'+STATE_PATH
                return SimpleNamespace(headers={'cookie':peer.cookie})
        return Client()
    def factory(self,host,port,**kwargs):
        peer=self
        class Connection:
            def __init__(self): self.sock=Socket(); self.closed=False; peer.resources.append(self)
            def set_debuglevel(self,value): assert value==0
            def connect(self):
                assert host=='pam.example.test'
                if peer.fault=='connect-deadline': peer.time+=5
            def request(self,method,path,*,headers):
                assert method=='GET' and path==STATE_PATH and headers['Cookie']==peer.cookie and 'Authorization' not in headers
                peer.calls.append((method,path))
            def getresponse(self):
                result=Response(json.dumps(peer.body).encode())
                if peer.fault=='detached': self.sock=None
                return result
            def close(self): self.closed=True
        class Response:
            def __init__(self,raw): self.raw=raw; self.offset=0; self.closed=False; self.status=200; peer.resources.append(self)
            def getheader(self,name,default=None):
                return {'content-type':'text/html' if peer.fault=='html' else 'application/json',
                    'content-length':str(len(self.raw)+(1 if peer.fault=='truncated' else 0))}.get(name.lower(),default)
            def isclosed(self): return self.offset>=len(self.raw)
            def readinto(self,view):
                if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                count=min(len(view),len(self.raw)-self.offset,113); view[:count]=self.raw[self.offset:self.offset+count]; self.offset+=count
                if peer.fault=='deadline': peer.time+=1
                return count
            def close(self):
                self.closed=True
                if peer.fault=='close': raise RuntimeError(PRIVATE)
                if peer.fault=='cookie-after-read': peer.cookie='SYNTHETIC_CHANGED_COOKIE'
                if peer.fault=='late-close': peer.time+=5
        return Connection()


def construct(peer,*,guarded=True,config=None,connection_factory=None):
    config=config or SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-unused-bearer',5,None)
    owner=OwnerSessionMetadataTransport(config,owner_name=ACTOR,credentials=peer.login,folder_path='synthetic-source',
        secret_name='synthetic-source',target_name='synthetic-source',witness=FortiPamSecretMetadataHttpTransport(config),
        connection_factory=connection_factory or peer.factory,clock=peer.http_clock)
    owner._client=peer.client(); owner._session_lock.acquire(); owner._expires_at=70.0
    try:
        source=GlassBreakSource(owner,peer.binding,peer.schema,GlassBreakIncident('2'*64,REASON),
            source_guard=(lambda:True) if guarded else None,clock=peer.clock)
        return source,owner
    except BaseException:
        owner._client=None; owner._session_lock.release(); raise


@pytest.fixture
def candidate():
    created=[]
    def make(**options):
        peer=Peer(); source,owner=construct(peer,**options); created.append((source,owner)); return peer,source,owner
    yield make
    for source,owner in created:
        source.close(); owner._client=None
        if owner._session_lock.locked(): owner._session_lock.release()


def test_exact_cookie_get_does_not_hash_token_resolve_credentials_or_touch_other_resources(candidate,monkeypatch):
    peer,source,owner=candidate(); decode,digest=json.loads,hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        value=raw.encode() if isinstance(raw,str) else raw
        assert PRIVATE.encode() not in value and COOKIE.encode() not in value
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert PRIVATE.encode() not in raw and COOKIE.encode() not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    observed=source.read()
    assert observed.state.eligible and observed.state.promoted is False and observed.expires_at==1010
    assert peer.calls==[('GET',STATE_PATH)] and peer.credentials==0 and owner._session_lock.locked()
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)
    assert COOKIE not in repr(source) and not owner.logout_verified


def test_original_fresh_plan_repeats_one_get_and_full_role_comparison(candidate):
    peer,source,owner=candidate(); plan=source.prepare_plan(); body=source.compile(plan)
    try: assert json.loads(body)==dict(comments=REASON)
    finally: body[:]=b'\0'*len(body)
    assert peer.calls==[('GET',STATE_PATH)]*2
    with pytest.raises(ValueError,match='unavailable'): source.compile(replace(plan))
    peer.body['results']['admin']['profile']['permissions']['audit']='read-write'
    with pytest.raises(ValueError,match='unavailable'): source.compile(plan)


@pytest.mark.parametrize('fault',['guard','client','config','owner','cookie','window','expired','lock','tls','schema','closed','mono','epoch'])
def test_lost_window_source_shape_or_guard_refuses_before_network(candidate,fault):
    peer,source,owner=candidate(guarded=fault!='guard')
    if fault=='client': owner._client=peer.client()
    elif fault=='config': owner._config=replace(owner._config)
    elif fault=='owner': owner._owner_name='foreign'
    elif fault=='cookie': peer.cookie='SYNTHETIC_CHANGED_COOKIE'
    elif fault=='window': owner._expires_at=71
    elif fault=='expired': peer.time=70
    elif fault=='lock': owner._session_lock.release()
    elif fault=='tls': source._tls.check_hostname=False
    elif fault=='schema': source._schema['name']['size']=63
    elif fault=='closed': source.close()
    elif fault in ('mono','epoch'):
        source.read(); peer.calls.clear()
        if fault=='mono': peer.time-=1
        else: peer.clock.value-=1
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert peer.calls==[] and peer.credentials==0


@pytest.mark.parametrize('fault',['html','truncated','close','deadline','connect-deadline','cookie-after-read','late-close'])
def test_transport_cleanup_deadline_and_post_read_window_drift_never_publish(candidate,fault):
    peer,source,owner=candidate(); peer.fault=fault
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert source._latest is None and all(not any(raw) for raw in peer.buffers)
    assert all(resource.closed for resource in peer.resources)


@pytest.mark.parametrize('fault',['expired','superseded','foreign','active'])
def test_expired_foreign_plan_and_active_view_cannot_acquire_a_body_or_inverse(candidate,fault):
    peer,source,owner=candidate(); plan=source.prepare_plan()
    if fault=='expired': peer.clock.value=1010
    elif fault=='superseded': source.prepare_plan()
    elif fault=='foreign': plan=candidate()[1].prepare_plan()
    else: peer.body['results']['admin']['promoted_admin']=True
    with pytest.raises(ValueError,match='unavailable'): source.compile(plan)
    if fault=='active':
        with pytest.raises(ValueError,match='unavailable'): source.prepare_plan()


def test_detached_socket_and_value_free_preview_preserve_qualification_gaps(candidate):
    peer,source,owner=candidate(); peer.fault='detached'; public=source.preview(); text=json.dumps(public)
    assert public['source_state_read_locally'] and public['source_role_shape_pin_matched']
    assert not public['activation_sent'] and not public['logout_performed'] and not public['protected_credentials_resolved']
    assert not public['native_complete_role_schema_qualified'] and not public['native_subject_or_session_scope_verified']
    assert all(marker not in text for marker in (ACTOR,SERIAL,REASON,COOKIE,PRIVATE))


def test_close_clears_only_owned_cookie_copy_and_keeps_producer_window(candidate):
    peer,source,owner=candidate(); client=owner._client; copy=source._cookie
    source.close()
    assert not any(copy) and owner._client is client and owner._session_lock.locked() and not owner.logout_verified


def test_original_plan_expiry_is_not_replaced_by_a_later_fresh_state(candidate,monkeypatch):
    peer,source,owner=candidate(); plan=source.prepare_plan(); peer.clock.value=1009; read=source._read
    def delayed(*args,**kwargs):
        result=read(*args,**kwargs); peer.clock.value+=1; return result
    monkeypatch.setattr(source,'_read',delayed)
    with pytest.raises(ValueError,match='unavailable'): source.compile(plan)
    assert peer.calls==[('GET',STATE_PATH)]*2 and all(not any(raw) for raw in peer.buffers)
