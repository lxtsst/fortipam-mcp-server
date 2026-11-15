"""Synthetic monitor ACK profile and fixed cookie POSTs; no native qualification."""
import hashlib
import json

import pytest

from fortipam_mcp.glass_break_contract import ACTIVATE_PATH,DEACTIVATE_PATH
from fortipam_mcp.glass_break_http_backend import GlassBreakHttpBackend,GlassBreakHttpError
from fortipam_mcp.glass_break_m4 import GlassBreakExecutionScope,GlassBreakM4Session
from test_glass_break_contract import SERIAL,PRIVATE,REASON
from test_glass_break_source import Peer,construct
from test_glass_break_m4 import Evidence,bind,execute
from test_system_email_m4_adapter import store_at
from v4_planning import M4AdapterDenied

OPAQUE='SYNTHETIC_OPAQUE_ACK_NEVER_DECODE_OR_HASH'
CSRF='SYNTHETIC_CSRF_NEVER_HASH'
COOKIE_HEADER='APSCOOKIE=SYNTHETIC_COOKIE_NEVER_HASH; ccsrftoken='+CSRF


class HttpPeer(Peer):
    def __init__(self):
        super().__init__(); self.cookie=COOKIE_HEADER; self.post_fault=None; self.writes=[]; self.on_connect=lambda:None
    def mutate(self,path,body):
        assert path in (ACTIVATE_PATH,DEACTIVATE_PATH); deactivate=path==DEACTIVATE_PATH
        assert json.loads(bytes(body))==({} if deactivate else dict(comments=REASON))
        self.writes.append(deactivate); self.body['results']['admin']['promoted_admin']=not deactivate
        ack=dict(http_method='POST',http_status=200,status='success',path='user',name='break-glass',
            action='deactivate' if deactivate else 'activate',serial=SERIAL,version='v7.0.0',build=29,
            results={'msg':OPAQUE},revision=OPAQUE)
        if self.post_fault=='extra-result': ack['results']['token']=OPAQUE
        elif self.post_fault=='extra': ack['password']=OPAQUE
        elif self.post_fault=='serial': ack['serial']='foreign'
        elif self.post_fault=='action': ack['action']='foreign'
        elif self.post_fault=='method': ack['http_method']='PUT'
        elif self.post_fault=='status': ack['status']='OK'
        elif self.post_fault=='bool-build': ack['build']=True
        elif self.post_fault=='message-type': ack['results']['msg']=dict(password=OPAQUE)
        return ack
    def factory(self,*args,**kwargs):
        connection=super().factory(*args,**kwargs); connect=connection.connect; request=connection.request; getresponse=connection.getresponse
        def connected(): connect(); self.on_connect()
        def requested(method,path,*,body=None,headers):
            if method!='POST': return request(method,path,headers=headers)
            assert headers['Cookie']==COOKIE_HEADER and headers['X-CSRFTOKEN']==CSRF and 'Authorization' not in headers
            assert 'X-HTTP-Method-Override' not in headers; connection.write_ack=self.mutate(path,body)
        def response():
            if not hasattr(connection,'write_ack'): return getresponse()
            if self.post_fault=='lost-ack': raise TimeoutError(OPAQUE)
            raw=json.dumps(connection.write_ack).encode(); peer=self
            if self.post_fault=='oversize': raw=b' '*16385
            class Response:
                status=200
                def __init__(self): self.offset=0; self.closed=False; peer.resources.append(self)
                def getheader(self,name,default=None):
                    return {'content-type':'text/html' if peer.post_fault=='html' else 'application/json',
                        'content-length':str(len(raw)+(1 if peer.post_fault=='truncated' else 0))}.get(name.lower(),default)
                def isclosed(self): return self.offset>=len(raw)
                def readinto(self,view):
                    if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                    count=min(len(view),len(raw)-self.offset,113); view[:count]=raw[self.offset:self.offset+count]; self.offset+=count; return count
                def close(self):
                    self.closed=True
                    if peer.post_fault=='close': raise RuntimeError(OPAQUE)
                    if peer.post_fault=='late-close': peer.time+=5
            result=Response()
            if self.post_fault=='detached': connection.sock=None
            return result
        connection.connect=connected; connection.request=requested; connection.getresponse=response; return connection


def assemble(root,peer,source,*,enabled=True):
    initial=source.prepare_plan(); backend=GlassBreakHttpBackend(source,initial,execution_enabled=(lambda:True) if enabled else None,source_guard=lambda:True)
    scope=GlassBreakExecutionScope('1'*64,'2'*64,'3'*64,'4'*64,'1'*64,'b'*64,'c'*64,initial.incident.digest,30,10)
    session=GlassBreakM4Session(source,initial,scope,backend,Evidence(peer.clock),store_at(root),source_guard=lambda:True)
    return session,backend


@pytest.fixture
def candidate():
    created=[]
    def make(root,*,enabled=True,cookie=COOKIE_HEADER):
        peer=HttpPeer(); peer.cookie=cookie; source,owner=construct(peer); created.append((source,owner))
        session,backend=assemble(root,peer,source,enabled=enabled); return session,peer,owner,backend
    yield make
    for source,owner in created:
        source.close(); owner._client=None
        if owner._session_lock.locked(): owner._session_lock.release()


def test_fixed_cookie_posts_and_exit_ignore_opaque_message_and_revision(candidate,tmp_path,monkeypatch):
    session,peer,owner,backend=candidate(tmp_path); decode,digest=json.loads,hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        value=raw.encode() if isinstance(raw,str) else raw
        assert OPAQUE.encode() not in value and CSRF.encode() not in value and COOKIE_HEADER.encode() not in value
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert OPAQUE.encode() not in raw and CSRF.encode() not in raw and COOKIE_HEADER.encode() not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    for deactivate in (False,True):
        bound=bind(session,deactivate=deactivate); assert execute(bound).outcome=='succeeded'; assert execute(bound).idempotent_replay
    assert peer.writes==[False,True] and backend._attempted=={False,True} and len(backend._acks)==2
    assert session._source.read().state.digest==session._initial.baseline.digest and not owner.logout_verified and peer.credentials==0
    assert all(not any(raw) for raw in peer.buffers) and all(resource.closed for resource in peer.resources)


@pytest.mark.parametrize('fault',['extra-result','extra','serial','action','method','status','bool-build','message-type','html','truncated',
    'oversize','close','late-close','lost-ack'])
def test_unknown_ack_or_cleanup_never_provides_receipt_replay_or_independent_exit(candidate,tmp_path,fault):
    session,peer,_,backend=candidate(tmp_path); bound=bind(session); peer.post_fault=fault
    result=execute(bound); assert result.outcome=='reconciliation_required' and peer.writes==[False] and backend._acks=={}
    peer.post_fault=None; assert execute(bound).idempotent_replay
    with pytest.raises(M4AdapterDenied): session.prepare_step(deactivate=True)
    assert backend._attempted=={False} and all(not any(raw) for raw in peer.buffers) and all(resource.closed for resource in peer.resources)


def test_detached_ack_socket_still_uses_original_handle(candidate,tmp_path):
    session,peer,_,backend=candidate(tmp_path); peer.post_fault='detached'
    assert execute(bind(session)).outcome=='succeeded' and False in backend._acks


def test_lost_exit_ack_is_unknown_even_when_visible_mode_is_off(candidate,tmp_path):
    session,peer,_,backend=candidate(tmp_path); assert execute(bind(session)).outcome=='succeeded'
    bound=bind(session,deactivate=True); peer.post_fault='lost-ack'
    assert execute(bound).outcome=='reconciliation_required' and peer.body['results']['admin']['promoted_admin'] is False
    assert execute(bound).idempotent_replay and set(backend._acks)=={False}
    with pytest.raises(M4AdapterDenied): session.prepare_step(deactivate=True)
    assert peer.writes==[False,True]


@pytest.mark.parametrize('options',[dict(enabled=False),dict(cookie='APSCOOKIE=SYNTHETIC_COOKIE_NO_CSRF')])
def test_default_gate_or_missing_csrf_refuses_before_write_socket(candidate,tmp_path,options):
    session,peer,_,backend=candidate(tmp_path,**options)
    assert execute(bind(session)).outcome=='reconciliation_required' and peer.writes==[] and backend._attempted==set()


def test_direct_backend_cannot_accept_a_correct_callback_outside_original_kernel(candidate,tmp_path):
    session,peer,_,backend=candidate(tmp_path); adapter,_,_,_=bind(session); body=session._initial.compile(session._initial.baseline)
    before=len(peer.resources)
    try:
        with memoryview(body).toreadonly() as view:
            with pytest.raises(GlassBreakHttpError):
                backend.submit(view,deactivate=False,parameters_digest=adapter._step.parameters_digest,before_send=adapter._before_send,timeout_seconds=5)
    finally: body[:]=b'\0'*len(body)
    assert peer.writes==[] and len(peer.resources)==before and backend._attempted==set()


@pytest.mark.parametrize('fault',['body','callback','parameters'])
def test_current_kernel_cannot_expand_the_private_body_or_owned_callback(candidate,tmp_path,fault):
    session,peer,_,backend=candidate(tmp_path); bound=bind(session); submit=backend.submit
    def changed(body,**kwargs):
        if fault=='callback': kwargs['before_send']=lambda:60
        elif fault=='parameters': kwargs['parameters_digest']='f'*64
        if fault=='body':
            wrong=bytearray(bytes(body)+b' ')
            try:
                with memoryview(wrong).toreadonly() as view: return submit(view,**kwargs)
            finally: wrong[:]=b'\0'*len(wrong)
        return submit(body,**kwargs)
    backend.submit=changed
    assert execute(bound).outcome=='reconciliation_required' and peer.writes==[] and backend._attempted==set()


def test_authority_loss_during_post_tls_connect_prevents_send(candidate,tmp_path):
    session,peer,_,backend=candidate(tmp_path); bound=bind(session); submit=backend.submit
    def armed(*args,**kwargs):
        peer.on_connect=lambda:setattr(backend,'_guard',None)
        try: return submit(*args,**kwargs)
        finally: peer.on_connect=lambda:None
    backend.submit=armed
    assert execute(bound).outcome=='reconciliation_required' and peer.writes==[] and backend._attempted=={False}


def test_tls_and_nested_state_guard_read_use_one_http_deadline(candidate,tmp_path):
    session,peer,_,backend=candidate(tmp_path); bound=bind(session); submit=backend.submit
    def armed(*args,**kwargs):
        peer.on_connect=lambda:setattr(peer,'time',peer.time+3)
        try: return submit(*args,**kwargs)
        finally: peer.on_connect=lambda:None
    backend.submit=armed
    assert execute(bound).outcome=='reconciliation_required' and peer.writes==[] and session._source._deadline_cap is None
    assert all(not any(raw) for raw in peer.buffers) and all(resource.closed for resource in peer.resources)


def test_real_loopback_cookie_https_activation_and_independent_exit(tmp_path):
    import http.client
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.glass_break_contract import STATE_PATH
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_secret_bulk_import_action_process import tls_material

    certificate,key=tls_material(tmp_path); peer=HttpPeer(); requests=[]; connections=[]; buffers=[]
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*_): pass
        def send(self,payload):
            raw=json.dumps(payload).encode(); self.send_response(200); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close'); self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.path==STATE_PATH and self.headers['Cookie']==COOKIE_HEADER and self.headers.get('Authorization') is None
            requests.append(('GET',self.path)); self.send(peer.body)
        def do_POST(self):
            assert self.path in (ACTIVATE_PATH,DEACTIVATE_PATH) and self.headers['Cookie']==COOKIE_HEADER and self.headers['X-CSRFTOKEN']==CSRF
            assert self.headers.get('Authorization') is None
            requests.append(('POST',self.path)); self.send(peer.mutate(self.path,self.rfile.read(int(self.headers['Content-Length']))))
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key); server.socket=tls.wrap_socket(server.socket,server_side=True)
    thread=Thread(target=server.serve_forever,daemon=True); thread.start()
    def factory(host,port,**kwargs):
        connection=http.client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection=lambda address,timeout,source_address:socket.create_connection(('127.0.0.1',server.server_port),timeout,source_address)
        connections.append(connection); return connection
    source=owner=None
    try:
        source,owner=construct(peer,config=SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-unused-bearer',5,str(certificate)),
            connection_factory=factory)
        receive=source._receive
        def tracked(*args,**kwargs):
            raw=receive(*args,**kwargs); buffers.append(raw); return raw
        source._receive=tracked
        session,backend=assemble(tmp_path,peer,source)
        for deactivate in (False,True): assert execute(bind(session,deactivate=deactivate)).outcome=='succeeded'
        assert [request for request in requests if request[0]=='POST']==[('POST',ACTIVATE_PATH),('POST',DEACTIVATE_PATH)]
        assert peer.writes==[False,True] and len(backend._acks)==2 and not owner.logout_verified and peer.credentials==0
        assert source.read().state.digest==session._initial.baseline.digest
        assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
    finally:
        if source is not None: source.close()
        if owner is not None:
            owner._client=None
            if owner._session_lock.locked(): owner._session_lock.release()
        server.shutdown(); server.server_close(); thread.join(timeout=2); assert not thread.is_alive()
