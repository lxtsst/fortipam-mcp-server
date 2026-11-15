"""Fixed local PUT routes and strict ACK receiver; product behavior is synthetic."""
import hashlib
import json

import pytest

from fortipam_mcp.email_alert_compound_contract import STEPS
from fortipam_mcp.email_alert_compound_source import EmailAlertCompoundSource
from fortipam_mcp.email_alert_general_source import EmailAlertGeneralSource
from fortipam_mcp.email_alert_http_backend import EmailAlertHttpBackend,EmailAlertHttpError,_route
from fortipam_mcp.email_alert_m4 import EmailAlertExecutionScope,EmailAlertM4Session
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_email_alert_compound_source import candidate as source_candidate
from test_email_alert_general_contract import SERIAL
from test_email_alert_m4 import Evidence,bind,execute
from test_system_email_m4_adapter import store_at
from v4_planning import M4AdapterDenied

PRIVATE = 'SYNTHETIC_ACK_NEVER_DECODE_OR_HASH'


class HttpPeer:
    def __init__(self):
        self.peer,self.prototype,_=source_candidate(); self.fault=None; self.writes=[]
        self.on_connect=lambda:None
    def mutate(self,path,body):
        step=next(step for step in STEPS if _route(step)[0]==path); _,native_path,table,name=_route(step)
        wire=json.loads(bytes(body)); self.writes.append(step)
        detail=path.replace('?vdom=root','?with_meta=true&vdom=root'); row=self.peer.payloads[detail]['results']
        if step=='certificate': row['cert-setting']=wire['cert-setting']; assert wire['reverse-service-setting']=={}
        else: wire.pop('$originalName',None); row.update(wire)
        ack=dict(build=29,http_method='PUT',http_status=200,name=table,path=native_path,status='OK',version='v7.0.0',
            serial=SERIAL,vdom='root',mkey=name,revision=PRIVATE,revision_changed=True,error=0,results=None)
        if self.fault=='echo': ack['results']=dict(password=PRIVATE)
        elif self.fault=='mkey': ack['mkey']='FOREIGN'
        elif self.fault=='identity': ack['serial']='FOREIGN'
        elif self.fault=='status': ack['status']='success'
        elif self.fault=='method': ack['http_method']='POST'
        elif self.fault=='extra': ack['password']=PRIVATE
        elif self.fault=='bool-build': ack['build']=True
        return ack
    def factory(self,*args,**kwargs):
        connection=self.peer.factory(*args,**kwargs); connect=connection.connect; request=connection.request; getresponse=connection.getresponse
        def connected(): connect(); self.on_connect()
        def requested(method,path,*,headers,body=None):
            if method!='PUT': return request(method,path,headers=headers,body=body)
            assert headers['Authorization']=='Bearer synthetic-api-token' and 'X-HTTP-Method-Override' not in headers
            connection.write_ack=self.mutate(path,body)
        def response():
            if not hasattr(connection,'write_ack'): return getresponse()
            if self.fault=='lost-ack': raise TimeoutError(PRIVATE)
            raw=json.dumps(connection.write_ack).encode()
            if self.fault=='oversize': raw=b' '*16385
            peer=self.peer; http=self
            class Response:
                status=200
                def __init__(self): self.offset=0; self.closed=False; peer.resources.append(self)
                def getheader(self,name,default=None):
                    return {'content-type':'text/html' if http.fault=='html' else 'application/json',
                        'content-length':str(len(raw)+(1 if http.fault=='truncated' else 0))}.get(name.lower(),default)
                def isclosed(self): return self.offset>=len(raw)
                def readinto(self,view):
                    if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                    count=min(len(view),len(raw)-self.offset,113); view[:count]=raw[self.offset:self.offset+count]; self.offset+=count; return count
                def close(self):
                    self.closed=True
                    if http.fault=='close': raise RuntimeError(PRIVATE)
                    if http.fault=='late-close': peer.time+=5
            result=Response()
            if self.fault=='detached': connection.sock=None
            return result
        connection.connect=connected; connection.request=requested; connection.getresponse=response; return connection


def candidate(tmp_path,http=None,source=None,*,enabled=True):
    http=http or HttpPeer(); peer=http.peer
    if source is None: source=http.prototype; source._general._factory=http.factory
    initial=source.prepare_plan()
    backend=EmailAlertHttpBackend(source,initial,execution_enabled=(lambda:True) if enabled else None,source_guard=lambda:True)
    scope=EmailAlertExecutionScope('1'*64,'2'*64,'3'*64,'4'*64,'b'*64,'c'*64,'d'*64)
    session=EmailAlertM4Session(source,initial,scope,backend,Evidence(peer.clock),store_at(tmp_path),source_guard=lambda:True,clock=peer.clock)
    return session,http,backend


def test_sixteen_exact_puts_keep_individual_originals_and_ignore_opaque_revision(monkeypatch,tmp_path):
    session,http,backend=candidate(tmp_path); decode,digest=json.loads,hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        assert PRIVATE.encode() not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert PRIVATE.encode() not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    for name,restore in [*((step,False) for step in STEPS),*((step,True) for step in reversed(STEPS))]:
        bound=bind(session,name,restore=restore); assert execute(bound).outcome=='succeeded'; assert execute(bound).idempotent_replay
    assert http.writes==[*STEPS,*reversed(STEPS)] and len(backend._attempted)==len(backend._acks)==16
    assert session._source.read().state.digest==session._initial.baseline.digest
    assert all(not any(raw) for raw in http.peer.buffers) and all(resource.closed for resource in http.peer.resources)


@pytest.mark.parametrize('fault',['echo','mkey','identity','status','method','extra','bool-build','html','truncated','oversize','close','late-close','lost-ack'])
def test_bad_ack_or_cleanup_never_provides_original_receipt_or_another_attempt(tmp_path,fault):
    session,http,backend=candidate(tmp_path); bound=bind(session); http.fault=fault
    result=execute(bound); assert result.outcome=='reconciliation_required' and http.writes==['general'] and backend._acks=={}
    http.fault=None; assert execute(bound).idempotent_replay
    with pytest.raises(M4AdapterDenied): session.prepare_step('general',restore=True)
    assert backend._attempted=={('general',False)} and all(not any(raw) for raw in http.peer.buffers)
    assert all(resource.closed for resource in http.peer.resources)


def test_connection_close_detaches_socket_without_losing_ack_body(tmp_path):
    session,http,backend=candidate(tmp_path); http.fault='detached'
    assert execute(bind(session)).outcome=='succeeded' and ('general',False) in backend._acks


def test_default_http_gate_refuses_before_the_write_socket(tmp_path):
    session,http,backend=candidate(tmp_path,enabled=False); bound=bind(session); before=len(http.peer.resources)
    assert execute(bound).outcome=='reconciliation_required' and backend._attempted==set() and http.writes==[]
    assert len(http.peer.resources)>before  # Kernel current-state GETs still occur.


def test_direct_backend_call_cannot_replace_original_active_kernel_ownership(tmp_path):
    session,http,backend=candidate(tmp_path); adapter,_,_,_=bind(session)
    body=session._initial.compile('general',session._initial.baseline); before=len(http.peer.resources)
    try:
        with memoryview(body).toreadonly() as view:
            with pytest.raises(EmailAlertHttpError):
                backend.submit(view,step='general',restore=False,parameters_digest=adapter._step.parameters_digest,
                    before_send=adapter._before_send,timeout_seconds=5)
    finally: body[:]=b'\0'*len(body)
    assert len(http.peer.resources)==before and backend._attempted==set() and http.writes==[]


@pytest.mark.parametrize('fault',['body','callback','parameters'])
def test_active_kernel_cannot_expand_the_fixed_private_body_callback_or_parameters(tmp_path,fault):
    session,http,backend=candidate(tmp_path); submit=backend.submit; bound=bind(session)
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
    assert execute(bound).outcome=='reconciliation_required' and http.writes==[] and backend._attempted==set()


def test_post_tls_revocation_and_total_guard_read_deadline_prevent_put(tmp_path):
    session,http,backend=candidate(tmp_path); submit=backend.submit; bound=bind(session)
    def armed(*args,**kwargs):
        http.on_connect=lambda:setattr(backend,'_guard',None)
        try: return submit(*args,**kwargs)
        finally: http.on_connect=lambda:None
    backend.submit=armed
    assert execute(bound).outcome=='reconciliation_required' and http.writes==[] and backend._attempted=={('general',False)}
    assert all(resource.closed for resource in http.peer.resources)


def test_tls_and_sixteen_guard_reads_share_one_http_total_deadline(tmp_path):
    session,http,backend=candidate(tmp_path); submit=backend.submit; bound=bind(session); observed=[]
    def armed(*args,**kwargs):
        started=http.peer.time; before=len(http.peer.calls)
        def delayed(): http.peer.time+=.4
        http.on_connect=delayed
        try: return submit(*args,**kwargs)
        finally:
            http.on_connect=lambda:None; observed.append((http.peer.time-started,len(http.peer.calls)-before))
    backend.submit=armed
    assert execute(bound).outcome=='reconciliation_required' and http.writes==[]
    assert observed and 5<=observed[0][0]<5.5 and observed[0][1]<16
    assert session._source._deadline_cap is None and all(not any(raw) for raw in http.peer.buffers)


def test_real_loopback_https_put_and_independent_restore_with_synthetic_qualifications(tmp_path):
    import http.client as client_module
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from test_secret_bulk_import_action_process import tls_material

    certificate,key=tls_material(tmp_path); http=HttpPeer(); peer=http.peer; connections=[]; requests=[]
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*_): pass
        def send(self,payload):
            raw=json.dumps(payload).encode(); self.send_response(200); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close'); self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.headers['Authorization']=='Bearer synthetic-api-token'; requests.append(('GET',self.path)); self.send(peer.payloads[self.path])
        def do_PUT(self):
            assert self.headers['Authorization']=='Bearer synthetic-api-token' and self.path==_route('general')[0]
            requests.append(('PUT',self.path)); self.send(http.mutate(self.path,self.rfile.read(int(self.headers['Content-Length']))))
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key); server.socket=tls.wrap_socket(server.socket,server_side=True)
    thread=Thread(target=server.serve_forever,daemon=True); thread.start()
    def real_factory(host,port,**kwargs):
        connection=client_module.HTTPSConnection(host,port,**kwargs)
        connection._create_connection=lambda address,timeout,source_address:socket.create_connection(('127.0.0.1',server.server_port),timeout,source_address)
        connections.append(connection); return connection
    general=EmailAlertGeneralSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,str(certificate)),
        http.prototype._general._scope,expected_serial=SERIAL,expected_schema_digest=http.prototype._general._schema_pin,
        source_digest='a'*64,source_guard=lambda:True,connection_factory=real_factory,clock=peer.clock)
    source=EmailAlertCompoundSource(general,expected_schema_digests=http.prototype._schema_pins,source_digest='b'*64,source_guard=lambda:True)
    try:
        session,http,backend=candidate(tmp_path,http,source)
        for restore in (False,True): assert execute(bind(session,restore=restore)).outcome=='succeeded'
        assert http.writes==['general','general'] and len(backend._acks)==2
        assert [request for request in requests if request[0]!='GET']==[('PUT',_route('general')[0])]*2
        assert source.read().state.digest==session._initial.baseline.digest and all(connection.sock is None for connection in connections)
    finally:
        source.close(); general.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
