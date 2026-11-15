"""Deadline regression coverage across both fixed Target HTTP adapters."""
import pytest

from fortipam_mcp.target_creation_http_transport import TargetCreationTransportError
from fortipam_mcp.target_preservation_http_transport import TargetCoordinateTransportError
from test_target_creation_http_transport import setup as creation_setup, create
from test_target_preservation_http_transport import setup as coordinate_setup, dispatch


class Socket:
    def __init__(self):self.closed=False;self.timeouts=[]
    def fileno(self):return -1 if self.closed else 42
    def settimeout(self,value):
        assert not self.closed
        self.timeouts.append(value)


def instrument(peer, fault, *, writes_only=False):
    factory=peer.factory;sockets=[];raw_buffers=[]
    def wrapped(*args,**kwargs):
        conn=factory(*args,**kwargs);sock=Socket();sockets.append(sock);conn.sock=sock
        original_connect=conn.connect;original_request=conn.request;original_headers=conn.getresponse;original_close=conn.close
        active=[not writes_only]
        def connect():
            original_connect()
            if fault=='connect' and not writes_only:peer.now=150
        def request(method,path,body,headers):
            assert headers['User-Agent']=='fortipam-mcp-target-lifecycle/1'
            active[0]=not writes_only or method in ('POST','PUT','DELETE')
            original_request(method,path,body,headers)
            if active[0] and fault=='request':peer.now=150
            if active[0] and fault=='narrow':peer.now=149
        def headers():
            response=original_headers();read=response.readinto
            if active[0] and fault=='headers':peer.now=150
            if fault=='closed_eof':conn.sock=None
            def readinto(view):
                raw_buffers.append(view.obj)
                if active[0] and fault=='drip':
                    with view[:1] as small:count=read(small)
                    peer.now+=10
                else:count=read(view)
                if active[0] and fault=='chunk' and count:peer.now=150
                if active[0] and fault=='eof' and not count:peer.now=150
                if fault=='closed_eof' and not count:sock.closed=True
                return count
            response.readinto=readinto
            return response
        def close():
            original_close();sock.closed=True
            if active[0] and fault=='close':peer.now=150
        conn.connect=connect;conn.request=request;conn.getresponse=headers;conn.close=close
        return conn
    peer.factory=wrapped
    return sockets,raw_buffers


def prepared(tmp_path, kind):
    if kind=='creation':
        peer,make=creation_setup(tmp_path);error=TargetCreationTransportError
        invoke=create;claim='create.claim.json';verified='create.verified.json'
    else:
        peer,_,make=coordinate_setup(tmp_path);error=TargetCoordinateTransportError
        invoke=dispatch;claim='update.claim.json';verified='update.verified.json'
    return peer,make,error,invoke,claim,verified


@pytest.mark.parametrize('kind',['creation','coordinate'])
@pytest.mark.parametrize('fault',['connect','request','headers','chunk','eof','close','drip'])
def test_late_read_denied_without_write_and_terminal_claim(tmp_path,kind,fault):
    peer,make,error,invoke,claim,verified=prepared(tmp_path,kind)
    sockets,buffers=instrument(peer,fault)
    with pytest.raises(error):invoke(make(execution_enabled=True))
    assert (tmp_path/claim).exists() and not (tmp_path/verified).exists()
    assert all(method=='GET' for method in peer.calls)
    assert all(not any(buffer) for buffer in buffers)
    assert all(conn.closed for conn in peer.connections)
    before=list(peer.calls);peer.now=100
    with pytest.raises(error):invoke(make(execution_enabled=True))
    assert peer.calls==before


@pytest.mark.parametrize('kind',['creation','coordinate'])
@pytest.mark.parametrize('fault',['request','headers','chunk','eof','close'])
def test_late_write_response_remains_consumed_without_followup(tmp_path,kind,fault):
    peer,make,error,invoke,claim,verified=prepared(tmp_path,kind)
    sockets,buffers=instrument(peer,fault,writes_only=True)
    with pytest.raises(error):invoke(make(execution_enabled=True))
    assert peer.calls==['GET','POST' if kind=='creation' else 'PUT']
    assert (tmp_path/claim).exists() and not (tmp_path/verified).exists()
    assert all(not any(buffer) for buffer in buffers)
    assert all(conn.closed for conn in peer.connections)
    before=list(peer.calls);peer.now=100
    with pytest.raises(error):invoke(make(execution_enabled=True))
    assert peer.calls==before


@pytest.mark.parametrize('kind',['creation','coordinate'])
@pytest.mark.parametrize('fault',['closed_eof','narrow'])
def test_closed_eof_and_remaining_socket_timeout(tmp_path,kind,fault):
    peer,make,error,invoke,claim,verified=prepared(tmp_path,kind)
    sockets,buffers=instrument(peer,fault)
    invoke(make(execution_enabled=True))
    assert (tmp_path/verified).exists()
    assert all(not any(buffer) for buffer in buffers)
    assert all(sock.closed and sock.timeouts for sock in sockets)
    if fault=='narrow':assert 1 in sockets[0].timeouts


@pytest.mark.parametrize('fault',['request','headers','chunk','eof','close'])
def test_late_delete_response_never_becomes_verified(tmp_path,fault):
    from test_target_original_ack_recovery import prepared as recovery_prepared, recover
    peer,make,original=recovery_prepared(tmp_path)
    sockets,buffers=instrument(peer,fault,writes_only=True)
    with pytest.raises(TargetCreationTransportError):recover(make(recovery_enabled=True),original.created)
    assert peer.calls[-1]=='DELETE' and peer.calls.count('DELETE')==1
    assert (tmp_path/'delete.claim.json').exists() and not (tmp_path/'delete.verified.json').exists()
    assert all(not any(buffer) for buffer in buffers)
    assert all(conn.closed for conn in peer.connections)
    before=list(peer.calls);peer.now=100
    with pytest.raises(TargetCreationTransportError):recover(make(recovery_enabled=True),original.created)
    assert peer.calls==before


@pytest.mark.parametrize('kind',['creation','coordinate'])
def test_guard_consumed_time_narrows_connect_timeout(tmp_path,kind):
    peer,make,error,invoke,claim,verified=prepared(tmp_path,kind)
    factory=peer.factory;timeouts=[]
    def wrapped(*args,**kwargs):
        conn=factory(*args,**kwargs);connect=conn.connect
        def observed_connect():
            timeouts.append(conn.timeout);connect()
        conn.connect=observed_connect;return conn
    peer.factory=wrapped;transport=make()
    def guard():peer.now=149
    if kind=='creation':body=transport._exchange('GET',absent=True,deadline=150,guard=guard)
    else:body=transport._request('GET',deadline=150,guard=guard)
    assert timeouts==[1]
    body[:]=b'\0'*len(body)
    if kind=='creation':transport.close()
