"""Fixed current/postcondition reads using actual lifecycle HTTP adapters."""
import pytest

from fortipam_mcp import target_preservation_contract as c
from test_target_creation_http_transport import setup as creator_setup
from test_target_preservation_http_transport import setup as coordinate_setup
from test_target_preservation_contract import row, capture
from test_target_http_deadlines import instrument
from fortipam_mcp.target_creation_http_transport import TargetCreationTransportError
from fortipam_mcp.target_preservation_http_transport import TargetCoordinateTransportError


def prepared(tmp_path,kind):
    if kind=='creator':
        peer,make=creator_setup(tmp_path);peer.created=row()
        return peer,make,TargetCreationTransportError
    peer,change,make=coordinate_setup(tmp_path)
    return peer,make,TargetCoordinateTransportError


@pytest.mark.parametrize('kind',['creator','coordinate'])
def test_reads_actual_full_state_on_each_call_without_phase_claim(tmp_path,kind):
    peer,make,error=prepared(tmp_path,kind);transport=make();guards=[]
    first=transport.read_current(expires_at=150,before_send=lambda:guards.append(True))
    value=peer.created if kind=='creator' else peer.row
    value['description']='changed opaque setting'
    second=transport.read_current(expires_at=150,before_send=lambda:guards.append(True))
    assert first==capture(row()) and second==capture(value)
    assert first.state_digest!=second.state_digest and len(guards)==6
    assert peer.calls==['GET','GET'] and all(x.closed for x in peer.connections+peer.responses)
    assert not list(tmp_path.iterdir()) and not transport._enabled
    if kind=='creator':assert not transport._recovery_enabled


@pytest.mark.parametrize('kind',['creator','coordinate'])
@pytest.mark.parametrize('expiry',[True,100,99,161,150.0])
def test_invalid_window_makes_no_request(tmp_path,kind,expiry):
    peer,make,error=prepared(tmp_path,kind)
    with pytest.raises(error):make().read_current(expires_at=expiry,before_send=lambda:None)
    assert not peer.calls and not list(tmp_path.iterdir())


@pytest.mark.parametrize('kind',['creator','coordinate'])
@pytest.mark.parametrize('fault',['connect','request','headers','chunk','eof','close','drip'])
def test_read_deadline_failure_wipes_and_closes_without_claim(tmp_path,kind,fault):
    peer,make,error=prepared(tmp_path,kind);sockets,buffers=instrument(peer,fault)
    with pytest.raises(error):make().read_current(expires_at=150,before_send=lambda:None)
    assert all(x=='GET' for x in peer.calls) and all(not any(x) for x in buffers)
    assert all(x.closed for x in peer.connections) and not list(tmp_path.iterdir())


@pytest.mark.parametrize('kind',['creator','coordinate'])
@pytest.mark.parametrize('point',['before','tls','after_projection','late_projection'])
def test_guard_denial_and_late_projection_fail_closed(tmp_path,kind,point,monkeypatch):
    peer,make,error=prepared(tmp_path,kind);calls=[];buffers=[]
    original=c.capture_target_state
    def capture(content,**kwargs):
        buffers.append(content);state=original(content,**kwargs)
        if point=='late_projection':peer.now=150
        return state
    monkeypatch.setattr(c,'capture_target_state',capture)
    def guard():
        calls.append(True)
        if len(calls)=={'before':1,'tls':2,'after_projection':3}.get(point):raise ValueError('PRIVATE_SENTINEL')
    with pytest.raises(error,match='^Protected Target') as caught:
        make().read_current(expires_at=150,before_send=guard)
    assert 'PRIVATE_SENTINEL' not in str(caught.value)
    assert all(x=='GET' for x in peer.calls) and all(not any(x) for x in buffers)
    assert all(x.closed for x in peer.connections) and not list(tmp_path.iterdir())


@pytest.mark.parametrize('kind',['creator','coordinate'])
def test_full_state_parse_failure_not_a_stored_baseline_fallback(tmp_path,kind):
    peer,make,error=prepared(tmp_path,kind)
    value=peer.created if kind=='creator' else peer.row
    del value['uuid']
    with pytest.raises(error):make().read_current(expires_at=150,before_send=lambda:None)
    assert peer.calls==['GET'] and not list(tmp_path.iterdir())


@pytest.mark.parametrize('kind',['creator','coordinate'])
@pytest.mark.parametrize('expire_after_tls',[False,True])
def test_current_read_joins_fresh_actual_dependency_source_guard(tmp_path,kind,expire_after_tls,monkeypatch):
    import ssl
    from test_target_api_dependency_reader import Harness, COORDINATES
    original=ssl.create_default_context
    monkeypatch.setattr(ssl,'create_default_context',lambda **kwargs:original())
    ca=tmp_path/'ca.pem';ca.write_text('SYNTHETIC_CA')
    directory=tmp_path/'state';directory.mkdir(mode=0o700)
    if kind=='creator':
        peer,make=creator_setup(directory,ca_file=str(ca));peer.created=row()
        error=TargetCreationTransportError
    else:
        peer,change,make=coordinate_setup(directory,ca_file=str(ca))
        error=TargetCoordinateTransportError
    h=Harness();reader=h.reader(base_url='https://pam.example',ca_file=str(ca))
    observed=reader.observe(COORDINATES);transport=make()
    def expire():
        if expire_after_tls:h.now=40
    if kind=='creator':peer.hook=expire
    else:peer.connect_hook=expire
    def guard():reader.check_transport_source(observed,transport)
    if expire_after_tls:
        with pytest.raises(error):transport.read_current(expires_at=150,before_send=guard)
        assert peer.calls==[]
    else:
        assert transport.read_current(expires_at=150,before_send=guard)==capture(row())
        assert peer.calls==['GET']
    assert len(h.requests)==8 and all(conn.closed for conn in peer.connections)
    assert not list(directory.iterdir()) and not transport._enabled
