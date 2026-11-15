"""Actual fixed-route absence observations for lifecycle pre/postconditions."""
import pytest

from fortipam_mcp import target_creation_http_transport as t
from test_target_creation_http_transport import setup
from test_target_preservation_contract import row
from test_target_http_deadlines import instrument


def test_fresh_native_absence_without_claim_or_write_gate(tmp_path):
    peer, make = setup(tmp_path); transport = make(); guards = []
    first = transport.read_absence(expires_at=150, before_send=lambda:guards.append(True))
    second = transport.read_absence(expires_at=150, before_send=lambda:guards.append(True))
    assert first == second == t.c._digest(('target-actor-visible-absence-v1',
        transport._proposal.name, transport._proposal.serial_digest))
    assert peer.calls == ['GET', 'GET'] and len(guards) == 6
    assert all(obj.closed for obj in peer.connections+peer.responses)
    assert not list(tmp_path.iterdir()) and not transport._enabled and not transport._recovery_enabled


@pytest.mark.parametrize('expiry', [True,100,99,161,150.0])
def test_invalid_window_denies_before_network(tmp_path, expiry):
    peer, make = setup(tmp_path)
    with pytest.raises(t.TargetCreationTransportError):
        make().read_absence(expires_at=expiry, before_send=lambda:None)
    assert not peer.calls and not list(tmp_path.iterdir())


@pytest.mark.parametrize('fault', ['connect','request','headers','chunk','eof','close','drip'])
def test_late_read_denies_and_wipes_without_claim(tmp_path, fault):
    peer, make = setup(tmp_path); sockets, buffers = instrument(peer, fault)
    with pytest.raises(t.TargetCreationTransportError):
        make().read_absence(expires_at=150, before_send=lambda:None)
    assert all(method == 'GET' for method in peer.calls)
    assert all(not any(buffer) for buffer in buffers)
    assert all(conn.closed for conn in peer.connections) and not list(tmp_path.iterdir())


@pytest.mark.parametrize('point', ['before','tls','projection','late_projection'])
def test_guard_and_projection_expiry_deny_and_wipe(tmp_path, monkeypatch, point):
    peer, make = setup(tmp_path); calls = []; buffers = []
    original = t.e._envelope
    def envelope(content, *args, **kwargs):
        buffers.append(content); result = original(content, *args, **kwargs)
        if point == 'late_projection': peer.now = 150
        return result
    monkeypatch.setattr(t.e, '_envelope', envelope)
    def guard():
        calls.append(True)
        if len(calls) == {'before':1,'tls':2,'projection':3}.get(point):
            raise ValueError('PRIVATE_SENTINEL')
    with pytest.raises(t.TargetCreationTransportError) as error:
        make().read_absence(expires_at=150, before_send=guard)
    assert 'PRIVATE_SENTINEL' not in str(error.value)
    assert all(not any(value) for value in buffers)
    assert all(conn.closed for conn in peer.connections) and not list(tmp_path.iterdir())


@pytest.mark.parametrize('fault', ['present','wrong_status','malformed_envelope'])
def test_existing_or_unqualified_response_never_becomes_absence(tmp_path, monkeypatch, fault):
    peer, make = setup(tmp_path)
    if fault == 'present': peer.created = row()
    if fault == 'wrong_status': peer.already_exists = True
    if fault == 'malformed_envelope':
        import test_target_creation_http_transport as fixture
        monkeypatch.setattr(fixture, 'envelope', lambda **kwargs:b'{"status":"Not Found"}')
    with pytest.raises(t.TargetCreationTransportError):
        make().read_absence(expires_at=150, before_send=lambda:None)
    assert peer.calls == ['GET'] and not list(tmp_path.iterdir())


@pytest.mark.parametrize('expire_after_tls', [False,True])
def test_absence_requires_fresh_actual_source_binding(tmp_path, monkeypatch, expire_after_tls):
    import ssl
    from test_target_api_dependency_reader import Harness, COORDINATES
    original = ssl.create_default_context
    monkeypatch.setattr(ssl, 'create_default_context', lambda **kwargs:original())
    ca = tmp_path/'ca.pem'; ca.write_text('SYNTHETIC_CA')
    directory = tmp_path/'state'; directory.mkdir(mode=0o700)
    peer, make = setup(directory, ca_file=str(ca)); transport = make()
    h = Harness(); reader = h.reader(base_url='https://pam.example', ca_file=str(ca))
    observation = reader.observe(COORDINATES)
    def hook():
        if expire_after_tls: h.now = 40
    peer.hook = hook
    def guard(): reader.check_transport_source(observation, transport)
    if expire_after_tls:
        with pytest.raises(t.TargetCreationTransportError):
            transport.read_absence(expires_at=150, before_send=guard)
        assert not peer.calls
    else:
        assert len(transport.read_absence(expires_at=150, before_send=guard)) == 64
        assert peer.calls == ['GET']
    assert not list(directory.iterdir()) and all(conn.closed for conn in peer.connections)
