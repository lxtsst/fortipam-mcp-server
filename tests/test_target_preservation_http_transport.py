"""Fixed coordinate transport: drift, durable non-replay and dispatch-time guards."""
from dataclasses import replace
import io
import json
import ssl
from pathlib import Path

import pytest

from fortipam_mcp import target_preservation_http_transport as t
from fortipam_mcp import target_preservation_contract as c
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_target_preservation_contract import row, response, capture, SERIAL


class Response:
    status = 200
    def __init__(self, raw: bytearray): self.raw = io.BytesIO(raw); self.closed = False
    def getheader(self, name: str, default: str = '') -> str:
        return 'application/json' if name == 'Content-Type' else default
    def readinto(self, buffer: memoryview) -> int: return self.raw.readinto(buffer)
    def close(self) -> None: self.closed = True


class Peer:
    def __init__(self):
        self.row = row(); self.calls = []; self.responses = []; self.bodies = []
        self.contexts = []; self.connections = []; self.now = 100; self.connect_hook = lambda: None
        self.lose_ack = False; self.side_effect = False; self.bad_ack = False
    def factory(self, host, port, **kwargs):
        assert host == 'pam.example' and port == 443
        assert kwargs['context'].check_hostname
        self.contexts.append(kwargs['context'])
        peer = self
        class Connection:
            closed = False
            def connect(self): peer.connect_hook()
            def request(self, method, path, body, headers):
                assert headers['Authorization'] == 'Bearer synthetic-token'
                assert path == '/api/v2/cmdb/secret/target/synthetic-target?with_meta=true&vdom=root'
                peer.calls.append(method)
                if method == 'PUT':
                    peer.bodies.append(body.obj)
                    update = json.loads(bytes(body))
                    assert set(update) <= {'address', 'domain', 'template', 'url'}
                    peer.row.update(update)
                    if peer.side_effect: peer.row['description'] = 'unexpected'
                    if peer.lose_ack: raise OSError('sensitive transport detail')
                    envelope = {'version':'v7.0.0', 'build':29, 'path':'secret', 'name':'target',
                        'status':'success', 'http_method':'PUT', 'http_status':200, 'vdom':'root',
                        'serial':SERIAL, 'mkey':'wrong' if peer.bad_ack else 'synthetic-target',
                        'results':{'unknown':'MATERIAL_SENTINEL'}}
                    raw = bytearray(json.dumps(envelope).encode())
                else: raw = response(peer.row)
                self.response = Response(raw); peer.responses.append(self.response)
            def getresponse(self): return self.response
            def close(self): self.closed = True
        conn = Connection(); self.connections.append(conn); return conn


def setup(tmp_path: Path, ca_file=None):
    tmp_path.chmod(0o700)
    peer = Peer(); baseline = capture(peer.row)
    change = c.TargetCoordinateChange(baseline, replace(baseline.coordinates, address='192.0.2.99'))
    def make(**kwargs):
        return t.TargetCoordinateHttpTransport(SecretMetadataHttpTransportConfig('https://pam.example', 'synthetic-token', 5, ca_file),
            change, state_directory=tmp_path, clock=lambda:peer.now, connection_factory=peer.factory, **kwargs)
    return peer, change, make


def dispatch(transport, phase='update', **kwargs):
    return transport.dispatch(phase=phase, plan_digest='a'*64, authorization_digest='b'*64,
        expires_at=150, before_send=lambda:None, **kwargs)


def test_roundtrip_and_durable_replay_denial(tmp_path):
    peer, change, make = setup(tmp_path)
    updated = dispatch(make(execution_enabled=True))
    assert peer.calls == ['GET','PUT','GET']
    with pytest.raises(t.TargetCoordinateTransportError): dispatch(make(execution_enabled=True))
    assert peer.calls == ['GET','PUT','GET']
    restored = dispatch(make(execution_enabled=True), 'restore', updated=updated)
    assert restored.state_digest == change.baseline.state_digest
    assert peer.calls == ['GET','PUT','GET']*2
    with pytest.raises(t.TargetCoordinateTransportError): dispatch(make(execution_enabled=True), 'restore', updated=updated)
    assert len(peer.calls) == 6
    assert all(not any(body) for body in peer.bodies)
    assert all(conn.closed for conn in peer.connections) and all(r.closed for r in peer.responses)
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in tmp_path.iterdir())


@pytest.mark.parametrize('fault', ['disabled','drift','expiry','guard','rollback','lost_ack','side_effect','bad_ack'])
def test_failure_never_retries(tmp_path, fault):
    peer, change, make = setup(tmp_path)
    transport = make(execution_enabled=fault != 'disabled')
    if fault == 'drift': peer.row['description'] = 'drift'
    if fault == 'expiry': peer.connect_hook = lambda:setattr(peer,'now',151)
    if fault == 'rollback': peer.connect_hook = lambda:setattr(peer,'now',99)
    if fault == 'lost_ack': peer.lose_ack = True
    if fault == 'side_effect': peer.side_effect = True
    if fault == 'bad_ack': peer.bad_ack = True
    def deny(): raise ValueError('sensitive authority failure')
    with pytest.raises(t.TargetCoordinateTransportError) as caught:
        transport.dispatch(phase='update', plan_digest='a'*64, authorization_digest='b'*64,
            expires_at=150, before_send=deny if fault == 'guard' else lambda:None)
    assert str(caught.value) == 'Protected Target coordinate transport unavailable.'
    writes = peer.calls.count('PUT')
    assert writes == (1 if fault in ('lost_ack','side_effect','bad_ack') else 0)
    if (tmp_path/'update.claim.json').exists():
        with pytest.raises(t.TargetCoordinateTransportError): dispatch(make(execution_enabled=True))
        assert peer.calls.count('PUT') == writes
    assert all(not any(body) for body in peer.bodies)
    assert all(conn.closed for conn in peer.connections)


def test_expiry_during_put_tls_consumes_without_put(tmp_path):
    peer, _, make = setup(tmp_path)
    def hook():
        if peer.calls == ['GET']: peer.now = 150
    peer.connect_hook = hook
    with pytest.raises(t.TargetCoordinateTransportError): dispatch(make(execution_enabled=True))
    assert peer.calls == ['GET'] and (tmp_path/'update.claim.json').exists()


def test_restore_requires_verified_update_and_no_drift(tmp_path):
    peer, change, make = setup(tmp_path)
    with pytest.raises(t.TargetCoordinateTransportError): dispatch(make(execution_enabled=True),'restore',updated=change.baseline)
    assert not peer.calls
    updated = dispatch(make(execution_enabled=True))
    peer.row['description'] = 'drift'
    with pytest.raises(t.TargetCoordinateTransportError): dispatch(make(execution_enabled=True),'restore',updated=updated)
    assert peer.calls.count('PUT') == 1


def test_symlink_claim_denied(tmp_path):
    peer, _, make = setup(tmp_path)
    transport = make(execution_enabled=True)
    (tmp_path/'update.claim.json').symlink_to(tmp_path/'missing')
    with pytest.raises(t.TargetCoordinateTransportError): dispatch(transport)
    assert not peer.calls


def test_ack_unknown_value_never_decoded(monkeypatch):
    baseline = capture(row())
    change = c.TargetCoordinateChange(baseline, replace(baseline.coordinates,address='192.0.2.99'))
    loads = json.loads
    def bounded(raw, *args, **kwargs):
        assert b'MATERIAL_SENTINEL' not in bytes(raw)
        return loads(raw,*args,**kwargs)
    monkeypatch.setattr(t.m.json,'loads',bounded)
    raw = bytearray(json.dumps({'version':'v7.0.0','build':29,'path':'secret','name':'target',
        'http_method':'PUT','status':'success','http_status':200,'vdom':'root','serial':SERIAL,
        'mkey':'synthetic-target','results':{'unknown':'MATERIAL_SENTINEL'}}).encode())
    assert len(t._ack(raw,change)) == 64 and not any(raw)


def test_directory_replaced_after_connect_denies_put(tmp_path):
    peer, _, make = setup(tmp_path)
    def replace_directory():
        if peer.calls == ['GET']:
            tmp_path.rename(tmp_path.with_name(tmp_path.name+'-retained'))
            tmp_path.mkdir(mode=0o700)
    peer.connect_hook = replace_directory
    with pytest.raises(t.TargetCoordinateTransportError): dispatch(make(execution_enabled=True))
    assert peer.calls == ['GET']


def test_mutation_requires_authority_after_tls(tmp_path):
    peer, _, make = setup(tmp_path)
    allowed = [True]
    def hook():
        if peer.calls == ['GET']: allowed[0] = False
    peer.connect_hook = hook
    def authority():
        if not allowed[0]: raise ValueError
    with pytest.raises(t.TargetCoordinateTransportError):
        make(execution_enabled=True).dispatch(phase='update',plan_digest='a'*64,
            authorization_digest='b'*64,expires_at=150,before_send=authority)
    assert peer.calls == ['GET']


def test_phase_subclass_rejected_before_files_or_network(tmp_path):
    peer, _, make = setup(tmp_path)
    class InjectedPhase(str):
        def __add__(self, suffix): return '../escaped'+suffix
    with pytest.raises(t.TargetCoordinateTransportError):
        dispatch(make(execution_enabled=True), InjectedPhase('update'))
    assert not peer.calls and not list(tmp_path.iterdir())
    assert not (tmp_path.parent/'escaped.claim.json').exists()


@pytest.mark.parametrize('replace_between_requests', [False, True])
def test_configured_ca_snapshot_cannot_change_after_binding(tmp_path, monkeypatch, replace_between_requests):
    ca_file = tmp_path.parent / ('synthetic-roots-' + str(replace_between_requests) + '.pem')
    ca_file.write_text('ORIGINAL_CA_SNAPSHOT')
    loaded = []
    def context_from_snapshot(*, cadata):
        loaded.append(cadata)
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(t.ssl,'create_default_context',context_from_snapshot)
    peer, _, make = setup(tmp_path, str(ca_file))
    transport = make(execution_enabled=True)
    if replace_between_requests:
        def hook():
            if peer.calls == ['GET']: ca_file.write_text('REPLACED_CA')
        peer.connect_hook = hook
    else:
        ca_file.write_text('REPLACED_CA')
    dispatch(transport)
    assert loaded == ['ORIGINAL_CA_SNAPSHOT']
    assert len(peer.contexts) == 3 and all(context is peer.contexts[0] for context in peer.contexts)
