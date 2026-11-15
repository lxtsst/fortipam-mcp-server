"""Protected metadata projection with generated public certificates only."""
import base64
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import pickle
from xml.etree import ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
import pytest

from fortipam_mcp import saml_idp_metadata_probe as native
from fortipam_mcp.saml_idp_metadata_probe import SamlMetadataBinding, SamlIdpMetadataProbe
from test_saml_server_contract import fixture
from test_saml_server_native_source import Socket
from test_system_email_m4_adapter import Clock
from v4_planning.material_provider import MaterialAccessDenied

MD,DS = native._MD,native._DS


def signing_certificate(*, not_before=0, not_after=10000):
    key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'Synthetic IdP signing certificate')])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())\
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.fromtimestamp(not_before,timezone.utc))\
        .not_valid_after(datetime.fromtimestamp(not_after,timezone.utc)).sign(key,hashes.SHA256())
    der = cert.public_bytes(Encoding.DER)
    return base64.b64encode(der).decode('ascii'),hashlib.sha256(der).hexdigest()


def document(record, certificate):
    root = ET.Element(MD+'EntityDescriptor',entityID=record['idp-entity-id'])
    role = ET.SubElement(root,MD+'IDPSSODescriptor',protocolSupportEnumeration=native._PROTOCOL)
    key = ET.SubElement(role,MD+'KeyDescriptor',use='signing')
    info = ET.SubElement(key,DS+'KeyInfo'); data = ET.SubElement(info,DS+'X509Data')
    ET.SubElement(data,DS+'X509Certificate').text = certificate
    for name,field in (('SingleSignOnService','idp-single-sign-on-url'),('SingleLogoutService','idp-single-logout-url')):
        ET.SubElement(role,MD+name,Binding=sorted(native._HTTP_BINDINGS)[0],Location=record[field])
    return root


@pytest.fixture(scope='module')
def certificates(): return signing_certificate(),signing_certificate()


class Peer:
    def __init__(self, certificates):
        self.record,_,_ = fixture(); self.certificates = certificates
        self.root = document(self.record,certificates[0][0]); self.clock = Clock(); self.time = 10.0
        self.binding = SamlMetadataBinding(self.record,metadata_url='https://pam.example.test/idp/metadata',
            signing_certificate_sha256=certificates[0][1])
        self.calls = []; self.resources = []; self.buffers = []; self.fault = None; self.xml = None
    def factory(self, host, port, **kwargs):
        peer = self
        class Connection:
            def __init__(self): self.sock = Socket(); self.closed = False; peer.resources.append(self)
            def set_debuglevel(self, level): assert level == 0
            def connect(self): assert host == 'pam.example.test'
            def request(self, method, path, *, headers):
                assert method == 'GET' and path == '/idp/metadata'
                assert 'Authorization' not in headers and 'Cookie' not in headers
                peer.calls.append(path)
            def getresponse(self): return Response()
            def close(self):
                self.closed = True
                if peer.fault == 'close': raise RuntimeError('SYNTHETIC_PRIVATE_CLOSE')
        class Response:
            def __init__(self):
                self.status = 302 if peer.fault == 'redirect' else 200; self.offset = 0; self.closed = False
                self.raw = peer.xml if peer.xml is not None else ET.tostring(peer.root,encoding='utf-8')
                if peer.fault == 'oversize': self.raw += b' '*65536
                peer.resources.append(self)
            def getheader(self, name, default=None):
                return {'content-type':'text/html' if peer.fault == 'html' else 'application/samlmetadata+xml',
                    'content-length':str(len(self.raw)+(1 if peer.fault == 'truncated' else 0)),
                    'content-encoding':'gzip' if peer.fault == 'compressed' else 'identity'}.get(name.lower(),default)
            def isclosed(self): return self.offset >= len(self.raw)
            def readinto(self, view):
                if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                count = min(len(view),len(self.raw)-self.offset,113)
                view[:count] = self.raw[self.offset:self.offset+count]; self.offset += count
                if peer.fault == 'deadline': peer.time += 1
                return count
            def close(self): self.closed = True
        return Connection()
    def probe(self, *, enabled=True, guarded=True):
        return SamlIdpMetadataProbe(self.binding,source_digest='a'*64,enabled=enabled,
            source_guard=(lambda: True) if guarded else None,connection_factory=self.factory,
            http_clock=lambda: self.time,clock=self.clock)


def test_fixed_unauthenticated_read_matches_only_the_bound_entity_endpoints_and_pin(certificates):
    peer = Peer(certificates); observation = peer.probe().observe(peer.binding.record_digest,timeout_seconds=5)
    assert observation.signing_certificate_sha256 == certificates[0][1]
    assert observation.record_digest == peer.binding.record_digest and observation.expires_at == 1010
    assert observation.summary()['prebound_signing_certificate_pin_matched'] is True
    assert observation.summary()['native_certificate_source_verified'] is False
    assert observation.summary()['metadata_signature_verified'] is False
    assert observation.summary()['saml_login_verified'] is False
    assert peer.calls == ['/idp/metadata'] and all(resource.closed for resource in peer.resources)
    assert all(not any(raw) for raw in peer.buffers)
    assert 'example' not in json.dumps(observation.summary()) and 'example' not in repr(observation)


@pytest.mark.parametrize('fault', ['entity','sso','slo','wrong-pin','duplicate-pin','encryption-only','wrong-role',
    'protocol','wrapping','ambiguous-role','invalid-cert','expired-metadata','unsigned-attribute','sso-response',
    'url-userinfo','redirect','html','compressed','truncated','close','deadline','oversize','depth'])
def test_foreign_ambiguous_expired_or_incomplete_metadata_never_returns_trust(certificates, fault):
    peer = Peer(certificates); role = peer.root.find(MD+'IDPSSODescriptor')
    if fault == 'entity': peer.root.set('entityID','https://synthetic-other.invalid')
    elif fault in ('sso','slo','url-userinfo'):
        name = 'SingleLogoutService' if fault == 'slo' else 'SingleSignOnService'
        role.find(MD+name).set('Location','https://user:password@idp.example/' if fault == 'url-userinfo' else 'https://synthetic-other.invalid/')
    elif fault == 'wrong-pin': role.find('.//'+DS+'X509Certificate').text = certificates[1][0]
    elif fault == 'duplicate-pin': role.append(copy.deepcopy(role.find(MD+'KeyDescriptor')))
    elif fault == 'encryption-only': role.find(MD+'KeyDescriptor').set('use','encryption')
    elif fault == 'wrong-role': role.tag = MD+'SPSSODescriptor'
    elif fault == 'protocol': role.set('protocolSupportEnumeration','urn:synthetic:other')
    elif fault == 'wrapping':
        peer.root.remove(role); ET.SubElement(peer.root,MD+'Extensions').append(role)
    elif fault == 'ambiguous-role': peer.root.append(copy.deepcopy(role))
    elif fault == 'invalid-cert': role.find('.//'+DS+'X509Certificate').text = 'invalid-cert'
    elif fault == 'expired-metadata': peer.root.set('validUntil','1970-01-01T00:16:39Z')
    elif fault == 'unsigned-attribute': role.set('WantAuthnRequestsSigned','invalid')
    elif fault == 'sso-response': role.find(MD+'SingleSignOnService').set('ResponseLocation','https://synthetic-response.invalid/')
    elif fault == 'depth':
        child = ET.SubElement(peer.root,MD+'Extensions')
        for _ in range(18): child = ET.SubElement(child,'synthetic')
    else: peer.fault = fault
    with pytest.raises(ValueError,match='unavailable'): peer.probe().observe(peer.binding.record_digest,timeout_seconds=5)
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('encoding', ['utf-8','utf-16'])
def test_dtd_and_external_entities_are_refused_without_a_second_request(certificates, encoding):
    peer = Peer(certificates)
    peer.xml = ('<?xml version="1.0" encoding="'+encoding+'"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "https://synthetic-other.invalid/">]>'
        '<root>&xxe;</root>').encode(encoding)
    with pytest.raises(ValueError,match='unavailable'): peer.probe().observe(peer.binding.record_digest,timeout_seconds=5)
    assert peer.calls == ['/idp/metadata'] and all(not any(raw) for raw in peer.buffers)


def test_unknown_extensions_are_not_hashed_and_security_relevant_projection_drift_is_bound(certificates):
    peer = Peer(certificates); probe = peer.probe()
    first = probe.observe(peer.binding.record_digest,timeout_seconds=5)
    ET.SubElement(ET.SubElement(peer.root,MD+'Extensions'),'synthetic-private-extension').text = 'SYNTHETIC_UNSELECTED_VALUE'
    same = probe.observe(peer.binding.record_digest,timeout_seconds=5)
    assert same.metadata_digest == first.metadata_digest
    role = peer.root.find(MD+'IDPSSODescriptor'); role.set('WantAuthnRequestsSigned','true')
    changed = probe.observe(peer.binding.record_digest,timeout_seconds=5)
    assert changed.metadata_digest != first.metadata_digest and changed.authn_requests_signature_required is True
    role.find(MD+'SingleLogoutService').set('ResponseLocation','https://synthetic-response.invalid/')
    assert probe.observe(peer.binding.record_digest,timeout_seconds=5).metadata_digest != changed.metadata_digest


@pytest.mark.parametrize('limits', [(1001,2000),(0,1000)])
def test_selected_certificate_outside_its_validity_window_is_refused(limits):
    public = signing_certificate(not_before=limits[0],not_after=limits[1])
    peer = Peer((public,public))
    with pytest.raises(ValueError,match='unavailable'): peer.probe().observe(peer.binding.record_digest,timeout_seconds=5)


def test_valid_until_caps_the_observation_and_multiple_signing_keys_do_not_rotate_the_pin(certificates):
    peer = Peer(certificates); role = peer.root.find(MD+'IDPSSODescriptor')
    extra = copy.deepcopy(role.find(MD+'KeyDescriptor')); extra.find('.//'+DS+'X509Certificate').text = certificates[1][0]
    role.append(extra); peer.root.set('validUntil','1970-01-01T00:16:45Z')
    observation = peer.probe().observe(peer.binding.record_digest,timeout_seconds=5)
    assert observation.expires_at == 1005 and observation.signing_certificate_sha256 == certificates[0][1]


@pytest.mark.parametrize('fault', ['disabled','guard','source','tls','closed','old-expat'])
def test_unready_or_foreign_bindings_do_not_connect(certificates, monkeypatch, fault):
    peer = Peer(certificates); probe = peer.probe(enabled=fault != 'disabled',guarded=fault != 'guard')
    if fault == 'tls': probe._tls.check_hostname = False
    if fault == 'closed': probe.close()
    if fault == 'old-expat': monkeypatch.setattr(native.expat,'version_info',(2,5,0))
    with pytest.raises(ValueError,match='unavailable'): probe.observe('f'*64 if fault == 'source' else peer.binding.record_digest,timeout_seconds=5)
    assert peer.calls == []


@pytest.mark.parametrize('clock', ['epoch','monotonic'])
def test_clock_rollback_is_terminal(certificates, clock):
    peer = Peer(certificates); probe = peer.probe(); probe.observe(peer.binding.record_digest,timeout_seconds=5)
    if clock == 'epoch': peer.clock.value = 999
    else: peer.time = 9.0
    with pytest.raises(ValueError,match='unavailable'): probe.observe(peer.binding.record_digest,timeout_seconds=5)
    peer.clock.value = 1000; peer.time = 10.0
    with pytest.raises(ValueError,match='unavailable'): probe.observe(peer.binding.record_digest,timeout_seconds=5)


def test_private_bindings_and_observations_cannot_be_copied_or_serialized(certificates):
    peer = Peer(certificates); observation = peer.probe().observe(peer.binding.record_digest,timeout_seconds=5)
    for value in (peer.binding,observation):
        for transform in (copy.copy,copy.deepcopy,pickle.dumps):
            with pytest.raises(MaterialAccessDenied): transform(value)
    with pytest.raises(ValueError): replace(observation,authn_requests_signature_required=1)
    with pytest.raises(ValueError): SamlMetadataBinding(peer.record,metadata_url='https://user:password@idp.example/metadata',
        signing_certificate_sha256=certificates[0][1])
    with pytest.raises(ValueError): SamlMetadataBinding(peer.record,metadata_url='https://idp.example:0/metadata',
        signing_certificate_sha256=certificates[0][1])


def test_missing_optional_parser_fails_before_network_and_disabled_probe_remains_constructible(certificates, monkeypatch):
    import builtins
    peer = Peer(certificates); original = builtins.__import__
    def importing(name,*args,**kwargs):
        if name == 'defusedxml.ElementTree': raise ModuleNotFoundError('Synthetic optional dependency absence.')
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',importing)
    with pytest.raises(ValueError,match='unavailable'): peer.probe()
    peer.probe(enabled=False)
    assert peer.calls == []


@pytest.mark.parametrize('drift', [False,True])
def test_real_projection_joins_fixed_saml_reads_and_blocks_m4_on_signing_pin_drift(certificates, tmp_path, drift):
    from test_saml_server_native_source import Peer as ApiPeer
    from test_saml_server_local_m4 import make, removal
    from v4_planning import M4AdapterDenied

    metadata = Peer(certificates); probe = metadata.probe(); api = ApiPeer()
    other_dependencies = api.dependencies.observe
    def combined(record_digest, *, timeout_seconds):
        trust = probe.observe(record_digest,timeout_seconds=timeout_seconds)
        other = other_dependencies(record_digest,timeout_seconds=timeout_seconds)
        # Global/proxy/certificate-source/isolation/recovery peers remain
        # synthetic. The new metadata producer supplies only its own fields.
        return replace(other,idp_metadata_digest=trust.metadata_digest,idp_certificate_sha256=trust.signing_certificate_sha256,
            observed_at=max(other.observed_at,trust.observed_at),expires_at=min(other.expires_at,trust.expires_at))
    api.dependencies.observe = combined
    value = make(tmp_path,peer=api)
    if drift:
        value.backend.on_send = lambda: setattr(metadata.root.find('.//'+DS+'X509Certificate'),'text',certificates[1][0])
    result = value.kernel.execute(value.plan,value.authorization)
    assert (result.outcome == 'succeeded') is not drift
    reads = len(metadata.calls)
    assert value.kernel.execute(value.plan,value.authorization).idempotent_replay
    assert len(metadata.calls) == reads
    if drift:
        assert value.backend.sends == 0
        with pytest.raises(M4AdapterDenied): removal(value)
    else:
        kernel,plan,authorization = removal(value)
        assert kernel.execute(plan,authorization).outcome == 'succeeded'
        assert value.backend.sends == value.store.claim_count == 2
    assert all(not any(raw) for raw in metadata.buffers)


def test_real_loopback_tls_fetch_has_no_management_authentication_or_secondary_requests(certificates, tmp_path):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from test_secret_bulk_import_action_process import tls_material

    certificate,key = tls_material(tmp_path); peer = Peer(certificates); requests = []; connections = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def do_GET(self):
            assert self.path == '/idp/metadata' and 'Authorization' not in self.headers and 'Cookie' not in self.headers
            requests.append(self.path); raw = ET.tostring(peer.root,encoding='utf-8')
            self.send_response(200); self.send_header('Content-Type','application/samlmetadata+xml')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close')
            self.end_headers(); self.wfile.write(raw)
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key)
    server.socket = tls.wrap_socket(server.socket,server_side=True)
    thread = Thread(target=server.serve_forever,daemon=True); thread.start()
    def factory(host,port,**kwargs):
        connection = http.client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(
            ('127.0.0.1',server.server_port),timeout,source_address)
        connections.append(connection); return connection
    probe = SamlIdpMetadataProbe(peer.binding,source_digest='a'*64,ca_file=str(certificate),enabled=True,
        source_guard=lambda: True,connection_factory=factory,clock=peer.clock)
    try:
        observation = probe.observe(peer.binding.record_digest,timeout_seconds=5)
        assert observation.signing_certificate_sha256 == certificates[0][1]
        assert observation.summary()['metadata_signature_verified'] is False
        assert requests == ['/idp/metadata'] and all(connection.sock is None for connection in connections)
    finally:
        probe.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
