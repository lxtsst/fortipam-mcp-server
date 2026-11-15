"""Combined native leaf import, identity, preservation and owned recovery check."""
import base64
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import time
from urllib.parse import parse_qs

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import httpx
import pytest

from fortipam_mcp.remote_certificate_identity import RemoteCertificateIdentity, expected_remote_import_name
from fortipam_mcp.remote_certificate_transport import COLLECTION, IMPORT, SELECTOR, NativeRemoteCertificateTransport, _TYPES
from fortipam_mcp.remote_certificate_workflow import NativeRemoteCertificateWorkflow
from fortipam_mcp.remote_certificate_runtime import PREFIX, build_remote_certificate_candidate
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore

NONCE = '0123456789abcdef'
NAME = expected_remote_import_name(NONCE)
SERIAL, OWNER = 'synthetic-remote-serial', 'synthetic-remote-owner'
IDENTITY = dict(requester_digest='1' * 64, transport_digest='2' * 64)


def public_leaf(nonce, now):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mcp-remote-' + nonce)])
    dt = datetime.fromtimestamp(now, timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(dt - timedelta(minutes=5)).not_valid_after(dt + timedelta(hours=6))
        .add_extension(x509.BasicConstraints(False, None), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), True)
        .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))


def frame(result, *, name='remote', path='vpn.certificate', method='GET', **extra):
    return dict(dict(http_method=method, status='success', http_status=200, version='v7.0.0', build=29,
        serial=SERIAL, vdom='root', name=name, path=path, results=deepcopy(result)), **extra)


class Peer:
    def __init__(self, fault):
        self.now = int(time.time()); self.fault = fault
        self.pem = public_leaf(NONCE, self.now)
        self.identity = RemoteCertificateIdentity.from_public_pem(NAME, self.pem)
        self.defaults = dict(name='', remote='', range='vdom', source='user')
        self.schema = {key: dict(type=value) for key, value in _TYPES.items()}
        self.schema['name'].update(required=True, size=35)
        self.original = dict(name='synthetic-original', remote='synthetic-opaque', range='vdom', source='user')
        self.original_cert = dict(name='synthetic-original', type='remote-cer', fingerprint='f' * 64,
            valid_from=100, valid_to=200, trusted=False, q_ref=1)
        self.rows = [deepcopy(self.original)]; self.certs = [deepcopy(self.original_cert)]
        if fault == 'capacity':
            self.rows = [dict(self.original, name='synthetic-original-' + str(i)) for i in range(32)]
            self.certs = [dict(self.original_cert, name=row['name']) for row in self.rows]
        self.original_rows, self.original_certs = deepcopy(self.rows), deepcopy(self.certs)
        self.writes = []; self.sessions = self.logouts = 0; self.store = None

    def owner(self):
        peer = self
        class Owner:
            logout_verified = False
            @contextmanager
            def authenticated(self):
                peer.sessions += 1
                self._client = httpx.Client(base_url='https://synthetic.example', cookies={'ccsrftoken': 'synthetic-csrf'},
                    transport=httpx.MockTransport(peer.handle))
                try: yield self
                finally:
                    self._client.close(); self.logout_verified = True; peer.logouts += 1
        return Owner()

    def handle(self, request):
        path, method = request.url.path, request.method
        query = parse_qs(request.url.query.decode())
        if method == 'GET':
            if path == '/api/v2/monitor/web-ui/state':
                return httpx.Response(200, json=frame({'admin': dict(name=OWNER, login_name=OWNER,
                    sponsored_group_name='', guest_admin=False)}, name='state', path='web-ui'))
            if path == COLLECTION:
                action = query.get('action')
                result = {'children': self.schema} if action == ['schema'] else self.defaults if action == ['default'] else [dict(row, q_no_edit=bool(self.sessions % 2)) for row in self.rows]
                return httpx.Response(200, json=frame(result))
            if path == SELECTOR.split('?')[0]:
                return httpx.Response(200, json=frame(self.certs, name='available-certificates', path='system'))
            if path == '/api/v2/monitor/web-ui/object-urls':
                return httpx.Response(200, json=frame({'by_type': {'123': {'path': 'vpn.certificate.remote'}}}, name='object-urls', path='web-ui'))
            if path == '/api/v2/monitor/system/object/usage':
                assert query == {'mkey': [NAME], 'qtypes': ['[123]']}
                return httpx.Response(200, json=frame({'currently_using': ['synthetic-ref'] if self.fault == 'referenced' else []},
                    name='object', path='system', mkey=NAME))
            raise AssertionError('unexpected native route')
        assert request.headers['X-CSRFTOKEN'] == 'synthetic-csrf'
        assert self.store.claim_count == len(self.writes) + 1
        self.writes.append(method)
        if method == 'POST':
            assert path == IMPORT
            assert json.loads(request.content) == dict(scope='vdom', certname=NONCE, file_content=base64.b64encode(self.pem).decode())
            self.rows.append(dict(self.defaults, name=NAME, range="global", q_origin_key=NAME))
            self.certs.append(dict(name=NAME, type='remote-cer', fingerprint=self.identity.sha256,
                valid_from=self.identity.valid_from, valid_to=self.identity.valid_to))
            if self.fault == 'range-drift': self.rows[-1]['range'] = 'vdom'
            if self.fault == 'wrong-identity': self.certs[-1]['fingerprint'] = 'e' * 64
            if self.fault == 'original-drift': self.rows[0]['range'] = 'global'
            if self.fault == 'trust-drift': self.certs[0]['trusted'] = True
            if self.fault == 'lost-ack': raise httpx.ReadTimeout('synthetic')
            return httpx.Response(200, json=frame({}, path='vpn-certificate', method=method, action='import',
                **({'serial': 'different'} if self.fault == 'wrong-ack' else {})))
        assert method == 'DELETE' and path == COLLECTION + '/' + NAME and not request.content
        self.rows = deepcopy(self.original_rows); self.certs = deepcopy(self.original_certs)
        return httpx.Response(200, json=frame({}, method=method, mkey=NAME))


def make(root, peer):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = root / 'execution.key'
    if not key.exists(): key.write_bytes(b'e' * 32); key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(root / 'execution.sqlite3', key); peer.store = store
    transport = NativeRemoteCertificateTransport(owner_factory=peer.owner, owner_name=OWNER, serial=SERIAL,
        nonce=NONCE, certificate_pem=peer.pem, clock=lambda: peer.now)
    return NativeRemoteCertificateWorkflow(transport, store, authority_key=b'a' * 32,
        environment_ref='synthetic-environment', scope_ref='synthetic-scope', audience_ref='synthetic-audience',
        allowed_requester_digest=IDENTITY['requester_digest'], allowed_transport_digest=IDENTITY['transport_digest'],
        import_enabled=True, recovery_enabled=True, clock=lambda: peer.now)


def run(workflow, phase):
    preview = workflow.preview(phase, **IDENTITY)
    assert preview['Proposed Changes']['native_certificate_storage_range'] == 'global'
    auth = workflow.authorize(phase, preview['preview_ref'], **IDENTITY)
    return workflow.execute(phase, auth['authorization_ref'], **IDENTITY), auth


def test_native_leaf_import_owned_recovery_and_preservation(tmp_path):
    assert build_remote_certificate_candidate({}) is None
    with pytest.raises(ValueError): build_remote_certificate_candidate({PREFIX + 'IMPORT_ENABLED': 'true'})
    for fault in ('none', 'capacity', 'range-drift', 'wrong-identity', 'original-drift', 'trust-drift', 'referenced', 'lost-ack', 'wrong-ack'):
        peer = Peer(fault); root = (tmp_path / fault).resolve(); workflow = make(root, peer)
        result, auth = run(workflow, 'import')
        assert workflow.execute('import', auth['authorization_ref'], **IDENTITY)['idempotent_replay']
        if fault in {'none', 'capacity'}:
            assert result['outcome'] == 'succeeded' and result['verification'] == 'verified'
            assert run(workflow, 'recover')[0]['outcome'] == 'succeeded'
            assert peer.writes == ['POST', 'DELETE'] and peer.rows == peer.original_rows
            assert peer.certs == peer.original_certs and workflow._store.claim_count == 2
        else:
            assert result['outcome'] != 'succeeded'
            assert peer.writes == ['POST'] and workflow._store.claim_count == 1
        replacement = make(root, peer)
        for phase in ('import', 'recover'):
            with pytest.raises(ValueError): replacement.preview(phase, **IDENTITY)
        assert peer.logouts == peer.sessions
        assert NONCE not in json.dumps(result) and SERIAL not in json.dumps(result)
        replacement.close(); workflow.close()
