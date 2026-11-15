"""Combined fixed timeout update, preservation, ambiguity and recovery check."""
from contextlib import contextmanager
from copy import deepcopy
import json
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.ems_timeout_transport import COLLECTION, STATUS, EmsTimeoutTransport, _FIELDS, digest
from fortipam_mcp.ems_timeout_workflow import EmsTimeoutWorkflow
from fortipam_mcp.ems_timeout_runtime import PREFIX, build_ems_timeout_candidate
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore

SERIAL, OWNER, NAME = 'synthetic-ems-serial', 'synthetic-owner', 'synthetic-ems'
IDENTITY = dict(requester_digest='1' * 64, transport_digest='2' * 64)


def frame(result, *, name='fctems', path='endpoint-control', method='GET', **extra):
    return dict(dict(http_method=method, status='success', http_status=200, version='v7.0.0', build=29,
        serial=SERIAL, vdom='root', name=name, path=path, results=deepcopy(result)), **extra)


class Peer:
    def __init__(self, fault):
        self.fault = fault
        self.schema = dict(mkey='name', mkey_type='string', category='table',
            children={k: dict(type=v) for k, v in _FIELDS.items()})
        self.schema['children']['call-timeout'].update(default=30, **{'min-value': 1, 'max-value': 180})
        row = {k: (30 if k == 'call-timeout' else 443) if v == 'integer' else 'synthetic-value'
            for k, v in _FIELDS.items()}
        row['certificate-fingerprint'] = 'synthetic-fingerprint'
        self.rows = [dict(row, name=NAME), dict(row, name='synthetic-companion')]
        self.original = deepcopy(self.rows)
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
        if method == 'GET':
            if path == '/api/v2/monitor/web-ui/state':
                return httpx.Response(200, json=frame({'admin': dict(name=OWNER, login_name=OWNER,
                    sponsored_group_name='', guest_admin=False)}, name='state', path='web-ui'))
            if path == COLLECTION:
                query = parse_qs(request.url.query.decode())
                result = self.schema if query.get('action') == ['schema'] else [dict(row, q_no_edit=bool(self.sessions % 2)) for row in self.rows]
                return httpx.Response(200, json=frame(result))
            assert path == STATUS and parse_qs(request.url.query.decode()) == {'ems_name': [NAME]}
            return httpx.Response(200, json=frame({'ems_status': 'failed' if self.fault == 'disconnected' and self.writes else 'success'},
                name='ems', action='status'))
        assert method == 'PUT' and path == COLLECTION + '/' + NAME
        assert request.headers['X-CSRFTOKEN'] == 'synthetic-csrf'
        assert self.store.claim_count == len(self.writes) + 1
        expected = 31 if not self.writes else 30
        assert request.content == ('{"call-timeout":' + str(expected) + '}').encode()
        self.writes.append(expected); self.rows[0]['call-timeout'] = expected
        if self.fault == 'field-drift': self.rows[0]['pull-tags'] = 'different'
        if self.fault == 'companion-drift': self.rows[1]['server'] = 'different'
        if self.fault == 'reference-drift': self.rows[0]['q_ref'] = 1
        if self.fault == 'trust-drift': self.rows[0]['certificate-fingerprint'] = 'different'
        if self.fault == 'lost-ack': raise httpx.ReadTimeout('synthetic')
        return httpx.Response(200, json=frame({}, method='PUT', mkey='different' if self.fault == 'wrong-ack' else NAME))


def make(root, peer):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = root / 'execution.key'
    if not key.exists(): key.write_bytes(b'e' * 32); key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(root / 'execution.sqlite3', key); peer.store = store
    transport = EmsTimeoutTransport(owner_factory=peer.owner, owner_name=OWNER, serial=SERIAL,
        name=NAME, nonce='0123456789abcdef', schema_digest=digest(peer.schema), baseline_rows=peer.original)
    return EmsTimeoutWorkflow(transport, store, authority_key=b'a' * 32,
        environment_ref='synthetic-environment', scope_ref='synthetic-scope', audience_ref='synthetic-audience',
        allowed_requester_digest=IDENTITY['requester_digest'], allowed_transport_digest=IDENTITY['transport_digest'],
        update_enabled=True, recovery_enabled=True, clock=lambda: 100)


def run(workflow, phase):
    preview = workflow.preview(phase, **IDENTITY)
    assert preview['Proposed Changes']['call_timeout_seconds'] == (31 if phase == 'update' else 30)
    auth = workflow.authorize(phase, preview['preview_ref'], **IDENTITY)
    return workflow.execute(phase, auth['authorization_ref'], **IDENTITY), auth


def test_timeout_update_restoration_preservation_and_non_replay(tmp_path):
    assert build_ems_timeout_candidate({}) is None
    with pytest.raises(ValueError): build_ems_timeout_candidate({PREFIX + 'UPDATE_ENABLED': 'true'})
    for fault in ('none', 'field-drift', 'companion-drift', 'reference-drift', 'trust-drift', 'disconnected', 'lost-ack', 'wrong-ack'):
        peer = Peer(fault); root = (tmp_path / fault).resolve(); workflow = make(root, peer)
        result, auth = run(workflow, 'update')
        reads = peer.sessions
        assert workflow.execute('update', auth['authorization_ref'], **IDENTITY)['idempotent_replay']
        assert peer.sessions == reads
        if fault == 'none':
            assert result['outcome'] == 'succeeded' and result['verification'] == 'verified'
            assert run(workflow, 'recover')[0]['outcome'] == 'succeeded'
            assert peer.writes == [31, 30] and peer.rows == peer.original and workflow._store.claim_count == 2
        else:
            assert result['outcome'] != 'succeeded'
            with pytest.raises(ValueError): workflow.preview('recover', **IDENTITY)
            assert peer.writes == [31] and workflow._store.claim_count == 1
        replacement = make(root, peer)
        for phase in ('update', 'recover'):
            with pytest.raises(ValueError): replacement.preview(phase, **IDENTITY)
        assert peer.logouts == peer.sessions
        assert SERIAL not in json.dumps(result) and NAME not in json.dumps(result)
        replacement.close(); workflow.close()
