"""Combined backup custody, native request, integrity and non-retry behavior."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.backup_export_runtime import PREFIX, build_backup_export_candidate
from fortipam_mcp.backup_export_transport import BackupExportTransport, EXPORT
from fortipam_mcp.backup_export_workflow import BackupExportWorkflow
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore

SERIAL, OWNER = 'synthetic-backup-serial', 'synthetic-backup-owner'
IDENTITY = dict(requester_digest='1' * 64, transport_digest='2' * 64)
ARTIFACT = b'synthetic-opaque-backup-fixture-' * 20


class Peer:
    def __init__(self, fault, vault):
        self.fault, self.vault = fault, vault
        self.sessions = self.logouts = self.exports = 0
        self.store = None
        self.password = None
        self.now = 100

    def owner(self):
        peer = self
        class Owner:
            logout_verified = False
            @contextmanager
            def authenticated(self):
                peer.sessions += 1
                self._client = httpx.Client(base_url='https://synthetic.invalid', transport=httpx.MockTransport(peer.handle))
                try: yield self
                finally:
                    self._client.close(); self.logout_verified = True; peer.logouts += 1
        return Owner()

    def handle(self, request):
        assert request.method == 'GET'
        if request.url.path == '/api/v2/monitor/web-ui/state':
            if self.fault == 'pre-export' and self.store.claim_count:
                return httpx.Response(403)
            if self.exports and self.fault in {'file-drift', 'password-drift', 'record-drift'}:
                name = {'file-drift':'backup.conf', 'password-drift':'backup.password', 'record-drift':'integrity.json'}[self.fault]
                (self.vault/name).write_bytes(b'synthetic-tampered')
            return httpx.Response(200, json=dict(http_method='GET', status='success', http_status=200,
                version='v7.0.0', build=29, serial=SERIAL, vdom='root', path='web-ui', name='state',
                results={'admin':dict(name=OWNER, login_name=OWNER, guest_admin=False,
                    sponsored_group_name='', global_admin=True)}))
        assert request.url.path == EXPORT
        assert self.store.claim_count == 1 and self.exports == 0
        params = parse_qs(request.url.query.decode())
        assert set(params) == {'scope', 'destination', 'password', 'confirmPassword'}
        assert params['scope'] == ['global'] and params['destination'] == ['file']
        assert len(params['password'][0]) == 15 and params['password'] == params['confirmPassword']
        self.password = params['password'][0].encode()
        assert (self.vault/'backup.password').read_bytes() == self.password
        self.exports += 1
        if self.fault == 'lost-response': raise httpx.ReadTimeout('synthetic')
        if self.fault == 'expiry': self.now = 161
        return httpx.Response(200, headers={'content-type':'text/html' if self.fault == 'html-response' else 'application/octet-stream',
            'content-disposition':'attachment; filename="ignored-device-name.conf"',
            'content-length':str(len(ARTIFACT) + (1 if self.fault == 'truncated' else 0))}, content=ARTIFACT)


def make(root: Path, peer):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = root/'execution.key'
    if not key.exists(): key.write_bytes(b'e' * 32); key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(root/'execution.sqlite3', key); peer.store = store
    transport = BackupExportTransport(owner_factory=peer.owner, owner_name=OWNER, serial=SERIAL,
        nonce='0123456789abcdef', custody_directory=peer.vault, retain_until=1000000,
        audience_digest=hashlib.sha256(b'synthetic-audience').hexdigest(), clock=lambda:peer.now)
    return BackupExportWorkflow(transport, store, authority_key=b'a' * 32,
        environment_ref='synthetic-environment', scope_ref='synthetic-scope', audience_ref='synthetic-audience',
        allowed_requester_digest=IDENTITY['requester_digest'], allowed_transport_digest=IDENTITY['transport_digest'],
        create_enabled=True, clock=lambda:peer.now)


def test_backup_download_private_custody_and_fail_closed_replay(tmp_path):
    assert build_backup_export_candidate({}) is None
    with pytest.raises(ValueError): build_backup_export_candidate({PREFIX+'CREATE_ENABLED':'true'})
    for fault in ('none', 'pre-export', 'file-drift', 'password-drift', 'record-drift', 'lost-response', 'html-response', 'truncated', 'expiry'):
        vault=(tmp_path/(fault+'-vault')).resolve();vault.mkdir(mode=0o700)
        peer=Peer(fault,vault);root=(tmp_path/fault).resolve();workflow=make(root,peer)
        preview=workflow.preview('create',**IDENTITY)
        assert list(vault.iterdir()) == []
        assert preview['Proposed Changes']['native_encryption_requested']
        auth=workflow.authorize('create',preview['preview_ref'],**IDENTITY)
        assert list(vault.iterdir()) == []
        result=workflow.execute('create',auth['authorization_ref'],**IDENTITY)
        assert not result['restore_tested'] and not result['configuration_write_executed']
        if fault == 'pre-export':
            assert not result['native_encryption_requested'] and peer.exports == 0
            assert result['outcome'] != 'succeeded' and workflow._store.claim_count == 1
            assert list(vault.iterdir()) == []
            workflow.close()
            continue
        assert result['native_encryption_requested']
        assert peer.exports == 1 and workflow._store.claim_count == 1
        assert peer.sessions == peer.logouts
        if fault == 'none':
            assert result['outcome'] == 'succeeded' and result['verification'] == 'verified'
            assert (vault/'backup.conf').read_bytes() == ARTIFACT
            assert (vault/'backup.password').read_bytes() == peer.password
            record=json.loads((vault/'integrity.json').read_bytes())
            assert record['sha256'] == hashlib.sha256(ARTIFACT).hexdigest() and not record['restore_tested']
            assert all(p.stat().st_mode & 0o777 == 0o600 for p in vault.iterdir())
        else:
            assert result['outcome'] != 'succeeded'
        assert workflow._transport._custody._password is None
        calls=peer.sessions
        if fault != 'expiry':
            assert workflow.execute('create',auth['authorization_ref'],**IDENTITY)['idempotent_replay']
            assert peer.sessions == calls
        assert peer.password.decode() not in json.dumps(result) and SERIAL not in json.dumps(result)
        assert str(vault) not in json.dumps(preview)
        replacement=make(root,peer)
        with pytest.raises(ValueError): replacement.preview('create',**IDENTITY)
        assert (vault/'backup.password').exists() and (vault/'lease.claim').exists()
        replacement.close();workflow.close()
