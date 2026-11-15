"""Original synthetic backup proof only; no real configuration, license or export."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.backup_export_transport import BackupExportTransport
from fortipam_mcp.backup_export_workflow import BackupExportWorkflow
from fortipam_mcp.license_artifact_source import LicenseArtifactSource
from fortipam_mcp.license_backup_source import LicenseBackupCustodySource
from fortipam_mcp.license_upload_material import LicenseUploadMaterialBinding
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_backup_export_workflow import Peer, IDENTITY, SERIAL, OWNER, ARTIFACT
from test_system_email_authority import owner_file
from test_system_email_m4_adapter import store_at
from v4_planning import canonical_digest
from v4_planning.material_provider import MaterialAccessDenied

AUDIENCE = hashlib.sha256(b'synthetic-audience').hexdigest()


def make(root, *, fault='none', checkpointed=True, guarded=True, identity=None):
    identity = IDENTITY if identity is None else identity
    vault = root/'archive'; vault.mkdir(mode=0o700)
    peer = Peer(fault, vault)
    store = store_at(root) if checkpointed else PersistentM4ExecutionStateStore(root/'state.db', owner_file(root/'state.key', b'e'*32))
    peer.store = store
    transport = BackupExportTransport(owner_factory=peer.owner, owner_name=OWNER, serial=SERIAL,
        nonce='0123456789abcdef', custody_directory=vault, retain_until=1000000, audience_digest=AUDIENCE, clock=lambda: peer.now)
    workflow = BackupExportWorkflow(transport, store, authority_key=b'a'*32,
        environment_ref='synthetic-environment', scope_ref='synthetic-scope', audience_ref='synthetic-audience',
        allowed_requester_digest=identity['requester_digest'], allowed_transport_digest=identity['transport_digest'],
        create_enabled=True, clock=lambda: peer.now)
    preview = workflow.preview('create', **identity)
    authorization = workflow.authorize('create', preview['preview_ref'], **identity)
    result = workflow.execute('create', authorization['authorization_ref'], **identity)
    path = owner_file(root/'synthetic-license.lic', b'SYNTHETIC_LICENSE')
    artifact = LicenseArtifactSource(path, expected_sha256=hashlib.sha256(b'SYNTHETIC_LICENSE').hexdigest(),
        scope_digest='f'*64, audience_digest=AUDIENCE, source_guard=lambda: True)
    license_binding = LicenseUploadMaterialBinding(artifact, target_serial_digest=canonical_digest(dict(serial=SERIAL)),
        requester_digest=identity['requester_digest'])
    source = LicenseBackupCustodySource(workflow, license_binding, allowed_transport_digest=identity['transport_digest'],
        source_guard=(lambda: True) if guarded else None, clock=lambda: peer.now)
    return SimpleNamespace(peer=peer, vault=vault, store=store, workflow=workflow, transport=transport,
        source=source, license=license_binding, artifact=artifact, result=result)


def observe(value, **identity): return value.source.observe(**(identity or IDENTITY))


@pytest.mark.parametrize('deadline', [False, float('nan'), float('inf'), 0.0, 'synthetic-invalid'])
def test_invalid_or_expired_combined_deadline_refuses_before_backup_file_reads(tmp_path, monkeypatch, deadline):
    from fortipam_mcp import backup_artifact_custody
    value = make(tmp_path)
    monkeypatch.setattr(backup_artifact_custody, '_read', lambda *_: pytest.fail('Invalid deadline must not read backup material.'))
    with pytest.raises(MaterialAccessDenied): value.source.observe(**IDENTITY, monotonic_deadline=deadline)
    assert value.source._attempted and value.peer.exports == 1


def test_fresh_read_after_original_lease_expiry_and_workflow_close_does_not_export(tmp_path, monkeypatch):
    value = make(tmp_path)
    assert value.result['outcome'] == 'succeeded'
    value.peer.now = 200; value.workflow.close()
    sessions, exports = value.peer.sessions, value.peer.exports
    before = {path.name: path.read_bytes() for path in value.vault.iterdir()}
    monkeypatch.setattr(value.transport._custody, '_guard', lambda: pytest.fail('Expired export authority must not be reused.'))
    monkeypatch.setattr(value.transport._custody, '_dispatch_guard', lambda: pytest.fail('No dispatch may reopen.'))
    result = observe(value)
    assert result['original_backup_execution_verified'] and result['retained_files_intact_locally']
    assert result['observed_at'] == 200 and result['expires_at'] == 210
    assert not result['native_encryption_verified'] and not result['restore_tested'] and not result['license_rollback_ready']
    assert not result['backup_matches_current_configuration_verified']
    assert not result['license_install_authorized'] and not result['device_contacted'] and not result['new_export_requested']
    assert value.peer.sessions == sessions and value.peer.exports == exports == 1
    public = json.dumps(result)
    for private in (str(value.vault), SERIAL, OWNER, value.peer.password.decode(), ARTIFACT.decode(),
            value.transport._custody._receipt[1], value.transport._custody._password_digest):
        assert private not in public
    assert before == {path.name: path.read_bytes() for path in value.vault.iterdir()}
    assert not value.artifact._used
    with pytest.raises(MaterialAccessDenied): observe(value)


@pytest.mark.parametrize('identity', [dict(requester_digest='e'*64, transport_digest=IDENTITY['transport_digest']),
    dict(requester_digest=IDENTITY['requester_digest'], transport_digest='e'*64)])
def test_foreign_reader_cannot_consume_or_revoke_original_read(tmp_path, identity):
    value = make(tmp_path)
    with pytest.raises(MaterialAccessDenied): observe(value, **identity)
    assert not value.source._attempted and not value.source._closed
    assert observe(value)['retained_files_intact_locally']


def test_default_read_guard_precedes_protected_file_reads(tmp_path, monkeypatch):
    from fortipam_mcp import backup_artifact_custody as module
    value = make(tmp_path, guarded=False)
    monkeypatch.setattr(module, '_read', lambda *_: pytest.fail('Closed read guard must not read configuration/password.'))
    with pytest.raises(MaterialAccessDenied): observe(value)
    assert value.source._attempted and value.peer.exports == 1


@pytest.mark.parametrize('name', ['lease.claim', 'backup.conf', 'backup.password', 'integrity.json'])
def test_changed_retained_file_refuses_without_reexporting(tmp_path, name):
    value = make(tmp_path); sessions = value.peer.sessions
    (value.vault/name).write_bytes(b'SYNTHETIC_TAMPERED')
    with pytest.raises(MaterialAccessDenied): observe(value)
    assert value.peer.sessions == sessions and value.peer.exports == 1


def test_unknown_original_claim_cannot_be_adopted_as_verified_backup(tmp_path, monkeypatch):
    from fortipam_mcp import backup_artifact_custody as module
    value = make(tmp_path, fault='file-drift')
    assert value.result['outcome'] != 'succeeded'
    monkeypatch.setattr(module, '_read', lambda *_: pytest.fail('UNKNOWN must refuse before backup reads.'))
    with pytest.raises(MaterialAccessDenied): observe(value)
    assert value.peer.exports == 1


def test_missing_original_checkpoint_cannot_supply_history_qualification(tmp_path, monkeypatch):
    from fortipam_mcp import backup_artifact_custody as module
    value = make(tmp_path, checkpointed=False)
    monkeypatch.setattr(module, '_read', lambda *_: pytest.fail('Unbound history must refuse before backup reads.'))
    with pytest.raises(MaterialAccessDenied): observe(value)


@pytest.mark.parametrize('change', ['retention', 'closed', 'guard', 'key', 'namespace', 'record-pin'])
def test_changed_read_context_refuses_before_protected_file_reads(tmp_path, monkeypatch, change):
    from fortipam_mcp import backup_artifact_custody as module
    value = make(tmp_path)
    if change == 'retention': value.peer.now = 1000000
    elif change == 'closed': value.source.close()
    elif change == 'guard': value.source._guard = lambda: True
    elif change == 'key': value.store._key_path.write_bytes(b'z'*32)
    elif change == 'namespace': value.workflow._namespace['scope_ref'] = 'foreign-scope'
    else: value.transport._custody._record_digest = 'e'*64
    monkeypatch.setattr(module, '_read', lambda *_: pytest.fail('Invalid read context must precede protected file reads.'))
    with pytest.raises(MaterialAccessDenied): observe(value)
    assert value.peer.exports == 1


@pytest.mark.parametrize('change', ['target', 'requester', 'audience'])
def test_foreign_license_binding_cannot_receive_backup_custody_evidence(tmp_path, change):
    value = make(tmp_path)
    artifact = value.artifact
    if change == 'audience':
        artifact = LicenseArtifactSource(artifact._path, expected_sha256=artifact._sha, scope_digest=artifact._scope,
            audience_digest='e'*64, source_guard=lambda: True)
    binding = LicenseUploadMaterialBinding(artifact, target_serial_digest='e'*64 if change == 'target' else value.license._serial,
        requester_digest='e'*64 if change == 'requester' else value.license._requester)
    with pytest.raises(MaterialAccessDenied):
        LicenseBackupCustodySource(value.workflow, binding, allowed_transport_digest=IDENTITY['transport_digest'], source_guard=lambda: True)


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_retained_read_interruptions_clear_every_loaded_buffer(tmp_path, monkeypatch, failure):
    from fortipam_mcp import backup_artifact_custody as module
    value = make(tmp_path); buffers = []; original_read = module._read
    def read(*args):
        raw = original_read(*args); buffers.append(raw); return raw
    def interrupted(*_): raise failure('SYNTHETIC_PRIVATE_FAILURE')
    monkeypatch.setattr(module, '_read', read)
    # Interrupt after a successful protected read, at the integrity comparison.
    monkeypatch.setattr(module, 'hmac', SimpleNamespace(compare_digest=interrupted))
    with pytest.raises(MaterialAccessDenied if failure is OSError else failure): observe(value)
    assert buffers and all(not any(raw) for raw in buffers)
    assert (value.vault/'backup.conf').exists() and (value.vault/'backup.password').exists()


@pytest.mark.parametrize('change', ['file', 'close', 'guard', 'guard-latency'])
def test_final_read_guard_cannot_publish_after_context_or_file_revocation(tmp_path, monkeypatch, change):
    value = make(tmp_path); calls = []
    elapsed = [0.0]
    if change == 'guard-latency':
        from fortipam_mcp import license_backup_source as module
        monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: elapsed[0]))
    def guard():
        calls.append(True)
        if len(calls) == 2:
            if change == 'file': (value.vault/'backup.conf').write_bytes(b'SYNTHETIC_TAMPERED')
            elif change == 'close': value.source.close()
            elif change == 'guard': value.source._guard = lambda: True
            else:
                # A slow guard advances both wall time and elapsed time.
                value.peer.now += 11; elapsed[0] += 11
        return True
    value.source._guard = value.source._guard_pin = guard
    with pytest.raises(MaterialAccessDenied): observe(value)
    assert len(calls) == 2 and value.peer.exports == 1


def test_read_guard_reentry_cannot_observe_or_reexport_a_second_time(tmp_path):
    value = make(tmp_path); rejected = []
    def guard():
        with pytest.raises(MaterialAccessDenied): observe(value)
        rejected.append(True)
        return True
    value.source._guard = value.source._guard_pin = guard
    assert observe(value)['retained_files_intact_locally'] and rejected
    assert value.peer.exports == 1


def test_epoch_clock_callback_cannot_publish_after_revoking_fresh_read_guard(tmp_path):
    value = make(tmp_path); allowed, clocks = [True], []
    value.source._guard = value.source._guard_pin = lambda: allowed[0]
    def clock():
        clocks.append(True)
        if len(clocks) == 2: allowed[0] = False
        return value.peer.now
    value.source._clock = clock
    with pytest.raises(MaterialAccessDenied): observe(value)
    assert len(clocks) == 2 and value.peer.exports == 1


def test_reconstructed_reader_does_not_accept_a_modified_original_custody_claim(tmp_path):
    value = make(tmp_path)
    (value.vault/'lease.claim').write_bytes(b'e'*64)
    reader = LicenseBackupCustodySource(value.workflow, value.license, allowed_transport_digest=IDENTITY['transport_digest'],
        source_guard=lambda: True, clock=lambda: value.peer.now)
    with pytest.raises(MaterialAccessDenied): reader.observe(**IDENTITY)
    assert value.peer.exports == 1


def test_guard_key_path_substitution_refuses_before_foreign_key_read(tmp_path, monkeypatch):
    value = make(tmp_path)
    foreign = owner_file(tmp_path/'foreign-input', b'SYNTHETIC_FOREIGN_PRIVATE_KEY_MUST_NOT_BE_READ')
    seen = []
    load = value.store._load_key
    def loading():
        seen.append(value.store._key_path)
        if value.store._key_path is foreign: pytest.fail('A changed key path must fail before opening it.')
        return load()
    monkeypatch.setattr(value.store, '_load_key', loading)
    def guard():
        value.store._key_path = foreign
        return True
    value.source._guard = value.source._guard_pin = guard
    with pytest.raises(MaterialAccessDenied): observe(value)
    assert foreign not in seen


def test_retained_read_cleanup_does_not_allocate_a_full_size_zero_copy(tmp_path, monkeypatch):
    from fortipam_mcp import backup_artifact_custody as module
    value = make(tmp_path); buffers = []; read = module._read
    def tracked(*args):
        raw = read(*args); buffers.append(raw); return raw
    def unavailable(*_): raise MemoryError('Synthetic zero allocation is unavailable.')
    monkeypatch.setattr(module, '_read', tracked)
    monkeypatch.setattr(module, 'bytes', unavailable, raising=False)
    try: result = observe(value)
    except MaterialAccessDenied: result = None
    assert buffers and all(not any(raw) for raw in buffers)
    assert result is not None and result['retained_files_intact_locally']


@pytest.mark.parametrize('budget', ['window', 'retention'])
def test_first_guard_cannot_read_protected_files_after_exhausting_budget(tmp_path, monkeypatch, budget):
    from fortipam_mcp import license_backup_source as module
    from fortipam_mcp import backup_artifact_custody as custody_module
    value = make(tmp_path)
    value.peer.now = 999995 if budget == 'retention' else 200
    elapsed, guards = [0.0], []
    def guard():
        guards.append(True)
        delay = 6 if budget == 'retention' else 11
        value.peer.now += delay; elapsed[0] += delay
        return True
    value.source._guard = value.source._guard_pin = guard
    monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: elapsed[0]))
    monkeypatch.setattr(custody_module, '_read', lambda *_: pytest.fail('Expired read scope cannot open configuration/password/record.'))
    with pytest.raises(MaterialAccessDenied): observe(value)
    assert guards == [True] and value.peer.exports == 1


@pytest.mark.parametrize('budget', ['window', 'retention'])
def test_slow_configuration_read_cannot_start_later_files_after_budget_expiry(tmp_path, monkeypatch, budget):
    from fortipam_mcp import license_backup_source as module
    from fortipam_mcp import backup_artifact_custody as custody_module
    value = make(tmp_path)
    value.peer.now = 999995 if budget == 'retention' else 200
    elapsed, buffers, names = [0.0], [], []
    read = custody_module._read
    def slow(path, limit):
        names.append(path.name)
        assert path.name == 'backup.conf', 'No later protected file may start after expiry.'
        raw = read(path, limit); buffers.append(raw)
        delay = 6 if budget == 'retention' else 11
        value.peer.now += delay; elapsed[0] += delay
        return raw
    monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: elapsed[0]))
    monkeypatch.setattr(custody_module, '_read', slow)
    with pytest.raises(MaterialAccessDenied): observe(value)
    assert names == ['backup.conf'] and buffers and all(not any(raw) for raw in buffers)
    assert value.peer.exports == 1
