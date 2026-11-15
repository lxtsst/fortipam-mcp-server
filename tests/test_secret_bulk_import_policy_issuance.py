"""Fixed policy issuance from independent exact Reference grants; synthetic data."""

from dataclasses import replace
import hashlib
import os
from pathlib import Path

import pytest

from fortipam_mcp import secret_bulk_import_intake_authority as policy
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from test_secret_bulk_import_submission import configured


def settings(tmp_path, fixture):
    key = tmp_path / 'issuance-policy.key'
    key.write_bytes(b'p' * 32)
    key.chmod(0o600)
    return dict(policy_path=tmp_path / 'issued-policy.json', key_path=key,
                key_sha256=hashlib.sha256(b'p' * 32).hexdigest(),
                eligibility=fixture['options']['authority']._human_owner_verifier,
                clock=lambda: fixture['clocks'][0], monotonic=lambda: fixture['clocks'][1])


def test_fixed_issuance_requires_live_remote_permission_and_clears_key_and_output_buffers(tmp_path, monkeypatch, capfd):
    fixture = configured(tmp_path, monkeypatch)
    kwargs = settings(tmp_path, fixture)
    read, buffers = policy._read_owned, []
    def captured(path, *args):
        assert path != fixture['owner_binding'].path
        raw, identity = read(path, *args)
        buffers.append(raw)
        return raw, identity
    monkeypatch.setattr(policy, '_read_owned', captured)
    with fixture['reference_transport']:
        digest = policy.issue_prebound_owner_file_policy_once(fixture['owner_binding'], **kwargs)
        verifier = policy.PinnedOwnerFileIntakeAuthority(fixture['owner_binding'],
            **{name: kwargs[name] for name in ('policy_path', 'key_path', 'key_sha256')}, policy_sha256=digest,
            human_owner_verifier=kwargs['eligibility'], clock=kwargs['clock'])
        verifier.verify(fixture['owner_binding'], now_epoch=fixture['clocks'][0])
        assert kwargs['policy_path'].stat().st_mode & 0o777 == 0o600
        assert digest == hashlib.sha256(kwargs['policy_path'].read_bytes()).hexdigest()
        before = kwargs['policy_path'].read_bytes()
        with pytest.raises(BulkImportIntakeError):
            policy.issue_prebound_owner_file_policy_once(fixture['owner_binding'], **kwargs)
        assert kwargs['policy_path'].read_bytes() == before
        fixture['root_authority'].revoke(fixture['handle'], now_epoch=fixture['clocks'][0])
        with pytest.raises(BulkImportIntakeError):
            verifier.verify(fixture['owner_binding'], now_epoch=fixture['clocks'][0])
    assert buffers and all(not any(raw) for raw in buffers)
    assert capfd.readouterr() == ('', '')


@pytest.mark.parametrize('fault', ['revoked', 'other-human', 'other-workload', 'too-long', 'expired', 'boolean-time',
    'fake-eligibility', 'local-ledger', 'key-mode', 'key-sha', 'key-size', 'output-mode', 'source-alias',
    'scope-key-alias', 'parent-symlink', 'existing-output', 'output-symlink'])
def test_issuance_denies_without_reading_source_or_overwriting_existing_files(tmp_path, monkeypatch, capfd, fault):
    fixture = configured(tmp_path, monkeypatch)
    kwargs = settings(tmp_path, fixture)
    binding = fixture['owner_binding']
    read = policy._read_owned
    def guarded(path, *args):
        assert path != binding.path, 'Issuance read source'
        return read(path, *args)
    monkeypatch.setattr(policy, '_read_owned', guarded)
    if fault == 'revoked':
        fixture['root_authority'].revoke(fixture['handle'], now_epoch=fixture['clocks'][0])
    elif fault == 'other-human':
        binding = replace(binding, subject='synthetic-other-human')
    elif fault == 'other-workload':
        binding = replace(binding, workload_digest='8' * 64)
    elif fault == 'too-long':
        binding = replace(binding, expires_at=binding.issued_at + 901)
    elif fault == 'expired':
        fixture['clocks'][0] = binding.expires_at
    elif fault == 'boolean-time':
        kwargs['clock'] = lambda: True
    elif fault == 'fake-eligibility':
        kwargs['eligibility'] = lambda *a: None
    elif fault == 'local-ledger':
        kwargs['eligibility']._authority = fixture['root_authority']
    elif fault == 'key-mode':
        kwargs['key_path'].chmod(0o644)
    elif fault == 'key-sha':
        kwargs['key_sha256'] = '0' * 64
    elif fault == 'key-size':
        kwargs['key_path'].write_bytes(b'p' * 31)
        kwargs['key_sha256'] = hashlib.sha256(b'p' * 31).hexdigest()
    elif fault == 'output-mode':
        destination = tmp_path / 'public-destination'
        destination.mkdir(mode=0o755)
        kwargs['policy_path'] = destination / 'policy.json'
    elif fault == 'source-alias':
        kwargs['policy_path'] = Path('/' + str(binding.path))
    elif fault == 'scope-key-alias':
        kwargs['key_path'] = kwargs['eligibility']._key.path
        kwargs['key_sha256'] = kwargs['eligibility']._key.digest
    elif fault == 'parent-symlink':
        alias = tmp_path / 'directory-alias'
        alias.symlink_to(tmp_path, target_is_directory=True)
        kwargs['policy_path'] = alias / 'issued-policy.json'
    elif fault == 'existing-output':
        kwargs['policy_path'].write_bytes(b'synthetic-existing-owner-file')
        kwargs['policy_path'].chmod(0o600)
    else:
        kwargs['policy_path'].symlink_to(binding.path)
    protected = fixture['owner_binding'].path.read_bytes()
    with fixture['reference_transport'], pytest.raises(BulkImportIntakeError) as caught:
        policy.issue_prebound_owner_file_policy_once(binding, **kwargs)
    assert str(caught.value) == 'Private bulk-import intake unavailable.'
    assert fixture['owner_binding'].path.read_bytes() == protected
    if fault == 'existing-output':
        assert kwargs['policy_path'].read_bytes() == b'synthetic-existing-owner-file'
    elif fault == 'output-symlink':
        assert kwargs['policy_path'].is_symlink()
    elif fault != 'source-alias':
        assert not kwargs['policy_path'].exists()
    assert capfd.readouterr() == ('', '')


@pytest.mark.parametrize('fault', ['revocation', 'key-drift', 'wall-rollback', 'mono-rollback', 'expired', 'write-error', 'fsync-error', 'replacement-output'])
def test_failure_after_creation_removes_only_new_policy_and_clears_owned_output(tmp_path, monkeypatch, fault):
    fixture = configured(tmp_path, monkeypatch)
    kwargs = settings(tmp_path, fixture)
    write, fsync, wipe = os.write, os.fsync, policy._wipe
    buffers, fired = [], [False]
    monkeypatch.setattr(policy, '_wipe', lambda raw: (buffers.append(raw), wipe(raw))[-1])
    def changed(descriptor, raw):
        if fault == 'write-error':
            raise OSError('synthetic-private-write-detail')
        count = write(descriptor, raw)
        if not fired[0]:
            fired[0] = True
            if fault == 'revocation':
                fixture['root_authority'].revoke(fixture['handle'], now_epoch=fixture['clocks'][0])
            elif fault == 'key-drift':
                kwargs['key_path'].chmod(0o644)
            elif fault == 'wall-rollback':
                fixture['clocks'][0] -= 1
            elif fault == 'mono-rollback':
                fixture['clocks'][1] -= 1
            elif fault == 'expired':
                fixture['clocks'][0] = fixture['owner_binding'].expires_at
            elif fault == 'replacement-output':
                replaced = kwargs['policy_path'].with_name('replacement-policy.json')
                replaced.write_bytes(b'synthetic-independent-owner-file')
                replaced.chmod(0o600)
                replaced.replace(kwargs['policy_path'])
        return count
    def synced(descriptor):
        if fault == 'fsync-error':
            raise OSError('synthetic-private-fsync-detail')
        return fsync(descriptor)
    monkeypatch.setattr(policy.os, 'write', changed)
    monkeypatch.setattr(policy.os, 'fsync', synced)
    with fixture['reference_transport'], pytest.raises(BulkImportIntakeError):
        policy.issue_prebound_owner_file_policy_once(fixture['owner_binding'], **kwargs)
    if fault == 'replacement-output':
        assert kwargs['policy_path'].read_bytes() == b'synthetic-independent-owner-file'
    else:
        assert not kwargs['policy_path'].exists()
    assert buffers and all(not any(raw) for raw in buffers)
