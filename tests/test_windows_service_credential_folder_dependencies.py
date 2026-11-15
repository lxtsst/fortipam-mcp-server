"""Service Folder admission with original synthetic M4s and fixed fresh sources."""
from dataclasses import replace

import pytest

from fortipam_mcp.windows_service_credential_folder_dependencies import (
    WindowsServiceCredentialFolderDependencies, WindowsServiceCredentialFolderDependencyError,
    service_credential_folder_context_digest,
)
from fortipam_mcp.windows_execution_secret_folder_dependencies import (
    WindowsExecutionSecretFolderDependencies, WindowsSecretFolderDependencyError,
)
from test_windows_execution_secret_folder_dependencies import prepared
from test_windows_service_credential_contract import binding
from test_windows_privileged_secret_contract import binding as privileged_binding


def setup(tmp_path, monkeypatch):
    source, api, policy, parent, now, native, original, legacy = prepared(tmp_path, monkeypatch)
    before = len(api.base.calls), list(native.calls)
    digest = service_credential_folder_context_digest(requester_digest='b' * 64,
        sources=source, original_folder=original)
    assert before == (len(api.base.calls), native.calls)
    profile = replace(binding(), folder_id=original.inspect_created_state().native_folder_id,
        serial_digest=legacy.serial_digest, folder_context_digest=digest)
    return dict(source=source, api=api, policy=policy, parent=parent, now=now, native=native,
        original=original, profile=profile, legacy=legacy, digest=digest)


def reader(cmp, **overrides):
    options = dict(requester_digest='b' * 64, sources=cmp['source'], original_folder=cmp['original'])
    options.update(overrides)
    return WindowsServiceCredentialFolderDependencies(cmp['profile'], **options)


def test_original_folder_policy_context_is_bound_before_any_fresh_read_or_material(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    before = len(cmp['api'].base.calls), list(cmp['native'].calls)
    files = {p: p.read_bytes() for custody in (cmp['parent'], cmp['original']) for p in custody._directory.iterdir()}
    dependency = reader(cmp)
    assert before == (len(cmp['api'].base.calls), cmp['native'].calls)
    observation = dependency.read_once()
    dependency.check_current(observation)
    assert observation.folder_creation_digest == cmp['original'].inspect_created_state().custody_digest
    assert observation.policy_creation_digest == cmp['parent'].inspect_created_state().custody_digest
    assert observation.folder_state_digest == cmp['source']._current.state_digest
    assert cmp['source']._current.policy_reference_count == 1
    assert cmp['native'].calls == before[1] and all(p.read_bytes() == value for p, value in files.items())
    assert not hasattr(dependency, 'issue') and not hasattr(dependency, 'execute')
    assert 'UNIT-WINDOWS' not in repr(observation)
    dependency.close()
    assert not cmp['source']._closed
    with pytest.raises(WindowsServiceCredentialFolderDependencyError): dependency.check_current(observation)
    cmp['source'].close(); cmp['policy'].close()


@pytest.mark.parametrize('fault', ['folder-context', 'folder-id', 'serial', 'requester', 'detached', 'missing-seal'])
def test_wrong_lineage_context_or_identity_denies_before_native_reads(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch)
    if fault == 'folder-context': cmp['profile'] = replace(cmp['profile'], folder_context_digest='f' * 64)
    if fault == 'folder-id': cmp['profile'] = replace(cmp['profile'], folder_id=42)
    if fault == 'serial': cmp['profile'] = replace(cmp['profile'], serial_digest='a' * 64)
    if fault == 'detached': cmp['original'] = cmp['original'].inspect_created_state()
    if fault == 'missing-seal': (cmp['original']._directory / 'created-state.json').unlink()
    before = len(cmp['api'].base.calls), list(cmp['native'].calls)
    with pytest.raises(WindowsServiceCredentialFolderDependencyError):
        reader(cmp, **({'requester_digest': 'f' * 64} if fault == 'requester' else {}))
    assert before == (len(cmp['api'].base.calls), cmp['native'].calls)
    cmp['source'].close(); cmp['policy'].close()


def test_complete_seal_unknown_cannot_compile_an_original_creation_dependency(tmp_path, monkeypatch):
    source, api, policy, _, _, native, original, _ = prepared(tmp_path, monkeypatch, unknown=True)
    before = len(api.base.calls), list(native.calls)
    with pytest.raises(WindowsServiceCredentialFolderDependencyError):
        service_credential_folder_context_digest(requester_digest='b' * 64, sources=source, original_folder=original)
    assert before == (len(api.base.calls), native.calls)
    source.close(); policy.close()


@pytest.mark.parametrize('fault', ['referenced-folder', 'policy-ref', 'parent', 'hidden-name', 'rights'])
def test_fresh_wrong_scope_or_references_poison_the_window_without_mutation(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch); dependency = reader(cmp)
    if fault == 'referenced-folder': cmp['api'].folder_has_reference = True
    if fault == 'policy-ref': cmp['api'].policy_cli_count = 0
    if fault == 'parent': cmp['api'].parent_changed = True
    if fault == 'hidden-name': cmp['api'].hidden_name = True
    if fault == 'rights': cmp['api'].failure = 'folder-role'
    writes = list(cmp['native'].calls)
    with pytest.raises(WindowsServiceCredentialFolderDependencyError): dependency.read_once()
    count = len(cmp['api'].base.calls)
    with pytest.raises(WindowsServiceCredentialFolderDependencyError): dependency.read_once()
    assert len(cmp['api'].base.calls) == count and cmp['native'].calls == writes
    dependency.close(); cmp['source'].close(); cmp['policy'].close()


@pytest.mark.parametrize('fault', ['copy', 'tamper', 'expiry', 'source-close', 'profile-context'])
def test_observation_identity_expiry_and_context_drift_refuse_stale_proofs(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch); dependency = reader(cmp); observation = dependency.read_once()
    if fault == 'copy': observation = replace(observation)
    if fault == 'tamper': object.__setattr__(observation, 'policy_creation_digest', 'f' * 64)
    if fault == 'expiry': cmp['now'][0] = observation.expires_at
    if fault == 'source-close': cmp['source'].close()
    if fault == 'profile-context': object.__setattr__(cmp['profile'], 'folder_context_digest', 'f' * 64)
    before = len(cmp['api'].base.calls), list(cmp['native'].calls)
    with pytest.raises(WindowsServiceCredentialFolderDependencyError): dependency.check_current(observation)
    assert before == (len(cmp['api'].base.calls), cmp['native'].calls)
    dependency.close(); cmp['source'].close(); cmp['policy'].close()


@pytest.mark.parametrize('profile_kind', ['legacy', 'privileged'])
def test_other_profile_entries_are_not_cast_or_relaxed(tmp_path, monkeypatch, profile_kind):
    cmp = setup(tmp_path, monkeypatch); service_profile = cmp['profile']
    cmp['profile'] = cmp['legacy'] if profile_kind == 'legacy' else privileged_binding()
    before = len(cmp['api'].base.calls), list(cmp['native'].calls)
    with pytest.raises(WindowsServiceCredentialFolderDependencyError): reader(cmp)
    with pytest.raises(WindowsSecretFolderDependencyError):
        WindowsExecutionSecretFolderDependencies(service_profile, requester_digest='b' * 64,
            sources=cmp['source'], original_folder=cmp['original'])
    assert before == (len(cmp['api'].base.calls), cmp['native'].calls)
    cmp['source'].close(); cmp['policy'].close()
