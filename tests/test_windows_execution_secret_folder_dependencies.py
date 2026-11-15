"""Explicit Secret Folder prerequisites consume actual synthetic original M4s."""
from dataclasses import replace

import pytest
from v4_planning import M4AdapterAmbiguous

from fortipam_mcp.windows_execution_secret_contract import WindowsExecutionSecretBinding
from fortipam_mcp.windows_execution_secret_folder_dependencies import (
    WindowsExecutionSecretFolderDependencies, WindowsSecretFolderDependencyError,
)
from fortipam_mcp.windows_execution_secret_preflight import WindowsExecutionOwnedDependencies
from test_windows_execution_folder_lifecycle import Native, lifecycle
from test_windows_execution_folder_sources import make
from test_windows_execution_secret_preflight import setup as inherited_preflight


def prepared(tmp_path, monkeypatch, *, unknown=False):
    source, api, policy, parent, now, *_ = make(tmp_path, monkeypatch)
    native = Native(source, api)
    create, store, _ = lifecycle(tmp_path, source, native)
    create.issue(create.preview())
    if unknown:
        def unavailable(plan):
            raise M4AdapterAmbiguous("Synthetic original postcondition failure after complete seal.")
        monkeypatch.setattr(create, "read_postcondition", unavailable)
    result = create.execute()
    assert str(result.outcome) == ("reconciliation_required" if unknown else "succeeded")
    original = create.original_creation()
    assert original.inspect_created_state().created_state_digest and store.claim_count == 1
    create.close()
    profile = WindowsExecutionSecretBinding("MCPV4WinExec20261022R7", "MCPV4WinTarget20261022R7",
        "192.0.2.20", "UNIT-WINDOWS", 41, source._request.binding.policy_request.binding.serial_digest, "d" * 64)
    return source, api, policy, parent, now, native, original, profile


def dependency(source, original, profile, *, requester="b" * 64):
    return WindowsExecutionSecretFolderDependencies(profile, requester_digest=requester,
        sources=source, original_folder=original)


def test_precreate_join_requires_original_policy_folder_and_fresh_zero_reference_window(tmp_path, monkeypatch):
    source, api, policy, parent, _, native, original, profile = prepared(tmp_path, monkeypatch)
    files = {str(p): p.read_bytes() for custody in (parent, original) for p in custody._directory.iterdir()}
    writes = list(native.calls)
    reader = dependency(source, original, profile)
    observation = reader.read_once()
    reader.check_current(observation)
    assert observation.folder_creation_digest == original.inspect_created_state().custody_digest
    assert observation.policy_creation_digest == parent.inspect_created_state().custody_digest
    assert observation.folder_state_digest == source._current.state_digest
    assert source._current.policy_reference_count == 1 and source.logout_verified
    assert native.calls == writes and all(p.read_bytes() == files[str(p)]
        for custody in (parent, original) for p in custody._directory.iterdir())
    assert not hasattr(reader, "issue") and not hasattr(reader, "execute")
    assert "UNIT-WINDOWS" not in repr(observation) and "192.0.2.20" not in repr(observation)
    reader.close()
    assert not source._closed and policy.source_context_digest
    with pytest.raises(WindowsSecretFolderDependencyError): reader.check_current(observation)
    source.close(); policy.close()


@pytest.mark.parametrize("fault", ["folder-id", "serial", "requester", "detached", "missing-seal"])
def test_wrong_or_incomplete_original_dependency_refuses_before_network(tmp_path, monkeypatch, fault):
    source, api, policy, _, _, native, original, profile = prepared(tmp_path, monkeypatch)
    requester = "b" * 64
    if fault == "folder-id": profile = replace(profile, folder_id=42)
    if fault == "serial": profile = replace(profile, serial_digest="a" * 64)
    if fault == "requester": requester = "f" * 64
    if fault == "detached": original = original.inspect_created_state()
    if fault == "missing-seal": (original._directory / "created-state.json").unlink()
    before = len(api.base.calls), list(native.calls)
    with pytest.raises(WindowsSecretFolderDependencyError): dependency(source, original, profile, requester=requester)
    assert before == (len(api.base.calls), native.calls)
    source.close(); policy.close()


def test_full_seal_unknown_is_recovery_evidence_but_never_a_new_secret_dependency(tmp_path, monkeypatch):
    source, api, policy, _, _, native, original, profile = prepared(tmp_path, monkeypatch, unknown=True)
    before = len(api.base.calls), list(native.calls)
    assert original.inspect_created_state().original_outcome == "reconciliation_required"
    with pytest.raises(WindowsSecretFolderDependencyError): dependency(source, original, profile)
    assert before == (len(api.base.calls), native.calls)
    source.close(); policy.close()


@pytest.mark.parametrize("fault", ["referenced-folder", "policy-ref", "parent", "hidden-name", "rights"])
def test_fresh_incompatible_or_referenced_state_poison_once_without_mutation(tmp_path, monkeypatch, fault):
    source, api, policy, _, _, native, original, profile = prepared(tmp_path, monkeypatch)
    reader = dependency(source, original, profile)
    if fault == "referenced-folder": api.folder_has_reference = True
    if fault == "policy-ref": api.policy_cli_count = 0
    if fault == "parent": api.parent_changed = True
    if fault == "hidden-name": api.hidden_name = True
    if fault == "rights": api.failure = "folder-role"
    writes = list(native.calls)
    with pytest.raises(WindowsSecretFolderDependencyError): reader.read_once()
    before = len(api.base.calls)
    with pytest.raises(WindowsSecretFolderDependencyError): reader.read_once()
    assert len(api.base.calls) == before and native.calls == writes
    reader.close(); source.close(); policy.close()


@pytest.mark.parametrize("fault", ["copy", "tamper", "expiry", "source-close", "profile"])
def test_window_identity_integrity_expiry_and_source_binding_refuse_stale_evidence(tmp_path, monkeypatch, fault):
    source, api, policy, _, now, native, original, profile = prepared(tmp_path, monkeypatch)
    reader = dependency(source, original, profile)
    observation = reader.read_once()
    if fault == "copy": observation = replace(observation)
    if fault == "tamper": object.__setattr__(observation, "policy_creation_digest", "f" * 64)
    if fault == "expiry": now[0] = observation.expires_at
    if fault == "source-close": source.close()
    if fault == "profile": object.__setattr__(profile, "private_nonce", "a" * 64)
    before = len(api.base.calls), list(native.calls)
    with pytest.raises(WindowsSecretFolderDependencyError): reader.check_current(observation)
    assert before == (len(api.base.calls), native.calls)
    reader.close(); source.close(); policy.close()


def test_new_dependency_does_not_satisfy_or_relax_the_legacy_inherited_preflight(tmp_path, monkeypatch):
    source, api, policy, _, _, native, original, profile = prepared(tmp_path, monkeypatch)
    reader = dependency(source, original, profile)
    root = tmp_path / "legacy"
    root.mkdir(mode=0o700)
    legacy = inherited_preflight(root, monkeypatch)
    kwargs = dict(legacy["kwargs"], folder_workflow=reader)
    before = len(legacy["harness"].requests), list(legacy["target"].calls)
    with pytest.raises(Exception) as caught:
        WindowsExecutionOwnedDependencies(legacy["profile"], **kwargs)
    assert type(caught.value).__name__ == "WindowsExecutionPreflightError"
    assert before == (len(legacy["harness"].requests), legacy["target"].calls)
    legacy["reader"].close()
    reader.close(); source.close(); policy.close()
