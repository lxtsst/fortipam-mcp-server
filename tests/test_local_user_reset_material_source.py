"""Synthetic-only checks for the private one-use BP002 material source."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

from fortipam_mcp.local_user_reset_http_transport import (
    FortiPamLocalUserResetHttpTransport, LocalUserResetBaseline, LocalUserResetBinding,
    LocalUserResetHttpOutcome, LocalUserResetHttpTransportError,
    _dispose_password,
)
from fortipam_mcp.local_user_reset_execution import (
    FortiPamLocalUserResetExecution, LocalUserResetExecutionError, LocalUserResetRunIntent,
)
from fortipam_mcp.local_user_reset_material_source import (
    LocalUserResetMaterialSourceError, OwnerOnlyLocalUserResetMaterialSource,
    stage_next_password_once,
)
from fortipam_mcp.local_user_reset_policy_reader import (
    FortiPamLocalUserResetPolicyReader, LocalUserResetPolicySnapshot,
)
import fortipam_mcp.local_user_reset_material_source as material_module
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

from test_local_user_reset_http_transport import Harness
from test_local_user_reset_provenance_inspector import CREATED, _setup as _provenance_setup
from test_m4_execution_store import _store


def _binding() -> LocalUserResetBinding:
    return LocalUserResetBinding(LocalUserResetBaseline(
        username="mcp-v4-user-reset-synthetic", status="disable", is_local=True,
        access_profile="Guest", sponsor_group="", schedule="", guest_auth="disable",
        nonmaterial_state_digest="a" * 64, fixture_creation_digest="b" * 64,
        reported_reference_count=0, usage_entry_count=0,
        product_version="7.0.0", product_build=29,
    ))


def _source(tmp_path: Path, *, enabled: bool = True, drift: bool = False,
            source_type: type[OwnerOnlyLocalUserResetMaterialSource] = OwnerOnlyLocalUserResetMaterialSource,
            ) -> tuple[OwnerOnlyLocalUserResetMaterialSource, Path, Path]:
    fixture, reset = tmp_path / "fixture", tmp_path / "reset"
    fixture.mkdir(mode=0o700)
    reset.mkdir(mode=0o700)
    old_bytes = bytes([65]) * 16
    old_path, new_path = fixture / "initial-password", reset / "next-password"
    old_path.write_bytes(old_bytes)
    old_path.chmod(0o600)
    binding = _binding()
    digest = stage_next_password_once(reset, fixture_directory=fixture,
                                      binding=binding, enabled=True)

    class Inspector:
        def read_nonmaterial_baseline(self) -> LocalUserResetBaseline:
            return replace(binding.expected, status="enable") if drift else binding.expected

        def verify_initial_material_view(
            self, material: memoryview, *, expected_fixture_digest: str,
        ) -> bool:
            return material.nbytes == len(old_bytes) and expected_fixture_digest == binding.expected.fixture_creation_digest

    return (source_type(
        fixture_directory=fixture, reset_directory=reset, binding=binding,
        inspector=Inspector(), expected_binding_digest=digest, enabled=enabled,
    ), old_path, new_path)


def test_exact_owner_only_source_transfers_mutable_buffers_once(tmp_path: Path) -> None:
    source, _, _ = _source(tmp_path)
    lease = source()
    with pytest.raises(LocalUserResetMaterialSourceError):
        source()
    old, new = lease._consume()
    assert old.nbytes == 16 and new.nbytes == 32
    old_owner, new_owner = old.obj, new.obj
    assert old_owner is not new_owner
    _dispose_password(old)
    _dispose_password(new)
    assert not any(old_owner) and not any(new_owner)
    with pytest.raises(LocalUserResetHttpTransportError):
        lease._consume()


def test_default_gate_never_reads_material(tmp_path: Path) -> None:
    source, _, _ = _source(tmp_path, enabled=False)
    with pytest.raises(LocalUserResetMaterialSourceError):
        source()


def test_rotated_fixture_reuses_explicit_signed_current_material(tmp_path: Path) -> None:
    prior, initial, current_path = _source(tmp_path)
    fixture = tmp_path / "fixture"
    marker = fixture / "current-login-binding.json"
    marker.write_text("{}")
    marker.chmod(0o600)
    next_reset = tmp_path / "next-reset"
    next_reset.mkdir(mode=0o700)
    next_digest = stage_next_password_once(next_reset, fixture_directory=fixture,
                                          binding=prior._binding, enabled=True)
    source = OwnerOnlyLocalUserResetMaterialSource(
        fixture_directory=fixture, reset_directory=next_reset,
        binding=prior._binding, inspector=prior._inspector,
        expected_binding_digest=next_digest, enabled=True,
        current_reset_directory=tmp_path / "reset",
        expected_current_binding_digest=prior._staged_binding_digest,
    )
    # Creation evidence remains immutable; the old value now comes from the
    # verified signed material selection, not the rotation marker's contents.
    original = initial.read_bytes()
    old, new = source()._consume()
    try:
        assert old == current_path.read_bytes() and old != original
        assert new == (next_reset / "next-password").read_bytes() and old != new
        assert source._binding_digest != next_digest
        assert initial.read_bytes() == original
    finally:
        _dispose_password(old)
        _dispose_password(new)
    with pytest.raises(LocalUserResetHttpTransportError):
        prior()._consume()
    with pytest.raises(LocalUserResetMaterialSourceError):
        OwnerOnlyLocalUserResetMaterialSource(
            fixture_directory=fixture, reset_directory=next_reset,
            binding=prior._binding, inspector=prior._inspector,
            expected_binding_digest=next_digest, enabled=True,
        )


def test_selected_current_material_tamper_cannot_release_a_lease(tmp_path: Path) -> None:
    prior, _, current_path = _source(tmp_path)
    next_reset = tmp_path / "next-reset"
    next_reset.mkdir(mode=0o700)
    next_digest = stage_next_password_once(next_reset, fixture_directory=tmp_path / "fixture",
                                          binding=prior._binding, enabled=True)
    source = OwnerOnlyLocalUserResetMaterialSource(
        fixture_directory=tmp_path / "fixture", reset_directory=next_reset,
        binding=prior._binding, inspector=prior._inspector,
        expected_binding_digest=next_digest, enabled=True,
        current_reset_directory=tmp_path / "reset",
        expected_current_binding_digest=prior._staged_binding_digest,
    )
    current_path.write_bytes(b"wrong-current-material")
    with pytest.raises(LocalUserResetHttpTransportError):
        source()._consume()


def _record_current_login(tmp_path: Path, source: OwnerOnlyLocalUserResetMaterialSource) -> None:
    result = json.dumps({"outcome": "succeeded"}).encode()
    acceptance = {"execution_outcome": "succeeded", "authenticated_identity_verified": True,
                  "authenticated_status": 200, "new_password_login_http_status": 303,
                  "execution_result_sha256": hashlib.sha256(result).hexdigest(), "observed_at": 100}
    pointer = {"username": source._binding.expected.username,
               "material_source": "../reset/next-password", "acceptance_record": "../reset/acceptance.json",
               "verified_at": 100, "identity_verified": True, "initial_password_is_historical": True}
    for path, value in (
        (tmp_path / "reset" / "result.json", result),
        (tmp_path / "reset" / "acceptance.json", json.dumps(acceptance).encode()),
        (tmp_path / "fixture" / "current-login-binding.json", json.dumps(pointer).encode()),
    ):
        path.write_bytes(value)
        path.chmod(0o600)


def _automatic_current_source(tmp_path: Path, *, enabled: bool = True) -> OwnerOnlyLocalUserResetMaterialSource:
    prior, _, _ = _source(tmp_path)
    _record_current_login(tmp_path, prior)
    next_reset = tmp_path / "next-reset"
    next_reset.mkdir(mode=0o700)
    next_digest = stage_next_password_once(next_reset, fixture_directory=tmp_path / "fixture",
                                          binding=prior._binding, enabled=True)
    return OwnerOnlyLocalUserResetMaterialSource.from_current_login_binding(
        fixture_directory=tmp_path / "fixture", reset_directory=next_reset,
        binding=prior._binding, inspector=prior._inspector,
        expected_binding_digest=next_digest, enabled=enabled,
    )


def test_current_login_selector_reuses_verified_source_without_initial_fallback(tmp_path: Path) -> None:
    source = _automatic_current_source(tmp_path)
    old, new = source()._consume()
    try:
        assert old == (tmp_path / "reset" / "next-password").read_bytes()
        assert old != (tmp_path / "fixture" / "initial-password").read_bytes()
        assert new == (tmp_path / "next-reset" / "next-password").read_bytes()
    finally:
        _dispose_password(old)
        _dispose_password(new)


def test_current_login_selector_stays_default_off(tmp_path: Path) -> None:
    source = _automatic_current_source(tmp_path, enabled=False)
    with pytest.raises(LocalUserResetMaterialSourceError):
        source()


def test_pending_transition_blocks_other_runs_restart_and_new_staging(tmp_path: Path) -> None:
    source = _automatic_current_source(tmp_path)
    source._reset = source._reset.rename(tmp_path / "reset-next")
    second = tmp_path / "reset-second"
    second.mkdir(mode=0o700)
    digest = stage_next_password_once(second, fixture_directory=source._fixture,
        binding=source._binding, enabled=True)
    other = OwnerOnlyLocalUserResetMaterialSource.from_current_login_binding(
        fixture_directory=source._fixture, reset_directory=second, binding=source._binding,
        inspector=source._inspector, expected_binding_digest=digest, enabled=True)
    source._reserve_transition_once()
    source._verify_current_selection()
    marker = source._fixture / "current-login-transition.json"
    assert marker.stat().st_mode & 0o777 == 0o600
    assert json.loads(marker.read_bytes())["reset_directory"] == "reset-next"
    with pytest.raises(LocalUserResetMaterialSourceError):
        other._verify_current_selection()
    with pytest.raises(LocalUserResetMaterialSourceError):
        other._reserve_transition_once()
    with pytest.raises(LocalUserResetMaterialSourceError):
        OwnerOnlyLocalUserResetMaterialSource.from_current_login_binding(
            fixture_directory=source._fixture, reset_directory=source._reset, binding=source._binding,
            inspector=source._inspector, expected_binding_digest=source._staged_binding_digest, enabled=True)
    third = tmp_path / "reset-third"
    third.mkdir(mode=0o700)
    with pytest.raises(LocalUserResetMaterialSourceError):
        stage_next_password_once(third, fixture_directory=source._fixture, binding=source._binding, enabled=True)
    assert list(third.iterdir()) == []
    old, new = source()._consume()
    _dispose_password(old)
    _dispose_password(new)


def test_pending_login_binding_reconstructs_only_readonly_acceptance_state(tmp_path: Path) -> None:
    source = _automatic_current_source(tmp_path)
    source._reset = source._reset.rename(tmp_path / "reset-next")
    source._reserve_transition_once()
    marker = source._fixture / "current-login-transition.json"
    before = marker.read_bytes()
    invocation = source._reset / "login-invocation"
    invocation.write_bytes(b"synthetic-consumed-login-record")
    invocation.chmod(0o600)
    arguments = dict(fixture_directory=source._fixture, reset_directory=source._reset,
        binding=source._binding, inspector=source._inspector,
        expected_binding_digest=source._staged_binding_digest)
    with pytest.raises(LocalUserResetMaterialSourceError):
        OwnerOnlyLocalUserResetMaterialSource.from_current_login_binding(**arguments)
    recovered = OwnerOnlyLocalUserResetMaterialSource.from_pending_login_binding(**arguments)
    assert recovered._enabled is False and recovered._consumed is True
    assert recovered._pending_login is True
    for field in ("_fixture", "_fixture_id", "_reset", "_reset_id", "_current", "_current_id",
                  "_current_binding_digest", "_expected_current_digest", "_staged_binding_digest",
                  "_expected_new_digest", "_current_selection_digest", "_binding_digest", "_pending_transition"):
        assert getattr(recovered, field) == getattr(source, field)
    recovered._verify_current_selection()
    for attempt in (recovered, recovered._reserve_transition_once, recovered._load):
        with pytest.raises(LocalUserResetMaterialSourceError):
            attempt()
    # Restoring the enable flag cannot revive this reconciliation-only source.
    recovered._enabled = True
    recovered._consumed = False
    for attempt in (recovered, recovered._reserve_transition_once, recovered._load):
        with pytest.raises(LocalUserResetMaterialSourceError):
            attempt()
    assert marker.read_bytes() == before
    assert invocation.read_bytes() == b"synthetic-consumed-login-record"
    assert not (source._reset / "acceptance.json").exists()
    third = tmp_path / "reset-third"
    third.mkdir(mode=0o700)
    with pytest.raises(LocalUserResetMaterialSourceError):
        stage_next_password_once(third, fixture_directory=source._fixture, binding=source._binding, enabled=True)


@pytest.mark.parametrize("failure", ["version", "reset_directory", "current_selection_digest",
    "staged_binding_digest", "material_pair_digest", "missing", "mode", "symlink", "selection_changed"])
def test_pending_login_binding_rejects_changed_transition(tmp_path: Path, failure: str) -> None:
    source = _automatic_current_source(tmp_path)
    source._reset = source._reset.rename(tmp_path / "reset-next")
    source._reserve_transition_once()
    marker = source._fixture / "current-login-transition.json"
    if failure == "missing":
        marker.unlink()
    elif failure == "mode":
        marker.chmod(0o644)
    elif failure == "symlink":
        marker.rename(marker.with_name("held-transition"))
        marker.symlink_to(marker.with_name("held-transition"))
    elif failure == "selection_changed":
        pointer = source._fixture / "current-login-binding.json"
        value = json.loads(pointer.read_bytes())
        value["verified_at"] += 1
        pointer.write_bytes(material_module._canonical(value))
    else:
        document = json.loads(marker.read_bytes())
        document[failure] = True if failure == "version" else "0" * 64
        marker.write_bytes(material_module._canonical(document))
    with pytest.raises(LocalUserResetMaterialSourceError):
        OwnerOnlyLocalUserResetMaterialSource.from_pending_login_binding(
            fixture_directory=source._fixture, reset_directory=source._reset, binding=source._binding,
            inspector=source._inspector, expected_binding_digest=source._staged_binding_digest)


def test_internal_pending_login_constructor_cannot_enable_execution(tmp_path: Path) -> None:
    source = _automatic_current_source(tmp_path)
    source._reset = source._reset.rename(tmp_path / "reset-next")
    source._reserve_transition_once()
    with pytest.raises(LocalUserResetMaterialSourceError):
        OwnerOnlyLocalUserResetMaterialSource(fixture_directory=source._fixture, reset_directory=source._reset,
            binding=source._binding, inspector=source._inspector,
            expected_binding_digest=source._staged_binding_digest,
            current_reset_directory=source._current,
            expected_current_binding_digest=source._current_binding_digest, enabled=True, _pending_login=True)


@pytest.mark.parametrize("failure", ["deleted", "changed", "symlink"])
def test_own_pending_transition_must_stay_intact_before_lease(tmp_path: Path, failure: str) -> None:
    source = _automatic_current_source(tmp_path)
    source._reset = source._reset.rename(tmp_path / "reset-next")
    source._reserve_transition_once()
    marker = source._fixture / "current-login-transition.json"
    if failure == "deleted":
        marker.unlink()
    elif failure == "changed":
        marker.write_bytes(b"{}")
    else:
        marker.rename(marker.with_name("held-transition"))
        marker.symlink_to(marker.with_name("held-transition"))
    with pytest.raises(LocalUserResetMaterialSourceError):
        source._verify_current_selection()
    with pytest.raises(LocalUserResetHttpTransportError):
        source()._consume()


def test_unpublishable_reset_directory_rejects_transition_before_reservation(tmp_path: Path) -> None:
    source = _automatic_current_source(tmp_path)
    with pytest.raises(LocalUserResetMaterialSourceError):
        source._reserve_transition_once()
    assert not (source._fixture / "current-login-transition.json").exists()


def test_missing_current_login_record_cannot_reconstruct_an_initial_source(tmp_path: Path) -> None:
    source = _automatic_current_source(tmp_path)
    (tmp_path / "fixture" / "current-login-binding.json").unlink()
    with pytest.raises(LocalUserResetMaterialSourceError):
        OwnerOnlyLocalUserResetMaterialSource.from_current_login_binding(
            fixture_directory=tmp_path / "fixture", reset_directory=tmp_path / "next-reset",
            binding=source._binding, inspector=source._inspector,
            expected_binding_digest=source._staged_binding_digest, enabled=True,
        )


@pytest.mark.parametrize("failure", ["pointer_identity", "pointer_path", "pointer_acceptance",
    "pointer_mode", "pointer_symlink", "pointer_deleted", "acceptance_identity", "acceptance_status",
    "acceptance_time", "result_hash", "record_changed", "manifest_changed"])
def test_current_login_selector_rechecks_its_records_before_releasing_material(
    tmp_path: Path, failure: str,
) -> None:
    source = _automatic_current_source(tmp_path)
    pointer_path = tmp_path / "fixture" / "current-login-binding.json"
    acceptance_path = tmp_path / "reset" / "acceptance.json"
    pointer = json.loads(pointer_path.read_text())
    acceptance = json.loads(acceptance_path.read_text())
    if failure == "pointer_identity":
        pointer["username"] = "mcp-v4-user-other"
    elif failure == "pointer_path":
        pointer["material_source"] = "../../reset/next-password"
    elif failure == "pointer_acceptance":
        pointer["acceptance_record"] = "../another/acceptance.json"
    elif failure == "pointer_mode":
        pointer_path.chmod(0o644)
    elif failure == "pointer_symlink":
        pointer_path.rename(pointer_path.with_name("held"))
        pointer_path.symlink_to(pointer_path.with_name("held"))
    elif failure == "pointer_deleted":
        pointer_path.unlink()
    elif failure == "acceptance_identity":
        acceptance["authenticated_identity_verified"] = False
    elif failure == "acceptance_status":
        acceptance["authenticated_status"] = True
    elif failure == "acceptance_time":
        acceptance["observed_at"] = 101
    elif failure == "result_hash":
        (tmp_path / "reset" / "result.json").write_text('{"outcome":"reconciliation_required"}')
    elif failure == "record_changed":
        pointer["verified_at"] = 101
    elif failure == "manifest_changed":
        (tmp_path / "reset" / "material-binding.json").write_text("{}")
    if (failure.startswith("pointer_") and failure not in {
        "pointer_mode", "pointer_symlink", "pointer_deleted",
    }) or failure == "record_changed":
        pointer_path.write_text(json.dumps(pointer))
    if failure.startswith("acceptance_"):
        acceptance_path.write_text(json.dumps(acceptance))
    with pytest.raises(LocalUserResetHttpTransportError):
        source()._consume()


def test_stager_is_default_closed_and_rejects_same_directory(tmp_path: Path) -> None:
    fixture, reset = tmp_path / "fixture", tmp_path / "reset"
    fixture.mkdir(mode=0o700)
    reset.mkdir(mode=0o700)
    with pytest.raises(LocalUserResetMaterialSourceError):
        stage_next_password_once(reset, fixture_directory=fixture, binding=_binding())
    with pytest.raises(LocalUserResetMaterialSourceError):
        stage_next_password_once(fixture, fixture_directory=fixture,
                                 binding=_binding(), enabled=True)
    assert list(fixture.iterdir()) == [] and list(reset.iterdir()) == []


def test_stager_writes_owner_only_once_and_refuses_replacement(tmp_path: Path) -> None:
    source, _, new_path = _source(tmp_path)
    reset = tmp_path / "reset"
    for name in ("material.key", "next-password", "material-binding.json"):
        assert stat.S_IMODE((reset / name).stat().st_mode) == 0o600
    assert new_path.stat().st_size == 32
    assert len(source._binding_digest) == 64
    with pytest.raises(LocalUserResetMaterialSourceError):
        stage_next_password_once(reset, fixture_directory=tmp_path / "fixture",
                                 binding=_binding(), enabled=True)


def test_interrupted_staging_retains_partial_state_and_cannot_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, reset = tmp_path / "fixture", tmp_path / "reset"
    fixture.mkdir(mode=0o700)
    reset.mkdir(mode=0o700)
    original_write = material_module._write_once

    def interrupted_write(directory: Path, identity: tuple[int, int], name: str,
                          content: bytearray) -> None:
        if name == "next-password":
            raise OSError("synthetic interruption")
        original_write(directory, identity, name, content)

    monkeypatch.setattr(material_module, "_write_once", interrupted_write)
    with pytest.raises(LocalUserResetMaterialSourceError):
        stage_next_password_once(reset, fixture_directory=fixture,
                                 binding=_binding(), enabled=True)
    assert (reset / "material.key").is_file()
    assert not (reset / "next-password").exists()
    monkeypatch.setattr(material_module, "_write_once", original_write)
    with pytest.raises(LocalUserResetMaterialSourceError):
        stage_next_password_once(reset, fixture_directory=fixture,
                                 binding=_binding(), enabled=True)


@pytest.mark.parametrize("failure", ["baseline", "digest", "mode", "symlink", "missing"])
def test_material_source_fails_closed_and_consumes_lease(tmp_path: Path, failure: str) -> None:
    source, _, new_path = _source(tmp_path, drift=failure == "baseline")
    if failure == "digest":
        new_path.write_bytes(bytes([66]) * 32)
    elif failure == "mode":
        new_path.chmod(0o644)
    elif failure == "symlink":
        new_path.rename(new_path.with_name("held"))
        new_path.symlink_to(new_path.with_name("held"))
    elif failure == "missing":
        new_path.unlink()
    lease = source()
    with pytest.raises(LocalUserResetHttpTransportError):
        lease._consume()
    with pytest.raises(LocalUserResetMaterialSourceError):
        source()


def test_replaced_owner_only_directory_is_rejected(tmp_path: Path) -> None:
    source, _, _ = _source(tmp_path)
    reset = tmp_path / "reset"
    reset.rename(tmp_path / "old-reset")
    reset.mkdir(mode=0o700)
    (reset / "next-password").write_bytes(bytes([66]) * 16)
    (reset / "next-password").chmod(0o600)
    with pytest.raises(LocalUserResetHttpTransportError):
        source()._consume()


def test_equal_but_wrong_typed_baseline_cannot_release_material(tmp_path: Path) -> None:
    source, _, _ = _source(tmp_path)
    expected = source._binding.expected

    class Inspector:
        def read_nonmaterial_baseline(self) -> LocalUserResetBaseline:
            # bool equals int under dataclass equality, but is not a valid count.
            return replace(expected, reported_reference_count=False)  # type: ignore[arg-type]

        def verify_initial_material_view(
            self, material: memoryview, *, expected_fixture_digest: str,
        ) -> bool:
            pytest.fail("Invalid baseline must not reach material verification")

    source._inspector = Inspector()
    with pytest.raises(LocalUserResetHttpTransportError):
        source()._consume()


def test_failed_sealed_initial_material_check_cannot_release_pair(tmp_path: Path) -> None:
    source, _, _ = _source(tmp_path)
    source._inspector.verify_initial_material_view = lambda _material, **_kwargs: False  # type: ignore[method-assign]
    with pytest.raises(LocalUserResetHttpTransportError):
        source()._consume()


def test_manifest_tamper_and_wrong_binding_digest_fail_closed(tmp_path: Path) -> None:
    source, _, _ = _source(tmp_path)
    with pytest.raises(LocalUserResetMaterialSourceError):
        OwnerOnlyLocalUserResetMaterialSource(
            fixture_directory=tmp_path / "fixture", reset_directory=tmp_path / "reset",
            binding=source._binding, inspector=source._inspector,
            expected_binding_digest="0" * 64, enabled=True,
        )
    manifest = tmp_path / "reset" / "material-binding.json"
    document = json.loads(manifest.read_bytes())
    document["body"]["nonce"] = "0" * 64
    manifest.write_bytes(json.dumps(document).encode())
    with pytest.raises(LocalUserResetHttpTransportError):
        source()._consume()


def test_reset_execution_context_binds_private_manifest_not_callback_identity(tmp_path: Path) -> None:
    first_root, second_root = tmp_path / "first", tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first, _, _ = _source(first_root)
    second, _, _ = _source(second_root)
    intent = LocalUserResetRunIntent(
        plan_ref="bp002-reset-synthetic-plan", requester_digest="1" * 64,
        authorization_digest="2" * 64, idempotency_digest="3" * 64,
        summary_digest="4" * 64, scope_digest="5" * 64,
        issued_at=1000, expires_at=1060,
    )

    class AlwaysAllow:
        def verify(self, intent: LocalUserResetRunIntent, *, context_digest: str,
                   now_epoch: int) -> bool:
            return True

    def runner(source: OwnerOnlyLocalUserResetMaterialSource,
               *, mismatched_binding: bool = False,
               enable_runner: bool = False,
               policy_origin: str | None = None) -> FortiPamLocalUserResetExecution:
        binding = (LocalUserResetBinding(source._binding.expected) if mismatched_binding
                   else source._binding)
        transport = FortiPamLocalUserResetHttpTransport(
            SecretMetadataHttpTransportConfig("https://pam.example.test", "unused", 5, None),
            binding=binding, inspector=source._inspector, owner_session=Harness(),
            material_lease_provider=source, enabled=False,
        )
        policy_reader = (FortiPamLocalUserResetPolicyReader(
            SecretMetadataHttpTransportConfig(policy_origin, "unused", 5, None),
        ) if policy_origin is not None else None)
        policy_snapshot = (LocalUserResetPolicySnapshot(
            minimum_length=8, min_change_characters=0,
            min_upper_case_letter=0, min_lower_case_letter=0, min_number=0,
            min_non_alphanumeric=0, status="disable", reuse_password="enable",
            expire_status="disable",
        ) if policy_reader is not None else None)
        return FortiPamLocalUserResetExecution(
            transport, _store(tmp_path), intent=intent,
            authenticated_requester_digest="1" * 64,
            authorized_scope_digest="5" * 64, enabled=enable_runner,
            policy_snapshot=policy_snapshot, policy_inspector=policy_reader,
            authorization_verifier=AlwaysAllow(),
        )

    assert first._binding_digest != second._binding_digest
    assert runner(first)._context != runner(second)._context
    with pytest.raises(LocalUserResetExecutionError):
        runner(first, mismatched_binding=True)
    with pytest.raises(LocalUserResetExecutionError):
        runner(first, enable_runner=True)
    with pytest.raises(LocalUserResetExecutionError):
        runner(first, enable_runner=True, policy_origin="https://other.example.test")
    with pytest.raises(LocalUserResetExecutionError):
        runner(first, enable_runner=True, policy_origin="https://pam.example.test")
    class DerivedSource(OwnerOnlyLocalUserResetMaterialSource):
        pass
    derived_root = tmp_path / "derived"
    derived_root.mkdir()
    derived, _, _ = _source(derived_root, source_type=DerivedSource)
    with pytest.raises(LocalUserResetExecutionError):
        runner(derived, enable_runner=True, policy_origin="https://pam.example.test")


def test_real_source_cannot_dispatch_without_trusted_intent_verifier(tmp_path: Path) -> None:
    h = Harness()
    h.verify_initial_material_view = lambda material, **kwargs: (  # type: ignore[attr-defined]
        material.nbytes == 16 and kwargs.get("expected_fixture_digest") == h.binding.expected.fixture_creation_digest
    )
    fixture, reset = tmp_path / "fixture", tmp_path / "reset"
    fixture.mkdir(mode=0o700)
    reset.mkdir(mode=0o700)
    old_bytes = bytes([65]) * 16
    old_path = fixture / "initial-password"
    old_path.write_bytes(old_bytes)
    old_path.chmod(0o600)
    digest = stage_next_password_once(reset, fixture_directory=fixture,
                                      binding=h.binding, enabled=True)
    source = OwnerOnlyLocalUserResetMaterialSource(
        fixture_directory=fixture, reset_directory=reset, binding=h.binding,
        inspector=h, expected_binding_digest=digest, enabled=True,
    )
    transport = FortiPamLocalUserResetHttpTransport(
        SecretMetadataHttpTransportConfig("https://pam.example.test", "unused", 5, None),
        binding=h.binding, inspector=h, owner_session=h,
        material_lease_provider=source, enabled=True,
    )
    result = transport.reset()
    guarded = transport._reset_with_dispatch_guard(lambda: None)
    assert result.outcome is LocalUserResetHttpOutcome.GATE_CLOSED
    assert guarded.outcome is LocalUserResetHttpOutcome.GATE_CLOSED
    assert h.calls == []
    assert source._consumed is False


def test_derived_real_source_cannot_bypass_dispatch_closure(tmp_path: Path) -> None:
    class DerivedSource(OwnerOnlyLocalUserResetMaterialSource):
        pass

    source, _, _ = _source(tmp_path, source_type=DerivedSource)
    transport = FortiPamLocalUserResetHttpTransport(
        SecretMetadataHttpTransportConfig("https://pam.example.test", "unused", 5, None),
        binding=source._binding, inspector=source._inspector,
        owner_session=Harness(), material_lease_provider=source, enabled=True,
    )
    assert transport.reset().outcome is LocalUserResetHttpOutcome.GATE_CLOSED
    assert transport._reset_with_dispatch_guard(lambda: None).outcome is LocalUserResetHttpOutcome.GATE_CLOSED
    assert source._consumed is False


@pytest.mark.parametrize("tamper", [False, True])
def test_real_sealed_inspector_binds_loaded_old_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: bool,
) -> None:
    inspector = _provenance_setup(tmp_path, monkeypatch)
    baseline = inspector.issue()
    fixture = tmp_path / "retained"
    reset = tmp_path / "reset"
    reset.mkdir(mode=0o700)
    binding = LocalUserResetBinding(baseline)
    digest = stage_next_password_once(reset, fixture_directory=fixture,
                                      binding=binding, enabled=True)
    if tamper:
        old_path = fixture / "initial-password"
        changed = bytearray(old_path.read_bytes())
        changed[0] ^= 1
        old_path.write_bytes(changed)
        os.utime(old_path, (CREATED + 1, CREATED + 1))
        changed[:] = b"\x00" * len(changed)
        assert inspector.read_nonmaterial_baseline() == baseline
    source = OwnerOnlyLocalUserResetMaterialSource(
        fixture_directory=fixture, reset_directory=reset,
        binding=binding, inspector=inspector,
        expected_binding_digest=digest, enabled=True,
    )
    lease = source()
    if tamper:
        with pytest.raises(LocalUserResetHttpTransportError):
            lease._consume()
    else:
        old, new = lease._consume()
        assert old.nbytes > 0 and new.nbytes == 32
        _dispose_password(old)
        _dispose_password(new)
