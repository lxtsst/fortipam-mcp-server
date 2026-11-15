"""Protected canonical bootstrap with synthetic consumed original evidence."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, cast

import pytest

from fortipam_mcp import instruction_quota_recovery_runtime as r
from fortipam_mcp import instruction_quota_runtime as original
from test_instruction_quota_http_transport import Connection, Cycle
from test_instruction_quota_live_workflow import IDENTITY
from test_instruction_quota_recovery_workflow import policy_for_test
from test_instruction_quota_runtime import setup, save, connect, run


def retained(tmp_path: Path) -> dict[Path, bytes]:
    return {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file() and not p.name.startswith(r._PREFIX)}


def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, str], dict[str, Any], Cycle]:
    env, manifest, path, cycle = setup(tmp_path)
    connect(monkeypatch, cycle)
    env[original.PREFIX + "EXECUTION_ENABLED"] = "true"
    assert run(original.build_instruction_quota_candidate(env))["verification"] == "verified"
    manifest["phase"] = "restore"
    save(path, manifest)
    restore = original.build_instruction_quota_candidate(env)
    with monkeypatch.context() as patch:
        def lost(self: Connection, *args: object, **kwargs: object) -> None:
            raise RuntimeError("synthetic-private-original-restore-unknown")
        patch.setattr(Connection, "request", lost)
        assert run(restore)["verification"] == "unknown"
    env[original.PREFIX + "EXECUTION_ENABLED"] = "false"
    env[r.PREFIX + "ENABLED"] = "true"
    for index, suffix in enumerate(r._KEYS.values()):
        key = cycle.path / (r._PREFIX + suffix)
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(bytes([81 + index]) * 32)
    return env, manifest, cycle


def test_disabled_startup_never_loads_original_or_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r, "_build_instruction_quota_candidate_binding", lambda *a, **k: pytest.fail("disabled source load"))
    assert r.build_instruction_quota_recovery_candidate({}) is None
    for value in ({"EXECUTION_ENABLED": "true"}, {"ENABLED": "TRUE"}, {"ENABLED": True}):
        with pytest.raises(ValueError):
            r.build_instruction_quota_recovery_candidate({r.PREFIX + k: v for k, v in value.items()})  # type: ignore[arg-type]


def test_closed_startup_verifies_all_five_keys_without_device_read_and_one_read_per_preview(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env, manifest, cycle = prepared(tmp_path, monkeypatch)
    before = retained(tmp_path)
    cycle.device.on_read = lambda: pytest.fail("startup performed a device read")
    item = r.build_instruction_quota_recovery_candidate(env)
    assert item is not None and item._workflow is None and item._enabled is False
    assert item._cohort == frozenset(hashlib.sha256(Path(value).read_bytes()).hexdigest()
        for name, value in manifest["paths"].items() if name.endswith("_hmac_key_file"))
    assert len(item._cohort) == 5 and retained(tmp_path) == before
    reads: list[bool] = []
    cycle.device.on_read = lambda: reads.append(True)
    first = item.preview(**IDENTITY)
    assert len(reads) == 1 and first["execution_admissible"] is False
    second = item.preview(**IDENTITY)
    assert len(reads) == 2 and second["preview_ref"] != first["preview_ref"]
    with pytest.raises(ValueError): item.authorize(cast(str, second["preview_ref"]), **IDENTITY)
    assert len(reads) == 2 and len(cycle.device.requests) == 1 and retained(tmp_path) == before


@pytest.mark.parametrize("key_name", sorted(original._PATH_KEYS - {"allocate_execution_database_file", "restore_execution_database_file"}))
def test_every_original_key_is_excluded_from_new_authority_before_new_database_creation(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key_name: str) -> None:
    env, manifest, cycle = prepared(tmp_path, monkeypatch)
    (cycle.path / (r._PREFIX + ".authority.key")).write_bytes(Path(manifest["paths"][key_name]).read_bytes())
    before = retained(tmp_path)
    with pytest.raises(ValueError): r.build_instruction_quota_recovery_candidate(env)
    assert not (cycle.path / (r._PREFIX + ".m4.sqlite")).exists()
    assert retained(tmp_path) == before and len(cycle.device.requests) == 1


@pytest.mark.parametrize("failure", ["old_gate", "old_unused_key", "old_marker", "missing_new_key", "new_key_reuse", "key_symlink", "key_mode"])
def test_bootstrap_rejects_unbound_or_unprotected_inputs_without_original_mutation(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    env, manifest, cycle = prepared(tmp_path, monkeypatch)
    key = cycle.path / (r._PREFIX + ".authority.key")
    if failure == "old_gate": env[original.PREFIX + "EXECUTION_ENABLED"] = "true"
    elif failure == "old_unused_key": Path(manifest["paths"]["allocate_authority_hmac_key_file"]).write_bytes(b"Z" * 32)
    elif failure == "old_marker": (cycle.path / original._MARKER).write_bytes(b"{}")
    elif failure == "missing_new_key": key.unlink()
    elif failure == "new_key_reuse": key.write_bytes((cycle.path / (r._PREFIX + ".native.key")).read_bytes())
    elif failure == "key_symlink":
        key.unlink(); key.symlink_to(cycle.path / (r._PREFIX + ".native.key"))
    elif failure == "key_mode": key.chmod(0o644)
    before = retained(tmp_path)
    with pytest.raises(ValueError): r.build_instruction_quota_recovery_candidate(env)
    assert not (cycle.path / (r._PREFIX + ".m4.sqlite")).exists()
    assert retained(tmp_path) == before and len(cycle.device.requests) == 1


@pytest.mark.parametrize("failure", ["old_unused_key", "old_marker", "new_key", "key_inode", "database_inode", "lock", "lock_inode"])
def test_active_binding_drift_denies_before_preview_read_or_dispatch(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    env, manifest, cycle = prepared(tmp_path, monkeypatch)
    item = r.build_instruction_quota_recovery_candidate(env)
    assert item is not None
    key = cycle.path / (r._PREFIX + ".authority.key")
    if failure == "old_unused_key": Path(manifest["paths"]["allocate_authority_hmac_key_file"]).write_bytes(b"Z" * 32)
    elif failure == "old_marker": (cycle.path / original._MARKER).write_bytes(b"{}")
    elif failure == "new_key": key.write_bytes(b"Z" * 32)
    elif failure in {"key_inode", "database_inode"}:
        target = key if failure == "key_inode" else item._store._path
        replacement = target.with_suffix(".replacement")
        replacement.write_bytes(target.read_bytes()); replacement.chmod(0o600); replacement.replace(target)
    elif failure == "lock": (cycle.path / "operation.lock").unlink()
    elif failure == "lock_inode":
        lock = cycle.path / "operation.lock"
        replacement = cycle.path / "replacement.lock"
        replacement.write_bytes(lock.read_bytes()); replacement.chmod(0o600); replacement.replace(lock)
    before = retained(tmp_path)
    cycle.device.on_read = lambda: pytest.fail("drift reached a device read")
    with pytest.raises(ValueError): item.preview(**IDENTITY)
    assert retained(tmp_path) == before and len(cycle.device.requests) == 1
    if failure == "lock": assert not (cycle.path / "operation.lock").exists()


def test_canonical_startup_with_synthetic_external_policy_uses_only_new_m4_and_preserves_original(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env, manifest, cycle = prepared(tmp_path, monkeypatch)
    env[r.PREFIX + "EXECUTION_ENABLED"] = "true"
    item = r.build_instruction_quota_recovery_candidate(env)
    assert item is not None
    before = retained(tmp_path)
    preview = item.preview(**IDENTITY)
    with pytest.raises(ValueError): item.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    assert item._workflow is not None
    policy_for_test(item._workflow)
    auth = item.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    result = item.execute(cast(str, auth["authorization_ref"]), **IDENTITY)
    assert result["outcome"] == "succeeded" and result["verification"] == "verified"
    assert result["original_restore_unknown_preserved"] is True and result["incident_closed"] is False
    assert retained(tmp_path) == before and len(cycle.device.requests) == 2
    assert not (cycle.path / "restore.ack.json").exists()
    assert item.execute(cast(str, auth["authorization_ref"]), **IDENTITY)["idempotent_replay"] is True
    assert len(cycle.device.requests) == 2
    reopened = r.build_instruction_quota_recovery_candidate(env)
    assert reopened is not None
    with pytest.raises(ValueError): reopened.preview(**IDENTITY)
    assert len(cycle.device.requests) == 2 and retained(tmp_path) == before


def test_missing_new_ledger_after_attempt_refuses_reinitialization(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env, manifest, cycle = prepared(tmp_path, monkeypatch)
    item = r.build_instruction_quota_recovery_candidate(env)
    assert item is not None
    attempt = cycle.path / (r._PREFIX + ".m4.attempt.json")
    attempt.write_bytes(b"incomplete-consumed-attempt"); attempt.chmod(0o600)
    item._store._path.unlink()
    before = retained(tmp_path)
    with pytest.raises(ValueError): r.build_instruction_quota_recovery_candidate(env)
    assert not item._store._path.exists() and retained(tmp_path) == before
    assert len(cycle.device.requests) == 1


def test_readonly_bootstrap_lock_disappearing_after_input_check_is_never_recreated(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env, manifest, cycle = prepared(tmp_path, monkeypatch)
    cls = original.FortiPamInstructionQuotaHttpTransport
    initialize = cls.__init__
    def remove_lock(self: Any, *args: object, **kwargs: object) -> None:
        initialize(self, *args, **kwargs)  # type: ignore[arg-type]
        (cycle.path / "operation.lock").unlink()
    monkeypatch.setattr(cls, "__init__", remove_lock)
    before = {p: raw for p, raw in retained(tmp_path).items() if p.name != "operation.lock"}
    with pytest.raises(ValueError):
        original.build_instruction_quota_candidate(env, read_only_reconciliation=True)
    assert not (cycle.path / "operation.lock").exists()
    assert retained(tmp_path) == before and len(cycle.device.requests) == 1


@pytest.mark.parametrize("point", ["read", "connect"])
@pytest.mark.parametrize("failure", ["old_unused_key", "new_authority", "new_native", "old_roles", "marker", "manifest"])
def test_bootstrap_drift_after_execute_entry_consumes_unknown_before_put(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, point: str, failure: str) -> None:
    env, manifest, cycle = prepared(tmp_path, monkeypatch)
    env[r.PREFIX + "EXECUTION_ENABLED"] = "true"
    item = r.build_instruction_quota_recovery_candidate(env)
    assert item is not None
    preview = item.preview(**IDENTITY)
    assert item._workflow is not None
    policy_for_test(item._workflow)
    auth = item.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    before = retained(tmp_path)
    targets = {"old_unused_key": [Path(manifest["paths"]["allocate_authority_hmac_key_file"])],
        "new_authority": [cycle.path / (r._PREFIX + ".authority.key")],
        "new_native": [cycle.path / (r._PREFIX + ".native.key")],
        "old_roles": [Path(manifest["paths"][name]) for name in ("allocate_authority_hmac_key_file", "restore_authority_hmac_key_file")],
        "marker": [cycle.path / original._MARKER],
        "manifest": [Path(env[original.PREFIX + "STARTUP_MANIFEST_FILE"])]}[failure]
    saved = [p.read_bytes() for p in targets]
    def drift() -> None:
        for i, path in enumerate(targets):
            path.write_bytes(saved[1 - i] if failure == "old_roles" else b"Z" * 32)
    if point == "read": cycle.device.on_read = drift
    else: cycle.device.on_connect = drift
    result = item.execute(cast(str, auth["authorization_ref"]), **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert result["compensation"] == "not_requested" and item._store.claim_count == 1
    assert len(cycle.device.requests) == 1 and not (cycle.path / "restore.ack.json").exists()
    cycle.device.on_read = cycle.device.on_connect = None
    for path, raw in zip(targets, saved): path.write_bytes(raw)
    assert retained(tmp_path) == before
    assert item.execute(cast(str, auth["authorization_ref"]), **IDENTITY)["idempotent_replay"] is True
    with pytest.raises(ValueError): item.preview(**IDENTITY)
    assert len(cycle.device.requests) == 1
