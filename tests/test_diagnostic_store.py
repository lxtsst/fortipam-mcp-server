from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
import os
import sqlite3
import stat

import pytest

import fortipam_mcp.diagnostic_store as diagnostic_store
from fortipam_mcp.baseline_drift import (
    BaselineRecord,
    ProjectionContract,
    ProjectionContractRegistry,
    ProjectionFieldContract,
    parse_projection_envelope,
)
from fortipam_mcp.diagnostic_store import (
    AuditProfile,
    DiagnosticBaselineStore,
    DiagnosticStoreError,
)


KEY = b"a" * 32
NOW = datetime(2026, 8, 22, 12, tzinfo=UTC)
PRINCIPAL = "1" * 64
CONTRACT = ProjectionContract(
    contract_id="ha_posture",
    version="v1",
    data_class="C1",
    source_product="FortiPAM",
    source_product_version="1.9.1",
    source_class="fortipam_api",
    scope_class="source_restricted",
    required_paths=frozenset({("ha_enabled",), ("topology", "mode")}),
    field_rules=(
        ProjectionFieldContract(("ha_enabled",), "bool", "v1"),
        ProjectionFieldContract(
            ("topology", "mode"), "string", "v1", enum_values=frozenset({"standalone", "cluster"})
        ),
    ),
)
REGISTRY = ProjectionContractRegistry([CONTRACT])


def _envelope() -> dict[str, object]:
    return {
        "schema_version": "2.3",
        "data_class": "C1",
        "source": {"product": "FortiPAM", "product_version": "1.9.1", "source_class": "fortipam_api"},
        "contract": {"id": "ha_posture", "version": "v1"},
        "scope_class": "source_restricted",
        "observed_at": "2026-08-22T11:00:00Z",
        "fresh_until": "2026-08-22T13:00:00Z",
        "evidence_state": "complete",
        "projection": {"ha_enabled": True, "topology": {"mode": "standalone"}},
    }


def _record() -> BaselineRecord:
    envelope = parse_projection_envelope(_envelope(), REGISTRY, require_required_paths=True)
    return BaselineRecord(envelope=envelope, digest=envelope.comparison_digest)


def _store(
    tmp_path: Path,
    *,
    principal: str = PRINCIPAL,
    key: bytes = KEY,
    audit_profiles: tuple[AuditProfile, ...] | None = None,
    clock: object = None,
) -> DiagnosticBaselineStore:
    return DiagnosticBaselineStore(
        tmp_path / "state" / "diagnostic.db",
        REGISTRY,
        principal,
        key,
        audit_profiles=audit_profiles,
        clock=clock,  # type: ignore[arg-type]
    )


def test_constructor_creates_owner_only_directory_database_and_safe_sqlite_settings(tmp_path: Path) -> None:
    store = _store(tmp_path)
    database = tmp_path / "state" / "diagnostic.db"
    assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    with store._connect() as connection:  # noqa: SLF001 - verify persistence hardening.
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2


def test_constructor_rejects_symlink_wide_permissions_and_non_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    os.chmod(unsafe, 0o755)
    with pytest.raises(DiagnosticStoreError):
        DiagnosticBaselineStore(unsafe / "diagnostic.db", REGISTRY, PRINCIPAL, KEY)

    existing = _store(tmp_path / "existing")
    os.chmod(tmp_path / "existing" / "state" / "diagnostic.db", 0o644)
    with pytest.raises(DiagnosticStoreError):
        DiagnosticBaselineStore(
            tmp_path / "existing" / "state" / "diagnostic.db", REGISTRY, PRINCIPAL, KEY
        )
    assert existing is not None

    secure = tmp_path / "secure"
    secure.mkdir(mode=0o700)
    target = tmp_path / "target.db"
    target.write_text("not a database", encoding="utf-8")
    os.chmod(target, 0o600)
    (secure / "diagnostic.db").symlink_to(target)
    with pytest.raises(DiagnosticStoreError):
        DiagnosticBaselineStore(secure / "diagnostic.db", REGISTRY, PRINCIPAL, KEY)

    owner_only = tmp_path / "owner"
    DiagnosticBaselineStore(owner_only / "diagnostic.db", REGISTRY, PRINCIPAL, KEY)
    real_uid = os.getuid()
    monkeypatch.setattr(diagnostic_store.os, "getuid", lambda: real_uid + 1)
    with pytest.raises(DiagnosticStoreError):
        DiagnosticBaselineStore(owner_only / "diagnostic.db", REGISTRY, PRINCIPAL, KEY)


def test_create_is_immutable_and_principal_scoped_without_plaintext_keys(tmp_path: Path) -> None:
    first = _store(tmp_path, principal="1" * 64)
    first.create("baseline-secret-id", _record())
    with pytest.raises(DiagnosticStoreError, match="already exists"):
        first.create("baseline-secret-id", _record())
    assert first.load("baseline-secret-id") is not None

    second = _store(tmp_path, principal="2" * 64)
    assert second.load("baseline-secret-id") is None
    raw_database = (tmp_path / "state" / "diagnostic.db").read_bytes()
    assert b"baseline-secret-id" not in raw_database
    assert b"1" * 64 not in raw_database
    assert b"2" * 64 not in raw_database


def test_audit_uses_a_domain_separated_record_reference_not_raw_digest(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = _record()
    store.create("baseline-secret-id", record)
    with sqlite3.connect(tmp_path / "state" / "diagnostic.db") as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)")}
        reference = connection.execute("SELECT record_reference FROM audit_events").fetchone()[0]
    assert "comparison_digest" not in columns
    assert reference != record.digest
    assert isinstance(reference, str) and len(reference) == 64


def test_create_uses_one_injected_utc_clock_value_for_record_and_audit(tmp_path: Path) -> None:
    calls: list[datetime] = []

    def clock() -> datetime:
        calls.append(NOW)
        return NOW

    store = _store(tmp_path, clock=clock)
    store.create("baseline-one", _record())
    with sqlite3.connect(tmp_path / "state" / "diagnostic.db") as connection:
        created_at = connection.execute("SELECT created_at FROM baselines").fetchone()[0]
        occurred_at = connection.execute("SELECT occurred_at FROM audit_events").fetchone()[0]
    assert calls == [NOW]
    assert created_at == occurred_at == "2026-08-22T12:00:00Z"
    naive_clock_store = _store(tmp_path / "naive", clock=lambda: datetime(2026, 8, 22, 12))
    with pytest.raises(DiagnosticStoreError):
        naive_clock_store.create("baseline-one", _record())


def test_create_rolls_back_when_audit_append_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)

    def fail_audit(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("fail closed")

    monkeypatch.setattr(store, "_append_audit", fail_audit)
    with pytest.raises(DiagnosticStoreError):
        store.create("baseline-one", _record())
    restored = _store(tmp_path)
    assert restored.load("baseline-one") is None


def test_audit_chain_detects_tampering_wrong_key_and_survives_restart(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create("baseline-one", _record())
    restarted = _store(tmp_path)
    assert restarted.load("baseline-one") is not None
    with pytest.raises(DiagnosticStoreError):
        _store(tmp_path, key=b"b" * 32)

    database = tmp_path / "state" / "diagnostic.db"
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE audit_events SET outcome = 'rejected' WHERE sequence = 1")
    with pytest.raises(DiagnosticStoreError):
        _store(tmp_path)


def test_append_event_is_contract_bound_and_strict(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.append_event("store_verify", "ha_posture", "ha_posture", "v1", "accepted", NOW)
    for values in (
        ("unknown", "ha_posture", "ha_posture", "v1", "accepted"),
        ("store_verify", "other_profile", "ha_posture", "v1", "accepted"),
        ("store_verify", "ha_posture", "ha_posture", "v1", "unknown"),
        ("baseline_compare", "ha_posture", "ha_posture", "v1", "accepted"),
        ("evidence_correlate", "ha_posture", "ha_posture", "v1", "unchanged"),
    ):
        with pytest.raises(DiagnosticStoreError):
            store.append_event(*values, NOW)


def test_explicit_correlation_audit_profile_uses_its_real_contract(tmp_path: Path) -> None:
    profiles = (
        AuditProfile(
            "ha_api_cli_v1",
            "ha_api_cli_v1",
            "v1",
            frozenset({"evidence_correlate"}),
        ),
    )
    store = _store(tmp_path, audit_profiles=profiles)
    store.append_event(
        "evidence_correlate",
        "ha_api_cli_v1",
        "ha_api_cli_v1",
        "v1",
        "operationally_consistent",
        NOW,
    )
    with pytest.raises(DiagnosticStoreError):
        store.append_event(
            "evidence_correlate",
            "ha_posture",
            "ha_posture",
            "v1",
            "operationally_consistent",
            NOW,
        )
    with pytest.raises(DiagnosticStoreError):
        store.append_event(
            "baseline_compare", "ha_api_cli_v1", "ha_posture", "v1", "unchanged", NOW
        )


def test_audit_profile_validation_rejects_unknown_event_and_duplicate(tmp_path: Path) -> None:
    with pytest.raises(DiagnosticStoreError):
        AuditProfile("ha_audit", "ha_posture", "v1", frozenset({"arbitrary_event"}))
    profile = AuditProfile("ha_audit", "ha_posture", "v1", frozenset({"baseline_compare"}))
    with pytest.raises(DiagnosticStoreError):
        _store(tmp_path, audit_profiles=(profile, profile))
    correlation = AuditProfile(
        "other_audit",
        "real_correlation_contract",
        "v1",
        frozenset({"evidence_correlate"}),
    )
    _store(tmp_path / "correlation", audit_profiles=(correlation,))


def test_store_rejects_raw_or_malformed_principal_namespaces(tmp_path: Path) -> None:
    for principal in ("operator-opaque", "g" * 64, "1" * 63, "1" * 65):
        with pytest.raises(DiagnosticStoreError):
            _store(tmp_path / principal[:8], principal=principal)


def test_concurrent_create_has_one_winner_and_one_fail_closed_duplicate(tmp_path: Path) -> None:
    def create() -> str:
        store = _store(tmp_path)
        try:
            store.create("baseline-one", _record())
        except DiagnosticStoreError:
            return "rejected"
        return "accepted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: create(), range(2)))
    assert sorted(results) == ["accepted", "rejected"]
    assert _store(tmp_path).load("baseline-one") is not None


def test_store_rejects_invalid_records_and_baseline_identifiers(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(DiagnosticStoreError):
        store.create("no", _record())
    with pytest.raises(DiagnosticStoreError):
        store.create("baseline-one", object())  # type: ignore[arg-type]
