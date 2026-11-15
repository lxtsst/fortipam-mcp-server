from __future__ import annotations

import os
from pathlib import Path
import sqlite3

import pytest

from v4_planning import (
    AuthenticatedRequester,
    DesiredObject,
    ObjectClass,
    PersistentSchemeDraftAuthority,
    SchemeDraft,
    SchemeDraftAuthorityError,
    SchemeId,
)


NOW = 1_950_000_000


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def _authority(
    root: Path,
    clock: MutableClock,
    *,
    key: bytes = b"scheme-draft-authority-test-key-0000000000000001",
) -> tuple[PersistentSchemeDraftAuthority, Path, Path]:
    state = root / "draft-state"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    key_path = state / "draft.hmac"
    if not key_path.exists():
        key_path.write_bytes(key)
        os.chmod(key_path, 0o600)
    database = state / "draft.sqlite3"
    return (
        PersistentSchemeDraftAuthority(
            database,
            key_path,
            authority_ref="v4-scheme-draft-authority-test",
            clock=clock,
        ),
        database,
        key_path,
    )


def _draft() -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.ACCESS_DOMAIN,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-004",
        environment_ref="scheme-draft-environment",
        scope_ref="scheme-draft-scope",
        owner_ref="scheme-draft-owner",
        audience_ref="scheme-draft-audience",
        outcome_code="establish_access_domain",
        desired_objects=(
            DesiredObject(
                object_ref="scheme-draft-folder",
                object_class=ObjectClass.PUBLIC_FOLDER,
                desired_exists=True,
                desired_fields=(("enabled", True), ("owner_ref", "scheme-draft-owner")),
            ),
        ),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("access_scope_change",),
        assumption_codes=("fixed_fixture_only",),
        excluded_scope_codes=("credential_material",),
        verification_codes=("relation_readback",),
        stop_codes=("current_state_drift",),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="none",
        reversibility_class="compensating_action_required",
        evidence_refs=("scheme-draft-evidence",),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
    )


def test_persistent_scheme_draft_round_trip_restart_and_revoke(tmp_path: Path) -> None:
    clock = MutableClock(NOW)
    authority, database, key_path = _authority(tmp_path, clock)
    requester = AuthenticatedRequester("a" * 64, "operator")

    draft_ref = authority.issue(
        _draft(), requester, expires_at=NOW + 600, now_epoch=NOW
    )
    assert draft_ref.startswith("scheme-draft-")
    assert authority.resolve(draft_ref, requester) == _draft()

    restarted = PersistentSchemeDraftAuthority(
        database,
        key_path,
        authority_ref="v4-scheme-draft-authority-test",
        clock=clock,
    )
    assert restarted.resolve(draft_ref, requester) == _draft()
    restarted.revoke(draft_ref, now_epoch=NOW + 1)
    clock.value = NOW + 1
    with pytest.raises(SchemeDraftAuthorityError, match="unavailable"):
        restarted.resolve(draft_ref, requester)


def test_persistent_scheme_draft_can_bind_trusted_requester_digest(
    tmp_path: Path,
) -> None:
    clock = MutableClock(NOW)
    authority, _database, _key_path = _authority(tmp_path, clock)
    requester = AuthenticatedRequester("trusted-bootstrap-subject", "operator")

    draft_ref = authority.issue_for_requester_digest(
        _draft(),
        requester.digest,
        expires_at=NOW + 600,
        now_epoch=NOW,
    )

    assert authority.resolve(draft_ref, requester) == _draft()
    with pytest.raises(SchemeDraftAuthorityError, match="issuance input"):
        authority.issue_for_requester_digest(
            _draft(),
            "invalid-digest",
            expires_at=NOW + 600,
            now_epoch=NOW,
        )


def test_persistent_scheme_draft_rejects_wrong_requester_expiry_and_clock_rollback(
    tmp_path: Path,
) -> None:
    clock = MutableClock(NOW)
    authority, _database, _key_path = _authority(tmp_path, clock)
    requester = AuthenticatedRequester("a" * 64, "operator")
    other = AuthenticatedRequester("b" * 64, "operator")
    draft_ref = authority.issue(
        _draft(), requester, expires_at=NOW + 60, now_epoch=NOW
    )

    with pytest.raises(SchemeDraftAuthorityError, match="unavailable"):
        authority.resolve(draft_ref, other)
    clock.value = NOW + 60
    with pytest.raises(SchemeDraftAuthorityError, match="unavailable"):
        authority.resolve(draft_ref, requester)
    clock.value = NOW - 1
    with pytest.raises(SchemeDraftAuthorityError, match="time moved backwards"):
        authority.resolve(draft_ref, requester)


def test_persistent_scheme_draft_rejects_tamper_and_wrong_key(tmp_path: Path) -> None:
    clock = MutableClock(NOW)
    authority, database, key_path = _authority(tmp_path, clock)
    requester = AuthenticatedRequester("a" * 64, "operator")
    authority.issue(_draft(), requester, expires_at=NOW + 600, now_epoch=NOW)

    original_key = key_path.read_bytes()
    key_path.write_bytes(b"different-scheme-draft-key-00000000000000000001")
    with pytest.raises(SchemeDraftAuthorityError, match="integrity failed"):
        PersistentSchemeDraftAuthority(
            database,
            key_path,
            authority_ref="v4-scheme-draft-authority-test",
            clock=clock,
        )
    key_path.write_bytes(original_key)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE scheme_draft_events SET draft_json = ? WHERE sequence = 1",
            ('{"tampered":true}',),
        )
    with pytest.raises(SchemeDraftAuthorityError, match="integrity failed"):
        PersistentSchemeDraftAuthority(
            database,
            key_path,
            authority_ref="v4-scheme-draft-authority-test",
            clock=clock,
        )


def test_persistent_scheme_draft_requires_owner_only_paths(tmp_path: Path) -> None:
    state = tmp_path / "unsafe-state"
    state.mkdir(mode=0o755)
    os.chmod(state, 0o755)
    key_path = state / "draft.hmac"
    key_path.write_bytes(b"scheme-draft-authority-test-key-0000000000000001")
    os.chmod(key_path, 0o600)

    with pytest.raises(SchemeDraftAuthorityError, match="owner-only"):
        PersistentSchemeDraftAuthority(
            state / "draft.sqlite3",
            key_path,
            authority_ref="v4-scheme-draft-authority-test",
        )
