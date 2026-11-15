from __future__ import annotations

import os
from pathlib import Path
import sqlite3

import pytest

from test_v4_m3 import Issuer, NOW, _plan
from v4_planning import (
    ApprovalReceiptAuthenticator,
    ApproverAuthorityCheckpointError,
    ApproverAuthorityError,
    ApproverAuthorityStoreTail,
    AuthenticatedApprover,
    AuthenticatedRequester,
    M3ApprovalGate,
    M3PlanPolicy,
    MonotonicApproverAuthorityCheckpoint,
    PersistentApproverAuthorizationAuthority,
)


AUTHORITY_REF = "persistent-approver-authority-ref01"
IDENTITY_AUTHORITY_REF = "oauth-identity-authority-ref01"
SUBJECT_NAMESPACE = "workforce-subject-namespace-v1"
CHECKPOINT_STORE_REF = "approver-authority-store-test"


class _ExternalApproverCheckpoint:
    authority_ref = "approver-monotonic-checkpoint-test"

    def __init__(self, store_ref: str = CHECKPOINT_STORE_REF) -> None:
        self.tail = ApproverAuthorityStoreTail.empty(store_ref)
        self.fail_next_advance = False
        self.advance_then_fail = False

    def verify(self, tail: ApproverAuthorityStoreTail) -> None:
        if tail != self.tail:
            raise ApproverAuthorityCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: ApproverAuthorityStoreTail,
        current: ApproverAuthorityStoreTail,
    ) -> None:
        if self.fail_next_advance:
            self.fail_next_advance = False
            raise ApproverAuthorityCheckpointError("checkpoint unavailable")
        valid_event_advance = (
            current.sequence == previous.sequence + 1
            and current.last_seen_at >= previous.last_seen_at
        )
        valid_time_advance = (
            current.sequence == previous.sequence
            and current.chain_mac == previous.chain_mac
            and current.last_seen_at > previous.last_seen_at
        )
        if (
            previous != self.tail
            or current.store_ref != previous.store_ref
            or not (valid_event_advance or valid_time_advance)
        ):
            raise ApproverAuthorityCheckpointError(
                "checkpoint compare-and-swap failed"
            )
        self.tail = current
        if self.advance_then_fail:
            self.advance_then_fail = False
            raise ApproverAuthorityCheckpointError(
                "checkpoint completion is ambiguous"
            )


def _requester() -> AuthenticatedRequester:
    return AuthenticatedRequester(
        "operator-subject-0001",
        "operator",
        identity_authority_ref=IDENTITY_AUTHORITY_REF,
        subject_namespace=SUBJECT_NAMESPACE,
    )


def _approver(subject: str = "approver-subject-0001") -> AuthenticatedApprover:
    return AuthenticatedApprover(
        subject,
        identity_authority_ref=IDENTITY_AUTHORITY_REF,
        subject_namespace=SUBJECT_NAMESPACE,
    )


def _write_key(path: Path, value: bytes = b"d" * 32) -> None:
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _new_authority(
    root: Path,
    *,
    key_value: bytes = b"d" * 32,
    monotonic_checkpoint: MonotonicApproverAuthorityCheckpoint | None = None,
    checkpoint_store_ref: str | None = None,
) -> tuple[PersistentApproverAuthorizationAuthority, Path, Path]:
    os.chmod(root, 0o700)
    key = root / "approver-authority.hmac"
    database = root / "approver-authority.sqlite3"
    if not key.exists():
        _write_key(key, key_value)
    return (
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=monotonic_checkpoint,
            checkpoint_store_ref=checkpoint_store_ref,
            clock=lambda: NOW,
        ),
        database,
        key,
    )


def _chain():
    requester = _requester()
    approver = _approver()
    plan = _plan(requester)
    issuer = Issuer()
    decision = M3PlanPolicy(issuer).evaluate(
        plan,
        requester,
        now_epoch=NOW + 30,
    )
    return requester, approver, plan, issuer, decision


def _issue(
    authority: PersistentApproverAuthorizationAuthority,
    approver: AuthenticatedApprover,
    plan,
    *,
    environment_ref: str | None = None,
    scope_ref: str | None = None,
    action_bindings: tuple[tuple[str, str], ...] | None = None,
    policy_version: str = "1.0.0",
    expires_at: int = NOW + 120,
    now_epoch: int = NOW,
) -> str:
    return authority.issue(
        approver,
        environment_ref=environment_ref or plan.environment_ref,
        scope_ref=scope_ref or plan.scope_ref,
        action_bindings=action_bindings
        or tuple(
            (line.action_family_ref, line.action_family_version)
            for line in plan.lines
        ),
        policy_version=policy_version,
        expires_at=expires_at,
        now_epoch=now_epoch,
    )


def test_exact_persistent_delegation_drives_signed_receipt_without_raw_state(
    tmp_path: Path,
) -> None:
    authority, database, key = _new_authority(tmp_path)
    requester, approver, plan, issuer, decision = _chain()
    grant_ref = _issue(authority, approver, plan)

    restarted = PersistentApproverAuthorizationAuthority(
        database,
        key,
        authority_ref=AUTHORITY_REF,
        clock=lambda: NOW + 40,
    )
    authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
    receipt = M3ApprovalGate(
        issuer,
        receipt_authenticator=authenticator,
        approver_authorizer=restarted,
    ).approve(
        decision,
        approver,
        now_epoch=NOW + 40,
        plan=plan,
        requester=requester,
    )

    assert receipt.approver_authority_ref == AUTHORITY_REF
    assert receipt.approver_authorization_digest is not None
    assert receipt.approval_nonce_digest is not None
    assert receipt.policy_version == decision.policy_version
    assert authenticator.verify(receipt) is True
    assert receipt.execution_authorized is False
    assert restarted.uses_key_material(b"d" * 32) is True
    stored = database.read_bytes()
    for raw_value in (
        approver.subject_ref,
        IDENTITY_AUTHORITY_REF,
        SUBJECT_NAMESPACE,
        plan.environment_ref,
        plan.scope_ref,
        plan.lines[0].action_family_ref,
        grant_ref,
        plan.plan_ref,
    ):
        assert raw_value.encode("utf-8") not in stored


def test_external_checkpoint_rejects_event_and_time_watermark_rollback(
    tmp_path: Path,
) -> None:
    checkpoint = _ExternalApproverCheckpoint()
    authority, database, key = _new_authority(
        tmp_path,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    requester, approver, plan, _issuer, decision = _chain()
    empty_database = database.read_bytes()
    _issue(authority, approver, plan)
    event_database = database.read_bytes()
    assert checkpoint.tail.sequence == 1
    assert checkpoint.tail.last_seen_at == NOW

    authority.authorize(
        plan,
        decision,
        requester,
        approver,
        now_epoch=NOW + 40,
    )
    assert checkpoint.tail.sequence == 1
    assert checkpoint.tail.last_seen_at == NOW + 40

    database.write_bytes(event_database)
    with pytest.raises(ApproverAuthorityError, match="verification failed"):
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )

    database.write_bytes(empty_database)
    with pytest.raises(ApproverAuthorityError, match="verification failed"):
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )


def test_external_checkpoint_advance_loss_and_ambiguity_fail_closed(
    tmp_path: Path,
) -> None:
    requester, approver, plan, _issuer, _decision = _chain()
    del requester

    lost_root = tmp_path / "lost"
    lost_root.mkdir(mode=0o700)
    lost_checkpoint = _ExternalApproverCheckpoint()
    lost, database, key = _new_authority(
        lost_root,
        monotonic_checkpoint=lost_checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    lost_checkpoint.fail_next_advance = True
    with pytest.raises(ApproverAuthorityError, match="checkpoint advance failed"):
        _issue(lost, approver, plan)
    assert lost_checkpoint.tail.sequence == 0
    with pytest.raises(ApproverAuthorityError, match="verification failed"):
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=lost_checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )

    ambiguous_root = tmp_path / "ambiguous"
    ambiguous_root.mkdir(mode=0o700)
    ambiguous_checkpoint = _ExternalApproverCheckpoint()
    ambiguous, database, key = _new_authority(
        ambiguous_root,
        monotonic_checkpoint=ambiguous_checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    ambiguous_checkpoint.advance_then_fail = True
    with pytest.raises(ApproverAuthorityError, match="checkpoint advance failed"):
        _issue(ambiguous, approver, plan)
    assert ambiguous_checkpoint.tail.sequence == 1
    restarted = PersistentApproverAuthorizationAuthority(
        database,
        key,
        authority_ref=AUTHORITY_REF,
        monotonic_checkpoint=ambiguous_checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
        clock=lambda: NOW,
    )
    with pytest.raises(ApproverAuthorityError, match="already exists"):
        _issue(restarted, approver, plan)


def test_external_checkpoint_requires_complete_valid_binding(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    key = tmp_path / "approver-authority.hmac"
    _write_key(key)
    database = tmp_path / "approver-authority.sqlite3"
    checkpoint = _ExternalApproverCheckpoint()

    with pytest.raises(ApproverAuthorityError, match="incomplete"):
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
        )
    with pytest.raises(ApproverAuthorityError, match="incomplete"):
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )
    with pytest.raises(ApproverAuthorityError, match="invalid"):
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref="short",
        )

    checkpoint.authority_ref = AUTHORITY_REF
    with pytest.raises(ApproverAuthorityError, match="invalid"):
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )


@pytest.mark.parametrize(
    "wrong_binding",
    ("approver", "environment", "scope", "action", "policy"),
)
def test_authorization_requires_exact_active_delegation(
    tmp_path: Path,
    wrong_binding: str,
) -> None:
    authority, _database, _key = _new_authority(tmp_path)
    requester, approver, plan, _issuer, decision = _chain()
    grant_approver = approver
    kwargs: dict[str, object] = {}
    if wrong_binding == "approver":
        grant_approver = _approver("different-approver-subject")
    elif wrong_binding == "environment":
        kwargs["environment_ref"] = "different-environment-ref01"
    elif wrong_binding == "scope":
        kwargs["scope_ref"] = "different-scope-reference01"
    elif wrong_binding == "action":
        kwargs["action_bindings"] = (("different-action-family", "1.0.0"),)
    elif wrong_binding == "policy":
        kwargs["policy_version"] = "9.9.9"
    _issue(authority, grant_approver, plan, **kwargs)  # type: ignore[arg-type]

    with pytest.raises(ApproverAuthorityError, match="delegation is unavailable"):
        authority.authorize(
            plan,
            decision,
            requester,
            approver,
            now_epoch=NOW + 40,
        )


def test_revocation_expiry_duplicate_and_clock_rollback_fail_closed(
    tmp_path: Path,
) -> None:
    authority, database, key = _new_authority(tmp_path)
    requester, approver, plan, _issuer, decision = _chain()
    grant_ref = _issue(authority, approver, plan, expires_at=NOW + 50)
    with pytest.raises(ApproverAuthorityError, match="already exists"):
        _issue(authority, approver, plan, now_epoch=NOW + 1)
    authority.revoke(grant_ref, now_epoch=NOW + 2)

    restarted = PersistentApproverAuthorizationAuthority(
        database,
        key,
        authority_ref=AUTHORITY_REF,
        clock=lambda: NOW + 3,
    )
    with pytest.raises(ApproverAuthorityError, match="delegation is unavailable"):
        restarted.authorize(
            plan,
            decision,
            requester,
            approver,
            now_epoch=NOW + 40,
        )
    new_grant = _issue(
        restarted,
        approver,
        plan,
        expires_at=NOW + 100,
        now_epoch=NOW + 41,
    )
    assert new_grant != grant_ref
    assert restarted.authorize(
        plan,
        decision,
        requester,
        approver,
        now_epoch=NOW + 50,
    ).authorized is True
    with pytest.raises(ApproverAuthorityError, match="moved backwards"):
        restarted.authorize(
            plan,
            decision,
            requester,
            approver,
            now_epoch=NOW + 49,
        )
    with pytest.raises(ApproverAuthorityError, match="delegation is unavailable"):
        restarted.authorize(
            plan,
            decision,
            requester,
            approver,
            now_epoch=NOW + 100,
        )


def test_integrity_wrong_key_and_owner_only_boundaries_fail_closed(
    tmp_path: Path,
) -> None:
    authority, database, key = _new_authority(tmp_path)
    _requester_value, approver, plan, _issuer, _decision = _chain()
    _issue(authority, approver, plan)
    os.chmod(database, 0o644)
    with pytest.raises(ApproverAuthorityError, match="owner-only"):
        authority.verify_ready()
    os.chmod(database, 0o600)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE approver_delegation_events "
            "SET expires_at = expires_at + 1 WHERE sequence = 1"
        )
    with pytest.raises(ApproverAuthorityError, match="integrity"):
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
        )

    _write_key(key, b"w" * 32)
    with pytest.raises(ApproverAuthorityError, match="integrity"):
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
        )

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o750)
    unsafe_key = unsafe / "authority.hmac"
    _write_key(unsafe_key)
    with pytest.raises(ApproverAuthorityError, match="owner-only"):
        PersistentApproverAuthorizationAuthority(
            unsafe / "authority.sqlite3",
            unsafe_key,
            authority_ref=AUTHORITY_REF,
        )


def test_authority_requires_distinct_absolute_state_and_key_paths(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    shared = tmp_path / "shared-state"
    _write_key(shared)
    with pytest.raises(ApproverAuthorityError, match="paths are invalid"):
        PersistentApproverAuthorizationAuthority(
            shared,
            shared,
            authority_ref=AUTHORITY_REF,
        )
    with pytest.raises(ApproverAuthorityError, match="paths are invalid"):
        PersistentApproverAuthorizationAuthority(
            Path("relative-state.sqlite3"),
            shared,
            authority_ref=AUTHORITY_REF,
        )


def test_authority_identity_is_bound_into_persistent_integrity_root(
    tmp_path: Path,
) -> None:
    authority, database, key = _new_authority(tmp_path)
    _requester_value, approver, plan, _issuer, _decision = _chain()
    _issue(authority, approver, plan)

    with pytest.raises(ApproverAuthorityError, match="integrity"):
        PersistentApproverAuthorizationAuthority(
            database,
            key,
            authority_ref="different-approver-authority-ref",
        )
