"""Owner-only SQLite/HMAC persistence for the repository-only V4 M3.2 plan chain.

This module persists only already-validated C0-C2 planning records. It has no
MCP, network, credential, product-adapter, dispatch, or device-write surface.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Callable, Mapping, NoReturn, Protocol, cast

from .approval import ApprovalReceipt, ApprovalReceiptAuthenticationAuthority
from .canonical import CanonicalValue, canonical_digest, canonical_json
from .import_parent import FileImportParentRecord
from .models import (
    ChangeKind,
    ConfirmationRecord,
    FinalIntentSummary,
    MaterialReferenceMetadata,
    ObjectChange,
    ObjectClass,
    PlanLine,
    PlanState,
    PlanningContractError,
    PreparedPlan,
    SchemeId,
    SummaryState,
    require_digest,
    require_ref,
)
from .policy import PlanPolicyDecision
from .store import (
    ApprovalClaimRecord,
    InMemoryProtectedPlanningStore,
    OriginalImportBindingRecord,
    OriginalImportRowAckRecord,
    PlanInvalidationRecord,
    ProtectedStoreError,
)


_SCHEMA_VERSION = 1
_CHAIN_ROOT = "chain-root"
_RECORD_TYPES = frozenset(
    {
        "summary",
        "confirmation",
        "plan",
        "policy_decision",
        "approval_receipt",
        "approval_claim",
        "plan_invalidation",
        "original_import_binding",
        "original_import_row_ack",
        "file_import_parent",
    }
)


class PersistentPlanningStoreError(ProtectedStoreError):
    """Raised when protected planning persistence cannot fail closed."""


class MonotonicCheckpointError(RuntimeError):
    """Raised when an independently trusted checkpoint cannot verify or advance."""


@dataclass(frozen=True, slots=True)
class PlanningStoreTail:
    """Value-free append-chain position bound to one protected planning store."""

    store_ref: str
    sequence: int
    chain_hmac: str

    def __post_init__(self) -> None:
        require_ref(self.store_ref, "planning store_ref")
        if type(self.sequence) is not int or self.sequence < 0:
            raise PlanningContractError("Planning store sequence is invalid.")
        if self.sequence == 0:
            if self.chain_hmac != _CHAIN_ROOT:
                raise PlanningContractError("Empty planning store tail is invalid.")
            return
        require_digest(self.chain_hmac, "planning store chain_hmac")


class MonotonicPlanningCheckpoint(Protocol):
    """Compare-and-swap boundary owned outside the protected SQLite store."""

    authority_ref: str

    def verify(self, tail: PlanningStoreTail) -> None: ...

    def advance(
        self,
        previous: PlanningStoreTail,
        current: PlanningStoreTail,
    ) -> None: ...


PersistedApprovalClaim = ApprovalClaimRecord


@dataclass(slots=True)
class _VerifiedState:
    chain: InMemoryProtectedPlanningStore
    summaries: dict[tuple[str, int], FinalIntentSummary]
    confirmations: dict[str, ConfirmationRecord]
    plans: dict[str, PreparedPlan]
    decisions: dict[str, PlanPolicyDecision]
    receipts: dict[str, ApprovalReceipt]
    claims: dict[str, ApprovalClaimRecord]
    invalidations: dict[str, PlanInvalidationRecord]
    import_bindings: dict[str, OriginalImportBindingRecord]
    import_row_acks: dict[str, OriginalImportRowAckRecord]
    file_import_parents: dict[str, FileImportParentRecord]


class PersistentProtectedPlanningStore:
    """Append-only M3.2 planning store protected by an owner-only HMAC key."""

    def __init__(
        self,
        database_path: Path,
        hmac_key_path: Path,
        *,
        clock: Callable[[], int] | None = None,
        monotonic_checkpoint: MonotonicPlanningCheckpoint | None = None,
        checkpoint_store_ref: str | None = None,
        approval_receipt_authenticator: (
            ApprovalReceiptAuthenticationAuthority | None
        ) = None,
    ) -> None:
        self._path = Path(database_path)
        self._key_path = Path(hmac_key_path)
        self._clock = clock or (lambda: int(time.time()))
        self._approval_receipt_authenticator = approval_receipt_authenticator
        if (monotonic_checkpoint is None) is not (checkpoint_store_ref is None):
            raise PersistentPlanningStoreError(
                "External monotonic checkpoint binding is incomplete."
            )
        self._monotonic_checkpoint = monotonic_checkpoint
        self._checkpoint_store_ref = checkpoint_store_ref
        if monotonic_checkpoint is not None and checkpoint_store_ref is not None:
            try:
                require_ref(
                    monotonic_checkpoint.authority_ref,
                    "monotonic checkpoint authority_ref",
                )
                require_ref(checkpoint_store_ref, "monotonic checkpoint store_ref")
            except PlanningContractError as exc:
                raise PersistentPlanningStoreError(
                    "External monotonic checkpoint binding is invalid."
                ) from exc
        self._prepare_database_path()
        self._key = self._load_key()
        if (
            self._approval_receipt_authenticator is not None
            and self._approval_receipt_authenticator.uses_key_material(self._key)
        ):
            raise PersistentPlanningStoreError(
                "Planning store and approval receipt HMAC keys must be independent."
            )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                self._initialize_schema(connection)
                self._verify_integrity(connection)
                self._verify_monotonic_checkpoint(connection)
                connection.commit()
        except PersistentPlanningStoreError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise PersistentPlanningStoreError(
                "The protected planning store integrity check failed."
            ) from exc

    def uses_key_material(self, candidate: bytes) -> bool:
        """Return only whether trusted composition reused this exact key."""

        return type(candidate) is bytes and hmac.compare_digest(self._key, candidate)

    def put_summary(self, summary: FinalIntentSummary) -> None:
        self._write_record(
            "summary",
            summary.summary_ref,
            summary.revision,
            summary.as_dict(),
            summary.summary_digest,
            summary.created_at,
            summary.expires_at,
            validator=lambda state: state.chain.put_summary(summary),
            parent=lambda state: self._summary_parent(state, summary),
        )

    def put_confirmation(self, record: ConfirmationRecord) -> None:
        payload = dict(record.canonical_content())
        payload["record_digest"] = record.record_digest
        self._write_record(
            "confirmation",
            record.confirmation_ref,
            1,
            payload,
            record.record_digest,
            record.confirmed_at,
            record.expires_at,
            validator=lambda state: state.chain.put_confirmation(record),
            parent=lambda state: self._confirmation_parent(state, record),
        )

    def put_plan(self, plan: PreparedPlan) -> None:
        payload = dict(plan.canonical_content())
        payload.update({"plan_digest": plan.plan_digest, "state": plan.state.value})
        self._write_record(
            "plan",
            plan.plan_ref,
            plan.revision,
            payload,
            plan.plan_digest,
            plan.created_at,
            plan.expires_at,
            validator=lambda state: state.chain.put_plan(plan),
            parent=lambda state: self._plan_parent(state, plan),
        )

    def put_original_import_binding(self, record: OriginalImportBindingRecord) -> None:
        """Retain original private metadata in this checkpoint-bound parent chain."""
        if (type(record) is not OriginalImportBindingRecord
                or self._monotonic_checkpoint is None):
            raise PersistentPlanningStoreError("Original import checkpoint binding is required.")
        record.__post_init__()
        plan = self._active_import_parent(self._read_state(), record.plan_ref)
        now = self._clock()
        if type(now) is not int or not plan.created_at <= now < plan.expires_at:
            raise PersistentPlanningStoreError("Original import parent is not fresh.")
        payload = record.as_dict()
        self._write_record(
            "original_import_binding", record.plan_ref, 1, payload,
            canonical_digest(payload), plan.created_at, plan.expires_at,
            validator=lambda state: self._validate_original_import_binding(state, record),
            parent=lambda state: self._import_parent_link(state, record.plan_ref),
        )

    def get_original_import_binding(
        self, plan_ref: str, *, expected_plan_digest: str, requester_digest: str,
        namespace_key_digest: str,
    ) -> OriginalImportBindingRecord:
        """Resolve the retained original; execution still needs fresh authorization."""
        if self._monotonic_checkpoint is None:
            raise PersistentPlanningStoreError("Original import checkpoint binding is required.")
        state = self._read_state()
        plan = self._active_import_parent(state, plan_ref)
        record = state.import_bindings.get(plan_ref)
        if (record is None or expected_plan_digest != plan.plan_digest
                or requester_digest != plan.requester_digest
                or namespace_key_digest != record.namespace_key_digest):
            raise PersistentPlanningStoreError("Original import binding is unavailable.")
        return record

    def _validate_original_import_binding(
        self, state: _VerifiedState, record: OriginalImportBindingRecord,
    ) -> None:
        plan = PersistentProtectedPlanningStore._active_import_parent(state, record.plan_ref)
        if record.plan_digest != plan.plan_digest or record.requester_digest != plan.requester_digest:
            raise PersistentPlanningStoreError("Original import parent does not match.")
        if hmac.compare_digest(record.namespace_key_digest, hashlib.sha256(self._key).hexdigest()):
            raise PersistentPlanningStoreError("Original import and ledger keys must be independent.")
        if type(plan) is FileImportParentRecord and any(
                getattr(record, name) != getattr(plan, name) for name in record.__dataclass_fields__):
            raise PersistentPlanningStoreError("Original import intent does not match.")
        for retained_parent in state.file_import_parents.values():
            if retained_parent.namespace_key_digest != record.namespace_key_digest:
                raise PersistentPlanningStoreError("Original import namespace key cannot be replaced.")
            if retained_parent.plan_ref != record.plan_ref and retained_parent.source_commitment == record.source_commitment:
                raise PersistentPlanningStoreError("Original import source already has a parent.")
        for existing in state.import_bindings.values():
            if existing.namespace_key_digest != record.namespace_key_digest:
                raise PersistentPlanningStoreError("Original import namespace key cannot be replaced.")
            if (existing.plan_ref == record.plan_ref
                    or existing.source_commitment == record.source_commitment):
                raise PersistentPlanningStoreError("Original import source already has a parent.")

    def _put_original_import_row_ack(self, record: OriginalImportRowAckRecord) -> None:
        """Trusted original transport only; persist C2 evidence, not authority."""
        if (type(record) is not OriginalImportRowAckRecord
                or self._monotonic_checkpoint is None):
            raise PersistentPlanningStoreError("Original import checkpoint binding is required.")
        record.__post_init__()
        plan = self._active_import_parent(self._read_state(), record.plan_ref)
        now = self._clock()
        if type(now) is not int or not plan.created_at <= now < plan.expires_at:
            raise PersistentPlanningStoreError("Original import parent is not fresh.")
        payload = record.as_dict()
        self._write_record("original_import_row_ack", record.idempotency_digest, 1,
            payload, canonical_digest(payload), plan.created_at, plan.expires_at,
            validator=lambda state: self._validate_original_import_row_ack(state, record),
            parent=lambda state: ("original_import_binding", record.plan_ref, 1,
                                  canonical_digest(state.import_bindings[record.plan_ref].as_dict())))

    def _get_original_import_row_ack(self, plan_ref: str, *, idempotency_digest: str,
                                     requester_digest: str, parent_binding_digest: str,
                                     parameters_digest: str) -> OriginalImportRowAckRecord:
        """Historical evidence may survive expiry/invalidation; grants no adoption."""
        if self._monotonic_checkpoint is None:
            raise PersistentPlanningStoreError("Original import checkpoint binding is required.")
        state = self._read_state()
        record = state.import_row_acks.get(idempotency_digest)
        if (record is None or record.plan_ref != plan_ref
                or record.requester_digest != requester_digest
                or record.parent_binding_digest != parent_binding_digest
                or record.parameters_digest != parameters_digest):
            raise PersistentPlanningStoreError("Original import ACK evidence is unavailable.")
        return record

    @staticmethod
    def _validate_original_import_row_ack(state: _VerifiedState,
                                         record: OriginalImportRowAckRecord) -> None:
        binding = state.import_bindings.get(record.plan_ref)
        if (binding is None or record.plan_ref in state.invalidations
                or record.requester_digest != binding.requester_digest
                or record.parent_binding_digest != canonical_digest(binding.as_dict())
                or record.row_index >= binding.row_count
                or record.context_digest != canonical_digest({
                    "authorization_digest": record.authorization_digest,
                    "plan_digest": record.child_plan_digest, "revision": record.child_revision})
                or any((existing.plan_ref == record.plan_ref and existing.row_index == record.row_index)
                       or (existing.serial_digest == record.serial_digest
                           and existing.native_secret_id == record.native_secret_id)
                       for existing in state.import_row_acks.values())):
            raise PersistentPlanningStoreError("Original import ACK evidence does not match.")

    def put_policy_decision(self, decision: PlanPolicyDecision) -> None:
        payload = dict(decision.canonical_content())
        payload["decision_digest"] = decision.decision_digest

        def validate(state: _VerifiedState) -> None:
            self._active_plan(state, decision.plan_ref)
            self._validate_decision(decision, state.plans)
            if any(item.plan_ref == decision.plan_ref for item in state.decisions.values()):
                raise PersistentPlanningStoreError(
                    "Prepared plan already produced a policy decision."
                )

        self._write_record(
            "policy_decision",
            decision.decision_ref,
            1,
            payload,
            decision.decision_digest,
            decision.issued_at,
            decision.expires_at,
            validator=validate,
            parent=lambda state: self._decision_parent(state, decision),
        )

    def put_approval_receipt(self, receipt: ApprovalReceipt) -> None:
        payload = dict(receipt.canonical_content())
        payload["receipt_digest"] = receipt.receipt_digest
        if receipt.receipt_mac is not None:
            payload["receipt_mac"] = receipt.receipt_mac

        def validate(state: _VerifiedState) -> None:
            self._active_plan(state, receipt.plan_ref)
            self._validate_receipt(receipt, state.decisions)
            if any(
                item.decision_ref == receipt.decision_ref
                for item in state.receipts.values()
            ):
                raise PersistentPlanningStoreError(
                    "Policy decision already produced an approval receipt."
                )

        self._write_record(
            "approval_receipt",
            receipt.receipt_ref,
            1,
            payload,
            receipt.receipt_digest,
            receipt.issued_at,
            receipt.expires_at,
            validator=validate,
            parent=lambda state: self._receipt_parent(state, receipt),
        )

    def claim_approval(
        self,
        receipt_ref: str,
        plan_ref: str,
        requester_digest: str,
    ) -> ApprovalClaimRecord:
        """Atomically consume one exact active receipt without authorizing dispatch."""

        now_epoch = self._clock()
        if type(now_epoch) is not int:
            raise PersistentPlanningStoreError("Trusted approval-claim clock is invalid.")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._verify_integrity(connection)
                previous_tail = self._verify_monotonic_checkpoint(connection)
                receipt = state.receipts.get(receipt_ref)
                plan = self._active_plan(state, plan_ref)
                if receipt is None or plan is None:
                    raise PersistentPlanningStoreError(
                        "Approval receipt or prepared plan is unavailable."
                    )
                if receipt_ref in state.claims:
                    raise PersistentPlanningStoreError("Approval receipt was replayed.")
                if (
                    now_epoch < receipt.issued_at
                    or now_epoch >= receipt.expires_at
                    or now_epoch < plan.created_at
                    or now_epoch >= plan.expires_at
                ):
                    raise PersistentPlanningStoreError(
                        "Approval receipt or prepared plan is outside its active lifetime."
                    )
                if (
                    receipt.plan_ref != plan.plan_ref
                    or receipt.plan_digest != plan.plan_digest
                    or receipt.requester_digest != requester_digest
                    or plan.requester_digest != requester_digest
                ):
                    raise PersistentPlanningStoreError(
                        "Approval receipt is not bound to the exact prepared plan."
                    )
                claim = ApprovalClaimRecord(
                    receipt_ref=receipt.receipt_ref,
                    receipt_digest=receipt.receipt_digest,
                    plan_ref=plan.plan_ref,
                    plan_digest=plan.plan_digest,
                    requester_digest=requester_digest,
                    claimed_at=now_epoch,
                )
                self._append_record(
                    connection,
                    record_type="approval_claim",
                    record_ref=receipt.receipt_ref,
                    revision=1,
                    parent=("approval_receipt", receipt.receipt_ref, 1, receipt.receipt_digest),
                    payload=claim.as_dict(),
                    object_digest=canonical_digest(claim.as_dict()),
                    issued_at=now_epoch,
                    expires_at=receipt.expires_at,
                )
                current_tail = (
                    self._checkpoint_tail(connection)
                    if previous_tail is not None
                    else None
                )
                connection.commit()
                self._advance_monotonic_checkpoint(previous_tail, current_tail)
                return claim
        except PersistentPlanningStoreError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise PersistentPlanningStoreError(
                "Approval receipt claim could not be persisted."
            ) from exc

    def get_summary(self, summary_ref: str, revision: int) -> FinalIntentSummary:
        record = self._read_state().summaries.get((summary_ref, revision))
        if record is None:
            self._missing("Summary revision")
        return record

    def get_confirmation(self, confirmation_ref: str) -> ConfirmationRecord:
        record = self._read_state().confirmations.get(confirmation_ref)
        if record is None:
            self._missing("Confirmation record")
        return record

    def find_confirmation_for_summary(
        self,
        summary_ref: str,
        revision: int,
    ) -> ConfirmationRecord | None:
        records = [
            record
            for record in self._read_state().confirmations.values()
            if record.summary_ref == summary_ref and record.summary_revision == revision
        ]
        if len(records) > 1:
            raise PersistentPlanningStoreError("Summary revision has multiple confirmations.")
        return records[0] if records else None

    def get_plan(self, plan_ref: str) -> PreparedPlan:
        return self._active_plan(self._read_state(), plan_ref)

    def get_import_parent(self, plan_ref: str) -> PreparedPlan | FileImportParentRecord:
        """Private import composition only; does not expose a new M2 profile."""
        if self._monotonic_checkpoint is None:
            raise PersistentPlanningStoreError("Original import checkpoint binding is required.")
        return self._active_import_parent(self._read_state(), plan_ref)

    def put_file_import_parent(self, record: FileImportParentRecord) -> None:
        if type(record) is not FileImportParentRecord or self._monotonic_checkpoint is None:
            raise PersistentPlanningStoreError("Private import parent checkpoint is required.")
        record.__post_init__()
        now = self._clock()
        if type(now) is not int or not record.created_at <= now < record.expires_at:
            raise PersistentPlanningStoreError("Private import parent is not fresh.")
        self._write_record('file_import_parent', record.plan_ref, 1, record.as_dict(),
            record.plan_digest, record.created_at, record.expires_at,
            validator=lambda state: self._validate_file_import_parent(state, record),
            parent=lambda state: (_CHAIN_ROOT, _CHAIN_ROOT, 0, _CHAIN_ROOT))

    def _validate_file_import_parent(self, state: _VerifiedState, record: FileImportParentRecord) -> None:
        if (record.plan_ref in state.plans or record.plan_ref in state.file_import_parents
                or record.plan_ref in state.invalidations
                or hmac.compare_digest(record.namespace_key_digest, hashlib.sha256(self._key).hexdigest())):
            raise PersistentPlanningStoreError("Private import parent identity is unavailable.")
        priors: tuple[FileImportParentRecord | OriginalImportBindingRecord, ...] = (
            *state.file_import_parents.values(), *state.import_bindings.values())
        for prior in priors:
            if prior.namespace_key_digest != record.namespace_key_digest:
                raise PersistentPlanningStoreError("Original import namespace key cannot be replaced.")
            if prior.source_commitment == record.source_commitment:
                raise PersistentPlanningStoreError("Original import source already has a parent.")

    @staticmethod
    def _active_import_parent(state: _VerifiedState, plan_ref: str) -> PreparedPlan | FileImportParentRecord:
        if plan_ref in state.invalidations:
            raise PersistentPlanningStoreError("Prepared plan was invalidated.")
        parent = state.file_import_parents.get(plan_ref)
        return parent if parent is not None else PersistentProtectedPlanningStore._active_plan(state, plan_ref)

    @staticmethod
    def _import_parent_link(state: _VerifiedState, plan_ref: str) -> tuple[str, str, int, str]:
        parent = PersistentProtectedPlanningStore._active_import_parent(state, plan_ref)
        return ('file_import_parent' if type(parent) is FileImportParentRecord else 'plan',
                plan_ref, parent.revision, parent.plan_digest)

    def find_plan_for_confirmation(self, confirmation_ref: str) -> PreparedPlan | None:
        state = self._read_state()
        records = [
            plan
            for plan in state.plans.values()
            if plan.confirmation_ref == confirmation_ref
        ]
        if len(records) > 1:
            raise PersistentPlanningStoreError("Confirmation has multiple prepared plans.")
        return self._active_plan(state, records[0].plan_ref) if records else None

    def get_policy_decision(self, decision_ref: str) -> PlanPolicyDecision:
        state = self._read_state()
        record = state.decisions.get(decision_ref)
        if record is None:
            self._missing("Policy decision")
        self._active_plan(state, record.plan_ref)
        return record

    def get_approval_receipt(self, receipt_ref: str) -> ApprovalReceipt:
        state = self._read_state()
        record = state.receipts.get(receipt_ref)
        if record is None:
            self._missing("Approval receipt")
        self._active_plan(state, record.plan_ref)
        return record

    def get_approval_claim(self, receipt_ref: str) -> ApprovalClaimRecord:
        state = self._read_state()
        record = state.claims.get(receipt_ref)
        if record is None:
            self._missing("Approval claim")
        self._active_plan(state, record.plan_ref)
        return record

    @staticmethod
    def _active_plan(state: _VerifiedState, plan_ref: str) -> PreparedPlan:
        if plan_ref in state.invalidations:
            raise PersistentPlanningStoreError("Prepared plan was invalidated.")
        plan = state.plans.get(plan_ref)
        if plan is None:
            raise PersistentPlanningStoreError("Prepared plan is unavailable.")
        return plan

    def invalidate_plan(self, plan_ref: str, *, evaluated_at: int,
                        reason_codes: tuple[str, ...]) -> None:
        # Read the immutable parent without granting access to an invalidated
        # plan; this also permits an exact retry of the same refusal record.
        try:
            require_ref(plan_ref, "Invalidated plan reference")
        except Exception:
            raise PersistentPlanningStoreError("Plan invalidation reference is invalid.") from None
        state = self._read_state()
        plan = state.file_import_parents.get(plan_ref) or state.plans.get(plan_ref)
        if plan is None:
            self._missing("Prepared plan")
        record = PlanInvalidationRecord(plan_ref, plan.plan_digest, evaluated_at, reason_codes)
        payload = record.as_dict()
        self._write_record(
            "plan_invalidation", plan_ref, 1, payload, canonical_digest(payload),
            evaluated_at, max(plan.expires_at, evaluated_at + 1),
            validator=lambda state: self._validate_import_invalidation(state, record),
            parent=lambda state: self._import_parent_link(state, plan_ref),
        )

    @staticmethod
    def _validate_import_invalidation(state: _VerifiedState, record: PlanInvalidationRecord) -> None:
        if record.plan_ref not in state.file_import_parents:
            state.chain.invalidate_plan(record.plan_ref, evaluated_at=record.evaluated_at,
                                        reason_codes=record.reason_codes)
        elif record.evaluated_at < state.file_import_parents[record.plan_ref].created_at:
            raise PersistentPlanningStoreError("Plan invalidation predates its parent plan.")

    def _write_record(
        self,
        record_type: str,
        record_ref: str,
        revision: int,
        payload: Mapping[str, object],
        object_digest: str,
        issued_at: int,
        expires_at: int,
        *,
        validator: Callable[[_VerifiedState], None],
        parent: Callable[[_VerifiedState], tuple[str, str, int, str]],
    ) -> None:
        payload_json = canonical_json(payload)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._verify_integrity(connection)
                previous_tail = self._verify_monotonic_checkpoint(connection)
                if record_type in {"plan", "file_import_parent", "policy_decision", "approval_receipt", "original_import_binding",
                                   "original_import_row_ack"}:
                    bound_plan_ref = payload.get("plan_ref")
                    if bound_plan_ref in state.invalidations:
                        raise PersistentPlanningStoreError("Prepared plan was invalidated.")
                if record_type == 'plan' and record_ref in state.file_import_parents:
                    raise PersistentPlanningStoreError("Private import parent cannot be replaced.")
                existing = connection.execute(
                    """
                    SELECT * FROM planning_records
                    WHERE record_type = ? AND record_ref = ? AND revision = ?
                    """,
                    (record_type, record_ref, revision),
                ).fetchone()
                if existing is not None:
                    if (
                        str(existing["payload_json"]) == payload_json
                        and str(existing["object_digest"]) == object_digest
                    ):
                        connection.rollback()
                        return
                    raise PersistentPlanningStoreError("Planning record is immutable.")
                try:
                    validator(state)
                except ProtectedStoreError as exc:
                    raise PersistentPlanningStoreError(str(exc)) from exc
                self._append_record(
                    connection,
                    record_type=record_type,
                    record_ref=record_ref,
                    revision=revision,
                    parent=parent(state),
                    payload=payload,
                    object_digest=object_digest,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                current_tail = (
                    self._checkpoint_tail(connection)
                    if previous_tail is not None
                    else None
                )
                connection.commit()
                self._advance_monotonic_checkpoint(previous_tail, current_tail)
        except PersistentPlanningStoreError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise PersistentPlanningStoreError(
                "The protected planning record could not be persisted."
            ) from exc

    def _read_state(self) -> _VerifiedState:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                state = self._verify_integrity(connection)
                self._verify_monotonic_checkpoint(connection)
                connection.commit()
                return state
        except PersistentPlanningStoreError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise PersistentPlanningStoreError(
                "The protected planning record could not be read."
            ) from exc

    @staticmethod
    def _missing(label: str) -> NoReturn:
        raise PersistentPlanningStoreError(f"{label} is unavailable.")

    @staticmethod
    def _summary_parent(
        state: _VerifiedState,
        summary: FinalIntentSummary,
    ) -> tuple[str, str, int, str]:
        if summary.revision == 1:
            return (_CHAIN_ROOT, _CHAIN_ROOT, 0, _CHAIN_ROOT)
        prior = state.summaries[(summary.summary_ref, summary.revision - 1)]
        return ("summary", prior.summary_ref, prior.revision, prior.summary_digest)

    @staticmethod
    def _confirmation_parent(
        state: _VerifiedState,
        record: ConfirmationRecord,
    ) -> tuple[str, str, int, str]:
        summary = state.summaries[(record.summary_ref, record.summary_revision)]
        if any(
            item.summary_ref == record.summary_ref
            and item.summary_revision == record.summary_revision
            for item in state.confirmations.values()
        ):
            raise PersistentPlanningStoreError(
                "Summary revision already produced a confirmation."
            )
        return ("summary", summary.summary_ref, summary.revision, summary.summary_digest)

    @staticmethod
    def _plan_parent(
        state: _VerifiedState,
        plan: PreparedPlan,
    ) -> tuple[str, str, int, str]:
        confirmation = state.confirmations[plan.confirmation_ref]
        if any(item.confirmation_ref == plan.confirmation_ref for item in state.plans.values()):
            raise PersistentPlanningStoreError(
                "Confirmation already produced a prepared plan."
            )
        return (
            "confirmation",
            confirmation.confirmation_ref,
            1,
            confirmation.record_digest,
        )

    @staticmethod
    def _decision_parent(
        state: _VerifiedState,
        decision: PlanPolicyDecision,
    ) -> tuple[str, str, int, str]:
        plan = state.plans[decision.plan_ref]
        return ("plan", plan.plan_ref, plan.revision, plan.plan_digest)

    @staticmethod
    def _receipt_parent(
        state: _VerifiedState,
        receipt: ApprovalReceipt,
    ) -> tuple[str, str, int, str]:
        decision = state.decisions[receipt.decision_ref]
        return (
            "policy_decision",
            decision.decision_ref,
            1,
            decision.decision_digest,
        )

    @staticmethod
    def _validate_decision(
        decision: PlanPolicyDecision,
        plans: Mapping[str, PreparedPlan],
    ) -> None:
        plan = plans.get(decision.plan_ref)
        if plan is None or (
            decision.plan_digest != plan.plan_digest
            or decision.requester_digest != plan.requester_digest
            or decision.issued_at < plan.created_at
            or decision.expires_at > plan.expires_at
        ):
            raise PersistentPlanningStoreError(
                "Policy decision is not bound to the stored prepared plan."
            )

    def _validate_receipt(
        self,
        receipt: ApprovalReceipt,
        decisions: Mapping[str, PlanPolicyDecision],
    ) -> None:
        authenticator = self._approval_receipt_authenticator
        if authenticator is None:
            if receipt.authenticator_ref is not None:
                raise PersistentPlanningStoreError(
                    "Approval receipt authenticator is unavailable."
                )
        elif not authenticator.verify(receipt):
            raise PersistentPlanningStoreError(
                "Approval receipt authenticity is invalid."
            )
        decision = decisions.get(receipt.decision_ref)
        if decision is None or (
            receipt.decision_digest != decision.decision_digest
            or receipt.plan_ref != decision.plan_ref
            or receipt.plan_digest != decision.plan_digest
            or receipt.requester_digest != decision.requester_digest
            or (
                receipt.policy_version is not None
                and receipt.policy_version != decision.policy_version
            )
            or receipt.issued_at < decision.issued_at
            or receipt.expires_at > decision.expires_at
        ):
            raise PersistentPlanningStoreError(
                "Approval receipt is not bound to the stored policy decision."
            )

    def _append_record(
        self,
        connection: sqlite3.Connection,
        *,
        record_type: str,
        record_ref: str,
        revision: int,
        parent: tuple[str, str, int, str],
        payload: Mapping[str, object],
        object_digest: str,
        issued_at: int,
        expires_at: int,
    ) -> None:
        if record_type not in _RECORD_TYPES or expires_at <= issued_at:
            raise PersistentPlanningStoreError("Planning record envelope is invalid.")
        anchor = connection.execute(
            "SELECT last_sequence, last_hmac FROM integrity_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise PersistentPlanningStoreError("Planning integrity anchor is unavailable.")
        sequence = int(anchor["last_sequence"]) + 1
        previous_hmac = str(anchor["last_hmac"])
        parent_type, parent_ref, parent_revision, parent_digest = parent
        payload_json = canonical_json(payload)
        fields: dict[str, CanonicalValue] = {
            "expires_at": expires_at,
            "issued_at": issued_at,
            "object_digest": object_digest,
            "parent_digest": parent_digest,
            "parent_ref": parent_ref,
            "parent_revision": parent_revision,
            "parent_type": parent_type,
            "payload_json": payload_json,
            "previous_hmac": previous_hmac,
            "record_ref": record_ref,
            "record_type": record_type,
            "revision": revision,
            "sequence": sequence,
        }
        chain_hmac = self._hmac("record", fields)
        connection.execute(
            """
            INSERT INTO planning_records(
                sequence, record_type, record_ref, revision, parent_type,
                parent_ref, parent_revision, parent_digest, payload_json,
                object_digest, issued_at, expires_at, previous_hmac, chain_hmac
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                record_type,
                record_ref,
                revision,
                parent_type,
                parent_ref,
                parent_revision,
                parent_digest,
                payload_json,
                object_digest,
                issued_at,
                expires_at,
                previous_hmac,
                chain_hmac,
            ),
        )
        anchor_hmac = self._anchor_hmac(sequence, chain_hmac)
        connection.execute(
            """
            UPDATE integrity_anchor
            SET last_sequence = ?, last_hmac = ?, anchor_hmac = ?
            WHERE singleton = 1
            """,
            (sequence, chain_hmac, anchor_hmac),
        )

    def _verify_monotonic_checkpoint(
        self,
        connection: sqlite3.Connection,
    ) -> PlanningStoreTail | None:
        if self._monotonic_checkpoint is None:
            return None
        tail = self._checkpoint_tail(connection)
        try:
            self._monotonic_checkpoint.verify(tail)
        except MonotonicCheckpointError as exc:
            raise PersistentPlanningStoreError(
                "External monotonic checkpoint verification failed."
            ) from exc
        return tail

    def _advance_monotonic_checkpoint(
        self,
        previous: PlanningStoreTail | None,
        current: PlanningStoreTail | None,
    ) -> None:
        if self._monotonic_checkpoint is None:
            return
        if previous is None or current is None:
            raise PersistentPlanningStoreError(
                "External monotonic checkpoint state is unavailable."
            )
        try:
            self._monotonic_checkpoint.advance(previous, current)
        except MonotonicCheckpointError as exc:
            raise PersistentPlanningStoreError(
                "External monotonic checkpoint advance failed."
            ) from exc

    def _checkpoint_tail(self, connection: sqlite3.Connection) -> PlanningStoreTail:
        if self._checkpoint_store_ref is None:
            raise PersistentPlanningStoreError(
                "External monotonic checkpoint store binding is unavailable."
            )
        anchor = connection.execute(
            "SELECT last_sequence, last_hmac FROM integrity_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise PersistentPlanningStoreError(
                "Planning integrity anchor is unavailable."
            )
        try:
            return PlanningStoreTail(
                self._checkpoint_store_ref,
                int(anchor["last_sequence"]),
                str(anchor["last_hmac"]),
            )
        except PlanningContractError as exc:
            raise PersistentPlanningStoreError(
                "External monotonic checkpoint state is invalid."
            ) from exc

    def _verify_integrity(self, connection: sqlite3.Connection) -> _VerifiedState:
        anchor = connection.execute("SELECT * FROM integrity_anchor WHERE singleton = 1").fetchone()
        if anchor is None:
            raise PersistentPlanningStoreError("Planning integrity anchor is unavailable.")
        last_sequence = int(anchor["last_sequence"])
        last_hmac = str(anchor["last_hmac"])
        if not hmac.compare_digest(
            str(anchor["anchor_hmac"]),
            self._anchor_hmac(last_sequence, last_hmac),
        ):
            raise PersistentPlanningStoreError("Planning integrity anchor is invalid.")

        state = _VerifiedState(
            chain=InMemoryProtectedPlanningStore(
                approval_receipt_authenticator=(
                    self._approval_receipt_authenticator
                ),
            ),
            summaries={},
            confirmations={},
            plans={},
            decisions={},
            receipts={},
            claims={},
            invalidations={},
            import_bindings={},
            import_row_acks={},
            file_import_parents={},
        )
        previous_hmac = _CHAIN_ROOT
        expected_sequence = 1
        rows = connection.execute(
            "SELECT * FROM planning_records ORDER BY sequence"
        ).fetchall()
        for row in rows:
            if int(row["sequence"]) != expected_sequence:
                raise PersistentPlanningStoreError("Planning record sequence is invalid.")
            fields = self._row_hmac_fields(row)
            actual_hmac = str(row["chain_hmac"])
            if (
                str(row["previous_hmac"]) != previous_hmac
                or not hmac.compare_digest(actual_hmac, self._hmac("record", fields))
            ):
                raise PersistentPlanningStoreError("Planning record HMAC chain is invalid.")
            self._decode_and_validate_row(row, state)
            previous_hmac = actual_hmac
            expected_sequence += 1
        if last_sequence != len(rows) or last_hmac != previous_hmac:
            raise PersistentPlanningStoreError("Planning record tail was altered.")
        return state

    def _decode_and_validate_row(
        self,
        row: sqlite3.Row,
        state: _VerifiedState,
    ) -> None:
        record_type = str(row["record_type"])
        if record_type not in _RECORD_TYPES:
            raise PersistentPlanningStoreError("Planning record type is invalid.")
        payload = _payload(str(row["payload_json"]))
        if canonical_json(payload) != str(row["payload_json"]):
            raise PersistentPlanningStoreError("Planning record payload is not canonical.")

        if record_type == "summary":
            summary_record = _summary_from_payload(payload)
            parent = (
                (_CHAIN_ROOT, _CHAIN_ROOT, 0, _CHAIN_ROOT)
                if summary_record.revision == 1
                else (
                    "summary",
                    summary_record.summary_ref,
                    summary_record.revision - 1,
                    state.summaries[
                        (summary_record.summary_ref, summary_record.revision - 1)
                    ].summary_digest,
                )
            )
            self._validate_row(row, summary_record.summary_ref, summary_record.revision, summary_record.summary_digest, summary_record.created_at, summary_record.expires_at, parent)
            state.chain.put_summary(summary_record)
            state.summaries[(summary_record.summary_ref, summary_record.revision)] = summary_record
            return
        if record_type == "confirmation":
            confirmation_record = _confirmation_from_payload(payload)
            summary = state.summaries[(confirmation_record.summary_ref, confirmation_record.summary_revision)]
            parent = ("summary", summary.summary_ref, summary.revision, summary.summary_digest)
            self._validate_row(row, confirmation_record.confirmation_ref, 1, confirmation_record.record_digest, confirmation_record.confirmed_at, confirmation_record.expires_at, parent)
            state.chain.put_confirmation(confirmation_record)
            state.confirmations[confirmation_record.confirmation_ref] = confirmation_record
            return
        if record_type == 'file_import_parent':
            file_parent = FileImportParentRecord.from_payload(payload)
            self._validate_file_import_parent(state, file_parent)
            self._validate_row(row, file_parent.plan_ref, 1, file_parent.plan_digest,
                file_parent.created_at, file_parent.expires_at, (_CHAIN_ROOT, _CHAIN_ROOT, 0, _CHAIN_ROOT))
            state.file_import_parents[file_parent.plan_ref] = file_parent
            return
        if record_type == "plan":
            plan_record = _plan_from_payload(payload)
            if plan_record.plan_ref in state.file_import_parents:
                raise PersistentPlanningStoreError("Private import parent cannot be replaced.")
            confirmation = state.confirmations[plan_record.confirmation_ref]
            parent = ("confirmation", confirmation.confirmation_ref, 1, confirmation.record_digest)
            self._validate_row(row, plan_record.plan_ref, plan_record.revision, plan_record.plan_digest, plan_record.created_at, plan_record.expires_at, parent)
            state.chain.put_plan(plan_record)
            state.plans[plan_record.plan_ref] = plan_record
            return
        if record_type == "original_import_binding":
            fields = {"plan_ref", "plan_digest", "requester_digest", "parent_idempotency_digest",
                      "input_commitment", "source_commitment", "dependency_commitment",
                      "namespace_key_digest", "row_count"}
            if set(payload) != fields:
                raise PersistentPlanningStoreError("Original import payload is invalid.")
            try:
                binding = OriginalImportBindingRecord(
                    _string(payload, "plan_ref"), _string(payload, "plan_digest"),
                    _string(payload, "requester_digest"), _string(payload, "parent_idempotency_digest"),
                    _string(payload, "input_commitment"), _string(payload, "source_commitment"),
                    _string(payload, "dependency_commitment"), _string(payload, "namespace_key_digest"),
                    _integer(payload, "row_count"),
                )
            except ProtectedStoreError:
                raise PersistentPlanningStoreError("Original import payload is invalid.") from None
            self._validate_original_import_binding(state, binding)
            plan = self._active_import_parent(state, binding.plan_ref)
            self._validate_row(row, binding.plan_ref, 1, canonical_digest(binding.as_dict()),
                plan.created_at, plan.expires_at, self._import_parent_link(state, plan.plan_ref))
            state.import_bindings[binding.plan_ref] = binding
            return
        if record_type == "original_import_row_ack":
            strings = {"plan_ref", "parent_binding_digest", "requester_digest", "idempotency_digest",
                       "parameters_digest", "child_plan_digest", "authorization_digest", "context_digest",
                       "serial_digest", "defaults_digest", "ack_source_digest", "acknowledgement_digest"}
            integers = {"row_index", "child_revision", "native_secret_id"}
            if set(payload) != strings | integers:
                raise PersistentPlanningStoreError("Original import ACK payload is invalid.")
            try:
                ack = OriginalImportRowAckRecord(
                    plan_ref=_string(payload, "plan_ref"),
                    parent_binding_digest=_string(payload, "parent_binding_digest"),
                    requester_digest=_string(payload, "requester_digest"), row_index=_integer(payload, "row_index"),
                    idempotency_digest=_string(payload, "idempotency_digest"),
                    parameters_digest=_string(payload, "parameters_digest"),
                    child_plan_digest=_string(payload, "child_plan_digest"), child_revision=_integer(payload, "child_revision"),
                    authorization_digest=_string(payload, "authorization_digest"), context_digest=_string(payload, "context_digest"),
                    serial_digest=_string(payload, "serial_digest"), defaults_digest=_string(payload, "defaults_digest"),
                    ack_source_digest=_string(payload, "ack_source_digest"),
                    acknowledgement_digest=_string(payload, "acknowledgement_digest"), native_secret_id=_integer(payload, "native_secret_id"))
            except ProtectedStoreError:
                raise PersistentPlanningStoreError("Original import ACK payload is invalid.") from None
            self._validate_original_import_row_ack(state, ack)
            plan = self._active_import_parent(state, ack.plan_ref)
            self._validate_row(row, ack.idempotency_digest, 1, canonical_digest(ack.as_dict()),
                plan.created_at, plan.expires_at, ("original_import_binding", ack.plan_ref, 1,
                    ack.parent_binding_digest))
            state.import_row_acks[ack.idempotency_digest] = ack
            return
        if record_type == "plan_invalidation":
            if set(payload) != {"plan_ref", "plan_digest", "evaluated_at", "reason_codes"}:
                raise PersistentPlanningStoreError("Plan invalidation payload is invalid.")
            invalidation = PlanInvalidationRecord(
                _string(payload, "plan_ref"), _string(payload, "plan_digest"),
                _integer(payload, "evaluated_at"), _strings(payload, "reason_codes"),
            )
            plan = self._active_import_parent(state, invalidation.plan_ref)
            if invalidation.plan_digest != plan.plan_digest or invalidation.plan_ref in state.invalidations:
                raise PersistentPlanningStoreError("Plan invalidation parent is invalid.")
            parent = self._import_parent_link(state, plan.plan_ref)
            self._validate_row(row, plan.plan_ref, 1, canonical_digest(invalidation.as_dict()),
                invalidation.evaluated_at, max(plan.expires_at, invalidation.evaluated_at + 1), parent)
            self._validate_import_invalidation(state, invalidation)
            state.invalidations[plan.plan_ref] = invalidation
            return
        if record_type == "policy_decision":
            self._active_plan(state, _string(payload, "plan_ref"))
            decision_record = _decision_from_payload(payload)
            self._validate_decision(decision_record, state.plans)
            plan = state.plans[decision_record.plan_ref]
            parent = ("plan", plan.plan_ref, plan.revision, plan.plan_digest)
            self._validate_row(row, decision_record.decision_ref, 1, decision_record.decision_digest, decision_record.issued_at, decision_record.expires_at, parent)
            if any(item.plan_ref == decision_record.plan_ref for item in state.decisions.values()):
                raise PersistentPlanningStoreError("Policy decision replay was persisted.")
            state.decisions[decision_record.decision_ref] = decision_record
            return
        if record_type == "approval_receipt":
            self._active_plan(state, _string(payload, "plan_ref"))
            receipt_record = _receipt_from_payload(payload)
            self._validate_receipt(receipt_record, state.decisions)
            decision = state.decisions[receipt_record.decision_ref]
            parent = ("policy_decision", decision.decision_ref, 1, decision.decision_digest)
            self._validate_row(row, receipt_record.receipt_ref, 1, receipt_record.receipt_digest, receipt_record.issued_at, receipt_record.expires_at, parent)
            if any(item.decision_ref == receipt_record.decision_ref for item in state.receipts.values()):
                raise PersistentPlanningStoreError("Approval receipt replay was persisted.")
            state.receipts[receipt_record.receipt_ref] = receipt_record
            return

        claim = _claim_from_payload(payload)
        self._active_plan(state, claim.plan_ref)
        receipt = state.receipts[claim.receipt_ref]
        plan = state.plans[claim.plan_ref]
        if (
            claim.receipt_digest != receipt.receipt_digest
            or claim.plan_digest != plan.plan_digest
            or claim.requester_digest != receipt.requester_digest
            or claim.claimed_at < receipt.issued_at
            or claim.claimed_at >= receipt.expires_at
            or claim.claimed_at >= plan.expires_at
        ):
            raise PersistentPlanningStoreError("Persisted approval claim is invalid.")
        parent = ("approval_receipt", receipt.receipt_ref, 1, receipt.receipt_digest)
        self._validate_row(row, claim.receipt_ref, 1, canonical_digest(claim.as_dict()), claim.claimed_at, receipt.expires_at, parent)
        if claim.receipt_ref in state.claims:
            raise PersistentPlanningStoreError("Approval claim replay was persisted.")
        state.claims[claim.receipt_ref] = claim

    @staticmethod
    def _validate_row(
        row: sqlite3.Row,
        record_ref: str,
        revision: int,
        object_digest: str,
        issued_at: int,
        expires_at: int,
        parent: tuple[str, str, int, str],
    ) -> None:
        actual_parent = (
            str(row["parent_type"]),
            str(row["parent_ref"]),
            int(row["parent_revision"]),
            str(row["parent_digest"]),
        )
        if (
            str(row["record_ref"]) != record_ref
            or int(row["revision"]) != revision
            or str(row["object_digest"]) != object_digest
            or int(row["issued_at"]) != issued_at
            or int(row["expires_at"]) != expires_at
            or actual_parent != parent
        ):
            raise PersistentPlanningStoreError("Planning record envelope is invalid.")

    def _row_hmac_fields(self, row: sqlite3.Row) -> dict[str, CanonicalValue]:
        return {
            "expires_at": int(row["expires_at"]),
            "issued_at": int(row["issued_at"]),
            "object_digest": str(row["object_digest"]),
            "parent_digest": str(row["parent_digest"]),
            "parent_ref": str(row["parent_ref"]),
            "parent_revision": int(row["parent_revision"]),
            "parent_type": str(row["parent_type"]),
            "payload_json": str(row["payload_json"]),
            "previous_hmac": str(row["previous_hmac"]),
            "record_ref": str(row["record_ref"]),
            "record_type": str(row["record_type"]),
            "revision": int(row["revision"]),
            "sequence": int(row["sequence"]),
        }

    def _hmac(self, domain: str, value: object) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        payload = domain.encode("ascii") + b"\x00" + encoded
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def _anchor_hmac(self, sequence: int, chain_hmac: str) -> str:
        return self._hmac(
            "anchor",
            {
                "last_hmac": chain_hmac,
                "last_sequence": sequence,
                "schema_version": _SCHEMA_VERSION,
            },
        )

    def _prepare_database_path(self) -> None:
        if not self._path.is_absolute() or not self._key_path.is_absolute():
            raise PersistentPlanningStoreError("Protected planning paths are unsafe.")
        parent = self._path.parent
        try:
            _assert_no_symlink_components(parent)
            existed = parent.exists()
            parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if not existed:
                os.chmod(parent, 0o700)
            _assert_owner_only(parent, directory=True)
            if self._path.exists() or self._path.is_symlink():
                _assert_owner_only(self._path, directory=False)
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
            os.chmod(self._path, 0o600)
            _assert_owner_only(self._path, directory=False)
        except PersistentPlanningStoreError:
            raise
        except OSError as exc:
            raise PersistentPlanningStoreError(
                "Protected planning database path is unsafe."
            ) from exc

    def _load_key(self) -> bytes:
        try:
            _assert_no_symlink_components(self._key_path.parent)
            _assert_owner_only(self._key_path.parent, directory=True)
            _assert_owner_only(self._key_path, directory=False)
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._key_path, flags)
            try:
                key = os.read(descriptor, 129)
            finally:
                os.close(descriptor)
            if not 32 <= len(key) <= 128:
                raise PersistentPlanningStoreError("Protected planning HMAC key is invalid.")
            return key
        except PersistentPlanningStoreError:
            raise
        except OSError as exc:
            raise PersistentPlanningStoreError(
                "Protected planning HMAC key is invalid."
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        _assert_owner_only(self._path.parent, directory=True)
        _assert_owner_only(self._path, directory=False)
        connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current not in {0, _SCHEMA_VERSION}:
            raise PersistentPlanningStoreError(
                "Protected planning store schema is unsupported."
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS planning_records(
                sequence INTEGER PRIMARY KEY,
                record_type TEXT NOT NULL,
                record_ref TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision >= 1),
                parent_type TEXT NOT NULL,
                parent_ref TEXT NOT NULL,
                parent_revision INTEGER NOT NULL CHECK(parent_revision >= 0),
                parent_digest TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                object_digest TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                previous_hmac TEXT NOT NULL,
                chain_hmac TEXT NOT NULL,
                UNIQUE(record_type, record_ref, revision)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS integrity_anchor(
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_sequence INTEGER NOT NULL,
                last_hmac TEXT NOT NULL,
                anchor_hmac TEXT NOT NULL
            )
            """
        )
        anchor = connection.execute(
            "SELECT singleton FROM integrity_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            if connection.execute("SELECT COUNT(*) FROM planning_records").fetchone()[0]:
                raise PersistentPlanningStoreError(
                    "Protected planning integrity anchor is missing."
                )
            connection.execute(
                """
                INSERT INTO integrity_anchor(singleton, last_sequence, last_hmac, anchor_hmac)
                VALUES (1, 0, ?, ?)
                """,
                (_CHAIN_ROOT, self._anchor_hmac(0, _CHAIN_ROOT)),
            )
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")


def _payload(value: str) -> dict[str, object]:
    parsed = json.loads(value)
    if type(parsed) is not dict:
        raise PersistentPlanningStoreError("Planning record payload is invalid.")
    return cast(dict[str, object], parsed)


def _summary_from_payload(value: Mapping[str, object]) -> FinalIntentSummary:
    material_value = value.get("material_reference_metadata")
    material = None
    if material_value is not None:
        item = _mapping(material_value)
        material = MaterialReferenceMetadata(
            provider_class=_string(item, "provider_class"),
            purpose=_string(item, "purpose"),
            lifecycle=_string(item, "lifecycle"),
        )
    changes = tuple(_change_from_payload(item) for item in _list(value, "object_changes"))
    return FinalIntentSummary(
        summary_ref=_string(value, "summary_ref"),
        revision=_integer(value, "revision"),
        state=SummaryState(_string(value, "state")),
        requester_digest=_string(value, "requester_digest"),
        requester_class=_string(value, "requester_class"),
        audience_ref=_string(value, "audience_ref"),
        scheme_id=SchemeId(_string(value, "scheme_id")),
        scheme_version=_string(value, "scheme_version"),
        registry_schema_version=_string(value, "registry_schema_version"),
        blueprint_ref=_string(value, "blueprint_ref"),
        action_family_ref=_string(value, "action_family_ref"),
        action_family_version=_string(value, "action_family_version"),
        environment_ref=_string(value, "environment_ref"),
        scope_ref=_string(value, "scope_ref"),
        owner_ref=_string(value, "owner_ref"),
        outcome_code=_string(value, "outcome_code"),
        object_changes=changes,
        unchanged_boundary=_strings(value, "unchanged_boundary"),
        facts=_strings(value, "facts"),
        assumptions=_strings(value, "assumptions"),
        excluded_scope=_strings(value, "excluded_scope"),
        verification_codes=_strings(value, "verification_codes"),
        stop_codes=_strings(value, "stop_codes"),
        evidence_policy=_string(value, "evidence_policy"),
        maintenance_class=_string(value, "maintenance_class"),
        reversibility_class=_string(value, "reversibility_class"),
        unresolved_gaps=_strings(value, "unresolved_gaps"),
        risk_class=_string(value, "risk_class"),
        external_effects=_strings(value, "external_effects"),
        approval_class=_string(value, "approval_class"),
        separation_required=_boolean(value, "separation_required"),
        reconciliation_strategy=_string(value, "reconciliation_strategy"),
        material_reference_metadata=material,
        reference_authority_ref=_string(value, "reference_authority_ref"),
        reference_authorization_digest=_string(value, "reference_authorization_digest"),
        reference_authorization_expires_at=_integer(value, "reference_authorization_expires_at"),
        created_at=_integer(value, "created_at"),
        expires_at=_integer(value, "expires_at"),
        current_state_digest=_string(value, "current_state_digest"),
        proposed_changes_digest=_string(value, "proposed_changes_digest"),
        expected_state_digest=_string(value, "expected_state_digest"),
        summary_digest=_string(value, "summary_digest"),
    )


def _change_from_payload(value: object) -> ObjectChange:
    item = _mapping(value)
    return ObjectChange(
        object_ref=_string(item, "object_ref"),
        object_class=ObjectClass(_string(item, "object_class")),
        change_kind=ChangeKind(_string(item, "change_kind")),
        current_fields=_fields(item, "current_fields"),
        proposed_fields=_fields(item, "projected_changes"),
        expected_fields=_fields(item, "expected_fields"),
        current_projection_digest=_string(item, "current_projection_digest"),
        expected_projection_digest=_string(item, "expected_projection_digest"),
        projection_contract_ref=_string(item, "projection_contract_ref"),
        projection_contract_version=_string(item, "projection_contract_version"),
        projection_source_ref=_string(item, "projection_source_ref"),
        observed_at=_integer(item, "observed_at"),
        fresh_until=_integer(item, "fresh_until"),
    )


def _confirmation_from_payload(value: Mapping[str, object]) -> ConfirmationRecord:
    return ConfirmationRecord(
        confirmation_ref=_string(value, "confirmation_ref"),
        requester_digest=_string(value, "requester_digest"),
        audience_ref=_string(value, "audience_ref"),
        summary_ref=_string(value, "summary_ref"),
        summary_revision=_integer(value, "summary_revision"),
        summary_digest=_string(value, "summary_digest"),
        interaction_ref_digest=_string(value, "interaction_ref_digest"),
        interaction_type=_string(value, "interaction_type"),
        nonce_digest=_string(value, "nonce_digest"),
        confirmed_at=_integer(value, "confirmed_at"),
        expires_at=_integer(value, "expires_at"),
        state=_string(value, "state"),
        record_digest=_string(value, "record_digest"),
    )


def _plan_from_payload(value: Mapping[str, object]) -> PreparedPlan:
    return PreparedPlan(
        plan_ref=_string(value, "plan_ref"),
        revision=_integer(value, "revision"),
        state=PlanState(_string(value, "state")),
        summary_ref=_string(value, "summary_ref"),
        summary_revision=_integer(value, "summary_revision"),
        summary_digest=_string(value, "summary_digest"),
        confirmation_ref=_string(value, "confirmation_ref"),
        confirmation_digest=_string(value, "confirmation_digest"),
        requester_digest=_string(value, "requester_digest"),
        environment_ref=_string(value, "environment_ref"),
        scope_ref=_string(value, "scope_ref"),
        scheme_id=SchemeId(_string(value, "scheme_id")),
        scheme_version=_string(value, "scheme_version"),
        registry_schema_version=_string(value, "registry_schema_version"),
        created_at=_integer(value, "created_at"),
        expires_at=_integer(value, "expires_at"),
        lines=tuple(_line_from_payload(item) for item in _list(value, "lines")),
        dispatchable=_boolean(value, "dispatchable"),
        adapter_registry_bound=_boolean(value, "adapter_registry_bound"),
        planner_runtime_packaged=_boolean(value, "planner_runtime_packaged"),
        planner_mcp_exposed=_boolean(value, "planner_mcp_exposed"),
        executor_runtime_packaged=_boolean(value, "executor_runtime_packaged"),
        executor_mcp_exposed=_boolean(value, "executor_mcp_exposed"),
        plan_digest=_string(value, "plan_digest"),
    )


def _line_from_payload(value: object) -> PlanLine:
    item = _mapping(value)
    return PlanLine(
        line_ref=_string(item, "line_ref"),
        action_family_ref=_string(item, "action_family_ref"),
        action_family_version=_string(item, "action_family_version"),
        target_ref=_string(item, "target_ref"),
        target_class=ObjectClass(_string(item, "target_class")),
        change_kind=ChangeKind(_string(item, "change_kind")),
        expected_current_digest=_string(item, "expected_current_digest"),
        expected_state_digest=_string(item, "expected_state_digest"),
        projection_contract_ref=_string(item, "projection_contract_ref"),
        depends_on=_strings(item, "depends_on"),
        dispatchable=_boolean(item, "dispatchable"),
        adapter=_string(item, "adapter"),
    )


def _decision_from_payload(value: Mapping[str, object]) -> PlanPolicyDecision:
    return PlanPolicyDecision(
        decision_ref=_string(value, "decision_ref"),
        plan_ref=_string(value, "plan_ref"),
        plan_digest=_string(value, "plan_digest"),
        requester_digest=_string(value, "requester_digest"),
        requester_subject_digest=_string(value, "requester_subject_digest"),
        outcome=_string(value, "outcome"),
        approval_class=_string(value, "approval_class"),
        separation_required=_boolean(value, "separation_required"),
        execution_authorized=_boolean(value, "execution_authorized"),
        policy_version=_string(value, "policy_version"),
        issued_at=_integer(value, "issued_at"),
        expires_at=_integer(value, "expires_at"),
        decision_digest=_string(value, "decision_digest"),
    )


def _receipt_from_payload(value: Mapping[str, object]) -> ApprovalReceipt:
    return ApprovalReceipt(
        receipt_ref=_string(value, "receipt_ref"),
        decision_ref=_string(value, "decision_ref"),
        decision_digest=_string(value, "decision_digest"),
        plan_ref=_string(value, "plan_ref"),
        plan_digest=_string(value, "plan_digest"),
        requester_digest=_string(value, "requester_digest"),
        approver_digest=_string(value, "approver_digest"),
        issued_at=_integer(value, "issued_at"),
        expires_at=_integer(value, "expires_at"),
        one_time=_boolean(value, "one_time"),
        execution_authorized=_boolean(value, "execution_authorized"),
        receipt_digest=_string(value, "receipt_digest"),
        authenticator_ref=_optional_string(value, "authenticator_ref"),
        receipt_mac=_optional_string(value, "receipt_mac"),
        approver_authority_ref=_optional_string(
            value,
            "approver_authority_ref",
        ),
        approver_authorization_digest=_optional_string(
            value,
            "approver_authorization_digest",
        ),
        policy_version=_optional_string(value, "policy_version"),
        approval_nonce_digest=_optional_string(value, "approval_nonce_digest"),
    )


def _claim_from_payload(value: Mapping[str, object]) -> PersistedApprovalClaim:
    return PersistedApprovalClaim(
        receipt_ref=_string(value, "receipt_ref"),
        receipt_digest=_string(value, "receipt_digest"),
        plan_ref=_string(value, "plan_ref"),
        plan_digest=_string(value, "plan_digest"),
        requester_digest=_string(value, "requester_digest"),
        claimed_at=_integer(value, "claimed_at"),
        execution_authorized=_boolean(value, "execution_authorized"),
    )


def _mapping(value: object) -> Mapping[str, object]:
    if type(value) is not dict:
        raise PersistentPlanningStoreError("Planning payload mapping is invalid.")
    return cast(dict[str, object], value)


def _string(value: Mapping[str, object], field: str) -> str:
    result = value.get(field)
    if type(result) is not str:
        raise PersistentPlanningStoreError(f"Planning payload field {field} is invalid.")
    return result


def _optional_string(value: Mapping[str, object], field: str) -> str | None:
    result = value.get(field)
    if result is None:
        return None
    if type(result) is not str:
        raise PersistentPlanningStoreError(
            f"Planning payload field {field} is invalid."
        )
    return result


def _integer(value: Mapping[str, object], field: str) -> int:
    result = value.get(field)
    if type(result) is not int:
        raise PersistentPlanningStoreError(f"Planning payload field {field} is invalid.")
    return result


def _boolean(value: Mapping[str, object], field: str) -> bool:
    result = value.get(field)
    if type(result) is not bool:
        raise PersistentPlanningStoreError(f"Planning payload field {field} is invalid.")
    return result


def _list(value: Mapping[str, object], field: str) -> list[object]:
    result = value.get(field)
    if type(result) is not list:
        raise PersistentPlanningStoreError(f"Planning payload field {field} is invalid.")
    return cast(list[object], result)


def _strings(value: Mapping[str, object], field: str) -> tuple[str, ...]:
    result = _list(value, field)
    if any(type(item) is not str for item in result):
        raise PersistentPlanningStoreError(f"Planning payload field {field} is invalid.")
    return tuple(cast(str, item) for item in result)


def _fields(
    value: Mapping[str, object],
    field: str,
) -> tuple[tuple[str, bool | str | int], ...]:
    result = _mapping(value.get(field))
    fields: list[tuple[str, bool | str | int]] = []
    for key, item in result.items():
        if type(item) not in {bool, str, int}:
            raise PersistentPlanningStoreError(
                f"Planning payload field {field} is invalid."
            )
        fields.append((key, cast(bool | str | int, item)))
    return tuple(sorted(fields))


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    info = os.lstat(path)
    required_type = stat.S_ISDIR if directory else stat.S_ISREG
    required_mode = 0o700 if directory else 0o600
    if (
        stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or not required_type(info.st_mode)
        or stat.S_IMODE(info.st_mode) != required_mode
    ):
        raise PersistentPlanningStoreError("Protected planning path is unsafe.")


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if not current.exists():
            return
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise PersistentPlanningStoreError("Protected planning path is unsafe.")


__all__ = [
    "PersistedApprovalClaim",
    "PersistentPlanningStoreError",
    "PersistentProtectedPlanningStore",
]
