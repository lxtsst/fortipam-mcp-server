"""Protected, unregistered M4 authorization for one child Folder create.

This module bridges an exact, already-confirmed M3 planning chain to the
repository-only M4 execution kernel.  It deliberately exposes no MCP tool,
HTTP route, FortiPAM credential, transport, or caller-supplied execution body.

The trusted planning Summary must explicitly carry the prepared request digest
as ``request_parameters_digest`` on its one Folder change.  The same change and
the one prepared plan line must bind the exact target and minimized current and
expected state digests.  Without those bindings, this module cannot manufacture
execution authority and fails closed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Protocol, cast

from v4_planning import (
    ChangeKind,
    M4AdapterDenied,
    M4AuthorizationDenied,
    M4AuthorizationReplay,
    M4ExecutionAuthorization,
    M4ExecutionPlan,
    ObjectClass,
    canonical_digest,
)
from v4_planning.approval import ApprovalReceipt
from v4_planning.canonical import CanonicalValue, canonical_json
from v4_planning.models import ConfirmationRecord, FinalIntentSummary, PreparedPlan
from v4_planning.policy import PlanPolicyDecision
from v4_planning.store import ApprovalClaimRecord

from .folder_create_contract import FolderCreateRequest
from .folder_m4_adapter import (
    ACTION_ID,
    ACTION_VERSION,
    ADAPTER_REF,
    PreparedChildFolderCreate,
)


_SCHEMA_VERSION = 1
_CHAIN_ROOT = "folder-m4-authorization-chain-root"
_ISSUE = "issue"
_CONSUME = "consume"
_MAX_ACTIVE_SECONDS = 60
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class FolderM4AuthorizationError(M4AuthorizationDenied):
    """Raised when a protected Folder execution binding is absent or invalid."""


class FolderM4AuthorizationCheckpointError(RuntimeError):
    """Raised when the external authorization checkpoint cannot be trusted."""


@dataclass(frozen=True, slots=True)
class FolderM4AuthorizationStoreTail:
    """Value-free position of one protected Folder authorization ledger."""

    store_ref: str
    sequence: int
    chain_mac: str

    @classmethod
    def empty(cls, store_ref: str) -> FolderM4AuthorizationStoreTail:
        return cls(store_ref, 0, _CHAIN_ROOT)

    def __post_init__(self) -> None:
        if (
            not _is_ref(self.store_ref)
            or type(self.sequence) is not int
            or self.sequence < 0
            or (
                self.sequence == 0
                and self.chain_mac != _CHAIN_ROOT
            )
            or (
                self.sequence > 0
                and not _is_digest(self.chain_mac)
            )
        ):
            raise FolderM4AuthorizationError(
                "Protected Folder authorization checkpoint position is invalid."
            )


class MonotonicFolderM4AuthorizationCheckpoint(Protocol):
    """External compare-and-swap authority for authorization ledger tails."""

    authority_ref: str

    def verify(self, tail: FolderM4AuthorizationStoreTail) -> None: ...

    def advance(
        self,
        previous: FolderM4AuthorizationStoreTail,
        current: FolderM4AuthorizationStoreTail,
    ) -> None: ...


class ProtectedPlanningChainReader(Protocol):
    """Read-only view of the owner-protected M3 planning record chain."""

    def get_summary(self, summary_ref: str, revision: int) -> FinalIntentSummary: ...

    def get_confirmation(self, confirmation_ref: str) -> ConfirmationRecord: ...

    def get_plan(self, plan_ref: str) -> PreparedPlan: ...

    def get_policy_decision(self, decision_ref: str) -> PlanPolicyDecision: ...

    def get_approval_receipt(self, receipt_ref: str) -> ApprovalReceipt: ...

    def get_approval_claim(self, receipt_ref: str) -> ApprovalClaimRecord: ...


@dataclass(frozen=True, slots=True)
class TrustedFolderM4PromotionDecision:
    """Separately authenticated decision that may promote M3 evidence to M4."""

    promotion_ref: str
    issuer_ref: str
    policy_version: str
    source_plan_ref: str
    source_plan_revision: int
    source_plan_digest: str
    summary_ref: str
    summary_revision: int
    summary_digest: str
    confirmation_ref: str
    confirmation_digest: str
    source_decision_ref: str
    source_decision_digest: str
    approval_ref: str
    approval_digest: str
    source_claim_digest: str
    requester_digest: str
    approver_digest: str
    action_id: str
    action_version: str
    adapter_ref: str
    target_ref: str
    parameters_digest: str
    expected_current_digest: str
    expected_state_digest: str
    idempotency_digest: str
    issued_at: int
    expires_at: int
    one_time: bool
    execution_authorized: bool
    decision_digest: str
    decision_mac: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "action_id": self.action_id,
            "action_version": self.action_version,
            "adapter_ref": self.adapter_ref,
            "approval_digest": self.approval_digest,
            "approval_ref": self.approval_ref,
            "approver_digest": self.approver_digest,
            "confirmation_digest": self.confirmation_digest,
            "confirmation_ref": self.confirmation_ref,
            "execution_authorized": self.execution_authorized,
            "expected_current_digest": self.expected_current_digest,
            "expected_state_digest": self.expected_state_digest,
            "expires_at": self.expires_at,
            "idempotency_digest": self.idempotency_digest,
            "issued_at": self.issued_at,
            "issuer_ref": self.issuer_ref,
            "one_time": self.one_time,
            "parameters_digest": self.parameters_digest,
            "policy_version": self.policy_version,
            "promotion_ref": self.promotion_ref,
            "requester_digest": self.requester_digest,
            "source_claim_digest": self.source_claim_digest,
            "source_decision_digest": self.source_decision_digest,
            "source_decision_ref": self.source_decision_ref,
            "source_plan_digest": self.source_plan_digest,
            "source_plan_ref": self.source_plan_ref,
            "source_plan_revision": self.source_plan_revision,
            "summary_digest": self.summary_digest,
            "summary_ref": self.summary_ref,
            "summary_revision": self.summary_revision,
            "target_ref": self.target_ref,
        }

    def __post_init__(self) -> None:
        if (
            self.action_id != ACTION_ID
            or self.action_version != ACTION_VERSION
            or self.adapter_ref != ADAPTER_REF
            or self.one_time is not True
            or self.execution_authorized is not True
            or type(self.source_plan_revision) is not int
            or self.source_plan_revision < 1
            or type(self.summary_revision) is not int
            or self.summary_revision < 1
            or type(self.issued_at) is not int
            or type(self.expires_at) is not int
            or self.expires_at <= self.issued_at
            or self.requester_digest == self.approver_digest
            or not all(
                _is_ref(value)
                for value in (
                    self.promotion_ref,
                    self.issuer_ref,
                    self.source_plan_ref,
                    self.summary_ref,
                    self.confirmation_ref,
                    self.source_decision_ref,
                    self.approval_ref,
                    self.target_ref,
                )
            )
            or _VERSION.fullmatch(self.policy_version) is None
        ):
            raise FolderM4AuthorizationError("M4 promotion decision is invalid.")
        for value in (
            self.source_plan_digest,
            self.summary_digest,
            self.confirmation_digest,
            self.source_decision_digest,
            self.approval_digest,
            self.source_claim_digest,
            self.requester_digest,
            self.approver_digest,
            self.parameters_digest,
            self.expected_current_digest,
            self.expected_state_digest,
            self.idempotency_digest,
            self.decision_digest,
            self.decision_mac,
        ):
            if not _is_digest(value):
                raise FolderM4AuthorizationError("M4 promotion digest is invalid.")
        if self.decision_digest != canonical_digest(self.canonical_content()):
            raise FolderM4AuthorizationError("M4 promotion decision digest is invalid.")


class PersistentFolderM4PromotionAuthority:
    """Unregistered future-host boundary using a dedicated owner-only HMAC key."""

    def __init__(self, hmac_key_path: Path) -> None:
        self._key_path = Path(hmac_key_path)
        self._key = _load_owner_key(self._key_path, "M4 promotion")

    def issue(
        self,
        *,
        promotion_ref: str,
        issuer_ref: str,
        policy_version: str,
        source_plan_ref: str,
        source_plan_revision: int,
        source_plan_digest: str,
        summary_ref: str,
        summary_revision: int,
        summary_digest: str,
        confirmation_ref: str,
        confirmation_digest: str,
        source_decision_ref: str,
        source_decision_digest: str,
        approval_ref: str,
        approval_digest: str,
        source_claim_digest: str,
        requester_digest: str,
        approver_digest: str,
        action_id: str,
        action_version: str,
        adapter_ref: str,
        target_ref: str,
        parameters_digest: str,
        expected_current_digest: str,
        expected_state_digest: str,
        idempotency_digest: str,
        issued_at: int,
        expires_at: int,
        one_time: bool,
        execution_authorized: bool,
    ) -> TrustedFolderM4PromotionDecision:
        """Issue only an explicit full decision; M3 records alone are insufficient."""

        content: dict[str, CanonicalValue] = {
            "action_id": action_id,
            "action_version": action_version,
            "adapter_ref": adapter_ref,
            "approval_digest": approval_digest,
            "approval_ref": approval_ref,
            "approver_digest": approver_digest,
            "confirmation_digest": confirmation_digest,
            "confirmation_ref": confirmation_ref,
            "execution_authorized": execution_authorized,
            "expected_current_digest": expected_current_digest,
            "expected_state_digest": expected_state_digest,
            "expires_at": expires_at,
            "idempotency_digest": idempotency_digest,
            "issued_at": issued_at,
            "issuer_ref": issuer_ref,
            "one_time": one_time,
            "parameters_digest": parameters_digest,
            "policy_version": policy_version,
            "promotion_ref": promotion_ref,
            "requester_digest": requester_digest,
            "source_claim_digest": source_claim_digest,
            "source_decision_digest": source_decision_digest,
            "source_decision_ref": source_decision_ref,
            "source_plan_digest": source_plan_digest,
            "source_plan_ref": source_plan_ref,
            "source_plan_revision": source_plan_revision,
            "summary_digest": summary_digest,
            "summary_ref": summary_ref,
            "summary_revision": summary_revision,
            "target_ref": target_ref,
        }
        decision_digest = canonical_digest(content)
        decision_mac = hmac.new(
            self._key,
            decision_digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return TrustedFolderM4PromotionDecision(
            promotion_ref=promotion_ref,
            issuer_ref=issuer_ref,
            policy_version=policy_version,
            source_plan_ref=source_plan_ref,
            source_plan_revision=source_plan_revision,
            source_plan_digest=source_plan_digest,
            summary_ref=summary_ref,
            summary_revision=summary_revision,
            summary_digest=summary_digest,
            confirmation_ref=confirmation_ref,
            confirmation_digest=confirmation_digest,
            source_decision_ref=source_decision_ref,
            source_decision_digest=source_decision_digest,
            approval_ref=approval_ref,
            approval_digest=approval_digest,
            source_claim_digest=source_claim_digest,
            requester_digest=requester_digest,
            approver_digest=approver_digest,
            action_id=action_id,
            action_version=action_version,
            adapter_ref=adapter_ref,
            target_ref=target_ref,
            parameters_digest=parameters_digest,
            expected_current_digest=expected_current_digest,
            expected_state_digest=expected_state_digest,
            idempotency_digest=idempotency_digest,
            issued_at=issued_at,
            expires_at=expires_at,
            one_time=one_time,
            execution_authorized=execution_authorized,
            decision_digest=decision_digest,
            decision_mac=decision_mac,
        )


@dataclass(frozen=True, slots=True)
class ProtectedChildFolderBinding:
    """Exact signed-at-rest association between the trusted chain and M4."""

    source_plan_digest: str
    source_decision_ref: str
    source_decision_digest: str
    source_claim_digest: str
    promotion_ref: str
    promotion_digest: str
    promotion_issuer_ref: str
    promotion_policy_version: str
    folder_name: str
    parent_folder_id: int
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    binding_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return _binding_content(
            source_plan_digest=self.source_plan_digest,
            source_decision_ref=self.source_decision_ref,
            source_decision_digest=self.source_decision_digest,
            source_claim_digest=self.source_claim_digest,
            promotion_ref=self.promotion_ref,
            promotion_digest=self.promotion_digest,
            promotion_issuer_ref=self.promotion_issuer_ref,
            promotion_policy_version=self.promotion_policy_version,
            folder_name=self.folder_name,
            parent_folder_id=self.parent_folder_id,
            plan=self.plan,
            authorization=self.authorization,
        )

    def __post_init__(self) -> None:
        prepared = self.prepared_action()
        if (
            self.plan.action_id != ACTION_ID
            or self.plan.action_version != ACTION_VERSION
            or self.plan.adapter_ref != ADAPTER_REF
            or self.plan.parameters_digest != prepared.parameters_digest
            or self.plan.expected_current_digest != prepared.expected_current_digest
            or self.plan.expected_state_digest != prepared.expected_state_digest
            or self.authorization.plan_ref != self.plan.plan_ref
            or self.authorization.plan_digest != self.plan.plan_digest
            or self.authorization.requester_digest != self.plan.requester_digest
            or self.authorization.confirmation_digest != self.plan.confirmation_digest
            or self.authorization.approval_digest != self.plan.approval_digest
            or self.authorization.expires_at > self.plan.expires_at
            or not _is_ref(self.promotion_ref)
            or not _is_ref(self.promotion_issuer_ref)
            or _VERSION.fullmatch(self.promotion_policy_version) is None
        ):
            raise FolderM4AuthorizationError("Protected Folder binding is inconsistent.")
        for digest in (
            self.source_plan_digest,
            self.source_decision_digest,
            self.source_claim_digest,
            self.promotion_digest,
            self.binding_digest,
        ):
            if not _is_digest(digest):
                raise FolderM4AuthorizationError("Protected Folder binding digest is invalid.")
        if self.binding_digest != canonical_digest(self.canonical_content()):
            raise FolderM4AuthorizationError("Protected Folder binding digest is invalid.")

    def prepared_action(self) -> PreparedChildFolderCreate:
        request = FolderCreateRequest.child(self.folder_name, self.parent_folder_id)
        return PreparedChildFolderCreate.build(
            plan_ref=self.plan.plan_ref,
            target_ref=self.plan.target_ref,
            request=request,
        )


@dataclass(slots=True)
class _ProtectedState:
    issues: dict[str, ProtectedChildFolderBinding]
    consumed: set[str]
    sequence: int
    last_mac: str


class PersistentFolderM4AuthorizationStore:
    """Owner-only, append-only SQLite/HMAC binding and one-time claim store."""

    def __init__(
        self,
        database_path: Path,
        hmac_key_path: Path,
        promotion_hmac_key_path: Path,
        *,
        monotonic_checkpoint: (
            MonotonicFolderM4AuthorizationCheckpoint | None
        ) = None,
        checkpoint_store_ref: str | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._path = Path(database_path)
        self._key_path = Path(hmac_key_path)
        self._promotion_key_path = Path(promotion_hmac_key_path)
        if len(
            {
                self._path.resolve(),
                self._key_path.resolve(),
                self._promotion_key_path.resolve(),
            }
        ) != 3:
            raise FolderM4AuthorizationError(
                "Protected Folder state paths must be independent."
            )
        if (monotonic_checkpoint is None) is not (checkpoint_store_ref is None):
            raise FolderM4AuthorizationError(
                "Protected Folder authorization checkpoint binding is incomplete."
            )
        if monotonic_checkpoint is not None and checkpoint_store_ref is not None:
            try:
                checkpoint_authority_ref = monotonic_checkpoint.authority_ref
            except AttributeError as exc:
                raise FolderM4AuthorizationError(
                    "Protected Folder authorization checkpoint binding is invalid."
                ) from exc
            if (
                not _is_ref(checkpoint_authority_ref)
                or not _is_ref(checkpoint_store_ref)
            ):
                raise FolderM4AuthorizationError(
                    "Protected Folder authorization checkpoint binding is invalid."
                )
        self._monotonic_checkpoint = monotonic_checkpoint
        self._checkpoint_store_ref = checkpoint_store_ref
        self._clock = clock or (lambda: int(time.time()))
        self._prepare_paths()
        self._key = self._load_key()
        self._promotion_key = _load_owner_key(self._promotion_key_path, "M4 promotion")
        if hmac.compare_digest(self._key, self._promotion_key):
            raise FolderM4AuthorizationError(
                "Folder store and M4 promotion HMAC keys must be independent."
            )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                self._initialize_schema(connection)
                self._verify_integrity(connection)
                connection.commit()
        except FolderM4AuthorizationError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise FolderM4AuthorizationError(
                "Protected Folder authorization store integrity validation failed."
            ) from exc

    @property
    def monotonic_checkpoint_protocol_bound(self) -> bool:
        """Report whether whole-ledger rollback protection is composed."""

        return self._monotonic_checkpoint is not None

    def verify_ready(self) -> None:
        """Revalidate owner-only state and the exact external checkpoint tail."""

        self._read_state()

    def issue(
        self,
        planning: ProtectedPlanningChainReader,
        prepared: PreparedChildFolderCreate,
        *,
        approval_receipt_ref: str,
        idempotency_digest: str,
        promotion: TrustedFolderM4PromotionDecision | None = None,
        now_epoch: int | None = None,
    ) -> ProtectedChildFolderBinding:
        """Persist one exact trusted-chain binding without dispatching it."""

        now = self._now(now_epoch)
        if not _is_digest(idempotency_digest):
            raise FolderM4AuthorizationError("M4 idempotency digest is invalid.")
        if promotion is None:
            raise FolderM4AuthorizationError(
                "A separate authenticated M4 promotion decision is required."
            )
        records = self._validate_planning_chain(
            planning,
            prepared,
            approval_receipt_ref=approval_receipt_ref,
            now_epoch=now,
        )
        summary, confirmation, source_plan, decision, receipt, claim = records
        source_claim_digest = canonical_digest(claim.as_dict())
        chain_expiry = min(
            now + _MAX_ACTIVE_SECONDS,
            summary.expires_at,
            confirmation.expires_at,
            source_plan.expires_at,
            decision.expires_at,
            receipt.expires_at,
        )
        if chain_expiry <= now:
            raise FolderM4AuthorizationError("Trusted Folder planning chain has expired.")
        self._validate_promotion(
            promotion,
            prepared=prepared,
            source_plan=source_plan,
            summary=summary,
            confirmation=confirmation,
            decision=decision,
            receipt=receipt,
            source_claim_digest=source_claim_digest,
            idempotency_digest=idempotency_digest,
            now_epoch=now,
            chain_expiry=chain_expiry,
        )
        expires_at = promotion.expires_at
        plan_values: dict[str, CanonicalValue] = {
            "action_id": ACTION_ID,
            "action_version": ACTION_VERSION,
            "adapter_ref": ADAPTER_REF,
            "approval_digest": receipt.receipt_digest,
            "compensation_ref": None,
            "confirmation_digest": confirmation.record_digest,
            "expected_current_digest": prepared.expected_current_digest,
            "expected_state_digest": prepared.expected_state_digest,
            "expires_at": expires_at,
            "idempotency_digest": idempotency_digest,
            "parameters_digest": prepared.parameters_digest,
            "plan_ref": source_plan.plan_ref,
            "requester_digest": source_plan.requester_digest,
            "revision": source_plan.revision,
            "summary_digest": summary.summary_digest,
            "target_ref": prepared.target_ref,
        }
        plan = M4ExecutionPlan(
            plan_ref=source_plan.plan_ref,
            revision=source_plan.revision,
            action_id=ACTION_ID,
            action_version=ACTION_VERSION,
            adapter_ref=ADAPTER_REF,
            target_ref=prepared.target_ref,
            requester_digest=source_plan.requester_digest,
            summary_digest=summary.summary_digest,
            confirmation_digest=confirmation.record_digest,
            approval_digest=receipt.receipt_digest,
            parameters_digest=prepared.parameters_digest,
            expected_current_digest=prepared.expected_current_digest,
            expected_state_digest=prepared.expected_state_digest,
            idempotency_digest=idempotency_digest,
            expires_at=expires_at,
            compensation_ref=None,
            plan_digest=canonical_digest(plan_values),
        )
        authorization_ref = promotion.promotion_ref
        authorization_values: dict[str, CanonicalValue] = {
            "approval_digest": receipt.receipt_digest,
            "approval_ref": receipt.receipt_ref,
            "approver_digest": receipt.approver_digest,
            "authorization_ref": authorization_ref,
            "confirmation_digest": confirmation.record_digest,
            "confirmation_ref": confirmation.confirmation_ref,
            "execution_authorized": True,
            "expires_at": expires_at,
            "issued_at": now,
            "one_time": True,
            "plan_digest": plan.plan_digest,
            "plan_ref": plan.plan_ref,
            "requester_digest": plan.requester_digest,
        }
        authorization = M4ExecutionAuthorization(
            authorization_ref=authorization_ref,
            plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest,
            requester_digest=plan.requester_digest,
            confirmation_ref=confirmation.confirmation_ref,
            confirmation_digest=confirmation.record_digest,
            approval_ref=receipt.receipt_ref,
            approval_digest=receipt.receipt_digest,
            approver_digest=receipt.approver_digest,
            issued_at=now,
            expires_at=expires_at,
            one_time=True,
            execution_authorized=True,
            authorization_digest=canonical_digest(authorization_values),
        )
        assert prepared.request.parent_folder_id is not None
        binding_content = _binding_content(
            source_plan_digest=source_plan.plan_digest,
            source_decision_ref=decision.decision_ref,
            source_decision_digest=decision.decision_digest,
            source_claim_digest=source_claim_digest,
            promotion_ref=promotion.promotion_ref,
            promotion_digest=promotion.decision_digest,
            promotion_issuer_ref=promotion.issuer_ref,
            promotion_policy_version=promotion.policy_version,
            folder_name=prepared.request.name,
            parent_folder_id=prepared.request.parent_folder_id,
            plan=plan,
            authorization=authorization,
        )
        binding = ProtectedChildFolderBinding(
            source_plan_digest=source_plan.plan_digest,
            source_decision_ref=decision.decision_ref,
            source_decision_digest=decision.decision_digest,
            source_claim_digest=source_claim_digest,
            promotion_ref=promotion.promotion_ref,
            promotion_digest=promotion.decision_digest,
            promotion_issuer_ref=promotion.issuer_ref,
            promotion_policy_version=promotion.policy_version,
            folder_name=prepared.request.name,
            parent_folder_id=prepared.request.parent_folder_id,
            plan=plan,
            authorization=authorization,
            binding_digest=canonical_digest(binding_content),
        )
        self._append_issue(binding, now_epoch=now)
        return binding

    def _validate_promotion(
        self,
        promotion: TrustedFolderM4PromotionDecision,
        *,
        prepared: PreparedChildFolderCreate,
        source_plan: PreparedPlan,
        summary: FinalIntentSummary,
        confirmation: ConfirmationRecord,
        decision: PlanPolicyDecision,
        receipt: ApprovalReceipt,
        source_claim_digest: str,
        idempotency_digest: str,
        now_epoch: int,
        chain_expiry: int,
    ) -> None:
        expected_mac = hmac.new(
            self._promotion_key,
            promotion.decision_digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(promotion.decision_mac, expected_mac):
            raise FolderM4AuthorizationError("M4 promotion decision authenticity is invalid.")
        if (
            promotion.source_plan_ref != source_plan.plan_ref
            or promotion.source_plan_revision != source_plan.revision
            or promotion.source_plan_digest != source_plan.plan_digest
            or promotion.summary_ref != summary.summary_ref
            or promotion.summary_revision != summary.revision
            or promotion.summary_digest != summary.summary_digest
            or promotion.confirmation_ref != confirmation.confirmation_ref
            or promotion.confirmation_digest != confirmation.record_digest
            or promotion.source_decision_ref != decision.decision_ref
            or promotion.source_decision_digest != decision.decision_digest
            or promotion.approval_ref != receipt.receipt_ref
            or promotion.approval_digest != receipt.receipt_digest
            or promotion.source_claim_digest != source_claim_digest
            or promotion.requester_digest != source_plan.requester_digest
            or promotion.approver_digest != receipt.approver_digest
            or promotion.target_ref != prepared.target_ref
            or promotion.parameters_digest != prepared.parameters_digest
            or promotion.expected_current_digest != prepared.expected_current_digest
            or promotion.expected_state_digest != prepared.expected_state_digest
            or promotion.idempotency_digest != idempotency_digest
            or now_epoch < promotion.issued_at
            or now_epoch >= promotion.expires_at
            or promotion.expires_at > chain_expiry
        ):
            raise FolderM4AuthorizationError(
                "M4 promotion decision is not bound to the exact active chain and action."
            )

    def resolve(self, plan: M4ExecutionPlan) -> PreparedChildFolderCreate:
        """Resolve only the exact signed binding; never accept an action body."""

        state = self._read_state()
        matches = [item for item in state.issues.values() if item.plan.plan_ref == plan.plan_ref]
        if len(matches) != 1 or matches[0].plan != plan:
            raise M4AdapterDenied("Protected Folder action binding is unavailable.")
        return matches[0].prepared_action()

    def resolve_execution_binding(
        self,
        authorization_ref: str,
    ) -> ProtectedChildFolderBinding:
        """Return one exact signed binding for an internal runtime assembly.

        The reference is only an opaque lookup key.  No caller-supplied plan,
        authorization, request body, or product locator is accepted here.
        """

        if not _is_ref(authorization_ref):
            raise FolderM4AuthorizationError(
                "Protected Folder authorization reference is invalid."
            )
        state = self._read_state()
        binding = state.issues.get(authorization_ref)
        if binding is None:
            raise FolderM4AuthorizationError(
                "Protected Folder execution binding is unavailable."
            )
        return binding

    def consume(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        authenticated_requester_digest: str,
        now_epoch: int,
    ) -> None:
        """Atomically consume one exact authorization before product reads/writes."""

        if not _is_digest(authenticated_requester_digest) or type(now_epoch) is not int:
            raise FolderM4AuthorizationError("Trusted execution identity or clock is invalid.")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._verify_integrity(connection)
                previous_tail = self._checkpoint_tail(
                    state.sequence,
                    state.last_mac,
                )
                binding = state.issues.get(authorization.authorization_ref)
                if binding is None:
                    raise FolderM4AuthorizationError("M4 authorization is unavailable.")
                if authorization.authorization_ref in state.consumed:
                    raise M4AuthorizationReplay("execution authorization was already consumed.")
                if (
                    binding.plan != plan
                    or binding.authorization != authorization
                    or authenticated_requester_digest != plan.requester_digest
                    or authenticated_requester_digest != authorization.requester_digest
                    or now_epoch < authorization.issued_at
                    or now_epoch >= authorization.expires_at
                    or now_epoch >= plan.expires_at
                ):
                    raise FolderM4AuthorizationError(
                        "M4 authorization is not bound to the exact active plan and identity."
                    )
                payload: dict[str, CanonicalValue] = {
                    "authorization_digest": authorization.authorization_digest,
                    "authorization_ref": authorization.authorization_ref,
                    "binding_digest": binding.binding_digest,
                    "consumed_at": now_epoch,
                    "plan_digest": plan.plan_digest,
                    "plan_ref": plan.plan_ref,
                    "requester_digest": authenticated_requester_digest,
                }
                record_mac = self._append_event(
                    connection,
                    event_type=_CONSUME,
                    authorization_ref=authorization.authorization_ref,
                    payload=payload,
                    object_digest=canonical_digest(payload),
                    previous_mac=state.last_mac,
                    created_at=now_epoch,
                )
                current_tail = self._checkpoint_tail(
                    state.sequence + 1,
                    record_mac,
                )
                connection.commit()
                self._advance_monotonic_checkpoint(previous_tail, current_tail)
        except (FolderM4AuthorizationError, M4AuthorizationReplay):
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise FolderM4AuthorizationError(
                "M4 authorization could not be consumed safely."
            ) from exc

    def _append_issue(self, binding: ProtectedChildFolderBinding, *, now_epoch: int) -> None:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._verify_integrity(connection)
                previous_tail = self._checkpoint_tail(
                    state.sequence,
                    state.last_mac,
                )
                if binding.authorization.authorization_ref in state.issues or any(
                    item.plan.plan_ref == binding.plan.plan_ref for item in state.issues.values()
                ):
                    raise FolderM4AuthorizationError(
                        "Prepared Folder plan already has an execution binding."
                    )
                payload = dict(binding.canonical_content())
                payload["binding_digest"] = binding.binding_digest
                record_mac = self._append_event(
                    connection,
                    event_type=_ISSUE,
                    authorization_ref=binding.authorization.authorization_ref,
                    payload=payload,
                    object_digest=binding.binding_digest,
                    previous_mac=state.last_mac,
                    created_at=now_epoch,
                )
                current_tail = self._checkpoint_tail(
                    state.sequence + 1,
                    record_mac,
                )
                connection.commit()
                self._advance_monotonic_checkpoint(previous_tail, current_tail)
        except FolderM4AuthorizationError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise FolderM4AuthorizationError(
                "Protected Folder execution binding could not be persisted."
            ) from exc

    def _validate_planning_chain(
        self,
        planning: ProtectedPlanningChainReader,
        prepared: PreparedChildFolderCreate,
        *,
        approval_receipt_ref: str,
        now_epoch: int,
    ) -> tuple[
        FinalIntentSummary,
        ConfirmationRecord,
        PreparedPlan,
        PlanPolicyDecision,
        ApprovalReceipt,
        ApprovalClaimRecord,
    ]:
        try:
            source_plan = planning.get_plan(prepared.plan_ref)
            summary = planning.get_summary(source_plan.summary_ref, source_plan.summary_revision)
            confirmation = planning.get_confirmation(source_plan.confirmation_ref)
            receipt = planning.get_approval_receipt(approval_receipt_ref)
            decision = planning.get_policy_decision(receipt.decision_ref)
            claim = planning.get_approval_claim(receipt.receipt_ref)
        except Exception as exc:
            raise FolderM4AuthorizationError(
                "Trusted Folder planning chain is incomplete."
            ) from exc
        if len(source_plan.lines) != 1 or len(summary.object_changes) != 1:
            raise FolderM4AuthorizationError("Folder execution requires one exact plan line.")
        line = source_plan.lines[0]
        change = summary.object_changes[0]
        proposed = dict(change.proposed_fields)
        if (
            summary.action_family_ref != ACTION_ID
            or summary.action_family_version != ACTION_VERSION
            or summary.current_state_digest != prepared.expected_current_digest
            or summary.expected_state_digest != prepared.expected_state_digest
            or proposed.get("request_parameters_digest") != prepared.parameters_digest
            or change.object_ref != prepared.target_ref
            or change.object_class is not ObjectClass.PUBLIC_FOLDER
            or change.change_kind is not ChangeKind.CREATE
            or change.current_projection_digest != prepared.expected_current_digest
            or change.expected_projection_digest != prepared.expected_state_digest
            or line.action_family_ref != ACTION_ID
            or line.action_family_version != ACTION_VERSION
            or line.target_ref != prepared.target_ref
            or line.target_class is not ObjectClass.PUBLIC_FOLDER
            or line.change_kind is not ChangeKind.CREATE
            or line.expected_current_digest != prepared.expected_current_digest
            or line.expected_state_digest != prepared.expected_state_digest
        ):
            raise FolderM4AuthorizationError(
                "Confirmed Summary does not bind the exact child Folder request and states."
            )
        if (
            confirmation.summary_ref != summary.summary_ref
            or confirmation.summary_revision != summary.revision
            or confirmation.summary_digest != summary.summary_digest
            or confirmation.requester_digest != summary.requester_digest
            or confirmation.record_digest != source_plan.confirmation_digest
            or confirmation.interaction_type != "authenticated_human_confirmation"
            or source_plan.summary_digest != summary.summary_digest
            or source_plan.requester_digest != summary.requester_digest
            or decision.plan_ref != source_plan.plan_ref
            or decision.plan_digest != source_plan.plan_digest
            or receipt.decision_ref != decision.decision_ref
            or receipt.decision_digest != decision.decision_digest
            or receipt.plan_ref != source_plan.plan_ref
            or receipt.plan_digest != source_plan.plan_digest
            or receipt.requester_digest != source_plan.requester_digest
            or receipt.approver_digest == source_plan.requester_digest
            or claim.receipt_ref != receipt.receipt_ref
            or claim.receipt_digest != receipt.receipt_digest
            or claim.plan_ref != source_plan.plan_ref
            or claim.plan_digest != source_plan.plan_digest
            or claim.requester_digest != source_plan.requester_digest
            or claim.execution_authorized is not False
        ):
            raise FolderM4AuthorizationError(
                "Confirmation and independent approval are not bound to the exact plan."
            )
        if any(
            now_epoch < issued or now_epoch >= expires
            for issued, expires in (
                (summary.created_at, summary.expires_at),
                (confirmation.confirmed_at, confirmation.expires_at),
                (source_plan.created_at, source_plan.expires_at),
                (decision.issued_at, decision.expires_at),
                (receipt.issued_at, receipt.expires_at),
            )
        ) or claim.claimed_at > now_epoch:
            raise FolderM4AuthorizationError("Trusted Folder planning chain is not active.")
        return summary, confirmation, source_plan, decision, receipt, claim

    def _read_state(self) -> _ProtectedState:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                state = self._verify_integrity(connection)
                connection.commit()
                return state
        except FolderM4AuthorizationError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise FolderM4AuthorizationError(
                "Protected Folder execution binding could not be read."
            ) from exc

    def _verify_integrity(self, connection: sqlite3.Connection) -> _ProtectedState:
        issues: dict[str, ProtectedChildFolderBinding] = {}
        consumed: set[str] = set()
        previous_mac = _CHAIN_ROOT
        rows = connection.execute("SELECT * FROM folder_m4_events ORDER BY ordinal").fetchall()
        for expected_ordinal, row in enumerate(rows, start=1):
            ordinal = int(row["ordinal"])
            event_type = str(row["event_type"])
            authorization_ref = str(row["authorization_ref"])
            payload_json = str(row["payload_json"])
            object_digest = str(row["object_digest"])
            created_at = int(row["created_at"])
            if ordinal != expected_ordinal or str(row["previous_mac"]) != previous_mac:
                raise FolderM4AuthorizationError("Protected Folder event chain is invalid.")
            payload = json.loads(payload_json)
            if not isinstance(payload, dict) or canonical_json(payload) != payload_json:
                raise FolderM4AuthorizationError("Protected Folder event payload is invalid.")
            expected_object_digest = (
                str(payload.get("binding_digest"))
                if event_type == _ISSUE
                else canonical_digest(cast(Mapping[str, object], payload))
            )
            if object_digest != expected_object_digest:
                raise FolderM4AuthorizationError("Protected Folder event digest is invalid.")
            expected_mac = self._event_mac(
                ordinal=ordinal,
                event_type=event_type,
                authorization_ref=authorization_ref,
                payload_json=payload_json,
                object_digest=object_digest,
                previous_mac=previous_mac,
                created_at=created_at,
            )
            if not hmac.compare_digest(str(row["record_mac"]), expected_mac):
                raise FolderM4AuthorizationError("Protected Folder event HMAC is invalid.")
            if event_type == _ISSUE:
                issued_binding = _binding_from_payload(payload)
                if (
                    authorization_ref != issued_binding.authorization.authorization_ref
                    or authorization_ref in issues
                ):
                    raise FolderM4AuthorizationError("Protected Folder issue event is invalid.")
                issues[authorization_ref] = issued_binding
            elif event_type == _CONSUME:
                consumed_binding = issues.get(authorization_ref)
                if consumed_binding is None or authorization_ref in consumed:
                    raise FolderM4AuthorizationError("Protected Folder consume event is invalid.")
                if (
                    payload.get("authorization_digest")
                    != consumed_binding.authorization.authorization_digest
                    or payload.get("binding_digest") != consumed_binding.binding_digest
                    or payload.get("plan_digest") != consumed_binding.plan.plan_digest
                    or payload.get("plan_ref") != consumed_binding.plan.plan_ref
                    or payload.get("requester_digest") != consumed_binding.plan.requester_digest
                ):
                    raise FolderM4AuthorizationError("Protected Folder consume binding is invalid.")
                consumed.add(authorization_ref)
            else:
                raise FolderM4AuthorizationError("Protected Folder event type is invalid.")
            previous_mac = expected_mac
        state = _ProtectedState(issues, consumed, len(rows), previous_mac)
        self._verify_monotonic_checkpoint(
            self._checkpoint_tail(state.sequence, state.last_mac)
        )
        return state

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        authorization_ref: str,
        payload: Mapping[str, object],
        object_digest: str,
        previous_mac: str,
        created_at: int,
    ) -> str:
        ordinal = int(connection.execute("SELECT COUNT(*) FROM folder_m4_events").fetchone()[0]) + 1
        payload_json = canonical_json(payload)
        record_mac = self._event_mac(
            ordinal=ordinal,
            event_type=event_type,
            authorization_ref=authorization_ref,
            payload_json=payload_json,
            object_digest=object_digest,
            previous_mac=previous_mac,
            created_at=created_at,
        )
        connection.execute(
            """
            INSERT INTO folder_m4_events(
                ordinal, event_type, authorization_ref, payload_json,
                object_digest, previous_mac, record_mac, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ordinal,
                event_type,
                authorization_ref,
                payload_json,
                object_digest,
                previous_mac,
                record_mac,
                created_at,
            ),
        )
        return record_mac

    def _checkpoint_tail(
        self,
        sequence: int,
        chain_mac: str,
    ) -> FolderM4AuthorizationStoreTail | None:
        if self._monotonic_checkpoint is None:
            return None
        if self._checkpoint_store_ref is None:
            raise FolderM4AuthorizationError(
                "Protected Folder authorization checkpoint state is unavailable."
            )
        return FolderM4AuthorizationStoreTail(
            self._checkpoint_store_ref,
            sequence,
            chain_mac,
        )

    def _verify_monotonic_checkpoint(
        self,
        tail: FolderM4AuthorizationStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if tail is None:
            raise FolderM4AuthorizationError(
                "Protected Folder authorization checkpoint state is unavailable."
            )
        try:
            checkpoint.verify(tail)
        except FolderM4AuthorizationCheckpointError as exc:
            raise FolderM4AuthorizationError(
                "Protected Folder authorization checkpoint verification failed."
            ) from exc

    def _advance_monotonic_checkpoint(
        self,
        previous: FolderM4AuthorizationStoreTail | None,
        current: FolderM4AuthorizationStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if previous is None or current is None:
            raise FolderM4AuthorizationError(
                "Protected Folder authorization checkpoint state is unavailable."
            )
        try:
            checkpoint.advance(previous, current)
        except FolderM4AuthorizationCheckpointError as exc:
            raise FolderM4AuthorizationError(
                "Protected Folder authorization checkpoint advance failed."
            ) from exc

    def _event_mac(self, **values: object) -> str:
        ordered = (
            str(values["ordinal"]),
            str(values["event_type"]),
            str(values["authorization_ref"]),
            str(values["payload_json"]),
            str(values["object_digest"]),
            str(values["previous_mac"]),
            str(values["created_at"]),
        )
        material = b"".join(
            len(item.encode("utf-8")).to_bytes(8, "big") + item.encode("utf-8")
            for item in ordered
        )
        return hmac.new(self._key, material, hashlib.sha256).hexdigest()

    def _prepare_paths(self) -> None:
        if not self._path.is_absolute() or not self._key_path.is_absolute():
            raise FolderM4AuthorizationError("Protected Folder store paths are unsafe.")
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
        except FolderM4AuthorizationError:
            raise
        except OSError as exc:
            raise FolderM4AuthorizationError("Protected Folder database path is unsafe.") from exc

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
                raise FolderM4AuthorizationError("Protected Folder HMAC key is invalid.")
            return key
        except FolderM4AuthorizationError:
            raise
        except OSError as exc:
            raise FolderM4AuthorizationError("Protected Folder HMAC key is invalid.") from exc

    def _connect(self) -> sqlite3.Connection:
        _assert_owner_only(self._path.parent, directory=True)
        _assert_owner_only(self._path, directory=False)
        connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    @staticmethod
    def _initialize_schema(connection: sqlite3.Connection) -> None:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current not in {0, _SCHEMA_VERSION}:
            raise FolderM4AuthorizationError("Protected Folder store schema is unsupported.")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS folder_m4_events(
                ordinal INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                authorization_ref TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                object_digest TEXT NOT NULL,
                previous_mac TEXT NOT NULL,
                record_mac TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        if current == 0:
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def _now(self, supplied: int | None) -> int:
        value = self._clock() if supplied is None else supplied
        if type(value) is not int or value < 0:
            raise FolderM4AuthorizationError("Trusted M4 clock is invalid.")
        return value


class ProtectedFolderM4AuthorizationVerifier:
    """Kernel verifier bound to a requester from an authenticated transport."""

    def __init__(
        self,
        store: PersistentFolderM4AuthorizationStore,
        authenticated_requester_digest: str,
    ) -> None:
        if not _is_digest(authenticated_requester_digest):
            raise FolderM4AuthorizationError("Trusted requester identity is invalid.")
        self._store = store
        self._requester = authenticated_requester_digest

    def verify(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        now_epoch: int,
    ) -> None:
        self._store.consume(
            plan,
            authorization,
            authenticated_requester_digest=self._requester,
            now_epoch=now_epoch,
        )


class ProtectedPreparedFolderActionResolver:
    """Adapter resolver backed only by the signed owner-protected binding."""

    def __init__(self, store: PersistentFolderM4AuthorizationStore) -> None:
        self._store = store

    def resolve(self, plan: M4ExecutionPlan) -> PreparedChildFolderCreate:
        return self._store.resolve(plan)


def _binding_content(
    *,
    source_plan_digest: str,
    source_decision_ref: str,
    source_decision_digest: str,
    source_claim_digest: str,
    promotion_ref: str,
    promotion_digest: str,
    promotion_issuer_ref: str,
    promotion_policy_version: str,
    folder_name: str,
    parent_folder_id: int,
    plan: M4ExecutionPlan,
    authorization: M4ExecutionAuthorization,
) -> dict[str, CanonicalValue]:
    plan_content = dict(plan.canonical_content())
    plan_content["plan_digest"] = plan.plan_digest
    authorization_content = dict(authorization.canonical_content())
    authorization_content["authorization_digest"] = authorization.authorization_digest
    return {
        "authorization": authorization_content,
        "folder_name": folder_name,
        "parent_folder_id": parent_folder_id,
        "plan": plan_content,
        "promotion_digest": promotion_digest,
        "promotion_issuer_ref": promotion_issuer_ref,
        "promotion_policy_version": promotion_policy_version,
        "promotion_ref": promotion_ref,
        "source_claim_digest": source_claim_digest,
        "source_decision_digest": source_decision_digest,
        "source_decision_ref": source_decision_ref,
        "source_plan_digest": source_plan_digest,
    }


def _binding_from_payload(payload: Mapping[str, object]) -> ProtectedChildFolderBinding:
    expected = {
        "authorization",
        "binding_digest",
        "folder_name",
        "parent_folder_id",
        "plan",
        "promotion_digest",
        "promotion_issuer_ref",
        "promotion_policy_version",
        "promotion_ref",
        "source_claim_digest",
        "source_decision_digest",
        "source_decision_ref",
        "source_plan_digest",
    }
    if set(payload) != expected:
        raise FolderM4AuthorizationError("Protected Folder issue payload shape is invalid.")
    raw_plan = payload["plan"]
    raw_auth = payload["authorization"]
    if not isinstance(raw_plan, Mapping) or not isinstance(raw_auth, Mapping):
        raise FolderM4AuthorizationError("Protected Folder issue payload is invalid.")
    try:
        compensation = raw_plan.get("compensation_ref")
        if compensation is not None and not isinstance(compensation, str):
            raise FolderM4AuthorizationError("Protected Folder plan payload is invalid.")
        plan = M4ExecutionPlan(
            plan_ref=_payload_str(raw_plan, "plan_ref"),
            revision=_payload_int(raw_plan, "revision"),
            action_id=_payload_str(raw_plan, "action_id"),
            action_version=_payload_str(raw_plan, "action_version"),
            adapter_ref=_payload_str(raw_plan, "adapter_ref"),
            target_ref=_payload_str(raw_plan, "target_ref"),
            requester_digest=_payload_str(raw_plan, "requester_digest"),
            summary_digest=_payload_str(raw_plan, "summary_digest"),
            confirmation_digest=_payload_str(raw_plan, "confirmation_digest"),
            approval_digest=_payload_str(raw_plan, "approval_digest"),
            parameters_digest=_payload_str(raw_plan, "parameters_digest"),
            expected_current_digest=_payload_str(raw_plan, "expected_current_digest"),
            expected_state_digest=_payload_str(raw_plan, "expected_state_digest"),
            idempotency_digest=_payload_str(raw_plan, "idempotency_digest"),
            expires_at=_payload_int(raw_plan, "expires_at"),
            compensation_ref=compensation,
            plan_digest=_payload_str(raw_plan, "plan_digest"),
        )
        authorization = M4ExecutionAuthorization(
            authorization_ref=_payload_str(raw_auth, "authorization_ref"),
            plan_ref=_payload_str(raw_auth, "plan_ref"),
            plan_digest=_payload_str(raw_auth, "plan_digest"),
            requester_digest=_payload_str(raw_auth, "requester_digest"),
            confirmation_ref=_payload_str(raw_auth, "confirmation_ref"),
            confirmation_digest=_payload_str(raw_auth, "confirmation_digest"),
            approval_ref=_payload_str(raw_auth, "approval_ref"),
            approval_digest=_payload_str(raw_auth, "approval_digest"),
            approver_digest=_payload_str(raw_auth, "approver_digest"),
            issued_at=_payload_int(raw_auth, "issued_at"),
            expires_at=_payload_int(raw_auth, "expires_at"),
            one_time=_payload_bool(raw_auth, "one_time"),
            execution_authorized=_payload_bool(raw_auth, "execution_authorized"),
            authorization_digest=_payload_str(raw_auth, "authorization_digest"),
        )
        return ProtectedChildFolderBinding(
            source_plan_digest=cast(str, payload["source_plan_digest"]),
            source_decision_ref=cast(str, payload["source_decision_ref"]),
            source_decision_digest=cast(str, payload["source_decision_digest"]),
            source_claim_digest=cast(str, payload["source_claim_digest"]),
            promotion_ref=cast(str, payload["promotion_ref"]),
            promotion_digest=cast(str, payload["promotion_digest"]),
            promotion_issuer_ref=cast(str, payload["promotion_issuer_ref"]),
            promotion_policy_version=cast(str, payload["promotion_policy_version"]),
            folder_name=cast(str, payload["folder_name"]),
            parent_folder_id=cast(int, payload["parent_folder_id"]),
            plan=plan,
            authorization=authorization,
            binding_digest=cast(str, payload["binding_digest"]),
        )
    except (TypeError, ValueError) as exc:
        raise FolderM4AuthorizationError("Protected Folder issue payload is invalid.") from exc


def _payload_str(payload: Mapping[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise FolderM4AuthorizationError("Protected Folder payload field is invalid.")
    return value


def _payload_int(payload: Mapping[str, object], field: str) -> int:
    value = payload.get(field)
    if type(value) is not int:
        raise FolderM4AuthorizationError("Protected Folder payload field is invalid.")
    return value


def _payload_bool(payload: Mapping[str, object], field: str) -> bool:
    value = payload.get(field)
    if type(value) is not bool:
        raise FolderM4AuthorizationError("Protected Folder payload field is invalid.")
    return value


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_ref(value: object) -> bool:
    return isinstance(value, str) and _REF.fullmatch(value) is not None


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise FolderM4AuthorizationError("Protected Folder path contains a symlink.")


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    details = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(details.st_mode) or stat.S_IMODE(details.st_mode) != (
        0o700 if directory else 0o600
    ):
        raise FolderM4AuthorizationError("Protected Folder path permissions are unsafe.")


def _load_owner_key(path: Path, label: str) -> bytes:
    try:
        if not path.is_absolute():
            raise FolderM4AuthorizationError(f"{label} HMAC key path is unsafe.")
        _assert_no_symlink_components(path.parent)
        _assert_owner_only(path.parent, directory=True)
        _assert_owner_only(path, directory=False)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            key = os.read(descriptor, 129)
        finally:
            os.close(descriptor)
        if not 32 <= len(key) <= 128:
            raise FolderM4AuthorizationError(f"{label} HMAC key is invalid.")
        return key
    except FolderM4AuthorizationError:
        raise
    except OSError as exc:
        raise FolderM4AuthorizationError(f"{label} HMAC key is invalid.") from exc


__all__ = [
    "FolderM4AuthorizationCheckpointError",
    "FolderM4AuthorizationError",
    "FolderM4AuthorizationStoreTail",
    "MonotonicFolderM4AuthorizationCheckpoint",
    "PersistentFolderM4AuthorizationStore",
    "PersistentFolderM4PromotionAuthority",
    "ProtectedChildFolderBinding",
    "ProtectedFolderM4AuthorizationVerifier",
    "ProtectedPlanningChainReader",
    "ProtectedPreparedFolderActionResolver",
    "TrustedFolderM4PromotionDecision",
]
