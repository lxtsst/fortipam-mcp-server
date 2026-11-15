"""Requester/approver separation and one-time receipt for V4 M3."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import hashlib
import hmac
from typing import Protocol, runtime_checkable

from .canonical import CanonicalValue, canonical_digest, canonical_json
from .engine import ReferenceIssuer
from .models import (
    AuthenticatedRequester,
    PreparedPlan,
    PlanningContractError,
    require_code,
    require_digest,
    require_ref,
    require_version,
)
from .policy import PlanPolicyDecision


class ApprovalDenied(PlanningContractError):
    """Raised when the M3 approval gate fails closed."""


APPROVAL_RECEIPT_AUTHENTICATOR_REF = "v4-approval-receipt-hmac-v1"
APPROVAL_RECEIPT_MAC_DOMAIN = "v4-plan-approval-receipt-v1"
MIN_APPROVAL_RECEIPT_KEY_BYTES = 32
MAX_APPROVAL_RECEIPT_KEY_BYTES = 4096


@runtime_checkable
class ApprovalReceiptAuthenticationAuthority(Protocol):
    """Authenticate approval receipts without requiring in-process key access."""

    authority_ref: str

    def mac(self, receipt_digest: str) -> str: ...

    def uses_key_material(self, candidate: bytes) -> bool: ...

    def verify(self, receipt: ApprovalReceipt) -> bool: ...


class ApprovalReceiptAuthenticator:
    """Authenticate approval receipts under a dedicated non-store HMAC key."""

    authority_ref = APPROVAL_RECEIPT_AUTHENTICATOR_REF

    def __init__(self, key: bytes) -> None:
        if (
            type(key) is not bytes
            or not MIN_APPROVAL_RECEIPT_KEY_BYTES
            <= len(key)
            <= MAX_APPROVAL_RECEIPT_KEY_BYTES
        ):
            raise PlanningContractError("Approval receipt HMAC key is invalid.")
        self._key = key

    def mac(self, receipt_digest: str) -> str:
        require_digest(receipt_digest, "receipt_digest")
        payload = (
            APPROVAL_RECEIPT_MAC_DOMAIN.encode("ascii")
            + b"\x00"
            + canonical_json({"receipt_digest": receipt_digest}).encode("ascii")
        )
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def uses_key_material(self, candidate: bytes) -> bool:
        """Return only whether trusted composition reused this exact key."""

        return type(candidate) is bytes and hmac.compare_digest(self._key, candidate)

    def verify(self, receipt: ApprovalReceipt) -> bool:
        if (
            receipt.authenticator_ref != self.authority_ref
            or receipt.receipt_mac is None
        ):
            return False
        return hmac.compare_digest(
            self.mac(receipt.receipt_digest),
            receipt.receipt_mac,
        )


@dataclass(frozen=True, slots=True)
class AuthenticatedApprover:
    subject_ref: str
    principal_class: str = "approver"
    identity_authority_ref: str | None = None
    subject_namespace: str | None = None

    def __post_init__(self) -> None:
        require_ref(self.subject_ref, "approver subject_ref")
        if self.principal_class != "approver":
            raise PlanningContractError("M3 approval requires an authenticated approver.")
        if (self.identity_authority_ref is None) is not (
            self.subject_namespace is None
        ):
            raise PlanningContractError("Approver identity binding must be complete.")
        if (
            self.identity_authority_ref is not None
            and self.subject_namespace is not None
        ):
            require_ref(
                self.identity_authority_ref,
                "approver identity_authority_ref",
            )
            require_ref(self.subject_namespace, "approver subject_namespace")

    @property
    def digest(self) -> str:
        content: dict[str, CanonicalValue] = {
            "principal_class": self.principal_class,
            "subject_ref": self.subject_ref,
        }
        if self.identity_authority_ref is not None:
            content["identity_authority_ref"] = self.identity_authority_ref
            content["subject_namespace"] = self.subject_namespace
        return canonical_digest(content)

    @property
    def identity_digest(self) -> str | None:
        """Return a comparable human-identity digest only for a full binding."""

        if self.identity_authority_ref is None or self.subject_namespace is None:
            return None
        return canonical_digest(
            {
                "identity_authority_ref": self.identity_authority_ref,
                "subject_namespace": self.subject_namespace,
                "subject_ref": self.subject_ref,
            }
        )


@dataclass(frozen=True, slots=True)
class ApproverAuthorizationDecision:
    """Exact value-free delegation decision from a trusted approval authority."""

    authorization_ref: str
    authority_ref: str
    plan_ref: str
    plan_digest: str
    policy_decision_ref: str
    policy_decision_digest: str
    policy_version: str
    requester_digest: str
    requester_identity_digest: str
    approver_digest: str
    approver_identity_digest: str
    identity_authority_ref: str
    subject_namespace: str
    environment_digest: str
    scope_digest: str
    action_set_digest: str
    delegation_digest: str
    delegated_role: str
    approval_class: str
    separation_required: bool
    executor_separation_required: bool
    authorized: bool
    execution_authorized: bool
    checked_at: int
    expires_at: int
    authorization_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "action_set_digest": self.action_set_digest,
            "approval_class": self.approval_class,
            "approver_digest": self.approver_digest,
            "approver_identity_digest": self.approver_identity_digest,
            "authority_ref": self.authority_ref,
            "authorization_ref": self.authorization_ref,
            "authorized": self.authorized,
            "checked_at": self.checked_at,
            "delegated_role": self.delegated_role,
            "delegation_digest": self.delegation_digest,
            "environment_digest": self.environment_digest,
            "execution_authorized": self.execution_authorized,
            "executor_separation_required": self.executor_separation_required,
            "expires_at": self.expires_at,
            "identity_authority_ref": self.identity_authority_ref,
            "plan_digest": self.plan_digest,
            "plan_ref": self.plan_ref,
            "policy_decision_digest": self.policy_decision_digest,
            "policy_decision_ref": self.policy_decision_ref,
            "policy_version": self.policy_version,
            "requester_digest": self.requester_digest,
            "requester_identity_digest": self.requester_identity_digest,
            "scope_digest": self.scope_digest,
            "separation_required": self.separation_required,
            "subject_namespace": self.subject_namespace,
        }

    def __post_init__(self) -> None:
        for field, value in (
            ("authorization_ref", self.authorization_ref),
            ("authority_ref", self.authority_ref),
            ("plan_ref", self.plan_ref),
            ("policy_decision_ref", self.policy_decision_ref),
            ("identity_authority_ref", self.identity_authority_ref),
            ("subject_namespace", self.subject_namespace),
        ):
            require_ref(value, field)
        for field, value in (
            ("plan_digest", self.plan_digest),
            ("policy_decision_digest", self.policy_decision_digest),
            ("requester_digest", self.requester_digest),
            ("requester_identity_digest", self.requester_identity_digest),
            ("approver_digest", self.approver_digest),
            ("approver_identity_digest", self.approver_identity_digest),
            ("environment_digest", self.environment_digest),
            ("scope_digest", self.scope_digest),
            ("action_set_digest", self.action_set_digest),
            ("delegation_digest", self.delegation_digest),
            ("authorization_digest", self.authorization_digest),
        ):
            require_digest(value, field)
        require_version(self.policy_version, "policy_version")
        require_code(self.delegated_role, "delegated_role")
        require_code(self.approval_class, "approval_class")
        if (
            self.delegated_role != "independent_approver"
            or self.approval_class != "independent_approval"
            or self.separation_required is not True
            or self.executor_separation_required is not True
            or self.authorized is not True
            or self.execution_authorized is not False
            or self.requester_digest == self.approver_digest
            or self.requester_identity_digest == self.approver_identity_digest
            or type(self.checked_at) is not int
            or type(self.expires_at) is not int
            or self.checked_at < 0
            or self.expires_at <= self.checked_at
        ):
            raise PlanningContractError(
                "Approver authorization widened authority or separation."
            )
        if self.authorization_digest != canonical_digest(self.canonical_content()):
            raise PlanningContractError(
                "Approver authorization decision digest is invalid."
            )


@runtime_checkable
class ApproverAuthorizationAuthority(Protocol):
    """Trusted non-MCP boundary for exact approver delegation decisions."""

    authority_ref: str

    def authorize(
        self,
        plan: PreparedPlan,
        decision: PlanPolicyDecision,
        requester: AuthenticatedRequester,
        approver: AuthenticatedApprover,
        *,
        now_epoch: int,
    ) -> ApproverAuthorizationDecision: ...


def approval_action_set_digest(plan: PreparedPlan) -> str:
    """Digest the ordered exact action-family/version set of one plan."""

    return approval_action_bindings_digest(
        tuple(
            (line.action_family_ref, line.action_family_version)
            for line in plan.lines
        )
    )


def approval_action_bindings_digest(
    action_bindings: Sequence[tuple[str, str]],
) -> str:
    """Validate and digest one ordered bounded delegated action set."""

    if (
        isinstance(action_bindings, (str, bytes, bytearray))
        or not isinstance(action_bindings, Sequence)
        or not 1 <= len(action_bindings) <= 19
    ):
        raise PlanningContractError("Approval action binding set is invalid.")
    values: list[dict[str, CanonicalValue]] = []
    for binding in action_bindings:
        if not isinstance(binding, tuple) or len(binding) != 2:
            raise PlanningContractError("Approval action binding set is invalid.")
        action_family_ref, action_family_version = binding
        if type(action_family_ref) is not str or type(action_family_version) is not str:
            raise PlanningContractError("Approval action binding set is invalid.")
        values.append(
            {
                "action_family_ref": require_ref(
                    action_family_ref,
                    "approval action_family_ref",
                ),
                "action_family_version": require_version(
                    action_family_version,
                    "approval action_family_version",
                ),
            }
        )
    return canonical_digest(values)


def approval_delegation_digest(
    plan: PreparedPlan,
    decision: PlanPolicyDecision,
    approver: AuthenticatedApprover,
) -> str:
    """Digest the exact scope a trusted authority must delegate."""

    approver_identity_digest = approver.identity_digest
    if (
        approver_identity_digest is None
        or approver.identity_authority_ref is None
        or approver.subject_namespace is None
    ):
        raise PlanningContractError("Approver identity binding is unavailable.")
    return canonical_digest(
        {
            "action_set_digest": approval_action_set_digest(plan),
            "approval_class": decision.approval_class,
            "approver_identity_digest": approver_identity_digest,
            "environment_digest": canonical_digest(plan.environment_ref),
            "identity_authority_ref": approver.identity_authority_ref,
            "policy_version": decision.policy_version,
            "scope_digest": canonical_digest(plan.scope_ref),
            "subject_namespace": approver.subject_namespace,
        }
    )


@dataclass(frozen=True, slots=True)
class ApprovalReceipt:
    receipt_ref: str
    decision_ref: str
    decision_digest: str
    plan_ref: str
    plan_digest: str
    requester_digest: str
    approver_digest: str
    issued_at: int
    expires_at: int
    one_time: bool
    execution_authorized: bool
    receipt_digest: str
    authenticator_ref: str | None = None
    receipt_mac: str | None = None
    approver_authority_ref: str | None = None
    approver_authorization_digest: str | None = None
    policy_version: str | None = None
    approval_nonce_digest: str | None = None

    def canonical_content(self) -> dict[str, CanonicalValue]:
        content: dict[str, CanonicalValue] = {
            "approver_digest": self.approver_digest,
            "decision_digest": self.decision_digest,
            "decision_ref": self.decision_ref,
            "execution_authorized": self.execution_authorized,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "one_time": self.one_time,
            "plan_digest": self.plan_digest,
            "plan_ref": self.plan_ref,
            "receipt_ref": self.receipt_ref,
            "requester_digest": self.requester_digest,
        }
        if self.authenticator_ref is not None:
            content["authenticator_ref"] = self.authenticator_ref
        if self.approver_authority_ref is not None:
            content["approval_nonce_digest"] = self.approval_nonce_digest
            content["approver_authority_ref"] = self.approver_authority_ref
            content[
                "approver_authorization_digest"
            ] = self.approver_authorization_digest
            content["policy_version"] = self.policy_version
        return content

    def __post_init__(self) -> None:
        for field, value in (
            ("receipt_ref", self.receipt_ref),
            ("decision_ref", self.decision_ref),
            ("plan_ref", self.plan_ref),
        ):
            require_ref(value, field)
        for field, value in (
            ("decision_digest", self.decision_digest),
            ("plan_digest", self.plan_digest),
            ("requester_digest", self.requester_digest),
            ("approver_digest", self.approver_digest),
            ("receipt_digest", self.receipt_digest),
        ):
            require_digest(value, field)
        if (self.authenticator_ref is None) is not (self.receipt_mac is None):
            raise PlanningContractError(
                "Approval receipt authentication binding is incomplete."
            )
        if self.authenticator_ref is not None and self.receipt_mac is not None:
            require_ref(self.authenticator_ref, "authenticator_ref")
            require_digest(self.receipt_mac, "receipt_mac")
        authorization_binding = (
            self.approver_authority_ref,
            self.approver_authorization_digest,
            self.policy_version,
            self.approval_nonce_digest,
        )
        if any(value is not None for value in authorization_binding) and not all(
            value is not None for value in authorization_binding
        ):
            raise PlanningContractError(
                "Approver authorization binding is incomplete."
            )
        if self.approver_authority_ref is not None:
            assert self.approver_authorization_digest is not None
            assert self.policy_version is not None
            assert self.approval_nonce_digest is not None

            require_ref(self.approver_authority_ref, "approver_authority_ref")
            require_digest(
                self.approver_authorization_digest,
                "approver_authorization_digest",
            )
            require_version(self.policy_version, "policy_version")
            require_digest(self.approval_nonce_digest, "approval_nonce_digest")
            if self.authenticator_ref is None:
                raise PlanningContractError(
                    "Approver authorization requires an authenticated receipt."
                )
        if (
            self.requester_digest == self.approver_digest
            or self.one_time is not True
            or self.execution_authorized is not False
            or self.expires_at <= self.issued_at
        ):
            raise PlanningContractError("M3 approval receipt widened authority or separation.")
        if self.receipt_digest != canonical_digest(self.canonical_content()):
            raise PlanningContractError("M3 approval receipt digest is invalid.")


@dataclass(frozen=True, slots=True)
class PlanGateResult:
    plan_ref: str
    plan_digest: str
    approval_validated: bool
    ready_for_dispatch: bool
    execution_authorized: bool
    blocker_codes: tuple[str, ...]


class M3ApprovalGate:
    """Issue and consume approval evidence while keeping dispatch denied."""

    def __init__(
        self,
        issuer: ReferenceIssuer,
        *,
        receipt_authenticator: ApprovalReceiptAuthenticationAuthority | None = None,
        approver_authorizer: ApproverAuthorizationAuthority | None = None,
    ) -> None:
        if approver_authorizer is not None:
            if receipt_authenticator is None:
                raise PlanningContractError(
                    "Approver authorization requires a receipt authenticator."
                )
            try:
                require_ref(
                    approver_authorizer.authority_ref,
                    "approver authorization authority_ref",
                )
            except (AttributeError, PlanningContractError) as exc:
                raise PlanningContractError(
                    "Approver authorization authority is invalid."
                ) from exc
            if not callable(getattr(approver_authorizer, "authorize", None)):
                raise PlanningContractError(
                    "Approver authorization authority is invalid."
                )
        self._issuer = issuer
        self._receipt_authenticator = receipt_authenticator
        self._approver_authorizer = approver_authorizer
        self._approved_decisions: set[str] = set()
        self._consumed_receipts: set[str] = set()

    def approve(
        self,
        decision: PlanPolicyDecision,
        approver: AuthenticatedApprover,
        *,
        now_epoch: int,
        plan: PreparedPlan | None = None,
        requester: AuthenticatedRequester | None = None,
    ) -> ApprovalReceipt:
        if now_epoch < decision.issued_at or now_epoch >= decision.expires_at:
            raise ApprovalDenied("Policy decision is outside its active lifetime.")
        if decision.execution_authorized or decision.outcome != "requires_independent_approval":
            raise ApprovalDenied("Policy decision cannot enter the approval gate.")
        if (
            approver.digest == decision.requester_digest
            or canonical_digest(approver.subject_ref)
            == decision.requester_subject_digest
        ):
            raise ApprovalDenied("Requester and approver separation is required.")
        if decision.decision_ref in self._approved_decisions:
            raise ApprovalDenied("Policy decision already produced an approval receipt.")
        authorization = self._authorize_approver(
            decision,
            approver,
            plan=plan,
            requester=requester,
            now_epoch=now_epoch,
        )
        receipt_ref = self._issuer.issue("approval-receipt")
        expires_at = min(
            decision.expires_at,
            authorization.expires_at if authorization is not None else decision.expires_at,
            now_epoch + 180,
        )
        content: dict[str, CanonicalValue] = {
            "approver_digest": approver.digest,
            "decision_digest": decision.decision_digest,
            "decision_ref": decision.decision_ref,
            "execution_authorized": False,
            "expires_at": expires_at,
            "issued_at": now_epoch,
            "one_time": True,
            "plan_digest": decision.plan_digest,
            "plan_ref": decision.plan_ref,
            "receipt_ref": receipt_ref,
            "requester_digest": decision.requester_digest,
        }
        authenticator_ref = None
        approver_authority_ref = None
        approver_authorization_digest = None
        policy_version = None
        approval_nonce_digest = None
        if self._receipt_authenticator is not None:
            authenticator_ref = self._receipt_authenticator.authority_ref
            content["authenticator_ref"] = authenticator_ref
        if authorization is not None:
            approver_authority_ref = authorization.authority_ref
            approver_authorization_digest = authorization.authorization_digest
            policy_version = decision.policy_version
            approval_nonce_digest = canonical_digest(
                self._issuer.issue("approval-nonce")
            )
            content.update(
                {
                    "approval_nonce_digest": approval_nonce_digest,
                    "approver_authority_ref": approver_authority_ref,
                    "approver_authorization_digest": approver_authorization_digest,
                    "policy_version": policy_version,
                }
            )
        receipt_digest = canonical_digest(content)
        receipt = ApprovalReceipt(
            receipt_ref=receipt_ref,
            decision_ref=decision.decision_ref,
            decision_digest=decision.decision_digest,
            plan_ref=decision.plan_ref,
            plan_digest=decision.plan_digest,
            requester_digest=decision.requester_digest,
            approver_digest=approver.digest,
            issued_at=now_epoch,
            expires_at=expires_at,
            one_time=True,
            execution_authorized=False,
            receipt_digest=receipt_digest,
            authenticator_ref=authenticator_ref,
            receipt_mac=(
                self._receipt_authenticator.mac(receipt_digest)
                if self._receipt_authenticator is not None
                else None
            ),
            approver_authority_ref=approver_authority_ref,
            approver_authorization_digest=approver_authorization_digest,
            policy_version=policy_version,
            approval_nonce_digest=approval_nonce_digest,
        )
        self._approved_decisions.add(decision.decision_ref)
        return receipt

    def _authorize_approver(
        self,
        decision: PlanPolicyDecision,
        approver: AuthenticatedApprover,
        *,
        plan: PreparedPlan | None,
        requester: AuthenticatedRequester | None,
        now_epoch: int,
    ) -> ApproverAuthorizationDecision | None:
        authority = self._approver_authorizer
        if authority is None:
            return None
        if plan is None or requester is None:
            raise ApprovalDenied("Exact approver authorization context is unavailable.")
        requester_identity_digest = requester.identity_digest
        approver_identity_digest = approver.identity_digest
        if (
            requester_identity_digest is None
            or approver_identity_digest is None
            or requester.identity_authority_ref != approver.identity_authority_ref
            or requester.subject_namespace != approver.subject_namespace
        ):
            raise ApprovalDenied("Comparable approver identity binding is unavailable.")
        if (
            plan.plan_ref != decision.plan_ref
            or plan.plan_digest != decision.plan_digest
            or plan.requester_digest != requester.digest
            or decision.requester_digest != requester.digest
        ):
            raise ApprovalDenied("Approver authorization context is not exact.")
        try:
            authorization = authority.authorize(
                plan,
                decision,
                requester,
                approver,
                now_epoch=now_epoch,
            )
        except PlanningContractError as exc:
            raise ApprovalDenied("Approver authorization is unavailable.") from exc
        if not isinstance(authorization, ApproverAuthorizationDecision):
            raise ApprovalDenied("Approver authorization decision is invalid.")
        if (
            authorization.authority_ref != authority.authority_ref
            or authorization.plan_ref != plan.plan_ref
            or authorization.plan_digest != plan.plan_digest
            or authorization.policy_decision_ref != decision.decision_ref
            or authorization.policy_decision_digest != decision.decision_digest
            or authorization.policy_version != decision.policy_version
            or authorization.requester_digest != requester.digest
            or authorization.requester_identity_digest
            != requester_identity_digest
            or authorization.approver_digest != approver.digest
            or authorization.approver_identity_digest
            != approver_identity_digest
            or authorization.identity_authority_ref
            != approver.identity_authority_ref
            or authorization.subject_namespace != approver.subject_namespace
            or authorization.environment_digest
            != canonical_digest(plan.environment_ref)
            or authorization.scope_digest != canonical_digest(plan.scope_ref)
            or authorization.action_set_digest != approval_action_set_digest(plan)
            or authorization.delegation_digest
            != approval_delegation_digest(plan, decision, approver)
            or authorization.approval_class != decision.approval_class
            or authorization.checked_at != now_epoch
            or authorization.expires_at > decision.expires_at
            or authorization.expires_at <= now_epoch
        ):
            raise ApprovalDenied("Approver authorization decision is not exact.")
        return authorization

    def claim_for_plan(
        self,
        receipt: ApprovalReceipt,
        plan: PreparedPlan,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> PlanGateResult:
        if self._receipt_authenticator is None:
            if receipt.authenticator_ref is not None:
                raise ApprovalDenied("Approval receipt authenticator is unavailable.")
        elif not self._receipt_authenticator.verify(receipt):
            raise ApprovalDenied("Approval receipt authenticity is invalid.")
        if now_epoch < receipt.issued_at or now_epoch >= receipt.expires_at:
            raise ApprovalDenied("Approval receipt is outside its active lifetime.")
        if receipt.receipt_ref in self._consumed_receipts:
            raise ApprovalDenied("Approval receipt was replayed.")
        if (
            receipt.plan_ref != plan.plan_ref
            or receipt.plan_digest != plan.plan_digest
            or receipt.requester_digest != requester.digest
            or requester.digest != plan.requester_digest
            or now_epoch >= plan.expires_at
        ):
            raise ApprovalDenied("Approval receipt is not bound to the exact active plan.")
        self._consumed_receipts.add(receipt.receipt_ref)
        return PlanGateResult(
            plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest,
            approval_validated=True,
            ready_for_dispatch=False,
            execution_authorized=False,
            blocker_codes=("adapter_registry_unbound", "plan_non_dispatchable"),
        )


__all__ = [
    "APPROVAL_RECEIPT_AUTHENTICATOR_REF",
    "APPROVAL_RECEIPT_MAC_DOMAIN",
    "ApprovalDenied",
    "ApproverAuthorizationAuthority",
    "ApproverAuthorizationDecision",
    "ApprovalReceipt",
    "ApprovalReceiptAuthenticator",
    "ApprovalReceiptAuthenticationAuthority",
    "AuthenticatedApprover",
    "M3ApprovalGate",
    "PlanGateResult",
    "approval_action_bindings_digest",
    "approval_action_set_digest",
    "approval_delegation_digest",
]
