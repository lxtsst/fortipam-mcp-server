"""Human-intent confirmation records for the non-executable V4 planner.

This module contains only bounded C0-C2/C4 references and digests.  It does not
authenticate a browser, parse an MCP request, load C3 material, contact a
product, approve a plan, or authorize execution.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac

from .canonical import CanonicalValue, canonical_digest, canonical_json
from .models import PlanningContractError, require_digest, require_ref


PLAN_CONFIRMATION_SCOPE = "fortipam:plan"
CONFIRMATION_RECEIPT_MAC_DOMAIN = "v4-intent-confirmation-receipt-v1"
MIN_CONFIRMATION_KEY_BYTES = 32
MAX_CONFIRMATION_KEY_BYTES = 128


class IntentConfirmationError(PlanningContractError):
    """Stable failure for a malformed or untrusted confirmation record."""


def _require_epoch(value: int, field: str) -> int:
    if type(value) is not int or value < 0:
        raise IntentConfirmationError(f"{field} must be a non-negative integer.")
    return value


def _require_scope(value: str) -> str:
    if value != PLAN_CONFIRMATION_SCOPE:
        raise IntentConfirmationError("Human intent confirmation requires fortipam:plan.")
    return value


@dataclass(frozen=True, slots=True)
class IntentConfirmationChallenge:
    """One opaque, expiring invitation to review an exact stored Summary."""

    challenge_ref: str
    challenge_token_digest: str
    requester_digest: str
    principal_namespace_digest: str
    audience_ref: str
    summary_ref: str
    summary_revision: int
    summary_digest: str
    required_scope: str
    issued_at: int
    expires_at: int
    record_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "audience_ref": self.audience_ref,
            "challenge_ref": self.challenge_ref,
            "challenge_token_digest": self.challenge_token_digest,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "principal_namespace_digest": self.principal_namespace_digest,
            "requester_digest": self.requester_digest,
            "required_scope": self.required_scope,
            "summary_digest": self.summary_digest,
            "summary_ref": self.summary_ref,
            "summary_revision": self.summary_revision,
        }

    def __post_init__(self) -> None:
        require_ref(self.challenge_ref, "challenge_ref")
        require_ref(self.audience_ref, "audience_ref")
        require_ref(self.summary_ref, "summary_ref")
        for field, value in (
            ("challenge_token_digest", self.challenge_token_digest),
            ("requester_digest", self.requester_digest),
            ("principal_namespace_digest", self.principal_namespace_digest),
            ("summary_digest", self.summary_digest),
            ("record_digest", self.record_digest),
        ):
            require_digest(value, field)
        _require_scope(self.required_scope)
        _require_epoch(self.issued_at, "issued_at")
        _require_epoch(self.expires_at, "expires_at")
        if self.summary_revision < 1 or self.expires_at <= self.issued_at:
            raise IntentConfirmationError("Confirmation challenge lifetime is invalid.")
        if self.record_digest != canonical_digest(self.canonical_content()):
            raise IntentConfirmationError("Confirmation challenge digest is invalid.")


@dataclass(frozen=True, slots=True)
class IntentReauthenticationRecord:
    """Password-reauthentication evidence without a password or raw session."""

    reauthentication_ref: str
    reauthentication_session_digest: str
    challenge_ref: str
    challenge_digest: str
    principal_namespace_digest: str
    required_scope: str
    authenticated_at: int
    expires_at: int
    record_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "authenticated_at": self.authenticated_at,
            "challenge_digest": self.challenge_digest,
            "challenge_ref": self.challenge_ref,
            "expires_at": self.expires_at,
            "principal_namespace_digest": self.principal_namespace_digest,
            "reauthentication_ref": self.reauthentication_ref,
            "reauthentication_session_digest": self.reauthentication_session_digest,
            "required_scope": self.required_scope,
        }

    def __post_init__(self) -> None:
        require_ref(self.reauthentication_ref, "reauthentication_ref")
        require_ref(self.challenge_ref, "challenge_ref")
        for field, value in (
            ("reauthentication_session_digest", self.reauthentication_session_digest),
            ("challenge_digest", self.challenge_digest),
            ("principal_namespace_digest", self.principal_namespace_digest),
            ("record_digest", self.record_digest),
        ):
            require_digest(value, field)
        _require_scope(self.required_scope)
        _require_epoch(self.authenticated_at, "authenticated_at")
        _require_epoch(self.expires_at, "expires_at")
        if self.expires_at <= self.authenticated_at:
            raise IntentConfirmationError("Reauthentication lifetime is invalid.")
        if self.record_digest != canonical_digest(self.canonical_content()):
            raise IntentConfirmationError("Reauthentication record digest is invalid.")


@dataclass(frozen=True, slots=True)
class IntentConfirmationReceipt:
    """Independently MAC-authenticated affirm/deny receipt.

    This receipt confirms intent only.  It is not an approval or execution
    receipt, and its invariant permanently keeps execution authorization false.
    """

    receipt_ref: str
    challenge_ref: str
    challenge_digest: str
    reauthentication_ref: str
    reauthentication_digest: str
    requester_digest: str
    principal_namespace_digest: str
    audience_ref: str
    summary_ref: str
    summary_revision: int
    summary_digest: str
    decision: str
    interaction_ref: str
    nonce_digest: str
    required_scope: str
    issued_at: int
    expires_at: int
    one_time: bool
    execution_authorized: bool
    receipt_digest: str
    receipt_mac: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "audience_ref": self.audience_ref,
            "challenge_digest": self.challenge_digest,
            "challenge_ref": self.challenge_ref,
            "decision": self.decision,
            "execution_authorized": self.execution_authorized,
            "expires_at": self.expires_at,
            "interaction_ref": self.interaction_ref,
            "issued_at": self.issued_at,
            "nonce_digest": self.nonce_digest,
            "one_time": self.one_time,
            "principal_namespace_digest": self.principal_namespace_digest,
            "reauthentication_digest": self.reauthentication_digest,
            "reauthentication_ref": self.reauthentication_ref,
            "receipt_ref": self.receipt_ref,
            "requester_digest": self.requester_digest,
            "required_scope": self.required_scope,
            "summary_digest": self.summary_digest,
            "summary_ref": self.summary_ref,
            "summary_revision": self.summary_revision,
        }

    def __post_init__(self) -> None:
        for field, value in (
            ("receipt_ref", self.receipt_ref),
            ("challenge_ref", self.challenge_ref),
            ("reauthentication_ref", self.reauthentication_ref),
            ("audience_ref", self.audience_ref),
            ("summary_ref", self.summary_ref),
            ("interaction_ref", self.interaction_ref),
        ):
            require_ref(value, field)
        for field, value in (
            ("challenge_digest", self.challenge_digest),
            ("reauthentication_digest", self.reauthentication_digest),
            ("requester_digest", self.requester_digest),
            ("principal_namespace_digest", self.principal_namespace_digest),
            ("summary_digest", self.summary_digest),
            ("nonce_digest", self.nonce_digest),
            ("receipt_digest", self.receipt_digest),
            ("receipt_mac", self.receipt_mac),
        ):
            require_digest(value, field)
        _require_scope(self.required_scope)
        _require_epoch(self.issued_at, "issued_at")
        _require_epoch(self.expires_at, "expires_at")
        if self.decision not in {"affirm", "deny"}:
            raise IntentConfirmationError("Confirmation decision is invalid.")
        if (
            self.summary_revision < 1
            or self.expires_at <= self.issued_at
            or self.one_time is not True
            or self.execution_authorized is not False
        ):
            raise IntentConfirmationError("Confirmation receipt widened authority.")
        if self.receipt_digest != canonical_digest(self.canonical_content()):
            raise IntentConfirmationError("Confirmation receipt digest is invalid.")


@dataclass(frozen=True, slots=True)
class SummaryInvalidationRecord:
    """Persistent denial marker that prevents a denied Summary from progressing."""

    invalidation_ref: str
    receipt_ref: str
    receipt_digest: str
    summary_ref: str
    summary_revision: int
    summary_digest: str
    requester_digest: str
    reason_code: str
    invalidated_at: int
    record_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "invalidated_at": self.invalidated_at,
            "invalidation_ref": self.invalidation_ref,
            "reason_code": self.reason_code,
            "receipt_digest": self.receipt_digest,
            "receipt_ref": self.receipt_ref,
            "requester_digest": self.requester_digest,
            "summary_digest": self.summary_digest,
            "summary_ref": self.summary_ref,
            "summary_revision": self.summary_revision,
        }

    def __post_init__(self) -> None:
        require_ref(self.invalidation_ref, "invalidation_ref")
        require_ref(self.receipt_ref, "receipt_ref")
        require_ref(self.summary_ref, "summary_ref")
        for field, value in (
            ("receipt_digest", self.receipt_digest),
            ("summary_digest", self.summary_digest),
            ("requester_digest", self.requester_digest),
            ("record_digest", self.record_digest),
        ):
            require_digest(value, field)
        if self.reason_code != "requester_denied":
            raise IntentConfirmationError("Summary invalidation reason is invalid.")
        _require_epoch(self.invalidated_at, "invalidated_at")
        if self.summary_revision < 1:
            raise IntentConfirmationError("Summary invalidation revision is invalid.")
        if self.record_digest != canonical_digest(self.canonical_content()):
            raise IntentConfirmationError("Summary invalidation digest is invalid.")


@dataclass(frozen=True, slots=True)
class IntentConfirmationClaim:
    """Non-executing proof that one exact confirmation receipt was consumed."""

    claim_ref: str
    receipt_ref: str
    receipt_digest: str
    requester_digest: str
    principal_namespace_digest: str
    summary_ref: str
    summary_revision: int
    summary_digest: str
    decision: str
    claimed_at: int
    execution_authorized: bool
    record_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "claim_ref": self.claim_ref,
            "claimed_at": self.claimed_at,
            "decision": self.decision,
            "execution_authorized": self.execution_authorized,
            "principal_namespace_digest": self.principal_namespace_digest,
            "receipt_digest": self.receipt_digest,
            "receipt_ref": self.receipt_ref,
            "requester_digest": self.requester_digest,
            "summary_digest": self.summary_digest,
            "summary_ref": self.summary_ref,
            "summary_revision": self.summary_revision,
        }

    def __post_init__(self) -> None:
        require_ref(self.claim_ref, "claim_ref")
        require_ref(self.receipt_ref, "receipt_ref")
        require_ref(self.summary_ref, "summary_ref")
        for field, value in (
            ("receipt_digest", self.receipt_digest),
            ("requester_digest", self.requester_digest),
            ("principal_namespace_digest", self.principal_namespace_digest),
            ("summary_digest", self.summary_digest),
            ("record_digest", self.record_digest),
        ):
            require_digest(value, field)
        if self.decision not in {"affirm", "deny"}:
            raise IntentConfirmationError("Confirmation claim decision is invalid.")
        if self.summary_revision < 1 or self.execution_authorized is not False:
            raise IntentConfirmationError("Confirmation claim widened authority.")
        _require_epoch(self.claimed_at, "claimed_at")
        if self.record_digest != canonical_digest(self.canonical_content()):
            raise IntentConfirmationError("Confirmation claim digest is invalid.")


class ConfirmationReceiptAuthenticator:
    """Issue and verify receipt MACs under a dedicated local key."""

    def __init__(self, key: bytes) -> None:
        if type(key) is not bytes or not MIN_CONFIRMATION_KEY_BYTES <= len(key) <= MAX_CONFIRMATION_KEY_BYTES:
            raise IntentConfirmationError("Confirmation receipt HMAC key is invalid.")
        self._key = key

    def mac(self, receipt_digest: str) -> str:
        require_digest(receipt_digest, "receipt_digest")
        payload = (
            CONFIRMATION_RECEIPT_MAC_DOMAIN.encode("ascii")
            + b"\x00"
            + canonical_json({"receipt_digest": receipt_digest}).encode("ascii")
        )
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, receipt: IntentConfirmationReceipt) -> bool:
        expected = self.mac(receipt.receipt_digest)
        return hmac.compare_digest(expected, receipt.receipt_mac)


def build_challenge(**values: object) -> IntentConfirmationChallenge:
    """Build a digest-bound challenge from already validated bounded fields."""

    content = dict(values)
    content.pop("record_digest", None)
    return IntentConfirmationChallenge(
        **values,  # type: ignore[arg-type]
        record_digest=canonical_digest(content),
    )


def build_reauthentication(**values: object) -> IntentReauthenticationRecord:
    """Build a digest-bound reauthentication record without raw credentials."""

    content = dict(values)
    content.pop("record_digest", None)
    return IntentReauthenticationRecord(
        **values,  # type: ignore[arg-type]
        record_digest=canonical_digest(content),
    )


def build_receipt(
    authenticator: ConfirmationReceiptAuthenticator,
    **values: object,
) -> IntentConfirmationReceipt:
    """Build one independently authenticated intent-confirmation receipt."""

    content = dict(values)
    content.pop("receipt_digest", None)
    content.pop("receipt_mac", None)
    receipt_digest = canonical_digest(content)
    return IntentConfirmationReceipt(
        **values,  # type: ignore[arg-type]
        receipt_digest=receipt_digest,
        receipt_mac=authenticator.mac(receipt_digest),
    )


def build_invalidation(**values: object) -> SummaryInvalidationRecord:
    content = dict(values)
    content.pop("record_digest", None)
    return SummaryInvalidationRecord(
        **values,  # type: ignore[arg-type]
        record_digest=canonical_digest(content),
    )


def build_claim(**values: object) -> IntentConfirmationClaim:
    content = dict(values)
    content.pop("record_digest", None)
    return IntentConfirmationClaim(
        **values,  # type: ignore[arg-type]
        record_digest=canonical_digest(content),
    )


__all__ = [
    "CONFIRMATION_RECEIPT_MAC_DOMAIN",
    "ConfirmationReceiptAuthenticator",
    "IntentConfirmationChallenge",
    "IntentConfirmationClaim",
    "IntentConfirmationError",
    "IntentConfirmationReceipt",
    "IntentReauthenticationRecord",
    "PLAN_CONFIRMATION_SCOPE",
    "SummaryInvalidationRecord",
    "build_challenge",
    "build_claim",
    "build_invalidation",
    "build_reauthentication",
    "build_receipt",
]
