"""Fail-closed V4 M4 transaction-kernel contract.

This module is a local safety state machine, not a FortiPAM adapter.  It binds
an already prepared, immutable action plan to authenticated human intent,
independent approval, and a separate execution-authorization decision.  The
default adapter and authorization verifier deny every call.  A test adapter
may be injected to exercise the state machine without a product transport.

The kernel deliberately accepts only value-free digests and opaque registry
references.  It never accepts an endpoint, method, body, credential, Secret
value, or raw product response.
"""

from __future__ import annotations

from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
import re
import threading
import time
from typing import NoReturn, Protocol, SupportsIndex

from .canonical import CanonicalValue, canonical_digest


class M4ExecutionError(ValueError):
    """Base error for malformed or rejected M4 execution inputs."""


class M4AuthorizationDenied(M4ExecutionError):
    """Raised when trusted confirmation/approval/authorization is absent."""


class M4AuthorizationReplay(M4ExecutionError):
    """Raised when a one-time execution authorization is reused."""


class M4AdapterDenied(M4ExecutionError):
    """Raised by the default adapter boundary; it never contacts a device."""


class M4AdapterTimeout(RuntimeError):
    """A bounded adapter call timed out before its result was known."""


class M4AdapterAmbiguous(RuntimeError):
    """The adapter lost a result and external state is not yet known."""


class M4AdapterFailure(RuntimeError):
    """A declared adapter failure occurred before a successful mutation."""


class M4Outcome(StrEnum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    PRECONDITION_FAILED = "precondition_failed"
    EXECUTION_FAILED = "execution_failed"
    VERIFICATION_FAILED = "verification_failed"
    RECONCILIATION_REQUIRED = "reconciliation_required"


class M4Verification(StrEnum):
    NOT_STARTED = "not_started"
    VERIFIED = "verified"
    FAILED = "failed"
    UNKNOWN = "unknown"


class M4Compensation(StrEnum):
    NOT_REQUESTED = "not_requested"
    REQUIRED = "required"
    UNKNOWN = "unknown"
    VERIFIED = "verified"
    FAILED = "failed"


class M4ClaimState(StrEnum):
    NEW = "new"
    REPLAY = "replay"
    IN_PROGRESS = "in_progress"


_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_ACTION = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def _ref(value: str, field: str) -> str:
    if not isinstance(value, str) or _REF.fullmatch(value) is None:
        raise M4ExecutionError(f"{field} must be an opaque reference.")
    return value


def _digest(value: str, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise M4ExecutionError(f"{field} must be a SHA-256 digest.")
    return value


def _action(value: str, field: str) -> str:
    if not isinstance(value, str) or _ACTION.fullmatch(value) is None:
        raise M4ExecutionError(f"{field} must be a hyphenated action identifier.")
    return value


def _version(value: str, field: str) -> str:
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        raise M4ExecutionError(f"{field} must be a semantic version.")
    return value


@dataclass(frozen=True, slots=True)
class M4ExecutionPlan:
    """Immutable, one-target execution contract with no wire details."""

    plan_ref: str
    revision: int
    action_id: str
    action_version: str
    adapter_ref: str
    target_ref: str
    requester_digest: str
    summary_digest: str
    confirmation_digest: str
    approval_digest: str
    parameters_digest: str
    expected_current_digest: str
    expected_state_digest: str
    idempotency_digest: str
    expires_at: int
    compensation_ref: str | None
    plan_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "action_id": self.action_id,
            "action_version": self.action_version,
            "adapter_ref": self.adapter_ref,
            "approval_digest": self.approval_digest,
            "compensation_ref": self.compensation_ref,
            "confirmation_digest": self.confirmation_digest,
            "expected_current_digest": self.expected_current_digest,
            "expected_state_digest": self.expected_state_digest,
            "expires_at": self.expires_at,
            "idempotency_digest": self.idempotency_digest,
            "parameters_digest": self.parameters_digest,
            "plan_ref": self.plan_ref,
            "requester_digest": self.requester_digest,
            "revision": self.revision,
            "summary_digest": self.summary_digest,
            "target_ref": self.target_ref,
        }

    def __post_init__(self) -> None:
        _ref(self.plan_ref, "plan_ref")
        if type(self.revision) is not int or self.revision < 1:
            raise M4ExecutionError("plan revision is invalid.")
        _action(self.action_id, "action_id")
        _version(self.action_version, "action_version")
        _ref(self.adapter_ref, "adapter_ref")
        _ref(self.target_ref, "target_ref")
        for field, value in (
            ("requester_digest", self.requester_digest),
            ("summary_digest", self.summary_digest),
            ("confirmation_digest", self.confirmation_digest),
            ("approval_digest", self.approval_digest),
            ("parameters_digest", self.parameters_digest),
            ("expected_current_digest", self.expected_current_digest),
            ("expected_state_digest", self.expected_state_digest),
            ("idempotency_digest", self.idempotency_digest),
            ("plan_digest", self.plan_digest),
        ):
            _digest(value, field)
        if self.compensation_ref is not None:
            _ref(self.compensation_ref, "compensation_ref")
        if type(self.expires_at) is not int or self.expires_at <= 0:
            raise M4ExecutionError("plan expiry is invalid.")
        if self.plan_digest != canonical_digest(self.canonical_content()):
            raise M4ExecutionError("plan digest is invalid.")


@dataclass(frozen=True, slots=True)
class M4ExecutionAuthorization:
    """Separate, trusted execution authorization bound to all prior gates."""

    authorization_ref: str
    plan_ref: str
    plan_digest: str
    requester_digest: str
    confirmation_ref: str
    confirmation_digest: str
    approval_ref: str
    approval_digest: str
    approver_digest: str
    issued_at: int
    expires_at: int
    one_time: bool
    execution_authorized: bool
    authorization_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "approval_digest": self.approval_digest,
            "approval_ref": self.approval_ref,
            "approver_digest": self.approver_digest,
            "authorization_ref": self.authorization_ref,
            "confirmation_digest": self.confirmation_digest,
            "confirmation_ref": self.confirmation_ref,
            "execution_authorized": self.execution_authorized,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "one_time": self.one_time,
            "plan_digest": self.plan_digest,
            "plan_ref": self.plan_ref,
            "requester_digest": self.requester_digest,
        }

    def __post_init__(self) -> None:
        for field, value in (
            ("authorization_ref", self.authorization_ref),
            ("confirmation_ref", self.confirmation_ref),
            ("approval_ref", self.approval_ref),
        ):
            _ref(value, field)
        for field, value in (
            ("plan_digest", self.plan_digest),
            ("requester_digest", self.requester_digest),
            ("confirmation_digest", self.confirmation_digest),
            ("approval_digest", self.approval_digest),
            ("approver_digest", self.approver_digest),
            ("authorization_digest", self.authorization_digest),
        ):
            _digest(value, field)
        _ref(self.plan_ref, "plan_ref")
        if (
            type(self.issued_at) is not int
            or type(self.expires_at) is not int
            or self.expires_at <= self.issued_at
            or self.one_time is not True
            or self.execution_authorized is not True
            or self.requester_digest == self.approver_digest
        ):
            raise M4ExecutionError("execution authorization is invalid.")
        if self.authorization_digest != canonical_digest(self.canonical_content()):
            raise M4ExecutionError("execution authorization digest is invalid.")


class M4AuthorizationVerifier(Protocol):
    """Trusted service that verifies confirmation, approval, and authorization."""

    def verify(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        now_epoch: int,
    ) -> None: ...


class DenyAllM4AuthorizationVerifier:
    """Default boundary; no M4 execution authorization is configured."""

    def verify(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        now_epoch: int,
    ) -> None:
        del plan, authorization, now_epoch
        raise M4AuthorizationDenied("No trusted M4 authorization verifier is configured.")


class M4ExecutionAdapter(Protocol):
    """Fixed, action-specific adapter boundary returning only digests."""

    def read_current(self, plan: M4ExecutionPlan) -> str: ...

    def dispatch(self, plan: M4ExecutionPlan) -> None: ...

    def read_postcondition(self, plan: M4ExecutionPlan) -> str: ...


class DenyAllM4Adapter:
    """Default product boundary; it cannot contact FortiPAM."""

    @staticmethod
    def _deny() -> None:
        raise M4AdapterDenied("No M4 product adapter is enabled.")

    def read_current(self, plan: M4ExecutionPlan) -> str:
        del plan
        self._deny()
        raise AssertionError("unreachable")

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        del plan
        self._deny()

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        del plan
        self._deny()
        raise AssertionError("unreachable")


@dataclass(frozen=True, slots=True)
class M4ExecutionResult:
    outcome: M4Outcome
    verification: M4Verification
    compensation: M4Compensation
    idempotent_replay: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "compensation": self.compensation.value,
            "idempotent_replay": self.idempotent_replay,
            "outcome": self.outcome.value,
            "verification": self.verification.value,
        }


@dataclass(frozen=True, slots=True)
class M4AuditEvent:
    ordinal: int
    authorization: str
    outcome: M4Outcome
    verification: M4Verification
    compensation: M4Compensation
    digest_reference: str


@dataclass(frozen=True, slots=True)
class M4Claim:
    state: M4ClaimState
    result: M4ExecutionResult | None = None

    def __post_init__(self) -> None:
        if self.state is M4ClaimState.REPLAY and self.result is None:
            raise M4ExecutionError("replay claim requires a result.")
        if self.state is not M4ClaimState.REPLAY and self.result is not None:
            raise M4ExecutionError("only replay claims may contain a result.")


class M4ExecutionStateStore(Protocol):
    @property
    def audit_events(self) -> tuple[M4AuditEvent, ...]: ...

    def claim(
        self,
        *,
        plan_ref: str,
        requester_digest: str,
        idempotency_digest: str,
        context_digest: str,
        authorization_digest: str,
    ) -> M4Claim: ...

    def finalize(
        self,
        *,
        plan_ref: str,
        requester_digest: str,
        idempotency_digest: str,
        context_digest: str,
        result: M4ExecutionResult,
        event: M4AuditEvent,
    ) -> None: ...

    def append_audit(self, event: M4AuditEvent) -> None: ...


class InMemoryM4ExecutionStateStore:
    """Reference store for tests; restart safety comes from reusing the store."""

    def __init__(self) -> None:
        self._claims: dict[tuple[str, str, str], tuple[str, M4ExecutionResult | None]] = {}
        self._used_authorizations: set[str] = set()
        self._audit: list[M4AuditEvent] = []

    @property
    def audit_events(self) -> tuple[M4AuditEvent, ...]:
        return tuple(self._audit)

    def claim(
        self,
        *,
        plan_ref: str,
        requester_digest: str,
        idempotency_digest: str,
        context_digest: str,
        authorization_digest: str,
    ) -> M4Claim:
        namespace = (plan_ref, requester_digest, idempotency_digest)
        existing = self._claims.get(namespace)
        if existing is not None:
            prior_context, prior_result = existing
            if prior_context != context_digest:
                raise M4ExecutionError("idempotency context conflict.")
            if prior_result is None:
                return M4Claim(M4ClaimState.IN_PROGRESS)
            return M4Claim(M4ClaimState.REPLAY, prior_result)
        if authorization_digest in self._used_authorizations:
            raise M4AuthorizationReplay("execution authorization was already consumed.")
        self._used_authorizations.add(authorization_digest)
        self._claims[namespace] = (context_digest, None)
        return M4Claim(M4ClaimState.NEW)

    def finalize(
        self,
        *,
        plan_ref: str,
        requester_digest: str,
        idempotency_digest: str,
        context_digest: str,
        result: M4ExecutionResult,
        event: M4AuditEvent,
    ) -> None:
        namespace = (plan_ref, requester_digest, idempotency_digest)
        existing = self._claims.get(namespace)
        if existing is None or existing[0] != context_digest or existing[1] is not None:
            raise M4ExecutionError("execution claim cannot be finalized.")
        self._claims[namespace] = (context_digest, result)
        self._audit.append(
            M4AuditEvent(
                len(self._audit) + 1,
                event.authorization,
                event.outcome,
                event.verification,
                event.compensation,
                event.digest_reference,
            )
        )

    def append_audit(self, event: M4AuditEvent) -> None:
        self._audit.append(
            M4AuditEvent(
                len(self._audit) + 1,
                event.authorization,
                event.outcome,
                event.verification,
                event.compensation,
                event.digest_reference,
            )
        )


class M4ExecutionKernel:
    """One bounded read -> dispatch -> readback transaction kernel."""

    def __init__(
        self,
        adapter: M4ExecutionAdapter | None = None,
        authorization_verifier: M4AuthorizationVerifier | None = None,
        state_store: M4ExecutionStateStore | None = None,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._adapter = adapter or DenyAllM4Adapter()
        self._authorizer = authorization_verifier or DenyAllM4AuthorizationVerifier()
        self._state = state_store or InMemoryM4ExecutionStateStore()
        self._clock = clock or (lambda: int(time.time()))

    @property
    def audit_events(self) -> tuple[M4AuditEvent, ...]:
        return self._state.audit_events

    def execute(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        now_epoch: int | None = None,
    ) -> M4ExecutionResult:
        now = self._now(now_epoch)
        self._validate_authorization(plan, authorization, now)
        context_digest = canonical_digest(
            {
                "authorization_digest": authorization.authorization_digest,
                "plan_digest": plan.plan_digest,
                "revision": plan.revision,
            }
        )
        claim = self._state.claim(
            plan_ref=plan.plan_ref,
            requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest,
            context_digest=context_digest,
            authorization_digest=authorization.authorization_digest,
        )
        if claim.state is M4ClaimState.REPLAY:
            assert claim.result is not None
            return M4ExecutionResult(
                claim.result.outcome,
                claim.result.verification,
                claim.result.compensation,
                True,
            )
        if claim.state is M4ClaimState.IN_PROGRESS:
            result = M4ExecutionResult(
                M4Outcome.RECONCILIATION_REQUIRED,
                M4Verification.UNKNOWN,
                M4Compensation.REQUIRED if plan.compensation_ref else M4Compensation.NOT_REQUESTED,
                True,
            )
            self._state.append_audit(
                M4AuditEvent(
                    0,
                    "in_progress",
                    result.outcome,
                    result.verification,
                    result.compensation,
                    canonical_digest(context_digest + "in_progress"),
                )
            )
            return result

        # The durable execution reservation must exist before consuming a
        # separate one-time product authorization.  A crash after authorization
        # consumption can then only recover as IN_PROGRESS and can never
        # redispatch the mutation.  Terminal replays and unfinished recoveries
        # are already bound to the exact plan/authorization context, so neither
        # state consumes the protected authorization a second time.
        self._authorizer.verify(plan, authorization, now_epoch=now)

        try:
            current = self._adapter.read_current(plan)
            _digest(current, "adapter current-state digest")
        except M4AdapterDenied:
            result = M4ExecutionResult(M4Outcome.DENIED, M4Verification.NOT_STARTED, M4Compensation.NOT_REQUESTED, False)
            self._record(plan, context_digest, result, "adapter_denied")
            return result
        except (M4AdapterTimeout, M4AdapterAmbiguous):
            result = self._unknown(plan, mutation_possible=False)
            self._record(plan, context_digest, result, "current_read_unknown")
            return result
        except M4AdapterFailure:
            result = M4ExecutionResult(
                M4Outcome.EXECUTION_FAILED,
                M4Verification.NOT_STARTED,
                M4Compensation.NOT_REQUESTED,
                False,
            )
            self._record(plan, context_digest, result, "current_read_failed")
            return result
        if current != plan.expected_current_digest:
            result = M4ExecutionResult(M4Outcome.PRECONDITION_FAILED, M4Verification.NOT_STARTED, M4Compensation.NOT_REQUESTED, False)
            self._record(plan, context_digest, result, "current_state_drift")
            return result

        try:
            scope = _M4DispatchScope(plan, authorization, self._state)
            token = _ACTIVE_DISPATCH.set(scope)
            try:
                self._adapter.dispatch(plan)
            finally:
                scope.close()
                _ACTIVE_DISPATCH.reset(token)
        except M4AdapterDenied:
            result = M4ExecutionResult(M4Outcome.DENIED, M4Verification.NOT_STARTED, M4Compensation.NOT_REQUESTED, False)
            self._record(plan, context_digest, result, "adapter_denied")
            return result
        except (M4AdapterTimeout, M4AdapterAmbiguous):
            result = self._unknown(plan)
            self._record(plan, context_digest, result, "dispatch_unknown")
            return result
        except M4AdapterFailure:
            result = M4ExecutionResult(M4Outcome.EXECUTION_FAILED, M4Verification.NOT_STARTED, M4Compensation.NOT_REQUESTED, False)
            self._record(plan, context_digest, result, "dispatch_failed")
            return result

        try:
            actual = self._adapter.read_postcondition(plan)
            _digest(actual, "adapter postcondition digest")
        except M4AdapterDenied:
            result = self._unknown(plan, mutation_possible=True)
            self._record(plan, context_digest, result, "post_read_denied")
            return result
        except (M4AdapterTimeout, M4AdapterAmbiguous, M4AdapterFailure):
            result = self._unknown(plan, mutation_possible=True)
            self._record(plan, context_digest, result, "post_read_unknown")
            return result
        result = (
            M4ExecutionResult(M4Outcome.SUCCEEDED, M4Verification.VERIFIED, M4Compensation.NOT_REQUESTED, False)
            if actual == plan.expected_state_digest
            else M4ExecutionResult(M4Outcome.VERIFICATION_FAILED, M4Verification.FAILED, M4Compensation.REQUIRED if plan.compensation_ref else M4Compensation.NOT_REQUESTED, False)
        )
        self._record(plan, context_digest, result, "verified" if result.outcome is M4Outcome.SUCCEEDED else "postcondition_mismatch")
        return result

    def _record(self, plan: M4ExecutionPlan, context_digest: str, result: M4ExecutionResult, authorization: str) -> None:
        self._state.finalize(
            plan_ref=plan.plan_ref,
            requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest,
            context_digest=context_digest,
            result=result,
            event=M4AuditEvent(
                0,
                authorization,
                result.outcome,
                result.verification,
                result.compensation,
                canonical_digest(context_digest + authorization),
            ),
        )

    @staticmethod
    def _validate_authorization(plan: M4ExecutionPlan, auth: M4ExecutionAuthorization, now: int) -> None:
        if (
            auth.plan_ref != plan.plan_ref
            or auth.plan_digest != plan.plan_digest
            or auth.requester_digest != plan.requester_digest
            or auth.confirmation_digest != plan.confirmation_digest
            or auth.approval_digest != plan.approval_digest
            or now < auth.issued_at
            or now >= auth.expires_at
            or now >= plan.expires_at
        ):
            raise M4AuthorizationDenied("authorization is not bound to the exact active plan.")

    def _unknown(
        self,
        plan: M4ExecutionPlan,
        *,
        mutation_possible: bool = True,
    ) -> M4ExecutionResult:
        return M4ExecutionResult(
            M4Outcome.RECONCILIATION_REQUIRED,
            M4Verification.UNKNOWN,
            (
                M4Compensation.REQUIRED
                if mutation_possible and plan.compensation_ref
                else M4Compensation.NOT_REQUESTED
            ),
            False,
        )

    def _now(self, supplied: int | None) -> int:
        value = self._clock() if supplied is None else supplied
        if type(value) is not int or value < 0:
            raise M4ExecutionError("execution clock is invalid.")
        return value


class _M4DispatchScope:
    """Transient ownership of this kernel's NEW, authorized adapter dispatch.

    This is private process-local evidence, never a resumable authorization or
    persisted token. Copied contexts cannot revive it after dispatch finishes.
    """

    __slots__ = ("plan", "authorization", "store", "thread", "active", "material_reserved", "product_reserved")

    def __init__(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                 store: M4ExecutionStateStore) -> None:
        self.plan, self.authorization = plan, authorization
        self.store: M4ExecutionStateStore | None = store
        self.thread, self.active = threading.get_ident(), True
        self.material_reserved = False
        self.product_reserved = False

    def __repr__(self) -> str:
        return "<M4 dispatch scope redacted>"

    def close(self) -> None:
        self.active, self.store = False, None

    def __copy__(self) -> NoReturn:
        raise RuntimeError("M4 dispatch ownership is private.")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise RuntimeError("M4 dispatch ownership is private.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise RuntimeError("M4 dispatch ownership is private.")


_ACTIVE_DISPATCH: ContextVar[_M4DispatchScope | None] = ContextVar("m4_private_dispatch", default=None)


def _require_m4_dispatch_ownership(
    plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
    store: M4ExecutionStateStore,
) -> None:
    """Require the original kernel's active dispatch; ledger IN_PROGRESS is insufficient."""
    scope = _ACTIVE_DISPATCH.get()
    if (scope is None or not scope.active or scope.thread != threading.get_ident()
            or scope.plan != plan or scope.authorization != authorization or scope.store is not store):
        raise M4AuthorizationDenied("Original M4 dispatch ownership is unavailable.")


def _reserve_m4_material_acquisition(
    plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
    store: M4ExecutionStateStore,
) -> None:
    """One pre-load reservation within the original NEW dispatch, never renewed."""
    _require_m4_dispatch_ownership(plan, authorization, store)
    scope = _ACTIVE_DISPATCH.get()
    assert scope is not None
    if scope.material_reserved:
        raise M4AuthorizationReplay("Original M4 material acquisition is already reserved.")
    scope.material_reserved = True


def _require_m4_material_acquisition_ownership(
    plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
    store: M4ExecutionStateStore,
) -> None:
    """Require both original dispatch and its already-consumed acquisition slot."""
    _require_m4_dispatch_ownership(plan, authorization, store)
    scope = _ACTIVE_DISPATCH.get()
    if scope is None or not scope.material_reserved:
        raise M4AuthorizationDenied("Original M4 material acquisition is unavailable.")


def _reserve_m4_product_startup(
    plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
    store: M4ExecutionStateStore,
) -> None:
    """One product process in the original dispatch; failed startup is consumed."""
    _require_m4_dispatch_ownership(plan, authorization, store)
    scope = _ACTIVE_DISPATCH.get()
    assert scope is not None
    if scope.product_reserved or scope.material_reserved:
        raise M4AuthorizationReplay("Original M4 product startup is unavailable.")
    scope.product_reserved = True


__all__ = [
    "DenyAllM4Adapter",
    "DenyAllM4AuthorizationVerifier",
    "InMemoryM4ExecutionStateStore",
    "M4AdapterAmbiguous",
    "M4AdapterDenied",
    "M4AdapterFailure",
    "M4AdapterTimeout",
    "M4AuthorizationDenied",
    "M4AuthorizationReplay",
    "M4AuthorizationVerifier",
    "M4AuditEvent",
    "M4Claim",
    "M4ClaimState",
    "M4Compensation",
    "M4ExecutionAdapter",
    "M4ExecutionAuthorization",
    "M4ExecutionError",
    "M4ExecutionKernel",
    "M4ExecutionPlan",
    "M4ExecutionResult",
    "M4ExecutionStateStore",
    "M4Outcome",
    "M4Verification",
]
