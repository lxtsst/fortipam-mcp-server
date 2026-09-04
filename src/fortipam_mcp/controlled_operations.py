"""Pure local, fake-adapter-only controlled-operation safety state machine.

No transport, MCP Tool, credential loader, filesystem, network, persistence,
or product adapter is implemented here.  A missing production approval verifier
fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import re
import time
from typing import Mapping, Protocol, TypeVar


class ControlledOperationError(ValueError): pass
class ApprovalRejected(ControlledOperationError): pass
class IdempotencyConflict(ControlledOperationError): pass
class OperationTimeoutError(RuntimeError): pass
class OperationAmbiguousError(RuntimeError): pass
class OperationExecutionError(RuntimeError): pass


class ParameterKind(StrEnum): ENUM = "enum"; BOOLEAN = "boolean"; IDENTIFIER = "identifier"
class PublicOutcome(StrEnum): SUCCEEDED = "succeeded"; PRECONDITION_FAILED = "precondition_failed"; EXECUTION_FAILED = "execution_failed"; VERIFICATION_FAILED = "verification_failed"; VERIFICATION_UNKNOWN = "verification_unknown"
class VerificationState(StrEnum): NOT_STARTED = "not_started"; VERIFIED = "verified"; FAILED = "failed"; UNKNOWN = "unknown"
class RollbackState(StrEnum): NOT_REQUESTED = "not_requested"; NOT_STARTED = "not_started"; VERIFIED = "verified"; FAILED = "failed"; UNKNOWN = "unknown"


_ACTION = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$")
_APPROVAL = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_FORBIDDEN = frozenset({"shell", "path", "url", "credential", "payload", "command", "secret", "token"})


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Trusted transport/security-layer identity, not an action input field."""
    subject_ref: str
    principal_class: str
    def __post_init__(self) -> None:
        if _REF.fullmatch(self.subject_ref) is None or self.principal_class not in {"operator", "automation"}:
            raise ControlledOperationError("Authenticated principal is invalid.")


@dataclass(frozen=True, slots=True)
class ParameterSpec:
    name: str
    kind: ParameterKind
    enum_values: frozenset[str] = frozenset()
    max_length: int = 128
    def __post_init__(self) -> None:
        if _ACTION.fullmatch(self.name.replace("_", "-")) is None or any(x in self.name.lower() for x in _FORBIDDEN):
            raise ControlledOperationError("Action parameter name is invalid.")
        if self.kind is ParameterKind.ENUM:
            if not self.enum_values or any(type(v) is not str or not v or len(v) > 64 for v in self.enum_values):
                raise ControlledOperationError("Enum parameter values are invalid.")
        elif self.enum_values:
            raise ControlledOperationError("Only enum parameters may declare values.")
        if not 8 <= self.max_length <= 128: raise ControlledOperationError("Identifier bound is invalid.")
    def validate(self, value: object) -> bool | str:
        if self.kind is ParameterKind.BOOLEAN:
            if type(value) is not bool: raise ControlledOperationError("Boolean parameter is invalid.")
            return value
        if self.kind is ParameterKind.ENUM:
            if type(value) is not str or value not in self.enum_values: raise ControlledOperationError("Enum parameter is invalid.")
            return value
        if type(value) is not str or len(value) > self.max_length or _REF.fullmatch(value) is None:
            raise ControlledOperationError("Identifier parameter is invalid.")
        return value


@dataclass(frozen=True, slots=True)
class ActionContract:
    action_id: str; version: str; target_class: str; product: str; product_version: str
    parameters: tuple[ParameterSpec, ...]; rollback_action_id: str; rollback_action_version: str
    max_affected: int = 1; reversible: bool = True
    def __post_init__(self) -> None:
        _contract_identity(self.action_id, self.version, self.target_class, self.product, self.product_version)
        if _ACTION.fullmatch(self.rollback_action_id) is None or _VERSION.fullmatch(self.rollback_action_version) is None: raise ControlledOperationError("Rollback binding is invalid.")
        _contract_shape(self.parameters, self.max_affected, self.reversible)
    def validate_parameters(self, values: Mapping[str, object]) -> dict[str, bool | str]: return _parameters(self.parameters, values)


@dataclass(frozen=True, slots=True)
class RollbackContract:
    action_id: str; version: str; target_class: str; product: str; product_version: str
    parameters: tuple[ParameterSpec, ...]; forward_action_id: str; forward_action_version: str
    max_affected: int = 1; reversible: bool = True
    def __post_init__(self) -> None:
        _contract_identity(self.action_id, self.version, self.target_class, self.product, self.product_version)
        if _ACTION.fullmatch(self.forward_action_id) is None or _VERSION.fullmatch(self.forward_action_version) is None: raise ControlledOperationError("Forward binding is invalid.")
        _contract_shape(self.parameters, self.max_affected, self.reversible)
    def validate_parameters(self, values: Mapping[str, object]) -> dict[str, bool | str]: return _parameters(self.parameters, values)


class ActionRegistry:
    """Immutable forward/rollback registry; runtime registration is absent."""
    def __init__(self, forward: tuple[ActionContract, ...], rollback: tuple[RollbackContract, ...]) -> None:
        if bool(forward) != bool(rollback):
            raise ControlledOperationError("Forward and rollback contracts must be paired.")
        self._forward = _index(forward); self._rollback = _index(rollback)
        for item in forward:
            reverse = self._rollback.get((item.rollback_action_id, item.rollback_action_version))
            if not isinstance(reverse, RollbackContract) or (reverse.target_class, reverse.product, reverse.product_version, reverse.forward_action_id, reverse.forward_action_version) != (item.target_class, item.product, item.product_version, item.action_id, item.version):
                raise ControlledOperationError("Matching rollback contract is required.")
    def get_forward(self, action_id: str, version: str) -> ActionContract:
        item = self._forward.get((action_id, version))
        if not isinstance(item, ActionContract): raise ControlledOperationError("Forward action is not registered.")
        return item
    def get_rollback(self, action_id: str, version: str) -> RollbackContract:
        item = self._rollback.get((action_id, version))
        if not isinstance(item, RollbackContract): raise ControlledOperationError("Rollback action is not registered.")
        return item


@dataclass(frozen=True, slots=True)
class ControlledOperationRequest:
    action_id: str; action_version: str; target_ref: str; parameters: Mapping[str, object]
    expected_current_digest: str; idempotency_key: str; approval_reference: str


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    purpose: str; principal_digest: str; action_id: str; action_version: str
    target_digest: str; parameters_digest: str; expected_current_digest: str


@dataclass(frozen=True, slots=True)
class VerifiedApprovalClaims:
    """Only a trusted verifier can create accepted claims/receipt bindings."""
    receipt_id: str; binding: ApprovalBinding; nonce_digest: str; expires_at: int


class ApprovalVerifier(Protocol):
    def verify(self, approval_reference: str, principal: AuthenticatedPrincipal, binding: ApprovalBinding, *, now_epoch: int) -> VerifiedApprovalClaims: ...


class DenyAllApprovalVerifier:
    def verify(self, approval_reference: str, principal: AuthenticatedPrincipal, binding: ApprovalBinding, *, now_epoch: int) -> VerifiedApprovalClaims:
        raise ApprovalRejected("No trusted approval verifier is configured.")


@dataclass(frozen=True, slots=True)
class VerifiedActionRequest:
    contract: ActionContract; target_ref: str; parameters: Mapping[str, bool | str]; expected_current_digest: str; context_digest: str


@dataclass(frozen=True, slots=True)
class VerifiedRollbackRequest:
    contract: RollbackContract; target_ref: str; parameters: Mapping[str, bool | str]; expected_current_digest: str; context_digest: str


class ControlledOperationAdapter(Protocol):
    def read_current(self, request: VerifiedActionRequest | VerifiedRollbackRequest) -> str: ...
    def execute(self, request: VerifiedActionRequest) -> None: ...
    def verify_postcondition(self, request: VerifiedActionRequest) -> bool: ...
    def rollback(self, request: VerifiedRollbackRequest) -> None: ...
    def verify_rollback_postcondition(self, request: VerifiedRollbackRequest) -> bool: ...


class DenyAllControlledOperationAdapter:
    """Fail-closed product boundary used while the action registry is empty."""

    @staticmethod
    def _deny() -> None:
        raise ControlledOperationError("No FortiPAM product action is enabled.")

    def read_current(self, request: VerifiedActionRequest | VerifiedRollbackRequest) -> str:
        del request
        self._deny()
        raise AssertionError("unreachable")

    def execute(self, request: VerifiedActionRequest) -> None:
        del request
        self._deny()

    def verify_postcondition(self, request: VerifiedActionRequest) -> bool:
        del request
        self._deny()
        raise AssertionError("unreachable")

    def rollback(self, request: VerifiedRollbackRequest) -> None:
        del request
        self._deny()

    def verify_rollback_postcondition(self, request: VerifiedRollbackRequest) -> bool:
        del request
        self._deny()
        raise AssertionError("unreachable")


@dataclass(frozen=True, slots=True)
class ControlledOperationResult:
    outcome: PublicOutcome; verification: VerificationState; rollback: RollbackState; idempotent_replay: bool
    def as_dict(self) -> dict[str, object]: return {"outcome": self.outcome.value, "verification": self.verification.value, "rollback": self.rollback.value, "idempotent_replay": self.idempotent_replay}


@dataclass(frozen=True, slots=True)
class AuditEvent:
    ordinal: int; principal_class: str; action_id: str; action_version: str; target_class: str; purpose: str
    authorization: str; outcome: str; verification: str; rollback: str; digest_reference: str


class ClaimState(StrEnum):
    """Persistent idempotency claim state returned before adapter execution."""

    NEW = "new"
    REPLAY = "replay"
    IN_PROGRESS = "in_progress"


@dataclass(frozen=True, slots=True)
class OperationClaim:
    """Result of atomically claiming an idempotency and approval receipt."""

    state: ClaimState
    result: ControlledOperationResult | None = None

    def __post_init__(self) -> None:
        if self.state is ClaimState.REPLAY and self.result is None:
            raise ControlledOperationError("Replay claim requires a result.")
        if self.state is not ClaimState.REPLAY and self.result is not None:
            raise ControlledOperationError("Only replay claims may contain a result.")


class ControlledOperationStateStore(Protocol):
    """Atomic state boundary required by the controlled-operation engine."""

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]: ...

    def claim(
        self,
        purpose: str,
        principal_digest: str,
        idempotency_digest: str,
        context_digest: str,
        receipt_digest: str,
    ) -> OperationClaim: ...

    def finalize(
        self,
        purpose: str,
        principal_digest: str,
        idempotency_digest: str,
        context_digest: str,
        result: ControlledOperationResult,
        event: AuditEvent,
    ) -> None: ...

    def append_audit(self, principal_digest: str, event: AuditEvent) -> None: ...


class InMemoryControlledOperationStateStore:
    """Process-local reference store used by pure unit tests only."""

    def __init__(self) -> None:
        self._used_receipts: set[str] = set()
        self._idempotency: dict[
            tuple[str, str, str],
            tuple[str, ControlledOperationResult | None],
        ] = {}
        self._audit: list[AuditEvent] = []

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._audit)

    def claim(
        self,
        purpose: str,
        principal_digest: str,
        idempotency_digest: str,
        context_digest: str,
        receipt_digest: str,
    ) -> OperationClaim:
        namespace = (purpose, principal_digest, idempotency_digest)
        prior = self._idempotency.get(namespace)
        if prior is not None:
            prior_context, prior_result = prior
            if prior_context != context_digest:
                raise IdempotencyConflict("Idempotency key context does not match.")
            if prior_result is None:
                return OperationClaim(ClaimState.IN_PROGRESS)
            return OperationClaim(ClaimState.REPLAY, prior_result)
        if receipt_digest in self._used_receipts:
            raise ApprovalRejected("Approval receipt was already consumed.")
        self._used_receipts.add(receipt_digest)
        self._idempotency[namespace] = (context_digest, None)
        return OperationClaim(ClaimState.NEW)

    def finalize(
        self,
        purpose: str,
        principal_digest: str,
        idempotency_digest: str,
        context_digest: str,
        result: ControlledOperationResult,
        event: AuditEvent,
    ) -> None:
        namespace = (purpose, principal_digest, idempotency_digest)
        prior = self._idempotency.get(namespace)
        if prior is None or prior[0] != context_digest or prior[1] is not None:
            raise ControlledOperationError("Operation state cannot be finalized.")
        self._idempotency[namespace] = (context_digest, result)
        self.append_audit(principal_digest, event)

    def append_audit(self, principal_digest: str, event: AuditEvent) -> None:
        if _DIGEST.fullmatch(principal_digest) is None:
            raise ControlledOperationError("Operation principal digest is invalid.")
        if not isinstance(event, AuditEvent):
            raise ControlledOperationError("Operation audit event is invalid.")
        self._audit.append(
            AuditEvent(
                len(self._audit) + 1,
                event.principal_class,
                event.action_id,
                event.action_version,
                event.target_class,
                event.purpose,
                event.authorization,
                event.outcome,
                event.verification,
                event.rollback,
                event.digest_reference,
            )
        )


class ControlledOperationEngine:
    """Approval-gated engine with an injectable atomic persistence boundary."""

    def __init__(
        self,
        registry: ActionRegistry,
        adapter: ControlledOperationAdapter,
        approval_verifier: ApprovalVerifier | None = None,
        state_store: ControlledOperationStateStore | None = None,
    ) -> None:
        self._registry = registry
        self._adapter = adapter
        self._verifier = approval_verifier or DenyAllApprovalVerifier()
        self._state = state_store or InMemoryControlledOperationStateStore()

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return self._state.audit_events

    def execute(self, request: ControlledOperationRequest, principal: AuthenticatedPrincipal, *, now_epoch: int | None = None) -> ControlledOperationResult:
        return self._start(request, principal, False, now_epoch)
    def rollback(self, request: ControlledOperationRequest, principal: AuthenticatedPrincipal, *, now_epoch: int | None = None) -> ControlledOperationResult:
        return self._start(request, principal, True, now_epoch)
    def _start(self, request: ControlledOperationRequest, principal: AuthenticatedPrincipal, rollback: bool, now_epoch: int | None) -> ControlledOperationResult:
        purpose = "rollback" if rollback else "forward"
        try:
            contract = self._registry.get_rollback(request.action_id, request.action_version) if rollback else self._registry.get_forward(request.action_id, request.action_version)
            verified, binding, receipt = self._verified(request, principal, contract, purpose, now_epoch)
        except ControlledOperationError:
            self._denied(request, principal, purpose); raise
        return self._run(request, principal, verified, binding, receipt, rollback)
    def _verified(self, request: ControlledOperationRequest, principal: AuthenticatedPrincipal, contract: ActionContract | RollbackContract, purpose: str, now_epoch: int | None) -> tuple[VerifiedActionRequest | VerifiedRollbackRequest, ApprovalBinding, str]:
        if now_epoch is None:
            now = int(time.time())
        elif type(now_epoch) is int and 0 <= now_epoch <= 4_102_444_800:
            now = now_epoch
        else:
            raise ControlledOperationError("Operation clock is invalid.")
        if _REF.fullmatch(request.target_ref) is None or _DIGEST.fullmatch(request.expected_current_digest) is None or _IDEMPOTENCY.fullmatch(request.idempotency_key) is None: raise ControlledOperationError("Request context is invalid.")
        if _APPROVAL.fullmatch(request.approval_reference) is None: raise ApprovalRejected("Approval reference is invalid.")
        values = contract.validate_parameters(request.parameters)
        binding = ApprovalBinding(purpose, _digest(principal.subject_ref), contract.action_id, contract.version, _digest(request.target_ref), _digest_json(values), request.expected_current_digest)
        claims = self._verifier.verify(request.approval_reference, principal, binding, now_epoch=now)
        if claims.binding != binding or type(claims.expires_at) is not int or claims.expires_at <= now or _REF.fullmatch(claims.receipt_id) is None or _DIGEST.fullmatch(claims.nonce_digest) is None: raise ApprovalRejected("Approval receipt is invalid.")
        receipt = _digest(claims.receipt_id + claims.nonce_digest)
        context = _digest_json({"binding": binding.__dict__ if hasattr(binding, "__dict__") else [binding.purpose, binding.principal_digest, binding.action_id, binding.action_version, binding.target_digest, binding.parameters_digest, binding.expected_current_digest], "receipt": receipt})
        verified: VerifiedActionRequest | VerifiedRollbackRequest
        if isinstance(contract, ActionContract): verified = VerifiedActionRequest(contract, request.target_ref, values, request.expected_current_digest, context)
        else: verified = VerifiedRollbackRequest(contract, request.target_ref, values, request.expected_current_digest, context)
        return verified, binding, receipt
    def _run(
        self,
        request: ControlledOperationRequest,
        principal: AuthenticatedPrincipal,
        verified: VerifiedActionRequest | VerifiedRollbackRequest,
        binding: ApprovalBinding,
        receipt: str,
        rollback: bool,
    ) -> ControlledOperationResult:
        idempotency_digest = _digest(request.idempotency_key)
        claim = self._state.claim(
            binding.purpose,
            binding.principal_digest,
            idempotency_digest,
            verified.context_digest,
            receipt,
        )
        if claim.state is ClaimState.REPLAY:
            assert claim.result is not None
            result = ControlledOperationResult(
                claim.result.outcome,
                claim.result.verification,
                claim.result.rollback,
                True,
            )
            self._audit_result(
                principal,
                verified,
                binding.purpose,
                "idempotent_replay",
                result,
                _digest(verified.context_digest + "replay"),
            )
            return result
        if claim.state is ClaimState.IN_PROGRESS:
            result = ControlledOperationResult(
                PublicOutcome.VERIFICATION_UNKNOWN,
                VerificationState.UNKNOWN,
                RollbackState.UNKNOWN if rollback else RollbackState.NOT_REQUESTED,
                True,
            )
            self._audit_result(
                principal,
                verified,
                binding.purpose,
                "idempotent_in_progress",
                result,
                _digest(verified.context_digest + "in-progress"),
            )
            return result
        try:
            current = self._adapter.read_current(verified)
        except (OperationTimeoutError, OperationAmbiguousError):
            return self._record(
                principal,
                request,
                verified,
                binding,
                _unknown(rollback),
            )
        if current != verified.expected_current_digest:
            return self._record(
                principal,
                request,
                verified,
                binding,
                _precondition(rollback),
            )
        result = (
            self._call_rollback(verified)
            if rollback
            else self._call_forward(verified)
        )
        return self._record(principal, request, verified, binding, result)
    def _call_forward(self, request: VerifiedActionRequest | VerifiedRollbackRequest) -> ControlledOperationResult:
        if not isinstance(request, VerifiedActionRequest): raise ControlledOperationError("Forward adapter request is invalid.")
        try: self._adapter.execute(request)
        except (OperationTimeoutError, OperationAmbiguousError): return _unknown(False)
        except OperationExecutionError: return ControlledOperationResult(PublicOutcome.EXECUTION_FAILED, VerificationState.NOT_STARTED, RollbackState.NOT_REQUESTED, False)
        try: checked = self._adapter.verify_postcondition(request)
        except (OperationTimeoutError, OperationAmbiguousError): checked = None
        return _postcondition(checked, False)
    def _call_rollback(self, request: VerifiedActionRequest | VerifiedRollbackRequest) -> ControlledOperationResult:
        if not isinstance(request, VerifiedRollbackRequest): raise ControlledOperationError("Rollback adapter request is invalid.")
        try: self._adapter.rollback(request)
        except (OperationTimeoutError, OperationAmbiguousError): return _unknown(True)
        except OperationExecutionError: return ControlledOperationResult(PublicOutcome.EXECUTION_FAILED, VerificationState.NOT_STARTED, RollbackState.FAILED, False)
        try: checked = self._adapter.verify_rollback_postcondition(request)
        except (OperationTimeoutError, OperationAmbiguousError): checked = None
        return _postcondition(checked, True)
    def _record(self, principal: AuthenticatedPrincipal, request: ControlledOperationRequest, verified: VerifiedActionRequest | VerifiedRollbackRequest, binding: ApprovalBinding, result: ControlledOperationResult) -> ControlledOperationResult:
        event = self._event(
            principal,
            verified,
            binding.purpose,
            "approved",
            result,
            _digest(verified.context_digest + verified.contract.action_id),
        )
        self._state.finalize(
            binding.purpose,
            binding.principal_digest,
            _digest(request.idempotency_key),
            verified.context_digest,
            result,
            event,
        )
        return result
    def _denied(self, request: ControlledOperationRequest, principal: AuthenticatedPrincipal, purpose: str) -> None:
        action = request.action_id if _ACTION.fullmatch(request.action_id) else "invalid"; version = request.action_version if _VERSION.fullmatch(request.action_version) else "0.0.0"; result = ControlledOperationResult(PublicOutcome.EXECUTION_FAILED, VerificationState.NOT_STARTED, RollbackState.NOT_REQUESTED, False)
        self._state.append_audit(
            _digest(principal.subject_ref),
            AuditEvent(
                0,
                principal.principal_class,
                action,
                version,
                "unrecognized",
                purpose,
                "denied",
                result.outcome.value,
                result.verification.value,
                result.rollback.value,
                _digest("denied" + request.idempotency_key),
            )
        )
    def _audit_result(self, principal: AuthenticatedPrincipal, verified: VerifiedActionRequest | VerifiedRollbackRequest, purpose: str, auth: str, result: ControlledOperationResult, digest: str) -> None:
        self._state.append_audit(
            _digest(principal.subject_ref),
            self._event(principal, verified, purpose, auth, result, digest)
        )

    @staticmethod
    def _event(
        principal: AuthenticatedPrincipal,
        verified: VerifiedActionRequest | VerifiedRollbackRequest,
        purpose: str,
        authorization: str,
        result: ControlledOperationResult,
        digest: str,
    ) -> AuditEvent:
        return AuditEvent(
            0,
            principal.principal_class,
            verified.contract.action_id,
            verified.contract.version,
            verified.contract.target_class,
            purpose,
            authorization,
            result.outcome.value,
            result.verification.value,
            result.rollback.value,
            digest,
        )


def _contract_identity(*values: str) -> None:
    if _ACTION.fullmatch(values[0]) is None or _VERSION.fullmatch(values[1]) is None or _ACTION.fullmatch(values[2]) is None or _ACTION.fullmatch(values[3]) is None or _VERSION.fullmatch(values[4]) is None: raise ControlledOperationError("Action contract identity is invalid.")
def _contract_shape(params: tuple[ParameterSpec, ...], max_affected: int, reversible: bool) -> None:
    if len({p.name for p in params}) != len(params) or max_affected != 1 or not reversible: raise ControlledOperationError("Action contract shape is invalid.")
def _parameters(specs: tuple[ParameterSpec, ...], values: Mapping[str, object]) -> dict[str, bool | str]:
    if set(values) != {spec.name for spec in specs}: raise ControlledOperationError("Action parameter schema is not accepted.")
    return {spec.name: spec.validate(values[spec.name]) for spec in specs}
T = TypeVar("T", ActionContract, RollbackContract)
def _index(contracts: tuple[T, ...]) -> dict[tuple[str, str], T]:
    result = {(item.action_id, item.version): item for item in contracts}
    if len(result) != len(contracts): raise ControlledOperationError("Action contract identities must be unique.")
    return result
def _postcondition(value: bool | None, rollback: bool) -> ControlledOperationResult:
    if value is True: return ControlledOperationResult(PublicOutcome.SUCCEEDED, VerificationState.VERIFIED, RollbackState.VERIFIED if rollback else RollbackState.NOT_REQUESTED, False)
    if value is False: return ControlledOperationResult(PublicOutcome.VERIFICATION_FAILED, VerificationState.FAILED, RollbackState.FAILED if rollback else RollbackState.NOT_REQUESTED, False)
    return _unknown(rollback)
def _unknown(rollback: bool) -> ControlledOperationResult: return ControlledOperationResult(PublicOutcome.VERIFICATION_UNKNOWN, VerificationState.UNKNOWN, RollbackState.UNKNOWN if rollback else RollbackState.NOT_REQUESTED, False)
def _precondition(rollback: bool) -> ControlledOperationResult: return ControlledOperationResult(PublicOutcome.PRECONDITION_FAILED, VerificationState.NOT_STARTED, RollbackState.NOT_STARTED if rollback else RollbackState.NOT_REQUESTED, False)
def _digest(value: str) -> str: return hashlib.sha256(value.encode()).hexdigest()
def _digest_json(value: object) -> str: return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
