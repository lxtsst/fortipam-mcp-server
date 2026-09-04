"""V3.1 local administrative-operation workflow.

The service is deliberately limited to a five-action JSON fixture adapter. It
uses the V3 controlled-operation engine for action contracts, confirmation
binding, idempotency, and bounded outcomes, while adding the V4-style
query/preview/confirm/readback boundary around it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import secrets
import time
from typing import Mapping

from .controlled_operations import (
    ActionContract,
    ActionRegistry,
    ApprovalBinding,
    ApprovalRejected,
    AuthenticatedPrincipal,
    ControlledOperationEngine,
    ControlledOperationRequest,
    InMemoryControlledOperationStateStore,
    ParameterKind,
    ParameterSpec,
    PublicOutcome,
    RollbackContract,
    VerifiedApprovalClaims,
)
from .lab_admin_adapter import ACTION_IDS, LabAdminAdapter, state_digest


class AdministrativeOperationError(ValueError):
    """Raised when a local administrative workflow cannot continue safely."""


class ConfirmationInvalidated(AdministrativeOperationError):
    """Raised when the exact preview no longer matches current fixture state."""


@dataclass(frozen=True, slots=True)
class OperationPreview:
    """A bounded Current/Proposed/Expected preview with an opaque confirmation."""

    action_id: str
    action_version: str
    target_ref: str
    current: Mapping[str, object]
    proposed: Mapping[str, object]
    expected: Mapping[str, object]
    current_state_digest: str
    proposed_changes_digest: str
    expected_state_digest: str
    confirmation_digest: str
    confirmation_token: str
    requester_digest: str
    environment_digest: str
    scope_digest: str
    expires_at: int
    parameters: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        """Return only non-secret preview fields."""

        return {
            "action_id": self.action_id,
            "action_version": self.action_version,
            "target_ref": self.target_ref,
            "current": dict(self.current),
            "proposed": dict(self.proposed),
            "expected": dict(self.expected),
            "current_state_digest": self.current_state_digest,
            "proposed_changes_digest": self.proposed_changes_digest,
            "expected_state_digest": self.expected_state_digest,
            "confirmation_digest": self.confirmation_digest,
            "confirmation_token": self.confirmation_token,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class LabOperationResult:
    """Safe execution result without parameters, material, or raw responses."""

    action_id: str
    outcome: str
    verification: str
    idempotent_replay: bool
    readback_verified: bool
    expected_state_digest: str
    actual_state_digest: str

    def as_dict(self) -> dict[str, object]:
        return {
            "action_id": self.action_id,
            "outcome": self.outcome,
            "verification": self.verification,
            "idempotent_replay": self.idempotent_replay,
            "readback_verified": self.readback_verified,
            "expected_state_digest": self.expected_state_digest,
            "actual_state_digest": self.actual_state_digest,
        }


class _ConfirmationVerifier:
    """In-process verifier for one exact preview token and binding."""

    def __init__(self) -> None:
        self._bindings: dict[str, tuple[ApprovalBinding, int]] = {}

    def register(self, token: str, binding: ApprovalBinding, expires_at: int) -> None:
        self._bindings[token] = (binding, expires_at)

    def verify(
        self,
        approval_reference: str,
        principal: AuthenticatedPrincipal,
        binding: ApprovalBinding,
        *,
        now_epoch: int,
    ) -> VerifiedApprovalClaims:
        entry = self._bindings.get(approval_reference)
        if entry is None or now_epoch >= entry[1] or entry[0] != binding:
            raise ApprovalRejected("The local confirmation token was rejected.")
        if binding.principal_digest != _digest(principal.subject_ref):
            raise ApprovalRejected("The local confirmation token was rejected.")
        receipt = "receipt-" + _digest(approval_reference)[:48]
        nonce_digest = _digest(approval_reference + binding.expected_current_digest)
        return VerifiedApprovalClaims(receipt, binding, nonce_digest, entry[1])


class AdministrativeOperationService:
    """Execute only fixed lab actions through the V3 safety engine."""

    ACTION_VERSIONS = {action_id: "3.1.0" for action_id in ACTION_IDS}

    def __init__(self, adapter: LabAdminAdapter | None = None) -> None:
        self.adapter = adapter or LabAdminAdapter()
        self._verifier = _ConfirmationVerifier()
        self._engine = ControlledOperationEngine(
            self._registry(),
            self.adapter,
            self._verifier,
            InMemoryControlledOperationStateStore(),
        )
        self._plans: dict[str, OperationPreview] = {}
        self._invalidated: set[str] = set()
        self._results: dict[tuple[str, str, str], LabOperationResult] = {}

    def query_current(
        self,
        action_id: str,
        target_ref: str,
        parameters: Mapping[str, object],
    ) -> dict[str, object]:
        """Query a fixed fixture projection without preparing or executing a plan."""

        base = self._validated_base_parameters(action_id, parameters)
        return self.adapter.query_current(action_id, target_ref, base)

    def preview(
        self,
        action_id: str,
        target_ref: str,
        parameters: Mapping[str, object],
        *,
        requester_ref: str,
        environment_ref: str,
        scope_ref: str,
        now_epoch: int | None = None,
        lifetime_seconds: int = 300,
    ) -> OperationPreview:
        """Create a Current/Proposed/Expected preview and exact token."""

        now = _now(now_epoch)
        if not 30 <= lifetime_seconds <= 900:
            raise AdministrativeOperationError("Preview lifetime is invalid.")
        principal = AuthenticatedPrincipal(requester_ref, "operator")
        _nonempty(environment_ref, "environment_ref")
        _nonempty(scope_ref, "scope_ref")
        base = self._validated_base_parameters(action_id, parameters)
        current = self.adapter.query_current(action_id, target_ref, base)
        expected = self.adapter.desired_state(action_id, target_ref, base)
        proposed = {
            "action_id": action_id,
            "change": "create_or_reconcile",
            "object_ref": target_ref,
            "desired": expected,
        }
        current_digest = state_digest(current)
        proposed_digest = state_digest(proposed)
        expected_digest = state_digest(expected)
        requester_digest = _digest(principal.subject_ref)
        environment_digest = _digest(environment_ref)
        scope_digest = _digest(scope_ref)
        confirmation_digest = state_digest(
            {
                "action_id": action_id,
                "action_version": self.ACTION_VERSIONS[action_id],
                "current_state_digest": current_digest,
                "proposed_changes_digest": proposed_digest,
                "expected_state_digest": expected_digest,
                "requester_digest": requester_digest,
                "environment_digest": environment_digest,
                "scope_digest": scope_digest,
            }
        )
        token = "confirmation-" + secrets.token_urlsafe(24)
        expires_at = now + lifetime_seconds
        final_parameters = dict(base)
        final_parameters["confirmation_digest"] = confirmation_digest
        binding = self._binding(
            action_id,
            target_ref,
            final_parameters,
            current_digest,
            principal,
        )
        self._verifier.register(token, binding, expires_at)
        plan = OperationPreview(
            action_id,
            self.ACTION_VERSIONS[action_id],
            target_ref,
            current,
            proposed,
            expected,
            current_digest,
            proposed_digest,
            expected_digest,
            confirmation_digest,
            token,
            requester_digest,
            environment_digest,
            scope_digest,
            expires_at,
            final_parameters,
        )
        self._plans[token] = plan
        return plan

    def execute(
        self,
        preview: OperationPreview,
        *,
        confirmation_token: str,
        confirmation_digest: str,
        requester_ref: str,
        environment_ref: str,
        scope_ref: str,
        idempotency_key: str,
        secret_value: str | None = None,
        now_epoch: int | None = None,
    ) -> LabOperationResult:
        """Execute one exact, still-fresh preview and verify fixture readback."""

        now = _now(now_epoch)
        if self._plans.get(confirmation_token) != preview:
            raise ConfirmationInvalidated("The confirmation token does not match the preview.")
        if confirmation_digest != preview.confirmation_digest:
            raise ConfirmationInvalidated("The confirmation digest does not match the preview.")
        if now >= preview.expires_at or confirmation_token in self._invalidated:
            self._invalidated.add(confirmation_token)
            raise ConfirmationInvalidated("The preview confirmation has expired or was invalidated.")
        principal = AuthenticatedPrincipal(requester_ref, "operator")
        if (
            _digest(principal.subject_ref) != preview.requester_digest
            or _digest(environment_ref) != preview.environment_digest
            or _digest(scope_ref) != preview.scope_digest
        ):
            raise ConfirmationInvalidated("The confirmation principal or scope changed.")
        replay_key = (preview.requester_digest, confirmation_token, idempotency_key)
        prior = self._results.get(replay_key)
        if prior is not None:
            return replace(prior, idempotent_replay=True)
        current = self.adapter.query_current(
            preview.action_id,
            preview.target_ref,
            preview.parameters,
        )
        if state_digest(current) != preview.current_state_digest:
            self._invalidated.add(confirmation_token)
            raise ConfirmationInvalidated("Current fixture state drifted after preview.")
        if preview.action_id == "create_secret":
            if not isinstance(secret_value, str) or not secret_value:
                raise AdministrativeOperationError("Secret material is required for this local fixture action.")
            self.adapter.stage_secret_material(
                str(preview.parameters["value_ref"]), secret_value
            )
        request = ControlledOperationRequest(
            _internal_action_id(preview.action_id),
            preview.action_version,
            preview.target_ref,
            preview.parameters,
            preview.current_state_digest,
            idempotency_key,
            confirmation_token,
        )
        try:
            result = self._engine.execute(request, principal, now_epoch=now)
        finally:
            if preview.action_id == "create_secret":
                self.adapter.discard_staged_material(str(preview.parameters["value_ref"]))
        actual = self.adapter.query_current(
            preview.action_id,
            preview.target_ref,
            preview.parameters,
        )
        actual_digest = state_digest(actual)
        readback_verified = (
            result.outcome is PublicOutcome.SUCCEEDED
            and actual_digest == preview.expected_state_digest
        )
        outcome = result.outcome.value if readback_verified or result.outcome is not PublicOutcome.SUCCEEDED else "verification_failed"
        safe_result = LabOperationResult(
            preview.action_id,
            outcome,
            result.verification.value,
            result.idempotent_replay,
            readback_verified,
            preview.expected_state_digest,
            actual_digest,
        )
        self._results[replay_key] = safe_result
        return safe_result

    @staticmethod
    def _registry() -> ActionRegistry:
        forward: list[ActionContract] = []
        rollback: list[RollbackContract] = []
        for action_id, parameters in _ACTION_PARAMETERS.items():
            internal_action_id = _internal_action_id(action_id)
            rollback_id = "rollback-" + internal_action_id
            forward.append(
                ActionContract(
                    internal_action_id,
                    "3.1.0",
                    "lab-admin-object",
                    "fortipam-lab-fixture",
                    "3.1.0",
                    parameters,
                    rollback_id,
                    "3.1.0",
                )
            )
            rollback.append(
                RollbackContract(
                    rollback_id,
                    "3.1.0",
                    "lab-admin-object",
                    "fortipam-lab-fixture",
                    "3.1.0",
                    parameters,
                    internal_action_id,
                    "3.1.0",
                )
            )
        return ActionRegistry(tuple(forward), tuple(rollback))

    @staticmethod
    def _binding(
        action_id: str,
        target_ref: str,
        parameters: Mapping[str, object],
        expected_current_digest: str,
        principal: AuthenticatedPrincipal,
    ) -> ApprovalBinding:
        contract_parameters = _ACTION_PARAMETER_MAP[action_id].validate_parameters(parameters)
        return ApprovalBinding(
            "forward",
            _digest(principal.subject_ref),
            _internal_action_id(action_id),
            "3.1.0",
            _digest(target_ref),
            _parameters_digest(contract_parameters),
            expected_current_digest,
        )

    @staticmethod
    def _validated_base_parameters(
        action_id: str,
        parameters: Mapping[str, object],
    ) -> dict[str, bool | str]:
        if action_id not in ACTION_IDS:
            raise AdministrativeOperationError("The administrative action is not allowlisted.")
        if not isinstance(parameters, Mapping) or "confirmation_digest" in parameters:
            raise AdministrativeOperationError("Only fixed action parameters are accepted.")
        values = dict(parameters)
        values["confirmation_digest"] = "0" * 64
        try:
            return _ACTION_PARAMETER_MAP[action_id].validate_parameters(values)
        except Exception as exc:
            raise AdministrativeOperationError("The fixed action parameters are invalid.") from exc


def _parameter(name: str, kind: ParameterKind, enum_values: tuple[str, ...] = ()) -> ParameterSpec:
    return ParameterSpec(name, kind, frozenset(enum_values))


def _internal_action_id(action_id: str) -> str:
    if action_id not in ACTION_IDS:
        raise AdministrativeOperationError("The administrative action is not allowlisted.")
    return action_id.replace("_", "-")


_ACTION_PARAMETERS: dict[str, tuple[ParameterSpec, ...]] = {
    "create_public_folder": (
        _parameter("parent_folder_ref", ParameterKind.IDENTIFIER),
        _parameter("folder_type", ParameterKind.ENUM, ("public", "private", "shared")),
        _parameter("vault_policy_ref", ParameterKind.IDENTIFIER),
        _parameter("user_permission", ParameterKind.ENUM, ("use", "manage")),
        _parameter("group_permission", ParameterKind.ENUM, ("use", "manage")),
        _parameter("folder_permission", ParameterKind.ENUM, ("use", "manage")),
        _parameter("vault_permission", ParameterKind.ENUM, ("use", "manage")),
        _parameter("allowed_launcher_type", ParameterKind.ENUM, ("any", "ssh", "sftp", "rdp")),
        _parameter("confirmation_digest", ParameterKind.IDENTIFIER),
    ),
    "create_target": (
        _parameter("target_class", ParameterKind.ENUM, ("ssh", "sftp", "rdp", "https")),
        _parameter("template_ref", ParameterKind.IDENTIFIER),
        _parameter("address_ref", ParameterKind.IDENTIFIER),
        _parameter("gateway_ref", ParameterKind.IDENTIFIER),
        _parameter("confirmation_digest", ParameterKind.IDENTIFIER),
    ),
    "create_secret": (
        _parameter("name_ref", ParameterKind.IDENTIFIER),
        _parameter("folder_ref", ParameterKind.IDENTIFIER),
        _parameter("template_ref", ParameterKind.IDENTIFIER),
        _parameter("target_ref", ParameterKind.IDENTIFIER),
        _parameter("value_ref", ParameterKind.IDENTIFIER),
        _parameter("field_name", ParameterKind.IDENTIFIER),
        _parameter("field_type", ParameterKind.ENUM, ("string", "username", "password", "key")),
        _parameter("field_desc_ref", ParameterKind.IDENTIFIER),
        _parameter("confirmation_digest", ParameterKind.IDENTIFIER),
    ),
    "create_local_user": (
        _parameter("name_ref", ParameterKind.IDENTIFIER),
        _parameter("status", ParameterKind.ENUM, ("enable", "disable")),
        _parameter("access_profile_ref", ParameterKind.IDENTIFIER),
        _parameter("display_name_ref", ParameterKind.IDENTIFIER),
        _parameter("comments_ref", ParameterKind.IDENTIFIER),
        _parameter("schedule_ref", ParameterKind.IDENTIFIER),
        _parameter("two_factor", ParameterKind.BOOLEAN),
        _parameter("confirmation_digest", ParameterKind.IDENTIFIER),
    ),
    "assign_folder_access": (
        _parameter("folder_ref", ParameterKind.IDENTIFIER),
        _parameter("subject_ref", ParameterKind.IDENTIFIER),
        _parameter("folder_permission", ParameterKind.ENUM, ("use", "manage")),
        _parameter("vault_permission", ParameterKind.ENUM, ("use", "manage")),
        _parameter("allowed_launcher_type", ParameterKind.ENUM, ("any", "ssh", "sftp", "rdp")),
        _parameter("confirmation_digest", ParameterKind.IDENTIFIER),
    ),
}
_ACTION_PARAMETER_MAP: dict[str, ActionContract] = {
    action_id: ActionContract(
        _internal_action_id(action_id),
        "3.1.0",
        "lab-admin-object",
        "fortipam-lab-fixture",
        "3.1.0",
        parameters,
        "rollback-" + _internal_action_id(action_id),
        "3.1.0",
    )
    for action_id, parameters in _ACTION_PARAMETERS.items()
}


def _parameters_digest(values: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _nonempty(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise AdministrativeOperationError(f"{field} is invalid.")


def _now(value: int | None) -> int:
    now = int(time.time()) if value is None else value
    if type(now) is not int or not 0 <= now <= 4_102_444_800:
        raise AdministrativeOperationError("Operation clock is invalid.")
    return now
