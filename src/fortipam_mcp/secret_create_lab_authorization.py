"""Startup-pinned authorization for the exact local Secret onboarding lab path.

This value-free verifier is limited to the ``lab_auto`` source-bound onboarding
exception.  It pins one already validated Secret-create M4 binding at startup;
it is not a substitute for a production trusted issuance or consumption ledger.
The protected C3 material binding is deliberately neither retained nor exposed.
"""

from __future__ import annotations

from v4_planning import (
    M4AuthorizationDenied,
    M4ExecutionAuthorization,
    M4ExecutionPlan,
    canonical_digest,
)
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    require_secret_create_lease_request,
)

from .secret_create_m4_runtime import SecretCreateM4ExecutionBinding


_DENIED = "Secret-create lab authorization is unavailable."


class SecretCreateLabAuthorizationVerifier:
    """Verify only one startup-pinned lab-auto Secret-create authorization."""

    __slots__ = (
        "_action_id",
        "_action_version",
        "_audience_digest",
        "_authorization_digest",
        "_binding_context_digest",
        "_plan_digest",
        "_policy_decision_digest",
        "_request_digest",
        "_scope_digest",
    )

    def __init__(self, binding: SecretCreateM4ExecutionBinding) -> None:
        try:
            (
                self._action_id,
                self._action_version,
                self._plan_digest,
                self._authorization_digest,
                self._policy_decision_digest,
                self._scope_digest,
                self._audience_digest,
                self._request_digest,
            ) = _binding_snapshot(binding)
            self._binding_context_digest = self._context_digest()
        except M4AuthorizationDenied:
            raise
        except Exception as exc:
            raise M4AuthorizationDenied(_DENIED) from exc

    def verify_binding(self, binding: SecretCreateM4ExecutionBinding) -> None:
        """Reject a reloaded value-free binding that differs from startup."""

        try:
            if _binding_snapshot(binding) != (
                self._action_id,
                self._action_version,
                self._plan_digest,
                self._authorization_digest,
                self._policy_decision_digest,
                self._scope_digest,
                self._audience_digest,
                self._request_digest,
            ):
                raise M4AuthorizationDenied(_DENIED)
        except M4AuthorizationDenied:
            raise
        except Exception as exc:
            raise M4AuthorizationDenied(_DENIED) from exc

    def verify(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        now_epoch: int,
    ) -> None:
        try:
            if (
                not isinstance(plan, M4ExecutionPlan)
                or not isinstance(authorization, M4ExecutionAuthorization)
                or type(now_epoch) is not int
                or now_epoch < 0
                or self._binding_context_digest != self._context_digest()
                or plan.action_id != self._action_id
                or plan.action_version != self._action_version
                or plan.plan_digest != self._plan_digest
                or canonical_digest(plan.canonical_content()) != self._plan_digest
                or authorization.authorization_digest
                != self._authorization_digest
                or canonical_digest(authorization.canonical_content())
                != self._authorization_digest
                or authorization.plan_ref != plan.plan_ref
                or authorization.plan_digest != plan.plan_digest
                or authorization.requester_digest != plan.requester_digest
                or authorization.confirmation_digest != plan.confirmation_digest
                or authorization.approval_digest != plan.approval_digest
                or authorization.one_time is not True
                or authorization.execution_authorized is not True
                or authorization.requester_digest == authorization.approver_digest
                or now_epoch < authorization.issued_at
                or now_epoch >= authorization.expires_at
                or now_epoch >= plan.expires_at
            ):
                raise M4AuthorizationDenied(_DENIED)
        except M4AuthorizationDenied:
            raise
        except Exception as exc:
            raise M4AuthorizationDenied(_DENIED) from exc

    def _context_digest(self) -> str:
        return canonical_digest(
            {
                "action_id": self._action_id,
                "action_version": self._action_version,
                "audience_digest": self._audience_digest,
                "authorization_digest": self._authorization_digest,
                "plan_digest": self._plan_digest,
                "policy_decision_digest": self._policy_decision_digest,
                "request_digest": self._request_digest,
                "scope_digest": self._scope_digest,
            }
        )


def _binding_snapshot(
    binding: SecretCreateM4ExecutionBinding,
) -> tuple[str, str, str, str, str, str, str, str]:
    if not isinstance(binding, SecretCreateM4ExecutionBinding):
        raise ValueError("invalid binding")
    plan = binding.plan
    authorization = binding.authorization
    request = require_secret_create_lease_request(binding.lease_request)
    if (
        not isinstance(plan, M4ExecutionPlan)
        or not isinstance(authorization, M4ExecutionAuthorization)
        or plan.action_id != SECRET_CREATE_ACTION_ID
        or plan.action_version != SECRET_CREATE_ACTION_VERSION
        or canonical_digest(plan.canonical_content()) != plan.plan_digest
        or canonical_digest(authorization.canonical_content())
        != authorization.authorization_digest
        or authorization.plan_ref != plan.plan_ref
        or authorization.plan_digest != plan.plan_digest
        or authorization.requester_digest != plan.requester_digest
        or authorization.confirmation_digest != plan.confirmation_digest
        or authorization.approval_digest != plan.approval_digest
        or authorization.one_time is not True
        or authorization.execution_authorized is not True
        or authorization.requester_digest == authorization.approver_digest
        or request.action_id != plan.action_id
        or request.action_version != plan.action_version
        or request.plan_digest != plan.plan_digest
        or request.authorization_digest != authorization.authorization_digest
        or request.policy_decision_digest != binding.policy_decision_digest
        or request.scope_digest != binding.scope_digest
        or request.audience_digest != binding.audience_digest
        or request.requested_at < authorization.issued_at
        or request.expires_at > authorization.expires_at
        or request.expires_at > plan.expires_at
    ):
        raise ValueError("binding mismatch")
    request_digest = canonical_digest(
        {
            "action_id": request.action_id,
            "action_version": request.action_version,
            "audience_digest": request.audience_digest,
            "authorization_digest": request.authorization_digest,
            "expires_at": request.expires_at,
            "plan_digest": request.plan_digest,
            "policy_decision_digest": request.policy_decision_digest,
            "provider_class": request.provider_class.value,
            "purpose": request.purpose.value,
            "requested_at": request.requested_at,
            "scope_digest": request.scope_digest,
        }
    )
    return (
        plan.action_id,
        plan.action_version,
        plan.plan_digest,
        authorization.authorization_digest,
        binding.policy_decision_digest,
        binding.scope_digest,
        binding.audience_digest,
        request_digest,
    )


__all__ = ["SecretCreateLabAuthorizationVerifier"]
