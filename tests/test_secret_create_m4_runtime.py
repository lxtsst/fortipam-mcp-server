from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from fortipam_mcp.secret_create_m4_runtime import (
    ProtectedSecretCreateM4Runtime,
    SecretCreateM4ExecutionBinding,
)
from test_v4_execution_kernel import CURRENT, EXPECTED, NOW, _authorization, _plan
from test_v4_secret_create_runtime import _Adapter, _Provider, _request, _runtime
from v4_planning import (
    InMemoryM4ExecutionStateStore,
    M4AuthorizationDenied,
    M4ExecutionAuthorization,
    M4ExecutionPlan,
    M4Outcome,
    M4Verification,
    canonical_digest,
)
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    SecretCreateAdapterOutcome,
    SecretCreatePrivateAdapter,
)
from v4_planning.material_provider import C3MaterialBinding


def _secret_plan() -> M4ExecutionPlan:
    base = _plan()
    content = dict(base.canonical_content())
    content["action_id"] = SECRET_CREATE_ACTION_ID
    content["action_version"] = SECRET_CREATE_ACTION_VERSION
    return replace(
        base,
        action_id=SECRET_CREATE_ACTION_ID,
        action_version=SECRET_CREATE_ACTION_VERSION,
        plan_digest=canonical_digest(content),
    )


class _Resolver:
    def __init__(self, binding: SecretCreateM4ExecutionBinding) -> None:
        self.binding = binding
        self.calls = 0

    def resolve_execution_binding(self, authorization_ref: str):
        assert authorization_ref == self.binding.authorization.authorization_ref
        self.calls += 1
        return self.binding


class _Verifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        now_epoch: int,
    ) -> None:
        assert authorization.plan_digest == plan.plan_digest
        assert now_epoch == NOW
        self.calls += 1


class _Reader:
    def __init__(
        self,
        *,
        post: str = EXPECTED,
        onboarding_binding_digest: str = "1" * 64,
    ) -> None:
        self.post = post
        self.onboarding_binding_digest = onboarding_binding_digest
        self.calls: list[str] = []

    def inspect_onboarding_binding_digest(self) -> str:
        return self.onboarding_binding_digest

    def read_current(self, plan: M4ExecutionPlan) -> str:
        del plan
        self.calls.append("current")
        return CURRENT

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        del plan
        self.calls.append("post")
        return self.post


def _binding(
    plan: M4ExecutionPlan,
    authorization: M4ExecutionAuthorization,
    *,
    authorization_digest: str | None = None,
) -> SecretCreateM4ExecutionBinding:
    request = _request(
        plan_digest=plan.plan_digest,
        authorization_digest=authorization_digest or authorization.authorization_digest,
        requested_at=NOW,
        expires_at=NOW + 60,
    )
    return SecretCreateM4ExecutionBinding(
        plan,
        authorization,
        C3MaterialBinding(),
        request,
        request.policy_decision_digest,
        request.scope_digest,
        request.audience_digest,
    )


def test_m4_authorization_wraps_single_use_material_and_independent_readback() -> None:
    plan = _secret_plan()
    authorization = _authorization(plan)
    provider = _Provider()
    private_adapter = _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED)
    material_runtime = _runtime(
        provider,
        cast(SecretCreatePrivateAdapter, private_adapter),
    )
    binding = _binding(plan, authorization)
    verifier = _Verifier()
    reader = _Reader()
    runtime = ProtectedSecretCreateM4Runtime(
        _Resolver(binding),
        verifier,
        InMemoryM4ExecutionStateStore(),
        material_runtime,
        reader,
        authenticated_requester_digest=plan.requester_digest,
        clock=lambda: NOW,
    )

    assert runtime.inspect_execution_plan(authorization.authorization_ref) is plan
    result = runtime.execute_bound(authorization.authorization_ref)

    assert result.outcome is M4Outcome.SUCCEEDED
    assert result.verification is M4Verification.VERIFIED
    assert verifier.calls == 1
    assert reader.calls == ["current", "post"]
    assert private_adapter.calls == 1
    assert provider.events == ["validate", "acquire", "release"]


def test_mismatched_material_authorization_is_denied_before_every_side_effect() -> None:
    plan = _secret_plan()
    authorization = _authorization(plan)
    provider = _Provider()
    binding = _binding(
        plan,
        authorization,
        authorization_digest="9" * 64,
    )
    reader = _Reader()
    private_adapter = _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED)
    runtime = ProtectedSecretCreateM4Runtime(
        _Resolver(binding),
        _Verifier(),
        InMemoryM4ExecutionStateStore(),
        _runtime(provider, cast(SecretCreatePrivateAdapter, private_adapter)),
        reader,
        authenticated_requester_digest=plan.requester_digest,
        clock=lambda: NOW,
    )

    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(authorization.authorization_ref)
    assert reader.calls == []
    assert private_adapter.calls == 0
    assert provider.events == []


def test_mismatched_onboarding_binding_is_denied_before_every_side_effect() -> None:
    plan = _secret_plan()
    authorization = _authorization(plan)
    provider = _Provider()
    reader = _Reader(onboarding_binding_digest="1" * 64)
    private_adapter = _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED)
    verifier = _Verifier()
    runtime = ProtectedSecretCreateM4Runtime(
        _Resolver(_binding(plan, authorization)),
        verifier,
        InMemoryM4ExecutionStateStore(),
        _runtime(provider, cast(SecretCreatePrivateAdapter, private_adapter)),
        reader,
        authenticated_requester_digest=plan.requester_digest,
        clock=lambda: NOW,
    )

    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(
            authorization.authorization_ref,
            expected_onboarding_binding_digest="2" * 64,
        )
    assert verifier.calls == 0
    assert reader.calls == []
    assert private_adapter.calls == 0
    assert provider.events == []


def test_uncertain_material_result_never_runs_outer_postcondition_read() -> None:
    plan = _secret_plan()
    authorization = _authorization(plan)
    provider = _Provider()
    private_adapter = _Adapter(SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED)
    reader = _Reader()
    runtime = ProtectedSecretCreateM4Runtime(
        _Resolver(_binding(plan, authorization)),
        _Verifier(),
        InMemoryM4ExecutionStateStore(),
        _runtime(provider, cast(SecretCreatePrivateAdapter, private_adapter)),
        reader,
        authenticated_requester_digest=plan.requester_digest,
        clock=lambda: NOW,
    )

    result = runtime.execute_bound(authorization.authorization_ref)

    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert result.verification is M4Verification.UNKNOWN
    assert reader.calls == ["current"]
    assert provider.events[0:2] == ["validate", "acquire"]
