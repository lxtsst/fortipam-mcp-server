from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from fortipam_mcp.secret_create_lab_authorization import (
    SecretCreateLabAuthorizationVerifier,
)
from fortipam_mcp.secret_create_m4_runtime import (
    ProtectedSecretCreateM4Runtime,
    SecretCreateM4ExecutionBinding,
)
from test_secret_create_m4_runtime import _Reader, _secret_plan
from test_v4_execution_kernel import NOW, _authorization
from test_v4_secret_create_runtime import _Adapter, _Provider, _request, _runtime
from v4_planning import (
    InMemoryM4ExecutionStateStore,
    M4AuthorizationDenied,
    canonical_digest,
)
from v4_planning.material_provider import C3MaterialBinding
from v4_planning.secret_create_adapter import (
    SecretCreateAdapterOutcome,
    SecretCreatePrivateAdapter,
)


def _binding() -> SecretCreateM4ExecutionBinding:
    plan = _secret_plan()
    authorization = _authorization(plan)
    request = _request(
        plan_digest=plan.plan_digest,
        authorization_digest=authorization.authorization_digest,
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


def test_startup_pinned_lab_authorization_is_value_free_and_accepts_exact_pair() -> None:
    binding = _binding()
    verifier = SecretCreateLabAuthorizationVerifier(binding)

    verifier.verify(binding.plan, binding.authorization, now_epoch=NOW)

    assert "material_binding" not in SecretCreateLabAuthorizationVerifier.__slots__
    assert not hasattr(verifier, "material_binding")
    assert binding.material_binding not in tuple(
        getattr(verifier, name)
        for name in SecretCreateLabAuthorizationVerifier.__slots__
    )


@pytest.mark.parametrize(
    "drift",
    ("plan", "authorization", "policy", "scope", "audience", "expired"),
)
def test_startup_pinned_lab_authorization_rejects_every_drift(drift: str) -> None:
    binding = _binding()
    verifier = SecretCreateLabAuthorizationVerifier(binding)
    plan = binding.plan
    authorization = binding.authorization
    now = NOW

    if drift == "plan":
        content = dict(plan.canonical_content())
        content["target_ref"] = "different-secret-target-ref01"
        plan = replace(
            plan,
            target_ref="different-secret-target-ref01",
            plan_digest=canonical_digest(content),
        )
    elif drift == "authorization":
        content = dict(authorization.canonical_content())
        content["approval_ref"] = "different-approval-reference01"
        authorization = replace(
            authorization,
            approval_ref="different-approval-reference01",
            authorization_digest=canonical_digest(content),
        )
    elif drift in {"policy", "scope", "audience"}:
        field = (
            "policy_decision_digest" if drift == "policy" else f"{drift}_digest"
        )
        changed = replace(binding, **{field: "9" * 64})
        with pytest.raises(M4AuthorizationDenied, match="unavailable"):
            SecretCreateLabAuthorizationVerifier(changed)
        return
    else:
        now = authorization.expires_at

    with pytest.raises(M4AuthorizationDenied, match="unavailable"):
        verifier.verify(plan, authorization, now_epoch=now)


class _ReloadedResolver:
    def __init__(self, binding: SecretCreateM4ExecutionBinding) -> None:
        self.binding = binding

    def resolve_execution_binding(
        self,
        authorization_ref: str,
    ) -> SecretCreateM4ExecutionBinding:
        assert authorization_ref == self.binding.authorization.authorization_ref
        return self.binding


@pytest.mark.parametrize("drift", ("policy", "scope", "audience"))
def test_runtime_rejects_reloaded_control_drift_before_any_dispatch(
    drift: str,
) -> None:
    startup = _binding()
    verifier = SecretCreateLabAuthorizationVerifier(startup)
    field = "policy_decision_digest" if drift == "policy" else f"{drift}_digest"
    changed_digest = "9" * 64
    reloaded = replace(
        startup,
        lease_request=replace(
            startup.lease_request,
            **{field: changed_digest},
        ),
        **{field: changed_digest},
    )
    provider = _Provider()
    private_adapter = _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED)
    reader = _Reader()
    runtime = ProtectedSecretCreateM4Runtime(
        _ReloadedResolver(reloaded),
        verifier,
        InMemoryM4ExecutionStateStore(),
        _runtime(
            provider,
            cast(SecretCreatePrivateAdapter, private_adapter),
        ),
        reader,
        authenticated_requester_digest=startup.plan.requester_digest,
        clock=lambda: NOW,
    )

    with pytest.raises(M4AuthorizationDenied, match="unavailable"):
        runtime.execute_bound(startup.authorization.authorization_ref)

    assert reader.calls == []
    assert private_adapter.calls == 0
    assert provider.events == []
