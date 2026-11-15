from __future__ import annotations

import json
from typing import cast

import pytest

from fortipam_mcp.secret_create_m4_binding import (
    OwnerOnlySecretCreateM4BindingResolver,
    SECRET_CREATE_M4_BINDING_CONTRACT,
    SECRET_CREATE_M4_BINDING_VERSION,
)
from fortipam_mcp.secret_create_m4_runtime import (
    ProtectedSecretCreateM4Runtime,
    SecretCreateM4RuntimeError,
)
from test_secret_create_m4_runtime import (
    _Reader,
    _Verifier,
    _secret_plan,
)
from test_v4_execution_kernel import NOW, _authorization
from test_v4_secret_create_runtime import _Adapter, _Provider, _request, _runtime
from v4_planning import InMemoryM4ExecutionStateStore, M4Outcome
from v4_planning.material_provider import C3MaterialBinding
from v4_planning.secret_create_adapter import (
    SecretCreateAdapterOutcome,
    SecretCreatePrivateAdapter,
)


class _MaterialResolver:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.binding = C3MaterialBinding()

    def resolve(self, binding_ref, request):
        assert request.action_id == "secret-create-from-reference"
        self.calls.append(binding_ref)
        return self.binding


def _payload():
    plan = _secret_plan()
    authorization = _authorization(plan)
    request = _request(
        plan_digest=plan.plan_digest,
        authorization_digest=authorization.authorization_digest,
        requested_at=NOW,
        expires_at=NOW + 60,
    )
    return plan, authorization, request, {
        "contract": SECRET_CREATE_M4_BINDING_CONTRACT,
        "version": SECRET_CREATE_M4_BINDING_VERSION,
        "material_binding_ref": "private-material-binding-ref01",
        "plan": {**plan.canonical_content(), "plan_digest": plan.plan_digest},
        "authorization": {
            **authorization.canonical_content(),
            "authorization_digest": authorization.authorization_digest,
        },
        "lease_request": {
            "action_id": request.action_id,
            "action_version": request.action_version,
            "plan_digest": request.plan_digest,
            "policy_decision_digest": request.policy_decision_digest,
            "authorization_digest": request.authorization_digest,
            "scope_digest": request.scope_digest,
            "audience_digest": request.audience_digest,
            "provider_class": request.provider_class.value,
            "purpose": request.purpose.value,
            "requested_at": request.requested_at,
            "expires_at": request.expires_at,
        },
        "policy_decision_digest": request.policy_decision_digest,
        "scope_digest": request.scope_digest,
        "audience_digest": request.audience_digest,
    }


def _owner_file(tmp_path, payload):
    path = tmp_path / "secret-m4-binding.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_owner_only_binding_reconstructs_exact_records_without_material_persistence(
    tmp_path,
) -> None:
    plan, authorization, request, payload = _payload()
    material = _MaterialResolver()
    resolver = OwnerOnlySecretCreateM4BindingResolver(
        _owner_file(tmp_path, payload),
        material,
    )

    binding = resolver.resolve_execution_binding(authorization.authorization_ref)

    assert binding.plan == plan
    assert binding.authorization == authorization
    assert binding.lease_request == request
    assert binding.material_binding is material.binding
    assert material.calls == ["private-material-binding-ref01"]
    assert "private-material-binding-ref01" not in repr(binding)


def test_persistent_binding_drives_the_existing_m4_and_material_runtime(tmp_path) -> None:
    plan, authorization, _request_value, payload = _payload()
    material = _MaterialResolver()
    resolver = OwnerOnlySecretCreateM4BindingResolver(
        _owner_file(tmp_path, payload),
        material,
    )
    provider = _Provider()
    private_adapter = _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED)
    runtime = ProtectedSecretCreateM4Runtime(
        resolver,
        _Verifier(),
        InMemoryM4ExecutionStateStore(),
        _runtime(provider, cast(SecretCreatePrivateAdapter, private_adapter)),
        _Reader(),
        authenticated_requester_digest=plan.requester_digest,
        clock=lambda: NOW,
    )

    result = runtime.execute_bound(authorization.authorization_ref)

    assert result.outcome is M4Outcome.SUCCEEDED
    assert material.calls == ["private-material-binding-ref01"]
    assert private_adapter.calls == 1


def test_binding_rejects_wrong_reference_permissions_and_symlink_before_material(
    tmp_path,
) -> None:
    _plan_value, authorization, _request_value, payload = _payload()
    material = _MaterialResolver()
    path = _owner_file(tmp_path, payload)
    resolver = OwnerOnlySecretCreateM4BindingResolver(path, material)

    with pytest.raises(SecretCreateM4RuntimeError, match="unavailable"):
        resolver.resolve_execution_binding("different-authorization-ref01")
    assert material.calls == []

    path.chmod(0o644)
    with pytest.raises(SecretCreateM4RuntimeError, match="unavailable"):
        resolver.resolve_execution_binding(authorization.authorization_ref)
    path.chmod(0o600)
    symlink = tmp_path / "secret-m4-binding-link.json"
    symlink.symlink_to(path)
    with pytest.raises(SecretCreateM4RuntimeError, match="unavailable"):
        OwnerOnlySecretCreateM4BindingResolver(symlink, material).resolve_execution_binding(
            authorization.authorization_ref
        )
    assert material.calls == []
