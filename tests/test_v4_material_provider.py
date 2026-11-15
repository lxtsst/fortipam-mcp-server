from __future__ import annotations

import copy
import json
import pickle

import pytest

from v4_planning.material_provider import (
    C3MaterialBinding,
    DenyAllMaterialProvider,
    MaterialAccessDenied,
    MaterialBindingStatus,
    MaterialContractError,
    MaterialLease,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
    MaterialRevocationReason,
)


def _request(**changes: object) -> MaterialLeaseRequest:
    values: dict[str, object] = {
        "action_id": "secret-create-from-reference",
        "action_version": "1.0.0",
        "plan_digest": "1" * 64,
        "policy_decision_digest": "2" * 64,
        "authorization_digest": "3" * 64,
        "scope_digest": "4" * 64,
        "audience_digest": "5" * 64,
        "provider_class": MaterialProviderClass.EXTERNAL_VAULT_LEASE,
        "purpose": MaterialPurpose.INITIAL_ONBOARDING,
        "requested_at": 1_000,
        "expires_at": 1_120,
    }
    values.update(changes)
    return MaterialLeaseRequest(**values)  # type: ignore[arg-type]


def test_request_accepts_only_value_free_exact_gate_bindings() -> None:
    request = _request()

    assert request.provider_class is MaterialProviderClass.EXTERNAL_VAULT_LEASE
    assert request.purpose is MaterialPurpose.INITIAL_ONBOARDING
    assert repr(request) == "<MaterialLeaseRequest redacted>"
    assert str(request) == "<MaterialLeaseRequest redacted>"
    assert set(request.__dataclass_fields__) == {
        "action_id",
        "action_version",
        "plan_digest",
        "policy_decision_digest",
        "authorization_digest",
        "scope_digest",
        "audience_digest",
        "provider_class",
        "purpose",
        "requested_at",
        "expires_at",
    }


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("action_id", "Secret.Create", "action_id"),
        ("action_version", "v1", "action_version"),
        ("plan_digest", "not-a-digest", "plan_digest"),
        ("policy_decision_digest", "A" * 64, "policy_decision_digest"),
        ("authorization_digest", "", "authorization_digest"),
        ("scope_digest", "6" * 63, "scope_digest"),
        ("audience_digest", "g" * 64, "audience_digest"),
        ("provider_class", "external_vault_lease", "provider_class"),
        ("purpose", "initial_onboarding", "purpose"),
        ("requested_at", True, "time bound"),
        ("expires_at", 1_000, "time bound"),
    ],
)
def test_request_rejects_malformed_or_untyped_control_metadata(
    field: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises(MaterialContractError, match=message):
        _request(**{field: value})


@pytest.mark.parametrize("opaque", [C3MaterialBinding(), MaterialLease()])
def test_private_objects_are_redacted_noncopyable_and_nonserializable(opaque: object) -> None:
    rendered = repr(opaque)
    assert rendered.endswith(" redacted>")
    assert str(opaque) == rendered
    with pytest.raises(MaterialAccessDenied, match="copied"):
        copy.copy(opaque)
    with pytest.raises(MaterialAccessDenied, match="copied"):
        copy.deepcopy(opaque)
    with pytest.raises(MaterialAccessDenied, match="serialized"):
        pickle.dumps(opaque)
    with pytest.raises(TypeError):
        json.dumps(opaque)


def test_default_provider_matches_four_operation_contract_and_denies_all() -> None:
    provider = DenyAllMaterialProvider()
    binding = C3MaterialBinding()
    lease = MaterialLease()
    request = _request()

    assert provider.validate_binding(binding, request) is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied, match="No accepted C3"):
        provider.acquire_lease(binding, request)
    with pytest.raises(MaterialAccessDenied, match="No accepted C3"):
        provider.release_lease(lease)
    with pytest.raises(MaterialAccessDenied, match="No accepted C3"):
        provider.revoke_lease(
            lease,
            reason=MaterialRevocationReason.RECONCILIATION_REQUIRED,
        )
    assert not hasattr(provider, "acquire")


def test_denial_errors_never_render_private_objects_or_request_context() -> None:
    provider = DenyAllMaterialProvider()
    with pytest.raises(MaterialAccessDenied) as captured:
        provider.acquire_lease(C3MaterialBinding(), _request())

    assert str(captured.value) == "No accepted C3 material provider is configured."
