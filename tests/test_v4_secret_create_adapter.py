from __future__ import annotations

import inspect

import pytest

from v4_planning.material_provider import (
    MaterialLease,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
)
from v4_planning.secret_create_adapter import (
    DenyAllSecretCreatePrivateAdapter,
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    SecretCreateAdapterDenied,
    SecretCreateContractStatus,
    require_secret_create_lease_request,
    secret_create_source_contract,
)


def _request(**changes: object) -> MaterialLeaseRequest:
    values: dict[str, object] = {
        "action_id": SECRET_CREATE_ACTION_ID,
        "action_version": SECRET_CREATE_ACTION_VERSION,
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


def test_source_contract_is_exact_value_free_and_non_callable() -> None:
    contract = secret_create_source_contract()

    assert contract.status is SecretCreateContractStatus.SOURCE_PINNED_TARGET_UNVERIFIED
    assert contract.source_repository == "fortinetdev/terraform-provider-fortipam"
    assert contract.source_commit == "f502400a020d12091b32e4ccce9aff0b2025034b"
    assert contract.source_api_version == "1.1.0"
    assert contract.source_product_floor == "1.5"
    assert contract.target_product_version == "1.9.1"
    assert contract.method == "POST"
    assert contract.path == "/api/v2/cmdb/secret/database"
    assert contract.access_group == "secretgrp"
    assert contract.request_model == "Body1"
    assert contract.logical_success_status == 200
    assert contract.response_identifier_type == "numeric_mkey"
    assert contract.provider_reads_material_after_create is True
    assert contract.target_version_validated is False
    assert contract.direct_provider_reuse_permitted is False
    assert contract.body_builder_available is False
    assert contract.live_call_permitted is False


def test_source_contract_records_schema_names_without_material_values() -> None:
    contract = secret_create_source_contract()

    assert contract.provider_body_properties == (
        "id",
        "name",
        "inherit-permission",
        "folder",
        "template",
        "field",
    )
    assert contract.provider_field_item_properties == ("id", "name", "value")
    assert "password" not in repr(contract).lower()
    assert "credential" not in repr(contract).lower()


def test_exact_secret_create_lease_binding_is_required() -> None:
    request = _request()

    assert require_secret_create_lease_request(request) is request
    for changes in (
        {"action_id": "secret-update-metadata"},
        {"action_version": "1.0.1"},
        {"purpose": MaterialPurpose.CREDENTIAL_ROTATION},
    ):
        with pytest.raises(SecretCreateAdapterDenied, match="binding is unavailable"):
            require_secret_create_lease_request(_request(**changes))


def test_private_adapter_has_no_body_or_material_argument_and_denies_by_default() -> None:
    parameters = inspect.signature(
        DenyAllSecretCreatePrivateAdapter.dispatch_create
    ).parameters
    assert tuple(parameters) == ("self", "lease", "request")

    with pytest.raises(SecretCreateAdapterDenied) as captured:
        DenyAllSecretCreatePrivateAdapter().dispatch_create(MaterialLease(), _request())

    assert str(captured.value) == (
        "No accepted private Secret create adapter is configured."
    )
    assert "redacted" not in str(captured.value).lower()
