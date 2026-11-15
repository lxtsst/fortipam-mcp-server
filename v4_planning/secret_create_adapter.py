"""Non-callable source contract and fail-closed Secret create adapter boundary.

The source contract records only categorical facts from the pinned official
FortiPAM Terraform provider.  It is not target-version acceptance and cannot
build or send a request.  A future private adapter may consume an opaque C3
lease, but the default implementation denies dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, Protocol

from .material_provider import MaterialLease, MaterialLeaseRequest, MaterialPurpose


SECRET_CREATE_ACTION_ID = "secret-create-from-reference"
SECRET_CREATE_ACTION_VERSION = "1.0.0"


class SecretCreateContractStatus(StrEnum):
    SOURCE_PINNED_TARGET_UNVERIFIED = "source_pinned_target_unverified"


class SecretCreateAdapterOutcome(StrEnum):
    VERIFIED_CREATED = "verified_created"
    RECONCILIATION_REQUIRED = "reconciliation_required"


class SecretCreateAdapterDenied(RuntimeError):
    """Raised when no accepted private Secret create adapter is configured."""


@dataclass(frozen=True, slots=True)
class SecretCreateSourceContract:
    """Value-free evidence about the pinned provider's Secret create path."""

    status: SecretCreateContractStatus
    source_repository: str
    source_commit: str
    source_api_version: str
    source_product_floor: str
    target_product_version: str
    method: str
    path: str
    access_group: str
    request_model: str
    provider_body_properties: tuple[str, ...]
    provider_field_item_properties: tuple[str, ...]
    logical_success_status: int
    response_identifier_type: str
    provider_reads_material_after_create: bool
    target_version_validated: bool
    direct_provider_reuse_permitted: bool
    body_builder_available: bool
    live_call_permitted: bool


_SOURCE_CONTRACT = SecretCreateSourceContract(
    status=SecretCreateContractStatus.SOURCE_PINNED_TARGET_UNVERIFIED,
    source_repository="fortinetdev/terraform-provider-fortipam",
    source_commit="f502400a020d12091b32e4ccce9aff0b2025034b",
    source_api_version="1.1.0",
    source_product_floor="1.5",
    target_product_version="1.9.1",
    method="POST",
    path="/api/v2/cmdb/secret/database",
    access_group="secretgrp",
    request_model="Body1",
    provider_body_properties=(
        "id",
        "name",
        "inherit-permission",
        "folder",
        "template",
        "field",
    ),
    provider_field_item_properties=("id", "name", "value"),
    logical_success_status=200,
    response_identifier_type="numeric_mkey",
    provider_reads_material_after_create=True,
    target_version_validated=False,
    direct_provider_reuse_permitted=False,
    body_builder_available=False,
    live_call_permitted=False,
)


def secret_create_source_contract() -> SecretCreateSourceContract:
    """Return immutable source evidence without enabling a transport."""

    return _SOURCE_CONTRACT


def require_secret_create_lease_request(
    request: MaterialLeaseRequest,
) -> MaterialLeaseRequest:
    """Reject a lease request that is not bound to this exact action contract."""

    if (
        request.action_id != SECRET_CREATE_ACTION_ID
        or request.action_version != SECRET_CREATE_ACTION_VERSION
        or request.purpose is not MaterialPurpose.INITIAL_ONBOARDING
    ):
        raise SecretCreateAdapterDenied(
            "The private Secret create material binding is unavailable."
        )
    return request


class SecretCreatePrivateAdapter(Protocol):
    """Action-specific private adapter; never exposed as an MCP interface."""

    def dispatch_create(
        self,
        lease: MaterialLease,
        request: MaterialLeaseRequest,
    ) -> SecretCreateAdapterOutcome: ...


class DenyAllSecretCreatePrivateAdapter:
    """Default adapter: deny without inspecting or rendering private objects."""

    def dispatch_create(
        self,
        lease: MaterialLease,
        request: MaterialLeaseRequest,
    ) -> NoReturn:
        del lease, request
        raise SecretCreateAdapterDenied(
            "No accepted private Secret create adapter is configured."
        )


__all__ = [
    "DenyAllSecretCreatePrivateAdapter",
    "SECRET_CREATE_ACTION_ID",
    "SECRET_CREATE_ACTION_VERSION",
    "SecretCreateAdapterDenied",
    "SecretCreateAdapterOutcome",
    "SecretCreateContractStatus",
    "SecretCreatePrivateAdapter",
    "SecretCreateSourceContract",
    "require_secret_create_lease_request",
    "secret_create_source_contract",
]
