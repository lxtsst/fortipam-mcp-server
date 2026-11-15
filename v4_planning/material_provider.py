"""Fail-closed private C3 material-provider contract for FortiPAM V4.

This module defines the in-process boundary that a future action-specific
provider must implement. It deliberately contains no provider registration,
material resolver, credential loader, product adapter, or runtime binding.
The default provider denies every operation.

Only value-free control metadata may enter :class:`MaterialLeaseRequest`.
Provider-specific bindings and leases remain opaque, non-copyable, and
non-serializable objects whose string representation is always redacted.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import NoReturn, Protocol, SupportsIndex


class MaterialContractError(ValueError):
    """Raised when value-free material control metadata is malformed."""


class MaterialAccessDenied(RuntimeError):
    """Raised when no accepted private C3 provider can perform an operation."""


class MaterialProviderClass(StrEnum):
    FORTIPAM_MANAGED_MATERIAL = "fortipam_managed_material"
    CENTRAL_LAB_INVENTORY_REFERENCE = "central_lab_inventory_reference"
    EXTERNAL_VAULT_LEASE = "external_vault_lease"
    OWNED_LAB_FIXTURE_REFERENCE = "owned_lab_fixture_reference"


class MaterialPurpose(StrEnum):
    INITIAL_ONBOARDING = "initial_onboarding"
    CREDENTIAL_ROTATION = "credential_rotation"
    JIT_DELIVERY = "jit_delivery"


class MaterialBindingStatus(StrEnum):
    AVAILABLE = "available"
    INCOMPATIBLE = "incompatible"
    UNAVAILABLE = "unavailable"
    EXPIRED = "expired"


class MaterialLeaseCompletion(StrEnum):
    RELEASED = "released"
    REVOKED = "revoked"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class MaterialRevocationReason(StrEnum):
    CANCELLED = "cancelled"
    LEASE_EXPIRED = "lease_expired"
    PROVIDER_TIMEOUT = "provider_timeout"
    RECONCILIATION_REQUIRED = "reconciliation_required"


_ACTION = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def _require_digest(value: str, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise MaterialContractError(f"{field} must be a SHA-256 digest.")


class _OpaqueC3Object:
    """Base for provider-owned objects that must never cross output boundaries."""

    __slots__ = ()
    _display_name = "OpaqueC3Object"

    def __repr__(self) -> str:
        return f"<{self._display_name} redacted>"

    __str__ = __repr__

    def __copy__(self) -> NoReturn:
        raise MaterialAccessDenied("Private C3 objects cannot be copied.")

    def __deepcopy__(self, memo: object) -> NoReturn:
        del memo
        raise MaterialAccessDenied("Private C3 objects cannot be copied.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise MaterialAccessDenied("Private C3 objects cannot be serialized.")


class C3MaterialBinding(_OpaqueC3Object):
    """Opaque base for a provider-owned binding; it exposes no locator."""

    __slots__ = ()
    _display_name = "C3MaterialBinding"


class MaterialLease(_OpaqueC3Object):
    """Opaque base for a provider-owned, time-bounded, single-use lease."""

    __slots__ = ()
    _display_name = "MaterialLease"


@dataclass(frozen=True, slots=True, repr=False)
class MaterialLeaseRequest:
    """Value-free context binding one lease request to all preceding gates."""

    action_id: str
    action_version: str
    plan_digest: str
    policy_decision_digest: str
    authorization_digest: str
    scope_digest: str
    audience_digest: str
    provider_class: MaterialProviderClass
    purpose: MaterialPurpose
    requested_at: int
    expires_at: int

    def __post_init__(self) -> None:
        if not isinstance(self.action_id, str) or _ACTION.fullmatch(self.action_id) is None:
            raise MaterialContractError("action_id must be a hyphenated action identifier.")
        if (
            not isinstance(self.action_version, str)
            or _VERSION.fullmatch(self.action_version) is None
        ):
            raise MaterialContractError("action_version must be a semantic version.")
        for field, value in (
            ("plan_digest", self.plan_digest),
            ("policy_decision_digest", self.policy_decision_digest),
            ("authorization_digest", self.authorization_digest),
            ("scope_digest", self.scope_digest),
            ("audience_digest", self.audience_digest),
        ):
            _require_digest(value, field)
        if not isinstance(self.provider_class, MaterialProviderClass):
            raise MaterialContractError("provider_class is not allowed.")
        if not isinstance(self.purpose, MaterialPurpose):
            raise MaterialContractError("purpose is not allowed.")
        if (
            type(self.requested_at) is not int
            or type(self.expires_at) is not int
            or self.requested_at < 0
            or self.expires_at <= self.requested_at
        ):
            raise MaterialContractError("material lease time bound is invalid.")
        if self.provider_class is MaterialProviderClass.OWNED_LAB_FIXTURE_REFERENCE and (
            self.action_id not in {"radius-server-create", "radius-server-pair-create"}
            or self.action_version != "1.0.0"
            or self.purpose is not MaterialPurpose.INITIAL_ONBOARDING
            or self.expires_at - self.requested_at > 60
        ):
            raise MaterialContractError("owned lab fixture material contract is not allowed.")

    def __repr__(self) -> str:
        return "<MaterialLeaseRequest redacted>"

    __str__ = __repr__


class MaterialProvider(Protocol):
    """Private provider protocol; it is never an MCP or planner interface."""

    def validate_binding(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialBindingStatus: ...

    def acquire_lease(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialLease: ...

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion: ...

    def revoke_lease(
        self,
        lease: MaterialLease,
        *,
        reason: MaterialRevocationReason,
    ) -> MaterialLeaseCompletion: ...


class DenyAllMaterialProvider:
    """Default provider: validate as unavailable and deny all lease operations."""

    def validate_binding(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialBindingStatus:
        del binding, request
        return MaterialBindingStatus.UNAVAILABLE

    @staticmethod
    def _deny() -> NoReturn:
        raise MaterialAccessDenied("No accepted C3 material provider is configured.")

    def acquire_lease(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> NoReturn:
        del binding, request
        self._deny()

    def release_lease(self, lease: MaterialLease) -> NoReturn:
        del lease
        self._deny()

    def revoke_lease(
        self,
        lease: MaterialLease,
        *,
        reason: MaterialRevocationReason,
    ) -> NoReturn:
        del lease, reason
        self._deny()


__all__ = [
    "C3MaterialBinding",
    "DenyAllMaterialProvider",
    "MaterialAccessDenied",
    "MaterialBindingStatus",
    "MaterialContractError",
    "MaterialLease",
    "MaterialLeaseCompletion",
    "MaterialLeaseRequest",
    "MaterialProvider",
    "MaterialProviderClass",
    "MaterialPurpose",
    "MaterialRevocationReason",
]
