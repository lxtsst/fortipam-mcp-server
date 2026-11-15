"""Private M4/C3 entry for the fixed nonprivileged service credential only.

The common composition accepts two exact profiles with distinct action refs and
transport methods. This entry cannot select the privileged proposal. Source,
nonadmin SID/material provenance, original full birth and independent recovery
must still be qualified by the trusted fixed native producer.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import C3MaterialBinding, MaterialLeaseRequest
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome
from v4_planning.secret_create_runtime import SecretCreateMaterialRuntime

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_central_lab_provider import CentralLabSecretCreateResolverLoader
from .windows_execution_secret_contract import WindowsExecutionSecretDefaults
from .windows_service_credential_contract import WindowsServiceCredentialBinding, WindowsServiceCredentialError
from .windows_privileged_secret_material import (
    _SERVICE_ADAPTER_REF as ADAPTER_REF, _SERVICE_TARGET_REF as TARGET_REF,
    _reference_parameters_digest, _reference_secret_material_runtime,
)

__all__ = [
    "ADAPTER_REF", "TARGET_REF", "WindowsServiceCredentialBodyTransport",
    "windows_service_credential_parameters_digest", "windows_service_credential_material_runtime",
]

_ERROR = "The private Windows service credential material lifecycle is unavailable."


class WindowsServiceCredentialBodyTransport(Protocol):
    def _windows_service_credential_ready(self, binding: WindowsServiceCredentialBinding,
            request: MaterialLeaseRequest) -> bool: ...

    def _create_windows_service_credential(self, binding: WindowsServiceCredentialBinding,
            request: MaterialLeaseRequest, body: memoryview) -> SecretCreateAdapterOutcome: ...


def windows_service_credential_parameters_digest(binding: WindowsServiceCredentialBinding,
        defaults: WindowsExecutionSecretDefaults, *, create_uuid: str) -> str:
    try:
        if type(binding) is not WindowsServiceCredentialBinding:
            raise ValueError
        return _reference_parameters_digest(binding, defaults, create_uuid=create_uuid)
    except Exception:
        raise WindowsServiceCredentialError(_ERROR) from None


def windows_service_credential_material_runtime(*, profile: WindowsServiceCredentialBinding,
        defaults: WindowsExecutionSecretDefaults, create_uuid: str,
        plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
        execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
        material_binding: C3MaterialBinding, request: MaterialLeaseRequest,
        loader: CentralLabSecretCreateResolverLoader, transport: WindowsServiceCredentialBodyTransport,
        clock: Callable[[], int]) -> SecretCreateMaterialRuntime:
    """Compose the exact service profile; no HTTP writer, Tool or new authority."""
    try:
        if type(profile) is not WindowsServiceCredentialBinding:
            raise ValueError
        return _reference_secret_material_runtime(profile=profile, defaults=defaults, create_uuid=create_uuid,
            plan=plan, authorization=authorization, execution_store=execution_store, material_store=material_store,
            material_binding=material_binding, request=request, loader=loader, transport=transport, clock=clock)
    except Exception:
        raise WindowsServiceCredentialError(_ERROR) from None
