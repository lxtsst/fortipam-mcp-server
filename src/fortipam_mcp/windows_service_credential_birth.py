"""Exact service-credential entry to private original full-birth custody.

The common engine binds distinct fixed profile/adapter/target refs and key
domains. It seals only supplied evidence inside the original active M4/C3.
It neither qualifies native sources nor grants recovery/deletion authority.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import MaterialLeaseRequest

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from .windows_execution_secret_contract import WindowsExecutionSecretDefaults
from .windows_service_credential_contract import WindowsServiceCredentialBinding
from .windows_service_credential_owner_auth import WindowsServiceCredentialOwnerBinding, owner_auth_binding_digest
from .windows_privileged_secret_birth import (
    WindowsPrivilegedSecretBirthError as WindowsServiceCredentialBirthError,
    WindowsPrivilegedSecretOriginalCreation as WindowsServiceCredentialOriginalCreation,
    _ReferenceSecretBirthCustody,
)

__all__ = [
    "WindowsServiceCredentialBirthCustody",
    "WindowsServiceCredentialBirthError",
    "WindowsServiceCredentialOriginalCreation",
]


class WindowsServiceCredentialBirthCustody(_ReferenceSecretBirthCustody):
    """Exact nonprivileged service profile; no caller profile/privilege switch."""
    def __init__(self, directory: Path, witness_key_file: Path, *,
            config: SecretMetadataHttpTransportConfig, profile: WindowsServiceCredentialBinding,
            defaults: WindowsExecutionSecretDefaults, full_row_fields: frozenset[str], plan: M4ExecutionPlan,
            authorization: M4ExecutionAuthorization, request: MaterialLeaseRequest,
            execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
            clock: Callable[[], int], owner_binding: WindowsServiceCredentialOwnerBinding | None = None) -> None:
        if type(profile) is not WindowsServiceCredentialBinding:
            raise WindowsServiceCredentialBirthError("The private original Windows service credential birth custody is unavailable.")
        self._owner_binding = owner_binding
        super().__init__(directory, witness_key_file, config=config, profile=profile, defaults=defaults,
            full_row_fields=full_row_fields, plan=plan, authorization=authorization, request=request,
            execution_store=execution_store, material_store=material_store, clock=clock)

    def _source_digest(self) -> str:
        observer = super()._source_digest()
        if self._owner_binding is None:
            return observer
        binding = self._owner_binding
        if (type(binding) is not WindowsServiceCredentialOwnerBinding
                or binding.serial_digest != self._profile.serial_digest
                or binding.folder_context_digest != self._profile.folder_context_digest):
            raise ValueError
        return canonical_digest(dict(metadata_observer=observer, actual_creator_authentication="owner-cookie",
            creator=owner_auth_binding_digest(self._config, binding)))
