"""Private fixed service credential on an existing Windows Target.

No privileged-account toggle or ownership of the existing Target is accepted.
The exact native nonadmin SID/material and original OS service context must be
qualified outside this pure contract. Supplied digests are not admission. No
transport, authority issuer, material reader, recovery action or Tool is added.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .secret_metadata_http_transport import _zeroize_mutable
from .windows_execution_secret_contract import REQUEST_UUID, WindowsExecutionSecretDefaults, _defaults_digest, _machine
from .windows_privileged_secret_contract import (
    _SELECTOR, _compile_reference_body, _project_reference_metadata, _reference_metadata,
)

CONTRACT = "fortipam-700-build29-windows-service-credential-existing-target-private-v1"
_NAME = re.compile(r"MCPV4SvcCred[0-9]{8}R[1-9][0-9]{0,2}\Z")
_ERROR = "The private Windows service credential is unavailable."


class WindowsServiceCredentialError(RuntimeError):
    """Fixed private refusal without selectors, account details or materials."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialBinding(_OpaqueC3Object):
    secret_name: str
    target_name: str
    target_address: str
    machine_name: str
    folder_id: int
    serial_digest: str
    target_reference_context_digest: str
    subject_context_digest: str
    subject_sid_digest: str
    material_source_context_digest: str
    service_context_digest: str
    association_context_digest: str
    folder_context_digest: str
    private_nonce: str

    def __post_init__(self) -> None:
        try:
            if (type(self.secret_name) is not str or _NAME.fullmatch(self.secret_name) is None
                    or type(self.target_name) is not str or _SELECTOR.fullmatch(self.target_name) is None
                    or self.target_name != self.target_name.strip()
                    or self.target_name.startswith("MCPV4WinTarget")
                    or len(self.target_name.encode("utf-8")) > 127
                    or type(self.folder_id) is not int or not 0 < self.folder_id <= 2147483647
                    or type(self.target_address) is not str):
                raise ValueError
            address = ipaddress.IPv4Address(self.target_address)
            if (str(address) != self.target_address or address.is_loopback or address.is_unspecified
                    or address.is_multicast or address.is_link_local):
                raise ValueError
            _machine(self.machine_name)
            for value in (self.serial_digest, self.target_reference_context_digest,
                          self.subject_context_digest, self.subject_sid_digest, self.material_source_context_digest,
                          self.service_context_digest, self.association_context_digest,
                          self.folder_context_digest, self.private_nonce):
                require_digest(value, "private_context_digest")
        except Exception:
            raise WindowsServiceCredentialError(_ERROR) from None

    @property
    def parameters_digest(self) -> str:
        self.__post_init__()
        return canonical_digest({"contract": CONTRACT, **{
            name: getattr(self, name) for name in self.__dataclass_fields__
        }})

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, fixed_service_credential_proposal=True,
                    privileged_account_requested=False, interactive_services_requested=False,
                    automatic_password_lifecycle_requested=False, existing_target_adoption_authorized=False,
                    nonadmin_subject_qualified=False, original_subject_sid_qualified=False,
                    material_source_qualified=False, original_service_qualified=False,
                    association_scope_qualified=False, original_birth_qualified=False,
                    effective_permission_qualified=False, independent_recovery_qualified=False,
                    execution_authorized=False, runtime_registered=False, private_values_returned=False)


def _metadata(binding: WindowsServiceCredentialBinding) -> dict[str, object]:
    return _reference_metadata(binding.secret_name, binding.target_name, binding.folder_id)


def build_windows_service_credential_body(binding: WindowsServiceCredentialBinding,
        defaults: WindowsExecutionSecretDefaults, *, create_uuid: str,
        username: memoryview, password: memoryview) -> bytearray:
    """Borrow a qualified local pair for one fixed nonprivileged proposal."""
    try:
        if type(binding) is not WindowsServiceCredentialBinding or type(defaults) is not WindowsExecutionSecretDefaults:
            raise ValueError
        binding.__post_init__()
        if (defaults.serial_digest != binding.serial_digest
                or defaults.guards_digest != _defaults_digest(defaults.policy_defaults)
                or type(create_uuid) is not str or create_uuid != REQUEST_UUID):
            raise ValueError
        return _compile_reference_body(_metadata(binding), binding.machine_name, username=username, password=password)
    except Exception:
        raise WindowsServiceCredentialError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialMetadata(_OpaqueC3Object):
    native_secret_id: int
    native_uuid: str
    password_field_id: int
    metadata_digest: str

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, supplied_fixed_service_credential_metadata_matched=True,
                    supplied_target_info_privileged_id_is_zero=True,
                    source_completeness_qualified=False, nonadmin_subject_qualified=False,
                    material_consistency_qualified=False, original_birth_qualified=False,
                    target_preservation_qualified=False, effective_permission_qualified=False,
                    independent_recovery_qualified=False, execution_authorized=False,
                    runtime_registered=False, private_values_returned=False)


def _project_windows_service_credential_metadata(raw: bytearray, binding: WindowsServiceCredentialBinding, *,
        expected_secret_id: int, expected_native_uuid: str | None = None) -> WindowsServiceCredentialMetadata:
    """Borrow only inside private custody; no native source completeness claim."""
    try:
        if type(binding) is not WindowsServiceCredentialBinding:
            raise ValueError
        binding.__post_init__()
        native_uuid, field_id, digest = _project_reference_metadata(raw,
            serial_digest=binding.serial_digest, parameters_digest=binding.parameters_digest,
            target_address=binding.target_address, expected_metadata=_metadata(binding), contract=CONTRACT,
            expected_association_id=0, expected_secret_id=expected_secret_id,
            expected_native_uuid=expected_native_uuid)
        return WindowsServiceCredentialMetadata(expected_secret_id, native_uuid, field_id, digest)
    except Exception:
        raise WindowsServiceCredentialError(_ERROR) from None


def consume_windows_service_credential_metadata(raw: bytearray, binding: WindowsServiceCredentialBinding, *,
        expected_secret_id: int, expected_native_uuid: str | None = None) -> WindowsServiceCredentialMetadata:
    """Consume one supplied native GET/OK frame; clear input on every exit."""
    try:
        return _project_windows_service_credential_metadata(raw, binding,
            expected_secret_id=expected_secret_id, expected_native_uuid=expected_native_uuid)
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)
