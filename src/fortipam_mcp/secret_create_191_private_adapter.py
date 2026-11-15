"""No-material interface for a future fixed FortiPAM 1.9.1 Secret create transport.

This adapter deliberately has no JSON body API.  A separately accepted private
transport must consume the opaque lease and protected target binding internally,
perform the fixed create plus no-material verification, and return one closed
categorical outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import stat
import re
from typing import Protocol
from urllib.parse import urlsplit

from .target_contract import (
    validate_domain_target_classification_tag,
    validate_domain_target_reference,
    WebTargetCreateInput,
)

from v4_planning.material_provider import MaterialLease, MaterialLeaseRequest
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    SecretCreateAdapterDenied,
    SecretCreateAdapterOutcome,
    require_secret_create_lease_request,
)


_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_SELECTOR = re.compile(r"^[^\x00-\x1f\x7f]{1,255}$")


@dataclass(frozen=True, slots=True, repr=False)
class SecretCreate191TargetBinding:
    contract_ref: str
    target_product_version: str
    plan_digest: str
    folder_path: str
    secret_name: str
    template_name: str
    target_name: str
    target_ipv4_address: str
    rdp_event_filter_profile_name: str | None = None
    rdp_service_enabled: bool = False
    target_product_build: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.rdp_service_enabled) is not bool
            or (self.contract_ref, self.target_product_version, self.target_product_build) not in {
                ("fortipam-191-secret-create-private-v1", "1.9.1", None),
                ("fortipam-700-build29-linux-ssh-create-candidate-v1", "7.0.0", 29),
                ("fortipam-700-build29-linux-ssh-sftp-recording-create-candidate-v2", "7.0.0", 29),
                ("fortipam-700-build29-windows-rdp-create-candidate-v1", "7.0.0", 29),
            }
            or _DIGEST.fullmatch(self.plan_digest) is None
            or any(
                _SELECTOR.fullmatch(value) is None
                for value in (
                    self.folder_path,
                    self.secret_name,
                    self.template_name,
                    self.target_name,
                )
            )
        ):
            raise SecretCreateAdapterDenied(
                "The FortiPAM 1.9.1 Secret-create target binding is unavailable."
            )
        try:
            normalized_address = str(ipaddress.IPv4Address(self.target_ipv4_address))
        except (ipaddress.AddressValueError, TypeError) as exc:
            raise SecretCreateAdapterDenied(
                "The FortiPAM 1.9.1 Secret-create target binding is unavailable."
            ) from exc
        if normalized_address != self.target_ipv4_address:
            raise SecretCreateAdapterDenied(
                "The FortiPAM 1.9.1 Secret-create target binding is unavailable."
            )
        if (
            self.rdp_event_filter_profile_name is not None
            and (
                _SELECTOR.fullmatch(self.rdp_event_filter_profile_name) is None
                or not self.rdp_event_filter_profile_name.startswith(
                    "mcp-v4-rdp-event-filter-"
                )
            )
        ):
            raise SecretCreateAdapterDenied(
                "The FortiPAM 1.9.1 Secret-create target binding is unavailable."
            )
        if self.contract_ref == "fortipam-700-build29-windows-rdp-create-candidate-v1" and (
            self.template_name != "Windows Machine" or not self.rdp_service_enabled
        ):
            raise SecretCreateAdapterDenied(
                "The build-29 Windows RDP Secret-create binding is unavailable."
            )
        if self.target_product_build == 29 and self.contract_ref != "fortipam-700-build29-windows-rdp-create-candidate-v1" and (
            self.template_name != "Unix Account (SSH Password)"
            or self.rdp_service_enabled
            or self.rdp_event_filter_profile_name is not None
        ):
            raise SecretCreateAdapterDenied(
                "The build-29 Linux SSH Secret-create binding is unavailable."
            )


@dataclass(frozen=True, slots=True, repr=False)
class SecretCreate191WebBinding:
    """Exact non-Target Web Account request selectors held outside MCP data."""

    contract_ref: str
    target_product_version: str
    plan_digest: str
    folder_path: str
    secret_name: str
    template_name: str
    web_url: str
    session_recording: bool
    target_product_build: int | None = None

    def __post_init__(self) -> None:
        if (
            (self.contract_ref, self.target_product_version, self.target_product_build) not in {
                ("fortipam-191-web-secret-create-private-v1", "1.9.1", None),
                ("fortipam-700-build29-web-secret-create-candidate-v1", "7.0.0", 29),
            }
            or (self.target_product_build is not None and type(self.target_product_build) is not int)
            or _DIGEST.fullmatch(self.plan_digest) is None
            or self.template_name != "Web Account"
            or self.session_recording is not True
            or any(
                _SELECTOR.fullmatch(value) is None
                for value in (
                    self.folder_path,
                    self.secret_name,
                    self.template_name,
                )
            )
        ):
            raise SecretCreateAdapterDenied(
                "The FortiPAM 1.9.1 Web Secret-create binding is unavailable."
            )
        parsed = urlsplit(self.web_url)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or len(self.web_url) > 2048
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.web_url
            )
        ):
            raise SecretCreateAdapterDenied(
                "The FortiPAM 1.9.1 Web Secret-create binding is unavailable."
            )


@dataclass(frozen=True, slots=True, repr=False)
class SecretCreate700WebTargetBinding:
    """Separate private build-29 Web profile; URL belongs to the exact Target."""

    contract_ref: str
    target_product_version: str
    plan_digest: str
    folder_path: str
    secret_name: str
    template_name: str
    target: WebTargetCreateInput
    session_recording: bool
    target_product_build: int = 29

    def __post_init__(self) -> None:
        if (self.contract_ref != "fortipam-700-build29-target-bound-web-create-candidate-v1"
                or self.target_product_version != "7.0.0"
                or type(self.target_product_build) is not int or self.target_product_build != 29
                or type(self.target) is not WebTargetCreateInput
                or not isinstance(self.plan_digest, str) or _DIGEST.fullmatch(self.plan_digest) is None
                or self.template_name != "Web Account" or self.session_recording is not True
                or any(not isinstance(value, str) or _SELECTOR.fullmatch(value) is None
                       for value in (self.folder_path, self.secret_name))):
            raise SecretCreateAdapterDenied("The private Target-bound Web binding is unavailable.")


@dataclass(frozen=True, slots=True, repr=False)
class SecretCreate700WinrmBinding:
    """Private selectors for the explicit noninteractive collector profile."""

    contract_ref: str
    target_product_version: str
    plan_digest: str
    folder_path: str
    secret_name: str
    template_name: str
    target_name: str
    target_ipv4_address: str
    folder_owner_name: str
    witness_folder_path: str
    witness_secret_name: str
    rdp_event_filter_profile_name: str
    target_product_build: int = 29

    def __post_init__(self) -> None:
        if (
            self.contract_ref != "fortipam-700-build29-winrm-collector-create-candidate-v2"
            or self.target_product_version != "7.0.0"
            or type(self.target_product_build) is not int
            or self.target_product_build != 29
            or self.template_name != "Windows Machine"
            or _DIGEST.fullmatch(self.plan_digest) is None
            or any(not isinstance(value, str) or _SELECTOR.fullmatch(value) is None
                   for value in (self.folder_path, self.secret_name, self.target_name,
                                 self.folder_owner_name, self.witness_folder_path,
                                 self.witness_secret_name, self.rdp_event_filter_profile_name))
            or not self.rdp_event_filter_profile_name.startswith("mcp-v4-rdp-event-filter-")
            or (self.folder_path, self.secret_name)
            == (self.witness_folder_path, self.witness_secret_name)
        ):
            raise SecretCreateAdapterDenied("The WinRM collector binding is unavailable.")
        try:
            if str(ipaddress.IPv4Address(self.target_ipv4_address)) != self.target_ipv4_address:
                raise ValueError
        except (ValueError, TypeError) as exc:
            raise SecretCreateAdapterDenied("The WinRM collector binding is unavailable.") from exc


def load_winrm_collector_private_binding(path: Path) -> SecretCreate700WinrmBinding:
    """Load fixed non-material selectors from one owner-only regular file."""
    try:
        if not path.is_absolute():
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or not 0 < info.st_size <= 16384):
                raise ValueError
            content = os.read(descriptor, 16385)
        finally:
            os.close(descriptor)
        if len(content) > 16384:
            raise ValueError
        value = json.loads(content)
        required = {
            "contract_ref", "target_product_version", "target_product_build",
            "folder_path", "secret_name", "template_name", "target_name",
            "target_ipv4_address", "folder_owner_name", "witness_folder_path", "witness_secret_name",
            "rdp_event_filter_profile_name",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError
        return SecretCreate700WinrmBinding(**value, plan_digest="0" * 64)
    except Exception:
        raise SecretCreateAdapterDenied("The WinRM collector binding is unavailable.") from None


@dataclass(frozen=True, slots=True, repr=False)
class SecretCreate700DomainBinding:
    """Private build-29 AD candidate; it does not enable an MCP action."""

    contract_ref: str
    target_product_version: str
    plan_digest: str
    folder_path: str
    secret_name: str
    template_name: str
    target_name: str
    target_ipv4_address: str
    domain_dns_root: str
    target_owner_name: str
    target_product_build: int = 29
    target_classification_tag: str = "Other"

    def __post_init__(self) -> None:
        try:
            if (self.contract_ref != "fortipam-700-build29-domain-account-create-candidate-v1"
                or self.target_product_version != "7.0.0"
                or type(self.target_product_build) is not int or self.target_product_build != 29
                or self.template_name != "Windows Domain Account"
                or not isinstance(self.plan_digest, str) or _DIGEST.fullmatch(self.plan_digest) is None
                or any(not isinstance(value, str) or _SELECTOR.fullmatch(value) is None
                    for value in (self.folder_path, self.secret_name, self.target_owner_name))):
                raise ValueError
            validate_domain_target_reference(self.target_name, self.target_ipv4_address, self.domain_dns_root)
            validate_domain_target_classification_tag(self.target_classification_tag)
        except (ValueError, TypeError):
            raise SecretCreateAdapterDenied("The private domain Account binding is unavailable.") from None


SecretCreate191Binding = (
    SecretCreate191TargetBinding | SecretCreate191WebBinding | SecretCreate700WinrmBinding
    | SecretCreate700DomainBinding | SecretCreate700WebTargetBinding
)


class SecretCreate191LeaseTransport(Protocol):
    """Private transport with no body, material, endpoint, or method argument."""

    def create_and_verify(
        self,
        binding: SecretCreate191Binding,
        lease: MaterialLease,
        request: MaterialLeaseRequest,
    ) -> SecretCreateAdapterOutcome: ...


class FortiPam191SecretCreatePrivateAdapter:
    """Bind one target and one private lease transport to the fixed action."""

    __slots__ = ("_binding", "_transport")

    def __init__(
        self,
        binding: SecretCreate191Binding,
        transport: SecretCreate191LeaseTransport,
    ) -> None:
        if not callable(getattr(transport, "create_and_verify", None)):
            raise SecretCreateAdapterDenied(
                "The FortiPAM 1.9.1 Secret-create transport is unavailable."
            )
        self._binding = binding
        self._transport = transport

    def dispatch_create(
        self,
        lease: MaterialLease,
        request: MaterialLeaseRequest,
    ) -> SecretCreateAdapterOutcome:
        exact = require_secret_create_lease_request(request)
        if (
            exact.action_id != SECRET_CREATE_ACTION_ID
            or exact.action_version != SECRET_CREATE_ACTION_VERSION
            or exact.plan_digest != self._binding.plan_digest
            or not isinstance(lease, MaterialLease)
        ):
            raise SecretCreateAdapterDenied(
                "The FortiPAM 1.9.1 Secret-create binding is unavailable."
            )
        try:
            outcome = self._transport.create_and_verify(
                self._binding,
                lease,
                exact,
            )
        except Exception:
            return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        if outcome is SecretCreateAdapterOutcome.VERIFIED_CREATED:
            return outcome
        return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED


__all__ = [
    "FortiPam191SecretCreatePrivateAdapter",
    "SecretCreate191Binding",
    "SecretCreate191LeaseTransport",
    "SecretCreate191TargetBinding",
    "SecretCreate191WebBinding",
    "SecretCreate700WinrmBinding",
    "SecretCreate700DomainBinding",
    "SecretCreate700WebTargetBinding",
]
