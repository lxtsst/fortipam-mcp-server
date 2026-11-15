"""Fixed REST transport for metadata-only FortiPAM Secret creation.

The action deliberately sends an empty ``field`` list.  It therefore creates
only Secret metadata and never accepts, reads, returns, logs, or persists a
credential value.  The module owns just the documented ID lookup, exact
Template detail, collection POST, and Secret detail-readback routes; it is not
a generic HTTP relay.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any, Literal
from urllib.parse import quote, urlsplit
import uuid

from .mutable_json_buffer import _erase_transfer_storage, _take_mutable_prefix
from .config import SYSTEM_STATUS_PATH
from .secret_create_191_private_adapter import SecretCreate700DomainBinding
from .target_contract import WebTargetCreateInput


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_"
COLLECTION_PATH = "/api/v2/cmdb/secret/database"
TEMPLATE_COLLECTION_PATH = "/api/v2/cmdb/secret/template"
FOLDER_COLLECTION_PATH = "/api/v2/cmdb/secret/folder"
UTILITY_ID_PATH = "/api/v2/utility/id"
MAX_RESPONSE_BYTES = 1_048_576
SECRET_NAME_PREFIX = "mcp-v4-secret-metadata-"
_SECRET_METADATA_DETAIL_QUERY = (
    "format=id%7Cname%7Cfolder%7Ctemplate%7Ctarget%7Cinherit-permission%7C"
    "proxy%7Crdp-tcp-forward%7Cblock-clipboard%7Crdp-service-status%7Cssh-service-status%7Chttp-service-status%7C"
    "rdp-event-filter%7Crdp-event-filter-profile%7Crecording%7C"
    "need-approval%7Cneed-approval-job%7Cbypass-approval%7Capproval-profile"
)
_WINRM_COLLECTOR_DETAIL_QUERY = (
    "format=id%7Cname%7Cfolder%7Ctemplate%7Ctarget%7Cinherit-permission%7C"
    "target-privilege-account%7Ctarget-info%7Crdp-service-status%7C"
    "ssh-service-status%7Chttp-service-status%7Csamba-service-status%7Ctelnet-service-status%7C"
    "recording%7Crdp-event-filter%7Crdp-event-filter-profile"
)
_DOMAIN_ACCOUNT_DETAIL_QUERY = (
    "format=id%7Cname%7Cfolder%7Ctemplate%7Ctarget%7Cinherit-permission%7C"
    "target-privilege-account%7Crdp-service-status%7Cssh-service-status%7C"
    "sftp-service-status%7Chttp-service-status%7Csamba-service-status%7Ctelnet-service-status"
)
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SECRET_NAME = re.compile(r"mcp-v4-secret-metadata-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_UNAVAILABLE = "FortiPAM V4 Secret metadata action is unavailable."
_SESSION_CONTROLS_EVENT_FILTER_PROFILE_DIGEST_DOMAIN = (
    b"fortipam-mcp:secret-session-controls:rdp-event-filter-profile:v1\x00"
)
_SECRET_CREATE_191_REQUIRED_DEFAULTS: dict[str, object] = {
    "approval-profile": "",
    "av-profile": "",
    "av-scan": "disable",
    "bypass-ssh-filter-for-owner": "disable",
    "dlp-sensor": "",
    "dlp-status": "disable",
    "need-approval": "disable",
    "need-approval-job": "disable",
    "pwd-chg-sch-frequency": "month",
    "pwd-chg-sch-interval": 1,
    "pwd-chg-sch-month-day": "1",
    "pwd-chg-sch-month-type": "specific",
    "pwd-chg-sch-week-day": "",
    "rdp-event-filter": "disable",
    "rdp-event-filter-profile": "",
    "secret-auth": "disable",
    "secret-auth-duration": 60,
    "secret-auth-server": "",
    "server-info": "Inherit",
    "ssh-filter": "disable",
    "ssh-filter-profile": "",
    "winappfilter": "disable",
    "winappfilter-profile": "",
    "target-privilege-account": "disable",
}


class SecretMetadataHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated Secret metadata API configuration is unsafe."""


class SecretMetadataHttpTransportError(RuntimeError):
    """Raised without disclosing a potentially Secret-bearing API response."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretMetadataHttpTransportConfig:
    """Dedicated HTTPS and bearer-token settings held only in process memory."""

    base_url: str
    bearer_token: str
    timeout_seconds: float
    ca_file: str | None

    def __repr__(self) -> str:
        return "<SecretMetadataHttpTransportConfig redacted>"

    __str__ = __repr__

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise SecretMetadataHttpTransportConfigurationError(
                "A dedicated HTTPS Secret metadata API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise SecretMetadataHttpTransportConfigurationError(
                "A dedicated Secret metadata API bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise SecretMetadataHttpTransportConfigurationError(
                "The Secret metadata API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise SecretMetadataHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class SecretMetadataInspection:
    """Private current-state projection with no Secret field content."""

    secret_exists: bool
    folder_exists: bool
    template_exists: bool


@dataclass(frozen=True, slots=True)
class DomainSecretMetadataInspection:
    """Fixed Domain relations and disabled services, without Secret material."""

    secret_exists: bool
    metadata_verified: bool
    field_was_redacted: bool


@dataclass(frozen=True, slots=True)
class SecretMetadataReadback:
    """Categorical post-write evidence with no Secret field content."""

    secret_exists: bool
    folder_matches: bool
    template_matches: bool
    inherit_permission_matches: bool
    field_values_attached: bool

    @property
    def verified(self) -> bool:
        return (
            self.secret_exists
            and self.folder_matches
            and self.template_matches
            and self.inherit_permission_matches
            and not self.field_values_attached
        )


@dataclass(frozen=True, slots=True)
class SecretMetadataProjectionInspection:
    """Categorical existing-state evidence without traversing Secret fields."""

    secret_exists: bool
    folder_exists: bool
    template_exists: bool
    folder_matches: bool
    template_matches: bool
    target_matches: bool
    inherit_permission_matches: bool
    field_values_attached: bool
    rdp_event_filter_matches: bool = False
    recording_matches: bool = False
    rdp_clipboard_control_compatible: bool = False
    rdp_service_enabled: bool = False
    http_service_enabled: bool = False
    ssh_service_enabled: bool = False
    sftp_service_enabled: bool = False
    proxy_mode_enabled: bool = False
    clipboard_blocking_matches: bool = False

    @property
    def metadata_relation_verified(self) -> bool:
        return (
            self.secret_exists
            and self.folder_exists
            and self.template_exists
            and self.folder_matches
            and self.template_matches
            and self.target_matches
            and self.inherit_permission_matches
        )


@dataclass(frozen=True, slots=True)
class SecretPasswordVerificationInspection:
    """Minimized 7.0 password-verification state for an exact bound Secret."""

    enabled: bool
    uses_policy_default: bool
    interval_minutes: int
    start_time_present: bool
    last_change_status_present: bool
    last_verification_status_present: bool
    successful_change_recorded: bool
    successful_verification_recorded: bool


@dataclass(frozen=True, slots=True)
class SecretAutomaticPasswordChangeInspection:
    """Redacted 7.0 automatic-change state for one exact bound Secret."""

    enabled: bool
    uses_policy_default: bool
    frequency: Literal["day", "week", "month"]
    interval: int
    start_date_present: bool
    next_change_present: bool
    successful_change_recorded: bool
    successful_change_after_start: bool


@dataclass(frozen=True, slots=True)
class SecretApprovalProjectionInspection:
    """Categorical approval posture for one existing Secret."""

    secret_exists: bool
    interactive_approval_required: bool
    job_approval_required: bool
    owner_bypass_allowed: bool
    approval_profile_matches: bool
    approval_profile_unset: bool
    field_values_attached: bool


@dataclass(frozen=True, slots=True, repr=False)
class SecretSessionControlsFolderPolicy:
    """Exact direct Folder Policy evidence, retained only in protected code."""

    folder_id: int
    folder_name: str
    policy_name: str
    recording: str
    block_clipboard: str
    rdp_event_filter: str

    def __post_init__(self) -> None:
        if type(self.folder_id) is not int or not 0 < self.folder_id <= 2_147_483_647:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        _segment(self.folder_name)
        _bounded_name(self.policy_name, maximum=128)
        for value in (self.recording, self.block_clipboard, self.rdp_event_filter):
            if type(value) is not str or value not in {"enable", "disable", "not-set"}:
                raise SecretMetadataHttpTransportError(_UNAVAILABLE)

    def preserved_fields(self) -> dict[str, object]:
        return {
            "folder_id": self.folder_id, "folder_name": self.folder_name,
            "inherit-policy": "disable", "secret-policy": self.policy_name,
            "recording": self.recording, "block-clipboard": self.block_clipboard,
            "rdp-event-filter": self.rdp_event_filter,
        }


@dataclass(frozen=True, slots=True, repr=False)
class SecretSessionControlsProjectionInspection:
    """Exact safe projection for one existing Secret's session controls.

    ``preserved_identity_relations_digest`` covers only the fixed allowlist
    validated by :meth:`inspect_session_controls_projection`, including the
    exact direct Folder Policy association and its three control states. It does not
    claim preservation of Secret fields, TOTP data, or unknown metadata.
    """

    recording_enabled: bool
    clipboard_blocking_enabled: bool
    rdp_event_filter_enabled: bool
    rdp_event_filter_profile_matches: bool
    rdp_event_filter_profile_digest: str
    proxy_enabled: bool
    rdp_tcp_forwarding_disabled: bool
    inherit_permission_matches: bool
    preserved_identity_relations_digest: str
    folder_policy: SecretSessionControlsFolderPolicy
    original_name: str
    original_template: str

    def __post_init__(self) -> None:
        _bounded_name(self.original_name, maximum=255)
        _template(self.original_template)


def load_secret_metadata_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> SecretMetadataHttpTransportConfig:
    """Load independently scoped Secret metadata API configuration after opt-in."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise SecretMetadataHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token is None:
        raise SecretMetadataHttpTransportConfigurationError(
            "Dedicated Secret metadata API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise SecretMetadataHttpTransportConfigurationError(
            "The Secret metadata API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return SecretMetadataHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamSecretMetadataHttpTransport:
    """Issue only fixed ID lookup, metadata-only create, and safe readback calls."""

    def verify_domain_account_preflight(
        self, target_name: str, address: str, domain: str, owner_name: str,
        *, expected_classification_tag: str = "Other",
    ) -> bool:
        """Qualify the fixed AD candidate dependency without reading Secret fields."""
        from .target_contract import (
            validate_domain_target_classification_tag, validate_domain_target_reference,
            DOMAIN_TEMPLATE, DOMAIN_TEMPLATE_FIELD_TYPES,
        )
        from .target_http_transport import _domain_native_envelope, _owner_relation_matches
        try:
            validate_domain_target_reference(target_name, address, domain)
            validate_domain_target_classification_tag(expected_classification_tag)
            _segment(owner_name)
            status, payload = self._request("GET", "/api/v2/cmdb/secret/target/" + _segment(target_name),
                None, query="format=name%7Caddress%7Cdomain%7Ctemplate%7Cclass%7Cldaps-port%7Cuser-naming-attribute%7Cuser-base%7Cuser-permission%7Caccess%7Cweb-proxy-status&vdom=root")
            target = _record(payload)
            if (status != 200 or not _domain_native_envelope(payload, "GET", 200)
                or target is None or target.get("name") != target_name or target.get("address") != address
                or target.get("domain") != domain or target.get("template") != DOMAIN_TEMPLATE
                or target.get("class") != expected_classification_tag
                or target.get("ldaps-port") != 636 or target.get("user-naming-attribute") != "sAMAccountName"
                or target.get("user-base") != "" or target.get("access") != "customized"
                or target.get("web-proxy-status") != "disable" or not _owner_relation_matches(target, owner_name)):
                return False
            status, payload = self._request("GET", TEMPLATE_COLLECTION_PATH + "/" + quote(DOMAIN_TEMPLATE, safe=""), None)
            template = _record(payload)
            if (status != 200 or not isinstance(payload, Mapping) or payload.get("version") != "v7.0.0"
                or type(payload.get("build")) is not int or payload.get("build") != 29
                or payload.get("http_method") != "GET" or payload.get("http_status") != 200
                or payload.get("status") != "success" or payload.get("path") != "secret"
                or payload.get("name") != "template" or payload.get("vdom") != "root"
                or (payload.get("error") is not None and (type(payload.get("error")) is not int or payload.get("error") != 0))
                or template is None or template.get("name") != DOMAIN_TEMPLATE):
                return False
            fields = template.get("field", template.get("fields"))
            return (isinstance(fields, list) and len(fields) == 4
                and all(isinstance(item, Mapping) and isinstance(item.get("name"), str) for item in fields)
                and {item.get("name"): item.get("type") for item in fields} == dict(DOMAIN_TEMPLATE_FIELD_TYPES))
        except Exception:
            return False

    def inspect_domain_account_projection(
        self, binding: SecretCreate700DomainBinding, *, expected_secret_id: int | None = None,
    ) -> DomainSecretMetadataInspection:
        """Read only one private-bound Domain Secret after exact dependencies.

        Pre-create absence requires a private qualified global namespace read.
        Path-lookup 404, a fixed post-create ID or drift never becomes absence.
        """
        if (type(binding) is not SecretCreate700DomainBinding
            or self._bound_secret_name != binding.secret_name
            or (expected_secret_id is not None and (
                type(expected_secret_id) is not int or not 0 < expected_secret_id <= 2_147_483_647))):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        folder = _folder_path(binding.folder_path)
        name = _secret_name(binding.secret_name, bound_name=self._bound_secret_name)
        if not self.verify_domain_account_preflight(
            binding.target_name, binding.target_ipv4_address, binding.domain_dns_root,
            binding.target_owner_name, expected_classification_tag=binding.target_classification_tag,
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        folder_id = self._lookup_id("folder", folder)
        if folder_id is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if expected_secret_id is None:
            absent = self._domain_secret_globally_absent(binding, folder_id)
            if type(absent) is not bool:
                raise SecretMetadataHttpTransportError(_UNAVAILABLE)
            if absent:
                return DomainSecretMetadataInspection(False, False, False)
        lookup_status, lookup = self._request(
            "GET", f"{UTILITY_ID_PATH}/{_path_for_url(folder + '/' + name)}", None,
            query="type=secret",
        )
        if not isinstance(lookup, Mapping):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if lookup_status == 200:
            record = lookup.get("results", lookup)
            candidate = record.get("id") if isinstance(record, Mapping) else None
            if (type(candidate) is not int or not 0 < candidate <= 2_147_483_647
                or ("id" in lookup and (type(lookup["id"]) is not int or lookup["id"] != candidate))):
                raise SecretMetadataHttpTransportError(_UNAVAILABLE)
            secret_id = candidate
        else:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if expected_secret_id is not None and secret_id != expected_secret_id:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        status, payload, redacted = self._request_projection_detail(secret_id, domain_account=True)
        detail = _record(payload)
        if status != 200 or detail is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        expected: dict[str, object] = {
            "id": secret_id, "name": name, "folder": folder_id, "template": binding.template_name,
            "target": binding.target_name, "inherit-permission": "enable",
            "target-privilege-account": "disable",
            **{service + "-service-status": "down" for service in ("rdp", "ssh", "sftp", "http", "samba", "telnet")},
        }
        if any(type(detail.get(key)) is not type(value) or detail.get(key) != value
               for key, value in expected.items()):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return DomainSecretMetadataInspection(True, True, redacted)

    def _domain_secret_globally_absent(
        self, binding: SecretCreate700DomainBinding, folder_id: int,
    ) -> bool:
        """Default deny; only the private qualified Owner subclass may attest."""
        return False

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        bound_secret_name: str | None = None,
        client_factory: Callable[..., Any] | None = None,
        detail_connection_factory: Callable[..., Any] | None = None,
        collector_witness_transport: FortiPamSecretMetadataHttpTransport | None = None,
    ) -> None:
        if bound_secret_name is not None:
            _segment(bound_secret_name)
        self._config = config
        self._bound_secret_name = bound_secret_name
        self._client_factory = client_factory
        self._detail_connection_factory = detail_connection_factory
        self._collector_witness_transport = collector_witness_transport

    def inspect(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
    ) -> SecretMetadataInspection:
        """Read Folder/Secret presence and one exact Template detail."""

        folder = _folder_path(folder_path)
        name = _secret_name(secret_name, bound_name=self._bound_secret_name)
        template_name = _template(template)
        folder_id = self._lookup_id("folder", folder)
        secret_id = self._lookup_id("secret", f"{folder}/{name}")
        return SecretMetadataInspection(
            secret_exists=secret_id is not None,
            folder_exists=folder_id is not None,
            template_exists=self._template_exists(template_name),
        )

    def inspect_projection(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
        target_name: str,
        *,
        expected_rdp_event_filter_profile: str | None = None,
    ) -> SecretMetadataProjectionInspection:
        """Read exact safe metadata needed for an idempotent Scheme projection."""

        folder = _folder_path(folder_path)
        name = _secret_name(secret_name, bound_name=self._bound_secret_name)
        template_name = _template(template)
        target = _bounded_name(target_name, maximum=255)
        event_filter_profile = (
            None
            if expected_rdp_event_filter_profile is None
            else _bounded_name(expected_rdp_event_filter_profile, maximum=128)
        )
        folder_id = self._lookup_id("folder", folder)
        secret_id = self._lookup_id("secret", f"{folder}/{name}")
        template_exists = self._template_exists(template_name)
        if secret_id is None:
            return SecretMetadataProjectionInspection(
                False,
                folder_id is not None,
                template_exists,
                False,
                False,
                False,
                False,
                False,
                False,
                False,
            )
        if folder_id is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        status, payload, field_was_redacted = self._request_projection_detail(
            secret_id
        )
        detail = _record(payload)
        if status != 200 or detail is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return SecretMetadataProjectionInspection(
            secret_exists=True,
            folder_exists=True,
            template_exists=template_exists,
            folder_matches=_positive_int(detail.get("folder")) == folder_id,
            template_matches=detail.get("template") == template_name,
            target_matches=detail.get("target") == target,
            inherit_permission_matches=detail.get("inherit-permission") == "enable",
            # FortiPAM 1.9.1 returns ``field`` despite the format allowlist.
            # Its complete value is replaced in a mutable response buffer
            # before JSON decoding; no field item reaches the projection.
            field_values_attached=field_was_redacted,
            rdp_service_enabled=detail.get("rdp-service-status") == "up",
            ssh_service_enabled=detail.get("ssh-service-status") == "up",
            sftp_service_enabled=detail.get("sftp-service-status") == "up",
            recording_matches=detail.get("recording") == "enable",
            rdp_event_filter_matches=(
                event_filter_profile is not None
                and detail.get("rdp-event-filter") == "enable"
                and detail.get("rdp-event-filter-profile") == event_filter_profile
            ),
            # Native RDP clipboard blocking requires proxy mode and does not
            # work with RDP TCP forwarding. This is compatibility evidence,
            # not an assertion that a clipboard blocking setting is enabled.
            rdp_clipboard_control_compatible=(
                detail.get("proxy") == "enable"
                and detail.get("rdp-tcp-forward") == "disable"
            ),
            clipboard_blocking_matches=detail.get("block-clipboard") == "enable",
        )

    def _verify_collector_folder_acl(self, folder_id: int, owner_name: str) -> bool:
        from .folder_http_transport import FortiPamFolderHttpTransport, FolderTransportConfig

        _bounded_name(owner_name, maximum=128)
        folder_transport = FortiPamFolderHttpTransport(FolderTransportConfig(
            base_url=self._config.base_url, bearer_token=self._config.bearer_token,
            timeout_seconds=self._config.timeout_seconds, ca_file=self._config.ca_file,
            explicitly_enabled=True,
        ))
        return folder_transport.verify_owner_only_folder(folder_id, owner_name)

    def resolve_existing_secret_id(self, folder_path: str, secret_name: str) -> int:
        """Resolve only the exact private-bound Secret, never a collection."""
        folder = _folder_path(folder_path)
        name = _secret_name(secret_name, bound_name=self._bound_secret_name)
        secret_id = self._lookup_id("secret", f"{folder}/{name}")
        if secret_id is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return secret_id

    def inspect_password_verification(
        self, folder_path: str, secret_name: str,
    ) -> SecretPasswordVerificationInspection:
        """Redact credential fields before decoding one 7.0 Secret detail."""

        if self._bound_secret_name is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if self.read_product_version_and_build() != ("7.0.0", 29):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        secret_id = self.resolve_existing_secret_id(folder_path, secret_name)
        status, payload, field_redacted = self._request_projection_detail(secret_id)
        detail = _record(payload)
        if (
            status != 200 or not field_redacted or detail is None
            or detail.get("id") != secret_id or detail.get("name") != secret_name
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        heartbeat = _required_enable_disable(detail, "password-heartbeat")
        use_policy_default = _required_enable_disable(
            detail, "heartbeat-use-policy-default"
        )
        interval = detail.get("heartbeat-interval")
        start_time = detail.get("heartbeat-start-time")
        statuses = (
            detail.get("last-password-change-status"),
            detail.get("last-password-verification-status"),
        )
        if (
            type(interval) is not int or not 5 <= interval <= 44640
            or type(start_time) not in {str, int}
            or any(type(value) is not str for value in statuses)
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return SecretPasswordVerificationInspection(
            enabled=heartbeat == "enable",
            uses_policy_default=use_policy_default == "enable",
            interval_minutes=interval,
            start_time_present=start_time not in ("", 0),
            last_change_status_present=bool(statuses[0]),
            last_verification_status_present=bool(statuses[1]),
            successful_change_recorded=(
                detail.get("last-success-password-change-time") not in (None, "", 0)
            ),
            successful_verification_recorded=(
                detail.get("last-success-password-verification-time") not in (None, "", 0)
            ),
        )

    def inspect_automatic_password_change(
        self, folder_path: str, secret_name: str,
    ) -> SecretAutomaticPasswordChangeInspection:
        """Read scheduler categories only after protected Secret fields are redacted."""

        if self._bound_secret_name is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if self.read_product_version_and_build() != ("7.0.0", 29):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        secret_id = self.resolve_existing_secret_id(folder_path, secret_name)
        status, payload, field_redacted = self._request_projection_detail(secret_id)
        detail = _record(payload)
        if (
            status != 200 or not field_redacted or detail is None
            or detail.get("id") != secret_id or detail.get("name") != secret_name
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        changer = _required_enable_disable(detail, "password-changer")
        policy_default = _required_enable_disable(
            detail, "pwd-chg-use-policy-default"
        )
        frequency = detail.get("pwd-chg-sch-frequency")
        interval = detail.get("pwd-chg-sch-interval")
        start_date = detail.get("pwd-chg-sch-start-date")
        next_change = detail.get("next-password-change-time")
        last_success = detail.get("last-success-password-change-time")
        if (
            frequency not in {"day", "week", "month"}
            or type(interval) is not int or not 1 <= interval <= 400
            or type(start_date) not in {str, int}
            or type(next_change) not in {str, int}
            or type(last_success) not in {str, int}
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return SecretAutomaticPasswordChangeInspection(
            enabled=changer == "enable",
            uses_policy_default=policy_default == "enable",
            frequency=frequency,
            interval=interval,
            start_date_present=start_date not in ("", 0),
            next_change_present=next_change not in ("", 0),
            successful_change_recorded=last_success not in ("", 0),
            successful_change_after_start=(
                type(start_date) is int and start_date > 0
                and type(last_success) is int and last_success >= start_date
            ),
        )

    def _verify_winrm_target(self, target_name: str, expected_address: str) -> bool:
        target = _bounded_name(target_name, maximum=255)
        try:
            if str(ipaddress.IPv4Address(expected_address)) != expected_address:
                return False
        except (ValueError, TypeError):
            return False
        status, payload = self._request(
            "GET", "/api/v2/cmdb/secret/target/" + quote(target, safe=""), None,
            query="format=name%7Caddress%7Ctemplate%7Cwinrm-https",
        )
        detail = _record(payload)
        return bool(status == 200 and detail is not None
                    and detail.get("name") == target
                    and detail.get("address") == expected_address
                    and detail.get("template") == "Windows Machine"
                    and detail.get("winrm-https") == "disable")

    def verify_winrm_collector_preflight(
        self,
        folder_path: str,
        secret_name: str,
        owner_name: str,
        witness_folder_path: str,
        witness_secret_name: str,
        target_name: str,
        expected_target_address: str,
    ) -> bool:
        """Check the fixed collector isolation and conflict prerequisites.

        All reads use the same verified appliance. A separately bound read-only
        witness identity may supply conflict evidence without granting either
        identity access to the other's Secret. It never receives CREATE material.
        This authorizes neither material access nor dispatch; the runtime must
        call it before lease acquisition and again for pre-write drift checks.
        """
        folder = _folder_path(folder_path)
        name = _secret_name(secret_name, bound_name=self._bound_secret_name)
        _bounded_name(owner_name, maximum=128)
        if self.read_product_version_and_build() != ("7.0.0", 29):
            return False
        if not self._verify_winrm_target(target_name, expected_target_address):
            return False
        folder_id = self._lookup_id("folder", folder)
        if folder_id is None or self._lookup_id("secret", f"{folder}/{name}") is not None:
            return False
        if not self._verify_collector_folder_acl(folder_id, owner_name):
            return False
        witness_transport = self._collector_witness_transport
        if witness_transport is not None:
            if (witness_transport._bound_secret_name != witness_secret_name
                or not self._same_collector_appliance(witness_transport)):
                return False
        else:
            witness_transport = FortiPamSecretMetadataHttpTransport(
                self._config, bound_secret_name=witness_secret_name,
                client_factory=self._client_factory,
                detail_connection_factory=self._detail_connection_factory,
            )
        return witness_transport.verify_target_has_no_collector(
            witness_folder_path, witness_secret_name, target_name,
        )

    def _same_collector_appliance(self, witness: FortiPamSecretMetadataHttpTransport) -> bool:
        """Compare authenticated status in memory; never expose device identity."""
        if self._config.base_url != witness._config.base_url:
            return False
        try:
            if witness.read_product_version_and_build() != ("7.0.0", 29):
                return False
            own_status, own = self._request("GET", SYSTEM_STATUS_PATH, None)
            other_status, other = witness._request("GET", SYSTEM_STATUS_PATH, None)
            if own_status != 200 or other_status != 200 or not isinstance(own, Mapping) or not isinstance(other, Mapping):
                return False
            serial = own.get("serial")
            return isinstance(serial, str) and 0 < len(serial) <= 128 and serial == other.get("serial")
        except Exception:
            return False

    def verify_target_has_no_collector(
        self,
        witness_folder_path: str,
        witness_secret_name: str,
        target_name: str,
    ) -> bool:
        """Read association through one exact existing Secret on the Target.

        The 7.0 Target CMDB record omits the association. A bound existing
        Secret is therefore required as a witness; absence is never inferred
        from an empty collection, a missing field or an unmatched Target.
        """
        folder = _folder_path(witness_folder_path)
        name = _secret_name(witness_secret_name, bound_name=self._bound_secret_name)
        target = _bounded_name(target_name, maximum=255)
        if self.read_product_version_and_build() != ("7.0.0", 29):
            return False
        folder_id = self._lookup_id("folder", folder)
        secret_id = self._lookup_id("secret", f"{folder}/{name}")
        if folder_id is None or secret_id is None:
            return False
        status, payload, _ = self._request_projection_detail(secret_id, winrm_collector=True)
        detail = _record(payload)
        if status != 200 or detail is None:
            return False
        target_info = detail.get("target-info")
        return bool(
            type(detail.get("id")) is int and detail.get("id") == secret_id
            and detail.get("name") == name
            and type(detail.get("folder")) is int and detail.get("folder") == folder_id
            and detail.get("target") == target
            and detail.get("target-privilege-account") == "disable"
            and isinstance(target_info, Mapping)
            and type(target_info.get("priv_acct")) is int
            and target_info.get("priv_acct") == 0
        )

    def verify_winrm_collector(
        self,
        folder_path: str,
        secret_name: str,
        target_name: str,
        *,
        expected_secret_id: int,
        owner_name: str,
        expected_target_address: str,
        expected_rdp_event_filter_profile: str,
    ) -> bool:
        """Verify fixed 7.0 collector postconditions without exposing material.

        This includes the exact owner-only Folder ACL prerequisite, but is not
        creation authority or proof of all effective appliance access.
        """
        folder = _folder_path(folder_path)
        name = _secret_name(secret_name, bound_name=self._bound_secret_name)
        target = _bounded_name(target_name, maximum=255)
        profile = _bounded_name(expected_rdp_event_filter_profile, maximum=128)
        if type(expected_secret_id) is not int or not 0 < expected_secret_id <= 2_147_483_647:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if self.read_product_version_and_build() != ("7.0.0", 29):
            return False
        if not self._verify_winrm_target(target, expected_target_address):
            return False
        folder_id = self._lookup_id("folder", folder)
        secret_id = self._lookup_id("secret", f"{folder}/{name}")
        if folder_id is None or secret_id != expected_secret_id:
            return False
        if not self._verify_collector_folder_acl(folder_id, owner_name):
            return False
        status, payload, _ = self._request_projection_detail(
            secret_id, winrm_collector=True
        )
        detail = _record(payload)
        if status != 200 or detail is None:
            return False
        target_info = detail.get("target-info")
        return bool(
            type(detail.get("id")) is int
            and detail.get("id") == expected_secret_id
            and detail.get("name") == name
            and type(detail.get("folder")) is int
            and detail.get("folder") == folder_id
            and detail.get("template") == "Windows Machine"
            and detail.get("target") == target
            and detail.get("inherit-permission") == "enable"
            and detail.get("target-privilege-account") == "enable"
            and detail.get("recording") == "enable"
            and detail.get("rdp-event-filter") == "enable"
            and detail.get("rdp-event-filter-profile") == profile
            and isinstance(target_info, Mapping)
            and type(target_info.get("priv_acct")) is int
            and target_info.get("priv_acct") == expected_secret_id
            and detail.get("rdp-service-status") == "up"
            and all(
                detail.get(key) == "down"
                for key in (
                    "ssh-service-status", "http-service-status",
                    "samba-service-status", "telnet-service-status",
                )
            )
        )

    def inspect_web_projection(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
        *,
        expected_secret_id: int | None = None,
    ) -> SecretMetadataProjectionInspection:
        """Read the exact non-Target Web Account relations without field values."""

        folder = _folder_path(folder_path)
        name = _secret_name(secret_name, bound_name=self._bound_secret_name)
        template_name = _template(template)
        if template_name != "Web Account":
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        folder_id = self._lookup_id("folder", folder)
        secret_id = self._lookup_id("secret", f"{folder}/{name}")
        if expected_secret_id is not None and (
            type(expected_secret_id) is not int
            or not 0 < expected_secret_id <= 2_147_483_647
            or secret_id != expected_secret_id
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        template_exists = self._template_exists(template_name)
        if secret_id is None:
            return SecretMetadataProjectionInspection(
                False,
                folder_id is not None,
                template_exists,
                False,
                False,
                False,
                False,
                False,
            )
        if folder_id is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        status, payload, field_was_redacted = self._request_projection_detail(
            secret_id
        )
        detail = _record(payload)
        if status != 200 or detail is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if expected_secret_id is not None:
            expected_identity: dict[str, object] = {
                "id": expected_secret_id,
                "name": name,
                "folder": folder_id,
                "template": template_name,
            }
            if any(
                type(detail.get(key)) is not type(value)
                or detail.get(key) != value
                for key, value in expected_identity.items()
            ):
                raise SecretMetadataHttpTransportError(_UNAVAILABLE)
            # A missing or malformed service state is not a disabled baseline.
            # Pinned reads prepare an existing-object update, so fail closed.
            if (
                detail.get("target") != ""
                or detail.get("http-service-status") not in ("up", "down")
                or detail.get("recording") not in ("enable", "disable")
                or detail.get("inherit-permission") not in ("enable", "disable")
            ):
                raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return SecretMetadataProjectionInspection(
            secret_exists=True,
            folder_exists=True,
            template_exists=template_exists,
            folder_matches=_positive_int(detail.get("folder")) == folder_id,
            template_matches=detail.get("template") == template_name,
            target_matches=detail.get("target") in {None, "", 0},
            inherit_permission_matches=detail.get("inherit-permission") == "enable",
            field_values_attached=field_was_redacted,
            recording_matches=detail.get("recording") == "enable",
            http_service_enabled=detail.get("http-service-status") == "up",
        )

    def inspect_target_bound_web_projection(
        self, folder_path: str, secret_name: str, *, target: WebTargetCreateInput,
        expected_secret_id: int | None = None,
    ) -> SecretMetadataProjectionInspection:
        """Require the exact build-29 Web Target, then read only Secret metadata.

        This separate create-time profile requires Target Web Proxy disabled.
        The accepted targetless reader retains its original no-Target contract.
        """
        if type(target) is not WebTargetCreateInput:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        folder = _folder_path(folder_path)
        name = _secret_name(secret_name, bound_name=self._bound_secret_name)
        if self.read_product_version_and_build() != ("7.0.0", 29):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        status, payload = self._request(
            "GET", "/api/v2/cmdb/secret/target/" + quote(target.target_name, safe=""), None,
            query="format=name%7Ctemplate%7Curl%7Caddress%7Cweb-proxy-status",
        )
        dependency = _record(payload)
        if (status != 200 or dependency is None
                or dependency.get("name") != target.target_name
                or dependency.get("template") != "Web Account"
                or dependency.get("url") != target.web_url
                or dependency.get("address") != ""
                or dependency.get("web-proxy-status") != "disable"
                or not isinstance(payload, Mapping) or payload.get("version") != "v7.0.0"
                or type(payload.get("build")) is not int or payload.get("build") != 29):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        folder_id = self._lookup_id("folder", folder)
        secret_id = self._lookup_id("secret", f"{folder}/{name}")
        if expected_secret_id is not None and (
            type(expected_secret_id) is not int or not 0 < expected_secret_id <= 2_147_483_647
            or secret_id != expected_secret_id
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        template_exists = self._template_exists("Web Account")
        if folder_id is None or not template_exists:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if secret_id is None:
            return SecretMetadataProjectionInspection(False, True, True, False, False, False, False, False)
        status, payload, redacted = self._request_projection_detail(secret_id)
        detail = _record(payload)
        if status != 200 or detail is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        identity: dict[str, object] = {"id": secret_id, "name": name, "folder": folder_id,
                                      "template": "Web Account", "target": target.target_name}
        if any(type(detail.get(key)) is not type(value) or detail.get(key) != value
               for key, value in identity.items()):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if any(detail.get(key) not in options for key, options in (
            ("inherit-permission", ("enable", "disable")), ("recording", ("enable", "disable")),
            ("http-service-status", ("up", "down")), ("proxy", ("enable", "disable")),
        )):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return SecretMetadataProjectionInspection(
            True, True, True, True, True, True,
            detail["inherit-permission"] == "enable", redacted,
            recording_matches=detail["recording"] == "enable",
            http_service_enabled=detail["http-service-status"] == "up",
            proxy_mode_enabled=detail["proxy"] == "enable",
        )

    def inspect_approval_projection(
        self,
        folder_path: str,
        secret_name: str,
        approval_profile_name: str,
        *,
        expected_secret_id: int | None = None,
    ) -> SecretApprovalProjectionInspection:
        """Read approval fields for one exact existing Secret without its fields."""

        folder = _folder_path(folder_path)
        name = _secret_name(secret_name, bound_name=self._bound_secret_name)
        profile = _bounded_name(approval_profile_name, maximum=128)
        secret_id = self._lookup_id("secret", f"{folder}/{name}")
        if expected_secret_id is not None and (
            type(expected_secret_id) is not int
            or expected_secret_id <= 0
            or expected_secret_id > 2_147_483_647
            or secret_id != expected_secret_id
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if secret_id is None:
            return SecretApprovalProjectionInspection(
                False,
                False,
                False,
                False,
                False,
                False,
                False,
            )
        status, payload, field_was_redacted = self._request_projection_detail(
            secret_id
        )
        detail = _record(payload)
        if status != 200 or detail is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        if (
            type(detail.get("id")) is not int
            or detail.get("id") != secret_id
            or type(detail.get("name")) is not str
            or detail.get("name") != name
            or any(
                type(detail.get(key)) is not str
                or detail.get(key) not in ("enable", "disable")
                for key in ("need-approval", "need-approval-job", "bypass-approval")
            )
            or type(detail.get("approval-profile")) is not str
            or detail.get("approval-profile") not in ("", profile)
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return SecretApprovalProjectionInspection(
            secret_exists=True,
            interactive_approval_required=detail.get("need-approval") == "enable",
            job_approval_required=detail.get("need-approval-job") == "enable",
            owner_bypass_allowed=detail.get("bypass-approval") == "enable",
            approval_profile_matches=detail.get("approval-profile") == profile,
            approval_profile_unset=detail.get("approval-profile") == "",
            field_values_attached=field_was_redacted,
        )

    def inspect_session_controls_projection(
        self,
        folder_path: str,
        secret_name: str,
        expected_template: str,
        expected_target: str,
        expected_rdp_event_filter_profile: str,
        *,
        expected_secret_id: int,
    ) -> SecretSessionControlsProjectionInspection:
        """Read exact existing-Secret session controls without Secret material."""

        folder = _folder_path(folder_path)
        name = _secret_name(secret_name, bound_name=self._bound_secret_name)
        template = _template(expected_template)
        target = _bounded_name(expected_target, maximum=255)
        event_filter_profile = _bounded_name(
            expected_rdp_event_filter_profile,
            maximum=128,
        )
        if (
            type(expected_secret_id) is not int
            or expected_secret_id <= 0
            or expected_secret_id > 2_147_483_647
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)

        folder_id = self._lookup_id("folder", folder)
        secret_id = self._lookup_id("secret", f"{folder}/{name}")
        if folder_id is None or secret_id != expected_secret_id:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)

        status, payload, _field_was_redacted = self._request_projection_detail(
            expected_secret_id
        )
        detail = _record(payload)
        if status != 200 or detail is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)

        identity_values: dict[str, object] = {
            "id": expected_secret_id,
            "name": name,
            "folder": folder_id,
            "template": template,
            "target": target,
        }
        if any(
            key not in detail or type(detail[key]) is not type(expected)
            for key, expected in identity_values.items()
        ) or any(detail[key] != expected for key, expected in identity_values.items()):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)

        inherit_permission = _required_enable_disable(
            detail,
            "inherit-permission",
        )
        proxy = _required_enable_disable(detail, "proxy")
        rdp_tcp_forward = _required_enable_disable(detail, "rdp-tcp-forward")
        recording = _required_enable_disable(detail, "recording")
        block_clipboard = _required_enable_disable(detail, "block-clipboard")
        rdp_event_filter = _required_enable_disable(detail, "rdp-event-filter")
        returned_event_filter_profile = detail.get("rdp-event-filter-profile")
        if not isinstance(returned_event_filter_profile, str) or (
            returned_event_filter_profile
            and _bounded_name(returned_event_filter_profile, maximum=128)
            != returned_event_filter_profile
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)

        policy = self._inspect_session_controls_folder_policy(folder, folder_id)
        preserved = {
            **identity_values,
            "inherit-permission": inherit_permission,
            "proxy": proxy,
            "rdp-tcp-forward": rdp_tcp_forward,
            "direct-folder-policy": policy.preserved_fields(),
        }
        return SecretSessionControlsProjectionInspection(
            recording_enabled=recording == "enable",
            clipboard_blocking_enabled=block_clipboard == "enable",
            rdp_event_filter_enabled=rdp_event_filter == "enable",
            rdp_event_filter_profile_matches=(
                returned_event_filter_profile == event_filter_profile
            ),
            rdp_event_filter_profile_digest=(
                _session_controls_event_filter_profile_digest(
                    returned_event_filter_profile
                )
            ),
            proxy_enabled=proxy == "enable",
            rdp_tcp_forwarding_disabled=rdp_tcp_forward == "disable",
            inherit_permission_matches=inherit_permission == "enable",
            preserved_identity_relations_digest=(
                _session_controls_preserved_digest(preserved)
            ),
            folder_policy=policy,
            original_name=name,
            original_template=template,
        )

    def _inspect_session_controls_folder_policy(
        self, folder_path: str, folder_id: int,
    ) -> SecretSessionControlsFolderPolicy:
        status, payload = self._request(
            "GET", f"{FOLDER_COLLECTION_PATH}/{folder_id}", None,
        )
        folder = _record(payload)
        name = folder_path.rsplit("/", 1)[-1]
        if (
            status != 200 or folder is None
            or type(folder.get("id")) is not int or folder["id"] != folder_id
            or folder.get("name") != name
            or folder.get("inherit-policy") != "disable"
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        policy_name = folder.get("secret-policy")
        if not isinstance(policy_name, str):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        policy_name = _bounded_name(policy_name, maximum=128)
        status, payload = self._request(
            "GET", "/api/v2/cmdb/secret/policy/" + quote(policy_name, safe=""), None,
        )
        policy = _record(payload)
        if status != 200 or policy is None or policy.get("name") != policy_name:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        states = [policy.get(key) for key in ("recording", "block-clipboard", "rdp-event-filter")]
        if any(type(value) is not str or value not in ("enable", "disable", "not-set") for value in states):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return SecretSessionControlsFolderPolicy(
            folder_id, name, policy_name,
            str(states[0]), str(states[1]), str(states[2]),
        )

    def read_product_version(self) -> str:
        """Return only a validated version from the fixed strict-TLS status route."""
        try:
            status, payload = self._request("GET", SYSTEM_STATUS_PATH, None)
            if status != 200 or not isinstance(payload, dict):
                raise ValueError
            version = payload.get("version")
            if not isinstance(version, str) or re.fullmatch(r"v?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", version) is None:
                raise ValueError
            return version.removeprefix("v")
        except Exception:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE) from None

    def read_product_version_and_build(self) -> tuple[str, int]:
        """Read the exact candidate firmware identity without exposing status data."""
        try:
            status, payload = self._request("GET", SYSTEM_STATUS_PATH, None)
            if status != 200 or not isinstance(payload, dict):
                raise ValueError
            version, build = payload.get("version"), payload.get("build")
            if (not isinstance(version, str)
                or re.fullmatch(r"v?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", version) is None
                or type(build) is not int or not 0 <= build <= 999999):
                raise ValueError
            return version.removeprefix("v"), build
        except Exception:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE) from None

    def resolve_folder_id(self, folder_path: str) -> int:
        """Resolve one validated Folder path for an internal fixed action."""

        identifier = self._lookup_id("folder", _folder_path(folder_path))
        if identifier is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return identifier

    def resolve_secret_create_uuid(self) -> str:
        """Resolve one 1.9.1 create UUID after exact default validation."""

        status, payload = self._request(
            "GET",
            COLLECTION_PATH,
            None,
            query="action=default",
        )
        detail = _record(payload)
        if (
            status != 200
            or detail is None
            or any(
                detail.get(name) != expected
                for name, expected in _SECRET_CREATE_191_REQUIRED_DEFAULTS.items()
            )
        ):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        value = detail.get("uuid")
        if not isinstance(value, str):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        try:
            normalized = str(uuid.UUID(value))
        except (ValueError, AttributeError) as exc:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE) from exc
        if value.lower() != normalized:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return normalized

    def verify_folder_policy_binding(
        self,
        folder_path: str,
        *,
        expected_folder_id: int,
        expected_folder_name: str,
        expected_policy_name: str,
    ) -> bool:
        """Verify one exact Folder path/detail policy relation without raw output."""

        folder = _folder_path(folder_path)
        folder_name = _segment(expected_folder_name)
        policy_name = _bounded_name(expected_policy_name, maximum=128)
        if folder.rsplit("/", 1)[-1] != folder_name:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        folder_id = self._lookup_id("folder", folder)
        if folder_id != _positive_int(expected_folder_id):
            return False
        status, payload = self._request(
            "GET",
            f"{FOLDER_COLLECTION_PATH}/{expected_folder_id}",
            None,
        )
        detail = _record(payload)
        if status != 200 or detail is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return (
            _positive_int(detail.get("id")) == expected_folder_id
            and detail.get("name") == folder_name
            and detail.get("inherit-policy") == "disable"
            and detail.get("secret-policy") == policy_name
        )

    def create_and_readback(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
    ) -> SecretMetadataReadback:
        """Create one material-free Secret and validate safe metadata only."""

        folder = _folder_path(folder_path)
        name = _secret_name(secret_name, bound_name=self._bound_secret_name)
        template_name = _template(template)
        folder_id = self._lookup_id("folder", folder)
        if folder_id is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        body = {
            "id": 0,
            "name": name,
            "inherit-permission": "enable",
            "folder": folder_id,
            "template": template_name,
            "field": [],
        }
        status, payload = self._request("POST", COLLECTION_PATH, body)
        if status != 200 or not _successful_response(payload):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        secret_id = self._lookup_id("secret", f"{folder}/{name}")
        if secret_id is None:
            return SecretMetadataReadback(False, False, False, False, True)
        detail_status, detail_payload = self._request(
            "GET", f"{COLLECTION_PATH}/{secret_id}", None
        )
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return SecretMetadataReadback(False, False, False, False, True)
        return SecretMetadataReadback(
            secret_exists=True,
            folder_matches=_positive_int(detail.get("folder")) == folder_id,
            template_matches=detail.get("template") == template_name,
            inherit_permission_matches=detail.get("inherit-permission") == "enable",
            field_values_attached=not _field_array_is_empty(detail),
        )

    def _lookup_id(self, object_type: Literal["folder", "secret"], path: str) -> int | None:
        status, payload = self._request(
            "GET",
            f"{UTILITY_ID_PATH}/{_path_for_url(path)}",
            None,
            query=f"type={object_type}",
        )
        if status == 404:
            return None
        if status != 200:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        identifier = _response_id(payload)
        if identifier is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return identifier

    def _template_exists(self, template_name: str) -> bool:
        status, payload = self._request(
            "GET",
            f"{TEMPLATE_COLLECTION_PATH}/{quote(template_name, safe='')}",
            None,
        )
        if status == 404:
            return False
        if status != 200:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        record = _record(payload)
        if record is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        returned_name = record.get("name", record.get("q_origin_key"))
        if returned_name != template_name:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return True

    def _request(
        self,
        method: Literal["GET", "POST", "DELETE"],
        path: str,
        body: Mapping[str, object] | None,
        *,
        query: str | None = None,
    ) -> tuple[int, object | None]:
        url = f"{self._config.base_url}{path}"
        if query is not None:
            url = f"{url}?{query}"
        try:
            import httpx

            factory = self._client_factory or httpx.Client
            with factory(
                verify=_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.request(
                    method,
                    url,
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                    json=body,
                )
        except Exception as exc:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE) from exc

    def _request_projection_detail(
        self,
        secret_id: int,
        *,
        winrm_collector: bool = False,
        domain_account: bool = False,
    ) -> tuple[int, object | None, bool]:
        """Read one detail response while removing ``field`` before decoding."""

        if (type(winrm_collector) is not bool or type(domain_account) is not bool
                or (winrm_collector and domain_account)):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        query = (_DOMAIN_ACCOUNT_DETAIL_QUERY if domain_account else
                 _WINRM_COLLECTOR_DETAIL_QUERY if winrm_collector else _SECRET_METADATA_DETAIL_QUERY)
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        connection: Any = None
        response: Any = None
        content = bytearray(MAX_RESPONSE_BYTES + 1)
        try:
            factory = self._detail_connection_factory or http.client.HTTPSConnection
            connection = factory(
                parsed.hostname,
                parsed.port or 443,
                timeout=self._config.timeout_seconds,
                context=_ssl_context(self._config),
            )
            connection.request(
                "GET",
                f"{COLLECTION_PATH}/{secret_id}?"
                f"{query}",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "User-Agent": "fortipam-mcp-v4-secret-metadata/1",
                    "Cache-Control": "no-cache, no-store",
                    "Pragma": "no-cache",
                },
            )
            response = connection.getresponse()
            status = response.status
            if status != 200:
                return int(status), None, False
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise SecretMetadataHttpTransportError(_UNAVAILABLE)
            total = 0
            while total < len(content):
                view = memoryview(content)[total:]
                try:
                    count = response.readinto(view)
                finally:
                    view.release()
                if not isinstance(count, int) or count < 0:
                    raise SecretMetadataHttpTransportError(_UNAVAILABLE)
                if count == 0:
                    break
                total += count
            if total > MAX_RESPONSE_BYTES:
                raise SecretMetadataHttpTransportError(_UNAVAILABLE)
            content = _take_mutable_prefix(content, total)
            field_was_redacted = _redact_json_field_values(content)
            return int(status), json.loads(content), field_was_redacted
        except SecretMetadataHttpTransportError:
            raise
        except Exception as exc:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE) from exc
        finally:
            _zeroize_mutable(content)
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def _redact_json_field_values(content: bytearray) -> bool:
    """Replace every JSON object ``field`` value before generic decoding."""

    index = 0
    redacted = False
    while index < len(content):
        if content[index] != 34:
            index += 1
            continue
        string_end = _json_string_end(content, index)
        cursor = _skip_json_space(content, string_end + 1)
        if cursor >= len(content) or content[cursor] != 58:
            index = string_end + 1
            continue
        try:
            key = json.loads(content[index : string_end + 1])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE) from exc
        if key != "field":
            index = string_end + 1
            continue
        value_start = _skip_json_space(content, cursor + 1)
        value_end = _json_value_end(content, value_start)
        _replace_json_value_with_null(content, value_start, value_end)
        redacted = True
        index = value_end
    return redacted


def _json_string_end(content: bytearray, start: int) -> int:
    if start >= len(content) or content[start] != 34:
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    escaped = False
    for index in range(start + 1, len(content)):
        byte = content[index]
        if escaped:
            escaped = False
        elif byte == 92:
            escaped = True
        elif byte == 34:
            return index
    raise SecretMetadataHttpTransportError(_UNAVAILABLE)


def _skip_json_space(content: bytearray, start: int) -> int:
    while start < len(content) and content[start] in {9, 10, 13, 32}:
        start += 1
    return start


def _json_value_end(content: bytearray, start: int) -> int:
    if start >= len(content):
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    first = content[start]
    if first == 34:
        return _json_string_end(content, start) + 1
    if first in {91, 123}:
        expected: list[int] = [93 if first == 91 else 125]
        index = start + 1
        while index < len(content):
            byte = content[index]
            if byte == 34:
                index = _json_string_end(content, index) + 1
                continue
            if byte in {91, 123}:
                expected.append(93 if byte == 91 else 125)
            elif byte in {93, 125}:
                if not expected or byte != expected.pop():
                    raise SecretMetadataHttpTransportError(_UNAVAILABLE)
                if not expected:
                    return index + 1
            index += 1
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    index = start
    while index < len(content) and content[index] not in {9, 10, 13, 32, 44, 93, 125}:
        index += 1
    if index == start:
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    return index


def _replace_json_value_with_null(
    content: bytearray,
    start: int,
    end: int,
) -> None:
    width = end - start
    if width == 2 and (
        content[start:end] == b"[]" or content[start:end] == b"{}"
    ):
        return
    if width < 4:
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    content[start:end] = b"null" + b" " * (width - 4)


def _zeroize_mutable(content: bytearray) -> None:
    _erase_transfer_storage(content)
    try:
        content.clear()
    except BufferError:
        pass


def _ssl_context(config: SecretMetadataHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise SecretMetadataHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _folder_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 255:
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    parts = value.split("/")
    if any(_SEGMENT.fullmatch(part) is None for part in parts):
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    return "/".join(parts)


def _secret_name(value: str, *, bound_name: str | None = None) -> str:
    if not isinstance(value, str) or (
        _SECRET_NAME.fullmatch(value) is None and value != bound_name
    ):
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    return value


def _segment(value: str) -> str:
    if not isinstance(value, str) or _SEGMENT.fullmatch(value) is None:
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    return value


def _bounded_name(value: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    return value


def _template(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 79
        or not value.isascii()
        or "/" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
    return value


def _path_for_url(value: str) -> str:
    return "/".join(quote(part, safe="-._~") for part in value.split("/"))


def _response_id(payload: object) -> int | None:
    if not isinstance(payload, Mapping):
        return None
    candidate: object = payload.get("id")
    results = payload.get("results")
    if isinstance(results, Mapping):
        candidate = results.get("id")
    if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate > 0:
        return candidate
    if isinstance(candidate, float) and candidate.is_integer() and candidate > 0:
        return int(candidate)
    return None


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    if isinstance(value, float) and value.is_integer() and value > 0:
        return int(value)
    return None


def _field_array_is_empty(detail: Mapping[str, object]) -> bool:
    """Never traverse field items: their values are outside this action boundary."""

    fields = detail.get("field")
    return fields is None or (isinstance(fields, list) and not fields)


def _required_enable_disable(
    detail: Mapping[str, object],
    name: str,
) -> Literal["enable", "disable"]:
    value = detail.get(name)
    if value == "enable":
        return "enable"
    if value == "disable":
        return "disable"
    raise SecretMetadataHttpTransportError(_UNAVAILABLE)


def _session_controls_preserved_digest(values: Mapping[str, object]) -> str:
    encoded = json.dumps(
        values,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _session_controls_event_filter_profile_digest(profile_name: str) -> str:
    return hashlib.sha256(
        _SESSION_CONTROLS_EVENT_FILTER_PROFILE_DIGEST_DOMAIN
        + profile_name.encode("utf-8")
    ).hexdigest()


def secret_session_controls_event_filter_profile_digest(profile_name: str) -> str:
    """Return the fixed safe digest for one expected event-filter Profile."""

    return _session_controls_event_filter_profile_digest(
        _bounded_name(profile_name, maximum=128)
    )


def _successful_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


__all__ = [
    "COLLECTION_PATH",
    "DomainSecretMetadataInspection",
    "ENV_PREFIX",
    "FOLDER_COLLECTION_PATH",
    "FortiPamSecretMetadataHttpTransport",
    "SECRET_NAME_PREFIX",
    "SecretApprovalProjectionInspection",
    "SecretAutomaticPasswordChangeInspection",
    "SecretMetadataHttpTransportConfig",
    "SecretMetadataHttpTransportConfigurationError",
    "SecretMetadataHttpTransportError",
    "SecretMetadataInspection",
    "SecretMetadataProjectionInspection",
    "SecretMetadataReadback",
    "SecretPasswordVerificationInspection",
    "SecretSessionControlsProjectionInspection",
    "load_secret_metadata_http_transport_config",
    "secret_session_controls_event_filter_profile_digest",
]
