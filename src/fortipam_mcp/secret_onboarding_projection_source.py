"""Minimized registered read-only observations for SecretOnboardingScheme.

The source composes existing read-only inspections with an owner-only selector
binding. It accepts absence for create planning or an existing Secret only when
the exact metadata-only detail read proves Folder, Template, Target, and
permission inheritance without returning credential fields.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
import ipaddress
import json
import logging
import os
from pathlib import Path
import stat
from typing import Protocol, cast
from urllib.parse import urlsplit

from v4_planning import (
    AuthenticatedRequester,
    AuthoritativeProjection,
    canonical_digest,
    FieldKind,
    FieldRule,
    ObjectClass,
    ProjectionContract,
    SchemeDraft,
    SchemeId,
)
from v4_planning.models import require_digest, require_ref

from .launcher_ssh_transport import (
    LauncherInspection,
    LauncherUpdateBaselineReadback,
)
from .recording_policy_http_transport import RecordingPolicyInspection
from .rdp_event_filter_ssh_transport import (
    RDP_EVENT_FILTER_NAME_PREFIX,
    RdpEventFilterReadback,
)
from .secret_metadata_http_transport import (
    SecretMetadataProjectionInspection,
    SecretSessionControlsProjectionInspection,
    secret_session_controls_event_filter_profile_digest,
)
from .secret_policy_ssh_transport import SecretPolicyUpdateBaseline
from .target_contract import TargetInspection


SOURCE_CONTRACT = "fortipam-secret-onboarding-observation-v1"
LEGACY_SOURCE_VERSION = "1.2.0"
POLICY_SOURCE_VERSION = "1.3.0"
SESSION_SECURITY_SOURCE_VERSION = "1.4.0"
PREVIOUS_SOURCE_VERSION = "1.5.0"
RDP_EVENT_FILTER_SOURCE_VERSION = "1.6.0"
SOURCE_VERSION = "1.7.0"
DOMAIN_SECRET_SOURCE_CONTRACT = "fortipam-domain-secret-observation-v1"
DOMAIN_SECRET_SOURCE_VERSION = "1.0.0"
DOMAIN_SECRET_SOURCE_REF = "fortipam-700-domain-secret-projection"

TARGET_BOUND_WEB_SOURCE_CONTRACT = "fortipam-target-bound-web-observation-v1"
TARGET_BOUND_WEB_SOURCE_VERSION = "1.0.0"
TARGET_BOUND_WEB_SOURCE_REF = "fortipam-700-target-bound-web-projection"
WEB_SERVICE_SOURCE_CONTRACT = "fortipam-web-secret-service-observation-v1"
WEB_SERVICE_SOURCE_VERSION = "1.0.0"
SOURCE_REF = "fortipam-191-secret-onboarding-projection"
SECRET_SESSION_CONTROLS_BINDING_VERSION = "1.9.0"
SECRET_SESSION_CONTROLS_SOURCE_CONTRACT = (
    "fortipam-secret-session-controls-observation-v1"
)
SECRET_SESSION_CONTROLS_SOURCE_VERSION = "1.1.0"
SECRET_SESSION_CONTROLS_SOURCE_REF = (
    "fortipam-191-secret-session-controls-projection"
)
SOURCE_UNAVAILABLE = "FortiPAM Secret onboarding projection source is unavailable."
_MAX_BINDING_BYTES = 32_768
_LOG = logging.getLogger(__name__)


def _projection_unavailable(stage: str) -> "SecretOnboardingProjectionSourceError":
    """Emit one value-free failure stage while preserving the public error."""

    _LOG.warning("secret_onboarding_projection_unavailable stage=%s", stage)
    return SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)


class SecretOnboardingProjectionSourceError(RuntimeError):
    """Stable, non-disclosing source failure."""


class SecretMetadataReadTransport(Protocol):
    def inspect_projection(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
        target_name: str,
        *,
        expected_rdp_event_filter_profile: str | None = None,
    ) -> SecretMetadataProjectionInspection: ...

    def inspect_web_projection(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
    ) -> SecretMetadataProjectionInspection: ...

    def inspect_session_controls_projection(
        self,
        folder_path: str,
        secret_name: str,
        expected_template: str,
        expected_target: str,
        expected_rdp_event_filter_profile: str,
        *,
        expected_secret_id: int,
    ) -> SecretSessionControlsProjectionInspection: ...


class TargetReadTransport(Protocol):
    def inspect(self, target_name: str) -> TargetInspection: ...


class LauncherReadTransport(Protocol):
    def inspect(self, launcher_name: str) -> LauncherInspection: ...

    def update_baseline_readback(
        self,
        launcher_name: str,
    ) -> LauncherUpdateBaselineReadback: ...


class FolderPolicyReadTransport(Protocol):
    def verify_folder_policy_binding(
        self,
        folder_path: str,
        *,
        expected_folder_id: int,
        expected_folder_name: str,
        expected_policy_name: str,
    ) -> bool: ...


class SecretPolicyClipboardReadTransport(Protocol):
    def read_session_security_baseline(
        self,
        policy_name: str,
    ) -> SecretPolicyUpdateBaseline: ...


class RecordingPolicyReadTransport(Protocol):
    def inspect(self, policy_name: str) -> RecordingPolicyInspection: ...


class RdpEventFilterReadTransport(Protocol):
    def readback(self, profile_name: str) -> RdpEventFilterReadback: ...


@dataclass(frozen=True, slots=True, repr=False)
class SecretOnboardingBinding:
    """Protected product selectors bound to exact Scheme object semantics."""

    folder_object_ref: str
    folder_path: str
    folder_ref: str
    target_object_ref: str
    target_name: str
    target_protocol: str
    connectivity_profile_ref: str
    target_ipv4_address: str
    template_object_ref: str
    template_name: str
    template_ref: str
    secret_object_ref: str
    secret_name: str
    launcher_object_ref: str | None = None
    launcher_name: str | None = None
    launcher_profile_ref: str | None = None
    policy_object_ref: str | None = None
    policy_folder_id: int | None = None
    policy_folder_name: str | None = None
    policy_profile_name: str | None = None
    policy_profile_ref: str | None = None
    rdp_event_filter_object_ref: str | None = None
    rdp_event_filter_profile_name: str | None = None
    rdp_event_filter_profile_ref: str | None = None
    secret_session_controls_object_ref: str | None = None
    existing_secret_id: int | None = None
    session_controls_identity_digest: str | None = None

    def __post_init__(self) -> None:
        refs = (
            self.folder_object_ref,
            self.folder_ref,
            self.target_object_ref,
            self.connectivity_profile_ref,
            self.template_object_ref,
            self.template_ref,
            self.secret_object_ref,
        )
        try:
            for value in refs:
                require_ref(value, "Secret onboarding binding reference")
            if self.launcher_object_ref is not None:
                require_ref(self.launcher_object_ref, "Launcher object_ref")
            if self.launcher_profile_ref is not None:
                require_ref(self.launcher_profile_ref, "Launcher profile_ref")
            if self.policy_object_ref is not None:
                require_ref(self.policy_object_ref, "Policy object_ref")
            if self.policy_profile_ref is not None:
                require_ref(self.policy_profile_ref, "Policy profile_ref")
            if self.secret_session_controls_object_ref is not None:
                require_ref(
                    self.secret_session_controls_object_ref,
                    "Secret session controls object_ref",
                )
            if self.session_controls_identity_digest is not None:
                require_digest(
                    self.session_controls_identity_digest,
                    "Secret session controls identity digest",
                )
        except (TypeError, ValueError) as exc:
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        for value in (
            self.folder_path,
            self.target_name,
            self.template_name,
            self.secret_name,
        ):
            _selector(value)
        if (
            self.target_protocol not in {"rdp", "ssh", "sftp"}
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        try:
            normalized_address = str(ipaddress.IPv4Address(self.target_ipv4_address))
        except (ipaddress.AddressValueError, TypeError) as exc:
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if normalized_address != self.target_ipv4_address:
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        launcher_values = (
            self.launcher_object_ref,
            self.launcher_name,
            self.launcher_profile_ref,
        )
        if any(value is None for value in launcher_values) != all(
            value is None for value in launcher_values
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        if self.launcher_name is not None:
            _selector(self.launcher_name)
        policy_values = (
            self.policy_object_ref,
            self.policy_folder_id,
            self.policy_folder_name,
            self.policy_profile_name,
            self.policy_profile_ref,
        )
        if any(value is None for value in policy_values) != all(
            value is None for value in policy_values
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        if self.policy_folder_id is not None:
            if (
                type(self.policy_folder_id) is not int
                or self.policy_folder_id <= 0
                or self.policy_folder_id > 2_147_483_647
            ):
                raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
            _selector(self.policy_folder_name)
            _selector(self.policy_profile_name)
        event_filter_values = (
            self.rdp_event_filter_object_ref,
            self.rdp_event_filter_profile_name,
            self.rdp_event_filter_profile_ref,
        )
        if any(value is None for value in event_filter_values) != all(
            value is None for value in event_filter_values
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        if self.rdp_event_filter_profile_name is not None:
            if (
                self.target_protocol != "rdp"
                or (
                    self.policy_object_ref is None
                    and self.secret_session_controls_object_ref is None
                )
                or not self.rdp_event_filter_profile_name.startswith(
                    RDP_EVENT_FILTER_NAME_PREFIX
                )
            ):
                raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
            _selector(self.rdp_event_filter_profile_name)
            try:
                require_ref(
                    cast(str, self.rdp_event_filter_object_ref),
                    "RDP event-filter object_ref",
                )
                require_ref(
                    cast(str, self.rdp_event_filter_profile_ref),
                    "RDP event-filter profile_ref",
                )
            except (TypeError, ValueError) as exc:
                raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        controls_values = (
            self.secret_session_controls_object_ref,
            self.existing_secret_id,
            self.session_controls_identity_digest,
        )
        if any(value is None for value in controls_values) != all(
            value is None for value in controls_values
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        if self.existing_secret_id is not None and (
            self.target_protocol != "rdp"
            or self.launcher_object_ref is not None
            or self.policy_object_ref is not None
            or self.rdp_event_filter_profile_name is None
            or type(self.existing_secret_id) is not int
            or not 0 < self.existing_secret_id <= 2_147_483_647
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretOnboardingBinding:
    """Protected selectors for the fixed built-in Web Account profile."""

    folder_object_ref: str
    folder_path: str
    folder_ref: str
    template_object_ref: str
    template_name: str
    template_ref: str
    secret_object_ref: str
    secret_name: str
    web_url: str
    session_recording: bool
    service_object_ref: str | None = None
    existing_secret_id: int | None = None

    def __post_init__(self) -> None:
        if (self.service_object_ref is None) != (self.existing_secret_id is None):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        if self.service_object_ref is not None:
            try:
                require_ref(self.service_object_ref, "Web service object reference")
            except ValueError:
                raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE) from None
            if type(self.existing_secret_id) is not int or not 0 < self.existing_secret_id <= 2_147_483_647:
                raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        try:
            for value in (
                self.folder_object_ref,
                self.folder_ref,
                self.template_object_ref,
                self.template_ref,
                self.secret_object_ref,
            ):
                require_ref(value, "Web Secret onboarding binding reference")
            for value in (
                self.folder_path,
                self.template_name,
                self.secret_name,
            ):
                _selector(value)
        except (TypeError, ValueError) as exc:
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        parsed = urlsplit(self.web_url)
        if (
            self.template_name != "Web Account"
            or self.session_recording is not True
            or parsed.scheme not in {"http", "https"}
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
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)


SecretOnboardingProductBinding = SecretOnboardingBinding | WebSecretOnboardingBinding


def secret_onboarding_binding_digest(
    binding: SecretOnboardingProductBinding,
) -> str:
    """Bind every private onboarding selector without returning any selector."""

    if not isinstance(
        binding,
        (SecretOnboardingBinding, WebSecretOnboardingBinding),
    ):
        raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
    binding_values = asdict(binding)
    if isinstance(binding, WebSecretOnboardingBinding) and binding.service_object_ref is None:
        binding_values.pop("service_object_ref")
        binding_values.pop("existing_secret_id")
    if (
        isinstance(binding, SecretOnboardingBinding)
        and binding.secret_session_controls_object_ref is None
        and binding.existing_secret_id is None
        and binding.session_controls_identity_digest is None
    ):
        binding_values.pop("secret_session_controls_object_ref")
        binding_values.pop("existing_secret_id")
        binding_values.pop("session_controls_identity_digest")
    return canonical_digest(
        {
            "binding_type": type(binding).__name__,
            "binding": binding_values,
        }
    )


class SecretOnboardingBindingResolver(Protocol):
    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> SecretOnboardingProductBinding: ...


class OwnerOnlySecretOnboardingBindingResolver:
    """Load one requester/scope-bound selector mapping without following links."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        if not self._path.is_absolute():
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)

    def bound_secret_name(self) -> str:
        """Return the one owner-bound Secret selector for transport attenuation.

        The complete requester/scope binding is still verified by ``resolve``
        before a projection can be produced.  This startup-time selector only
        prevents the metadata transport from expanding beyond the protected
        Secret named by the binding.
        """

        payload = self._load()
        if (
            payload.get("contract") != SOURCE_CONTRACT
            or payload.get("version")
            not in {
                LEGACY_SOURCE_VERSION,
                POLICY_SOURCE_VERSION,
                SESSION_SECURITY_SOURCE_VERSION,
                PREVIOUS_SOURCE_VERSION,
                RDP_EVENT_FILTER_SOURCE_VERSION,
                SOURCE_VERSION,
                SECRET_SESSION_CONTROLS_BINDING_VERSION,
            }
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        return _selector(payload.get("secret_name"))

    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> SecretOnboardingProductBinding:
        payload = self._load()
        exact = {
            "contract",
            "version",
            "requester_digest",
            "environment_ref",
            "scope_ref",
            "folder_object_ref",
            "folder_path",
            "folder_ref",
            "target_object_ref",
            "target_name",
            "target_protocol",
            "connectivity_profile_ref",
            "target_ipv4_address",
            "template_object_ref",
            "template_name",
            "template_ref",
            "secret_object_ref",
            "secret_name",
            "launcher_object_ref",
            "launcher_name",
            "launcher_profile_ref",
        }
        policy_fields = {
            "policy_object_ref",
            "policy_folder_id",
            "policy_folder_name",
            "policy_profile_name",
            "policy_profile_ref",
        }
        event_filter_fields = {
            "rdp_event_filter_object_ref",
            "rdp_event_filter_profile_name",
            "rdp_event_filter_profile_ref",
        }
        session_controls_fields = {
            "secret_session_controls_object_ref",
            "existing_secret_id",
            "session_controls_identity_digest",
        }
        web_exact = {
            "contract",
            "version",
            "requester_digest",
            "environment_ref",
            "scope_ref",
            "folder_object_ref",
            "folder_path",
            "folder_ref",
            "template_object_ref",
            "template_name",
            "template_ref",
            "secret_object_ref",
            "secret_name",
            "web_url",
            "session_recording",
        }
        legacy_metadata_fields = {
            "secret_account_type",
            "secret_enabled",
            "secret_lifecycle_class",
        }
        payload_keys = set(payload)
        frozen_payload_keys = frozenset(payload_keys)
        web_shape = frozen_payload_keys in {frozenset(web_exact), frozenset(web_exact | {"service_object_ref", "existing_secret_id"})}
        version = payload.get("version")
        previous_shape = frozen_payload_keys in {
            frozenset(exact),
            frozenset(exact | policy_fields),
        }
        rdp_event_filter_shape = frozen_payload_keys in {
            frozenset(exact),
            frozenset(exact | policy_fields),
            frozenset(exact | policy_fields | event_filter_fields),
        }
        session_controls_shape = frozen_payload_keys == frozenset(
            exact | event_filter_fields | session_controls_fields
        )
        legacy_shape = frozen_payload_keys in {
            frozenset(exact | legacy_metadata_fields),
            frozenset(exact | legacy_metadata_fields | policy_fields),
        }
        if (
            payload.get("contract") != SOURCE_CONTRACT
            or version
            not in {
                LEGACY_SOURCE_VERSION,
                POLICY_SOURCE_VERSION,
                SESSION_SECURITY_SOURCE_VERSION,
                PREVIOUS_SOURCE_VERSION,
                RDP_EVENT_FILTER_SOURCE_VERSION,
                SOURCE_VERSION,
                SECRET_SESSION_CONTROLS_BINDING_VERSION,
            }
            or (
                version == SOURCE_VERSION
                and not (
                    rdp_event_filter_shape
                    or web_shape
                )
            )
            or (
                version == SECRET_SESSION_CONTROLS_BINDING_VERSION
                and not session_controls_shape
            )
            or (
                version == RDP_EVENT_FILTER_SOURCE_VERSION
                and not rdp_event_filter_shape
            )
            or (version == PREVIOUS_SOURCE_VERSION and not previous_shape)
            or (
                version
                in {
                    LEGACY_SOURCE_VERSION,
                    POLICY_SOURCE_VERSION,
                    SESSION_SECURITY_SOURCE_VERSION,
                }
                and not legacy_shape
            )
            or (
                policy_fields <= payload_keys
                and version == LEGACY_SOURCE_VERSION
            )
            or payload.get("requester_digest") != requester.digest
            or payload.get("environment_ref") != draft.environment_ref
            or payload.get("scope_ref") != draft.scope_ref
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        try:
            if web_shape:
                return WebSecretOnboardingBinding(
                    folder_object_ref=_string(payload, "folder_object_ref"),
                    folder_path=_string(payload, "folder_path"),
                    folder_ref=_string(payload, "folder_ref"),
                    template_object_ref=_string(payload, "template_object_ref"),
                    template_name=_string(payload, "template_name"),
                    template_ref=_string(payload, "template_ref"),
                    secret_object_ref=_string(payload, "secret_object_ref"),
                    secret_name=_string(payload, "secret_name"),
                    web_url=_string(payload, "web_url"),
                    session_recording=_boolean(payload, "session_recording"),
                    service_object_ref=_optional_string(payload, "service_object_ref"),
                    existing_secret_id=(_integer(payload, "existing_secret_id") if payload.get("existing_secret_id") is not None else None),
                )
            has_policy = policy_fields <= payload_keys and any(
                payload.get(field) is not None for field in policy_fields
            )
            return SecretOnboardingBinding(
                folder_object_ref=_string(payload, "folder_object_ref"),
                folder_path=_string(payload, "folder_path"),
                folder_ref=_string(payload, "folder_ref"),
                target_object_ref=_string(payload, "target_object_ref"),
                target_name=_string(payload, "target_name"),
                target_protocol=_string(payload, "target_protocol"),
                connectivity_profile_ref=_string(payload, "connectivity_profile_ref"),
                target_ipv4_address=_string(payload, "target_ipv4_address"),
                template_object_ref=_string(payload, "template_object_ref"),
                template_name=_string(payload, "template_name"),
                template_ref=_string(payload, "template_ref"),
                secret_object_ref=_string(payload, "secret_object_ref"),
                secret_name=_string(payload, "secret_name"),
                launcher_object_ref=_optional_string(payload, "launcher_object_ref"),
                launcher_name=_optional_string(payload, "launcher_name"),
                launcher_profile_ref=_optional_string(payload, "launcher_profile_ref"),
                policy_object_ref=(
                    _string(payload, "policy_object_ref") if has_policy else None
                ),
                policy_folder_id=(
                    _integer(payload, "policy_folder_id") if has_policy else None
                ),
                policy_folder_name=(
                    _string(payload, "policy_folder_name") if has_policy else None
                ),
                policy_profile_name=(
                    _string(payload, "policy_profile_name") if has_policy else None
                ),
                policy_profile_ref=(
                    _string(payload, "policy_profile_ref") if has_policy else None
                ),
                rdp_event_filter_profile_name=(
                    _optional_string(payload, "rdp_event_filter_profile_name")
                    if event_filter_fields <= payload_keys
                    else None
                ),
                rdp_event_filter_object_ref=(
                    _optional_string(payload, "rdp_event_filter_object_ref")
                    if event_filter_fields <= payload_keys
                    else None
                ),
                rdp_event_filter_profile_ref=(
                    _optional_string(payload, "rdp_event_filter_profile_ref")
                    if event_filter_fields <= payload_keys
                    else None
                ),
                secret_session_controls_object_ref=(
                    _string(payload, "secret_session_controls_object_ref")
                    if session_controls_shape
                    else None
                ),
                existing_secret_id=(
                    _integer(payload, "existing_secret_id")
                    if session_controls_shape
                    else None
                ),
                session_controls_identity_digest=(
                    _string(payload, "session_controls_identity_digest")
                    if session_controls_shape
                    else None
                ),
            )
        except (TypeError, ValueError) as exc:
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE) from exc

    def _load(self) -> Mapping[str, object]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._path, flags)
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077
                    or info.st_size <= 0
                    or info.st_size > _MAX_BINDING_BYTES
                ):
                    raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
                content = os.read(descriptor, _MAX_BINDING_BYTES + 1)
            finally:
                os.close(descriptor)
            if len(content) > _MAX_BINDING_BYTES:
                raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
            value = json.loads(content)
        except SecretOnboardingProjectionSourceError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if not isinstance(value, Mapping):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        return cast(Mapping[str, object], value)


class FortiPamSecretOnboardingProjectionSource:
    """Reduce existing read-only inspections to the typed onboarding Scheme."""

    mode = "source_backed"
    contract_registered = True

    def __init__(
        self,
        secret_transport: SecretMetadataReadTransport,
        target_transport: TargetReadTransport | None,
        launcher_transport: LauncherReadTransport | None,
        resolver: SecretOnboardingBindingResolver,
        folder_policy_transport: FolderPolicyReadTransport | None = None,
        secret_policy_clipboard_transport: (
            SecretPolicyClipboardReadTransport | None
        ) = None,
        recording_policy_transport: RecordingPolicyReadTransport | None = None,
        rdp_event_filter_transport: RdpEventFilterReadTransport | None = None,
    ) -> None:
        self._secret_transport = secret_transport
        self._target_transport = target_transport
        self._launcher_transport = launcher_transport
        self._resolver = resolver
        self._folder_policy_transport = folder_policy_transport
        self._secret_policy_clipboard_transport = secret_policy_clipboard_transport
        self._recording_policy_transport = recording_policy_transport
        self._rdp_event_filter_transport = rdp_event_filter_transport

    def project(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> tuple[AuthoritativeProjection, ...]:
        if draft.scheme_id is not SchemeId.SECRET_ONBOARDING or type(now_epoch) is not int:
            raise _projection_unavailable("draft_shape")
        binding = self._binding(draft, requester)
        web_profile = isinstance(binding, WebSecretOnboardingBinding)
        rdp_profile = (
            isinstance(binding, SecretOnboardingBinding)
            and binding.target_protocol == "rdp"
        )
        session_controls_profile = (
            rdp_profile
            and isinstance(binding, SecretOnboardingBinding)
            and binding.secret_session_controls_object_ref is not None
        )
        if web_profile:
            if (
                draft.blueprint_ref != "FPA-BP-007"
                or draft.outcome_code != "onboard_web_account"
            ):
                raise _projection_unavailable("web_draft_binding")
        elif not isinstance(binding, SecretOnboardingBinding):
            raise _projection_unavailable("binding_type")
        if rdp_profile:
            if not isinstance(binding, SecretOnboardingBinding):
                raise _projection_unavailable("rdp_binding_type")
            common_rdp_invalid = (
                draft.blueprint_ref != "FPA-BP-006"
                or draft.outcome_code != "onboard_windows_rdp_resource"
                or (
                    binding.rdp_event_filter_profile_name is not None
                    and self._rdp_event_filter_transport is None
                )
            )
            session_controls_invalid = session_controls_profile and (
                binding.existing_secret_id is None
                or binding.launcher_object_ref is not None
                or binding.policy_object_ref is not None
                or binding.rdp_event_filter_profile_name is None
            )
            create_profile_invalid = not session_controls_profile and (
                binding.launcher_object_ref is None
                or binding.policy_object_ref is None
                or self._folder_policy_transport is None
                or self._secret_policy_clipboard_transport is None
                or self._recording_policy_transport is None
            )
            if common_rdp_invalid or session_controls_invalid or create_profile_invalid:
                raise _projection_unavailable("rdp_binding_contract")
        elif not web_profile:
            if not isinstance(binding, SecretOnboardingBinding):
                raise _projection_unavailable("linux_binding_type")
            if (
                draft.blueprint_ref != "FPA-BP-005"
                or draft.outcome_code != "onboard_privileged_resource"
                or binding.policy_object_ref is not None
            ):
                raise _projection_unavailable("linux_binding_contract")
        desired = {item.object_ref: item for item in draft.desired_objects}
        secret_inherit_permission = True
        if session_controls_profile:
            secret_desired = desired.get(binding.secret_object_ref)
            if (
                secret_desired is None
                or secret_desired.object_class is not ObjectClass.SECRET_METADATA
            ):
                raise _projection_unavailable("session_controls_secret_metadata")
            requested_inherit_permission = dict(secret_desired.desired_fields).get(
                "inherit_permission"
            )
            if type(requested_inherit_permission) is not bool:
                raise _projection_unavailable("session_controls_secret_metadata")
            secret_inherit_permission = requested_inherit_permission
        expected: dict[str, tuple[ObjectClass, dict[str, bool | str]]] = {
            binding.folder_object_ref: (
                ObjectClass.FOLDER_BINDING,
                {"folder_ref": binding.folder_ref},
            ),
            binding.template_object_ref: (
                ObjectClass.TEMPLATE_BINDING,
                {"compatibility": "compatible", "template_ref": binding.template_ref},
            ),
            binding.secret_object_ref: (
                (
                    ObjectClass.WEB_SECRET_METADATA
                    if web_profile
                    else ObjectClass.SECRET_METADATA
                ),
                (
                    {"inherit_permission": True, "session_recording": True}
                    if web_profile
                    else {"inherit_permission": secret_inherit_permission}
                ),
            ),
        }
        if isinstance(binding, WebSecretOnboardingBinding) and binding.service_object_ref is not None:
            expected[binding.service_object_ref] = (
                ObjectClass.WEB_SECRET_SERVICE_BINDING, {"http_service_enabled": True},
            )
        if isinstance(binding, SecretOnboardingBinding):
            expected[binding.target_object_ref] = (
                ObjectClass.TARGET,
                {
                    "connectivity_profile_ref": binding.connectivity_profile_ref,
                    "protocol": binding.target_protocol,
                },
            )
        if (
            isinstance(binding, SecretOnboardingBinding)
            and binding.launcher_object_ref is not None
        ):
            expected[binding.launcher_object_ref] = (
                ObjectClass.LAUNCHER_BINDING,
                {"launcher_profile_ref": cast(str, binding.launcher_profile_ref)},
            )
        if (
            isinstance(binding, SecretOnboardingBinding)
            and binding.policy_object_ref is not None
        ):
            expected[binding.policy_object_ref] = (
                ObjectClass.POLICY_BINDING,
                {"policy_profile_ref": cast(str, binding.policy_profile_ref)},
            )
        if (
            isinstance(binding, SecretOnboardingBinding)
            and binding.rdp_event_filter_object_ref is not None
        ):
            expected[binding.rdp_event_filter_object_ref] = (
                ObjectClass.RDP_EVENT_FILTER_BINDING,
                {
                    "profile_ref": cast(
                        str,
                        binding.rdp_event_filter_profile_ref,
                    )
                },
            )
        if session_controls_profile:
            assert isinstance(binding, SecretOnboardingBinding)
            assert binding.secret_session_controls_object_ref is not None
            assert binding.session_controls_identity_digest is not None
            assert binding.rdp_event_filter_profile_name is not None
            expected[binding.secret_session_controls_object_ref] = (
                ObjectClass.SECRET_SESSION_CONTROLS_BINDING,
                {
                    "clipboard_blocking_enabled": True,
                    "event_filter_profile_digest": (
                        secret_session_controls_event_filter_profile_digest(
                            binding.rdp_event_filter_profile_name
                        )
                    ),
                    "preserved_identity_digest": (
                        binding.session_controls_identity_digest
                    ),
                    "profile_ref": cast(str, binding.rdp_event_filter_profile_ref),
                    "rdp_event_filter_enabled": True,
                    "rdp_event_filter_profile_matches": True,
                    "recording_enabled": True,
                },
            )
        if (
            set(desired) != set(expected)
            or any(
                desired[ref].object_class is not object_class
                or dict(desired[ref].desired_fields) != fields
                or not desired[ref].desired_exists
                for ref, (object_class, fields) in expected.items()
            )
        ):
            raise _projection_unavailable("draft_binding_alignment")
        session_controls: SecretSessionControlsProjectionInspection | None = None
        try:
            if isinstance(binding, WebSecretOnboardingBinding):
                if binding.service_object_ref is not None:
                    reader = getattr(self._secret_transport, "inspect_web_projection")
                    secret = reader(
                        binding.folder_path, binding.secret_name, binding.template_name,
                        expected_secret_id=binding.existing_secret_id,
                    )
                    if not secret.metadata_relation_verified:
                        raise _projection_unavailable("web_service_existing_relation")
                else:
                    secret = self._secret_transport.inspect_web_projection(
                        binding.folder_path, binding.secret_name, binding.template_name,
                    )
                target = None
            else:
                secret = (
                    self._secret_transport.inspect_projection(
                        binding.folder_path,
                        binding.secret_name,
                        binding.template_name,
                        binding.target_name,
                        expected_rdp_event_filter_profile=(
                            binding.rdp_event_filter_profile_name
                        ),
                    )
                    if binding.rdp_event_filter_profile_name is not None
                    else self._secret_transport.inspect_projection(
                        binding.folder_path,
                        binding.secret_name,
                        binding.template_name,
                        binding.target_name,
                    )
                )
                if session_controls_profile:
                    controls_reader = getattr(
                        self._secret_transport,
                        "inspect_session_controls_projection",
                        None,
                    )
                    if not callable(controls_reader):
                        raise _projection_unavailable("session_controls_transport")
                    session_controls = controls_reader(
                        binding.folder_path,
                        binding.secret_name,
                        binding.template_name,
                        binding.target_name,
                        cast(str, binding.rdp_event_filter_profile_name),
                        expected_secret_id=cast(int, binding.existing_secret_id),
                    )
                if self._target_transport is None:
                    raise _projection_unavailable("target_transport")
                target = self._target_transport.inspect(binding.target_name)
            launcher: LauncherInspection | LauncherUpdateBaselineReadback | None = None
            if (
                isinstance(binding, SecretOnboardingBinding)
                and binding.launcher_name is not None
            ):
                if self._launcher_transport is None:
                    raise _projection_unavailable("launcher_transport")
                launcher = (
                    self._launcher_transport.update_baseline_readback(
                        binding.launcher_name
                    )
                    if rdp_profile
                    else self._launcher_transport.inspect(binding.launcher_name)
                )
            policy_exists = False
            event_filter_exists = False
            if (
                isinstance(binding, SecretOnboardingBinding)
                and binding.policy_object_ref is not None
            ):
                policy_exists = (
                    self._read_policy_binding(binding)
                    and self._read_policy_session_security(binding)
                )
            if (
                isinstance(binding, SecretOnboardingBinding)
                and binding.rdp_event_filter_object_ref is not None
            ):
                event_filter_exists = self._read_rdp_event_filter(binding)
        except SecretOnboardingProjectionSourceError:
            raise
        except Exception as exc:
            raise _projection_unavailable("transport_read") from exc
        if (
            not isinstance(secret, SecretMetadataProjectionInspection)
            or (not web_profile and not isinstance(target, TargetInspection))
            or (
                session_controls_profile
                and not isinstance(
                    session_controls,
                    SecretSessionControlsProjectionInspection,
                )
            )
            or (
                launcher is not None
                and not isinstance(
                    launcher,
                    (LauncherInspection, LauncherUpdateBaselineReadback),
                )
            )
        ):
            raise _projection_unavailable("transport_result_shape")
        if secret.secret_exists:
            if session_controls_profile:
                if not (
                    secret.folder_exists
                    and secret.template_exists
                    and secret.folder_matches
                    and secret.template_matches
                    and secret.target_matches
                ):
                    raise _projection_unavailable("secret_metadata_relation")
            elif not secret.metadata_relation_verified:
                raise _projection_unavailable("secret_metadata_relation")
        if web_profile and secret.secret_exists and not secret.recording_matches:
            raise _projection_unavailable("web_recording_relation")
        if (
            secret.secret_exists
            and isinstance(binding, SecretOnboardingBinding)
            and binding.rdp_event_filter_object_ref is not None
            and not session_controls_profile
            and not secret.rdp_event_filter_matches
        ):
            raise _projection_unavailable("rdp_event_filter_relation")
        if (
            rdp_profile
            and not session_controls_profile
            and secret.secret_exists
            and not secret.rdp_clipboard_control_compatible
        ):
            raise _projection_unavailable("rdp_clipboard_control_compatibility")
        if rdp_profile and not session_controls_profile and (
            not secret.folder_exists
            or not secret.template_exists
            or not isinstance(target, TargetInspection)
            or not target.exists
            or not isinstance(launcher, LauncherUpdateBaselineReadback)
            or not launcher.verified
            or not policy_exists
        ):
            raise _projection_unavailable("rdp_required_baseline")
        if session_controls_profile:
            if (
                not isinstance(binding, SecretOnboardingBinding)
                or not secret.secret_exists
                or not isinstance(target, TargetInspection)
                or not target.exists
                or not event_filter_exists
                or not isinstance(
                    session_controls,
                    SecretSessionControlsProjectionInspection,
                )
                or not session_controls.proxy_enabled
                or not session_controls.rdp_tcp_forwarding_disabled
                or secret.inherit_permission_matches
                != session_controls.inherit_permission_matches
            ):
                raise _projection_unavailable("session_controls_required_baseline")
        exists = {
            binding.folder_object_ref: secret.folder_exists,
            binding.template_object_ref: secret.template_exists,
            binding.secret_object_ref: secret.secret_exists,
        }
        if isinstance(binding, SecretOnboardingBinding):
            if not isinstance(target, TargetInspection):
                raise _projection_unavailable("target_result_shape")
            exists[binding.target_object_ref] = target.exists
        if (
            isinstance(binding, SecretOnboardingBinding)
            and binding.launcher_object_ref is not None
            and launcher is not None
        ):
            exists[binding.launcher_object_ref] = launcher.launcher_name_exists
        if (
            isinstance(binding, SecretOnboardingBinding)
            and binding.policy_object_ref is not None
        ):
            exists[binding.policy_object_ref] = policy_exists
        if (
            isinstance(binding, SecretOnboardingBinding)
            and binding.rdp_event_filter_object_ref is not None
        ):
            exists[binding.rdp_event_filter_object_ref] = event_filter_exists
        if session_controls_profile:
            assert isinstance(binding, SecretOnboardingBinding)
            assert binding.secret_session_controls_object_ref is not None
            assert isinstance(
                session_controls,
                SecretSessionControlsProjectionInspection,
            )
            exists[binding.secret_session_controls_object_ref] = True
        actual_fields: dict[str, dict[str, bool | str | int]] = {}
        if isinstance(binding, WebSecretOnboardingBinding) and binding.service_object_ref is not None:
            exists[binding.service_object_ref] = True
            actual_fields[binding.service_object_ref] = {
                "exists": True, "http_service_enabled": secret.http_service_enabled,
            }
        if session_controls_profile:
            assert isinstance(binding, SecretOnboardingBinding)
            assert binding.secret_session_controls_object_ref is not None
            assert isinstance(
                session_controls,
                SecretSessionControlsProjectionInspection,
            )
            actual_fields[binding.secret_object_ref] = {
                "exists": True,
                "inherit_permission": session_controls.inherit_permission_matches,
            }
            actual_fields[binding.secret_session_controls_object_ref] = {
                "clipboard_blocking_enabled": (
                    session_controls.clipboard_blocking_enabled
                ),
                "event_filter_profile_digest": (
                    session_controls.rdp_event_filter_profile_digest
                ),
                "exists": True,
                "preserved_identity_digest": (
                    session_controls.preserved_identity_relations_digest
                ),
                "profile_ref": cast(str, binding.rdp_event_filter_profile_ref),
                "rdp_event_filter_enabled": (
                    session_controls.rdp_event_filter_enabled
                ),
                "rdp_event_filter_profile_matches": (
                    session_controls.rdp_event_filter_profile_matches
                ),
                "recording_enabled": session_controls.recording_enabled,
            }
        projections: list[AuthoritativeProjection] = []
        for item in draft.desired_objects:
            fields = actual_fields.get(
                item.object_ref,
                {"exists": exists[item.object_ref]},
            )
            if exists[item.object_ref] and item.object_ref not in actual_fields:
                fields.update(dict(item.desired_fields))
            projections.append(
                AuthoritativeProjection.from_mapping(
                    contract=secret_onboarding_projection_contract(item.object_class),
                    object_ref=item.object_ref,
                    observed_at=now_epoch,
                    fresh_until=now_epoch + 300,
                    fields=fields,
                )
            )
        return tuple(projections)

    def _read_policy_binding(self, binding: SecretOnboardingBinding) -> bool:
        transport = self._folder_policy_transport
        folder_id = binding.policy_folder_id
        if transport is None or folder_id is None:
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        folder_name = binding.policy_folder_name
        policy_name = binding.policy_profile_name
        if folder_name is None or policy_name is None:
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        return transport.verify_folder_policy_binding(
            binding.folder_path,
            expected_folder_id=folder_id,
            expected_folder_name=folder_name,
            expected_policy_name=policy_name,
        )

    def _read_policy_session_security(
        self,
        binding: SecretOnboardingBinding,
    ) -> bool:
        clipboard_transport = self._secret_policy_clipboard_transport
        recording_transport = self._recording_policy_transport
        policy_name = binding.policy_profile_name
        if (
            clipboard_transport is None
            or recording_transport is None
            or policy_name is None
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        clipboard = clipboard_transport.read_session_security_baseline(policy_name)
        recording = recording_transport.inspect(policy_name)
        if not isinstance(clipboard, SecretPolicyUpdateBaseline) or not isinstance(
            recording,
            RecordingPolicyInspection,
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        return (
            clipboard.policy_name_exists
            and clipboard.rdp_clipboard_block_enabled
            and recording.policy_exists
            and recording.recording_enabled
        )

    def _read_rdp_event_filter(self, binding: SecretOnboardingBinding) -> bool:
        profile_name = binding.rdp_event_filter_profile_name
        if profile_name is None:
            return True
        transport = self._rdp_event_filter_transport
        if transport is None:
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        readback = transport.readback(profile_name)
        return isinstance(readback, RdpEventFilterReadback) and readback.verified

    def _binding(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> SecretOnboardingProductBinding:
        try:
            value = self._resolver.resolve(draft, requester)
        except Exception as exc:
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if not isinstance(
            value,
            (SecretOnboardingBinding, WebSecretOnboardingBinding),
        ):
            raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
        return value

    def resolve_private_binding(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> SecretOnboardingProductBinding:
        """Resolve the private selectors for an internal fixed-action binder."""

        return self._binding(draft, requester)


def secret_onboarding_projection_contract(object_class: ObjectClass) -> ProjectionContract:
    rules: dict[ObjectClass, tuple[FieldRule, ...]] = {
        ObjectClass.FOLDER_BINDING: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("folder_ref", FieldKind.REFERENCE),
        ),
        ObjectClass.TARGET: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule(
                "protocol",
                FieldKind.ENUM,
                ("database", "https", "rdp", "sftp", "ssh", "supported_other"),
            ),
            FieldRule("connectivity_profile_ref", FieldKind.REFERENCE),
        ),
        ObjectClass.TEMPLATE_BINDING: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("template_ref", FieldKind.REFERENCE),
            FieldRule("compatibility", FieldKind.ENUM, ("compatible", "unknown")),
        ),
        ObjectClass.SECRET_METADATA: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("inherit_permission", FieldKind.BOOLEAN),
        ),
        ObjectClass.WEB_SECRET_SERVICE_BINDING: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("http_service_enabled", FieldKind.BOOLEAN),
        ),
        ObjectClass.DOMAIN_TARGET_BINDING: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("profile_ref", FieldKind.REFERENCE),
            FieldRule("target_relation_matches", FieldKind.BOOLEAN),
        ),
        ObjectClass.DOMAIN_SECRET_METADATA: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("inherit_permission", FieldKind.BOOLEAN),
            FieldRule("non_privileged_account", FieldKind.BOOLEAN),
            FieldRule("services_disabled", FieldKind.BOOLEAN),
            FieldRule("target_association_matches", FieldKind.BOOLEAN),
        ),
        ObjectClass.WEB_TARGET_BINDING: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("profile_ref", FieldKind.REFERENCE),
            FieldRule("target_relation_matches", FieldKind.BOOLEAN),
        ),
        ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("inherit_permission", FieldKind.BOOLEAN),
            FieldRule("session_recording", FieldKind.BOOLEAN),
            FieldRule("http_service_enabled", FieldKind.BOOLEAN),
            FieldRule("proxy_mode_enabled", FieldKind.BOOLEAN),
            FieldRule("target_association_matches", FieldKind.BOOLEAN),
        ),
        ObjectClass.WEB_SECRET_METADATA: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("inherit_permission", FieldKind.BOOLEAN),
            FieldRule("session_recording", FieldKind.BOOLEAN),
        ),
        ObjectClass.LAUNCHER_BINDING: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("launcher_profile_ref", FieldKind.REFERENCE),
        ),
        ObjectClass.POLICY_BINDING: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("policy_profile_ref", FieldKind.REFERENCE),
        ),
        ObjectClass.RDP_EVENT_FILTER_BINDING: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("profile_ref", FieldKind.REFERENCE),
        ),
        ObjectClass.SECRET_SESSION_CONTROLS_BINDING: (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("recording_enabled", FieldKind.BOOLEAN),
            FieldRule("clipboard_blocking_enabled", FieldKind.BOOLEAN),
            FieldRule("rdp_event_filter_enabled", FieldKind.BOOLEAN),
            FieldRule("rdp_event_filter_profile_matches", FieldKind.BOOLEAN),
            FieldRule("event_filter_profile_digest", FieldKind.DIGEST),
            FieldRule("preserved_identity_digest", FieldKind.DIGEST),
            FieldRule("profile_ref", FieldKind.REFERENCE),
        ),
    }
    if object_class not in rules:
        raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
    if object_class in {ObjectClass.DOMAIN_TARGET_BINDING, ObjectClass.DOMAIN_SECRET_METADATA}:
        return ProjectionContract(
            contract_id=DOMAIN_SECRET_SOURCE_CONTRACT,
            version=DOMAIN_SECRET_SOURCE_VERSION,
            source_ref=DOMAIN_SECRET_SOURCE_REF,
            object_class=object_class,
            field_rules=rules[object_class], max_age_seconds=300,
        )
    if object_class in {
        ObjectClass.WEB_TARGET_BINDING, ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA,
    }:
        return ProjectionContract(
            contract_id=TARGET_BOUND_WEB_SOURCE_CONTRACT,
            version=TARGET_BOUND_WEB_SOURCE_VERSION,
            source_ref=TARGET_BOUND_WEB_SOURCE_REF,
            object_class=object_class,
            field_rules=rules[object_class],
            max_age_seconds=300,
        )
    session_controls = object_class is ObjectClass.SECRET_SESSION_CONTROLS_BINDING
    web_service = object_class is ObjectClass.WEB_SECRET_SERVICE_BINDING
    return ProjectionContract(
        contract_id=(
            SECRET_SESSION_CONTROLS_SOURCE_CONTRACT
            if session_controls
            else WEB_SERVICE_SOURCE_CONTRACT if web_service else SOURCE_CONTRACT
        ),
        version=(
            SECRET_SESSION_CONTROLS_SOURCE_VERSION
            if session_controls
            else WEB_SERVICE_SOURCE_VERSION if web_service else SOURCE_VERSION
        ),
        source_ref=(
            SECRET_SESSION_CONTROLS_SOURCE_REF if session_controls else SOURCE_REF
        ),
        object_class=object_class,
        field_rules=rules[object_class],
        max_age_seconds=300,
    )


def _selector(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
    return value


def _string(value: Mapping[str, object], name: str) -> str:
    result = value.get(name)
    if not isinstance(result, str):
        raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
    return result


def _optional_string(value: Mapping[str, object], name: str) -> str | None:
    result = value.get(name)
    if result is not None and not isinstance(result, str):
        raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
    return result


def _boolean(value: Mapping[str, object], name: str) -> bool:
    result = value.get(name)
    if type(result) is not bool:
        raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
    return result


def _integer(value: Mapping[str, object], name: str) -> int:
    result = value.get(name)
    if type(result) is not int:
        raise SecretOnboardingProjectionSourceError(SOURCE_UNAVAILABLE)
    return result


__all__ = [
    "FortiPamSecretOnboardingProjectionSource",
    "FolderPolicyReadTransport",
    "LEGACY_SOURCE_VERSION",
    "LauncherReadTransport",
    "OwnerOnlySecretOnboardingBindingResolver",
    "POLICY_SOURCE_VERSION",
    "PREVIOUS_SOURCE_VERSION",
    "RDP_EVENT_FILTER_SOURCE_VERSION",
    "RdpEventFilterReadTransport",
    "SESSION_SECURITY_SOURCE_VERSION",
    "RecordingPolicyReadTransport",
    "SOURCE_CONTRACT",
    "SOURCE_REF",
    "SOURCE_VERSION",
    "SECRET_SESSION_CONTROLS_BINDING_VERSION",
    "SECRET_SESSION_CONTROLS_SOURCE_CONTRACT",
    "SECRET_SESSION_CONTROLS_SOURCE_REF",
    "SECRET_SESSION_CONTROLS_SOURCE_VERSION",
    "SecretMetadataReadTransport",
    "SecretPolicyClipboardReadTransport",
    "SecretOnboardingBinding",
    "SecretOnboardingBindingResolver",
    "SecretOnboardingProductBinding",
    "SecretOnboardingProjectionSourceError",
    "TargetReadTransport",
    "WebSecretOnboardingBinding",
    "secret_onboarding_projection_contract",
    "secret_onboarding_binding_digest",
]
