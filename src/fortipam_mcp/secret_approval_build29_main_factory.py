"""Real, fixed build-29 main composition with independently closed execution.

The readonly context loads only protected configuration and its explicitly
referenced API token. Account Username, private sources, SSH credentials,
qualification manifests and execution state are not read during construction.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import hmac
import json
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import cast
from urllib.parse import urlsplit

from v4_planning.models import require_digest, require_ref
from v4_planning.approval import ApprovalReceiptAuthenticator

from .approval_and_observe_execution_mcp_action import ProtectedApprovalAndObserveMcpAction
from .approver_authority_sidecar import UnixApproverAuthorizationClient, UnixApproverAuthorizationClientSettings
from .approval_and_observe_projection_source import ApprovalAndObserveBinding
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_collector_runtime import PREFIX as OWNER_PREFIX, owner_login_provider
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_approval_build29_http_transport import (
    FortiPamSecretApprovalBuild29HttpTransport, SecretApprovalBuild29LinuxFieldsBinding,
)
from .secret_approval_build29_m4_composition import SecretApprovalBuild29M4RunnerFactory
from .secret_approval_build29_metadata_reader import (
    SecretApprovalBuild29ProfileReader, SecretApprovalBuild29ProjectionReader,
)
from .secret_approval_build29_private_sources import SecretApprovalBuild29PrivateSources
from .secret_approval_build29_projection_source import (
    SOURCE_CONTRACT, SOURCE_VERSION, _BINDING_KEYS, _reject_constant, _unique_members,
    FortiPamSecretApprovalBuild29ProjectionSource, OwnerOnlySecretApprovalBuild29BindingResolver,
)
from .secret_approval_build29_runtime_provider import (
    OwnerOnlySecretApprovalBuild29QualificationVerifier, OwnerOnlySecretApprovalBuild29UsernameSource,
    OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier, OwnerOnlySecretApprovalBuild29EnvUsernameSource,
    OwnerOnlySecretApprovalBuild29RemoteUsernameSource,
    SecretApprovalBuild29RuntimeProducer, _read_private_buffer,
)
from .secret_create_central_lab_provider import (
    _parse_prebound_secret_env, _read_owner_only_secret_env_file, _validated_variable_name,
)
from .secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig, _zeroize_mutable,
)
from .target_ssh_transport import TargetSshTransportConfig
from .v4_runtime_host import V4PlanHostComponents


PREFIX = "FORTIPAM_MCP_V4_APPROVAL_BUILD29_"
RUNTIME_CONTRACT = "fortipam-700-build29-approval-main-runtime-v1"
RUNTIME_VERSION = "1.0.0"
RUNTIME_KEYS = frozenset({
    "contract", "version", "source_plan_ref", "approval_receipt_ref", "authorization_ref",
    "environment_ref", "scope_ref", "requester_digest", "folder_id", "serial", "owner_name", "web_url",
    "username_file", "claim_directory", "witness_key_file", "known_hosts_file", "ssh_port",
    "qualification_file", "qualification_authority_ref", "qualification_key_file", "evidence_digest",
    "execution_db", "execution_key_file", "secret_env_file", "owner_username_variable",
    "owner_password_variable", "api_token_variable", "base_url", "ca_file",
    "approval_receipt_key_file", "approver_authority_socket", "approver_authority_ref",
})
LINUX_RUNTIME_CONTRACT = "fortipam-700-build29-linux-approval-main-runtime-v1"
LINUX_RUNTIME_VERSION = "1.0.0"
LINUX_RUNTIME_KEYS = (RUNTIME_KEYS - {"web_url", "username_file", "secret_env_file"}) | {
    "linux_target_name", "linux_target_ipv4_address", "linux_username_env_file",
    "linux_username_variable", "owner_api_env_file", "ssh_host", "expected_folder_acl_digest",
}
LINUX_REMOTE_RUNTIME_CONTRACT = "fortipam-700-build29-linux-remote-approval-main-runtime-v1"
LINUX_REMOTE_RUNTIME_KEYS = (LINUX_RUNTIME_KEYS - {"linux_username_env_file", "linux_username_variable"}) | {"linux_username_reference_file"}
_PATH_KEYS = frozenset({
    "username_file", "claim_directory", "witness_key_file", "known_hosts_file", "qualification_file",
    "qualification_key_file", "execution_db", "execution_key_file", "secret_env_file",
    "approval_receipt_key_file", "approver_authority_socket",
})
_UNAVAILABLE = "Protected build-29 approval main composition is unavailable."


class SecretApprovalBuild29MainFactoryError(RuntimeError):
    """Stable refusal without configuration, credential or selector values."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29MainContext:
    """Typed readonly getters and one sealed execution-factory association."""

    secret_transport: SecretApprovalBuild29ProjectionReader
    approval_profile_transport: SecretApprovalBuild29ProfileReader
    binding_resolver: OwnerOnlySecretApprovalBuild29BindingResolver
    _owner: OwnerSessionMetadataTransport
    _credentials: Callable[[], tuple[str, str]]
    _settings: Mapping[str, object]
    _binding: ApprovalAndObserveBinding
    _binding_payload: Mapping[str, object]
    _enabled: bool
    _lock: Lock = field(default_factory=Lock)
    _components: V4PlanHostComponents | None = None
    _action: ProtectedApprovalAndObserveMcpAction | None = None
    _initialization_attempted: bool = False
    _planning_authorities: tuple[ApprovalReceiptAuthenticator, UnixApproverAuthorizationClient] | None = None
    _planning_authorities_attempted: bool = False

    def planning_authorities(self) -> tuple[ApprovalReceiptAuthenticator, UnixApproverAuthorizationClient]:
        """Load one dedicated receipt key; defer UDS readiness to the host."""
        with self._lock:
            raw = bytearray()
            try:
                if self._enabled is not True:
                    raise ValueError
                if self._planning_authorities is not None:
                    return self._planning_authorities
                if self._planning_authorities_attempted:
                    raise ValueError
                object.__setattr__(self, "_planning_authorities_attempted", True)
                raw = _read_private_buffer(_path(self._settings, "approval_receipt_key_file"), 4096)
                authenticator = ApprovalReceiptAuthenticator(bytes(raw))
                authority = UnixApproverAuthorizationClient(UnixApproverAuthorizationClientSettings(
                    _path(self._settings, "approver_authority_socket"),
                    cast(str, self._settings["approver_authority_ref"]),
                ))
                pair = (authenticator, authority)
                object.__setattr__(self, "_planning_authorities", pair)
                return pair
            except Exception:
                raise SecretApprovalBuild29MainFactoryError(_UNAVAILABLE) from None
            finally:
                _zeroize_mutable(raw)

    def execution_factory(self, components: V4PlanHostComponents) -> ProtectedApprovalAndObserveMcpAction:
        """Bind only these build-29 getters to existing protected chain services.

        This creates no source qualification receipt. The independently signed
        exact-plan manifest is verified by the runtime before an M4 claim.
        """
        with self._lock:
            sources: SecretApprovalBuild29PrivateSources | None = None
            witness_key, qualification_key, execution_key = bytearray(), bytearray(), bytearray()
            try:
                if self._enabled is not True or type(components) is not V4PlanHostComponents:
                    raise ValueError
                source = components.approval_and_observe_projection_source
                planning = components._secret_approval_planning_reader
                authenticator = components._secret_approval_receipt_authenticator
                authority = components._secret_approval_approver_authority_ref
                pair = self._planning_authorities
                if (type(source) is not FortiPamSecretApprovalBuild29ProjectionSource
                        or source._secret_transport is not self.secret_transport
                        or source._approval_profile_transport is not self.approval_profile_transport
                        or source._resolver is not self.binding_resolver
                        or planning is None or type(authenticator) is not ApprovalReceiptAuthenticator or authority is None
                        or pair is None or authenticator is not pair[0] or authority != pair[1].authority_ref
                        or self.binding_resolver._load() != self._binding_payload):
                    raise ValueError
                gate = components.plan_services._workflow._approval_gate
                if gate._receipt_authenticator is not pair[0] or gate._approver_authorizer is not pair[1]:
                    raise ValueError
                require_ref(authority, "approver authority")
                if self._action is not None:
                    if components is not self._components:
                        raise ValueError
                    return self._action
                if self._initialization_attempted:
                    raise ValueError
                object.__setattr__(self, "_initialization_attempted", True)
                settings = self._settings
                # The keyed store validates and reuses its own ledger on a
                # restart. No ledger is copied, reset or removed here.
                database = _path(settings, "execution_db")
                username, password = self._credentials()
                if username != settings["owner_name"]:
                    raise ValueError
                linux = settings["contract"] in {LINUX_RUNTIME_CONTRACT, LINUX_REMOTE_RUNTIME_CONTRACT}
                host = (cast(str, settings["ssh_host"]) if linux
                        else urlsplit(cast(str, settings["base_url"])).hostname)
                if host is None:
                    raise ValueError
                ssh = TargetSshTransportConfig(
                    host, cast(int, settings["ssh_port"]), username, password,
                    _path(settings, "known_hosts_file"), 15,
                )
                del username, password
                witness_key = _read_private_buffer(_path(settings, "witness_key_file"), 4096)
                qualification_key = _read_private_buffer(_path(settings, "qualification_key_file"), 4096)
                execution_key = _read_private_buffer(_path(settings, "execution_key_file"), 128)
                if (len(witness_key) < 32 or len(qualification_key) < 32 or len(execution_key) < 32
                        or authenticator.uses_key_material(bytes(qualification_key))
                        or hmac.compare_digest(qualification_key, witness_key)
                        or hmac.compare_digest(qualification_key, execution_key)):
                    raise ValueError
                binding = self._binding
                web_url = None if linux else cast(str, settings["web_url"])
                linux_target = cast(str, settings["linux_target_name"]) if linux else None
                account_source = _username_source(settings)
                sources = SecretApprovalBuild29PrivateSources(
                    self._owner, ssh, expected_serial=cast(str, settings["serial"]),
                    expected_secret_id=binding.secret_id, expected_secret_name=binding.secret_name,
                    folder_path=binding.folder_path, expected_folder_id=cast(int, settings["folder_id"]),
                    web_url=web_url, witness_key=witness_key,
                    linux_target_name=linux_target, expected_ssh_host=host if linux else None,
                )
                producer = SecretApprovalBuild29RuntimeProducer(
                    self._owner, sources, binding=binding, expected_folder_id=cast(int, settings["folder_id"]),
                    expected_serial=cast(str, settings["serial"]), web_url=web_url,
                    username_source=account_source, linux_target_name=linux_target,
                    expected_folder_acl_digest=cast(str, settings["expected_folder_acl_digest"]) if linux else None,
                    linux_target_ipv4_address=cast(str, settings["linux_target_ipv4_address"]) if linux else None,
                    claim_directory=_path(settings, "claim_directory"), execution_enabled=True,
                )
                qualifier_type = (OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier if linux
                                  else OwnerOnlySecretApprovalBuild29QualificationVerifier)
                qualifier = qualifier_type(
                    _path(settings, "qualification_file"), authority_ref=cast(str, settings["qualification_authority_ref"]),
                    authority_key=bytes(qualification_key), expected_evidence_digest=cast(str, settings["evidence_digest"]),
                )
                store = PersistentM4ExecutionStateStore(database, _path(settings, "execution_key_file"))
                if not hmac.compare_digest(store._key, execution_key):
                    raise ValueError
                factory = SecretApprovalBuild29M4RunnerFactory(
                    planning=planning, receipt_authenticator=authenticator, producer=producer, execution_store=store,
                    source_plan_ref=cast(str, settings["source_plan_ref"]),
                    approval_receipt_ref=cast(str, settings["approval_receipt_ref"]),
                    approver_authority_ref=authority, authorization_ref=cast(str, settings["authorization_ref"]),
                    authorized_environment_ref=cast(str, settings["environment_ref"]),
                    authorized_scope_ref=cast(str, settings["scope_ref"]),
                    qualification_verifier=qualifier, execution_enabled=True, clock=components._clock,
                )
                action = components.bind_approval_and_observe_execution_mcp_action(
                    factory, authorized_environment_ref=cast(str, settings["environment_ref"]),
                    authorized_scope_ref=cast(str, settings["scope_ref"]), execution_enabled=True,
                )
                if type(action) is not ProtectedApprovalAndObserveMcpAction:
                    raise ValueError
                object.__setattr__(self, "_components", components)
                object.__setattr__(self, "_action", action)
                return action
            except Exception:
                if sources is not None:
                    sources.close()
                raise SecretApprovalBuild29MainFactoryError(_UNAVAILABLE) from None
            finally:
                _zeroize_mutable(witness_key)
                _zeroize_mutable(qualification_key)
                _zeroize_mutable(execution_key)


def build_secret_approval_build29_main_context(
    environment: Mapping[str, str], binding_path: Path, *, execution_enabled: bool = False,
) -> SecretApprovalBuild29MainContext:
    """Load the explicit private runtime contract without account-material reads."""
    raw = bytearray()
    try:
        if type(execution_enabled) is not bool:
            raise ValueError
        runtime_path = _absolute(environment[PREFIX + "RUNTIME_FILE"])
        if not isinstance(binding_path, Path) or not binding_path.is_absolute() or ".." in binding_path.parts:
            raise ValueError
        raw = _read_private_buffer(runtime_path, 16384)
        value = json.loads(raw, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
        settings = _qualify_settings(value, runtime_path, binding_path)
        resolver = OwnerOnlySecretApprovalBuild29BindingResolver(binding_path)
        payload = resolver._load()
        binding = _qualified_binding(payload, settings)
        credential_environment = {
            OWNER_PREFIX + "SESSION_ENABLED": "true", OWNER_PREFIX + "LOGIN_ENV_FILE": str(_owner_api_env_path(settings)),
            OWNER_PREFIX + "USERNAME_VARIABLE": cast(str, settings["owner_username_variable"]),
            OWNER_PREFIX + "PASSWORD_VARIABLE": cast(str, settings["owner_password_variable"]),
        }
        credentials = owner_login_provider(credential_environment)
        if credentials is None:
            raise ValueError
        token = _metadata_token(settings)
        config = SecretMetadataHttpTransportConfig(
            cast(str, settings["base_url"]), token, 15, cast(str | None, settings["ca_file"]),
        )
        owner = OwnerSessionMetadataTransport(
            config, owner_name=cast(str, settings["owner_name"]), credentials=credentials,
            folder_path=binding.folder_path, secret_name=binding.secret_name,
            target_name=cast(str, settings["linux_target_name"]) if settings["contract"] in {LINUX_RUNTIME_CONTRACT, LINUX_REMOTE_RUNTIME_CONTRACT} else binding.secret_name,
            witness=FortiPamSecretMetadataHttpTransport(config, bound_secret_name=binding.secret_name),
        )
        transport = FortiPamSecretApprovalBuild29HttpTransport(
            owner, expected_secret_id=binding.secret_id, expected_secret_name=binding.secret_name,
            expected_folder_id=cast(int, settings["folder_id"]), folder_path=binding.folder_path,
            expected_serial=cast(str, settings["serial"]),
            linux_target_name=cast(str, settings["linux_target_name"]) if settings["contract"] in {LINUX_RUNTIME_CONTRACT, LINUX_REMOTE_RUNTIME_CONTRACT} else None,
        )
        return SecretApprovalBuild29MainContext(
            SecretApprovalBuild29ProjectionReader(transport, approval_profile_name=binding.approval_profile_name),
            SecretApprovalBuild29ProfileReader(owner, expected_serial=cast(str, settings["serial"]), profile_name=binding.approval_profile_name),
            resolver, owner, credentials, settings, binding, MappingProxyType(dict(payload)), execution_enabled,
        )
    except Exception:
        raise SecretApprovalBuild29MainFactoryError(_UNAVAILABLE) from None
    finally:
        _zeroize_mutable(raw)


def _absolute(value: object) -> Path:
    if type(value) is not str or not value:
        raise ValueError
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError
    return path


def _path(settings: Mapping[str, object], name: str) -> Path:
    return _absolute(settings[name])


def _qualify_settings(value: object, runtime_path: Path, binding_path: Path) -> Mapping[str, object]:
    if type(value) is not dict:
        raise ValueError
    remote = value.get("contract") == LINUX_REMOTE_RUNTIME_CONTRACT
    linux = remote or value.get("contract") == LINUX_RUNTIME_CONTRACT
    expected_keys = LINUX_REMOTE_RUNTIME_KEYS if remote else (LINUX_RUNTIME_KEYS if linux else RUNTIME_KEYS)
    if set(value) != expected_keys:
        raise ValueError
    settings = cast(dict[str, object], value)
    if (settings["contract"] != (LINUX_REMOTE_RUNTIME_CONTRACT if remote else (LINUX_RUNTIME_CONTRACT if linux else RUNTIME_CONTRACT))
            or settings["version"] != (LINUX_RUNTIME_VERSION if linux else RUNTIME_VERSION)
            or any(type(item) is not str or not item for name, item in settings.items()
                   if name not in {"folder_id", "ssh_port", "ca_file"})
            or type(settings["folder_id"]) is not int or not 0 < cast(int, settings["folder_id"]) <= 2_147_483_647
            or type(settings["ssh_port"]) is not int or not 1 <= cast(int, settings["ssh_port"]) <= 65535):
        raise ValueError
    for name in ("source_plan_ref", "approval_receipt_ref", "authorization_ref", "environment_ref", "scope_ref", "qualification_authority_ref", "approver_authority_ref"):
        require_ref(cast(str, settings[name]), name)
    for name in ("requester_digest", "evidence_digest"):
        require_digest(cast(str, settings[name]), name)
    path_keys = ((_PATH_KEYS - {"username_file", "secret_env_file"})
                 | {"linux_username_env_file", "owner_api_env_file"}) if linux else _PATH_KEYS
    if remote:
        path_keys = (path_keys - {"linux_username_env_file"}) | {"linux_username_reference_file"}
    paths = [_path(settings, name) for name in sorted(path_keys)] + [runtime_path, binding_path]
    if settings["ca_file"] is not None:
        paths.append(_absolute(settings["ca_file"]))
    if len(set(paths)) != len(paths):
        raise ValueError
    variables = [_validated_variable_name(settings[name]) for name in
                 ("api_token_variable", "owner_username_variable", "owner_password_variable")]
    if len(set(variables)) != 3:
        raise ValueError
    if linux:
        require_digest(cast(str, settings["expected_folder_acl_digest"]), "Linux Folder ACL")
        if not remote:
            _validated_variable_name(settings["linux_username_variable"])
        # The protected operator binds the centrally verified same-device SSH
        # ingress and existing pin; no MCP parameter may supply an endpoint.
        ssh_host = cast(str, settings["ssh_host"])
        if (len(ssh_host) > 253 or not ssh_host.isascii()
                or any(not (char.isalnum() or char in ".-:") for char in ssh_host)):
            raise ValueError
        username_source = _username_source(settings)
        SecretApprovalBuild29LinuxFieldsBinding(
            cast(str, settings["linux_target_name"]), cast(str, settings["linux_target_ipv4_address"]),
            username_source.read_span,
        )
    return MappingProxyType(dict(settings))


def _qualified_binding(payload: Mapping[str, object], settings: Mapping[str, object]) -> ApprovalAndObserveBinding:
    if (set(payload) != _BINDING_KEYS or payload["contract"] != SOURCE_CONTRACT or payload["version"] != SOURCE_VERSION
            or any(type(item) is not str for name, item in payload.items() if name != "secret_id")
            or type(payload["secret_id"]) is not int
            or any(payload[name] != settings[name] for name in ("requester_digest", "environment_ref", "scope_ref"))):
        raise ValueError
    require_digest(cast(str, payload["requester_digest"]), "requester_digest")
    require_ref(cast(str, payload["environment_ref"]), "environment_ref")
    require_ref(cast(str, payload["scope_ref"]), "scope_ref")
    return ApprovalAndObserveBinding(
        cast(str, payload["approval_profile_object_ref"]), cast(str, payload["approval_profile_ref"]),
        cast(str, payload["approval_profile_name"]), cast(str, payload["secret_approval_object_ref"]),
        cast(str, payload["folder_path"]), cast(str, payload["secret_name"]), cast(int, payload["secret_id"]),
    )


def _username_source(settings: Mapping[str, object]) -> (
    OwnerOnlySecretApprovalBuild29UsernameSource | OwnerOnlySecretApprovalBuild29EnvUsernameSource
    | OwnerOnlySecretApprovalBuild29RemoteUsernameSource
):
    if settings["contract"] == LINUX_REMOTE_RUNTIME_CONTRACT:
        return OwnerOnlySecretApprovalBuild29RemoteUsernameSource(_path(settings, "linux_username_reference_file"))
    if settings["contract"] == LINUX_RUNTIME_CONTRACT:
        return OwnerOnlySecretApprovalBuild29EnvUsernameSource(
            _path(settings, "linux_username_env_file"),
            username_variable=cast(str, settings["linux_username_variable"]),
        )
    return OwnerOnlySecretApprovalBuild29UsernameSource(_path(settings, "username_file"))


def _owner_api_env_path(settings: Mapping[str, object]) -> Path:
    return _path(settings, "owner_api_env_file" if settings["contract"] in {LINUX_RUNTIME_CONTRACT, LINUX_REMOTE_RUNTIME_CONTRACT} else "secret_env_file")


def _metadata_token(settings: Mapping[str, object]) -> str:
    content = bytearray()
    pair: tuple[bytearray, bytearray] | None = None
    try:
        content = _read_owner_only_secret_env_file(_owner_api_env_path(settings))
        pair = _parse_prebound_secret_env(
            content, _validated_variable_name(settings["api_token_variable"]),
            _validated_variable_name(settings["owner_username_variable"]), extract_values=True,
        )
        if pair is None or pair[1].decode("utf-8") != settings["owner_name"]:
            raise ValueError
        return pair[0].decode("utf-8")
    finally:
        _zeroize_mutable(content)
        if pair is not None:
            _zeroize_mutable(pair[0])
            _zeroize_mutable(pair[1])
