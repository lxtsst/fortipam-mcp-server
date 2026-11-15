"""MCP boundary for bounded FortiPAM active-launch observation/control."""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_ACTIVE_LAUNCH_ACTION_PREFIX = "FORTIPAM_MCP_V4_ACTIVE_LAUNCH_ACTION_"
V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV = f"{V4_ACTIVE_LAUNCH_ACTION_PREFIX}ENABLED"
V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENABLED"
)
V4_ACTIVE_LAUNCH_OBSERVE_TOOL = "observe_v4_active_launches"
V4_ACTIVE_LAUNCH_DISCONNECT_PREVIEW_TOOL = "preview_v4_active_launch_disconnect"
V4_ACTIVE_LAUNCH_DISCONNECT_CONFIRM_TOOL = "confirm_v4_active_launch_disconnect"
V4_ACTIVE_LAUNCH_DISCONNECT_ACTION_TOOL = (
    "execute_confirmed_v4_active_launch_disconnect"
)
V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE = "FortiPAM V4 active-launch control is unavailable."


class V4ActiveLaunchActionConfigurationError(ValueError):
    """Raised when the active-launch action host is incomplete or unsafe."""


class V4ActiveLaunchActionRuntimeError(RuntimeError):
    """Stable, non-disclosing active-launch MCP failure."""


def load_v4_active_launch_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent active-launch opt-in, disabled by default."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ActiveLaunchActionConfigurationError(
        f"{V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_active_launch_disconnect_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent disconnect dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ActiveLaunchActionConfigurationError(
        f"{V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENV} must be exactly true or false."
    )


def active_launch_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the explicit V4 plan/operate authorization scope."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4ActiveLaunchActionRuntimeError(
            V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE
        ) from exc


class ProtectedActiveLaunchMcpAction:
    """Expose opaque observation plus confirmation-gated one-launch disconnect."""

    def __init__(self, workflow: Any, *, disconnect_execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._disconnect_execution_enabled = disconnect_execution_enabled

    def observe(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            self._validate_bound_principal(principal)
            return cast(
                dict[str, object],
                self._workflow.observe(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ActiveLaunchActionRuntimeError(
                V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE
            ) from exc

    def preview_disconnect(
        self,
        launch_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            self._validate_bound_principal(principal)
            return cast(
                dict[str, object],
                self._workflow.preview_disconnect(
                    launch_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ActiveLaunchActionRuntimeError(
                V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE
            ) from exc

    def confirm_disconnect(
        self,
        preview_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            self._validate_bound_principal(principal)
            return cast(
                dict[str, object],
                self._workflow.confirm_disconnect(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ActiveLaunchActionRuntimeError(
                V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE
            ) from exc

    def execute_disconnect(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._disconnect_execution_enabled:
            raise V4ActiveLaunchActionRuntimeError(
                V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            self._validate_bound_principal(principal)
            return cast(
                dict[str, object],
                self._workflow.execute_disconnect(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ActiveLaunchActionRuntimeError(
                V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE
            ) from exc

    def _validate_bound_principal(self, principal: Any) -> None:
        from .active_launch_live_workflow import FixedActiveLaunchLiveWorkflow
        if type(self._workflow) is FixedActiveLaunchLiveWorkflow:
            self._workflow.validate_principal(_requester_digest(principal), principal.transport_namespace_digest)


def build_v4_active_launch_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedActiveLaunchMcpAction:
    """Bind fixed durable execution, or retain the existing read-only profile."""

    env = os.environ if environment is None else environment
    try:
        candidate_path = env.get(V4_ACTIVE_LAUNCH_ACTION_PREFIX + "CANDIDATE_PROFILE_FILE")
        candidate_sha = env.get(V4_ACTIVE_LAUNCH_ACTION_PREFIX + "CANDIDATE_PROFILE_SHA256")
        if candidate_path is not None or candidate_sha is not None:
            return _build_fixed_active_launch_action(env, candidate_path, candidate_sha)
        if load_v4_active_launch_disconnect_execution_feature(env):
            raise ValueError("A fixed original candidate and durable store are required.")
        from .active_launch_live_workflow import ActiveLaunchLiveWorkflow
        from .antivirus_profile_ssh_transport import (
            load_antivirus_profile_ssh_transport_config,
        )
        from .active_launch_ssh_transport import (
            ActiveLaunchSshTransportConfig,
            FortiPamActiveLaunchSshTransport,
            ENV_PREFIX, load_active_launch_ssh_transport_config,
        )
        current_profile = (load_active_launch_ssh_transport_config(env)
            if env.get(ENV_PREFIX + "ENABLED") == "true"
            else load_antivirus_profile_ssh_transport_config(env))

        workflow = ActiveLaunchLiveWorkflow(
            FortiPamActiveLaunchSshTransport(
                ActiveLaunchSshTransportConfig(
                    host=current_profile.host,
                    port=current_profile.port,
                    username=current_profile.username,
                    password=current_profile.password,
                    known_hosts_file=current_profile.known_hosts_file,
                    timeout_seconds=current_profile.timeout_seconds,
                )
            )
        )
    except Exception as exc:
        raise V4ActiveLaunchActionConfigurationError(
            V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedActiveLaunchMcpAction(
        workflow,
        disconnect_execution_enabled=(
            load_v4_active_launch_disconnect_execution_feature(env)
        ),
    )


def _build_fixed_active_launch_action(env: Mapping[str, str], path: str | None,
                                     digest: str | None) -> ProtectedActiveLaunchMcpAction:
    """Load one pinned private candidate without opening its Owner credentials."""
    import hashlib
    import hmac
    import json
    from dataclasses import fields
    from .active_launch_live_workflow import (FIXED_DISCONNECT_CONTRACT,
        FixedActiveLaunchBinding, FixedActiveLaunchLiveWorkflow)
    from .active_launch_ssh_transport import (ENV_PREFIX, ActiveLaunchSshTransportConfig,
        FortiPamActiveLaunchSshTransport, load_active_launch_ssh_transport_config)
    from .m4_execution_store import PersistentM4ExecutionStateStore
    from .secret_bulk_import_file import _read_owned, _wipe
    from .secret_bulk_import_intake_authority import _members
    from .secret_bulk_import_token_channel import _PinnedKey
    from v4_planning.models import require_digest

    if not isinstance(path, str) or not Path(path).is_absolute() or not isinstance(digest, str):
        raise ValueError
    require_digest(digest, "fixed launch profile")
    raw = bytearray()
    authority = execution = bytearray()
    try:
        raw, _ = _read_owned(Path(path))
        if not 0 < len(raw) <= 16384 or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_members)
        names = {field.name for field in fields(FixedActiveLaunchBinding)}
        if (type(value) is not dict or set(value) != names | {"contract", "execution_database",
                "execution_key_path", "execution_key_sha256", "authority_key_path", "authority_key_sha256"}
                or value["contract"] != FIXED_DISCONNECT_CONTRACT):
            raise ValueError
        binding = FixedActiveLaunchBinding(**{name: value[name] for name in names})
        database = Path(value["execution_database"])
        if not database.is_absolute():
            raise ValueError
        execution = _PinnedKey(Path(value["execution_key_path"]), value["execution_key_sha256"]).load()
        authority = _PinnedKey(Path(value["authority_key_path"]), value["authority_key_sha256"]).load()
        if hmac.compare_digest(authority, execution):
            raise ValueError
        if env.get(ENV_PREFIX + "ENABLED") != "true":
            raise ValueError
        owner_mode = env.get(ENV_PREFIX + "OWNER_LOGIN_ENABLED", "false")
        if owner_mode == "false":
            config = load_active_launch_ssh_transport_config(env)
            if config.username != binding.owner_name:
                raise ValueError
            transport: Any = FortiPamActiveLaunchSshTransport(config, expected_serial_digest=binding.serial_digest)
        elif owner_mode == "true":
            from .owner_collector_runtime import PREFIX as LOGIN_PREFIX, owner_login_provider
            login = {LOGIN_PREFIX + "SESSION_ENABLED": "true"}
            for suffix in ("LOGIN_ENV_FILE", "USERNAME_VARIABLE", "PASSWORD_VARIABLE"):
                login[LOGIN_PREFIX + suffix] = env[ENV_PREFIX + suffix]
            credentials = owner_login_provider(login)
            if credentials is None or env.get(ENV_PREFIX + "SSH_USERNAME") != binding.owner_name:
                raise ValueError
            config = ActiveLaunchSshTransportConfig(host=env[ENV_PREFIX + "SSH_HOST"],
                port=int(env.get(ENV_PREFIX + "SSH_PORT", "22")), username=binding.owner_name,
                password="private-owner-provider", known_hosts_file=Path(env[ENV_PREFIX + "SSH_KNOWN_HOSTS_FILE"]),
                timeout_seconds=float(env.get(ENV_PREFIX + "SSH_TIMEOUT_SECONDS", "15")))
            transport = _OwnerActiveLaunchTransport(config, credentials, binding.serial_digest)
        else:
            raise ValueError
        # An exclusive binding marker prevents a missing/deleted old ledger
        # from silently being recreated for this original native object.
        marker = database.with_name(database.name + ".binding")
        pin = hmac.new(execution, (FIXED_DISCONNECT_CONTRACT + "\0" + binding.serial_digest + "\0"
            + binding.token_id + "\0" + binding.identity_digest + "\0"
            + binding.owner_name + "\0" + binding.allowed_requester_digest + "\0"
            + binding.allowed_transport_digest).encode(), hashlib.sha256).hexdigest().encode()
        if os.path.lexists(marker):
            previous, _ = _read_owned(marker)
            try:
                if not database.is_file() or not hmac.compare_digest(previous, pin):
                    raise ValueError
            finally:
                _wipe(previous)
        else:
            if any(os.path.lexists(Path(str(database) + suffix)) for suffix in ("", "-wal", "-shm", "-journal")):
                raise ValueError
            # Validate directory ownership/mode before publishing any marker.
            from .secret_bulk_import_intake_authority import _publish_policy
            _publish_policy(marker, bytearray(pin), lambda: None)
        store = PersistentM4ExecutionStateStore(database, Path(value["execution_key_path"]))
        workflow = FixedActiveLaunchLiveWorkflow(transport, binding, store, authority_key=bytes(authority))
        return ProtectedActiveLaunchMcpAction(workflow,
            disconnect_execution_enabled=load_v4_active_launch_disconnect_execution_feature(env))
    finally:
        for buffer in (raw, authority, execution):
            _wipe(buffer)


class _OwnerActiveLaunchTransport:
    """Resolve the existing central Owner only at the fixed CLI decision."""

    def __init__(self, config: Any, credentials: Any, serial_digest: str) -> None:
        self._config, self._credentials, self._serial = config, credentials, serial_digest

    def _transport(self) -> Any:
        from dataclasses import replace
        from .active_launch_ssh_transport import FortiPamActiveLaunchSshTransport
        username, password = self._credentials()
        if username != self._config.username:
            raise ValueError(V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE)
        return FortiPamActiveLaunchSshTransport(replace(self._config, password=password),
            expected_serial_digest=self._serial)

    def list_active_launches(self) -> Any:
        return self._transport().list_active_launches()

    def clear_active_launch_and_readback(self, token_id: str, *,
                                       expected_identity_digest: str | None = None,
                                       guard: Any = None) -> Any:
        return self._transport().clear_active_launch_and_readback(token_id,
            expected_identity_digest=expected_identity_digest, guard=guard)


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ActiveLaunchActionRuntimeError(
            V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedActiveLaunchMcpAction",
    "V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV",
    "V4_ACTIVE_LAUNCH_ACTION_PREFIX",
    "V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE",
    "V4_ACTIVE_LAUNCH_DISCONNECT_ACTION_TOOL",
    "V4_ACTIVE_LAUNCH_DISCONNECT_CONFIRM_TOOL",
    "V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENV",
    "V4_ACTIVE_LAUNCH_DISCONNECT_PREVIEW_TOOL",
    "V4_ACTIVE_LAUNCH_OBSERVE_TOOL",
    "V4ActiveLaunchActionConfigurationError",
    "V4ActiveLaunchActionRuntimeError",
    "active_launch_action_principal_from_access_token",
    "build_v4_active_launch_action",
    "load_v4_active_launch_action_feature",
    "load_v4_active_launch_disconnect_execution_feature",
]
