"""Default-off categorical MCP candidate for one protected Secret request."""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
import stat
from typing import Any

from v4_planning.models import require_ref

from .folder_mcp_action import folder_action_principal_from_access_token
from .secret_request_create_http_transport import (
    FortiPamSecretRequestCreateHttpTransport,
    OwnerOnlySecretRequestCreateBindingResolver,
    OwnerOnlySecretRequestCreateDispatchClaim,
    SecretRequestCreateTransportOutcome,
)
from .secret_metadata_http_transport import (
    load_secret_metadata_http_transport_config,
    _zeroize_mutable,
)
from .secret_request_create_invocation_witness import OwnerOnlySecretRequestCreateInvocationWitnessStore
from .v4_plan_runtime import V4PlanningPrincipal


V4_SECRET_REQUEST_CREATE_PREFIX = "FORTIPAM_MCP_V4_SECRET_REQUEST_CREATE_"
V4_SECRET_REQUEST_CREATE_FEATURE_ENV = (
    f"{V4_SECRET_REQUEST_CREATE_PREFIX}TOOLS_ENABLED"
)
V4_SECRET_REQUEST_CREATE_EXECUTION_ENV = (
    f"{V4_SECRET_REQUEST_CREATE_PREFIX}EXECUTION_ENABLED"
)
V4_SECRET_REQUEST_CREATE_TOOL = "create_v4_bound_secret_request"
V4_SECRET_REQUEST_CREATE_UNAVAILABLE = (
    "FortiPAM V4 Secret request creation is unavailable."
)
_HEX_KEY = frozenset("0123456789abcdef")


class V4SecretRequestCreateConfigurationError(ValueError):
    """Raised when the explicit Request Create host binding is incomplete."""


def load_v4_secret_request_create_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the Tool-registration opt-in, defaulting to disabled."""

    return _exact_boolean(V4_SECRET_REQUEST_CREATE_FEATURE_ENV, environment)


def load_v4_secret_request_create_execution_gate(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent one-shot dispatch gate, defaulting to denied."""

    return _exact_boolean(V4_SECRET_REQUEST_CREATE_EXECUTION_ENV, environment)


def secret_request_create_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> V4PlanningPrincipal:
    """Require the existing planning identity plus non-default operation scope."""

    try:
        principal = folder_action_principal_from_access_token(
            access_token,
            planning_settings,
        )
        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("validated planning principal required")
        return principal
    except Exception as exc:
        raise RuntimeError(V4_SECRET_REQUEST_CREATE_UNAVAILABLE) from exc


class ProtectedSecretRequestCreateMcpAction:
    """Accept only an opaque intent ref and return no request-side values."""

    __slots__ = ("_execution_enabled", "_transport")

    def __init__(
        self,
        transport: FortiPamSecretRequestCreateHttpTransport,
        *,
        execution_enabled: bool = False,
    ) -> None:
        if (
            not isinstance(transport, FortiPamSecretRequestCreateHttpTransport)
            or type(execution_enabled) is not bool
        ):
            raise RuntimeError(V4_SECRET_REQUEST_CREATE_UNAVAILABLE)
        self._transport = transport
        self._execution_enabled = execution_enabled

    def execute(
        self,
        intent_ref: str,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]:
        """Use this authenticated invocation as the sole operational intent."""

        if not self._execution_enabled or not isinstance(
            principal, V4PlanningPrincipal
        ):
            raise RuntimeError(V4_SECRET_REQUEST_CREATE_UNAVAILABLE)
        result = self._transport.create(intent_ref, principal=principal)
        bound = result.outcome is SecretRequestCreateTransportOutcome.BOUND
        return {
            "contract": "fortipam-v4-secret-request-create-result-v1",
            "outcome": result.outcome.value,
            "request_bound": bound,
            "reconciliation_required": not bound,
            "raw_values_returned": False,
            "request_identifiers_returned": False,
            "request_intent_returned": False,
        }


def build_v4_secret_request_create_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedSecretRequestCreateMcpAction:
    """Build the exact owner-bound Request Create action from local state."""

    env = os.environ if environment is None else environment
    try:
        binding_path = _absolute_path(env, "INTENT_BINDING_FILE")
        claim_path = _absolute_path(env, "DISPATCH_CLAIM_FILE")
        key_path = _absolute_path(env, "HMAC_KEY_FILE")
        environment_ref = require_ref(
            env[f"{V4_SECRET_REQUEST_CREATE_PREFIX}AUTHORIZED_ENVIRONMENT_REF"],
            "authorized_environment_ref",
        )
        scope_ref = require_ref(
            env[f"{V4_SECRET_REQUEST_CREATE_PREFIX}AUTHORIZED_SCOPE_REF"],
            "authorized_scope_ref",
        )
        key = _load_owner_only_hex_key(key_path)
        config = load_secret_metadata_http_transport_config(env)
        authentication_mode = env.get(
            f"{V4_SECRET_REQUEST_CREATE_PREFIX}AUTHENTICATION_MODE", "api-bearer")
        resolver = OwnerOnlySecretRequestCreateBindingResolver(binding_path)
        claim = OwnerOnlySecretRequestCreateDispatchClaim(claim_path, key)
        witness_sink = None
        witness_fields = ("INVOCATION_WITNESS_FILE", "INVOCATION_WITNESS_HMAC_KEY_FILE")
        if any(f"{V4_SECRET_REQUEST_CREATE_PREFIX}{field}" in env for field in witness_fields):
            witness_path = _absolute_path(env, witness_fields[0])
            witness_key_path = _absolute_path(env, witness_fields[1])
            witness_key = _load_owner_only_hex_key(witness_key_path)
            if witness_key == key or witness_path in {binding_path, claim_path, key_path, witness_key_path}:
                raise ValueError
            witness_sink = OwnerOnlySecretRequestCreateInvocationWitnessStore(witness_path, witness_key)
            witness_sink.assert_available()
        if authentication_mode == "api-bearer":
            transport = FortiPamSecretRequestCreateHttpTransport(
                config, binding_resolver=resolver, dispatch_claim=claim,
                authorized_environment_ref=environment_ref,
                authorized_scope_ref=scope_ref, invocation_witness_sink=witness_sink)
        elif authentication_mode == "bp005-requester-session":
            from .secret_request_requester_session import build_bp005_requester_session
            transport = build_bp005_requester_session(config, env).compose_create_transport(
                binding_resolver=resolver, dispatch_claim=claim,
                authorized_environment_ref=environment_ref,
                authorized_scope_ref=scope_ref, invocation_witness_sink=witness_sink)
        else:
            raise ValueError
    except Exception as exc:
        raise V4SecretRequestCreateConfigurationError(
            V4_SECRET_REQUEST_CREATE_UNAVAILABLE
        ) from exc
    return ProtectedSecretRequestCreateMcpAction(
        transport,
        execution_enabled=load_v4_secret_request_create_execution_gate(env),
    )


def _exact_boolean(
    name: str,
    environment: Mapping[str, str] | None,
) -> bool:
    env = os.environ if environment is None else environment
    value = env.get(name)
    if value is None or value == "false":
        return False
    if value == "true":
        return True
    raise V4SecretRequestCreateConfigurationError(
        f"{name} must be exactly true or false."
    )


def _absolute_path(environment: Mapping[str, str], suffix: str) -> Path:
    raw = environment.get(f"{V4_SECRET_REQUEST_CREATE_PREFIX}{suffix}")
    if not isinstance(raw, str) or not raw.strip():
        raise V4SecretRequestCreateConfigurationError(
            V4_SECRET_REQUEST_CREATE_UNAVAILABLE
        )
    path = Path(raw.strip()).expanduser()
    if not path.is_absolute():
        raise V4SecretRequestCreateConfigurationError(
            V4_SECRET_REQUEST_CREATE_UNAVAILABLE
        )
    return path


def _load_owner_only_hex_key(path: Path) -> bytes:
    content = bytearray()
    try:
        metadata = path.lstat()
        parent = path.parent.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
            or metadata.st_size > 129
        ):
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            content = bytearray(os.read(descriptor, 130))
        finally:
            os.close(descriptor)
        encoded = bytes(content).strip()
        if (
            len(encoded) != 64
            or any(chr(byte) not in _HEX_KEY for byte in encoded)
        ):
            raise ValueError
        return bytes.fromhex(encoded.decode("ascii"))
    except (OSError, UnicodeError, ValueError):
        raise V4SecretRequestCreateConfigurationError(
            V4_SECRET_REQUEST_CREATE_UNAVAILABLE
        ) from None
    finally:
        _zeroize_mutable(content)


__all__ = [
    "ProtectedSecretRequestCreateMcpAction",
    "V4_SECRET_REQUEST_CREATE_EXECUTION_ENV",
    "V4_SECRET_REQUEST_CREATE_FEATURE_ENV",
    "V4_SECRET_REQUEST_CREATE_PREFIX",
    "V4_SECRET_REQUEST_CREATE_TOOL",
    "V4_SECRET_REQUEST_CREATE_UNAVAILABLE",
    "V4SecretRequestCreateConfigurationError",
    "build_v4_secret_request_create_action",
    "load_v4_secret_request_create_execution_gate",
    "load_v4_secret_request_create_feature",
    "secret_request_create_principal_from_access_token",
]
