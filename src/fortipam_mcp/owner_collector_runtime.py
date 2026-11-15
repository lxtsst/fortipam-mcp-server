"""Explicit private Owner login binding and bounded collector session lifetime."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from v4_planning import M4ExecutionPlan, M4ExecutionResult
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_create_191_private_adapter import SecretCreate700WinrmBinding
from .secret_create_central_lab_provider import (
    _validated_variable_name, _read_owner_only_secret_env_file,
    _parse_prebound_secret_env, _zeroize,
)
from .secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig
from .secret_onboarding_action_sequence import SecretCreateBoundRuntime

PREFIX = "FORTIPAM_MCP_V4_SECRET_CREATE_LAB_AUTO_OWNER_"
_UNAVAILABLE = "The private collector Owner login is unavailable."


def owner_login_provider(environment: Mapping[str, str]) -> Callable[[], tuple[str, str]] | None:
    """Bind protected variable references without opening or parsing credentials."""
    enabled = environment.get(PREFIX + "SESSION_ENABLED", "false")
    if enabled == "false":
        return None
    if enabled != "true":
        raise ValueError(_UNAVAILABLE)
    try:
        path = Path(environment[PREFIX + "LOGIN_ENV_FILE"])
        username = _validated_variable_name(environment[PREFIX + "USERNAME_VARIABLE"])
        password = _validated_variable_name(environment[PREFIX + "PASSWORD_VARIABLE"])
        if not path.is_absolute() or username == password:
            raise ValueError
    except Exception:
        raise ValueError(_UNAVAILABLE) from None

    def load() -> tuple[str, str]:
        content = bytearray()
        pair: tuple[bytearray, bytearray] | None = None
        try:
            content = _read_owner_only_secret_env_file(path)
            pair = _parse_prebound_secret_env(content, username, password, extract_values=True)
            if pair is None:
                raise ValueError
            return pair[0].decode("utf-8"), pair[1].decode("utf-8")
        except Exception:
            raise ValueError(_UNAVAILABLE) from None
        finally:
            _zeroize(content)
            if pair is not None:
                _zeroize(pair[0])
                _zeroize(pair[1])
    return load


def owner_collector_transport(config: SecretMetadataHttpTransportConfig,
    binding: SecretCreate700WinrmBinding, credentials: Callable[[], tuple[str, str]],
    *, allow_secret_create: bool = False) -> OwnerSessionMetadataTransport:
    if not isinstance(binding, SecretCreate700WinrmBinding):
        raise ValueError(_UNAVAILABLE)
    witness = FortiPamSecretMetadataHttpTransport(config, bound_secret_name=binding.witness_secret_name)
    return OwnerSessionMetadataTransport(config, owner_name=binding.folder_owner_name,
        credentials=credentials, folder_path=binding.folder_path, secret_name=binding.secret_name,
        target_name=binding.target_name, witness=witness, allow_secret_create=allow_secret_create)


class OwnerAuthenticatedCollectorRuntime:
    """Authenticate only around the already-authorized protected M4 execution."""
    def __init__(self, runtime: SecretCreateBoundRuntime, session: OwnerSessionMetadataTransport) -> None:
        self._runtime, self._session = runtime, session

    def inspect_execution_plan(self, authorization_ref: str) -> M4ExecutionPlan:
        return self._runtime.inspect_execution_plan(authorization_ref)

    def inspect_onboarding_binding_digest(self, authorization_ref: str) -> str:
        return self._runtime.inspect_onboarding_binding_digest(authorization_ref)

    def execute_bound(self, authorization_ref: str, *,
                      expected_onboarding_binding_digest: str | None = None) -> M4ExecutionResult:
        with self._session.authenticated():
            return self._runtime.execute_bound(authorization_ref,
                expected_onboarding_binding_digest=expected_onboarding_binding_digest)
