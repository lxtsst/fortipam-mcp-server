"""API-first transport for one bounded FortiPAM laboratory Role assignment.

The action assigns one existing ``mcp-v4-role-*`` custom Role to one disabled
``mcp-v4-user-*`` Local User.  It uses only fixed user/Role detail GET routes
and one minimal user detail PUT; it is not a generic REST client or user
administration adapter.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
from typing import Any, Literal
from urllib.parse import quote, urlsplit


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ROLE_ASSIGN_"
LAB_USER_NAME_PREFIX = "mcp-v4-user-"
ROLE_NAME_PREFIX = "mcp-v4-role-"
_USER_COLLECTION_PATH = "/api/v2/cmdb/system/admin"
_ROLE_COLLECTION_PATH = "/api/v2/cmdb/system/accprofile"
_MAX_RESPONSE_BYTES = 1_048_576
_USER_NAME = re.compile(r"mcp-v4-user-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_ROLE_NAME = re.compile(r"mcp-v4-role-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_DENIED_MESSAGE = "FortiPAM V4 Role assignment transport is unavailable."


class RoleAssignHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated Role-assignment API configuration is unsafe."""


class RoleAssignHttpTransportError(RuntimeError):
    """Raised for a bounded Role-assignment API transport failure."""


@dataclass(frozen=True, slots=True)
class RoleAssignHttpTransportConfig:
    """Dedicated HTTPS and bearer-token settings kept only in process memory."""

    base_url: str
    bearer_token: str
    timeout_seconds: float
    ca_file: str | None

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise RoleAssignHttpTransportConfigurationError(
                "A dedicated HTTPS Role assignment API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise RoleAssignHttpTransportConfigurationError(
                "A dedicated Role assignment bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise RoleAssignHttpTransportConfigurationError(
                "The Role assignment API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise RoleAssignHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class RoleAssignInspection:
    """Value-minimized current state for one user and one requested Role."""

    user_exists: bool
    role_exists: bool
    user_disabled: bool
    assignment_matches: bool
    state_digest: str


@dataclass(frozen=True, slots=True)
class RoleAssignReadback:
    """Categorical readback for the exact laboratory assignment contract."""

    user_exists: bool
    role_exists: bool
    user_disabled: bool
    assignment_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.user_exists,
                self.role_exists,
                self.user_disabled,
                self.assignment_matches,
            )
        )


def load_role_assign_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> RoleAssignHttpTransportConfig:
    """Load only independently scoped Role-assignment API credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise RoleAssignHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token_file = _value(env, "API_TOKEN_FILE")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token_file is None:
        raise RoleAssignHttpTransportConfigurationError(
            "Dedicated Role assignment API target and token file are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise RoleAssignHttpTransportConfigurationError(
            "The Role assignment API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return RoleAssignHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=_read_owner_only_token(Path(token_file)),
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamRoleAssignHttpTransport:
    """Issue only compiled Role/user inspection and assignment API requests."""

    def __init__(
        self,
        config: RoleAssignHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect_assignment(
        self,
        username: str,
        role_name: str,
    ) -> RoleAssignInspection:
        """Read one fixed user/Role pair without returning configuration values."""

        user = _user_name(username)
        role = _role_name(role_name)
        user_status, user_payload = self._request("GET", self._user_path(user), None)
        if user_status == 404:
            return RoleAssignInspection(
                user_exists=False,
                role_exists=False,
                user_disabled=False,
                assignment_matches=False,
                state_digest=_state_digest(user, role, None, None, False),
            )
        user_record = _record(user_payload)
        if user_status != 200 or user_record is None:
            raise RoleAssignHttpTransportError(_DENIED_MESSAGE)
        status = user_record.get("status")
        current_role = user_record.get("accprofile")
        if status not in {"enable", "disable"} or not isinstance(current_role, str):
            raise RoleAssignHttpTransportError(_DENIED_MESSAGE)

        role_status, role_payload = self._request("GET", self._role_path(role), None)
        role_exists = role_status == 200 and _record(role_payload) is not None
        if role_status not in {200, 404} or (role_status == 200 and not role_exists):
            raise RoleAssignHttpTransportError(_DENIED_MESSAGE)
        return RoleAssignInspection(
            user_exists=True,
            role_exists=role_exists,
            user_disabled=status == "disable",
            assignment_matches=current_role == role,
            state_digest=_state_digest(user, role, status, current_role, role_exists),
        )

    def assign_and_readback(self, username: str, role_name: str) -> RoleAssignReadback:
        """Perform one minimal access-profile PUT and fixed user/Role readback."""

        user = _user_name(username)
        role = _role_name(role_name)
        status, payload = self._request(
            "PUT",
            self._user_path(user),
            {"accprofile": role},
        )
        if status != 200 or not _successful_write_response(payload):
            raise RoleAssignHttpTransportError(_DENIED_MESSAGE)
        inspection = self.inspect_assignment(user, role)
        return RoleAssignReadback(
            user_exists=inspection.user_exists,
            role_exists=inspection.role_exists,
            user_disabled=inspection.user_disabled,
            assignment_matches=inspection.assignment_matches,
        )

    def _request(
        self,
        method: Literal["GET", "PUT"],
        path: str,
        body: Mapping[str, str] | None,
    ) -> tuple[int, object]:
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
                    f"{self._config.base_url}{path}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                    json=body,
                )
        except Exception as exc:
            raise RoleAssignHttpTransportError(_DENIED_MESSAGE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > _MAX_RESPONSE_BYTES:
            raise RoleAssignHttpTransportError(_DENIED_MESSAGE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RoleAssignHttpTransportError(_DENIED_MESSAGE) from exc

    @staticmethod
    def _user_path(username: str) -> str:
        return f"{_USER_COLLECTION_PATH}/{quote(username, safe='')}"

    @staticmethod
    def _role_path(role_name: str) -> str:
        return f"{_ROLE_COLLECTION_PATH}/{quote(role_name, safe='')}"


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _successful_write_response(payload: object) -> bool:
    if not isinstance(payload, Mapping):
        return False
    return payload.get("http_status") in {None, 200}


def _state_digest(
    username: str,
    role_name: str,
    status: str | None,
    current_role: str | None,
    role_exists: bool,
) -> str:
    payload = json.dumps(
        {
            "username": username,
            "role_name": role_name,
            "status": status,
            "current_role": current_role,
            "role_exists": role_exists,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ssl_context(config: RoleAssignHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise RoleAssignHttpTransportError(_DENIED_MESSAGE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _read_owner_only_token(path: Path) -> str:
    try:
        metadata = path.lstat()
        if (
            not path.is_file()
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise RoleAssignHttpTransportConfigurationError(
                "The Role assignment token file must be an owner-only regular file."
            )
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RoleAssignHttpTransportConfigurationError(
            "The Role assignment token file is unavailable."
        ) from exc
    if not token:
        raise RoleAssignHttpTransportConfigurationError(
            "The Role assignment token file is empty."
        )
    return token


def _user_name(value: str) -> str:
    if not isinstance(value, str) or _USER_NAME.fullmatch(value) is None:
        raise RoleAssignHttpTransportError(_DENIED_MESSAGE)
    return value


def _role_name(value: str) -> str:
    if not isinstance(value, str) or _ROLE_NAME.fullmatch(value) is None:
        raise RoleAssignHttpTransportError(_DENIED_MESSAGE)
    return value


__all__ = [
    "ENV_PREFIX",
    "FortiPamRoleAssignHttpTransport",
    "LAB_USER_NAME_PREFIX",
    "ROLE_NAME_PREFIX",
    "RoleAssignHttpTransportConfig",
    "RoleAssignHttpTransportConfigurationError",
    "RoleAssignHttpTransportError",
    "RoleAssignInspection",
    "RoleAssignReadback",
    "load_role_assign_http_transport_config",
]
