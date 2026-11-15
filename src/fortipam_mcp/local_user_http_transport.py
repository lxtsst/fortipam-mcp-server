"""Fixed HTTPS transport for the FortiPAM Local User Disable action.

This replaces the appliance CLI commit path, which the lab device rejects for
the bounded writer identity even though the corresponding REST update is
accepted and readback-verifiable. The transport has no generic request relay:
it can read or set ``status=disable`` for exactly one validated Local User.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import ssl
import stat
from typing import Any, Literal
from urllib.parse import quote, urlsplit

from .local_user_ssh_transport import LocalUserInspection, LocalUserReadback


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_LOCAL_USER_"
_COLLECTION_PATH = "/api/v2/cmdb/system/admin"
_MAX_RESPONSE_BYTES = 1_048_576
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DENIED_MESSAGE = "FortiPAM V4 Local User transport is unavailable."


class LocalUserHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated Local User HTTP configuration is unsafe."""


class LocalUserHttpTransportError(RuntimeError):
    """Raised for a bounded Local User HTTP transport failure."""


@dataclass(frozen=True, slots=True)
class LocalUserHttpTransportConfig:
    """Dedicated HTTPS and bearer-token settings held only in process memory."""

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
            raise LocalUserHttpTransportConfigurationError(
                "A dedicated HTTPS API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise LocalUserHttpTransportConfigurationError(
                "A dedicated bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise LocalUserHttpTransportConfigurationError("The timeout is invalid.")
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise LocalUserHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


def load_local_user_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> LocalUserHttpTransportConfig:
    """Load the independent Local User API identity without fallback."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise LocalUserHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token_file = _value(env, "API_TOKEN_FILE")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token_file is None:
        raise LocalUserHttpTransportConfigurationError(
            "Dedicated Local User API target and token file are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise LocalUserHttpTransportConfigurationError(
            "The Local User API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return LocalUserHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=_read_owner_only_token(Path(token_file)),
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamLocalUserHttpTransport:
    """Issue only compiled Local User GET and status-disable HTTPS requests."""

    def __init__(
        self,
        config: LocalUserHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self, username: str) -> LocalUserInspection:
        """Read one exact Local User state without returning its metadata."""

        name = _user_name(username)
        payload = self._request("GET", name, None)
        return _inspection(payload)

    def disable_and_readback(self, username: str) -> LocalUserReadback:
        """Set one exact Local User status to disable and read it back."""

        name = _user_name(username)
        self._request("PUT", name, {"status": "disable"})
        inspection = self.inspect(name)
        return LocalUserReadback(
            user_exists=inspection.exists,
            status_disabled=inspection.status == "disable",
        )

    def _request(
        self,
        method: Literal["GET", "PUT"],
        username: str,
        body: dict[str, str] | None,
    ) -> object:
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
                    f"{self._config.base_url}{_COLLECTION_PATH}/{quote(username, safe='')}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                    json=body,
                )
        except Exception as exc:
            raise LocalUserHttpTransportError(_DENIED_MESSAGE) from exc
        if not 200 <= response.status_code < 300:
            raise LocalUserHttpTransportError(_DENIED_MESSAGE)
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower():
            raise LocalUserHttpTransportError(_DENIED_MESSAGE)
        content = response.content
        if len(content) > _MAX_RESPONSE_BYTES:
            raise LocalUserHttpTransportError(_DENIED_MESSAGE)
        try:
            return json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LocalUserHttpTransportError(_DENIED_MESSAGE) from exc


def _inspection(payload: object) -> LocalUserInspection:
    if not isinstance(payload, dict):
        raise LocalUserHttpTransportError(_DENIED_MESSAGE)
    result = payload.get("results", payload)
    if isinstance(result, list):
        result = result[0] if len(result) == 1 else None
    if not isinstance(result, dict):
        raise LocalUserHttpTransportError(_DENIED_MESSAGE)
    status = result.get("status")
    if status not in {"enable", "disable"}:
        raise LocalUserHttpTransportError(_DENIED_MESSAGE)
    assert status in {"enable", "disable"}
    return LocalUserInspection(True, status)


def _ssl_context(config: LocalUserHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise LocalUserHttpTransportError(_DENIED_MESSAGE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _read_owner_only_token(path: Path) -> str:
    try:
        metadata = path.stat()
        if not path.is_file() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise LocalUserHttpTransportConfigurationError(
                "The Local User token file must be owner-only."
            )
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise LocalUserHttpTransportConfigurationError(
            "The Local User token file is unavailable."
        ) from exc
    if not token:
        raise LocalUserHttpTransportConfigurationError(
            "The Local User token file is empty."
        )
    return token


def _user_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise LocalUserHttpTransportError(_DENIED_MESSAGE)
    return value


__all__ = [
    "ENV_PREFIX",
    "FortiPamLocalUserHttpTransport",
    "LocalUserHttpTransportConfig",
    "LocalUserHttpTransportConfigurationError",
    "LocalUserHttpTransportError",
    "load_local_user_http_transport_config",
]
