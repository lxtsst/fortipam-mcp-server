"""Strict API status preflight for the maintenance-mode successor.

The FortiPAM 1.9.1 catalog exposes one exact read-only maintenance route while
its PUT body remains unspecified. This module uses that GET only to classify
the mode before and after the existing fixed SSH enable command.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import ssl
import stat
from typing import Any, Protocol
from urllib.parse import urlsplit

from .maintenance_mode_ssh_transport import (
    MaintenanceModeInspection,
    MaintenanceModeReadback,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_STATUS_API_"
MAINTENANCE_PATH = "/api/v2/cmdb/system/maintenance"
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 maintenance mode status transport is unavailable."


class MaintenanceModeStatusHttpTransportConfigurationError(ValueError):
    """Raised when the exact read-only API route is unsafe."""


class MaintenanceModeStatusHttpTransportError(RuntimeError):
    """Stable non-disclosing error for maintenance-mode status reads."""


@dataclass(frozen=True, slots=True)
class MaintenanceModeStatusHttpTransportConfig:
    """Dedicated HTTPS settings and an in-memory bearer token."""

    base_url: str
    bearer_token: str
    timeout_seconds: float
    ca_file: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", _base_url(self.base_url))
        if (
            not isinstance(self.bearer_token, str)
            or not self.bearer_token
            or self.bearer_token != self.bearer_token.strip()
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.bearer_token
            )
        ):
            raise MaintenanceModeStatusHttpTransportConfigurationError(
                "A dedicated maintenance-mode status bearer token is required."
            )
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(
            self.timeout_seconds, bool
        ):
            raise MaintenanceModeStatusHttpTransportConfigurationError(
                "The maintenance-mode status timeout is invalid."
            )
        if not 1 <= float(self.timeout_seconds) <= 60:
            raise MaintenanceModeStatusHttpTransportConfigurationError(
                "The maintenance-mode status timeout must be between 1 and 60 seconds."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise MaintenanceModeStatusHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


def load_maintenance_mode_status_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> MaintenanceModeStatusHttpTransportConfig:
    """Load an explicitly enabled exact maintenance GET route."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise MaintenanceModeStatusHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    supplied = _value(env, "BASE_URL") or _value(env, "HOST")
    token_file = _value(env, "API_TOKEN_FILE")
    if supplied is None or token_file is None:
        raise MaintenanceModeStatusHttpTransportConfigurationError(
            "Dedicated maintenance-mode status target and token file are required."
        )
    try:
        timeout = float(_value(env, "TIMEOUT_SECONDS") or "15")
    except ValueError as exc:
        raise MaintenanceModeStatusHttpTransportConfigurationError(
            "The maintenance-mode status timeout is invalid."
        ) from exc
    return MaintenanceModeStatusHttpTransportConfig(
        base_url=supplied if "://" in supplied else f"https://{supplied}",
        bearer_token=_read_owner_only_token(Path(token_file)),
        timeout_seconds=timeout,
        ca_file=_value(env, "CA_FILE"),
    )


class FortiPamMaintenanceModeStatusHttpTransport:
    """Issue one exact maintenance GET and reduce it to enable or disable."""

    def __init__(
        self,
        config: MaintenanceModeStatusHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self) -> MaintenanceModeInspection:
        record = _record(self._request())
        mode = record.get("mode") if record is not None else None
        if mode not in {"enable", "disable"}:
            raise MaintenanceModeStatusHttpTransportError(_UNAVAILABLE)
        return MaintenanceModeInspection(status=mode)

    def _request(self) -> object:
        try:
            import httpx

            factory = self._client_factory or httpx.Client
            with factory(
                verify=_ssl_context(self._config),
                timeout=float(self._config.timeout_seconds),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.request(
                    "GET",
                    f"{self._config.base_url}{MAINTENANCE_PATH}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                )
        except Exception as exc:
            raise MaintenanceModeStatusHttpTransportError(_UNAVAILABLE) from exc
        try:
            status = int(response.status_code)
            content = bytes(response.content)
            content_type = str(response.headers.get("content-type", ""))
        except Exception as exc:
            raise MaintenanceModeStatusHttpTransportError(_UNAVAILABLE) from exc
        if (
            status != 200
            or len(content) > MAX_RESPONSE_BYTES
            or "json" not in content_type.lower()
        ):
            raise MaintenanceModeStatusHttpTransportError(_UNAVAILABLE)
        try:
            return json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MaintenanceModeStatusHttpTransportError(_UNAVAILABLE) from exc


class _MaintenanceModeSshSuccessor(Protocol):
    def _enable_after_external_preflight(self) -> None: ...

    def _disable_after_external_preflight(self) -> MaintenanceModeReadback: ...


class FortiPamMaintenanceModeSuccessorTransport:
    """Compose exact API drift checks with the fixed SSH enable command."""

    def __init__(
        self,
        status_transport: FortiPamMaintenanceModeStatusHttpTransport,
        ssh_transport: _MaintenanceModeSshSuccessor,
    ) -> None:
        self._status_transport = status_transport
        self._ssh_transport = ssh_transport

    def inspect(self) -> MaintenanceModeInspection:
        return self._status_transport.inspect()

    def enable_and_readback(self) -> MaintenanceModeReadback:
        before = self._status_transport.inspect()
        if not before.exact_disabled_baseline:
            raise MaintenanceModeStatusHttpTransportError(_UNAVAILABLE)
        self._ssh_transport._enable_after_external_preflight()
        after = self._status_transport.inspect()
        if after.status != "enable":
            raise MaintenanceModeStatusHttpTransportError(_UNAVAILABLE)
        return MaintenanceModeReadback(status="enable")

    def disable_and_readback(self) -> MaintenanceModeReadback:
        before = self._status_transport.inspect()
        if not before.exact_enabled_baseline:
            raise MaintenanceModeStatusHttpTransportError(_UNAVAILABLE)
        cli_readback = self._ssh_transport._disable_after_external_preflight()
        if (
            not isinstance(cli_readback, MaintenanceModeReadback)
            or not cli_readback.verified_disabled
        ):
            raise MaintenanceModeStatusHttpTransportError(_UNAVAILABLE)
        after = self._status_transport.inspect()
        if after.status != "disable":
            raise MaintenanceModeStatusHttpTransportError(_UNAVAILABLE)
        return MaintenanceModeReadback(status="disable")


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return {str(key): value for key, value in result.items()}
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return {str(key): value for key, value in result[0].items()}
    return None


def _base_url(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise MaintenanceModeStatusHttpTransportConfigurationError(
            "The maintenance-mode status HTTPS target is invalid."
        )
    normalized = value.rstrip("/")
    parsed = urlsplit(normalized)
    try:
        port = parsed.port
    except ValueError as exc:
        raise MaintenanceModeStatusHttpTransportConfigurationError(
            "The maintenance-mode status target port is invalid."
        ) from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise MaintenanceModeStatusHttpTransportConfigurationError(
            "The maintenance-mode status target must be a bare HTTPS origin."
        )
    return normalized


def _ssl_context(config: MaintenanceModeStatusHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        context = ssl.create_default_context(cafile=config.ca_file)
    else:
        try:
            import truststore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("truststore is required for TLS verification.") from exc
        context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _read_owner_only_token(path: Path) -> str:
    try:
        metadata = path.lstat()
        if (
            not path.is_file()
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise MaintenanceModeStatusHttpTransportConfigurationError(
                "The maintenance-mode status token file must be owner-only."
            )
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise MaintenanceModeStatusHttpTransportConfigurationError(
            "The maintenance-mode status token file is unavailable."
        ) from exc
    if not token:
        raise MaintenanceModeStatusHttpTransportConfigurationError(
            "The maintenance-mode status token file is empty."
        )
    return token


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


__all__ = [
    "ENV_PREFIX",
    "FortiPamMaintenanceModeStatusHttpTransport",
    "FortiPamMaintenanceModeSuccessorTransport",
    "MAINTENANCE_PATH",
    "MaintenanceModeStatusHttpTransportConfig",
    "MaintenanceModeStatusHttpTransportConfigurationError",
    "MaintenanceModeStatusHttpTransportError",
    "load_maintenance_mode_status_http_transport_config",
]
