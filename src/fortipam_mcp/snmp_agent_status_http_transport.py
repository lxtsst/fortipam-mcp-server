"""Strict API status preflight for the FortiPAM SNMP Agent successor.

The FortiPAM 1.9.1 catalog exposes one exact read-only sysinfo route while its
PUT body remains unspecified. This module uses that GET only to classify the
Agent status before and after the existing fixed SSH enable command. It does
not expose an API write, community, SNMPv3 user, notification, interface, or
query/trap surface.
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

from .snmp_agent_ssh_transport import SnmpAgentInspection, SnmpAgentReadback


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_STATUS_API_"
SYSINFO_PATH = "/api/v2/cmdb/system.snmp/sysinfo"
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 SNMP agent status transport is unavailable."


class SnmpAgentStatusHttpTransportConfigurationError(ValueError):
    """Raised when the exact read-only API route is unsafe."""


class SnmpAgentStatusHttpTransportError(RuntimeError):
    """Stable non-disclosing error for SNMP Agent status reads."""


@dataclass(frozen=True, slots=True)
class SnmpAgentStatusHttpTransportConfig:
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
            raise SnmpAgentStatusHttpTransportConfigurationError(
                "A dedicated SNMP Agent status bearer token is required."
            )
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(
            self.timeout_seconds, bool
        ):
            raise SnmpAgentStatusHttpTransportConfigurationError(
                "The SNMP Agent status timeout is invalid."
            )
        if not 1 <= float(self.timeout_seconds) <= 60:
            raise SnmpAgentStatusHttpTransportConfigurationError(
                "The SNMP Agent status timeout must be between 1 and 60 seconds."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise SnmpAgentStatusHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


def load_snmp_agent_status_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> SnmpAgentStatusHttpTransportConfig:
    """Load an explicitly enabled exact sysinfo GET route."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise SnmpAgentStatusHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    supplied = _value(env, "BASE_URL") or _value(env, "HOST")
    token_file = _value(env, "API_TOKEN_FILE")
    if supplied is None or token_file is None:
        raise SnmpAgentStatusHttpTransportConfigurationError(
            "Dedicated SNMP Agent status target and token file are required."
        )
    try:
        timeout = float(_value(env, "TIMEOUT_SECONDS") or "15")
    except ValueError as exc:
        raise SnmpAgentStatusHttpTransportConfigurationError(
            "The SNMP Agent status timeout is invalid."
        ) from exc
    return SnmpAgentStatusHttpTransportConfig(
        base_url=supplied if "://" in supplied else f"https://{supplied}",
        bearer_token=_read_owner_only_token(Path(token_file)),
        timeout_seconds=timeout,
        ca_file=_value(env, "CA_FILE"),
    )


class FortiPamSnmpAgentStatusHttpTransport:
    """Issue one exact sysinfo GET and reduce it to enable or disable."""

    def __init__(
        self,
        config: SnmpAgentStatusHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self) -> SnmpAgentInspection:
        """Return only the explicit Agent status from the exact API record."""

        record = _record(self._request())
        status = record.get("status") if record is not None else None
        if status not in {"enable", "disable"}:
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE)
        return SnmpAgentInspection(status=status)

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
                    f"{self._config.base_url}{SYSINFO_PATH}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                )
        except Exception as exc:
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE) from exc
        try:
            status = int(response.status_code)
            content = bytes(response.content)
            content_type = str(response.headers.get("content-type", ""))
        except Exception as exc:
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE) from exc
        if (
            status != 200
            or len(content) > MAX_RESPONSE_BYTES
            or "json" not in content_type.lower()
        ):
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE)
        try:
            return json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE) from exc


class _SnmpAgentSshSuccessor(Protocol):
    def _enable_after_external_preflight(self) -> SnmpAgentReadback: ...

    def _disable_after_external_preflight(self) -> SnmpAgentReadback: ...


class FortiPamSnmpAgentSuccessorTransport:
    """Compose exact API drift checks with the fixed SSH enable command."""

    def __init__(
        self,
        status_transport: FortiPamSnmpAgentStatusHttpTransport,
        ssh_transport: _SnmpAgentSshSuccessor,
    ) -> None:
        self._status_transport = status_transport
        self._ssh_transport = ssh_transport

    def inspect(self) -> SnmpAgentInspection:
        return self._status_transport.inspect()

    def enable_and_readback(self) -> SnmpAgentReadback:
        before = self._status_transport.inspect()
        if not before.exact_disabled_baseline:
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE)
        cli_readback = self._ssh_transport._enable_after_external_preflight()
        if not isinstance(cli_readback, SnmpAgentReadback) or not cli_readback.verified:
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE)
        after = self._status_transport.inspect()
        if after.status != "enable":
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE)
        return SnmpAgentReadback(status="enable")

    def disable_and_readback(self) -> SnmpAgentReadback:
        before = self._status_transport.inspect()
        if not before.exact_enabled_baseline:
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE)
        cli_readback = self._ssh_transport._disable_after_external_preflight()
        if (
            not isinstance(cli_readback, SnmpAgentReadback)
            or not cli_readback.verified_disabled
        ):
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE)
        after = self._status_transport.inspect()
        if after.status != "disable":
            raise SnmpAgentStatusHttpTransportError(_UNAVAILABLE)
        return SnmpAgentReadback(status="disable")


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
        raise SnmpAgentStatusHttpTransportConfigurationError(
            "The SNMP Agent status HTTPS target is invalid."
        )
    normalized = value.rstrip("/")
    parsed = urlsplit(normalized)
    try:
        port = parsed.port
    except ValueError as exc:
        raise SnmpAgentStatusHttpTransportConfigurationError(
            "The SNMP Agent status target port is invalid."
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
        raise SnmpAgentStatusHttpTransportConfigurationError(
            "The SNMP Agent status target must be a bare HTTPS origin."
        )
    return normalized


def _ssl_context(config: SnmpAgentStatusHttpTransportConfig) -> ssl.SSLContext:
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
            raise SnmpAgentStatusHttpTransportConfigurationError(
                "The SNMP Agent status token file must be owner-only."
            )
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SnmpAgentStatusHttpTransportConfigurationError(
            "The SNMP Agent status token file is unavailable."
        ) from exc
    if not token:
        raise SnmpAgentStatusHttpTransportConfigurationError(
            "The SNMP Agent status token file is empty."
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
    "FortiPamSnmpAgentStatusHttpTransport",
    "FortiPamSnmpAgentSuccessorTransport",
    "SYSINFO_PATH",
    "SnmpAgentStatusHttpTransportConfig",
    "SnmpAgentStatusHttpTransportConfigurationError",
    "SnmpAgentStatusHttpTransportError",
    "load_snmp_agent_status_http_transport_config",
]
