"""Read-only API reconciliation for one exact FortiPAM Secret Gateway.

This adapter exists only to reconcile a previously created
``mcp-v4-secret-gateway-*`` disabled Forward Gateway baseline. It issues one
catalogued detail ``GET`` and reduces the response to categorical fixed fields.
It exposes no create, update, delete, collection, association, certificate,
route, forwarding, reverse-service, or session capability.
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
from typing import Any
from urllib.parse import quote, urlsplit


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_RECONCILE_API_"
COLLECTION_PATH = "/api/v2/cmdb/secret/gateway"
MAX_RESPONSE_BYTES = 1_048_576
DOCUMENTATION_ADDRESS = "192.0.2.1"
FIXED_DESCRIPTION = "MCP V4 disabled forward gateway"
_GATEWAY_NAME = re.compile(
    r"mcp-v4-secret-gateway-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z"
)
_UNAVAILABLE = "FortiPAM V4 Secret Gateway reconciliation transport is unavailable."


class SecretGatewayReconciliationHttpTransportConfigurationError(ValueError):
    """Raised when the read-only Secret Gateway route is unsafe."""


class SecretGatewayReconciliationHttpTransportError(RuntimeError):
    """Stable non-disclosing error for the bounded detail read."""


@dataclass(frozen=True, slots=True)
class SecretGatewayReconciliationHttpTransportConfig:
    """Dedicated HTTPS and bearer-token settings kept only in memory."""

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
            raise SecretGatewayReconciliationHttpTransportConfigurationError(
                "A dedicated Secret Gateway reconciliation bearer token is required."
            )
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(
            self.timeout_seconds, bool
        ):
            raise SecretGatewayReconciliationHttpTransportConfigurationError(
                "The Secret Gateway reconciliation timeout is invalid."
            )
        if not 1 <= float(self.timeout_seconds) <= 60:
            raise SecretGatewayReconciliationHttpTransportConfigurationError(
                "The Secret Gateway reconciliation timeout must be between 1 and 60 seconds."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise SecretGatewayReconciliationHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class SecretGatewayBaselineReadback:
    """Categorical readback for the fixed disabled Forward Gateway baseline."""

    gateway_name_exists: bool
    status_disabled: bool
    forward_type_enabled: bool
    documentation_address_matches: bool
    port_443_enabled: bool
    tcp_url_map_enabled: bool
    tls_1_3_maximum_enabled: bool
    description_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.gateway_name_exists,
                self.status_disabled,
                self.forward_type_enabled,
                self.documentation_address_matches,
                self.port_443_enabled,
                self.tcp_url_map_enabled,
                self.tls_1_3_maximum_enabled,
                self.description_matches,
            )
        )


def load_secret_gateway_reconciliation_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> SecretGatewayReconciliationHttpTransportConfig:
    """Load an explicitly enabled, read-only Secret Gateway detail route."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise SecretGatewayReconciliationHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    supplied = _value(env, "BASE_URL") or _value(env, "HOST")
    token_file = _value(env, "API_TOKEN_FILE")
    if supplied is None or token_file is None:
        raise SecretGatewayReconciliationHttpTransportConfigurationError(
            "Dedicated Secret Gateway reconciliation target and token file are required."
        )
    try:
        timeout = float(_value(env, "TIMEOUT_SECONDS") or "15")
    except ValueError as exc:
        raise SecretGatewayReconciliationHttpTransportConfigurationError(
            "The Secret Gateway reconciliation timeout is invalid."
        ) from exc
    return SecretGatewayReconciliationHttpTransportConfig(
        base_url=supplied if "://" in supplied else f"https://{supplied}",
        bearer_token=_read_owner_only_token(Path(token_file)),
        timeout_seconds=timeout,
        ca_file=_value(env, "CA_FILE"),
    )


class FortiPamSecretGatewayReconciliationHttpTransport:
    """Issue one fixed Secret Gateway detail GET and classify its state."""

    def __init__(
        self,
        config: SecretGatewayReconciliationHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def read_disabled_forward_baseline(
        self,
        gateway_name: str,
    ) -> SecretGatewayBaselineReadback:
        """Read only the exact fixed disabled Forward Gateway baseline."""

        name = _gateway_name(gateway_name)
        payload = self._request(self._detail_path(name))
        return _baseline_readback(payload, name)

    def _request(self, path: str) -> object:
        expected_prefix = f"{COLLECTION_PATH}/"
        if not path.startswith(expected_prefix):
            raise SecretGatewayReconciliationHttpTransportError(_UNAVAILABLE)
        encoded_name = path.removeprefix(expected_prefix)
        try:
            decoded_name = _gateway_name(encoded_name)
        except SecretGatewayReconciliationHttpTransportError:
            raise
        if quote(decoded_name, safe="") != encoded_name:
            raise SecretGatewayReconciliationHttpTransportError(_UNAVAILABLE)
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
                    f"{self._config.base_url}{path}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                )
        except Exception as exc:
            raise SecretGatewayReconciliationHttpTransportError(_UNAVAILABLE) from exc
        try:
            status = int(response.status_code)
            content = bytes(response.content)
            content_type = str(response.headers.get("content-type", ""))
        except Exception as exc:
            raise SecretGatewayReconciliationHttpTransportError(_UNAVAILABLE) from exc
        if (
            status != 200
            or len(content) > MAX_RESPONSE_BYTES
            or "json" not in content_type.lower()
        ):
            raise SecretGatewayReconciliationHttpTransportError(_UNAVAILABLE)
        try:
            return json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretGatewayReconciliationHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path(gateway_name: str) -> str:
        return f"{COLLECTION_PATH}/{quote(gateway_name, safe='')}"


def _baseline_readback(
    payload: object,
    gateway_name: str,
) -> SecretGatewayBaselineReadback:
    record = _record(payload)
    if record is None:
        raise SecretGatewayReconciliationHttpTransportError(_UNAVAILABLE)
    return SecretGatewayBaselineReadback(
        gateway_name_exists=record.get("name") == gateway_name,
        status_disabled=record.get("status") == "disable",
        forward_type_enabled=record.get("type") == "forward",
        documentation_address_matches=record.get("address") == DOCUMENTATION_ADDRESS,
        port_443_enabled=record.get("port") == 443,
        tcp_url_map_enabled=record.get("url-map") == "tcp",
        tls_1_3_maximum_enabled=record.get("ssl-max-version") == "tls-1.3",
        description_matches=record.get("description") == FIXED_DESCRIPTION,
    )


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return {str(key): value for key, value in result.items()}
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return {str(key): value for key, value in result[0].items()}
    return None


def _gateway_name(value: object) -> str:
    if not isinstance(value, str) or _GATEWAY_NAME.fullmatch(value) is None:
        raise SecretGatewayReconciliationHttpTransportError(_UNAVAILABLE)
    return value


def _base_url(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise SecretGatewayReconciliationHttpTransportConfigurationError(
            "The Secret Gateway reconciliation HTTPS target is invalid."
        )
    normalized = value.rstrip("/")
    parsed = urlsplit(normalized)
    try:
        port = parsed.port
    except ValueError as exc:
        raise SecretGatewayReconciliationHttpTransportConfigurationError(
            "The Secret Gateway reconciliation target port is invalid."
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
        raise SecretGatewayReconciliationHttpTransportConfigurationError(
            "The Secret Gateway reconciliation target must be a bare HTTPS origin."
        )
    return normalized


def _ssl_context(config: SecretGatewayReconciliationHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        context = ssl.create_default_context(cafile=config.ca_file)
    else:
        try:
            import truststore
        except ImportError as exc:  # pragma: no cover - dependency guard.
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
            raise SecretGatewayReconciliationHttpTransportConfigurationError(
                "The Secret Gateway reconciliation token file must be owner-only."
            )
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SecretGatewayReconciliationHttpTransportConfigurationError(
            "The Secret Gateway reconciliation token file is unavailable."
        ) from exc
    if not token:
        raise SecretGatewayReconciliationHttpTransportConfigurationError(
            "The Secret Gateway reconciliation token file is empty."
        )
    return token


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


__all__ = [
    "COLLECTION_PATH",
    "DOCUMENTATION_ADDRESS",
    "ENV_PREFIX",
    "FIXED_DESCRIPTION",
    "FortiPamSecretGatewayReconciliationHttpTransport",
    "MAX_RESPONSE_BYTES",
    "SecretGatewayBaselineReadback",
    "SecretGatewayReconciliationHttpTransportConfig",
    "SecretGatewayReconciliationHttpTransportConfigurationError",
    "SecretGatewayReconciliationHttpTransportError",
    "load_secret_gateway_reconciliation_http_transport_config",
]
