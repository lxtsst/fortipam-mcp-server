"""Read-only API reconciliation for one exact FortiPAM Dependency Updater.

This adapter exists only to reconcile a previously created
``mcp-v4-dependency-updater-*`` Windows-service baseline. It issues one
catalogued detail ``GET`` and reduces the response to four categorical fields.
It exposes no create, update, delete, collection, association, credential, or
service-operation capability.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_DEPENDENCY_UPDATER_RECONCILE_API_"
COLLECTION_PATH = "/api/v2/cmdb/secret/dependency-updater"
MAX_RESPONSE_BYTES = 1_048_576
_UPDATER_NAME = re.compile(
    r"mcp-v4-dependency-updater-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z"
)
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._$-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Dependency Updater reconciliation transport is unavailable."


class DependencyUpdaterReconciliationHttpTransportConfigurationError(ValueError):
    """Raised when the read-only Dependency Updater route is unsafe."""


class DependencyUpdaterReconciliationHttpTransportError(RuntimeError):
    """Stable non-disclosing error for the bounded detail read."""


@dataclass(frozen=True, slots=True)
class DependencyUpdaterReconciliationHttpTransportConfig:
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
            raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
                "A dedicated Dependency Updater reconciliation bearer token is required."
            )
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(
            self.timeout_seconds, bool
        ):
            raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
                "The Dependency Updater reconciliation timeout is invalid."
            )
        if not 1 <= float(self.timeout_seconds) <= 60:
            raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
                "The Dependency Updater reconciliation timeout must be between 1 and 60 seconds."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class DependencyUpdaterBaselineReadback:
    """Categorical readback for the fixed Windows-service create baseline."""

    updater_name_exists: bool
    win_service_type_enabled: bool
    restart_disabled: bool
    service_name_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.updater_name_exists,
                self.win_service_type_enabled,
                self.restart_disabled,
                self.service_name_matches,
            )
        )


def load_dependency_updater_reconciliation_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> DependencyUpdaterReconciliationHttpTransportConfig:
    """Load an explicitly enabled, read-only Dependency Updater detail route."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    supplied = _value(env, "BASE_URL") or _value(env, "HOST")
    token_file = _value(env, "API_TOKEN_FILE")
    if supplied is None or token_file is None:
        raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
            "Dedicated Dependency Updater reconciliation target and token file are required."
        )
    try:
        timeout = float(_value(env, "TIMEOUT_SECONDS") or "15")
    except ValueError as exc:
        raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
            "The Dependency Updater reconciliation timeout is invalid."
        ) from exc
    return DependencyUpdaterReconciliationHttpTransportConfig(
        base_url=supplied if "://" in supplied else f"https://{supplied}",
        bearer_token=_read_owner_only_token(Path(token_file)),
        timeout_seconds=timeout,
        ca_file=_value(env, "CA_FILE"),
    )


class FortiPamDependencyUpdaterReconciliationHttpTransport:
    """Issue one fixed Dependency Updater detail GET and classify its state."""

    def __init__(
        self,
        config: DependencyUpdaterReconciliationHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def read_windows_service_baseline(
        self,
        updater_name: str,
        service_name: str,
    ) -> DependencyUpdaterBaselineReadback:
        """Read only the exact fixed Windows-service baseline."""

        name = _updater_name(updater_name)
        service = _service_name(service_name)
        payload = self._request(self._detail_path(name))
        return _baseline_readback(payload, name, service)

    def _request(self, path: str) -> object:
        expected_prefix = f"{COLLECTION_PATH}/"
        if not path.startswith(expected_prefix):
            raise DependencyUpdaterReconciliationHttpTransportError(_UNAVAILABLE)
        encoded_name = path.removeprefix(expected_prefix)
        try:
            decoded_name = _updater_name(encoded_name)
        except DependencyUpdaterReconciliationHttpTransportError:
            raise
        if quote(decoded_name, safe="") != encoded_name:
            raise DependencyUpdaterReconciliationHttpTransportError(_UNAVAILABLE)
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
            raise DependencyUpdaterReconciliationHttpTransportError(_UNAVAILABLE) from exc
        try:
            status = int(response.status_code)
            content = bytes(response.content)
            content_type = str(response.headers.get("content-type", ""))
        except Exception as exc:
            raise DependencyUpdaterReconciliationHttpTransportError(_UNAVAILABLE) from exc
        if (
            status != 200
            or len(content) > MAX_RESPONSE_BYTES
            or "json" not in content_type.lower()
        ):
            raise DependencyUpdaterReconciliationHttpTransportError(_UNAVAILABLE)
        try:
            return json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DependencyUpdaterReconciliationHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path(updater_name: str) -> str:
        return f"{COLLECTION_PATH}/{quote(updater_name, safe='')}"


def _baseline_readback(
    payload: object,
    updater_name: str,
    service_name: str,
) -> DependencyUpdaterBaselineReadback:
    record = _record(payload)
    if record is None:
        raise DependencyUpdaterReconciliationHttpTransportError(_UNAVAILABLE)
    return DependencyUpdaterBaselineReadback(
        updater_name_exists=record.get("name") == updater_name,
        win_service_type_enabled=record.get("type") == "win-service",
        restart_disabled=record.get("restart") == "disable",
        service_name_matches=record.get("service-name") == service_name,
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


def _updater_name(value: object) -> str:
    if not isinstance(value, str) or _UPDATER_NAME.fullmatch(value) is None:
        raise DependencyUpdaterReconciliationHttpTransportError(_UNAVAILABLE)
    return value


def _service_name(value: object) -> str:
    if not isinstance(value, str) or _SERVICE_NAME.fullmatch(value) is None:
        raise DependencyUpdaterReconciliationHttpTransportError(_UNAVAILABLE)
    return value


def _base_url(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
            "The Dependency Updater reconciliation HTTPS target is invalid."
        )
    normalized = value.rstrip("/")
    parsed = urlsplit(normalized)
    try:
        port = parsed.port
    except ValueError as exc:
        raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
            "The Dependency Updater reconciliation target port is invalid."
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
        raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
            "The Dependency Updater reconciliation target must be a bare HTTPS origin."
        )
    return normalized


def _ssl_context(
    config: DependencyUpdaterReconciliationHttpTransportConfig,
) -> ssl.SSLContext:
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
            raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
                "The Dependency Updater reconciliation token file must be owner-only."
            )
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
            "The Dependency Updater reconciliation token file is unavailable."
        ) from exc
    if not token:
        raise DependencyUpdaterReconciliationHttpTransportConfigurationError(
            "The Dependency Updater reconciliation token file is empty."
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
    "DependencyUpdaterBaselineReadback",
    "DependencyUpdaterReconciliationHttpTransportConfig",
    "DependencyUpdaterReconciliationHttpTransportConfigurationError",
    "DependencyUpdaterReconciliationHttpTransportError",
    "ENV_PREFIX",
    "FortiPamDependencyUpdaterReconciliationHttpTransport",
    "MAX_RESPONSE_BYTES",
    "load_dependency_updater_reconciliation_http_transport_config",
]
