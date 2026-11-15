"""Read-only API reconciliation for one exact FortiPAM Web VNC Template.

This adapter exists only to reconcile the fixed, previously created
``mcp-v4-template-*`` baseline.  It issues one catalogued detail ``GET`` and
reduces the response to categorical fields.  It exposes no create, update,
delete, collection, Secret, Target, or raw-response capability.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_TEMPLATE_RECONCILE_API_"
COLLECTION_PATH = "/api/v2/cmdb/secret/template"
MAX_RESPONSE_BYTES = 1_048_576
TEMPLATE_DEFAULT_PORT = 5900
_TEMPLATE_NAME = re.compile(
    r"mcp-v4-template-[A-Za-z0-9][A-Za-z0-9._-]{0,46}\Z"
)
_UNAVAILABLE = "FortiPAM V4 Template reconciliation transport is unavailable."


class TemplateReconciliationHttpTransportConfigurationError(ValueError):
    """Raised when the read-only Template detail transport is unsafe."""


class TemplateReconciliationHttpTransportError(RuntimeError):
    """Stable non-disclosing error for the bounded detail read."""


@dataclass(frozen=True, slots=True)
class TemplateReconciliationHttpTransportConfig:
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
            raise TemplateReconciliationHttpTransportConfigurationError(
                "A dedicated Template reconciliation bearer token is required."
            )
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(
            self.timeout_seconds, bool
        ):
            raise TemplateReconciliationHttpTransportConfigurationError(
                "The Template reconciliation timeout is invalid."
            )
        if not 1 <= float(self.timeout_seconds) <= 60:
            raise TemplateReconciliationHttpTransportConfigurationError(
                "The Template reconciliation timeout must be between 1 and 60 seconds."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise TemplateReconciliationHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class TemplateBaselineReadback:
    """Categorical readback for the exact Web VNC create baseline."""

    template_name_exists: bool
    access_everyone: bool
    username_field_present: bool
    username_field_mandatory: bool
    password_field_present: bool
    password_field_mandatory: bool
    web_vnc_launcher_present: bool
    web_vnc_port_is_default: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.template_name_exists,
                self.access_everyone,
                self.username_field_present,
                self.username_field_mandatory,
                self.password_field_present,
                self.password_field_mandatory,
                self.web_vnc_launcher_present,
                self.web_vnc_port_is_default,
            )
        )


def load_template_reconciliation_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> TemplateReconciliationHttpTransportConfig:
    """Load an explicitly enabled, read-only Template API detail route."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise TemplateReconciliationHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    supplied = _value(env, "BASE_URL") or _value(env, "HOST")
    token_file = _value(env, "API_TOKEN_FILE")
    if supplied is None or token_file is None:
        raise TemplateReconciliationHttpTransportConfigurationError(
            "Dedicated Template reconciliation target and token file are required."
        )
    try:
        timeout = float(_value(env, "TIMEOUT_SECONDS") or "15")
    except ValueError as exc:
        raise TemplateReconciliationHttpTransportConfigurationError(
            "The Template reconciliation timeout is invalid."
        ) from exc
    return TemplateReconciliationHttpTransportConfig(
        base_url=supplied if "://" in supplied else f"https://{supplied}",
        bearer_token=_read_owner_only_token(Path(token_file)),
        timeout_seconds=timeout,
        ca_file=_value(env, "CA_FILE"),
    )


class FortiPamTemplateReconciliationHttpTransport:
    """Issue one fixed Template detail GET and return categorical evidence."""

    def __init__(
        self,
        config: TemplateReconciliationHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def read_default_web_vnc_baseline(
        self,
        template_name: str,
    ) -> TemplateBaselineReadback:
        """Read and classify only the fixed port-5900 Web VNC baseline."""

        name = _template_name(template_name)
        payload = self._request(self._detail_path(name))
        return _baseline_readback(payload, name)

    def _request(self, path: str) -> object:
        expected_prefix = f"{COLLECTION_PATH}/"
        if not path.startswith(expected_prefix):
            raise TemplateReconciliationHttpTransportError(_UNAVAILABLE)
        encoded_name = path.removeprefix(expected_prefix)
        try:
            decoded_name = _template_name(encoded_name)
        except TemplateReconciliationHttpTransportError:
            raise
        if quote(decoded_name, safe="") != encoded_name:
            raise TemplateReconciliationHttpTransportError(_UNAVAILABLE)
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
            raise TemplateReconciliationHttpTransportError(_UNAVAILABLE) from exc
        try:
            status = int(response.status_code)
            content = bytes(response.content)
            content_type = str(response.headers.get("content-type", ""))
        except Exception as exc:
            raise TemplateReconciliationHttpTransportError(_UNAVAILABLE) from exc
        if (
            status != 200
            or len(content) > MAX_RESPONSE_BYTES
            or "json" not in content_type.lower()
        ):
            raise TemplateReconciliationHttpTransportError(_UNAVAILABLE)
        try:
            return json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TemplateReconciliationHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path(template_name: str) -> str:
        return f"{COLLECTION_PATH}/{quote(template_name, safe='')}"


def _baseline_readback(payload: object, template_name: str) -> TemplateBaselineReadback:
    record = _record(payload)
    if record is None:
        raise TemplateReconciliationHttpTransportError(_UNAVAILABLE)
    fields = _mapping_list(record.get("field"))
    launchers = _mapping_list(record.get("launcher"))
    username = [item for item in fields if item.get("name") == "Username"]
    password = [item for item in fields if item.get("name") == "Password"]
    web_vnc = [item for item in launchers if item.get("launcher-name") == "Web VNC"]
    exact_field_set = len(fields) == 2 and len(username) == 1 and len(password) == 1
    exact_launcher_set = len(launchers) == 1 and len(web_vnc) == 1
    username_record = username[0] if len(username) == 1 else {}
    password_record = password[0] if len(password) == 1 else {}
    launcher_record = web_vnc[0] if len(web_vnc) == 1 else {}
    return TemplateBaselineReadback(
        template_name_exists=record.get("name") == template_name,
        access_everyone=record.get("access") == "everyone",
        username_field_present=exact_field_set
        and username_record.get("type") == "username",
        username_field_mandatory=exact_field_set
        and username_record.get("mandatory") == "enable",
        password_field_present=exact_field_set
        and password_record.get("type") == "password",
        password_field_mandatory=exact_field_set
        and password_record.get("mandatory") == "enable",
        web_vnc_launcher_present=exact_launcher_set,
        web_vnc_port_is_default=exact_launcher_set
        and launcher_record.get("port") == TEMPLATE_DEFAULT_PORT,
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


def _mapping_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        return []
    return [
        {str(key): child for key, child in item.items()}
        for item in value
        if isinstance(item, Mapping)
    ]


def _template_name(value: object) -> str:
    if not isinstance(value, str) or _TEMPLATE_NAME.fullmatch(value) is None:
        raise TemplateReconciliationHttpTransportError(_UNAVAILABLE)
    return value


def _base_url(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise TemplateReconciliationHttpTransportConfigurationError(
            "The Template reconciliation HTTPS target is invalid."
        )
    normalized = value.rstrip("/")
    parsed = urlsplit(normalized)
    try:
        port = parsed.port
    except ValueError as exc:
        raise TemplateReconciliationHttpTransportConfigurationError(
            "The Template reconciliation target port is invalid."
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
        raise TemplateReconciliationHttpTransportConfigurationError(
            "The Template reconciliation target must be a bare HTTPS origin."
        )
    return normalized


def _ssl_context(config: TemplateReconciliationHttpTransportConfig) -> ssl.SSLContext:
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
            raise TemplateReconciliationHttpTransportConfigurationError(
                "The Template reconciliation token file must be owner-only."
            )
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise TemplateReconciliationHttpTransportConfigurationError(
            "The Template reconciliation token file is unavailable."
        ) from exc
    if not token:
        raise TemplateReconciliationHttpTransportConfigurationError(
            "The Template reconciliation token file is empty."
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
    "ENV_PREFIX",
    "FortiPamTemplateReconciliationHttpTransport",
    "MAX_RESPONSE_BYTES",
    "TEMPLATE_DEFAULT_PORT",
    "TemplateBaselineReadback",
    "TemplateReconciliationHttpTransportConfig",
    "TemplateReconciliationHttpTransportConfigurationError",
    "TemplateReconciliationHttpTransportError",
    "load_template_reconciliation_http_transport_config",
]
