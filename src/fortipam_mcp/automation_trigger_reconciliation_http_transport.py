"""Read-only API reconciliation for one exact FortiPAM Automation Trigger.

This adapter exists only to reconcile a previously created
``mcp-v4-automation-trigger-*`` event-log baseline. It issues one catalogued
detail ``GET`` and reduces the response to categorical fixed fields, including
the appliance's nested single-logid representation. It exposes no create,
update, delete, collection, Action, Stitch, or execution capability.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_AUTOMATION_TRIGGER_RECONCILE_API_"
COLLECTION_PATH = "/api/v2/cmdb/system/automation-trigger"
MAX_RESPONSE_BYTES = 1_048_576
FIXED_LOG_ID = 44547
FIXED_FIELD_VALUE = "mcp-v4-no-action"
_TRIGGER_NAME = re.compile(
    r"mcp-v4-automation-trigger-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z"
)
_UNAVAILABLE = "FortiPAM V4 Automation Trigger reconciliation transport is unavailable."


class AutomationTriggerReconciliationHttpTransportConfigurationError(ValueError):
    """Raised when the read-only Automation Trigger route is unsafe."""


class AutomationTriggerReconciliationHttpTransportError(RuntimeError):
    """Stable non-disclosing error for the bounded detail read."""


@dataclass(frozen=True, slots=True)
class AutomationTriggerReconciliationHttpTransportConfig:
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
            raise AutomationTriggerReconciliationHttpTransportConfigurationError(
                "A dedicated Automation Trigger reconciliation bearer token is required."
            )
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(
            self.timeout_seconds, bool
        ):
            raise AutomationTriggerReconciliationHttpTransportConfigurationError(
                "The Automation Trigger reconciliation timeout is invalid."
            )
        if not 1 <= float(self.timeout_seconds) <= 60:
            raise AutomationTriggerReconciliationHttpTransportConfigurationError(
                "The Automation Trigger reconciliation timeout must be between 1 and 60 seconds."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise AutomationTriggerReconciliationHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class AutomationTriggerBaselineReadback:
    """Categorical readback for the fixed unbound event-log Trigger baseline."""

    trigger_name_exists: bool
    event_log_type_enabled: bool
    fixed_single_logid_present: bool
    category_one_present: bool
    logic_and_enabled: bool
    exact_msg_regex_field_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.trigger_name_exists,
                self.event_log_type_enabled,
                self.fixed_single_logid_present,
                self.category_one_present,
                self.logic_and_enabled,
                self.exact_msg_regex_field_present,
            )
        )


def load_automation_trigger_reconciliation_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> AutomationTriggerReconciliationHttpTransportConfig:
    """Load an explicitly enabled, read-only Automation Trigger detail route."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise AutomationTriggerReconciliationHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    supplied = _value(env, "BASE_URL") or _value(env, "HOST")
    token_file = _value(env, "API_TOKEN_FILE")
    if supplied is None or token_file is None:
        raise AutomationTriggerReconciliationHttpTransportConfigurationError(
            "Dedicated Automation Trigger reconciliation target and token file are required."
        )
    try:
        timeout = float(_value(env, "TIMEOUT_SECONDS") or "15")
    except ValueError as exc:
        raise AutomationTriggerReconciliationHttpTransportConfigurationError(
            "The Automation Trigger reconciliation timeout is invalid."
        ) from exc
    return AutomationTriggerReconciliationHttpTransportConfig(
        base_url=supplied if "://" in supplied else f"https://{supplied}",
        bearer_token=_read_owner_only_token(Path(token_file)),
        timeout_seconds=timeout,
        ca_file=_value(env, "CA_FILE"),
    )


class FortiPamAutomationTriggerReconciliationHttpTransport:
    """Issue one fixed Automation Trigger detail GET and classify its state."""

    def __init__(
        self,
        config: AutomationTriggerReconciliationHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def read_event_log_baseline(
        self,
        trigger_name: str,
    ) -> AutomationTriggerBaselineReadback:
        """Read only the exact fixed no-action event-log Trigger baseline."""

        name = _trigger_name(trigger_name)
        payload = self._request(self._detail_path(name))
        return _baseline_readback(payload, name)

    def _request(self, path: str) -> object:
        expected_prefix = f"{COLLECTION_PATH}/"
        if not path.startswith(expected_prefix):
            raise AutomationTriggerReconciliationHttpTransportError(_UNAVAILABLE)
        encoded_name = path.removeprefix(expected_prefix)
        try:
            decoded_name = _trigger_name(encoded_name)
        except AutomationTriggerReconciliationHttpTransportError:
            raise
        if quote(decoded_name, safe="") != encoded_name:
            raise AutomationTriggerReconciliationHttpTransportError(_UNAVAILABLE)
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
            raise AutomationTriggerReconciliationHttpTransportError(_UNAVAILABLE) from exc
        try:
            status = int(response.status_code)
            content = bytes(response.content)
            content_type = str(response.headers.get("content-type", ""))
        except Exception as exc:
            raise AutomationTriggerReconciliationHttpTransportError(_UNAVAILABLE) from exc
        if (
            status != 200
            or len(content) > MAX_RESPONSE_BYTES
            or "json" not in content_type.lower()
        ):
            raise AutomationTriggerReconciliationHttpTransportError(_UNAVAILABLE)
        try:
            return json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AutomationTriggerReconciliationHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path(trigger_name: str) -> str:
        return f"{COLLECTION_PATH}/{quote(trigger_name, safe='')}"


def _baseline_readback(
    payload: object,
    trigger_name: str,
) -> AutomationTriggerBaselineReadback:
    record = _record(payload)
    if record is None:
        raise AutomationTriggerReconciliationHttpTransportError(_UNAVAILABLE)
    logids = _mapping_list(record.get("logid"))
    fields = _mapping_list(record.get("fields"))
    exact_logid = len(logids) == 1 and logids[0].get("id") == FIXED_LOG_ID
    exact_field = (
        len(fields) == 1
        and fields[0].get("match") == "regex"
        and fields[0].get("name") == "msg"
        and fields[0].get("value") == FIXED_FIELD_VALUE
    )
    return AutomationTriggerBaselineReadback(
        trigger_name_exists=record.get("name") == trigger_name,
        event_log_type_enabled=record.get("event-type") == "event-log",
        fixed_single_logid_present=exact_logid,
        category_one_present=record.get("category") == 1,
        logic_and_enabled=record.get("logic") == "and",
        exact_msg_regex_field_present=exact_field,
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
    if not isinstance(value, list):
        return []
    return [
        {str(key): child for key, child in item.items()}
        for item in value
        if isinstance(item, Mapping)
    ]


def _trigger_name(value: object) -> str:
    if not isinstance(value, str) or _TRIGGER_NAME.fullmatch(value) is None:
        raise AutomationTriggerReconciliationHttpTransportError(_UNAVAILABLE)
    return value


def _base_url(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise AutomationTriggerReconciliationHttpTransportConfigurationError(
            "The Automation Trigger reconciliation HTTPS target is invalid."
        )
    normalized = value.rstrip("/")
    parsed = urlsplit(normalized)
    try:
        port = parsed.port
    except ValueError as exc:
        raise AutomationTriggerReconciliationHttpTransportConfigurationError(
            "The Automation Trigger reconciliation target port is invalid."
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
        raise AutomationTriggerReconciliationHttpTransportConfigurationError(
            "The Automation Trigger reconciliation target must be a bare HTTPS origin."
        )
    return normalized


def _ssl_context(
    config: AutomationTriggerReconciliationHttpTransportConfig,
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
            raise AutomationTriggerReconciliationHttpTransportConfigurationError(
                "The Automation Trigger reconciliation token file must be owner-only."
            )
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise AutomationTriggerReconciliationHttpTransportConfigurationError(
            "The Automation Trigger reconciliation token file is unavailable."
        ) from exc
    if not token:
        raise AutomationTriggerReconciliationHttpTransportConfigurationError(
            "The Automation Trigger reconciliation token file is empty."
        )
    return token


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


__all__ = [
    "AutomationTriggerBaselineReadback",
    "AutomationTriggerReconciliationHttpTransportConfig",
    "AutomationTriggerReconciliationHttpTransportConfigurationError",
    "AutomationTriggerReconciliationHttpTransportError",
    "COLLECTION_PATH",
    "ENV_PREFIX",
    "FIXED_FIELD_VALUE",
    "FIXED_LOG_ID",
    "FortiPamAutomationTriggerReconciliationHttpTransport",
    "MAX_RESPONSE_BYTES",
    "load_automation_trigger_reconciliation_http_transport_config",
]
