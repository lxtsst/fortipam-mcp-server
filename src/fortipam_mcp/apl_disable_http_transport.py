"""Fixed private-binding REST APL disable transport for FortiPAM 7.0 build 29."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import re
import threading
from typing import Any, Literal
from urllib.parse import quote

from .apl_ssh_transport import AplDisableInspection, AplReadback
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, SecretMetadataHttpTransportConfig, _ssl_context,
    ENV_PREFIX as METADATA_ENV_PREFIX, load_secret_metadata_http_transport_config,
)

REST_ENV_PREFIX = "FORTIPAM_MCP_V4_APL_DISABLE_REST_700_"
BINDING_CONTRACT = "fortipam-v4-apl-disable-rest-700-binding-v1"

_DENIED = "FortiPAM REST Auto-Provision Rule disable is unavailable."


class AplDisableHttpTransportError(RuntimeError):
    """Stable error without selectors, responses or credential material."""


@dataclass(frozen=True, slots=True, repr=False)
class AplDisableHttpBinding:
    rule_name: str
    group_name: str
    role_name: str

    def __post_init__(self) -> None:
        for value, prefix, maximum in (
            (self.rule_name, "mcp-v4-apl-", 63),
            (self.group_name, "mcp-v4-user-group-", 63),
            (self.role_name, "mcp-v4-role-", 63),
        ):
            if not isinstance(value, str) or len(value) > maximum or not re.fullmatch(
                re.escape(prefix) + r"[A-Za-z0-9][A-Za-z0-9._-]*", value
            ):
                raise AplDisableHttpTransportError(_DENIED)


class FortiPamAplDisableHttpTransport:
    """Disable one privately bound rule once, preserving its complete baseline."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, binding: AplDisableHttpBinding,
        *, client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig) or not isinstance(binding, AplDisableHttpBinding):
            raise AplDisableHttpTransportError(_DENIED)
        self._config = config
        self._binding = binding
        self._client_factory = client_factory
        self._baseline: str | None = None
        self._attempted = False
        self._lock = threading.RLock()

    def inspect_disable(self, auto_provision_rule_name: str, remote_user_group_name: str, role_name: str) -> AplDisableInspection:
        with self._lock:
            return self._inspect_disable(auto_provision_rule_name, remote_user_group_name, role_name)

    def _inspect_disable(self, auto_provision_rule_name: str, remote_user_group_name: str, role_name: str) -> AplDisableInspection:
        self._require_binding(auto_provision_rule_name, remote_user_group_name, role_name)
        rule, group, role = self._read_baseline()
        current = _digest([rule, group, role])
        if self._baseline is not None and current != self._baseline:
            raise AplDisableHttpTransportError(_DENIED)
        self._baseline = current
        return AplDisableInspection(
            True, rule.get("status") == "enable",
            rule.get("remote-group") == self._binding.group_name,
            rule.get("accprofile") == self._binding.role_name, True, True,
        )

    def disable_and_readback(self, auto_provision_rule_name: str, remote_user_group_name: str, role_name: str) -> AplReadback:
        with self._lock:
            return self._disable_and_readback(auto_provision_rule_name, remote_user_group_name, role_name)

    def _disable_and_readback(self, auto_provision_rule_name: str, remote_user_group_name: str, role_name: str) -> AplReadback:
        if self._attempted:
            raise AplDisableHttpTransportError(_DENIED)
        self._require_binding(auto_provision_rule_name, remote_user_group_name, role_name)
        if self._baseline is None:
            raise AplDisableHttpTransportError(_DENIED)
        before, group_before, role_before = self._read_baseline()
        if _digest([before, group_before, role_before]) != self._baseline or not (
            before.get("status") == "enable"
            and before.get("remote-group") == self._binding.group_name
            and before.get("accprofile") == self._binding.role_name
        ):
            raise AplDisableHttpTransportError(_DENIED)
        self._attempted = True
        self._request("PUT", "user", "auto-provision-rule", self._binding.rule_name, {"status": "disable"})
        after, group_after, role_after = self._read_baseline()
        if (_digest({k: v for k, v in before.items() if k != "status"}) !=
                _digest({k: v for k, v in after.items() if k != "status"})
                or _digest(group_before) != _digest(group_after)
                or _digest(role_before) != _digest(role_after)):
            raise AplDisableHttpTransportError(_DENIED)
        result = AplReadback(True, after.get("status") == "disable",
                             after.get("remote-group") == self._binding.group_name,
                             after.get("accprofile") == self._binding.role_name)
        if not result.verified:
            raise AplDisableHttpTransportError(_DENIED)
        return result

    def _require_binding(self, rule: str, group: str, role: str) -> None:
        if (rule, group, role) != (self._binding.rule_name, self._binding.group_name, self._binding.role_name):
            raise AplDisableHttpTransportError(_DENIED)

    def _read_baseline(self) -> tuple[Mapping[str, object], Mapping[str, object], Mapping[str, object]]:
        return (
            self._detail("user", "auto-provision-rule", self._binding.rule_name),
            self._detail("user", "group", self._binding.group_name),
            self._detail("system", "accprofile", self._binding.role_name),
        )

    def _detail(self, path: str, table: str, key: str) -> Mapping[str, object]:
        payload = self._request("GET", path, table, key, None)
        results = payload.get("results")
        record = results[0] if isinstance(results, list) and len(results) == 1 else results
        if not isinstance(record, dict) or record.get("name") != key:
            raise AplDisableHttpTransportError(_DENIED)
        return record

    def _request(self, method: Literal["GET", "PUT"], path: str, table: str, key: str, body: dict[str, str] | None) -> Mapping[str, object]:
        try:
            import httpx
            factory = self._client_factory or httpx.Client
            with factory(verify=_ssl_context(self._config), timeout=self._config.timeout_seconds,
                         follow_redirects=False, trust_env=False) as client:
                response = client.request(method, f"{self._config.base_url}/api/v2/cmdb/{path}/{table}/{quote(key, safe='')}",
                    headers={"Accept": "application/json", "Authorization": f"Bearer {self._config.bearer_token}"}, json=body)
            if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower() or len(response.content) > MAX_RESPONSE_BYTES:
                raise ValueError("response unavailable")
            payload = json.loads(response.content)
            if not isinstance(payload, dict) or any(payload.get(k) != v for k, v in {
                "status": "success", "http_status": 200, "http_method": method,
                "path": path, "name": table, "version": "v7.0.0", "build": 29,
            }.items()):
                raise ValueError("envelope unavailable")
            return payload
        except Exception:
            raise AplDisableHttpTransportError(_DENIED) from None


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_apl_disable_http_transport(environment: Mapping[str, str]) -> FortiPamAplDisableHttpTransport:
    """Load only dedicated API settings and one owner-only private binding."""
    try:
        path = Path(environment[REST_ENV_PREFIX + "BINDING_FILE"])
        if not path.is_absolute():
            raise ValueError("absolute binding required")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096:
                raise ValueError("private binding required")
            content = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        value = json.loads(content)
        if not isinstance(value, dict) or set(value) != {"contract", "rule_name", "group_name", "role_name"} or value["contract"] != BINDING_CONTRACT:
            raise ValueError("binding contract required")
        binding = AplDisableHttpBinding(value["rule_name"], value["group_name"], value["role_name"])
        settings = {METADATA_ENV_PREFIX + "ENABLED": "true"}
        for suffix in ("BASE_URL", "API_TOKEN", "TIMEOUT_SECONDS", "CA_FILE"):
            if REST_ENV_PREFIX + suffix in environment:
                settings[METADATA_ENV_PREFIX + suffix] = environment[REST_ENV_PREFIX + suffix]
        return FortiPamAplDisableHttpTransport(load_secret_metadata_http_transport_config(settings), binding)
    except Exception:
        raise AplDisableHttpTransportError(_DENIED) from None
