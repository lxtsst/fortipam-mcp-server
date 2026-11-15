"""One disabled, privately bound REST APL create on FortiPAM 7.0 build 29."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
from typing import Any, Literal
from urllib.parse import quote

from .apl_ssh_transport import (
    AplInspection, AplReadback, _apl_name, _user_group_name, _role_name,
)
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, SecretMetadataHttpTransportConfig, _ssl_context,
    ENV_PREFIX as METADATA_ENV_PREFIX, load_secret_metadata_http_transport_config,
)

REST_ENV_PREFIX = "FORTIPAM_MCP_V4_APL_CREATE_REST_700_"
BINDING_CONTRACT = "fortipam-v4-apl-create-rest-700-binding-v1"
_DENIED = "FortiPAM REST Auto-Provision Rule create is unavailable."


class AplCreateHttpTransportError(RuntimeError):
    """Stable failure with no selectors, device response or credentials."""


@dataclass(frozen=True, slots=True, repr=False)
class AplCreateHttpBinding:
    rule_name: str
    group_name: str
    role_name: str

    def __post_init__(self) -> None:
        try:
            _apl_name(self.rule_name)
            _user_group_name(self.group_name)
            _role_name(self.role_name)
        except Exception:
            raise AplCreateHttpTransportError(_DENIED) from None


class FortiPamAplCreateHttpTransport:
    """Create one absent rule, binding all dependencies and a durable claim."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        binding: AplCreateHttpBinding,
        claim_path: Path,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig) or not isinstance(
            binding, AplCreateHttpBinding
        ):
            raise AplCreateHttpTransportError(_DENIED)
        self._config = config
        self._binding = binding
        self._claim_path = Path(claim_path)
        self._client_factory = client_factory
        self._baseline: str | None = None
        self._lock = threading.RLock()
        self._check_claim_parent()

    def inspect(self, auto_provision_rule_name: str, remote_user_group_name: str,
                role_name: str) -> AplInspection:
        with self._lock:
            self._require_binding(auto_provision_rule_name, remote_user_group_name, role_name)
            self._require_unconsumed()
            rules, group, role = self._snapshot()
            digest = _digest([rules, group, role])
            if self._baseline is not None and digest != self._baseline:
                raise AplCreateHttpTransportError(_DENIED)
            self._baseline = digest
            return AplInspection(self._binding.rule_name in rules, True, True)

    def create_disabled_and_readback(
        self, auto_provision_rule_name: str, remote_user_group_name: str, role_name: str,
    ) -> AplReadback:
        with self._lock:
            self._require_binding(auto_provision_rule_name, remote_user_group_name, role_name)
            self._require_unconsumed()
            if self._baseline is None:
                raise AplCreateHttpTransportError(_DENIED)
            rules, group, role = self._snapshot()
            if self._binding.rule_name in rules or _digest([rules, group, role]) != self._baseline:
                raise AplCreateHttpTransportError(_DENIED)
            body = {
                "name": self._binding.rule_name,
                "status": "disable",
                "remote-group": self._binding.group_name,
                "accprofile": self._binding.role_name,
            }
            self._reserve_claim()
            self._request("POST", "user", "auto-provision-rule", None, body)
            after, group_after, role_after = self._snapshot()
            created = after.get(self._binding.rule_name)
            detail = self._detail("user", "auto-provision-rule", self._binding.rule_name)
            if (
                not isinstance(created, dict)
                or any(created.get(key) != value or detail.get(key) != value
                       for key, value in body.items())
                or _digest({key: value for key, value in after.items()
                            if key != self._binding.rule_name}) != _digest(rules)
                or _digest(group_after) != _digest(group)
                or _digest(role_after) != _digest(role)
            ):
                raise AplCreateHttpTransportError(_DENIED)
            return AplReadback(True, True, True, True)

    def _require_binding(self, rule: str, group: str, role: str) -> None:
        if (rule, group, role) != (
            self._binding.rule_name, self._binding.group_name, self._binding.role_name
        ):
            raise AplCreateHttpTransportError(_DENIED)

    def _snapshot(self) -> tuple[dict[str, object], Mapping[str, object], Mapping[str, object]]:
        payload = self._request("GET", "user", "auto-provision-rule", None, None)
        rows = payload.get("results")
        if not isinstance(rows, list) or payload.get("limit_reached", False) is not False:
            raise AplCreateHttpTransportError(_DENIED)
        rules: dict[str, object] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                raise AplCreateHttpTransportError(_DENIED)
            name = row["name"]
            if not name or name in rules:
                raise AplCreateHttpTransportError(_DENIED)
            rules[name] = row
        return (
            rules,
            self._detail("user", "group", self._binding.group_name),
            self._detail("system", "accprofile", self._binding.role_name),
        )

    def _detail(self, path: str, table: str, key: str) -> Mapping[str, object]:
        payload = self._request("GET", path, table, key, None)
        results = payload.get("results")
        record = results[0] if isinstance(results, list) and len(results) == 1 else results
        if not isinstance(record, dict) or record.get("name") != key:
            raise AplCreateHttpTransportError(_DENIED)
        return record

    def _request(self, method: Literal["GET", "POST"], path: str, table: str,
                 key: str | None, body: dict[str, str] | None) -> Mapping[str, object]:
        try:
            import httpx
            factory = self._client_factory or httpx.Client
            suffix = "" if key is None else "/" + quote(key, safe="")
            with factory(verify=_ssl_context(self._config), timeout=self._config.timeout_seconds,
                         follow_redirects=False, trust_env=False) as client:
                response = client.request(
                    method, f"{self._config.base_url}/api/v2/cmdb/{path}/{table}{suffix}",
                    headers={"Accept": "application/json",
                             "Authorization": f"Bearer {self._config.bearer_token}"}, json=body,
                )
            if (response.status_code != 200
                    or "json" not in response.headers.get("content-type", "").lower()
                    or len(response.content) > MAX_RESPONSE_BYTES):
                raise ValueError("response unavailable")
            payload = json.loads(response.content)
            if not isinstance(payload, dict) or any(payload.get(k) != v for k, v in {
                "status": "success", "http_status": 200, "http_method": method,
                "path": path, "name": table, "version": "v7.0.0", "build": 29,
            }.items()):
                raise ValueError("envelope unavailable")
            return payload
        except Exception:
            raise AplCreateHttpTransportError(_DENIED) from None

    def _check_claim_parent(self) -> None:
        try:
            info = self._claim_path.parent.lstat()
            if (not self._claim_path.is_absolute() or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError("private claim directory required")
        except Exception:
            raise AplCreateHttpTransportError(_DENIED) from None

    def _require_unconsumed(self) -> None:
        self._check_claim_parent()
        if os.path.lexists(self._claim_path):
            raise AplCreateHttpTransportError(_DENIED)

    def _reserve_claim(self) -> None:
        self._require_unconsumed()
        try:
            directory = os.open(self._claim_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(directory)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError("private claim directory required")
                descriptor = os.open(
                    self._claim_path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=directory,
                )
                with os.fdopen(descriptor, "w") as stream:
                    json.dump({"contract": BINDING_CONTRACT, "state": "post_attempt_reserved",
                               "baseline_digest": self._baseline,
                               "binding_digest": _digest([self._binding.rule_name,
                                                          self._binding.group_name,
                                                          self._binding.role_name])}, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            raise AplCreateHttpTransportError(_DENIED) from None


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_apl_create_http_transport(environment: Mapping[str, str]) -> FortiPamAplCreateHttpTransport:
    """Load dedicated API credentials, a private binding and persistent claim path."""
    try:
        path = Path(environment[REST_ENV_PREFIX + "BINDING_FILE"])
        if not path.is_absolute():
            raise ValueError("absolute binding required")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096):
                raise ValueError("private binding required")
            content = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        value = json.loads(content)
        if (not isinstance(value, dict)
                or set(value) != {"contract", "rule_name", "group_name", "role_name"}
                or value["contract"] != BINDING_CONTRACT):
            raise ValueError("binding contract required")
        binding = AplCreateHttpBinding(value["rule_name"], value["group_name"], value["role_name"])
        settings = {METADATA_ENV_PREFIX + "ENABLED": "true"}
        for suffix in ("BASE_URL", "API_TOKEN", "TIMEOUT_SECONDS", "CA_FILE"):
            if REST_ENV_PREFIX + suffix in environment:
                settings[METADATA_ENV_PREFIX + suffix] = environment[REST_ENV_PREFIX + suffix]
        return FortiPamAplCreateHttpTransport(
            load_secret_metadata_http_transport_config(settings), binding,
            Path(environment[REST_ENV_PREFIX + "CLAIM_FILE"]),
        )
    except Exception:
        raise AplCreateHttpTransportError(_DENIED) from None
