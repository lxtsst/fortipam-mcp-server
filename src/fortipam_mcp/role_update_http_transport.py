"""Fixed build-29 REST inspection, diagnostics enable and explicit readback."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any
from urllib.parse import quote, urlsplit

from .role_create_ssh_transport import RoleUpdateInspection, RoleUpdateReadback


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_"
ROLE_COLLECTION_PATH = "/api/v2/cmdb/system/accprofile"
_MAX_RESPONSE_BYTES = 1_048_576
_DENIED_MESSAGE = "FortiPAM V4 Role update REST transport is unavailable."
_ROLE_NAME = re.compile(r"mcp-v4-role-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_ROLE_FIELDS = (
    "name", "secfabgrp", "ftviewgrp", "authgrp", "secretgrp",
    "secretgrp-permission", "cli", "sysgrp", "sysgrp-permission",
    "system-diagnostics",
)
_SECRET_PERMISSIONS = {
    "launcher": "read", "pwd-changer": "read", "template": "read-write",
    "secret-policy": "read", "request": "read-write",
    "folder-table": "read-write", "secret-table": "read-write",
    "create-personal-folder": "read-write",
}
_MAX_ASSIGNMENTS = 200


class RoleUpdateHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated Role-update REST settings are unsafe."""


class RoleUpdateHttpTransportError(RuntimeError):
    """Raised for a bounded Role-update REST transport failure."""


@dataclass(frozen=True, slots=True)
class RoleUpdateHttpTransportConfig:
    """Dedicated HTTPS and bearer settings retained only in process memory."""

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
            raise RoleUpdateHttpTransportConfigurationError(
                "A dedicated HTTPS Role update API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise RoleUpdateHttpTransportConfigurationError(
                "A dedicated Role update bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise RoleUpdateHttpTransportConfigurationError(
                "The Role update API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise RoleUpdateHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


def load_role_update_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> RoleUpdateHttpTransportConfig:
    """Load the independently scoped Role-update API binding."""

    env = os.environ if environment is None else environment
    if _value(env, "API_ENABLED") != "true":
        raise RoleUpdateHttpTransportConfigurationError(
            f"{ENV_PREFIX}API_ENABLED must be exactly true."
        )
    base_url = _value(env, "API_BASE_URL") or _value(env, "API_HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "API_TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "API_CA_FILE")
    if base_url is None or token is None:
        raise RoleUpdateHttpTransportConfigurationError(
            "Dedicated Role update API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise RoleUpdateHttpTransportConfigurationError(
            "The Role update API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return RoleUpdateHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamRoleUpdateHttpTransport:
    """Read fixed projections and send only one field-only Role PUT."""

    def __init__(
        self,
        config: RoleUpdateHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect_update(self, role_name: str) -> RoleUpdateInspection:
        """Require explicit switches, dependencies and a complete assignment read."""

        record, assigned = self._read_update_state(role_name)
        core, permissions = _permissions_match(record)
        return RoleUpdateInspection(
            role_exists=True,
            core_access_matches=core,
            secret_permissions_match=permissions,
            system_diagnostics_disabled=record["system-diagnostics"] == "disable",
            role_assigned=assigned,
        )

    def enable_diagnostics_and_readback(self, role_name: str) -> RoleUpdateReadback:
        """Read an explicit enabled value after the fixed PUT; never invert unknown."""

        self.enable_diagnostics(role_name)
        record, assigned = self._read_update_state(role_name)
        core, permissions = _permissions_match(record)
        return RoleUpdateReadback(
            role_exists=True,
            core_access_matches=core,
            secret_permissions_match=permissions,
            system_diagnostics_enabled=record["system-diagnostics"] == "enable",
            role_assigned=assigned,
        )

    def _read_update_state(
        self, role_name: str,
    ) -> tuple[Mapping[str, Any], bool]:
        name = _role_name(role_name)
        projection = quote("|".join(_ROLE_FIELDS), safe="")
        status, payload = self._request(
            "GET", f"{ROLE_COLLECTION_PATH}/{quote(name, safe='')}?format={projection}",
            None,
        )
        rows = _read_records(status, payload, "accprofile")
        if len(rows) != 1:
            raise RoleUpdateHttpTransportError(_DENIED_MESSAGE)
        record = rows[0]
        if (
            record.get("name") != name
            or not all(field in record for field in _ROLE_FIELDS)
            or not isinstance(record.get("system-diagnostics"), str)
            or record.get("system-diagnostics") not in {"enable", "disable"}
            or not isinstance(record.get("cli"), str)
            or record.get("cli") not in {"enable", "disable"}
        ):
            raise RoleUpdateHttpTransportError(_DENIED_MESSAGE)
        status, payload = self._request(
            "GET", "/api/v2/cmdb/system/admin?format=accprofile"
            f"&count={_MAX_ASSIGNMENTS}&start=0&with_meta=true", None,
        )
        assignments = _read_records(status, payload, "admin")
        if (
            not isinstance(payload, Mapping)
            or len(assignments) >= _MAX_ASSIGNMENTS
            or type(payload.get("size")) is not int
            or payload["size"] != len(assignments)
            or type(payload.get("matched_count")) is not int
            or payload["matched_count"] != len(assignments)
            or not all(isinstance(row.get("accprofile"), str) for row in assignments)
        ):
            raise RoleUpdateHttpTransportError(_DENIED_MESSAGE)
        return record, any(row["accprofile"] == name for row in assignments)

    def enable_diagnostics(self, role_name: str) -> None:
        """Issue the minimal field-only PUT and reject any unverified response."""

        role_name = _role_name(role_name)
        status, payload = self._request(
            "PUT",
            f"{ROLE_COLLECTION_PATH}/{quote(role_name, safe='')}",
            {"system-diagnostics": "enable"},
        )
        if status != 200 or not _successful_write_response(payload):
            raise RoleUpdateHttpTransportError(_DENIED_MESSAGE)

    def _request(
        self,
        method: str,
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
            raise RoleUpdateHttpTransportError(_DENIED_MESSAGE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > _MAX_RESPONSE_BYTES:
            raise RoleUpdateHttpTransportError(_DENIED_MESSAGE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RoleUpdateHttpTransportError(_DENIED_MESSAGE) from exc


def _successful_write_response(payload: object) -> bool:
    if not isinstance(payload, Mapping):
        return False
    http_status = payload.get("http_status")
    error = payload.get("error", 0)
    return (
        type(http_status) is int
        and http_status == 200
        and payload.get("status") == "success"
        and type(error) is int
        and error == 0
    )


def _read_records(status: int, payload: object, name: str) -> list[Mapping[str, Any]]:
    if (
        status != 200
        or not isinstance(payload, Mapping)
        or not _successful_write_response(payload)
        or payload.get("http_method") != "GET"
        or payload.get("path") != "system"
        or payload.get("name") != name
        or payload.get("version") != "v7.0.0"
        or type(payload.get("build")) is not int
        or payload["build"] != 29
    ):
        raise RoleUpdateHttpTransportError(_DENIED_MESSAGE)
    rows = payload.get("results")
    if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
        raise RoleUpdateHttpTransportError(_DENIED_MESSAGE)
    return rows


def _permissions_match(record: Mapping[str, Any]) -> tuple[bool, bool]:
    system = record.get("sysgrp-permission")
    admin_write = record.get("sysgrp") == "read-write" or (
        record.get("sysgrp") == "custom"
        and isinstance(system, Mapping) and system.get("admin") == "read-write"
    )
    core = (
        all(record.get(field) == "read" for field in ("secfabgrp", "ftviewgrp", "authgrp"))
        and record.get("secretgrp") == "custom"
        and record.get("cli") == "enable" and admin_write
    )
    secret = record.get("secretgrp-permission")
    permissions = isinstance(secret, Mapping) and all(
        secret.get(field) == value for field, value in _SECRET_PERMISSIONS.items()
    )
    return core, permissions


def _role_name(value: str) -> str:
    if not isinstance(value, str) or _ROLE_NAME.fullmatch(value) is None:
        raise RoleUpdateHttpTransportError(_DENIED_MESSAGE)
    return value


def _ssl_context(config: RoleUpdateHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:
        raise RoleUpdateHttpTransportError(_DENIED_MESSAGE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


__all__ = [
    "FortiPamRoleUpdateHttpTransport",
    "RoleUpdateHttpTransportConfig",
    "RoleUpdateHttpTransportConfigurationError",
    "RoleUpdateHttpTransportError",
    "load_role_update_http_transport_config",
]
