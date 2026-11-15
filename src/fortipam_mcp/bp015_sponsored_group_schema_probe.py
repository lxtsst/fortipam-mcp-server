"""Fixed, non-disclosing BP015 Sponsored Group schema probe for FortiPAM 7.0."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import http.client
import json
from typing import Any, Final
from urllib.parse import urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
    SecretMetadataHttpTransportError,
    _ssl_context,
    _zeroize_mutable,
    load_secret_metadata_http_transport_config,
)


SCHEMA_PATH: Final = "/api/v2/cmdb/user/group?action=schema"
_UNAVAILABLE: Final = "FortiPAM BP015 Sponsored Group schema inspection is unavailable."
_EXPECTED_GROUP_TYPES: Final = frozenset(
    {"pam-users", "firewall", "sponsor", "fsso-service", "guest", "rsso"}
)
_ALLOWED_ENVELOPE_KEYS: Final = frozenset(
    {
        "action", "build", "http_method", "http_status", "name", "path",
        "results", "revision", "serial", "status", "vdom", "version",
    }
)
_EXPECTED_RESULTS_KEYS: Final = frozenset(
    {
        "access_group", "category", "children", "help", "max_table_size_global",
        "max_table_size_item", "max_table_size_vdom", "mkey", "mkey_type",
        "name", "path", "q_type",
    }
)
_EXPECTED_GROUP_TYPE_KEYS: Final = frozenset(
    {"category", "default", "help", "multiple_values", "name", "options", "type"}
)
_EXPECTED_GROUP_MAX_KEYS: Final = frozenset(
    {
        "category", "default", "help", "max-value", "min-value",
        "multiple_values", "name", "type",
    }
)
_EXPECTED_USER_PERMISSION_KEYS: Final = frozenset(
    {
        "category", "children", "help", "max_table_size_global",
        "max_table_size_item", "max_table_size_vdom", "mkey", "mkey_type", "name",
    }
)
_EXPECTED_INTEGER_KEYS: Final = _EXPECTED_GROUP_MAX_KEYS
_EXPECTED_PERMISSION_KEYS: Final = _EXPECTED_GROUP_TYPE_KEYS
_EXPECTED_USER_NAME_KEYS: Final = frozenset(
    {
        "category", "children", "help", "max_table_size_global",
        "max_table_size_item", "max_table_size_vdom", "member_table", "mkey",
        "mkey_type", "name", "required",
    }
)
_EXPECTED_USER_NAME_VALUE_KEYS: Final = frozenset(
    {
        "category", "datasource", "default", "help", "multiple_values", "name",
        "required", "size", "type",
    }
)


class BP015SponsoredGroupSchemaProbeError(RuntimeError):
    """Stable non-disclosing failure for the fixed schema inspection."""


def load_bp015_sponsored_group_schema_probe_config(
    environment: Mapping[str, str] | None = None,
) -> SecretMetadataHttpTransportConfig:
    """Reuse the existing protected, dedicated central API-token configuration."""

    return load_secret_metadata_http_transport_config(environment)


class FortiPamBP015SponsoredGroupSchemaProbe:
    """Read exactly one Group schema route and return categorical evidence only."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Any | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory

    def inspect(self) -> dict[str, object]:
        """Issue the fixed strict-TLS GET and project only schema compatibility facts."""

        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
        connection: Any = None
        response: Any = None
        content = bytearray(MAX_RESPONSE_BYTES + 1)
        try:
            factory = self._connection_factory or http.client.HTTPSConnection
            connection = factory(
                parsed.hostname,
                parsed.port or 443,
                timeout=self._config.timeout_seconds,
                context=_ssl_context(self._config),
            )
            connection.request(
                "GET",
                SCHEMA_PATH,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "User-Agent": "fortipam-mcp-v4-bp015-schema-probe/1",
                },
            )
            response = connection.getresponse()
            if int(response.status) != 200:
                raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
            total = _read_bounded(response, content)
            content = _take_mutable_prefix(content, total)
            payload = json.loads(content)
            return _project_schema(payload)
        except BP015SponsoredGroupSchemaProbeError:
            raise
        except (
            SecretMetadataHttpTransportError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE) from exc
        except Exception as exc:
            raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE) from exc
        finally:
            _zeroize_mutable(content)
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def _read_bounded(response: Any, content: bytearray) -> int:
    total = 0
    while total < len(content):
        view = memoryview(content)[total:]
        try:
            count = response.readinto(view)
        finally:
            view.release()
        if not isinstance(count, int) or count < 0:
            raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
        if count == 0:
            break
        total += count
    if total > MAX_RESPONSE_BYTES:
        raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
    return total


def _project_schema(payload: object) -> dict[str, object]:
    envelope = _mapping(payload)
    if set(envelope) - _ALLOWED_ENVELOPE_KEYS:
        raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
    if (
        envelope.get("status") != "success"
        or envelope.get("version") != "v7.0.0"
        or type(envelope.get("build")) is not int
        or envelope.get("build") != 29
        or envelope.get("http_method") != "GET"
        or envelope.get("http_status") != 200
        or envelope.get("action") != "schema"
        or envelope.get("path") != "user"
        or envelope.get("name") != "group"
    ):
        raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
    results = _mapping(envelope.get("results"))
    _require_exact_keys(results, _EXPECTED_RESULTS_KEYS)
    fields = _mapping(results.get("children"))
    group_type = _field(fields, "group-type")
    group_max_users = _field(fields, "group-max-users")
    user_permission = _field(fields, "user-permission")
    _require_exact_keys(group_type, _EXPECTED_GROUP_TYPE_KEYS)
    _require_exact_keys(group_max_users, _EXPECTED_GROUP_MAX_KEYS)
    _require_exact_keys(user_permission, _EXPECTED_USER_PERMISSION_KEYS)
    group_types = _normalized_options(group_type, _EXPECTED_GROUP_TYPES)
    if (
        group_max_users.get("type") != "integer"
        or type(group_max_users.get("min-value")) is not int
        or group_max_users.get("min-value") != 1
        or type(group_max_users.get("max-value")) is not int
        or group_max_users.get("max-value") != 10_000
    ):
        raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
    permission_shape = _normalized_user_permission(user_permission)
    normalized = {
        "group-type": {"type": "option", "options": group_types},
        "group-max-users": {"type": "integer", "min": 1, "max": 10_000},
        "user-permission": permission_shape,
    }
    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "version_build_is_7_0_0_build_29": True,
        "group_type_schema_defined": True,
        "group_max_users_schema_defined": True,
        "user_permission_schema_defined": True,
        "group_type_frontend_compatible": True,
        "group_max_users_frontend_compatible": True,
        "user_permission_frontend_compatible": True,
        "schema_digest": digest,
        "device_write_executed": False,
    }


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
    return value


def _field(fields: Mapping[str, object], name: str) -> Mapping[str, object]:
    return _mapping(fields.get(name))


def _normalized_options(
    field: Mapping[str, object], expected_options: frozenset[str]
) -> list[str]:
    options = field.get("options")
    if (
        field.get("type") != "option"
        or not isinstance(options, list)
        or len(options) != len(expected_options)
    ):
        raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
    names: list[str] = []
    for option in options:
        option_mapping = _mapping(option)
        _require_exact_keys(option_mapping, frozenset({"help", "name"}))
        name = option_mapping.get("name")
        if not isinstance(name, str):
            raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
        names.append(name)
    if len(names) != len(set(names)) or frozenset(names) != expected_options:
        raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
    return sorted(names)


def _normalized_user_permission(field: Mapping[str, object]) -> dict[str, object]:
    children = _mapping(field.get("children"))
    _require_exact_keys(children, frozenset({"id", "permission", "user-name"}))
    identifier = _mapping(children.get("id"))
    permission = _mapping(children.get("permission"))
    user_names = _mapping(children.get("user-name"))
    _require_exact_keys(identifier, _EXPECTED_INTEGER_KEYS)
    _require_exact_keys(permission, _EXPECTED_PERMISSION_KEYS)
    _require_exact_keys(user_names, _EXPECTED_USER_NAME_KEYS)
    if identifier.get("type") != "integer":
        raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
    permission_options = _normalized_options(permission, frozenset({"owner", "use"}))
    user_name_children = _mapping(user_names.get("children"))
    _require_exact_keys(user_name_children, frozenset({"name"}))
    user_name = _mapping(user_name_children.get("name"))
    _require_exact_keys(user_name, _EXPECTED_USER_NAME_VALUE_KEYS)
    if user_name.get("type") != "string":
        raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)
    return {
        "children": {
            "id": "integer",
            "permission": {"type": "option", "options": permission_options},
            "user-name": {"children": {"name": "string"}},
        }
    }


def _require_exact_keys(value: Mapping[str, object], expected: frozenset[str]) -> None:
    if set(value) != expected:
        raise BP015SponsoredGroupSchemaProbeError(_UNAVAILABLE)


__all__ = [
    "BP015SponsoredGroupSchemaProbeError",
    "FortiPamBP015SponsoredGroupSchemaProbe",
    "SCHEMA_PATH",
    "load_bp015_sponsored_group_schema_probe_config",
]
