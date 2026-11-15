"""Fixed, non-disclosing BP015 Sponsor-member schema probe for FortiPAM 7.0."""

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


SCHEMA_PATH: Final = "/api/v2/cmdb/system/admin?action=schema&with_meta=true"
_UNAVAILABLE: Final = "FortiPAM BP015 Sponsor member schema inspection is unavailable."
_ALLOWED_ENVELOPE_KEYS: Final = frozenset({
    "action", "build", "http_method", "http_status", "name", "path",
    "results", "revision", "serial", "status", "vdom", "version",
})
_EXPECTED_RESULTS_KEYS: Final = frozenset({
    "access_group", "category", "children", "help", "max_table_size_global",
    "max_table_size_item", "max_table_size_vdom", "mkey", "mkey_type",
    "name", "path", "q_type",
})
_STRING_KEYS: Final = frozenset({
    "category", "default", "help", "multiple_values", "name", "size", "type",
})
_REQUIRED_DATASOURCE_STRING_KEYS: Final = _STRING_KEYS | frozenset(
    {"datasource", "required"}
)
_OPTION_KEYS: Final = frozenset({
    "category", "default", "help", "multiple_values", "name", "options", "type",
})
_OPTION_ITEM_KEYS: Final = frozenset({"help", "name"})


class BP015SponsorMemberSchemaProbeError(RuntimeError):
    """Stable non-disclosing failure for the fixed schema inspection."""


def load_bp015_sponsor_member_schema_probe_config(
    environment: Mapping[str, str] | None = None,
) -> SecretMetadataHttpTransportConfig:
    """Reuse the existing protected, dedicated central API-token configuration."""

    return load_secret_metadata_http_transport_config(environment)


class FortiPamBP015SponsorMemberSchemaProbe:
    """Read exactly the Sponsor-member schema route and project safe facts only."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Any | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory

    def inspect(self) -> dict[str, object]:
        """Issue one fixed strict-TLS GET and return categorical compatibility facts."""

        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
        connection: Any = None
        response: Any = None
        content = bytearray(MAX_RESPONSE_BYTES + 1)
        try:
            factory = self._connection_factory or http.client.HTTPSConnection
            connection = factory(
                parsed.hostname, parsed.port or 443,
                timeout=self._config.timeout_seconds, context=_ssl_context(self._config),
            )
            connection.request(
                "GET", SCHEMA_PATH,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "User-Agent": "fortipam-mcp-v4-bp015-member-schema-probe/1",
                },
            )
            response = connection.getresponse()
            if int(response.status) != 200:
                raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
            total = _read_bounded(response, content)
            content = _take_mutable_prefix(content, total)
            return _project_schema(json.loads(content))
        except BP015SponsorMemberSchemaProbeError:
            raise
        except (
            SecretMetadataHttpTransportError, UnicodeDecodeError, json.JSONDecodeError,
            TypeError, ValueError,
        ) as exc:
            raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE) from exc
        except Exception as exc:
            raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE) from exc
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
            raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
        if count == 0:
            break
        total += count
    if total > MAX_RESPONSE_BYTES:
        raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
    return total


def _project_schema(payload: object) -> dict[str, object]:
    envelope = _mapping(payload)
    if set(envelope) - _ALLOWED_ENVELOPE_KEYS:
        raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
    if (
        envelope.get("status") != "success"
        or envelope.get("version") != "v7.0.0"
        or type(envelope.get("build")) is not int
        or envelope.get("build") != 29
        or envelope.get("http_method") != "GET"
        or envelope.get("http_status") != 200
        or envelope.get("action") != "schema"
        or envelope.get("path") != "system"
        or envelope.get("name") != "admin"
    ):
        raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
    results = _mapping(envelope.get("results"))
    _require_exact_keys(results, _EXPECTED_RESULTS_KEYS)
    fields = _mapping(results.get("children"))
    name = _field(fields, "name")
    accprofile = _field(fields, "accprofile")
    schedule = _field(fields, "schedule")
    sponsor_group = _field(fields, "sponsor-group")
    status = _field(fields, "status")
    remote_auth = _field(fields, "remote-auth")
    _require_exact_keys(name, _STRING_KEYS)
    _require_exact_keys(accprofile, _REQUIRED_DATASOURCE_STRING_KEYS)
    for field in (schedule, sponsor_group):
        _require_exact_keys(field, _STRING_KEYS)
    for field in (status, remote_auth):
        _require_exact_keys(field, _OPTION_KEYS)
    _require_string(name, "name", default="")
    _require_string(
        accprofile, "accprofile", default="pam_standard_user", required=True
    )
    _require_string(schedule, "schedule", default="")
    _require_string(sponsor_group, "sponsor-group", default="")
    _require_options(status, "status", default="enable", expected=frozenset({"enable", "disable"}))
    _require_options(remote_auth, "remote-auth", default="disable", expected=frozenset({"enable", "disable"}))
    normalized = {
        "name": {"type": "string", "default": ""},
        "accprofile": {"type": "string", "default": "pam_standard_user", "required": True},
        "schedule": {"type": "string", "default": ""},
        "sponsor-group": {"type": "string", "default": ""},
        "status": {"type": "option", "default": "enable", "options": ["disable", "enable"]},
        "remote-auth": {"type": "option", "default": "disable", "options": ["disable", "enable"]},
    }
    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "version_build_is_7_0_0_build_29": True,
        "name_schema_defined": True,
        "accprofile_schema_defined": True,
        "schedule_schema_defined": True,
        "sponsor_group_schema_defined": True,
        "status_schema_defined": True,
        "remote_auth_schema_defined": True,
        "member_schema_frontend_compatible": True,
        "schema_digest": digest,
        "member_relation_contract_ready": False,
        "device_write_executed": False,
    }


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
    return value


def _field(fields: Mapping[str, object], field_name: str) -> Mapping[str, object]:
    return _mapping(fields.get(field_name))


def _require_string(
    field: Mapping[str, object],
    field_name: str,
    *,
    default: str,
    required: bool | None = None,
) -> None:
    if (
        field.get("name") != field_name
        or field.get("type") != "string"
        or field.get("default") != default
        or (required is not None and field.get("required") is not required)
    ):
        raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)


def _require_options(
    field: Mapping[str, object], field_name: str, *, default: str, expected: frozenset[str],
) -> None:
    options = field.get("options")
    if (
        field.get("name") != field_name
        or field.get("type") != "option"
        or field.get("default") != default
        or not isinstance(options, list)
        or len(options) != len(expected)
    ):
        raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
    names: list[str] = []
    for option in options:
        option_mapping = _mapping(option)
        _require_exact_keys(option_mapping, _OPTION_ITEM_KEYS)
        option_name = option_mapping.get("name")
        if not isinstance(option_name, str):
            raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)
        names.append(option_name)
    if len(names) != len(set(names)) or frozenset(names) != expected:
        raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)


def _require_exact_keys(value: Mapping[str, object], expected: frozenset[str]) -> None:
    if set(value) != expected:
        raise BP015SponsorMemberSchemaProbeError(_UNAVAILABLE)


__all__ = [
    "BP015SponsorMemberSchemaProbeError",
    "FortiPamBP015SponsorMemberSchemaProbe",
    "SCHEMA_PATH",
    "load_bp015_sponsor_member_schema_probe_config",
]
