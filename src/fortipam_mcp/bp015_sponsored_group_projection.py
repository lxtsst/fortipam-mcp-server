"""Fixed, value-minimized BP015 Sponsored Group collection projection."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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


COLLECTION_PATH: Final = "/api/v2/cmdb/user/group?with_meta=true"
COLLECTION_BODY: Final[bytes] = json.dumps(
    {
        "json_filter": [
            {
                "logic": "or",
                "filters": [
                    {
                        "key": "group-type",
                        "type": "string",
                        "operator": "exact",
                        "negate": False,
                        "pattern": "sponsor",
                    }
                ],
            }
        ]
    },
    separators=(",", ":"),
).encode("utf-8")
_UNAVAILABLE: Final = "FortiPAM BP015 Sponsored Group collection inspection is unavailable."
_KNOWN_GROUP_TYPES: Final = frozenset(
    {"pam-users", "firewall", "sponsor", "fsso-service", "guest", "rsso"}
)
_PERMISSION_LEVELS: Final = frozenset({"use", "owner"})
_MAX_GROUP_RECORDS: Final = 512
_MAX_PERMISSION_RELATIONS: Final = 64
_ALLOWED_ENVELOPE_KEYS: Final = frozenset(
    {
        "action", "build", "http_method", "http_status", "matched_count", "name",
        "next_idx", "path", "results", "revision", "serial", "status", "vdom", "version",
    }
)


class BP015SponsoredGroupProjectionError(RuntimeError):
    """Stable non-disclosing failure for the fixed collection inspection."""


def load_bp015_sponsored_group_projection_config(
    environment: Mapping[str, str] | None = None,
) -> SecretMetadataHttpTransportConfig:
    """Reuse the existing protected, dedicated central API-token configuration."""

    return load_secret_metadata_http_transport_config(environment)


class FortiPamBP015SponsoredGroupProjection:
    """Read one fixed Group collection and return categorical BP015 evidence."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Any | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory

    def inspect(self) -> dict[str, object]:
        """Issue the fixed frontend-equivalent read and discard identity fields."""

        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
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
                "POST",
                COLLECTION_PATH,
                body=COLLECTION_BODY,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "Content-Type": "application/json",
                    "User-Agent": "fortipam-mcp-v4-bp015-projection/1",
                    "X-HTTP-Method-Override": "GET",
                },
            )
            response = connection.getresponse()
            if int(response.status) != 200:
                raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
            total = _read_bounded(response, content)
            content = _take_mutable_prefix(content, total)
            return _project_collection(json.loads(content))
        except BP015SponsoredGroupProjectionError:
            raise
        except (
            SecretMetadataHttpTransportError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE) from exc
        except Exception as exc:
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE) from exc
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
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
        if count == 0:
            break
        total += count
    if total > MAX_RESPONSE_BYTES:
        raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
    return total


def _project_collection(payload: object) -> dict[str, object]:
    envelope = _mapping(payload)
    if set(envelope) - _ALLOWED_ENVELOPE_KEYS:
        raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
    if (
        envelope.get("status") != "OK"
        or envelope.get("version") != "v7.0.0"
        or type(envelope.get("build")) is not int
        or envelope.get("build") != 29
        or envelope.get("http_method") != "POST"
        or envelope.get("http_status") != 200
        or envelope.get("path") != "user"
        or envelope.get("name") != "group"
    ):
        raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
    records = _records(envelope.get("results"))
    sponsor_count = 0
    permission_relation_count = 0
    for record in records:
        group_type = record.get("group-type")
        if not isinstance(group_type, str) or group_type not in _KNOWN_GROUP_TYPES:
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
        if group_type != "sponsor":
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
        sponsor_count += 1
        maximum = record.get("group-max-users")
        if type(maximum) is not int or not 1 <= maximum <= 10_000:
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
        relations = _relations(record.get("user-permission"))
        permission_relation_count += len(relations)
    categorical = {
        "sponsored_group_count_band": _count_band(sponsor_count),
        "sponsored_group_records_observed": sponsor_count > 0,
        "group_max_users_in_range": sponsor_count > 0,
        "permission_relation_count_band": _count_band(permission_relation_count),
        "permission_relations_observed": permission_relation_count > 0,
        "permission_levels_use_or_owner_only": permission_relation_count > 0,
    }
    return {
        **categorical,
        "projection_digest": _digest(categorical),
        "device_access": True,
        "device_write_executed": False,
        "source_contract_ready": False,
    }


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
    return value


def _records(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or len(value) > _MAX_GROUP_RECORDS:
        raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
    return [_mapping(record) for record in value]


def _relations(value: object) -> Sequence[Mapping[str, object]]:
    if (
        not isinstance(value, list)
        or len(value) > _MAX_PERMISSION_RELATIONS
    ):
        raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
    relations = [_mapping(relation) for relation in value]
    for relation in relations:
        if set(relation) != {"id", "permission", "user-name"}:
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
        if type(relation.get("id")) is not int or relation.get("permission") not in _PERMISSION_LEVELS:
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
        users = relation.get("user-name")
        if not isinstance(users, list) or not users or len(users) > _MAX_PERMISSION_RELATIONS:
            raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
        for user in users:
            user_record = _mapping(user)
            if set(user_record) != {"name"} or not isinstance(user_record.get("name"), str):
                raise BP015SponsoredGroupProjectionError(_UNAVAILABLE)
    return relations


def _count_band(count: int) -> str:
    if count == 0:
        return "zero"
    if count == 1:
        return "one"
    return "multiple"


def _digest(categorical: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(categorical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "BP015SponsoredGroupProjectionError",
    "COLLECTION_BODY",
    "COLLECTION_PATH",
    "FortiPamBP015SponsoredGroupProjection",
    "load_bp015_sponsored_group_projection_config",
]
