"""Fixed, non-disclosing BP015 Sponsor-member no-match contract probe."""

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


MEMBER_READ_PATH: Final = "/api/v2/cmdb/system/admin?with_meta=true"
MEMBER_READ_BODY: Final[bytes] = json.dumps(
    {
        "json_filter": [
            {
                "logic": "and",
                "filters": [
                    {
                        "key": "name",
                        "type": "string",
                        "operator": "exact",
                        "pattern": "invitation_guest",
                        "negate": True,
                    }
                ],
            },
            {
                "logic": "or",
                "filters": [
                    {
                        "key": "sponsor-group",
                        "type": "string",
                        "operator": "exact",
                        "pattern": "mcp-v4-bp015-contract-probe-nonexistent",
                        "negate": False,
                    }
                ],
            },
            {
                "logic": "or",
                "filters": [
                    {
                        "key": "name",
                        "type": "string",
                        "operator": "exact",
                        "pattern": "invitation_guests",
                        "negate": True,
                    }
                ],
            },
        ]
    },
    separators=(",", ":"),
).encode("utf-8")
_UNAVAILABLE: Final = "FortiPAM BP015 Sponsor member read inspection is unavailable."
_ALLOWED_ENVELOPE_KEYS: Final = frozenset(
    {
        "action", "build", "http_method", "http_status", "matched_count", "name",
        "next_idx", "path", "results", "revision", "serial", "size", "status", "vdom",
        "version",
    }
)


class BP015SponsorMemberReadProbeError(RuntimeError):
    """Stable non-disclosing failure for the fixed no-match inspection."""


def load_bp015_sponsor_member_read_probe_config(
    environment: Mapping[str, str] | None = None,
) -> SecretMetadataHttpTransportConfig:
    """Reuse the existing protected, dedicated central API-token configuration."""

    return load_secret_metadata_http_transport_config(environment)


class FortiPamBP015SponsorMemberReadProbe:
    """Read one fixed Sponsor-member no-match route and return safe evidence only."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Any | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise BP015SponsorMemberReadProbeError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory

    def inspect(self) -> dict[str, object]:
        """Issue the fixed frontend-equivalent strict-TLS no-match read."""

        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise BP015SponsorMemberReadProbeError(_UNAVAILABLE)
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
                MEMBER_READ_PATH,
                body=MEMBER_READ_BODY,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "Content-Type": "application/json",
                    "User-Agent": "fortipam-mcp-v4-bp015-member-read-probe/1",
                    "X-HTTP-Method-Override": "GET",
                },
            )
            response = connection.getresponse()
            if int(response.status) != 200:
                raise BP015SponsorMemberReadProbeError(_UNAVAILABLE)
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise BP015SponsorMemberReadProbeError(_UNAVAILABLE)
            total = _read_bounded(response, content)
            content = _take_mutable_prefix(content, total)
            return _project_no_match(json.loads(content))
        except BP015SponsorMemberReadProbeError:
            raise
        except (
            SecretMetadataHttpTransportError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise BP015SponsorMemberReadProbeError(_UNAVAILABLE) from exc
        except Exception as exc:
            raise BP015SponsorMemberReadProbeError(_UNAVAILABLE) from exc
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
            raise BP015SponsorMemberReadProbeError(_UNAVAILABLE)
        if count == 0:
            break
        total += count
    if total > MAX_RESPONSE_BYTES:
        raise BP015SponsorMemberReadProbeError(_UNAVAILABLE)
    return total


def _project_no_match(payload: object) -> dict[str, object]:
    envelope = _mapping(payload)
    if set(envelope) - _ALLOWED_ENVELOPE_KEYS:
        raise BP015SponsorMemberReadProbeError(_UNAVAILABLE)
    if (
        envelope.get("status") != "success"
        or envelope.get("version") != "v7.0.0"
        or type(envelope.get("build")) is not int
        or envelope.get("build") != 29
        or envelope.get("http_method") != "POST"
        or envelope.get("http_status") != 200
        or envelope.get("path") != "system"
        or envelope.get("name") != "admin"
        or envelope.get("results") != []
        or envelope.get("matched_count") != 0
        or envelope.get("next_idx") != 0
        or not _bounded_size(envelope.get("size"))
    ):
        raise BP015SponsorMemberReadProbeError(_UNAVAILABLE)
    categorical = {
        "route_contract_accepted": True,
        "filter_contract_accepted": True,
        "device_response_accepted": True,
        "member_relation_count_band": "zero",
    }
    return {
        **categorical,
        "member_relation_read_digest": _digest(categorical),
        "member_relation_contract_ready": False,
        "device_write_executed": False,
    }


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise BP015SponsorMemberReadProbeError(_UNAVAILABLE)
    return value


def _bounded_size(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 100_000
    )


def _digest(categorical: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(categorical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "BP015SponsorMemberReadProbeError",
    "FortiPamBP015SponsorMemberReadProbe",
    "MEMBER_READ_BODY",
    "MEMBER_READ_PATH",
    "load_bp015_sponsor_member_read_probe_config",
]
