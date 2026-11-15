"""Fixed, read-only BP014 Discovery source detail transport.

The FortiPAM ``format`` query limits the record to the categorical fields
needed for a disabled-scan source readback. No source list, scan, import, or
mutation route is exposed here.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
from urllib.parse import quote

import httpx

from .discovery_entry_projection import (
    DISCOVERY_DETAIL_PATH,
    DiscoveryEntryProjectionError,
    DiscoveryEntryReadback,
    DiscoverySourceType,
    project_discovery_entry_detail,
    validate_discovery_entry_name,
)
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
    _ssl_context,
    _zeroize_mutable,
)


_MAX_DETAIL_BYTES = 65_536
_UNAVAILABLE = "FortiPAM Discovery detail read is unavailable."


class DiscoveryEntryHttpTransportError(RuntimeError):
    """Stable error that cannot include protected response content."""


def read_discovery_entry_detail(
    config: SecretMetadataHttpTransportConfig, *, expected_name: str,
    expected_secret_id: int | None = None,
    expected_source_type: DiscoverySourceType = "Active-directory",
) -> DiscoveryEntryReadback:
    """Read exactly one source by protected name and return minimized state."""

    result = inspect_discovery_entry_detail(
        config, expected_name=expected_name, expected_secret_id=expected_secret_id,
        expected_source_type=expected_source_type,
    )
    if result is None:
        raise DiscoveryEntryHttpTransportError(_UNAVAILABLE)
    return result


def inspect_discovery_entry_detail(
    config: SecretMetadataHttpTransportConfig, *, expected_name: str,
    expected_secret_id: int | None = None,
    expected_source_type: DiscoverySourceType = "Active-directory",
) -> DiscoveryEntryReadback | None:
    """Classify one exact source as visible or returning the fixed 404 envelope."""

    if not isinstance(config, SecretMetadataHttpTransportConfig):
        raise DiscoveryEntryHttpTransportError(_UNAVAILABLE)
    # The projector validates the exact name before it can enter a URL.
    try:
        validate_discovery_entry_name(expected_name)
        if expected_source_type not in ("Active-directory", "Unix-like"):
            raise DiscoveryEntryProjectionError(_UNAVAILABLE)
        if expected_secret_id is not None and (
            type(expected_secret_id) is not int
            or not 0 < expected_secret_id <= 2_147_483_647
        ):
            raise DiscoveryEntryProjectionError(_UNAVAILABLE)
    except DiscoveryEntryProjectionError:
        raise DiscoveryEntryHttpTransportError(_UNAVAILABLE) from None
    status, body = _get_detail(config, expected_name)
    if status == 404:
        if not isinstance(body, Mapping) or any((
            body.get("status") != "error",
            body.get("http_method") != "GET",
            body.get("http_status") != 404,
            body.get("path") != "secret",
            body.get("name") != "discovery",
            body.get("vdom") != "root",
            body.get("version") != "v7.0.0",
            type(body.get("build")) is not int,
            body.get("build") != 29,
            body.get("results") is not None and body.get("results") != [],
        )):
            raise DiscoveryEntryHttpTransportError(_UNAVAILABLE)
        return None
    if status != 200 or not isinstance(body, Mapping):
        raise DiscoveryEntryHttpTransportError(_UNAVAILABLE)
    try:
        return project_discovery_entry_detail(
            body, expected_name=expected_name, expected_secret_id=expected_secret_id,
            expected_source_type=expected_source_type,
        )
    except (ValueError, TypeError):
        raise DiscoveryEntryHttpTransportError(_UNAVAILABLE) from None


def _get_detail(
    config: SecretMetadataHttpTransportConfig, expected_name: str
) -> tuple[int, object]:
    path = DISCOVERY_DETAIL_PATH.format(name=quote(expected_name, safe=""))
    payload = bytearray()
    try:
        with httpx.Client(
            base_url=config.base_url,
            verify=_ssl_context(config),
            timeout=config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            with client.stream(
                "GET",
                path,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Authorization": f"Bearer {config.bearer_token}",
                    "Cache-Control": "no-cache, no-store",
                },
            ) as response:
                if response.status_code not in {200, 404} or "json" not in response.headers.get(
                    "content-type", ""
                ).lower():
                    raise DiscoveryEntryHttpTransportError(_UNAVAILABLE)
                for chunk in response.iter_bytes():
                    if len(payload) + len(chunk) > _MAX_DETAIL_BYTES:
                        raise DiscoveryEntryHttpTransportError(_UNAVAILABLE)
                    payload.extend(chunk)
                status = response.status_code
        return status, json.loads(payload)
    except (httpx.HTTPError, OSError, ValueError, TypeError):
        raise DiscoveryEntryHttpTransportError(_UNAVAILABLE) from None
    finally:
        _zeroize_mutable(payload)
