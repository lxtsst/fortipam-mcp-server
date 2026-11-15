"""Minimized BP014 Discovery source readback for FortiPAM 7.0 build 29.

The caller owns the fixed detail GET and protected expected name. This module
only validates its response and returns categorical state. It has no HTTP
transport, MCP registration, scan, import, or write capability.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Final, Literal


DISCOVERY_DETAIL_PATH: Final = (
    "/api/v2/cmdb/secret/discovery/{name}?format=name%7Csource-type%7C"
    "discovery-type%7Cschedule-status%7Cauto-onboarding%7Cdiscovery-method%7C"
    "discovery-secret%7Clast-discovery-time&vdom=root"
)
_NAME: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9 _-]{0,79}\Z")
_ZERO_TIME: Final = "0000-00-00 00:00:00"
_UNAVAILABLE: Final = "FortiPAM Discovery detail projection is unavailable."
_DETAIL_FIELDS: Final = frozenset({
    "name", "source-type", "discovery-type", "schedule-status",
    "auto-onboarding", "discovery-method", "discovery-secret",
    "last-discovery-time", "q_origin_key",
})
DiscoverySourceType = Literal["Active-directory", "Unix-like"]


class DiscoveryEntryProjectionError(ValueError):
    """Raised without including the source name or response contents."""


@dataclass(frozen=True, slots=True, repr=False)
class DiscoveryEntryReadback:
    """Only categorical properties needed by a disabled-scan create workflow."""

    exact_name_found: bool
    active_directory_account_source: bool
    source_type_matches_expected: bool
    periodic_scanning_disabled: bool
    auto_onboarding_disabled: bool
    existing_secret_method: bool
    discovery_secret_bound: bool
    discovery_secret_matches_expected: bool | None
    no_scan_timestamp: bool

    @property
    def disabled_source_verified(self) -> bool:
        return all((
            self.exact_name_found,
            self.source_type_matches_expected,
            self.periodic_scanning_disabled,
            self.auto_onboarding_disabled,
            self.existing_secret_method,
            self.discovery_secret_bound,
            self.no_scan_timestamp,
        ))

    @property
    def create_readback_verified(self) -> bool:
        return self.disabled_source_verified and self.discovery_secret_matches_expected is True

    def __repr__(self) -> str:
        return "<DiscoveryEntryReadback categorical>"


def project_discovery_entry_detail(
    response: Mapping[str, object], *, expected_name: str,
    expected_secret_id: int | None = None,
    expected_source_type: DiscoverySourceType = "Active-directory",
) -> DiscoveryEntryReadback:
    """Validate one exact detail response without exposing its protected fields."""

    validate_discovery_entry_name(expected_name)
    if expected_source_type not in ("Active-directory", "Unix-like"):
        raise DiscoveryEntryProjectionError(_UNAVAILABLE)
    if expected_secret_id is not None and (
        type(expected_secret_id) is not int or not 0 < expected_secret_id <= 2_147_483_647
    ):
        raise DiscoveryEntryProjectionError(_UNAVAILABLE)
    if not isinstance(response, Mapping) or any((
        response.get("status") != "success",
        response.get("http_method") != "GET",
        response.get("http_status") != 200,
        response.get("path") != "secret",
        response.get("name") != "discovery",
        response.get("vdom") != "root",
        response.get("version") != "v7.0.0",
        type(response.get("build")) is not int,
        response.get("build") != 29,
    )):
        raise DiscoveryEntryProjectionError(_UNAVAILABLE)
    rows = response.get("results")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
        raise DiscoveryEntryProjectionError(_UNAVAILABLE)
    row = rows[0]
    if set(row) != _DETAIL_FIELDS or row.get("name") != expected_name:
        raise DiscoveryEntryProjectionError(_UNAVAILABLE)
    discovery_secret = row.get("discovery-secret")
    return DiscoveryEntryReadback(
        exact_name_found=True,
        active_directory_account_source=(
            row.get("source-type") == "Active-directory"
            and row.get("discovery-type") == "account-discovery"
        ),
        source_type_matches_expected=(
            row.get("source-type") == expected_source_type
            and row.get("discovery-type") == "account-discovery"
        ),
        periodic_scanning_disabled=row.get("schedule-status") == "disable",
        auto_onboarding_disabled=row.get("auto-onboarding") == "disable",
        existing_secret_method=row.get("discovery-method") == "existing-secret",
        discovery_secret_bound=(
            isinstance(discovery_secret, int)
            and not isinstance(discovery_secret, bool)
            and discovery_secret > 0
        ),
        discovery_secret_matches_expected=(
            None if expected_secret_id is None else discovery_secret == expected_secret_id
        ),
        no_scan_timestamp=row.get("last-discovery-time") == _ZERO_TIME,
    )


def validate_discovery_entry_name(expected_name: str) -> None:
    """Reject unsafe source names before placing one in an exact detail path."""

    if not isinstance(expected_name, str) or _NAME.fullmatch(expected_name) is None:
        raise DiscoveryEntryProjectionError(_UNAVAILABLE)
