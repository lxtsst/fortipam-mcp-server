"""Fixed disabled-scan BP014 account Discovery create bodies for 7.0.

The 29 fields mirror an observed build-29 UI POST and frontend serializer. This pure contract has no
transport, MCP registration, execution Gate, scan, import, or rollback ability.
The Discovery credential is an opaque protected-runtime Secret ID; no password
or username enters this candidate body.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .discovery_entry_projection import validate_discovery_entry_name


DISCOVERY_CREATE_PATH: Final = (
    "/api/v2/cmdb/secret/discovery?with_meta=true&vdom=root"
)
_MAX_ID: Final = 2_147_483_647
_UNAVAILABLE: Final = "FortiPAM Discovery source create contract is unavailable."


class DiscoveryEntryCreateContractError(ValueError):
    """Raised without including source names or credential references."""


def _validate_input(source_name: str, discovery_secret_id: int) -> None:
    try:
        validate_discovery_entry_name(source_name)
    except ValueError:
        raise DiscoveryEntryCreateContractError(_UNAVAILABLE) from None
    if type(discovery_secret_id) is not int or not 0 < discovery_secret_id <= _MAX_ID:
        raise DiscoveryEntryCreateContractError(_UNAVAILABLE)


def _body(source_name: str, discovery_secret_id: int, source_type: str) -> dict[str, object]:
    """Return the fixed account-only, no-scan, no-onboarding field set."""

    return {
        "$originalName": source_name,
        "accprofiles": "",
        "auto-onboarding": "disable",
        "change-log": "enable",
        "discovery-method": "existing-secret",
        "discovery-password": "",
        "discovery-sch-frequency": "unknown",
        "discovery-sch-interval": 0,
        "discovery-sch-month-day": "",
        "discovery-sch-month-type": "unknown",
        "discovery-sch-start-date": "",
        "discovery-sch-week-day": "",
        "discovery-secret": discovery_secret_id,
        "discovery-type": "account-discovery",
        "discovery-username": "",
        "group-filters": "",
        "login-method": "existing-secret",
        "login-password": "",
        "login-secret": 0,
        "login-username": "",
        "name": source_name,
        "network-range": [],
        "owner": "",
        "privileged-account-only": "disable",
        "schedule": "one-shot",
        "schedule-status": "disable",
        "scheduled-time": "",
        "search-base": "",
        "source-type": source_type,
    }


@dataclass(frozen=True, slots=True, repr=False)
class DisabledAdDiscoveryCreateInput:
    """One source name and one existing protected Secret reference."""

    source_name: str
    discovery_secret_id: int

    def __post_init__(self) -> None:
        _validate_input(self.source_name, self.discovery_secret_id)

    def body(self) -> dict[str, object]:
        """Return only the observed no-scan, no-onboarding POST field set."""

        return _body(self.source_name, self.discovery_secret_id, "Active-directory")

    def __repr__(self) -> str:
        return "<DisabledAdDiscoveryCreateInput protected>"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, repr=False)
class DisabledUnixDiscoveryCreateInput:
    """One Unix account-only source using an existing visible Secret reference."""

    source_name: str
    discovery_secret_id: int

    def __post_init__(self) -> None:
        _validate_input(self.source_name, self.discovery_secret_id)

    def body(self) -> dict[str, object]:
        return _body(self.source_name, self.discovery_secret_id, "Unix-like")

    def __repr__(self) -> str:
        return "<DisabledUnixDiscoveryCreateInput protected>"

    __str__ = __repr__
