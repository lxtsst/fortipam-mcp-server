"""Offline-only BP015 Sponsored Group create contract for FortiPAM 7.0.

This module validates a complete, caller-supplied build-29 ``action=default``
fixture and compiles the one minimized Sponsored Group candidate body.  It has
no transport, MCP registration, execution Gate, credential handling, or device
write capability.  Default values are checked only long enough to establish
the shape; values that can identify an account or carry credentials are never
retained in evidence or emitted in the candidate body.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Final, Literal


CREATE_METHOD: Final[Literal["POST"]] = "POST"
CREATE_PATH: Final = "/api/v2/cmdb/user/group"
DEFAULT_METHOD: Final[Literal["GET"]] = "GET"
DEFAULT_QUERY: Final = "action=default&with_meta=true"
SCHEMA_REF: Final = "fortipam-7.0.0-build29-bp015-sponsored-group-create-candidate-v1"
FORTIPAM_VERSION: Final[Literal["7.0.0"]] = "7.0.0"
FORTIPAM_BUILD: Final[Literal[29]] = 29

_ENVELOPE_KEYS: Final = frozenset(
    {
        "action",
        "build",
        "http_method",
        "http_status",
        "name",
        "path",
        "results",
        "revision",
        "serial",
        "status",
        "vdom",
        "version",
    }
)
# Kept independent from ``bp015_sponsored_group_default_probe`` intentionally:
# this candidate contract must remain a pure fixture boundary.
_EXPECTED_RESULTS_KEYS: Final = frozenset(
    {
        "access",
        "auth-concurrent-override",
        "auth-concurrent-value",
        "authtimeout",
        "company",
        "creation-time",
        "email",
        "expire",
        "expire-type",
        "group-max-users",
        "group-type",
        "guest",
        "http-digest-realm",
        "id",
        "logic-type",
        "match",
        "max-accounts",
        "member",
        "mobile-phone",
        "multiple-guest-add",
        "name",
        "password",
        "sms-custom-server",
        "sms-server",
        "sponsor",
        "sso-attribute-value",
        "user-id",
        "user-name",
        "user-permission",
    }
)
_INTEGER_RESULT_FIELDS: Final = frozenset(
    {
        "auth-concurrent-value",
        "authtimeout",
        "expire",
        "group-max-users",
        "id",
        "max-accounts",
    }
)
_ENUM_RESULT_FIELDS: Final = frozenset(
    {
        "access",
        "auth-concurrent-override",
        "expire-type",
        "group-type",
        "logic-type",
        "multiple-guest-add",
    }
)
_LIST_RESULT_FIELDS: Final = frozenset(
    {"guest", "match", "member", "user-permission"}
)
_TEXT_RESULT_FIELDS: Final = frozenset(
    {
        "company",
        "creation-time",
        "email",
        "http-digest-realm",
        "mobile-phone",
        "name",
        "password",
        "sms-custom-server",
        "sms-server",
        "sponsor",
        "sso-attribute-value",
        "user-id",
        "user-name",
    }
)
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_MAX_INT32: Final = 2_147_483_647


class SponsoredGroupCreateContractError(ValueError):
    """Raised when BP015 candidate evidence or input is outside this contract."""


@dataclass(frozen=True, slots=True)
class SponsoredGroupDefaultEvidence:
    """Value-minimized proof of the accepted build-29 default fixture."""

    schema_ref: str = SCHEMA_REF
    fortipam_version: Literal["7.0.0"] = FORTIPAM_VERSION
    fortipam_build: Literal[29] = FORTIPAM_BUILD
    create_path: str = CREATE_PATH
    create_method: Literal["POST"] = CREATE_METHOD
    bounded_default_shape: Literal[True] = True
    raw_values_returned: Literal[False] = False
    create_contract_ready: Literal[False] = False

    def __post_init__(self) -> None:
        if (
            self.schema_ref != SCHEMA_REF
            or self.fortipam_version != FORTIPAM_VERSION
            or self.fortipam_build != FORTIPAM_BUILD
            or self.create_path != CREATE_PATH
            or self.create_method != CREATE_METHOD
            or self.bounded_default_shape is not True
            or self.raw_values_returned is not False
            or self.create_contract_ready is not False
        ):
            raise SponsoredGroupCreateContractError(
                "Sponsored Group default evidence is unsupported."
            )


@dataclass(frozen=True, slots=True, repr=False)
class SponsoredGroupCreateInput:
    """Protected input for one minimized, non-dispatchable Group candidate."""

    group_name: str
    owner_name: str
    maximum_members: int

    def __post_init__(self) -> None:
        _identifier(self.group_name, "group_name")
        _identifier(self.owner_name, "owner_name")
        if type(self.maximum_members) is not int or not 1 <= self.maximum_members <= 10_000:
            raise SponsoredGroupCreateContractError(
                "maximum_members must be an integer from 1 through 10000."
            )

    def body(self, evidence: SponsoredGroupDefaultEvidence) -> dict[str, object]:
        """Compile only the exact, minimized frontend-shaped candidate body."""

        if type(evidence) is not SponsoredGroupDefaultEvidence:
            raise SponsoredGroupCreateContractError(
                "Exact Sponsored Group default evidence is required."
            )
        return {
            "name": self.group_name,
            "group-type": "sponsor",
            "group-max-users": self.maximum_members,
            "access": "customized",
            "user-permission": [
                {
                    "id": 1,
                    "permission": "owner",
                    "user-name": [{"name": self.owner_name}],
                }
            ],
            "member": [],
        }


def validate_sponsored_group_default_response(
    response: Mapping[str, object],
) -> SponsoredGroupDefaultEvidence:
    """Fail closed unless one complete build-29 Group default fixture is valid."""

    if not isinstance(response, Mapping) or set(response) != _ENVELOPE_KEYS:
        raise SponsoredGroupCreateContractError(
            "Sponsored Group default response does not match the exact contract."
        )
    if (
        response.get("status") != "success"
        or response.get("http_method") != DEFAULT_METHOD
        or response.get("http_status") != 200
        or response.get("action") != "default"
        or response.get("path") != "user"
        or response.get("name") != "group"
        or response.get("version") != f"v{FORTIPAM_VERSION}"
        or type(response.get("build")) is not int
        or response.get("build") != FORTIPAM_BUILD
    ):
        raise SponsoredGroupCreateContractError(
            "Sponsored Group default response is not the accepted target version."
        )
    _bounded_text(response.get("revision"), "revision", 128, allow_empty=False)
    _bounded_text(response.get("serial"), "serial", 128, allow_empty=False)
    _bounded_text(response.get("vdom"), "vdom", 128, allow_empty=False)
    _validate_results(response.get("results"))
    return SponsoredGroupDefaultEvidence()


def _validate_results(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != _EXPECTED_RESULTS_KEYS:
        raise SponsoredGroupCreateContractError(
            "Sponsored Group defaults do not match the complete accepted projection."
        )
    results = value
    if (
        results.get("name") != ""
        or type(results.get("id")) is not int
        or results.get("id") != 0
        or results.get("access") != "everyone"
        or results.get("group-type") != "firewall"
        or type(results.get("group-max-users")) is not int
        or results.get("group-max-users") != 10
    ):
        raise SponsoredGroupCreateContractError(
            "Sponsored Group defaults differ from the observed default values."
        )
    for field in _LIST_RESULT_FIELDS:
        if results.get(field) != []:
            raise SponsoredGroupCreateContractError(
                "Sponsored Group default list fields must be empty."
            )
    for field in _INTEGER_RESULT_FIELDS - {"id", "group-max-users"}:
        _nonnegative_int32(results.get(field), field)
    for field in _ENUM_RESULT_FIELDS - {"access", "group-type"}:
        _bounded_text(results.get(field), field, 64, allow_empty=True)
    for field in _TEXT_RESULT_FIELDS - {"name"}:
        _bounded_text(results.get(field), field, 4_096, allow_empty=True)


def _identifier(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 64
        or _IDENTIFIER.fullmatch(value) is None
    ):
        raise SponsoredGroupCreateContractError(
            f"{field} must be a 1..64 character ASCII identifier."
        )
    return value


def _bounded_text(
    value: object,
    field: str,
    maximum: int,
    *,
    allow_empty: bool,
) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or (not value and not allow_empty)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SponsoredGroupCreateContractError(f"{field} is not a bounded string.")
    return value


def _nonnegative_int32(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_INT32:
        raise SponsoredGroupCreateContractError(
            f"{field} must be a non-negative signed int32 value."
        )
    return value


__all__ = [
    "CREATE_METHOD",
    "CREATE_PATH",
    "DEFAULT_METHOD",
    "DEFAULT_QUERY",
    "FORTIPAM_BUILD",
    "FORTIPAM_VERSION",
    "SCHEMA_REF",
    "SponsoredGroupCreateContractError",
    "SponsoredGroupCreateInput",
    "SponsoredGroupDefaultEvidence",
    "validate_sponsored_group_default_response",
]
