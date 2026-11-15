"""Closed prospective EMS tag-manager role DTO; no source or write authority.

Only the observed 7.4.8.2245 permission domain is accepted. Metadata, a draft,
and its digest never establish freshness, account ownership or backend access.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

CONTRACT = "ems-7.4.8.2245-prospective-tag-manager-role-v1"
ROLE_CREATE_PATH = "/api/v1/roles/create"
_ERROR = "The prospective EMS tag-manager role is unavailable."
_PERMISSION_LABELS = frozenset({
    "ASSIGN_POLICIES",
    "ENDPOINT_COMMANDS",
    "ENDPOINT_CONTROL",
    "MANAGE_ALERT_SETTINGS",
    "MANAGE_CA_CERTIFICATES",
    "MANAGE_COMPLIANCE_VERIFICATION_RULES",
    "MANAGE_CUSTOM_MESSAGE_SETTINGS",
    "MANAGE_EDR",
    "MANAGE_FEATURE_SELECT_SETTINGS",
    "MANAGE_FILTERS",
    "MANAGE_FORENSICS_ANALYSIS",
    "MANAGE_FORTINET_SERVICES_SETTINGS",
    "MANAGE_GOOGLE_DOMAINS",
    "MANAGE_GROUP_ASSIGNMENT",
    "MANAGE_INSTALLERS",
    "MANAGE_INVITATIONS",
    "MANAGE_LDAPS",
    "MANAGE_LICENSE",
    "MANAGE_MDM_INTEGRATION_SETTINGS",
    "MANAGE_ON_NET_DETECTION",
    "MANAGE_PROFILES",
    "MANAGE_QUARANTINE",
    "MANAGE_SERVER_SETTINGS",
    "MANAGE_SOFTWARE_INVENTORY",
    "MANAGE_USER_MANAGEMENT",
    "MANAGE_WORKGROUPS",
    "SUPER",
    "VIEW_ALERT_SETTINGS",
    "VIEW_CA_CERTIFICATES",
    "VIEW_COMPLIANCE_VERIFICATION_RULES",
    "VIEW_CUSTOM_MESSAGE_SETTINGS",
    "VIEW_EDR",
    "VIEW_FEATURE_SELECT_SETTINGS",
    "VIEW_FILTERS",
    "VIEW_FORENSICS_ANALYSIS",
    "VIEW_FORTINET_SERVICES_SETTINGS",
    "VIEW_GROUP_ASSIGNMENT",
    "VIEW_INSTALLERS",
    "VIEW_LICENSE",
    "VIEW_MDM_INTEGRATION_SETTINGS",
    "VIEW_ON_NET_DETECTION",
    "VIEW_POLICIES",
    "VIEW_PROFILES",
    "VIEW_QUARANTINE",
    "VIEW_SERVER_SETTINGS",
    "VIEW_SOFTWARE_INVENTORY",
    "VIEW_USER_MANAGEMENT",
})
_REQUIRED_LABELS = frozenset({"MANAGE_COMPLIANCE_VERIFICATION_RULES",
    "VIEW_COMPLIANCE_VERIFICATION_RULES", "VIEW_GROUP_ASSIGNMENT"})
_ORDER = tuple(sorted(_PERMISSION_LABELS))
_NATIVE_WIRE = {
    "SUPER": "is_super",
    "MANAGE_COMPLIANCE_VERIFICATION_RULES": "manage_host_verification_rules",
    "VIEW_COMPLIANCE_VERIFICATION_RULES": "view_host_verification_rules",
}
_EXPECTED_WIRE = tuple(_NATIVE_WIRE.get(label, label.lower()) for label in _ORDER)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagRolePermissionSchema(_OpaqueC3Object):
    _wire: tuple[str, ...]

    def __post_init__(self) -> None:
        if (type(self._wire) is not tuple or len(self._wire) != len(_ORDER)
                or any(type(value) is not str or value != expected for expected, value in zip(_EXPECTED_WIRE, self._wire))):
            raise ValueError(_ERROR)

    @property
    def digest(self) -> str:
        self.__post_init__()
        return _digest({"contract": CONTRACT, "permission_wire": self._wire})


def qualify_permission_schema(permissions: object) -> EmsTagRolePermissionSchema:
    """Consume canonical labels from a trusted metadata reader; never default."""
    if type(permissions) is not dict or set(permissions) != _PERMISSION_LABELS:
        raise ValueError(_ERROR)
    return EmsTagRolePermissionSchema(tuple(permissions[label] for label in _ORDER))


@dataclass(frozen=True, slots=True, repr=False)
class ProspectiveEmsTagManagerRole(_OpaqueC3Object):
    schema: EmsTagRolePermissionSchema
    nonce: str

    def __post_init__(self) -> None:
        if (type(self.schema) is not EmsTagRolePermissionSchema or type(self.nonce) is not str
                or re.fullmatch(r"[a-f0-9]{32}", self.nonce) is None):
            raise ValueError(_ERROR)
        self.schema.__post_init__()

    @property
    def _body(self) -> dict[str, Any]:
        self.__post_init__()
        return {"name": "mcpv4r_" + self.nonce[:24],
                "description": "Disposable tag-manager lab role; no super permission.",
                **{wire: label in _REQUIRED_LABELS for label, wire in zip(_ORDER, self.schema._wire)
                   if label != "SUPER"}}

    @property
    def parameters_digest(self) -> str:
        self.__post_init__()
        return _digest({"contract": CONTRACT, "schema": self.schema.digest,
                        "method": "POST", "path": ROLE_CREATE_PATH, "body": self._body})


def _detail(value: object, schema: EmsTagRolePermissionSchema) -> dict[str, Any]:
    if type(schema) is not EmsTagRolePermissionSchema:
        raise ValueError(_ERROR)
    schema.__post_init__()
    if (type(value) is not dict
            or set(value) != set(schema._wire) | {"id", "uid", "name", "description", "is_built_in"}
            or type(value["id"]) is not int or value["id"] == 0 or not -(2**63) < value["id"] < 2**63
            or type(value["uid"]) is not str or re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", value["uid"]) is None
            or type(value["name"]) is not str or not 1 <= len(value["name"]) <= 128
            or value["description"] is not None and (type(value["description"]) is not str or len(value["description"]) > 4096)
            or type(value["is_built_in"]) is not bool
            or any(type(value[key]) is not bool for key in schema._wire)):
        raise ValueError(_ERROR)
    return value


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagRoleDetail(_OpaqueC3Object):
    """Complete metadata only; matching a proposal never establishes ownership."""

    schema: EmsTagRolePermissionSchema
    _raw: bytes

    def __post_init__(self) -> None:
        if type(self._raw) is not bytes or not 0 < len(self._raw) <= 16384:
            raise ValueError(_ERROR)
        try:
            value = _detail(json.loads(self._raw), self.schema)
            if self._raw != json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode():
                raise ValueError
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise ValueError(_ERROR) from None

    @property
    def digest(self) -> str:
        self.__post_init__()
        return hashlib.sha256(self._raw).hexdigest()

    @property
    def _uid(self) -> str:
        self.__post_init__()
        return str(json.loads(self._raw)["uid"])

    @property
    def _numeric_id(self) -> int:
        self.__post_init__()
        return int(json.loads(self._raw)["id"])

    def matches_proposal(self, draft: ProspectiveEmsTagManagerRole) -> bool:
        self.__post_init__()
        if type(draft) is not ProspectiveEmsTagManagerRole:
            raise ValueError(_ERROR)
        draft.__post_init__()
        value = json.loads(self._raw)
        return (self.schema.digest == draft.schema.digest and value["is_super"] is False
                and value["is_built_in"] is False and all(value[key] == item for key, item in draft._body.items()))


def qualify_role_detail(detail: object, schema: EmsTagRolePermissionSchema) -> EmsTagRoleDetail:
    """Consume a trusted reader's decoded detail; keep both identifier types."""
    value = _detail(detail, schema)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return EmsTagRoleDetail(schema, raw)
