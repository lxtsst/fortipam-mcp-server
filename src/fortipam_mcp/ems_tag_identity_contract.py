"""Complete bounded EMS role/admin metadata scope; no ownership or authority."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from typing import Any
from urllib.parse import urlencode

from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_contract import _canonical, _envelope
from .ems_tag_role_contract import EmsTagRoleDetail, EmsTagRolePermissionSchema, ProspectiveEmsTagManagerRole

CONTRACT = "ems-7.4.8.2245-complete-role-admin-metadata-v1"
ROLE_INDEX = "/api/v1/roles/index"
ADMIN_INDEX = "/api/v1/admins/refresh"
MAX_ROLES = 16
MAX_ADMINS = 16
_ERROR = "The complete EMS identity metadata is unavailable."
_UID = re.compile(r"[a-zA-Z0-9_-]{1,128}\Z")


def _uid(value: object) -> str:
    if type(value) is not str or _UID.fullmatch(value) is None:
        raise ValueError(_ERROR)
    return value


def _admin_id(value: object) -> int:
    if type(value) is not int or not 0 < value < 2**31:
        raise ValueError(_ERROR)
    return value


def _metadata(value: object, budget: list[int], depth: int = 0) -> None:
    """Never retain material slots, including unexpected nested ones."""
    budget[0] -= 1
    if budget[0] < 0 or depth > 8:
        raise ValueError(_ERROR)
    if value is None or type(value) is bool:
        return
    if type(value) is int and -(2**63) < value < 2**63:
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is str and len(value) <= 65536 and "\x00" not in value:
        return
    if type(value) is list and len(value) <= 256:
        for item in value:
            _metadata(item, budget, depth + 1)
        return
    if type(value) is dict and len(value) <= 128:
        for key, item in value.items():
            if (type(key) is not str or not 1 <= len(key) <= 128 or "\x00" in key
                    or "password" in key.casefold()
                    or key.casefold() in {"token", "session", "secret", "private_key", "totp_secret"}
                    or key.casefold().endswith(("_token", "_password", "_secret"))
                    or key.endswith("role_uid") and key not in {"role_uid", "default_site_role_uid"}):
                raise ValueError(_ERROR)
            _metadata(item, budget, depth + 1)
        return
    raise ValueError(_ERROR)


def _rows(payload: object, *, maximum: int) -> list[dict[str, Any]]:
    value = _envelope(payload)
    if type(value) is not list or not 1 <= len(value) <= maximum or any(type(row) is not dict for row in value):
        raise ValueError(_ERROR)
    _metadata(value, [10000])
    return value


def role_catalog(payload: object) -> tuple[bytes, ...]:
    rows = _rows(payload, maximum=MAX_ROLES)
    names: set[str] = set()
    identifiers: set[str] = set()
    result = []
    for row in rows:
        if (not {"uid", "name", "description", "is_built_in", "is_super"} <= set(row)
                or type(row["name"]) is not str or not 1 <= len(row["name"]) <= 128
                or type(row["is_built_in"]) is not bool or type(row["is_super"]) is not bool):
            raise ValueError(_ERROR)
        uid = _uid(row["uid"])
        if uid in identifiers or row["name"].casefold() in names:
            raise ValueError(_ERROR)
        names.add(row["name"].casefold());identifiers.add(uid)
        result.append((uid, _canonical(row)))
    return tuple(raw for _, raw in sorted(result))


def admin_catalog(payload: object) -> tuple[bytes, ...]:
    rows = _rows(payload, maximum=MAX_ADMINS)
    identifiers: set[tuple[int, str | None]] = set()
    result = []
    for row in rows:
        if (not {"id", "name", "user_type", "vdom"} <= set(row)
                or type(row["name"]) is not str or not 1 <= len(row["name"]) <= 256
                or type(row["user_type"]) is not str or not 1 <= len(row["user_type"]) <= 32
                or row["vdom"] is not None and (type(row["vdom"]) is not str or not 1 <= len(row["vdom"]) <= 128)):
            raise ValueError(_ERROR)
        identifier = _admin_id(row["id"])
        identity = (identifier, row["vdom"])
        if identity in identifiers:
            raise ValueError(_ERROR)
        identifiers.add(identity)
        result.append(((identifier, "" if row["vdom"] is None else row["vdom"]),
                       _canonical({key: item for key, item in row.items() if key != "last_active_time"})))
    return tuple(raw for _, raw in sorted(result))


def admin_detail_path(row: bytes) -> str:
    value = json.loads(row)
    identifier = _admin_id(value["id"])
    # Native axios omits null/undefined parameters; no default site is invented.
    query = "?" + urlencode({"vdom": value["vdom"]}) if value["vdom"] is not None else ""
    return "/api/v1/admins/" + str(identifier) + "/get" + query


def qualify_admin_detail(payload: object, catalog_row: bytes, role_uids: frozenset[str]) -> bytes:
    value = _envelope(payload)
    row = json.loads(catalog_row)
    if type(value) is not dict:
        raise ValueError(_ERROR)
    _metadata(value, [10000])
    if any(key not in value or type(value[key]) is not type(row[key]) or value[key] != row[key]
           for key in ("id", "name", "user_type", "vdom")):
        raise ValueError(_ERROR)
    if not {"role_uid", "default_site_role_uid", "trusted_hosts_enabled", "trusted_hosts", "allow_all_domains"} <= set(value):
        raise ValueError(_ERROR)
    for key in ("trusted_hosts_enabled", "allow_all_domains"):
        if type(value[key]) is not bool:
            raise ValueError(_ERROR)
    if value["trusted_hosts"] is not None and type(value["trusted_hosts"]) is not str:
        raise ValueError(_ERROR)
    # Native local no-domain EMS details omit the empty relation. The native
    # form maps absence to an empty selection; retain absence in the full scope.
    if "idps" in value:
        if type(value["idps"]) is not list:raise ValueError(_ERROR)
    elif value["user_type"] != "EMS" or value["allow_all_domains"] is not False:
        raise ValueError(_ERROR)
    refs = _role_references(value)
    if not refs <= role_uids:
        raise ValueError(_ERROR)
    return _canonical({key: item for key, item in value.items() if key != "last_active_time"})


def _role_references(value: object) -> frozenset[str]:
    result: set[str] = set()
    if type(value) is dict:
        for key, item in value.items():
            if key in {"role_uid", "default_site_role_uid"} and item is not None:
                result.add(_uid(item))
            elif type(item) in (dict, list):
                result.update(_role_references(item))
    elif type(value) is list:
        for item in value:
            result.update(_role_references(item))
    return frozenset(result)


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagIdentityScope(_OpaqueC3Object):
    schema: EmsTagRolePermissionSchema
    _role_rows: tuple[bytes, ...]
    _role_details: tuple[EmsTagRoleDetail, ...]
    _admin_rows: tuple[bytes, ...]
    _admin_details: tuple[bytes, ...]

    def __post_init__(self) -> None:
        try:
            if (type(self.schema) is not EmsTagRolePermissionSchema
                    or any(type(items) is not tuple for items in (self._role_rows, self._role_details, self._admin_rows, self._admin_details))
                    or any(type(raw) is not bytes for raw in (*self._role_rows, *self._admin_rows, *self._admin_details))
                    or sum(map(len, (*self._role_rows, *self._admin_rows, *self._admin_details))) > 1048576):
                raise ValueError
            self.schema.__post_init__()
            roles = role_catalog({"data": [json.loads(raw) for raw in self._role_rows], "result": {"retval": 1, "message": None}})
            admins = admin_catalog({"data": [json.loads(raw) for raw in self._admin_rows], "result": {"retval": 1, "message": None}})
            if roles != self._role_rows or admins != self._admin_rows or len(roles) != len(self._role_details) or len(admins) != len(self._admin_details):
                raise ValueError
            uids = frozenset(json.loads(raw)["uid"] for raw in roles)
            for raw, detail in zip(roles, self._role_details):
                if type(detail) is not EmsTagRoleDetail or detail.schema.digest != self.schema.digest:
                    raise ValueError
                detail.__post_init__()
                row, full = json.loads(raw), json.loads(detail._raw)
                if any(key not in full or type(full[key]) is not type(item) or full[key] != item for key, item in row.items()):
                    raise ValueError
            for raw, detail_raw in zip(admins, self._admin_details):
                if qualify_admin_detail({"data": json.loads(detail_raw), "result": {"retval": 1, "message": None}}, raw, uids) != detail_raw:
                    raise ValueError
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise ValueError(_ERROR) from None

    @property
    def digest(self) -> str:
        self.__post_init__()
        return hashlib.sha256(_canonical({"contract": CONTRACT, "schema": self.schema.digest,
            "roles": [detail.digest for detail in self._role_details], "role_catalog": [json.loads(raw) for raw in self._role_rows],
            "admins": [json.loads(raw) for raw in self._admin_details], "admin_catalog": [json.loads(raw) for raw in self._admin_rows]})).hexdigest()

    def role_is_referenced(self, uid: str) -> bool:
        self.__post_init__();_uid(uid)
        return any(uid in _role_references(json.loads(raw)) for raw in self._admin_details)


def verify_role_created(baseline: EmsTagIdentityScope, created: EmsTagIdentityScope,
                        draft: ProspectiveEmsTagManagerRole) -> EmsTagRoleDetail:
    """Verify only a complete delta; the caller still needs original ACK/custody."""
    try:
        if (type(baseline) is not EmsTagIdentityScope or type(created) is not EmsTagIdentityScope
                or type(draft) is not ProspectiveEmsTagManagerRole):
            raise ValueError
        baseline.__post_init__();created.__post_init__();draft.__post_init__()
        if (baseline.schema.digest != created.schema.digest or baseline.schema.digest != draft.schema.digest
                or baseline._admin_rows != created._admin_rows or baseline._admin_details != created._admin_details):
            raise ValueError
        before = {detail._uid: (raw, detail.digest) for raw, detail in zip(baseline._role_rows, baseline._role_details)}
        after = {detail._uid: (raw, detail.digest) for raw, detail in zip(created._role_rows, created._role_details)}
        added = set(after) - set(before)
        if (len(added) != 1 or len(after) != len(before) + 1
                or any(after.get(uid) != value for uid, value in before.items())
                or any(json.loads(raw)["name"].casefold() == draft._body["name"].casefold() for raw in baseline._role_rows)):
            raise ValueError
        candidate = next(detail for detail in created._role_details if detail._uid in added)
        if (not candidate.matches_proposal(draft) or created.role_is_referenced(candidate._uid)
                or candidate._numeric_id in {detail._numeric_id for detail in baseline._role_details}):
            raise ValueError
        return candidate
    except (ValueError, TypeError, KeyError, StopIteration):
        raise ValueError(_ERROR) from None


def verify_role_restored(baseline: EmsTagIdentityScope, restored: EmsTagIdentityScope) -> None:
    """Complete restoration is necessary, but never promotes a terminal UNKNOWN."""
    if (type(baseline) is not EmsTagIdentityScope or type(restored) is not EmsTagIdentityScope
            or baseline.digest != restored.digest):
        raise ValueError(_ERROR)
