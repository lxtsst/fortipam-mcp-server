"""Private isolated-Folder creation evidence; no write or recovery authority."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
import unicodedata

from .isolated_folder_m4_adapter import IsolatedFolderBinding

CONTRACT = "fortipam-700-build29-isolated-folder-creation-ownership-v1"
RDP_POLICY_CONTRACT = "fortipam-700-build29-initial-rdp-policy-folder-ownership-v1"
_UNAVAILABLE = "The isolated Folder creation ownership is unavailable."
_FIELDS = frozenset({"id", "name", "folder-type", "parent-folder", "inherit-policy", "inherit-permission",
                     "inherit-folder-ztna", "secret-policy", "ztna-ems-tag", "ztna-tags-match-logic",
                     "user-permission", "group-permission"})


@dataclass(frozen=True, slots=True, repr=False)
class IsolatedFolderCreationSnapshot:
    serial: str
    folder: Mapping[str, object]


@dataclass(frozen=True, slots=True, repr=False)
class IsolatedFolderCreationOwnership:
    contract: str
    preview_ref: str
    authorization_ref: str
    requester_digest: str
    parameters_digest: str
    workflow_record_mac: str
    native_folder_id: int
    serial: str
    baseline_json: str
    baseline_digest: str

    @property
    def snapshot(self) -> IsolatedFolderCreationSnapshot:
        """Give the caller its own copy; the signed canonical baseline is immutable."""
        return IsolatedFolderCreationSnapshot(self.serial, json.loads(self.baseline_json))


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _identifier(value: object) -> bool:
    return type(value) is int and 0 < value <= 2_147_483_647


def _serial(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is not None


def _origin(row: Mapping[str, object], identity: str | int) -> None:
    if "q_origin_key" in row:
        value = row["q_origin_key"]
        if type(value) is not type(identity) or value != identity:
            raise ValueError(_UNAVAILABLE)


def validate_creation_snapshot(snapshot: object, *, expected_serial: str, folder_id: int,
                               binding: IsolatedFolderBinding) -> str:
    """Return a private canonical copy of the complete qualified 12-field projection."""
    try:
        if (type(snapshot) is not IsolatedFolderCreationSnapshot or not _serial(expected_serial)
            or type(snapshot.serial) is not str
            or snapshot.serial != expected_serial or not _identifier(folder_id)
            or not isinstance(snapshot.folder, Mapping) or set(snapshot.folder) != _FIELDS):
            raise ValueError
        # Copy before validation so a returned receipt cannot alias source objects.
        row = json.loads(_canonical(dict(snapshot.folder)))
        if (type(row["id"]) is not int or row["id"] != folder_id
            or type(row["parent-folder"]) is not int or row["parent-folder"] != binding.parent_folder_id
            or row["name"] != binding.name or row["folder-type"] != "public"
            or row["inherit-policy"] != ("enable" if binding.initial_rdp_policy is None else "disable")
            or row["inherit-permission"] != "disable"
            or row["inherit-folder-ztna"] != "enable" or row["group-permission"] != []
            or row["ztna-ems-tag"] != [] or row["ztna-tags-match-logic"] not in {"and", "or"}
            or type(row["secret-policy"]) is not str or len(row["secret-policy"]) > 255
            or binding.empty_inactive_policy and row["secret-policy"] != ""
            or binding.initial_rdp_policy is not None and row["secret-policy"] != binding.initial_rdp_policy.name
            or any(unicodedata.category(c).startswith("C") for c in row["secret-policy"])):
            raise ValueError
        users = row["user-permission"]
        if not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict):
            raise ValueError
        relation = users[0]
        required = {"id", "user-name", "folder-permission", "secret-permission", "allowed-launcher-type"}
        if (not required <= set(relation) or not set(relation) <= required | {"q_origin_key"}
            or not _identifier(relation["id"]) or relation["folder-permission"] != "owner"
            or relation["secret-permission"] != "owner" or relation["allowed-launcher-type"] != "all"):
            raise ValueError
        _origin(relation, relation["id"])
        principals = relation["user-name"]
        if (not isinstance(principals, list) or len(principals) != 1 or not isinstance(principals[0], dict)
            or not {"name"} <= set(principals[0]) <= {"name", "q_origin_key"}
            or principals[0]["name"] != binding.owner_name):
            raise ValueError
        _origin(principals[0], binding.owner_name)
        return _canonical(row)
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def validate_creation_ownership(ownership: IsolatedFolderCreationOwnership, *, binding: IsolatedFolderBinding,
                               expected_serial: str) -> None:
    expected_contract = CONTRACT if binding.initial_rdp_policy is None else RDP_POLICY_CONTRACT
    if (type(ownership) is not IsolatedFolderCreationOwnership or ownership.contract != expected_contract
        or ownership.parameters_digest != binding.parameters_digest
        or not isinstance(ownership.baseline_json, str)):
        raise ValueError(_UNAVAILABLE)
    canonical = validate_creation_snapshot(ownership.snapshot, expected_serial=expected_serial,
                                          folder_id=ownership.native_folder_id, binding=binding)
    if (canonical != ownership.baseline_json or not hmac.compare_digest(
            _digest(json.loads(canonical)), ownership.baseline_digest)):
        raise ValueError(_UNAVAILABLE)


def ownership_payload(ownership: IsolatedFolderCreationOwnership) -> str:
    return _canonical(asdict(ownership))
