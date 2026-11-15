"""Pure minimized FortiPAM mapping contract, never a source or write authority.

The selected connector's current status supplies its exact EMS serial. The
older frontend serial regex is not an identity authority. Caller-provided or
saved frames do not establish a fresh authenticated FortiPAM source.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_contract import DisabledLinuxProcessTag, _canonical

_ERROR = "The private FortiPAM EMS Tag mapping is unavailable."
_FIELDS = frozenset({"name", "type", "sub-type", "obj-tag", "obj-type", "tag-type", "tag-detection-level"})
_META = frozenset({"q_origin_key", "q_class", "q_global_entry", "q_mkey_type", "q_name", "q_no_edit",
    "q_no_rename", "q_path", "q_ref", "q_static", "q_type"})


@dataclass(frozen=True, slots=True, repr=False)
class FpaEmsTagMapping(_OpaqueC3Object):
    _rows: tuple[bytes, ...]
    _owned_names: tuple[str, ...]
    positive_serial_prefix_count: int

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical([row.hex() for row in self._rows])).hexdigest()

    @property
    def without_owned_digest(self) -> str:
        kept = [row.hex() for row in self._rows if json.loads(row)["name"] not in self._owned_names]
        return hashlib.sha256(_canonical(kept)).hexdigest()

    @property
    def candidate_absent(self) -> bool:
        return not self._owned_names

    def require_zero_owned_references(self, usage: object) -> None:
        """Every mapped address needs its own complete current usage response."""
        try:
            if type(usage) is not dict or set(usage) != set(self._owned_names):
                raise ValueError
            for encoded in self._rows:
                row = json.loads(encoded)
                if row["name"] not in self._owned_names:
                    continue
                if type(row.get("q_ref")) is not int or row["q_ref"] != 0:
                    raise ValueError
                frame = usage[row["name"]]
                if (type(frame) is not dict or frame.get("mkey") != row["name"]
                        or type(frame.get("results")) is not dict
                        or type(frame["results"].get("currently_using")) is not list
                        or frame["results"].get("currently_using") != []):
                    raise ValueError
        except Exception:
            raise ValueError(_ERROR) from None


def qualify_fpa_tag_mapping(frame: object, *, ems_serial: str,
                            draft: DisabledLinuxProcessTag) -> FpaEmsTagMapping:
    """Preserve the complete projection and bind labels to an exact serial prefix."""
    try:
        if (type(frame) is not dict or type(ems_serial) is not str or not 0 < len(ems_serial) <= 79
                or not ems_serial.isascii() or any(ord(c) <= 32 or ord(c) >= 127 for c in ems_serial)
                or type(draft) is not DisabledLinuxProcessTag):
            raise ValueError
        draft.__post_init__()
        rows = frame.get("results")
        if (type(rows) is not list or len(rows) > 200 or frame.get("limit_reached", False) is not False
                or type(frame.get("matched_count", len(rows))) is not int
                or frame.get("matched_count", len(rows)) != len(rows)):
            raise ValueError
        names: set[str] = set()
        encoded: list[tuple[str, bytes]] = []
        owned: list[str] = []
        positive = 0
        prefixes = (ems_serial.casefold() + "_", "mac_" + ems_serial.casefold() + "_")
        for row in rows:
            if (type(row) is not dict or set(row) - _FIELDS - _META
                    or type(row.get("name")) is not str or not 0 < len(row["name"]) <= 79
                    or any(type(row.get(key)) is not str for key in ("type", "sub-type"))
                    or row["name"] in names
                    or any(value is not None and type(value) is not str for key, value in row.items()
                           if key in _FIELDS)):
                raise ValueError
            names.add(row["name"])
            tag = row["type"] == "dynamic" and row["sub-type"] == "ems-tag"
            same_serial = row["name"].casefold().startswith(prefixes)
            positive += int(tag and same_serial)
            label = row.get("obj-tag")
            same_label = type(label) is str and label.casefold() == draft._name.casefold()
            if same_label:
                if (not tag or not same_serial or label != draft._name
                        or type(row.get("q_ref")) is not int or row["q_ref"] < 0
                        or type(row.get("q_global_entry")) is not bool or row["q_global_entry"]):
                    raise ValueError
                owned.append(row["name"])
            elif draft._name.casefold() in row["name"].casefold():
                raise ValueError
            encoded.append((row["name"], _canonical(row)))
        if positive == 0:
            raise ValueError
        return FpaEmsTagMapping(tuple(raw for _, raw in sorted(encoded)), tuple(sorted(owned)), positive)
    except Exception:
        raise ValueError(_ERROR) from None


def fpa_address_reference_type(frame: object) -> int:
    """The virtual frontend Tag factory is not the backend reference type."""
    try:
        if type(frame) is not dict or type(frame.get("results")) is not dict:
            raise ValueError
        by_type = frame["results"].get("by_type")
        if type(by_type) is not dict:
            raise ValueError
        matches = [key for key, row in by_type.items() if type(row) is dict and row.get("path") == "firewall.address"]
        if (len(matches) != 1 or type(matches[0]) is not str or not matches[0].isascii()
                or not matches[0].isdecimal() or str(int(matches[0])) != matches[0]
                or not 0 <= int(matches[0]) < 2**31):
            raise ValueError
        return int(matches[0])
    except Exception:
        raise ValueError(_ERROR) from None
