"""Private EMS 7.4.8 tag projections; no transport, dispatch or authority.

The fixed prospective draft is disabled and uses one Linux process rule. Only
complete metadata and a zero client count can satisfy its local postcondition.
These projections do not prove synchronization, freshness, original ownership,
write permission, an ACK or independent recovery.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, NoReturn

from v4_planning.material_provider import _OpaqueC3Object

CONTRACT = "ems-7.4.8.2245-disabled-linux-process-tag-v3"
VERSION = "7.4.8.2245"
MAX_ORIGINAL_TAGS = 16
_ERROR = "The fixed EMS tag evidence is unavailable."
_NOTICE = "Disposable lab validation; keep disabled."
_DETAIL_FIELDS = frozenset({
    "tag_id", "tag_name", "description", "detection_level", "status",
    "comments", "rules", "use_custom_logic", "logic_windows", "logic_mac",
    "logic_linux", "logic_ios", "logic_android", "error_msg", "tag_type",
    "client_count", "tag_detection_type",
})
_LOGIC_FIELDS = frozenset({
    "logic_windows", "logic_mac", "logic_linux", "logic_ios", "logic_android",
})
_RULE_FIELDS = frozenset({
    "id", "os", "type", "content", "negative", "fct_based", "match_type_id",
    "domain_name", "no_valid_policy", "comparator", "context", "updates",
})


class EmsTagContractError(ValueError):
    """Value-free rejection of incomplete or incompatible source material."""


def _fail() -> NoReturn:
    raise EmsTagContractError(_ERROR)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        _fail()


def _fingerprint(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _integer(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= 2**31 - 1


def _text(value: object, maximum: int, *, empty: bool = True) -> bool:
    return (type(value) is str and len(value) <= maximum and "\x00" not in value
            and (empty or bool(value)))


def _envelope(payload: object) -> Any:
    if type(payload) is not dict or set(payload) != {"data", "result"}:
        _fail()
    result = payload["result"]
    if (type(result) is not dict or set(result) != {"retval", "message"}
            or type(result["retval"]) is not int or result["retval"] != 1
            or (result["message"] is not None and not _text(result["message"], 4096))):
        _fail()
    return payload["data"]


@dataclass(frozen=True, slots=True, repr=False)
class DisabledLinuxProcessTag(_OpaqueC3Object):
    nonce: str

    def __post_init__(self) -> None:
        if type(self.nonce) is not str or re.fullmatch(r"[a-f0-9]{32}", self.nonce) is None:
            _fail()

    @property
    def _name(self) -> str:
        self.__post_init__()
        return "mcpv4e_" + self.nonce[:24]

    @property
    def _process(self) -> str:
        self.__post_init__()
        return "mcpv4p_" + self.nonce

    @property
    def _body(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "name": self._name, "description": _NOTICE, "status": False,
            "comments": "mcp-v4-owned-disabled-tag-" + self.nonce,
            "rules": [{"id": 1, "os": 3, "type": 6, "content": self._process,
                       "negative": False}],
            "use_custom_logic": False,
        }

    @property
    def parameters_digest(self) -> str:
        return _fingerprint({"contract": CONTRACT, "version": VERSION, "body": self._body})

    @property
    def _validation_body(self) -> dict[str, Any]:
        return {"rules": [{"type": 6, "os": 3, "content": self._process}]}


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagDetail(_OpaqueC3Object):
    _raw: bytes
    _id: int
    _name: str
    _enabled: bool
    _clients: int

    def __post_init__(self) -> None:
        actual = _detail_components(self._raw)
        supplied = (self._id, self._name, self._enabled, self._clients)
        if any(type(a) is not type(b) or a != b for a, b in zip(actual, supplied)):
            _fail()

    @property
    def digest(self) -> str:
        self.__post_init__()
        return hashlib.sha256(self._raw).hexdigest()

    @property
    def disabled_and_unassigned(self) -> bool:
        self.__post_init__()
        return not self._enabled and self._clients == 0


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagCatalog(_OpaqueC3Object):
    _rows: tuple[bytes, ...]
    _ids: tuple[int, ...]
    _names: tuple[str, ...]

    def __post_init__(self) -> None:
        if (type(self._rows) is not tuple or type(self._ids) is not tuple
                or type(self._names) is not tuple
                or len(self._rows) > 256
                or any(type(row) is not bytes for row in self._rows)
                or sum(map(len, self._rows)) > 262144
                or any(type(identifier) is not int for identifier in self._ids)):
            _fail()
        try:
            actual = _catalog_parts([json.loads(row) for row in self._rows], len(self._rows))
        except (ValueError, TypeError, UnicodeError, RecursionError):
            _fail()
        if actual != (self._rows, self._ids, self._names):
            _fail()

    @property
    def count(self) -> int:
        self.__post_init__()
        return len(self._rows)

    @property
    def digest(self) -> str:
        self.__post_init__()
        return _fingerprint([json.loads(row) for row in self._rows])

    def contains_draft(self, draft: DisabledLinuxProcessTag) -> bool:
        self.__post_init__()
        if type(draft) is not DisabledLinuxProcessTag:
            _fail()
        return draft._name.casefold() in self._names

    def matches_detail(self, detail: EmsTagDetail) -> bool:
        self.__post_init__()
        if type(detail) is not EmsTagDetail:
            _fail()
        detail.__post_init__()
        if detail._id not in self._ids:
            return False
        row = json.loads(self._rows[self._ids.index(detail._id)])
        return (row["name"] == detail._name and row.get("status") is detail._enabled)


def _catalog_parts(records: object, total: object) -> tuple[tuple[bytes, ...], tuple[int, ...], tuple[str, ...]]:
    if (type(records) is not list or type(total) is not int
            or not 0 <= total <= 256 or len(records) != total):
        _fail()
    rows: list[dict[str, Any]] = records
    if any(type(row) is not dict or not _integer(row.get("id"), minimum=1)
           or not _text(row.get("name"), 256, empty=False)
           or type(row.get("status")) not in {bool, type(None)} for row in rows):
        _fail()
    if len({row["id"] for row in rows}) != len(rows):
        _fail()
    if len({row["name"].casefold() for row in rows}) != len(rows):
        _fail()
    rows = sorted(rows, key=lambda row: row["id"])
    encoded = tuple(_canonical(row) for row in rows)
    if sum(map(len, encoded)) > 262144:
        _fail()
    return (encoded, tuple(row["id"] for row in rows),
            tuple(row["name"].casefold() for row in rows))


def qualify_tag_catalog(payload: object) -> EmsTagCatalog:
    """Preserve complete rows; the bound reader must independently exclude filters."""
    data = _envelope(payload)
    if type(data) is not dict or not {"tags", "total"} <= set(data):
        _fail()
    return EmsTagCatalog(*_catalog_parts(data["tags"], data["total"]))


def _detail_row(row: object) -> dict[str, Any]:
    if type(row) is not dict or set(row) != _DETAIL_FIELDS:
        _fail()
    if (not _integer(row["tag_id"], minimum=1) or not _integer(row["tag_type"])
            or not _integer(row["client_count"])
            or type(row["status"]) is not bool
            or type(row["use_custom_logic"]) is not bool
            or not _text(row["tag_name"], 256, empty=False)
            or not _text(row["description"], 512)
            or not _text(row["comments"], 256)
            or not _text(row["detection_level"], 64)
            or (row["tag_detection_type"] is not None
                and not _integer(row["tag_detection_type"]))
            or (row["error_msg"] is not None and not _text(row["error_msg"], 4096))):
        _fail()
    if any(row[field] is not None and not _text(row[field], 16384) for field in _LOGIC_FIELDS):
        _fail()
    rules = row["rules"]
    if type(rules) is not list or len(rules) > 256:
        _fail()
    ids: set[int] = set()
    for rule in rules:
        if (type(rule) is not dict or not {"id", "os", "type", "content"} <= set(rule)
                or not set(rule) <= _RULE_FIELDS or not _integer(rule["id"], minimum=1)
                or rule["id"] in ids or not _integer(rule["os"])
                or not _integer(rule["type"])
                or ("negative" in rule and type(rule["negative"]) is not bool)
                or (rule["content"] is not None and not _text(rule["content"], 4096))):
            _fail()
        ids.add(rule["id"])
        for field in ("match_type_id", "updates"):
            if field in rule and rule[field] is not None and not _integer(rule[field]):
                _fail()
        for field, maximum in (("comparator", 32), ("context", 4096), ("domain_name", 512)):
            if field in rule and rule[field] is not None and not _text(rule[field], maximum):
                _fail()
        for field in ("fct_based", "no_valid_policy"):
            if field in rule and rule[field] is not None and type(rule[field]) is not bool:
                _fail()
    return row


def _detail_components(encoded: bytes) -> tuple[int, str, bool, int]:
    if type(encoded) is not bytes or not 0 < len(encoded) <= 262144:
        _fail()
    try:
        row = _detail_row(json.loads(encoded))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _fail()
    if _canonical(row) != encoded:
        _fail()
    return row["tag_id"], row["tag_name"], row["status"], row["client_count"]


def qualify_tag_detail(payload: object) -> EmsTagDetail:
    """Keep the whole seventeen-field native state, including client_count."""
    row = _detail_row(_envelope(payload))
    encoded = _canonical(row)
    if len(encoded) > 262144:
        _fail()
    return EmsTagDetail(encoded, row["tag_id"], row["tag_name"], row["status"], row["client_count"])


def _fixed_linux_logic(value: object) -> bool:
    """Recognize only the native generated single-rule expression."""
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError
            result[key] = item
        return result

    if type(value) is not str or len(value) > 1024:
        return False
    try:
        parsed = json.loads(value, object_pairs_hook=unique_object)
        return _canonical(parsed) == b'{"op":null,"rules":[{"id":1}]}'
    except (ValueError, TypeError, RecursionError):
        return False


def matches_disabled_process_tag(detail: EmsTagDetail, draft: DisabledLinuxProcessTag) -> bool:
    """Check only the prospective state; this never grants original ownership."""
    if type(detail) is not EmsTagDetail or type(draft) is not DisabledLinuxProcessTag:
        _fail()
    row = json.loads(detail._raw)
    body = draft._body
    if (not detail.disabled_and_unassigned or row["tag_name"] != body["name"]
            or any(row[field] != body[field] for field in ("description", "comments", "use_custom_logic"))
            or row["error_msg"] not in (None, "")
            or any(row[field] is not None for field in _LOGIC_FIELDS - {"logic_linux"})
            or not _fixed_linux_logic(row["logic_linux"])
            or len(row["rules"]) != 1):
        return False
    rule = row["rules"][0]
    return (all(type(rule.get(field)) is type(value) and rule[field] == value
                for field, value in body["rules"][0].items())
            and set(rule) <= set(body["rules"][0]) | {"updates"}
            and rule.get("updates") is None)


def single_addition_matches(before: EmsTagCatalog, after: EmsTagCatalog,
                            detail: EmsTagDetail, draft: DisabledLinuxProcessTag) -> bool:
    """Compare a complete delta without synthesizing ACK, custody or M4 claims."""
    if (type(before) is not EmsTagCatalog or type(after) is not EmsTagCatalog
            or type(detail) is not EmsTagDetail or type(draft) is not DisabledLinuxProcessTag):
        _fail()
    if (before.contains_draft(draft) or after.count != before.count + 1
            or detail._id in before._ids or not after.matches_detail(detail)
            or not matches_disabled_process_tag(detail, draft)):
        return False
    retained = tuple(row for row, identifier in zip(after._rows, after._ids)
                     if identifier != detail._id)
    return retained == before._rows


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagFullScope(_OpaqueC3Object):
    """Bounded complete catalog plus every listed tag's full native state."""

    catalog: EmsTagCatalog
    details: tuple[EmsTagDetail, ...]

    def __post_init__(self) -> None:
        if (type(self.catalog) is not EmsTagCatalog or type(self.details) is not tuple
                or self.catalog.count > MAX_ORIGINAL_TAGS + 1
                or len(self.details) != self.catalog.count
                or any(type(detail) is not EmsTagDetail for detail in self.details)):
            _fail()
        for detail in self.details:
            detail.__post_init__()
        if (tuple(sorted(detail._id for detail in self.details)) != self.catalog._ids
                or any(not self.catalog.matches_detail(detail) for detail in self.details)):
            _fail()
        self._rule_sets()

    def _rule_sets(self) -> dict[int, int | None]:
        result: dict[int, int | None] = {}
        for encoded in self.catalog._rows:
            row = json.loads(encoded)
            if "rule_set_id" not in row or (row["rule_set_id"] is not None
                    and not _integer(row["rule_set_id"], minimum=1)):
                _fail()
            result[row["id"]] = row["rule_set_id"]
        return result

    @property
    def digest(self) -> str:
        self.__post_init__()
        return _fingerprint({"catalog": self.catalog.digest,
                             "details": [detail.digest for detail in sorted(self.details, key=lambda d: d._id)]})

    def _candidate(self, draft: DisabledLinuxProcessTag) -> EmsTagDetail:
        self.__post_init__()
        if type(draft) is not DisabledLinuxProcessTag:
            _fail()
        matches = [detail for detail in self.details if detail._name.casefold() == draft._name.casefold()]
        if len(matches) != 1:
            _fail()
        return matches[0]


def full_single_addition_matches(before: EmsTagFullScope, after: EmsTagFullScope,
                                  draft: DisabledLinuxProcessTag) -> bool:
    """Require untouched prior full states and a distinct new owned rule set."""
    if (type(before) is not EmsTagFullScope or type(after) is not EmsTagFullScope
            or type(draft) is not DisabledLinuxProcessTag):
        _fail()
    before.__post_init__()
    after.__post_init__()
    if before.catalog.count > MAX_ORIGINAL_TAGS or not after.catalog.contains_draft(draft):
        return False
    candidate = after._candidate(draft)
    if not single_addition_matches(before.catalog, after.catalog, candidate, draft):
        return False
    old = {detail._id: detail.digest for detail in before.details}
    retained = {detail._id: detail.digest for detail in after.details if detail._id != candidate._id}
    rule_set = after._rule_sets()[candidate._id]
    return old == retained and rule_set is not None and rule_set not in before._rule_sets().values()


def create_current_digest(draft: DisabledLinuxProcessTag, baseline_digest: str,
                          source_context_digest: str) -> str:
    from v4_planning.models import require_digest

    if type(draft) is not DisabledLinuxProcessTag:
        _fail()
    require_digest(baseline_digest, "ems_baseline")
    require_digest(source_context_digest, "ems_source")
    return _fingerprint({"contract": CONTRACT, "phase": "absent", "parameters": draft.parameters_digest,
                         "baseline": baseline_digest, "source": source_context_digest})


def create_expected_digest(draft: DisabledLinuxProcessTag, baseline_digest: str,
                           source_context_digest: str) -> str:
    return _fingerprint({"current": create_current_digest(draft, baseline_digest, source_context_digest),
                         "postcondition": "one-disabled-unassigned-tag-distinct-rule-set-full-prior-state-preserved"})
