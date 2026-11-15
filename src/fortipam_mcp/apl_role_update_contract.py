"""Private build-29 disabled-APL role transition; no I/O or write authority.

Only the native model's accprofile field changes. The transport must separately
prove original disposable creation ownership, dependency visibility, fresh
state, authorization, single dispatch, product ACK and recovery ownership.
The owner must clear returned private request buffers after use.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from types import MappingProxyType
from typing import Literal, NoReturn, TypeAlias

from v4_planning.material_provider import C3MaterialBinding

CONTRACT = "fortipam-700-build29-disabled-apl-role-update-private-v1"
CONFIG_FIELDS = (
    "name", "status", "description", "remote-group", "accprofile", "schedule",
    "delegation-on-purge", *(f"trusthost{i}" for i in range(1, 11)),
    *(f"ip6-trusthost{i}" for i in range(1, 11)),
)
_METADATA_TYPES: Mapping[str, type[str] | type[int] | type[bool]] = MappingProxyType({
    "q_global_entry": bool, "q_mkey_type": str, "q_name": str,
    "q_no_edit": bool, "q_no_rename": bool, "q_origin_key": str,
    "q_path": str, "q_ref": int, "q_static": bool, "q_type": int,
})
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_UNAVAILABLE = "The private disabled APL role transition is unavailable."
Scalar: TypeAlias = str | int | bool


class AplRoleUpdateContractError(RuntimeError):
    """Value-free refusal; never include selectors or current state."""


def _fail() -> NoReturn:
    raise AplRoleUpdateContractError(_UNAVAILABLE)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _require_digest(value: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _fail()


class _Private(C3MaterialBinding):
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        _fail()

    def __delattr__(self, name: str) -> None:
        _fail()


class AplRoleUpdateBinding(_Private):
    """Owner-only fixed identity and two existing laboratory Role selectors."""

    __slots__ = ("rule_name", "group_name", "original_role", "updated_role", "nonce", "digest")
    rule_name: str
    group_name: str
    original_role: str
    updated_role: str
    nonce: str
    digest: str

    def __init__(self, rule_name: str, group_name: str, original_role: str,
                 updated_role: str, nonce: str) -> None:
        for value, prefix in ((rule_name, "mcp-v4-apl-"),
                              (group_name, "mcp-v4-user-group-"),
                              (original_role, "mcp-v4-role-"),
                              (updated_role, "mcp-v4-role-")):
            if (type(value) is not str or len(value) > 63
                    or re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is None):
                _fail()
        _require_digest(nonce)
        # Build 29 silently truncates names beyond its native 35-character limit.
        if len(rule_name) > 35 or original_role == updated_role:
            _fail()
        values = {"rule_name": rule_name, "group_name": group_name,
                  "original_role": original_role, "updated_role": updated_role, "nonce": nonce}
        for name, value in values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "digest", _digest({"contract": CONTRACT, **values}))


def _snapshot(record: Mapping[str, object], binding: AplRoleUpdateBinding,
              role: str) -> dict[str, Scalar]:
    if type(binding) is not AplRoleUpdateBinding or not isinstance(record, Mapping):
        _fail()
    if set(record) != set(CONFIG_FIELDS) | set(_METADATA_TYPES):
        _fail()
    result: dict[str, Scalar] = {}
    for name in CONFIG_FIELDS:
        value = record[name]
        if type(value) is not str or len(value) > 8192:
            _fail()
        assert isinstance(value, str)
        result[name] = value
    for name, kind in _METADATA_TYPES.items():
        value = record[name]
        if type(value) is not kind:
            _fail()
        assert isinstance(value, (str, int, bool))
        if isinstance(value, str) and len(value) > 8192:
            _fail()
        result[name] = value
    if (result["name"] != binding.rule_name or result["q_origin_key"] != binding.rule_name
            or result["remote-group"] != binding.group_name or result["accprofile"] != role
            or result["status"] != "disable" or result["q_ref"] != 0
            or result["q_no_edit"] is not False or result["q_static"] is not False
            or result["q_global_entry"] is not False):
        _fail()
    return result


class AplRoleTransition(_Private):
    """Immutable original/expected state; these fingerprints grant no authority."""

    __slots__ = ("binding", "_before", "_after", "schema_digest", "serial_digest",
                 "dependencies_digest", "before_digest", "after_digest", "digest")
    binding: AplRoleUpdateBinding
    _before: Mapping[str, Scalar]
    _after: Mapping[str, Scalar]
    schema_digest: str
    serial_digest: str
    dependencies_digest: str
    before_digest: str
    after_digest: str
    digest: str

    def __init__(self, current: Mapping[str, object], binding: AplRoleUpdateBinding, *,
                 schema_digest: str, serial_digest: str, dependencies_digest: str) -> None:
        try:
            for value in (schema_digest, serial_digest, dependencies_digest):
                _require_digest(value)
            if type(binding) is not AplRoleUpdateBinding:
                _fail()
            before = _snapshot(current, binding, binding.original_role)
            after = dict(before, accprofile=binding.updated_role)
            attributes: dict[str, object] = {
                "binding": binding, "_before": MappingProxyType(before), "_after": MappingProxyType(after),
                "schema_digest": schema_digest, "serial_digest": serial_digest,
                "dependencies_digest": dependencies_digest,
                "before_digest": _digest(before), "after_digest": _digest(after),
            }
            for key, attribute_value in attributes.items():
                object.__setattr__(self, key, attribute_value)
            object.__setattr__(self, "digest", _digest({"contract": CONTRACT, "binding": binding.digest,
                "schema": schema_digest, "serial": serial_digest, "dependencies": dependencies_digest,
                "before": self.before_digest, "after": self.after_digest}))
        except Exception:
            raise AplRoleUpdateContractError(_UNAVAILABLE) from None


def _require_context(transition: AplRoleTransition, *, schema_digest: str,
                     serial_digest: str, dependencies_digest: str) -> None:
    if type(transition) is not AplRoleTransition:
        _fail()
    for actual, expected in ((schema_digest, transition.schema_digest),
                             (serial_digest, transition.serial_digest),
                             (dependencies_digest, transition.dependencies_digest)):
        _require_digest(actual)
        if actual != expected:
            _fail()


def _require_state(current: Mapping[str, object], transition: AplRoleTransition,
                   *, updated: bool) -> None:
    role = transition.binding.updated_role if updated else transition.binding.original_role
    state = _snapshot(current, transition.binding, role)
    if _digest(state) != (transition.after_digest if updated else transition.before_digest):
        _fail()


def build_role_transition_body(current: Mapping[str, object], transition: AplRoleTransition, *,
                               phase: Literal["update", "restore"], schema_digest: str,
                               serial_digest: str, dependencies_digest: str) -> bytearray:
    """Compile exactly 28 native fields after complete state/context comparison.

    Restore accepts only the complete expected B state and emits the original
    A state. It never adopts current values as a new baseline or sets status on.
    Dispatch and independent restore authority are outside this pure contract.
    """
    try:
        if phase not in ("update", "restore"):
            _fail()
        _require_context(transition, schema_digest=schema_digest, serial_digest=serial_digest,
                         dependencies_digest=dependencies_digest)
        _require_state(current, transition, updated=phase == "restore")
        desired = transition._after if phase == "update" else transition._before
        body = {name: desired[name] for name in ("q_origin_key", *CONFIG_FIELDS)}
        return bytearray(json.dumps(body, ensure_ascii=True, separators=(",", ":"),
                                   allow_nan=False).encode())
    except Exception:
        raise AplRoleUpdateContractError(_UNAVAILABLE) from None


def verify_role_transition(current: Mapping[str, object], transition: AplRoleTransition, *,
                           phase: Literal["update", "restore"], schema_digest: str,
                           serial_digest: str, dependencies_digest: str) -> None:
    """Require the complete expected post-state, including unchanged metadata."""
    try:
        if phase not in ("update", "restore"):
            _fail()
        _require_context(transition, schema_digest=schema_digest, serial_digest=serial_digest,
                         dependencies_digest=dependencies_digest)
        _require_state(current, transition, updated=phase == "update")
    except Exception:
        raise AplRoleUpdateContractError(_UNAVAILABLE) from None
