"""Disabled role mapping must preserve all other fields and reject drift."""
from __future__ import annotations

import copy
import json
import pickle

import pytest

from fortipam_mcp.apl_role_update_contract import (
    CONFIG_FIELDS, AplRoleTransition, AplRoleUpdateBinding, AplRoleUpdateContractError,
    build_role_transition_body, verify_role_transition,
)
from v4_planning.material_provider import MaterialAccessDenied

CONTEXT = {"schema_digest": "a" * 64, "serial_digest": "b" * 64, "dependencies_digest": "c" * 64}


def fixture() -> tuple[dict[str, object], AplRoleTransition]:
    binding = AplRoleUpdateBinding("mcp-v4-apl-synthetic", "mcp-v4-user-group-synthetic",
                                   "mcp-v4-role-a", "mcp-v4-role-b", "d" * 64)
    row: dict[str, object] = {key: "" for key in CONFIG_FIELDS}
    row.update(name=binding.rule_name, status="disable", accprofile=binding.original_role,
               q_origin_key=binding.rule_name, q_ref=0, q_static=False, q_global_entry=False,
               q_no_edit=False, q_no_rename=False, q_mkey_type="string", q_type=0,
               q_name="auto-provision-rule", q_path="user")
    row["remote-group"] = binding.group_name
    row["description"] = "Synthetic nonempty original description"
    row["schedule"] = "synthetic-existing-schedule"
    row["delegation-on-purge"] = "synthetic-existing-delegate"
    for index in range(1, 11):
        row[f"trusthost{index}"] = f"192.0.2.{index} 255.255.255.255"
        row[f"ip6-trusthost{index}"] = f"2001:db8::{index}/128"
    return row, AplRoleTransition(row, binding, **CONTEXT)


def test_native_update_and_independent_restore_preserve_complete_original_state() -> None:
    before, transition = fixture()
    original = copy.deepcopy(before)
    body = build_role_transition_body(before, transition, phase="update", **CONTEXT)
    try:
        wire = json.loads(body)
        assert set(wire) == {"q_origin_key", *CONFIG_FIELDS}
        assert wire["accprofile"] == transition.binding.updated_role
        assert {k: v for k, v in wire.items() if k != "accprofile"} == {
            k: original[k] for k in wire if k != "accprofile"}
        after = dict(before, accprofile=wire["accprofile"])
        verify_role_transition(after, transition, phase="update", **CONTEXT)
    finally:
        body[:] = b"\0" * len(body)
    restore = build_role_transition_body(after, transition, phase="restore", **CONTEXT)
    try:
        assert json.loads(restore) == {key: original[key] for key in ("q_origin_key", *CONFIG_FIELDS)}
        verify_role_transition(before, transition, phase="restore", **CONTEXT)
    finally:
        restore[:] = b"\0" * len(restore)
    assert before == original


def test_native_rule_name_limit_rejects_truncation_before_transport_creation() -> None:
    _, transition = fixture()
    original = transition.binding
    name = "mcp-v4-apl-" + "a" * 24
    assert len(name) == 35
    binding = AplRoleUpdateBinding(name, original.group_name, original.original_role,
                                  original.updated_role, original.nonce)
    assert binding.rule_name == name
    with pytest.raises(AplRoleUpdateContractError):
        AplRoleUpdateBinding(name + "b", original.group_name, original.original_role,
                             original.updated_role, original.nonce)


@pytest.mark.parametrize("key,value", [
    ("status", "enable"), ("q_ref", 1), ("q_ref", False), ("q_static", True),
    ("q_no_edit", True), ("q_global_entry", True), ("accprofile", {"name": "role"}),
    ("q_origin_key", "another-rule"), ("remote-group", "another-group"),
])
def test_enabled_referenced_or_incomplete_baseline_never_compiles(key: str, value: object) -> None:
    row, transition = fixture()
    row[key] = value
    with pytest.raises(AplRoleUpdateContractError, match="^The private disabled APL role transition is unavailable.$"):
        AplRoleTransition(row, transition.binding, **CONTEXT)


@pytest.mark.parametrize("key", ["description", "schedule", "delegation-on-purge", "trusthost10",
                                 "ip6-trusthost10", "q_no_rename", "q_type"])
def test_update_and_restore_reject_drift_in_preserved_fields(key: str) -> None:
    original, transition = fixture()
    for phase in ("update", "restore"):
        current = dict(original, accprofile=transition.binding.original_role if phase == "update"
                       else transition.binding.updated_role)
        current[key] = (not current[key]) if type(current[key]) is bool else (
            99 if type(current[key]) is int else "changed-private-value")
        with pytest.raises(AplRoleUpdateContractError):
            build_role_transition_body(current, transition, phase=phase, **CONTEXT)


@pytest.mark.parametrize("key", ["schema_digest", "serial_digest", "dependencies_digest"])
def test_context_drift_is_not_a_new_baseline(key: str) -> None:
    row, transition = fixture()
    context = dict(CONTEXT)
    context[key] = "e" * 64
    with pytest.raises(AplRoleUpdateContractError):
        build_role_transition_body(row, transition, phase="update", **context)


def test_snapshot_is_complete_immutable_and_cannot_cross_material_boundary() -> None:
    row, transition = fixture()
    for altered in ({k: v for k, v in row.items() if k != "trusthost10"}, dict(row, unknown="value")):
        with pytest.raises(AplRoleUpdateContractError):
            AplRoleTransition(altered, transition.binding, **CONTEXT)
    row["description"] = "caller mutation"
    with pytest.raises(AplRoleUpdateContractError):
        build_role_transition_body(row, transition, phase="update", **CONTEXT)
    for value in (transition, transition.binding):
        assert "mcp-v4" not in repr(value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                operation(value)
        with pytest.raises(AplRoleUpdateContractError):
            setattr(value, "digest", "f" * 64)
    original, _ = fixture()
    with pytest.raises(AplRoleUpdateContractError):
        build_role_transition_body(original, transition, phase="restore", **CONTEXT)
