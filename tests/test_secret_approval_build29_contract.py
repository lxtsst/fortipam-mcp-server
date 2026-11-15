from __future__ import annotations

from copy import deepcopy

import pytest

from fortipam_mcp.secret_approval_build29_contract import (
    APPROVAL_FIELDS,
    SecretApprovalBuild29ContractError,
    compile_secret_approval_build29_enable_body,
    compile_secret_approval_build29_restore_body,
    qualify_secret_approval_build29_schema,
)


_PROFILE = "mcp-v4-approval-profile-unit01"
_IDENTITY: dict[str, object] = {
    "id": 24, "folder": 17, "name": "mcp-v4-bp008-approval-unit01",
}
_BASELINE = {
    "need-approval": "disable", "need-approval-job": "disable",
    "bypass-approval": "disable", "approval-profile": "",
}


def _schema() -> dict[str, object]:
    selected: dict[str, dict[str, object]] = {}
    for name in APPROVAL_FIELDS:
        member: dict[str, object] = {
            "name": name, "category": "unitary", "multiple_values": False,
            "default": _BASELINE[name], "help": "Unit-test schema description.",
            "type": "string" if name == "approval-profile" else "option",
        }
        if name != "bypass-approval":
            member["required"] = True
        if name == "approval-profile":
            member.update(size=79, datasource=["secret.approval-profile.name"])
        else:
            member["options"] = [
                {"name": value, "help": "Unit-test enum description."}
                for value in ("enable", "disable")
            ]
        selected[name] = member
    return {"version": "v7.0.0", "build": 29, "selected_schema": selected}


def _metadata(*, applied: bool = False) -> dict[str, object]:
    fields = {**_BASELINE, "need-approval": "enable", "approval-profile": _PROFILE} if applied else _BASELINE
    return {
        "version": "v7.0.0", "build": 29,
        "results": {**_IDENTITY, **fields, "field": None},
    }


@pytest.mark.parametrize("original_bypass", ["disable", "enable"])
def test_fixed_enable_and_same_binding_restore_emit_only_preserved_four_fields(original_bypass: str) -> None:
    baseline = _metadata()
    row = baseline["results"]
    assert isinstance(row, dict)
    row["bypass-approval"] = original_bypass
    applied = _metadata(applied=True)
    applied_row = applied["results"]
    assert isinstance(applied_row, dict)
    applied_row["bypass-approval"] = original_bypass
    before = deepcopy(baseline)
    proposed = compile_secret_approval_build29_enable_body(
        baseline, schema=_schema(), identity=_IDENTITY, approval_profile_name=_PROFILE,
    )
    restored = compile_secret_approval_build29_restore_body(
        applied, baseline, schema=_schema(), identity=_IDENTITY, approval_profile_name=_PROFILE,
    )
    assert proposed == {**_BASELINE, "need-approval": "enable", "bypass-approval": original_bypass, "approval-profile": _PROFILE}
    assert restored == {**_BASELINE, "bypass-approval": original_bypass}
    assert set(proposed) == set(restored) == APPROVAL_FIELDS
    assert baseline == before
    restored["need-approval"] = "enable"
    assert baseline == before


@pytest.mark.parametrize(
    ("field", "member", "value"),
    [
        ("approval-profile", "size", 80),
        ("approval-profile", "datasource", ["secret.database.name"]),
        ("approval-profile", "default", "other-profile"),
        ("approval-profile", "type", "option"),
        ("need-approval", "options", [{"name": "enable", "help": "x"}]),
        ("need-approval-job", "default", "enable"),
        ("bypass-approval", "multiple_values", True),
        ("need-approval", "required", False),
        ("need-approval", "category", "other"),
        ("bypass-approval", "extra", "unknown"),
    ],
)
def test_schema_rejects_semantic_and_shape_drift(field: str, member: str, value: object) -> None:
    schema = _schema()
    selected = schema["selected_schema"]
    assert isinstance(selected, dict)
    selected[field][member] = value
    with pytest.raises(SecretApprovalBuild29ContractError, match="unavailable"):
        qualify_secret_approval_build29_schema(schema)


@pytest.mark.parametrize(("key", "value"), [("version", "v1.9.1"), ("build", 30), ("build", True)])
def test_schema_rejects_version_drift(key: str, value: object) -> None:
    schema = _schema()
    schema[key] = value
    with pytest.raises(SecretApprovalBuild29ContractError):
        qualify_secret_approval_build29_schema(schema)


@pytest.mark.parametrize(
    ("key", "value"),
    [("version", "v1.9.1"), ("build", 30), ("build", True),
     ("http_status", 200), ("field", [{"value": "unit-test-material"}]),
     ("keyinfo", "unit-test-material"), ("unknown", "extra")],
)
def test_enable_rejects_minimized_projection_drift(key: str, value: object) -> None:
    baseline = _metadata()
    baseline[key] = value
    with pytest.raises(SecretApprovalBuild29ContractError):
        compile_secret_approval_build29_enable_body(
            baseline, schema=_schema(), identity=_IDENTITY, approval_profile_name=_PROFILE,
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [(key, value) for key in ("need-approval", "need-approval-job", "bypass-approval")
     for value in (None, "unknown", True)]
    + [(key, "enable") for key in ("need-approval", "need-approval-job")]
    + [("approval-profile", "foreign-profile"), ("approval-profile", None),
       ("id", 25), ("id", True), ("name", "other-secret"), ("folder", 18),
       ("field", [{"value": "unit-test-material"}]), ("keyinfo", {"value": "unit-test-material"}),
       ("q_origin_key", "25"), ("unknown", "extra")],
)
def test_enable_rejects_identity_control_and_material_drift(key: str, value: object) -> None:
    baseline = _metadata()
    row = baseline["results"]
    assert isinstance(row, dict)
    row[key] = value
    with pytest.raises(SecretApprovalBuild29ContractError):
        compile_secret_approval_build29_enable_body(
            baseline, schema=_schema(), identity=_IDENTITY, approval_profile_name=_PROFILE,
        )


@pytest.mark.parametrize("key", sorted(APPROVAL_FIELDS | {"id", "name", "folder"}))
def test_enable_rejects_missing_identity_or_control(key: str) -> None:
    baseline = _metadata()
    row = baseline["results"]
    assert isinstance(row, dict)
    row.pop(key)
    with pytest.raises(SecretApprovalBuild29ContractError):
        compile_secret_approval_build29_enable_body(
            baseline, schema=_schema(), identity=_IDENTITY, approval_profile_name=_PROFILE,
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [("need-approval", "disable"), ("need-approval-job", "enable"),
     ("bypass-approval", "enable"), ("approval-profile", "foreign-profile"),
     ("id", 25), ("folder", 18), ("name", "other-secret")],
)
def test_restore_rejects_any_applied_tuple_or_binding_drift(key: str, value: object) -> None:
    applied = _metadata(applied=True)
    row = applied["results"]
    assert isinstance(row, dict)
    row[key] = value
    with pytest.raises(SecretApprovalBuild29ContractError):
        compile_secret_approval_build29_restore_body(
            applied, _metadata(), schema=_schema(), identity=_IDENTITY, approval_profile_name=_PROFILE,
        )


def test_restore_rejects_disabled_bypass_drift_from_enabled_baseline() -> None:
    baseline = _metadata()
    row = baseline["results"]
    assert isinstance(row, dict)
    row["bypass-approval"] = "enable"
    with pytest.raises(SecretApprovalBuild29ContractError):
        compile_secret_approval_build29_restore_body(
            _metadata(applied=True), baseline, schema=_schema(), identity=_IDENTITY, approval_profile_name=_PROFILE,
        )


@pytest.mark.parametrize("profile", ["production-profile", "mcp-v4-approval-profile-", "mcp-v4-approval-profile-" + "a" * 41])
def test_enable_rejects_unbounded_or_foreign_profile_name(profile: str) -> None:
    with pytest.raises(SecretApprovalBuild29ContractError):
        compile_secret_approval_build29_enable_body(
            _metadata(), schema=_schema(), identity=_IDENTITY, approval_profile_name=profile,
        )
