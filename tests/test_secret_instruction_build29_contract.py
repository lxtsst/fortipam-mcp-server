"""No material, foreign identity or drift enters an Instruction delta."""
from copy import deepcopy

import pytest

from fortipam_mcp import secret_instruction_build29_contract as c

IDENTITY: dict[str, object] = {
    "id": 7, "name": "mcp-v4-render-fixture", "folder": 3, "template": "Web Account",
}
PROFILE = "mcp-v4-ip-render"
SCHEMA = {"version": "v7.0.0", "build": 29, "selected_schema": {c.FIELD: {
    "type": "string", "size": 79, "default": "", "multiple_values": False,
    "datasource": ["secret.instruction-profile.name"],
}}}


def baseline() -> dict[str, object]:
    return {"version": "v7.0.0", "build": 29, "results": {**IDENTITY, c.FIELD: ""}}


def test_attach_and_exact_restore_compile_only_the_reference() -> None:
    original = baseline()
    body = c.compile_secret_instruction_build29_attach_body(
        original, schema=SCHEMA, identity=IDENTITY, instruction_profile_name=PROFILE,
    )
    assert body == {c.FIELD: PROFILE}
    applied = {**original, "results": {**IDENTITY, **body}}
    assert c.compile_secret_instruction_build29_restore_body(
        applied, original, schema=SCHEMA, identity=IDENTITY,
        instruction_profile_name=PROFILE,
    ) == {c.FIELD: ""}
    assert original == baseline()


@pytest.mark.parametrize("fault", [
    "credentials", "totp", "foreign-id", "foreign-template", "bool-id",
    "already-assigned", "null-reference", "untyped-profile", "schema-source",
    "schema-default", "schema-multiple", "schema-build",
])
def test_material_foreign_identity_and_unqualified_sources_are_rejected(fault: str) -> None:
    original, schema, identity, profile = baseline(), deepcopy(SCHEMA), dict(IDENTITY), PROFILE
    row = original["results"]
    assert isinstance(row, dict)
    if fault == "credentials": row["field"] = [{"value": "must-not-be-serialized"}]
    elif fault == "totp": row["totp-setting"] = {"shared-key": None}
    elif fault == "foreign-id": row["id"] = 8
    elif fault == "foreign-template": row["template"] = "Unix Account (SSH Password)"
    elif fault == "bool-id": identity["id"] = row["id"] = True
    elif fault == "already-assigned": row[c.FIELD] = "another-profile"
    elif fault == "null-reference": row[c.FIELD] = None
    elif fault == "untyped-profile": profile = "external-profile"
    elif fault == "schema-source": schema["selected_schema"][c.FIELD]["datasource"] = ["secret.other.name"]
    elif fault == "schema-default": schema["selected_schema"][c.FIELD]["default"] = None
    elif fault == "schema-multiple": schema["selected_schema"][c.FIELD]["multiple_values"] = 0
    elif fault == "schema-build": schema["build"] = True
    with pytest.raises(c.SecretInstructionBuild29ContractError) as caught:
        c.compile_secret_instruction_build29_attach_body(
            original, schema=schema, identity=identity, instruction_profile_name=profile,
        )
    assert PROFILE not in str(caught.value) and "must-not-be-serialized" not in str(caught.value)


def test_restore_rejects_replaced_reference() -> None:
    original = baseline()
    applied = {**original, "results": {**IDENTITY, c.FIELD: "other-profile"}}
    with pytest.raises(c.SecretInstructionBuild29ContractError):
        c.compile_secret_instruction_build29_restore_body(
            applied, original, schema=SCHEMA, identity=IDENTITY,
            instruction_profile_name=PROFILE,
        )
