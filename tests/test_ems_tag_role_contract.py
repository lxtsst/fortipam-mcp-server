"""A prospective role DTO cannot inherit or invent elevated permissions."""
from dataclasses import replace

import pytest

from fortipam_mcp.ems_tag_role_contract import (
    EmsTagRolePermissionSchema,
    ProspectiveEmsTagManagerRole,
    _PERMISSION_LABELS,
    qualify_permission_schema,
    qualify_role_detail,
)


def permissions():
    result = {label: label.lower() for label in _PERMISSION_LABELS}
    result.update(SUPER="is_super", MANAGE_COMPLIANCE_VERIFICATION_RULES="manage_host_verification_rules",
                  VIEW_COMPLIANCE_VERIFICATION_RULES="view_host_verification_rules")
    return result


def test_new_role_grants_only_the_complete_native_tag_permission_closure():
    source = permissions()
    schema = qualify_permission_schema(source)
    draft = ProspectiveEmsTagManagerRole(schema, "a" * 32)
    body = draft._body
    assert len(body) == 48 and "super" not in body and "is_super" not in body
    assert {key for key, value in body.items() if value is True} == {
        "manage_host_verification_rules", "view_host_verification_rules", "view_group_assignment"}
    assert all(value is False for key, value in body.items() if key not in {
        "name", "description", "manage_host_verification_rules",
        "view_host_verification_rules", "view_group_assignment"})
    original = draft.parameters_digest
    source["SUPER"] = "other"
    body["is_super"] = True
    body["view_group_assignment"] = False
    assert draft.parameters_digest == original and "is_super" not in draft._body
    assert draft._body["name"] not in repr(draft) + repr(schema)


@pytest.mark.parametrize("fault", ["missing", "unknown", "alias", "super_literal", "bool", "case"])
def test_schema_drift_or_permission_redirection_refuses_before_a_draft(fault):
    value = permissions()
    if fault == "missing": value.pop("VIEW_GROUP_ASSIGNMENT")
    elif fault == "unknown": value["NEW_PERMISSION"] = "new_permission"
    elif fault == "alias": value["MANAGE_COMPLIANCE_VERIFICATION_RULES"] = value["VIEW_GROUP_ASSIGNMENT"]
    elif fault == "super_literal": value["MANAGE_COMPLIANCE_VERIFICATION_RULES"] = "is_super"
    elif fault == "bool": value["MANAGE_COMPLIANCE_VERIFICATION_RULES"] = True
    else: value["VIEW_GROUP_ASSIGNMENT"] = "VIEW_GROUP_ASSIGNMENT"
    with pytest.raises(ValueError, match="^The prospective EMS tag-manager role is unavailable\\.$"):
        qualify_permission_schema(value)


def test_invalid_nonce_or_replaced_schema_cannot_render_a_proposal():
    schema = qualify_permission_schema(permissions())
    with pytest.raises(ValueError): ProspectiveEmsTagManagerRole(schema, "../role")
    with pytest.raises(ValueError): EmsTagRolePermissionSchema(tuple("super" for _ in schema._wire))
    with pytest.raises(ValueError): replace(ProspectiveEmsTagManagerRole(schema, "a" * 32), schema=None)


def test_complete_role_detail_keeps_both_identifiers_and_requires_every_permission():
    schema = qualify_permission_schema(permissions())
    draft = ProspectiveEmsTagManagerRole(schema, "a" * 32)
    row = {**draft._body, "id": 17, "uid": "synthetic-route-uid", "is_super": False, "is_built_in": False}
    detail = qualify_role_detail(row, schema)
    assert detail._numeric_id == 17 and detail._uid == "synthetic-route-uid"
    assert detail.matches_proposal(draft)
    original = detail.digest
    assert "synthetic-route-uid" not in repr(detail)
    row["is_super"] = True
    assert detail.digest == original and detail.matches_proposal(draft)
    assert not qualify_role_detail(row, schema).matches_proposal(draft)
    row["is_super"] = False
    row["view_group_assignment"] = False
    assert not qualify_role_detail(row, schema).matches_proposal(draft)
    row["view_group_assignment"] = True
    for key, value in [("id", True), ("id", "17"), ("uid", 17), ("uid", "../route"),
                       ("is_built_in", 0), ("view_group_assignment", 1), ("id", 0)]:
        with pytest.raises(ValueError): qualify_role_detail({**row, key: value}, schema)
    with pytest.raises(ValueError): qualify_role_detail({key: value for key, value in row.items() if key != "id"}, schema)
    with pytest.raises(ValueError): qualify_role_detail({**row, "foreign": False}, schema)
    with pytest.raises(ValueError): replace(detail, _raw=detail._raw.replace(b'"id":17', b'"id":true'))
