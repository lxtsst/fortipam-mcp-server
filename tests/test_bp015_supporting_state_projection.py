from __future__ import annotations

from collections.abc import Callable
from dataclasses import fields
from typing import cast

import pytest

from v4_planning import (
    BP015AdminCategoricalInspection,
    BP015FolderAclCategoricalInspection,
    BP015ScheduleCategoricalInspection,
    BP015SecretApprovalCategoricalInspection,
    BP015SupportingStateProjection,
    BP015SupportingStateProjectionError,
    TemporaryAccessParentAssessment,
    build_bp015_supporting_state_projection,
)


def _projection(**overrides: bool) -> BP015SupportingStateProjection:
    values = {
        "sponsor_admin_exists": True,
        "member_exists": True,
        "member_status_recognized": True,
        "member_schedule_matches": True,
        "schedule_exists": True,
        "schedule_detail_matches": True,
        "recurring_window_observed": True,
        "folder_exists": True,
        "exact_group_acl_relation_observed": True,
        "folder_permission_observed": True,
        "secret_permission_observed": True,
        "secret_exists": True,
        "approval_posture_observed": True,
        "secret_field_values_absent": True,
    }
    values.update(overrides)
    return build_bp015_supporting_state_projection(
        BP015AdminCategoricalInspection(
            values["sponsor_admin_exists"], values["member_exists"],
            values["member_status_recognized"], values["member_schedule_matches"],
        ),
        BP015ScheduleCategoricalInspection(
            values["schedule_exists"], values["schedule_detail_matches"],
            values["recurring_window_observed"],
        ),
        BP015FolderAclCategoricalInspection(
            values["folder_exists"], values["exact_group_acl_relation_observed"],
            values["folder_permission_observed"], values["secret_permission_observed"],
        ),
        BP015SecretApprovalCategoricalInspection(
            values["secret_exists"], values["approval_posture_observed"],
            values["secret_field_values_absent"],
        ),
    )


def test_projection_is_partial_value_minimized_and_non_executable() -> None:
    projection = _projection()
    result = projection.as_dict()

    assert result["supporting_state_evidence"] == "partial"
    assert result["current_state_evidence"] == "unavailable"
    assert result["source_contract_ready"] is False
    assert result["execution_ready"] is False
    assert result["device_access"] is False
    assert result["dispatchable"] is False
    assert all(type(value) is bool for key, value in result.items() if key.endswith("observed") or key.endswith("matches") or key.endswith("absent"))
    assert len(cast(str, result["supporting_state_digest"])) == 64


@pytest.mark.parametrize("factory", [
    lambda: BP015AdminCategoricalInspection(True, True, True, 1),  # type: ignore[arg-type]
    lambda: BP015ScheduleCategoricalInspection(True, False, "false"),  # type: ignore[arg-type]
    lambda: BP015FolderAclCategoricalInspection(True, True, [], False),  # type: ignore[arg-type]
    lambda: BP015SecretApprovalCategoricalInspection(True, None, True),  # type: ignore[arg-type]
])
def test_inspections_reject_non_boolean_values(factory: Callable[[], object]) -> None:
    with pytest.raises(BP015SupportingStateProjectionError, match="boolean"):
        factory()


@pytest.mark.parametrize("changed_field", [
    "sponsor_admin_exists",
    "member_exists",
    "member_status_recognized",
    "member_schedule_matches",
    "schedule_exists",
    "schedule_detail_matches",
    "recurring_window_observed",
    "folder_exists",
    "exact_group_acl_relation_observed",
    "folder_permission_observed",
    "secret_permission_observed",
    "secret_exists",
    "approval_posture_observed",
    "secret_field_values_absent",
])
def test_digest_changes_with_each_categorical_fact(changed_field: str) -> None:
    baseline = _projection()
    changed = _projection(**{changed_field: False})

    assert baseline.supporting_state_digest != changed.supporting_state_digest


def test_partial_projection_cannot_promote_parent_current_state() -> None:
    projection = _projection()
    parent = TemporaryAccessParentAssessment(
        sponsor_ref="temporary-sponsor-reference01",
        group_ref="temporary-group-reference01",
        entitlement_boundary_ref="temporary-entitlement-ref01",
        scope_ref="temporary-scope-reference01",
        end_date_ref="temporary-end-date-reference01",
        revocation_owner_ref="temporary-revocation-owner01",
        evidence_owner_ref="temporary-evidence-owner-ref01",
        review_cadence_code="monthly",
        negative_test="denied_after_expiry",
    )

    assert projection.current_state_evidence == "unavailable"
    assert parent.current_state_evidence == "unavailable"
    assert parent.execution_ready is False


@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"member_exists": False}, "member_status_observed"),
        ({"member_exists": False}, "member_schedule_matches"),
        ({"schedule_exists": False}, "member_schedule_matches"),
        ({"schedule_exists": False}, "recurring_window_observed"),
        ({"schedule_detail_matches": False}, "recurring_window_observed"),
        ({"secret_exists": False}, "secret_field_values_absent"),
    ],
)
def test_dependent_facts_fail_closed_when_their_source_is_absent(
    overrides: dict[str, bool], field: str,
) -> None:
    assert _projection(**overrides).as_dict()[field] is False


def test_inputs_and_outputs_cannot_retain_selectors_or_raw_response_values() -> None:
    input_types = (
        BP015AdminCategoricalInspection,
        BP015ScheduleCategoricalInspection,
        BP015FolderAclCategoricalInspection,
        BP015SecretApprovalCategoricalInspection,
    )
    for input_type in input_types:
        assert all(type(field.type) is type(bool) or field.type == "bool" for field in fields(input_type))
    result = _projection().as_dict()
    assert not {"name", "ref", "id", "raw", "mapping"} & set(result)
