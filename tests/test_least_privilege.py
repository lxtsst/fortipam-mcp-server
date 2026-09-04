from __future__ import annotations

from copy import deepcopy

from fortipam_mcp.least_privilege import (
    ACCESS_CATEGORY_FIELDS,
    REQUIRED_CUSTOM_PERMISSIONS,
    ROUTE_PERMISSION_HYPOTHESIS,
    SAFE_PROFILE_CONTROLS,
    V16_REQUIRED_CUSTOM_PERMISSIONS,
    V16_ROUTE_PERMISSION_HYPOTHESIS,
    V17_ROUTE_PERMISSION_HYPOTHESIS,
    desired_access_profile,
    desired_access_profile_v16,
    desired_access_profile_v17,
    evaluate_access_profile,
    evaluate_access_profile_v16,
    evaluate_access_profile_v17,
    evaluate_live_authorization,
    evaluate_live_authorization_v16,
    evaluate_live_authorization_v17,
)


def test_desired_access_profile_is_custom_only_for_required_categories() -> None:
    profile = desired_access_profile()

    assert set(ROUTE_PERMISSION_HYPOTHESIS) == {
        "system_status",
        "system_global",
        "approval_profile",
        "fortianalyzer_delivery",
        "license_support",
        "ha_configuration",
        "recording_storage",
    }
    assert {
        category for category in ACCESS_CATEGORY_FIELDS if profile[category] == "custom"
    } == set(REQUIRED_CUSTOM_PERMISSIONS)
    assert {
        category for category in ACCESS_CATEGORY_FIELDS if profile[category] == "none"
    } == set(ACCESS_CATEGORY_FIELDS) - set(REQUIRED_CUSTOM_PERMISSIONS)
    for field, value in SAFE_PROFILE_CONTROLS.items():
        assert profile[field] == value


def test_access_profile_evaluator_accepts_exact_candidate_shape_only() -> None:
    result = evaluate_access_profile(desired_access_profile())

    assert result["candidate_profile_shape_confirmed"] is True
    assert result["required_custom_subpermission_count"] == 6
    assert result["broad_top_level_access_count"] == 0
    assert result["reason_codes"] == []
    assert result["route_authorization_mapping_verified"] is False


def test_access_profile_evaluator_rejects_broad_and_unexpected_access() -> None:
    profile = deepcopy(desired_access_profile())
    profile["sysgrp"] = "read"
    secret_permissions = profile["secretgrp-permission"]
    assert isinstance(secret_permissions, dict)
    secret_permissions["pwd-changer"] = "read"

    result = evaluate_access_profile(profile)

    assert result["candidate_profile_shape_confirmed"] is False
    assert result["broad_top_level_access_count"] == 1
    assert result["unexpected_custom_subpermission_access_count"] == 1
    assert "BROAD_READ_PERMISSION_CATEGORIES_PRESENT" in result["reason_codes"]
    assert "UNEXPECTED_CUSTOM_SUBPERMISSION_ACCESS_PRESENT" in result["reason_codes"]


def test_access_profile_evaluator_rejects_safety_control_drift() -> None:
    profile = desired_access_profile()
    profile["cli"] = "enable"

    result = evaluate_access_profile(profile)

    assert result["candidate_profile_shape_confirmed"] is False
    assert result["safety_control_mismatch_count"] == 1
    assert "SAFETY_CONTROL_SHAPE_MISMATCH" in result["reason_codes"]


def test_live_authorization_accepts_exact_positive_and_negative_matrix() -> None:
    result = evaluate_live_authorization(
        (200, 200, 200, 200, 200, 200, 200),
        (403, 403, 403, 403, 403),
    )

    assert result["candidate_operationally_accepted"] is True
    assert result["route_authorization_mapping_verified_in_lab"] is True
    assert result["vendor_route_authorization_contract_claimed"] is False
    assert result["reason_codes"] == []


def test_live_authorization_fails_closed_on_unrelated_read() -> None:
    result = evaluate_live_authorization(
        (200, 200, 200, 200, 200, 200, 200),
        (403, 403, 200, 403, 403),
    )

    assert result["candidate_operationally_accepted"] is False
    assert result["negative_route_failure_count"] == 1
    assert "UNRELATED_ROUTE_NOT_DENIED" in result["reason_codes"]


def test_v16_profile_adds_only_password_changer_read_to_v15_shape() -> None:
    v15 = desired_access_profile()
    v16 = desired_access_profile_v16()

    assert set(V16_ROUTE_PERMISSION_HYPOTHESIS) == set(ROUTE_PERMISSION_HYPOTHESIS) | {
        "password_changer_configuration"
    }
    assert sum(len(fields) for fields in V16_REQUIRED_CUSTOM_PERMISSIONS.values()) == 7
    assert v15["secretgrp-permission"]["pwd-changer"] == "none"  # type: ignore[index]
    assert v16["secretgrp-permission"]["pwd-changer"] == "read"  # type: ignore[index]
    assert evaluate_access_profile(v16)["candidate_profile_shape_confirmed"] is False
    result = evaluate_access_profile_v16(v16)
    assert result["candidate_profile_shape_confirmed"] is True
    assert result["required_custom_subpermission_count"] == 7


def test_v16_live_authorization_requires_eight_positive_and_eleven_denials() -> None:
    accepted = evaluate_live_authorization_v16(
        (200, 200, 200, 200, 200, 200, 200, 200),
        (403,) * 11,
    )
    assert accepted["candidate_operationally_accepted"] is True

    failed = evaluate_live_authorization_v16(
        (200, 200, 200, 200, 200, 200, 200, 200),
        (403,) * 10 + (200,),
    )
    assert failed["candidate_operationally_accepted"] is False
    assert failed["negative_route_failure_count"] == 1


def test_v17_profile_adds_only_the_required_security_fabric_read() -> None:
    v16 = desired_access_profile_v16()
    v17 = desired_access_profile_v17()

    assert set(V17_ROUTE_PERMISSION_HYPOTHESIS) == set(
        V16_ROUTE_PERMISSION_HYPOTHESIS
    ) | {"ems_connection"}
    assert v16["secfabgrp"] == "none"
    assert v17["secfabgrp"] == "read"
    assert evaluate_access_profile_v16(v17)["candidate_profile_shape_confirmed"] is False
    result = evaluate_access_profile_v17(v17)
    assert result["candidate_profile_shape_confirmed"] is True
    assert result["broad_top_level_access_count"] == 1
    assert result["accepted_broad_read_category_count"] == 1
    assert result["broad_read_residual_risk_present"] is True
    assert result["reason_codes"] == []


def test_v17_profile_rejects_any_second_broad_category() -> None:
    profile = desired_access_profile_v17()
    profile["authgrp"] = "read"

    result = evaluate_access_profile_v17(profile)

    assert result["candidate_profile_shape_confirmed"] is False
    assert result["broad_top_level_access_count"] == 2
    assert "BROAD_READ_PERMISSION_CATEGORIES_PRESENT" in result["reason_codes"]


def test_v17_live_authorization_requires_nine_positive_and_eleven_denials() -> None:
    accepted = evaluate_live_authorization_v17((200,) * 9, (403,) * 11)
    assert accepted["candidate_operationally_accepted"] is True

    failed = evaluate_live_authorization_v17((200,) * 8 + (403,), (403,) * 11)
    assert failed["candidate_operationally_accepted"] is False
    assert failed["required_route_failure_count"] == 1
