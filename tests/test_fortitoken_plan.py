from __future__ import annotations

from fortipam_mcp.fortitoken_plan import (
    V4_FORTITOKEN_ASSIGN_PLAN_CONTRACT,
    V4_FORTITOKEN_REVOKE_PLAN_CONTRACT,
    fortitoken_assign_plan_requirements,
    fortitoken_revoke_plan_requirements,
)


def _assert_common_boundary(result: dict[str, object]) -> None:
    assert result["source_version"] == "1.9.0"
    assert result["target_version"] == "1.9.1"
    assert result["target_version_validation_required"] is True
    assert result["planning_status"] == "requirements_only"
    assert result["configuration_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["forticloud_contacted"] is False
    assert result["mobile_service_contacted"] is False
    assert result["protected_material_loaded"] is False
    assert result["mfa_effect_applied"] is False
    assert result["notification_sent"] is False
    assert result["local_state_written"] is False
    assert result["raw_source_content_returned"] is False


def test_fortitoken_assign_plan_is_version_bounded_and_non_executable() -> None:
    result = fortitoken_assign_plan_requirements()
    _assert_common_boundary(result)
    assert result["contract"] == V4_FORTITOKEN_ASSIGN_PLAN_CONTRACT
    assert result["action_family"] == "fortitoken.assign"
    assert "login_mfa_push_or_otp_test" in result["blocked_operations"]


def test_fortitoken_revoke_plan_is_version_bounded_and_non_executable() -> None:
    result = fortitoken_revoke_plan_requirements()
    _assert_common_boundary(result)
    assert result["contract"] == V4_FORTITOKEN_REVOKE_PLAN_CONTRACT
    assert result["action_family"] == "fortitoken.revoke"
    assert "user_two_factor_assignment_change" in result["blocked_operations"]


def test_fortitoken_plan_results_return_fresh_mutable_collections() -> None:
    first = fortitoken_assign_plan_requirements()
    second = fortitoken_assign_plan_requirements()
    first["documented_requirements"].clear()  # type: ignore[union-attr]
    assert second["documented_requirements"]
