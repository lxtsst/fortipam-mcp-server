from __future__ import annotations

from fortipam_mcp.glass_break_plan import (
    V4_GLASS_BREAK_PLAN_CONTRACT,
    glass_break_plan_requirements,
)


def test_glass_break_plan_is_value_free_and_non_executable() -> None:
    result = glass_break_plan_requirements()

    assert result["contract"] == V4_GLASS_BREAK_PLAN_CONTRACT
    assert result["action_family"] == "glass-break.activate"
    assert result["target_version"] == "1.9.1"
    assert result["planning_status"] == "requirements_only"
    assert result["activation_ready"] is False
    assert result["access_elevated"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["local_state_written"] is False
    assert result["protected_material_accepted"] is False
    assert result["secret_material_returned"] is False
    assert result["raw_source_content_returned"] is False
    assert set(result["blocked_operations"]) == {
        "device_state_read",
        "identity_role_reason_or_incident_input",
        "glass_break_permission_change",
        "glass_break_activation",
        "glass_break_deactivation",
        "folder_secret_or_request_enumeration",
        "credential_or_clear_text_access",
        "secret_launch",
        "notification_configuration_or_delivery",
        "session_recording_change",
        "execution_authorization",
    }


def test_glass_break_plan_returns_fresh_mutable_collections() -> None:
    first = glass_break_plan_requirements()
    second = glass_break_plan_requirements()

    first["documented_requirements"].clear()  # type: ignore[union-attr]
    first["project_acceptance_requirements"].clear()  # type: ignore[union-attr]

    assert second["documented_requirements"]
    assert second["project_acceptance_requirements"]
