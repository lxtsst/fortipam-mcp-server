from __future__ import annotations

from fortipam_mcp.scim_client_plan import (
    V4_SCIM_CLIENT_CREATE_PLAN_CONTRACT,
    V4_SCIM_CLIENT_DISABLE_PLAN_CONTRACT,
    V4_SCIM_CLIENT_ROTATE_PLAN_CONTRACT,
    scim_client_create_plan_requirements,
    scim_client_disable_plan_requirements,
    scim_client_rotate_plan_requirements,
)


def _assert_common_boundary(result: dict[str, object]) -> None:
    assert result["source_version"] == "1.9.0"
    assert result["target_version"] == "1.9.1"
    assert result["target_version_validation_required"] is True
    assert result["planning_status"] == "requirements_only"
    assert result["configuration_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["scim_system_contacted"] is False
    assert result["protected_material_loaded"] is False
    assert result["provisioning_effect_applied"] is False
    assert result["local_state_written"] is False
    assert result["raw_source_content_returned"] is False


def test_scim_client_create_plan_is_version_bounded_and_non_executable() -> None:
    result = scim_client_create_plan_requirements()
    _assert_common_boundary(result)
    assert result["contract"] == V4_SCIM_CLIENT_CREATE_PLAN_CONTRACT
    assert result["action_family"] == "scim-client.create"
    assert "scim_request_connection_or_tls_test" in result["blocked_operations"]


def test_scim_client_rotate_plan_is_version_bounded_and_non_executable() -> None:
    result = scim_client_rotate_plan_requirements()
    _assert_common_boundary(result)
    assert result["contract"] == V4_SCIM_CLIENT_ROTATE_PLAN_CONTRACT
    assert result["action_family"] == "scim-client.rotate"


def test_scim_client_disable_plan_is_version_bounded_and_non_executable() -> None:
    result = scim_client_disable_plan_requirements()
    _assert_common_boundary(result)
    assert result["contract"] == V4_SCIM_CLIENT_DISABLE_PLAN_CONTRACT
    assert result["action_family"] == "scim-client.disable"
    assert "user_provision_update_deprovision_or_session_termination" in result[
        "blocked_operations"
    ]


def test_scim_client_plan_results_return_fresh_mutable_collections() -> None:
    first = scim_client_create_plan_requirements()
    second = scim_client_create_plan_requirements()
    first["documented_requirements"].clear()  # type: ignore[union-attr]
    assert second["documented_requirements"]
