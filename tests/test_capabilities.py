from __future__ import annotations

import pytest

from fortipam_mcp.capabilities import (
    DEFAULT_CAPABILITY_REGISTRY,
    ExecutionMode,
    ToolPack,
    get_capability_matrix,
)
from fortipam_mcp.mcp_smoke import LAB_EXPECTED_TOOLS


def test_registry_describes_the_exact_frozen_tool_surface() -> None:
    registry = DEFAULT_CAPABILITY_REGISTRY

    assert registry.tool_names == LAB_EXPECTED_TOOLS
    assert len(registry.capabilities) == 34
    assert all(capability.description for capability in registry.capabilities)
    assert all(capability.supported_product_versions for capability in registry.capabilities)
    diagnostic_tools = {
        "create_ha_diagnostic_baseline",
        "compare_ha_diagnostic_baseline",
        "correlate_ha_api_cli_posture",
    }
    lab_execute_tools = {"execute_confirmed_v31_lab_operation"}
    assert {
        capability.tool_name
        for capability in registry.capabilities
        if capability.annotation()["local_state_write"] is True
    } == diagnostic_tools | lab_execute_tools
    assert all(
        capability.annotation()["device_write"] is False
        for capability in registry.capabilities
    )
    assert all(capability.annotation()["destructive"] is False for capability in registry.capabilities)
    assert all(
        capability.annotation()["idempotent"] is (capability.tool_name not in diagnostic_tools)
        for capability in registry.capabilities
    )


def test_execution_mode_and_contact_invariants_are_explicit() -> None:
    capabilities = DEFAULT_CAPABILITY_REGISTRY.capabilities

    live_tools = {
        capability.tool_name
        for capability in capabilities
        if capability.execution_mode is ExecutionMode.LIVE
    }
    assert live_tools == {
        "get_overall_health_summary",
        "get_system_status_summary",
        "get_system_global_summary",
        "get_approval_profile_summary",
        "get_fortianalyzer_delivery_posture_summary",
        "get_license_support_posture_summary",
        "get_ha_configuration_posture_summary",
        "get_recording_storage_health_summary",
        "get_password_changer_configuration_posture_summary",
            "get_ems_connection_posture_summary",
            "get_cli_ha_configuration_summary",
            "get_cli_ha_status_summary",
            "get_cli_ha_checksum_summary",
            "create_ha_diagnostic_baseline",
            "compare_ha_diagnostic_baseline",
            "correlate_ha_api_cli_posture",
        }
    assert all(
        capability.contacts_fortipam
        is (capability.execution_mode is ExecutionMode.LIVE)
        for capability in capabilities
    )
    assert {
        capability.tool_name
        for capability in capabilities
        if capability.execution_mode is ExecutionMode.LAB_SIMULATED
    } == {
        "preview_v31_lab_public_folder",
        "preview_v31_lab_target",
        "preview_v31_lab_secret_metadata",
        "preview_v31_lab_local_user",
        "preview_v31_lab_folder_access_assignment",
        "execute_confirmed_v31_lab_operation",
    }


def test_sanitized_matrix_is_static_and_excludes_endpoint_and_secret_fields() -> None:
    matrix = get_capability_matrix()

    assert matrix["schema_version"] == "1.1"
    assert matrix["current_surface_only"] is True
    assert matrix["network_call_executed"] is False
    assert matrix["fortipam_contacted"] is False
    assert matrix["tool_count"] == 34
    assert {tool["tool_name"] for tool in matrix["tools"]} == set(
        LAB_EXPECTED_TOOLS
    )
    rendered = repr(matrix).lower()
    for forbidden in ("path", "parameter", "token", "credential", "host"):
        assert forbidden not in rendered


def test_pack_and_explicit_tool_filters_intersect_without_side_effects() -> None:
    selected = get_capability_matrix(
        enabled_packs=[ToolPack.APPROVAL_READ],
        enabled_tools=["plan_approval_profile_read", "get_system_status_summary"],
    )

    assert selected["tool_count"] == 1
    assert selected["tools"] == [
        {
            "tool_name": "plan_approval_profile_read",
            "description": "Validate the fixed approval-profile read plan.",
            "pack": "approval-read",
            "execution_mode": "plan",
            "risk_level": "low",
            "input_scope": "none",
            "supported_product_versions": ["1.9.1"],
            "contacts_fortipam": False,
            "device_write": False,
            "local_state_write": False,
            "read_only": True,
            "destructive": False,
            "idempotent": True,
        }
    ]


@pytest.mark.parametrize("invalid", (["unknown"], ["not-a-tool"]))
def test_filter_rejects_unknown_pack_or_tool(invalid: list[str]) -> None:
    with pytest.raises(ValueError):
        if invalid == ["unknown"]:
            get_capability_matrix(enabled_packs=invalid)
        else:
            get_capability_matrix(enabled_tools=invalid)
