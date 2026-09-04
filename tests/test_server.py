from __future__ import annotations

import asyncio
import logging

from mcp import Client

from fortipam_mcp.config import ConfigurationError
from fortipam_mcp.env import EnvironmentLoadReport
from fortipam_mcp.mcp_smoke import EXPECTED_TOOLS, LAB_EXPECTED_TOOLS
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp import server as server_module


def test_mcp_v2_registers_expected_tools_without_live_configuration(monkeypatch) -> None:
    environment_loads = 0

    def _load_environment() -> EnvironmentLoadReport:
        nonlocal environment_loads
        environment_loads += 1
        return EnvironmentLoadReport(source="test", loaded=False)

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _load_environment,
    )

    def _unconfigured():
        raise ConfigurationError("test-only unconfigured server")

    monkeypatch.setattr(server_module, "load_config", _unconfigured)
    server = server_module.FortiPamMcpServer()

    assert environment_loads == 0

    async def _list_tools() -> tuple[dict[str, dict], dict[str, object]]:
        async with Client(server.mcp) as client:
            result = await client.list_tools()
            return (
                {tool.name: tool.input_schema for tool in result.tools},
                {tool.name: tool.annotations for tool in result.tools},
            )

    schemas, annotations = asyncio.run(_list_tools())
    assert set(schemas) == set(EXPECTED_TOOLS)
    local_state_tools = set(server_module.DIAGNOSTIC_TOOLS)
    for tool_name in EXPECTED_TOOLS:
        assert schemas[tool_name].get("additionalProperties") is False
        annotation = annotations[tool_name]
        assert annotation is not None
        assert annotation.read_only_hint is (tool_name not in local_state_tools)
        assert annotation.destructive_hint is False
        assert annotation.idempotent_hint is (tool_name not in set(server_module.DIAGNOSTIC_TOOLS))
        assert annotation.open_world_hint is False
    for tool_name in set(server_module.LIVE_TOOLS) - {
        "create_ha_diagnostic_baseline",
        "compare_ha_diagnostic_baseline",
    }:
        assert schemas[tool_name].get("properties") == {}
        assert schemas[tool_name].get("required", []) == []
    for tool_name in (
        "create_ha_diagnostic_baseline",
        "compare_ha_diagnostic_baseline",
    ):
        assert set(schemas[tool_name].get("properties", {})) == {"baseline_id"}
        assert schemas[tool_name].get("required") == ["baseline_id"]
    assert set(schemas).isdisjoint(server_module.LAB_ADMIN_TOOLS)
    assert environment_loads == 0


def test_lab_simulated_profile_registers_exact_lab_surface_without_credentials(
    monkeypatch,
) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Listing LAB tools must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.LAB_SIMULATED
    )

    async def _list_tools() -> dict[str, dict]:
        async with Client(server.mcp) as client:
            result = await client.list_tools()
        return {tool.name: tool.input_schema for tool in result.tools}

    schemas = asyncio.run(_list_tools())
    assert set(schemas) == set(LAB_EXPECTED_TOOLS)
    assert len(schemas) == 34
    assert set(server_module.LAB_ADMIN_PREVIEW_TOOLS) == {
        "preview_v31_lab_public_folder",
        "preview_v31_lab_target",
        "preview_v31_lab_secret_metadata",
        "preview_v31_lab_local_user",
        "preview_v31_lab_folder_access_assignment",
    }
    expected_lab_preview_schemas = {
        "preview_v31_lab_public_folder": {
            "folder_ref",
            "parent_folder_ref",
            "folder_type",
            "folder_permission",
            "vault_permission",
            "allowed_launcher_type",
            "vault_policy_ref",
            "user_permission",
            "group_permission",
        },
        "preview_v31_lab_target": {
            "target_ref",
            "target_class",
            "template_ref",
            "address_ref",
            "gateway_ref",
        },
        "preview_v31_lab_secret_metadata": {
            "secret_ref",
            "name_ref",
            "folder_ref",
            "template_ref",
            "target_ref",
            "field_desc_ref",
        },
        "preview_v31_lab_local_user": {
            "user_ref",
            "name_ref",
            "status",
            "access_profile_ref",
            "display_name_ref",
            "comments_ref",
            "schedule_ref",
            "two_factor",
        },
        "preview_v31_lab_folder_access_assignment": {
            "assignment_ref",
            "folder_ref",
            "subject_ref",
            "folder_permission",
            "vault_permission",
            "allowed_launcher_type",
        },
    }
    for tool_name, expected_properties in expected_lab_preview_schemas.items():
        assert set(schemas[tool_name].get("properties", {})) == expected_properties
        expected_required = (
            expected_properties - {"vault_policy_ref", "user_permission", "group_permission"}
            if tool_name == "preview_v31_lab_public_folder"
            else expected_properties
        )
        assert sorted(schemas[tool_name].get("required", [])) == sorted(expected_required)
    assert set(schemas[server_module.LAB_ADMIN_EXECUTE_TOOL].get("properties", {})) == {
        "confirmation_token",
        "confirmation_digest",
        "idempotency_key",
    }
    assert schemas[server_module.LAB_ADMIN_EXECUTE_TOOL].get("required") == [
        "confirmation_token",
        "confirmation_digest",
        "idempotency_key",
    ]


def test_live_tool_rejects_unknown_input_before_loading_credentials(monkeypatch) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Rejected tool input must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer()

    async def _call_tool() -> bool:
        async with Client(server.mcp) as client:
            result = await client.call_tool(
                "get_system_status_summary",
                {"path": "/not-authorized-negative-test"},
            )
        return result.is_error

    assert asyncio.run(_call_tool()) is True


def test_cli_tools_are_no_input_and_dispatch_only_to_fixed_methods(monkeypatch) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Injected CLI tools must not reload credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer()

    class _FixedCliTools:
        async def get_ha_configuration_summary(self) -> dict[str, object]:
            return {"workflow_id": "ha_configuration", "raw_cli_returned": False}

        async def get_ha_status_summary(self) -> dict[str, object]:
            return {"workflow_id": "ha_status", "raw_cli_returned": False}

        async def get_ha_checksum_summary(self) -> dict[str, object]:
            return {"workflow_id": "ha_checksum", "raw_cli_returned": False}

    server._cli_tools = _FixedCliTools()  # type: ignore[assignment]

    async def _call_tools() -> list[dict]:
        async with Client(server.mcp) as client:
            results = []
            for name in server_module.CLI_TOOLS:
                result = await client.call_tool(name, {})
                results.append(result.structured_content)
            rejected = await client.call_tool(
                "get_cli_ha_configuration_summary", {"command": "show full-configuration"}
            )
            assert rejected.is_error is True
        return results

    results = asyncio.run(_call_tools())
    assert [result["workflow_id"] for result in results] == [
        "ha_configuration",
        "ha_status",
        "ha_checksum",
    ]
    assert all(result["raw_cli_returned"] is False for result in results)


def test_server_info_distinguishes_live_tools_from_fixed_routes(monkeypatch) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Server metadata must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer()

    async def _call_tool() -> dict:
        async with Client(server.mcp) as client:
            result = await client.call_tool("get_server_info", {})
        return result.structured_content

    info = asyncio.run(_call_tool())

    assert info["version"] == "3.1.3"
    assert info["compiled_fortipam_route_count"] == 9
    assert info["compiled_cli_workflow_count"] == 3
    assert info["live_tools"] == list(server_module.LIVE_TOOLS)
    assert len(info["live_tools"]) == 16
    assert info["device_write_enabled"] is False
    assert info["runtime_profile"] == "readonly"
    assert info["lab_admin_enabled"] is False
    assert info["lab_admin_tool_count"] == 0
    assert info["credential_source_loaded"] is False


def test_lab_admin_tools_are_in_memory_and_never_load_credentials(monkeypatch) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("LAB administrative tools must not load credentials.")

    monkeypatch.setattr(server_module, "load_runtime_environment", _unexpected_environment_load)
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.LAB_SIMULATED
    )

    async def _preview_and_execute() -> tuple[dict, dict]:
        async with Client(server.mcp) as client:
            preview = await client.call_tool(
                "preview_v31_lab_public_folder",
                {
                    "folder_ref": "folder-ref-lab-01",
                    "parent_folder_ref": "folder-ref-root-01",
                    "folder_type": "public",
                    "folder_permission": "manage",
                    "vault_permission": "use",
                    "allowed_launcher_type": "ssh",
                },
            )
            assert preview.is_error is False
            body = preview.structured_content
            execute = await client.call_tool(
                "execute_confirmed_v31_lab_operation",
                {
                    "confirmation_token": body["confirmation_token"],
                    "confirmation_digest": body["confirmation_digest"],
                    "idempotency_key": "idempotency-key-mcp-lab-0001",
                },
            )
            assert execute.is_error is False
        return body, execute.structured_content

    preview, result = asyncio.run(_preview_and_execute())
    assert preview["adapter_kind"] == "lab_simulated"
    assert preview["lab_adapter"] is True
    assert preview["device_contacted"] is False
    assert preview["fortipam_contacted"] is False
    assert preview["device_write"] is False
    assert result["adapter_kind"] == "lab_simulated"
    assert result["lab_adapter"] is True
    assert result["device_contacted"] is False
    assert result["fortipam_contacted"] is False
    assert result["device_write"] is False
    assert result["readback"]["readback_verified"] is True


def test_capability_matrix_tool_is_offline_and_static(monkeypatch) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Capability metadata must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer()

    async def _call_tool() -> dict:
        async with Client(server.mcp) as client:
            result = await client.call_tool("get_capability_matrix", {})
        return result.structured_content

    matrix = asyncio.run(_call_tool())

    assert matrix["tool_count"] == len(EXPECTED_TOOLS)
    assert matrix["network_call_executed"] is False
    assert matrix["fortipam_contacted"] is False
    assert {tool["tool_name"] for tool in matrix["tools"]} == set(EXPECTED_TOOLS)


def test_lab_capability_matrix_matches_registered_surface_without_credentials(
    monkeypatch,
) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("LAB capability metadata must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.LAB_SIMULATED
    )

    async def _call_tool() -> dict:
        async with Client(server.mcp) as client:
            result = await client.call_tool("get_capability_matrix", {})
        return result.structured_content

    matrix = asyncio.run(_call_tool())

    assert matrix["tool_count"] == len(LAB_EXPECTED_TOOLS)
    assert matrix["network_call_executed"] is False
    assert matrix["fortipam_contacted"] is False
    assert {tool["tool_name"] for tool in matrix["tools"]} == set(
        LAB_EXPECTED_TOOLS
    )


def test_server_suppresses_dependency_request_urls(monkeypatch) -> None:
    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        lambda: EnvironmentLoadReport(source="test", loaded=False),
    )

    def _unconfigured():
        raise ConfigurationError("test-only unconfigured server")

    monkeypatch.setattr(server_module, "load_config", _unconfigured)
    server_module.FortiPamMcpServer()

    assert logging.getLogger("httpx").level >= logging.WARNING
    assert logging.getLogger("httpcore").level >= logging.WARNING


def test_operational_scenario_tools_work_through_mcp_without_credentials(
    monkeypatch,
) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Offline scenario tools must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer()

    async def _call_tools() -> tuple[dict, dict, dict]:
        async with Client(server.mcp) as client:
            status = await client.call_tool("get_scenario_catalog_status", {})
            search = await client.call_tool(
                "search_operational_scenarios",
                {"query": "self approval"},
            )
            scenario = await client.call_tool(
                "get_operational_scenario",
                {"scenario_id": "self-approval-control"},
            )
        return (
            status.structured_content,
            search.structured_content,
            scenario.structured_content,
        )

    status, search, scenario = asyncio.run(_call_tools())

    assert status["scenario_count"] == 19
    assert search["results"][0]["scenario_id"] == "self-approval-control"
    assert scenario["scenario"]["live_call_permitted"] is False
