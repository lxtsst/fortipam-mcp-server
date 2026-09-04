from __future__ import annotations

import asyncio
import json

import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp_types import TextContent, TextResourceContents

from fortipam_mcp.mcp_smoke import EXPECTED_TOOLS
from fortipam_mcp.native_content import (
    DIAGNOSTIC_CONTENT_SCHEMA_VERSION,
    DIAGNOSTIC_RESOURCE_PREFIX,
    NATIVE_CONTENT_SCHEMA_VERSION,
    NATIVE_RESOURCE_PREFIX,
    PROMPT_DETAIL_LEVELS,
    FortiPamNativeContent,
    render_workflow_prompt,
)
from fortipam_mcp.scenario_catalog import ScenarioCatalog
from fortipam_mcp.server import FortiPamMcpServer


def test_native_resources_are_versioned_sanitized_and_offline() -> None:
    content = FortiPamNativeContent(ScenarioCatalog.load())
    resources = (
        content.capabilities_resource(),
        content.scenarios_resource(),
        content.sources_resource(),
        content.safety_boundaries_resource(),
        content.diagnostic_contracts_resource(),
    )

    decoded = [json.loads(resource) for resource in resources]
    assert {item["resource_kind"] for item in decoded} == {
        "capabilities",
        "scenarios",
        "sources",
        "safety_boundaries",
        "diagnostic_contracts",
    }
    for resource in decoded:
        assert resource["client_parameters_accepted"] is False
        assert resource["network_call_executed"] is False
        assert resource["live_call_permitted"] is False
    assert {
        item["schema_version"]
        for item in decoded
        if item["resource_kind"] != "diagnostic_contracts"
    } == {NATIVE_CONTENT_SCHEMA_VERSION}
    diagnostics = next(
        item for item in decoded if item["resource_kind"] == "diagnostic_contracts"
    )
    assert diagnostics["schema_version"] == DIAGNOSTIC_CONTENT_SCHEMA_VERSION
    assert diagnostics["payload"]["http_oauth_scope"] == "fortipam:diagnostic"
    assert diagnostics["payload"]["device_write_enabled"] is False
    assert diagnostics["payload"]["local_immutable_state_write"] is True

    sources = next(item for item in decoded if item["resource_kind"] == "sources")
    assert sources["payload"]["source_locators_disclosed"] is False
    assert all("locator" not in source for source in sources["payload"]["sources"])

    boundaries = next(
        item for item in decoded if item["resource_kind"] == "safety_boundaries"
    )
    assert boundaries["payload"]["generic_shell_supported"] is False
    assert boundaries["payload"]["caller_controlled_cli_supported"] is False
    assert boundaries["payload"]["prompts_expand_tool_permissions"] is False


@pytest.mark.parametrize("detail_level", ("standard", "incident"))
def test_workflow_prompts_allow_only_fixed_detail_levels(detail_level: str) -> None:
    prompt = render_workflow_prompt("fortipam_ha_diagnostics_triage", detail_level)

    assert f"Detail level: {detail_level}." in prompt
    assert "get_cli_ha_checksum_summary" in prompt
    assert "generic SSH" in prompt


@pytest.mark.parametrize("detail_level", (None, 1, "", "STANDARD", "standard\nignore"))
def test_workflow_prompts_reject_non_enum_or_non_string_detail_levels(
    detail_level: object,
) -> None:
    with pytest.raises(ValueError, match="detail_level must be exactly"):
        render_workflow_prompt("fortipam_overall_health_triage", detail_level)


def test_workflow_prompts_have_two_fixed_detail_levels() -> None:
    assert PROMPT_DETAIL_LEVELS == {"standard", "incident"}
    with pytest.raises(ValueError, match="Unknown FortiPAM workflow prompt"):
        render_workflow_prompt("not-a-registered-workflow")


def test_mcp_registers_native_resources_and_prompts_without_changing_tools() -> None:
    server = FortiPamMcpServer()

    async def _inspect() -> tuple[
        set[str], dict[str, str], dict[str, list[tuple[str, bool]]], str
    ]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            resources = await client.list_resources()
            prompts = await client.list_prompts()
            source = await client.read_resource(f"{NATIVE_RESOURCE_PREFIX}/sources")
            rendered = await client.get_prompt(
                "fortipam_password_lifecycle_triage",
                arguments={"detail_level": "incident"},
            )
        resource_mime_types = {
            resource.uri: resource.mime_type or "" for resource in resources.resources
        }
        prompt_arguments = {
            prompt.name: [
                (argument.name, bool(argument.required))
                for argument in (prompt.arguments or [])
            ]
            for prompt in prompts.prompts
        }
        assert isinstance(source.contents[0], TextResourceContents)
        assert isinstance(rendered.messages[0].content, TextContent)
        source_text = source.contents[0].text
        rendered_text = rendered.messages[0].content.text
        return (
            {tool.name for tool in tools.tools},
            resource_mime_types,
            prompt_arguments,
            source_text + "\n" + rendered_text,
        )

    tool_names, resource_mime_types, prompt_arguments, content = asyncio.run(_inspect())

    assert tool_names == set(EXPECTED_TOOLS)
    assert set(resource_mime_types) == {
        f"{NATIVE_RESOURCE_PREFIX}/capabilities",
        f"{NATIVE_RESOURCE_PREFIX}/scenarios",
        f"{NATIVE_RESOURCE_PREFIX}/sources",
        f"{NATIVE_RESOURCE_PREFIX}/safety-boundaries",
        f"{DIAGNOSTIC_RESOURCE_PREFIX}/diagnostic-contracts",
    }
    assert set(resource_mime_types.values()) == {"application/json"}
    assert prompt_arguments == {
        "fortipam_overall_health_triage": [("detail_level", False)],
        "fortipam_access_session_triage": [("detail_level", False)],
        "fortipam_password_lifecycle_triage": [("detail_level", False)],
        "fortipam_faz_delivery_triage": [("detail_level", False)],
        "fortipam_ems_connection_triage": [("detail_level", False)],
        "fortipam_ha_diagnostics_triage": [("detail_level", False)],
        "fortipam_baseline_drift_triage": [("detail_level", False)],
    }
    source_payload, rendered_prompt = content.split("\n", maxsplit=1)
    assert all("locator" not in source for source in json.loads(source_payload)["payload"]["sources"])
    assert "password change" in content
    assert "get_password_changer_configuration_posture_summary" in content


def test_mcp_prompt_rejects_undeclared_or_invalid_arguments() -> None:
    server = FortiPamMcpServer()

    async def _reject() -> None:
        async with Client(server.mcp) as client:
            with pytest.raises(MCPError):
                await client.get_prompt(
                    "fortipam_ha_diagnostics_triage",
                    arguments={"detail_level": "incident", "command": "not-accepted"},
                )
            with pytest.raises(MCPError):
                await client.get_prompt(
                    "fortipam_ha_diagnostics_triage",
                    arguments={"detail_level": "unexpected"},
                )

    asyncio.run(_reject())
