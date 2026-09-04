"""Deterministic MCP stdio smoke check without a FortiPAM device call."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict, dataclass
import json
import os
import sys
from typing import Sequence

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from .runtime_profile import RUNTIME_PROFILE_ENV, RuntimeProfile, load_runtime_profile

EXPECTED_TOOLS = (
    "get_server_info",
    "health_check",
    "get_capability_matrix",
    "fortipam_configuration_status",
    "get_api_catalog_status",
    "search_api_catalog",
    "classify_api_operation",
    "get_scenario_catalog_status",
    "search_operational_scenarios",
    "get_operational_scenario",
    "plan_curated_reads",
    "plan_approval_profile_read",
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
)
LAB_ADMIN_TOOLS = (
    "preview_v31_lab_public_folder",
    "preview_v31_lab_target",
    "preview_v31_lab_secret_metadata",
    "preview_v31_lab_local_user",
    "preview_v31_lab_folder_access_assignment",
    "execute_confirmed_v31_lab_operation",
)
LAB_EXPECTED_TOOLS = EXPECTED_TOOLS + LAB_ADMIN_TOOLS
EXPECTED_RESOURCES = (
    "fortipam://v2.1/capabilities",
    "fortipam://v2.1/scenarios",
    "fortipam://v2.1/sources",
    "fortipam://v2.1/safety-boundaries",
    "fortipam://v2.3/diagnostic-contracts",
)
EXPECTED_PROMPTS = (
    "fortipam_overall_health_triage",
    "fortipam_access_session_triage",
    "fortipam_password_lifecycle_triage",
    "fortipam_faz_delivery_triage",
    "fortipam_ems_connection_triage",
    "fortipam_ha_diagnostics_triage",
    "fortipam_baseline_drift_triage",
)
STRICT_NO_INPUT_TOOLS = frozenset(
    {
        "get_cli_ha_configuration_summary",
        "get_cli_ha_status_summary",
        "get_cli_ha_checksum_summary",
        "correlate_ha_api_cli_posture",
    }
)


@dataclass(frozen=True, slots=True)
class StdioSmokeResult:
    """Sanitized result from MCP initialize and tools/list."""

    protocol_version: str
    tool_count: int
    resource_count: int
    prompt_count: int
    expected_tools: tuple[str, ...]
    expected_resources: tuple[str, ...]
    expected_prompts: tuple[str, ...]


def expected_tools_for_profile(profile: RuntimeProfile) -> tuple[str, ...]:
    """Return the exact approved surface for one resolved runtime profile."""

    if profile is RuntimeProfile.LAB_SIMULATED:
        return LAB_EXPECTED_TOOLS
    return EXPECTED_TOOLS


def assert_expected_tools(
    tool_names: set[str],
    expected_tools: Sequence[str] = EXPECTED_TOOLS,
) -> None:
    """Raise when the server does not expose the approved tool set."""

    missing = [tool for tool in expected_tools if tool not in tool_names]
    unexpected = sorted(tool_names - set(expected_tools))
    if missing:
        raise RuntimeError(f"Missing expected MCP tool(s): {', '.join(missing)}")
    if unexpected:
        raise RuntimeError(f"Unexpected MCP tool(s): {', '.join(unexpected)}")


def assert_expected_native_content(
    resource_uris: set[str], prompt_names: set[str]
) -> None:
    """Raise when MCP-native Resources or Prompts drift from V2.1."""

    if resource_uris != set(EXPECTED_RESOURCES):
        raise RuntimeError("Unexpected MCP Resource surface.")
    if prompt_names != set(EXPECTED_PROMPTS):
        raise RuntimeError("Unexpected MCP Prompt surface.")


def assert_strict_no_input_tools(tools: Sequence[object]) -> None:
    """Require the three V2 CLI tools to reject every caller input field."""

    by_name = {getattr(tool, "name", None): tool for tool in tools}
    for name in STRICT_NO_INPUT_TOOLS:
        tool = by_name.get(name)
        schema = getattr(tool, "input_schema", None)
        if not isinstance(schema, dict) or (
            schema.get("type") != "object"
            or schema.get("properties") not in ({}, None)
            or schema.get("required") not in (None, [])
            or schema.get("additionalProperties") is not False
        ):
            raise RuntimeError(f"MCP tool has a non-strict input schema: {name}")


def run_smoke(
    command: Sequence[str] | None = None,
    *,
    timeout: float = 20.0,
) -> StdioSmokeResult:
    """Run MCP initialize and tools/list through stdio."""

    selected = list(command or [sys.executable, "-m", "fortipam_mcp.server"])
    if not selected:
        raise ValueError("MCP smoke command must not be empty.")
    runtime_profile = load_runtime_profile()
    expected_tools = expected_tools_for_profile(runtime_profile)
    return asyncio.run(
        _run_stdio_smoke(selected, timeout, expected_tools, runtime_profile)
    )


async def _run_stdio_smoke(
    command: list[str],
    timeout: float,
    expected_tools: tuple[str, ...],
    runtime_profile: RuntimeProfile,
) -> StdioSmokeResult:
    parameters = StdioServerParameters(
        command=command[0],
        args=command[1:],
        env={RUNTIME_PROFILE_ENV: runtime_profile.value},
    )
    with open(os.devnull, "w", encoding="utf-8") as dependency_errors:
        async with stdio_client(parameters, errlog=dependency_errors) as (read, write):
            async with ClientSession(
                read,
                write,
                read_timeout_seconds=timeout,
            ) as session:
                initialized = await session.initialize()
                tools_response = await session.list_tools()
                resources_response = await session.list_resources()
                prompts_response = await session.list_prompts()
                resource_response = await session.read_resource(
                    "fortipam://v2.1/safety-boundaries"
                )
                prompt_response = await session.get_prompt(
                    "fortipam_ha_diagnostics_triage",
                    arguments={"detail_level": "incident"},
                )
    tool_names = {tool.name for tool in tools_response.tools}
    resource_uris = {str(resource.uri) for resource in resources_response.resources}
    prompt_names = {prompt.name for prompt in prompts_response.prompts}
    assert_expected_tools(tool_names, expected_tools)
    assert_expected_native_content(resource_uris, prompt_names)
    assert_strict_no_input_tools(tools_response.tools)
    if not resource_response.contents:
        raise RuntimeError("MCP Resource read returned no content.")
    if not prompt_response.messages:
        raise RuntimeError("MCP Prompt rendering returned no messages.")
    return StdioSmokeResult(
        protocol_version=str(initialized.protocol_version),
        tool_count=len(tool_names),
        resource_count=len(resource_uris),
        prompt_count=len(prompt_names),
        expected_tools=expected_tools,
        expected_resources=EXPECTED_RESOURCES,
        expected_prompts=EXPECTED_PROMPTS,
    )


def main(argv: list[str] | None = None) -> None:
    """Console entrypoint."""

    parser = argparse.ArgumentParser(description="Smoke-test FortiPAM MCP stdio.")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args(argv)
    print(json.dumps(asdict(run_smoke(timeout=args.timeout)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
