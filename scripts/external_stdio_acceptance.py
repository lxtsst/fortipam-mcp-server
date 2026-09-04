#!/usr/bin/env python3
"""Accept the fixed API and CLI live surface through external MCP stdio."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Sequence

from mcp import ClientSession
from mcp.client.stdio import (
    StdioServerParameters,
    get_default_environment,
    stdio_client,
)

from fortipam_mcp.env import DEVICE_PREFIX
from fortipam_mcp.mcp_smoke import EXPECTED_TOOLS
from fortipam_mcp.server import CLI_TOOLS
from scripts.external_http_acceptance import _safe_cli_result

ACCEPTANCE_TOOLS = (
    "fortipam_configuration_status",
    "plan_curated_reads",
    "get_system_status_summary",
    "get_system_global_summary",
    "get_approval_profile_summary",
    "get_fortianalyzer_delivery_posture_summary",
    "get_license_support_posture_summary",
    "get_ha_configuration_posture_summary",
    "get_recording_storage_health_summary",
    "get_password_changer_configuration_posture_summary",
    "get_ems_connection_posture_summary",
    "get_overall_health_summary",
    *CLI_TOOLS,
)


async def run_external_acceptance(command: Sequence[str]) -> dict[str, object]:
    """Call the accepted tools through one external stdio server process."""

    selected = list(command)
    if not selected:
        raise ValueError("External MCP acceptance command must not be empty.")
    parameters = StdioServerParameters(
        command=selected[0],
        args=selected[1:],
        env=_child_environment(),
    )
    results: dict[str, object] = {}
    with open(os.devnull, "w", encoding="utf-8") as dependency_errors:
        async with stdio_client(parameters, errlog=dependency_errors) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                listed = await session.list_tools()
                tool_names = {tool.name for tool in listed.tools}
                if tool_names != set(EXPECTED_TOOLS):
                    raise RuntimeError(
                        "External FortiPAM MCP exposed an unexpected tool surface."
                    )
                for tool_name in ACCEPTANCE_TOOLS:
                    result = await session.call_tool(tool_name, {})
                    if result.is_error:
                        raise RuntimeError(
                            f"External FortiPAM MCP acceptance failed: {tool_name}"
                        )
                    structured = _structured_result(result.structured_content)
                    results[tool_name] = (
                        _safe_cli_result(tool_name, structured)
                        if tool_name in CLI_TOOLS
                        else structured
                    )
                denied_count = 0
                for tool_name in ACCEPTANCE_TOOLS:
                    denied = await session.call_tool(
                        tool_name,
                        {"unexpected": "must-deny"},
                    )
                    if not denied.is_error:
                        raise RuntimeError(
                            "External FortiPAM MCP accepted an undeclared input: "
                            f"{tool_name}"
                        )
                    denied_count += 1
    return {
        "protocol": "external MCP stdio client",
        "protocol_version": str(initialized.protocol_version),
        "read_only": True,
        "tool_count": len(tool_names),
        "undeclared_input_denial_count": denied_count,
        "raw_response_bodies_returned": False,
        "tools": results,
    }


def _structured_result(value: Any) -> object:
    if not isinstance(value, dict):
        raise RuntimeError(
            "External FortiPAM MCP acceptance tool did not return structured output."
        )
    return value


def _child_environment(
    environment: dict[str, str] | None = None,
) -> dict[str, str]:
    """Pass only SDK-safe defaults and the dedicated FortiPAM prefix."""

    source = os.environ if environment is None else environment
    selected = get_default_environment()
    selected.update(
        {
            key: value
            for key, value in source.items()
            if key.startswith(f"{DEVICE_PREFIX}_")
        }
    )
    return selected


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Accept FortiPAM MCP through an external stdio command."
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        result = asyncio.run(run_external_acceptance(command))
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1:])
