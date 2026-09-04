#!/usr/bin/env python3
"""Run the fixed FortiPAM MCP read-only acceptance set in process."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp import Client

from fortipam_mcp.posture_contracts import (
    PostureContractError,
    validate_ems_connection_posture,
)
from fortipam_mcp.server import FIXED_ROUTE_TOOLS, FortiPamMcpServer

ACCEPTANCE_TOOLS = (
    "fortipam_configuration_status",
    "plan_curated_reads",
    "get_overall_health_summary",
) + FIXED_ROUTE_TOOLS


async def run_acceptance() -> dict[str, object]:
    """Call only the compiled acceptance tools and return their structured results."""

    server = FortiPamMcpServer()
    results: dict[str, object] = {}
    async with Client(server.mcp) as client:
        for tool_name in ACCEPTANCE_TOOLS:
            result = await client.call_tool(tool_name, {})
            if result.is_error:
                raise RuntimeError(f"FortiPAM MCP acceptance tool failed: {tool_name}")
            results[tool_name] = _validated_result(
                tool_name,
                result.structured_content,
            )
    return {
        "protocol": "MCP in-memory client",
        "read_only": True,
        "raw_response_bodies_returned": False,
        "tools": results,
    }


def _structured_result(value: Any) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("FortiPAM MCP acceptance tool did not return structured output.")
    return value


def _validated_result(tool_name: str, value: Any) -> dict[str, object]:
    structured = _structured_result(value)
    if tool_name == "get_ems_connection_posture_summary":
        posture = structured.get("posture")
        try:
            validate_ems_connection_posture(posture)
        except PostureContractError as exc:
            raise RuntimeError("FortiPAM EMS acceptance contract failed.") from exc
    return structured


def main() -> None:
    print(json.dumps(asyncio.run(run_acceptance()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
