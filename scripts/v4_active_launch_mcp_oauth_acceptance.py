#!/usr/bin/env python3
"""Validate the read-only V4 active-launch OAuth/MCP observation surface."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import v4_address_mcp_oauth_surface_acceptance as oauth


TOOLS = frozenset(
    {
        "observe_v4_active_launches",
        "preview_v4_active_launch_disconnect",
        "confirm_v4_active_launch_disconnect",
        "execute_confirmed_v4_active_launch_disconnect",
    }
)
OBSERVATION_CONTRACT = "fortipam_v4_active_launch_observation_cli_v1"


class ActiveLaunchMcpOAuthAcceptanceError(RuntimeError):
    """Raised when the bounded observation acceptance contract fails."""


async def run_active_launch_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    allow_insecure_private_ip_lab: bool = False,
) -> dict[str, object]:
    """Discover the complete pack and invoke only its read-only observation Tool."""

    observation_verified = False
    observed_state: str | None = None
    observed_count: int | None = None

    async def callback(session: ClientSession) -> None:
        nonlocal observation_verified, observed_state, observed_count
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not TOOLS <= names:
            raise ActiveLaunchMcpOAuthAcceptanceError(
                "Active-launch MCP Tool surface is incomplete."
            )
        reply = await session.call_tool("observe_v4_active_launches", {})
        _validate_observation(reply.structured_content, reply.is_error)
        assert isinstance(reply.structured_content, dict)
        observed_state = str(reply.structured_content["observation"])
        count = reply.structured_content["active_launch_count"]
        observed_count = count if isinstance(count, int) else None
        observation_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(
            url,
            login_file,
            client_state_file,
            ca_file=ca_file,
            tool_session_callback=callback,
            required_tools=TOOLS,
            allow_insecure_private_ip_lab=allow_insecure_private_ip_lab,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise ActiveLaunchMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise ActiveLaunchMcpOAuthAcceptanceError(
                "Active-launch MCP observation failed."
            ) from None
        raise
    return {
        "contract": "fortipam_v4_active_launch_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "active_launch_tool_surface_complete": True,
        "active_launch_observation_verified": observation_verified,
        "active_launch_observation_state": observed_state,
        "active_launch_count": observed_count,
        "device_tool_invoked": observation_verified,
        "device_write_executed": False,
        "disconnect_preview_invoked": False,
        "disconnect_confirmation_invoked": False,
        "disconnect_execution_invoked": False,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_observation(projection: Any, is_error: bool) -> None:
    if not isinstance(projection, dict):
        raise ActiveLaunchMcpOAuthAcceptanceError("Active-launch observation was invalid.")
    observation = projection.get("observation")
    references = projection.get("active_launch_refs")
    common = (
        is_error
        or projection.get("contract") != OBSERVATION_CONTRACT
        or observation not in {"verified", "unavailable_or_unrecognized"}
        or not isinstance(references, list)
        or projection.get("raw_cli_returned") is not False
        or projection.get("wad_token_returned") is not False
        or projection.get("identity_target_secret_or_session_data_returned") is not False
        or projection.get("device_write_executed") is not False
    )
    if common:
        raise ActiveLaunchMcpOAuthAcceptanceError("Active-launch observation was invalid.")
    assert isinstance(references, list)
    count = projection.get("active_launch_count")
    if observation == "verified":
        if not isinstance(count, int) or isinstance(count, bool) or count < 0 or count != len(references):
            raise ActiveLaunchMcpOAuthAcceptanceError("Active-launch observation was invalid.")
        for reference in references:
            if (
                not isinstance(reference, dict)
                or not isinstance(reference.get("launch_ref"), str)
                or not str(reference["launch_ref"]).startswith("active-launch-ref-")
                or not isinstance(reference.get("expires_at"), int)
                or reference.get("token_or_session_data_returned") is not False
            ):
                raise ActiveLaunchMcpOAuthAcceptanceError("Active-launch observation was invalid.")
    elif count is not None or references:
        raise ActiveLaunchMcpOAuthAcceptanceError("Active-launch observation was invalid.")


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, ActiveLaunchMcpOAuthAcceptanceError)
        or (
            isinstance(item, BaseExceptionGroup)
            and _contains_acceptance_error(item)
        )
        for item in error.exceptions
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--allow-insecure-private-ip-lab", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_active_launch_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                allow_insecure_private_ip_lab=args.allow_insecure_private_ip_lab,
            )
        )
    except ActiveLaunchMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
