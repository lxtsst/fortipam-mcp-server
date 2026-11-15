#!/usr/bin/env python3
"""Accept one bounded V4 active-Launch disconnect OAuth/MCP flow."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from mcp import ClientSession

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import v4_address_mcp_oauth_surface_acceptance as oauth


TOOLS = frozenset(
    {
        "preview_v4_active_launch_disconnect",
        "confirm_v4_active_launch_disconnect",
        "execute_confirmed_v4_active_launch_disconnect",
    }
)
WORKFLOW = "fortipam_v4_active_launch_disconnect_cli_workflow_v1"
EXECUTION = "fortipam_v4_active_launch_disconnect_cli_execution_v1"
PREVIEW_PREFIX = "active-launch-disconnect-preview-"
AUTHORIZATION_PREFIX = "active-launch-disconnect-authorized-"
LAUNCH_REF_PREFIX = "active-launch-ref-"


class ActiveLaunchDisconnectMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded active-Launch disconnect acceptance fails."""


async def run_active_launch_disconnect_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    launch_ref: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    ca_file: Path | None = None,
    allow_insecure_private_ip_lab: bool = False,
) -> dict[str, object]:
    """Verify or execute only one previously observed active-Launch disconnect."""

    preview_requested = launch_ref is not None or preview_state_file is not None
    if preview_requested and execute_preview_state_file is not None:
        raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
            "Active-Launch disconnect preview and execution inputs cannot be combined."
        )
    if (
        preview_requested
        and (launch_ref is None or preview_state_file is None)
    ):
        raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
            "Active-Launch disconnect preview inputs are incomplete."
        )
    preview_verified = execution_verified = False
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
                "Active-Launch disconnect MCP Tool surface is incomplete."
            )
        if preview_requested:
            assert launch_ref is not None and preview_state_file is not None
            if not launch_ref.startswith(LAUNCH_REF_PREFIX):
                raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
                    "Active-Launch reference is invalid."
                )
            phase = "preview"
            reply = await session.call_tool(
                "preview_v4_active_launch_disconnect",
                {"launch_ref": launch_ref},
            )
            _validate_preview(reply.structured_content, launch_ref, reply.is_error)
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(preview_state_file, str(reply.structured_content["preview_ref"]))
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool(
                "confirm_v4_active_launch_disconnect",
                {"preview_ref": _read_preview_ref(execute_preview_state_file)},
            )
            body = confirmation.structured_content
            authorization_ref = body.get("authorization_ref") if isinstance(body, dict) else None
            if (
                confirmation.is_error
                or not isinstance(body, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith(AUTHORIZATION_PREFIX)
                or body.get("contract") != WORKFLOW
                or body.get("confirmation") != "recorded"
                or body.get("execution") != "authorized_once"
                or body.get("device_write_executed") is not False
            ):
                raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
                    "Active-Launch disconnect MCP confirmation failed."
                )
            phase = "execution readback"
            reply = await session.call_tool(
                "execute_confirmed_v4_active_launch_disconnect",
                {"authorization_ref": authorization_ref},
            )
            _validate_execution(reply.structured_content, reply.is_error)
            execute_preview_state_file.unlink()
            execution_verified = True

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
        raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
                f"Active-Launch disconnect MCP {phase} failed."
            ) from None
        raise
    return {
        "contract": "fortipam_v4_active_launch_disconnect_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "active_launch_disconnect_tool_surface_complete": True,
        "active_launch_disconnect_preview_verified": preview_verified,
        "active_launch_disconnect_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "observation_tool_invoked": False,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(projection: Any, launch_ref: str, is_error: bool) -> None:
    current = projection.get("Current State") if isinstance(projection, dict) else None
    proposed = projection.get("Proposed Changes") if isinstance(projection, dict) else None
    expected = projection.get("Expected State") if isinstance(projection, dict) else None
    preview_ref = projection.get("preview_ref") if isinstance(projection, dict) else None
    if (
        is_error
        or not isinstance(current, dict)
        or not isinstance(proposed, dict)
        or not isinstance(expected, dict)
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(PREVIEW_PREFIX)
        or projection.get("contract") != WORKFLOW
        or projection.get("device_write_executed") is not False
        or current.get("requested_active_launch_reference") != launch_ref
        or current.get("selected_active_launch_present") is not True
        or current.get("selected_launch_reference_returned") is not True
        or current.get("raw_cli_returned") is not False
        or current.get("wad_token_returned") is not False
        or current.get("identity_target_secret_or_session_data_returned") is not False
        or current.get("write_transport") != "ssh_cli_fallback"
        or proposed.get("operation")
        != "disconnect_exactly_one_previously_observed_active_launch"
        or proposed.get("selected_active_launch_reference") != launch_ref
        or proposed.get("selected_launch_reference_returned") is not True
        or any(
            proposed.get(key) is not False
            for key in (
                "clear_all_active_launches",
                "caller_controlled_cli",
                "raw_cli_returned",
                "wad_token_returned",
                "identity_target_secret_or_session_data_returned",
                "rest_write_attempted",
            )
        )
        or expected.get("selected_active_launch_reference_matches") is not True
        or expected.get("selected_active_launch_present") is not False
        or expected.get("single_active_launch_disconnect_command_used") is not True
        or expected.get("clear_all_active_launches") is not False
        or expected.get("verification_transport") != "ssh_cli_fallback"
        or any(
            expected.get(key) is not False
            for key in (
                "raw_cli_returned",
                "wad_token_returned",
                "identity_target_secret_or_session_data_returned",
            )
        )
    ):
        raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
            "Active-Launch disconnect C/P/E projection was invalid."
        )


def _validate_execution(result: Any, is_error: bool) -> None:
    if (
        is_error
        or not isinstance(result, dict)
        or result.get("contract") != EXECUTION
        or result.get("outcome") != "succeeded"
        or result.get("verification") != "verified"
        or result.get("idempotent_replay") is not False
        or result.get("compensation")
        != "a_new_secret_launch_is_required_to_restore_a_disconnected_launch"
        or result.get("selected_active_launch_disconnected") is not True
        or result.get("clear_all_active_launches") is not False
        or result.get("raw_cli_returned") is not False
        or result.get("wad_token_returned") is not False
        or result.get("identity_target_secret_or_session_data_returned") is not False
    ):
        raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
            "Active-Launch disconnect MCP execution readback failed."
        )


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, ActiveLaunchDisconnectMcpOAuthAcceptanceError)
        or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item))
        for item in error.exceptions
    )


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if (
        path.parent.is_symlink()
        or not path.parent.is_dir()
        or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
        or path.exists()
        or path.is_symlink()
        or not preview_ref.startswith(PREVIEW_PREFIX)
    ):
        raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
            "Preview state reference is invalid."
        )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": preview_ref}).encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    if (
        path.is_symlink()
        or not path.is_file()
        or stat.S_IMODE(path.stat().st_mode) & 0o077
    ):
        raise ActiveLaunchDisconnectMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        preview_ref = json.loads(path.read_text(encoding="utf-8")).get("preview_ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        ) from exc
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise ActiveLaunchDisconnectMcpOAuthAcceptanceError(
            "Preview state reference is invalid."
        )
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--launch-ref")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--allow-insecure-private-ip-lab", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_active_launch_disconnect_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                launch_ref=args.launch_ref,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
                ca_file=args.ca_file,
                allow_insecure_private_ip_lab=args.allow_insecure_private_ip_lab,
            )
        )
    except ActiveLaunchDisconnectMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
