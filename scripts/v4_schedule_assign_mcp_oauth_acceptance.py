#!/usr/bin/env python3
"""Accept one bounded V4 Local User login-Schedule OAuth/MCP C/P/E flow."""

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
        "preview_v4_schedule_assign",
        "confirm_v4_schedule_assign",
        "execute_confirmed_v4_schedule_assign",
    }
)
WORKFLOW = "fortipam_v4_schedule_assign_api_workflow_v1"
EXECUTION = "fortipam_v4_schedule_assign_api_execution_v1"
PREVIEW_PREFIX = "schedule-assign-preview-"
AUTHORIZATION_PREFIX = "schedule-assign-authorized-"


class ScheduleAssignMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded Schedule assignment acceptance fails."""


async def run_schedule_assign_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    username: str | None = None,
    schedule_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    ca_file: Path | None = None,
) -> dict[str, object]:
    """Verify the exact Tool surface or execute one assignment once."""

    preview_requested = any(
        value is not None for value in (username, schedule_name, preview_state_file)
    )
    if preview_requested and execute_preview_state_file is not None:
        raise ScheduleAssignMcpOAuthAcceptanceError(
            "Schedule assignment preview and execution inputs cannot be combined."
        )
    if preview_requested and None in {username, schedule_name, preview_state_file}:
        raise ScheduleAssignMcpOAuthAcceptanceError(
            "Schedule assignment preview inputs are incomplete."
        )
    preview_verified = False
    execution_verified = False
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise ScheduleAssignMcpOAuthAcceptanceError(
                "Schedule assignment MCP Tool surface is incomplete."
            )
        if preview_requested:
            assert username is not None
            assert schedule_name is not None
            assert preview_state_file is not None
            phase = "preview"
            reply = await session.call_tool(
                "preview_v4_schedule_assign",
                {"username": username, "schedule_name": schedule_name},
            )
            _validate_preview(
                reply.structured_content,
                username,
                schedule_name,
                reply.is_error,
            )
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(
                preview_state_file,
                str(reply.structured_content["preview_ref"]),
            )
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool(
                "confirm_v4_schedule_assign",
                {"preview_ref": _read_preview_ref(execute_preview_state_file)},
            )
            body = confirmation.structured_content
            authorization_ref = (
                body.get("authorization_ref") if isinstance(body, dict) else None
            )
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
                raise ScheduleAssignMcpOAuthAcceptanceError(
                    "Schedule assignment MCP confirmation failed."
                )
            phase = "execution readback"
            reply = await session.call_tool(
                "execute_confirmed_v4_schedule_assign",
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
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise ScheduleAssignMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise ScheduleAssignMcpOAuthAcceptanceError(
                f"Schedule assignment MCP {phase} failed."
            ) from None
        raise
    return {
        "contract": "fortipam_v4_schedule_assign_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "schedule_assign_tool_surface_complete": True,
        "schedule_assign_preview_verified": preview_verified,
        "schedule_assign_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(
    projection: Any,
    username: str,
    schedule_name: str,
    is_error: bool,
) -> None:
    current = projection.get("Current State") if isinstance(projection, dict) else None
    proposed = (
        projection.get("Proposed Changes") if isinstance(projection, dict) else None
    )
    expected = (
        projection.get("Expected State") if isinstance(projection, dict) else None
    )
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
        or current
        != {
            "requested_username": username,
            "user_exists": True,
            "user_status": "disabled",
            "user_type": "local",
            "current_schedule_unassigned": True,
            "requested_schedule_name": schedule_name,
            "schedule_exists": True,
            "write_transport": "rest_api",
        }
        or proposed
        != {
            "operation": "assign_existing_login_schedule_to_disabled_local_user_via_api",
            "username": username,
            "schedule_name": schedule_name,
            "request_body": "product_ui_existing_user_projection_schedule_only_change",
        }
        or expected
        != {
            "user_exists": True,
            "schedule_exists": True,
            "user_remains_disabled": True,
            "user_remains_local": True,
            "schedule_matches": True,
            "user_non_schedule_state_preserved": True,
            "schedule_state_preserved": True,
            "readback_transport": "rest_api",
        }
    ):
        raise ScheduleAssignMcpOAuthAcceptanceError(
            "Schedule assignment C/P/E projection was invalid."
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
        != "separate_confirmed_login_schedule_change_required"
        or any(
            result.get(key) is not False
            for key in (
                "username_returned",
                "schedule_name_returned",
                "user_payload_returned",
                "schedule_payload_returned",
                "credential_material_returned",
                "raw_api_response_returned",
            )
        )
    ):
        raise ScheduleAssignMcpOAuthAcceptanceError(
            "Schedule assignment MCP execution readback failed."
        )


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, ScheduleAssignMcpOAuthAcceptanceError)
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
        raise ScheduleAssignMcpOAuthAcceptanceError(
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
        raise ScheduleAssignMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        )
    try:
        preview_ref = json.loads(path.read_text(encoding="utf-8")).get(
            "preview_ref"
        )
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise ScheduleAssignMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        ) from exc
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise ScheduleAssignMcpOAuthAcceptanceError(
            "Preview state reference is invalid."
        )
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--username")
    parser.add_argument("--schedule-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_schedule_assign_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                username=args.username,
                schedule_name=args.schedule_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
                ca_file=args.ca_file,
            )
        )
    except ScheduleAssignMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
