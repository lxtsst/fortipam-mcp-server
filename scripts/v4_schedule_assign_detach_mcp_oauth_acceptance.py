#!/usr/bin/env python3
"""Accept the fixed b57/b66 Schedule-assignment recovery OAuth/MCP flow."""

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
        "preview_v4_schedule_assignment_detach",
        "confirm_v4_schedule_assignment_detach",
        "execute_confirmed_v4_schedule_assignment_detach",
    }
)
WORKFLOW = "fortipam_v4_schedule_assign_detach_api_workflow_v1"
EXECUTION = "fortipam_v4_schedule_assign_detach_api_execution_v1"
PREVIEW_PREFIX = "schedule-assign-detach-preview-"
AUTHORIZATION_PREFIX = "schedule-assign-detach-authorized-"
EXPECTED_TOOL_COUNT = 286
EXPECTED_SELECTED_CAPABILITY_COUNT = 287


class ScheduleAssignDetachMcpOAuthAcceptanceError(RuntimeError):
    """Raised when fixed Schedule-assignment recovery acceptance fails."""


async def run_schedule_assign_detach_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify the fixed surface, or save/execute exactly one C/P/E."""

    if preview_state_file is not None and execute_preview_state_file is not None:
        raise ScheduleAssignDetachMcpOAuthAcceptanceError(
            "Schedule detach preview and execution cannot be combined."
        )
    preview_verified = False
    execution_verified = False
    observed_tool_count = 0
    observed_capability_count = 0
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        nonlocal observed_tool_count, observed_capability_count
        names = {tool.name for tool in (await session.list_tools()).tools}
        observed_tool_count = len(names)
        if not TOOLS <= names or observed_tool_count != EXPECTED_TOOL_COUNT:
            raise ScheduleAssignDetachMcpOAuthAcceptanceError(
                "Schedule detach MCP Tool surface is incomplete."
            )
        matrix_result = await session.call_tool("get_capability_matrix", {})
        matrix = matrix_result.structured_content
        capability_count = matrix.get("tool_count") if isinstance(matrix, dict) else 0
        observed_capability_count = (
            capability_count if type(capability_count) is int else 0
        )
        if (
            matrix_result.is_error
            or observed_capability_count != EXPECTED_SELECTED_CAPABILITY_COUNT
        ):
            raise ScheduleAssignDetachMcpOAuthAcceptanceError(
                "Schedule detach capability surface is incomplete."
            )
        if preview_state_file is not None:
            phase = "preview"
            preview = await session.call_tool(
                "preview_v4_schedule_assignment_detach", {}
            )
            _validate_preview(preview.structured_content, preview.is_error)
            projection = preview.structured_content
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(preview_state_file, preview_ref)
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            preview_ref = _read_preview_ref(execute_preview_state_file)
            confirmation = await session.call_tool(
                "confirm_v4_schedule_assignment_detach",
                {"preview_ref": preview_ref},
            )
            confirmed = confirmation.structured_content
            authorization_ref = (
                confirmed.get("authorization_ref")
                if isinstance(confirmed, dict)
                else None
            )
            if (
                confirmation.is_error
                or not isinstance(confirmed, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith(AUTHORIZATION_PREFIX)
                or confirmed.get("contract") != WORKFLOW
                or confirmed.get("confirmation") != "recorded"
                or confirmed.get("execution") != "authorized_once"
                or confirmed.get("device_write_executed") is not False
            ):
                raise ScheduleAssignDetachMcpOAuthAcceptanceError(
                    "Schedule detach MCP confirmation failed."
                )
            phase = "execution readback"
            execution = await session.call_tool(
                "execute_confirmed_v4_schedule_assignment_detach",
                {"authorization_ref": authorization_ref},
            )
            _validate_execution(execution.structured_content, execution.is_error)
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
        raise ScheduleAssignDetachMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise ScheduleAssignDetachMcpOAuthAcceptanceError(
                f"Schedule detach MCP {phase} failed."
            ) from None
        raise

    return {
        "contract": "fortipam_v4_schedule_assign_detach_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "tool_count": observed_tool_count,
        "selected_capability_count": observed_capability_count,
        "schedule_assign_detach_tool_surface_complete": True,
        "schedule_assign_detach_preview_verified": preview_verified,
        "schedule_assign_detach_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(projection: Any, is_error: bool) -> None:
    if (
        is_error
        or not isinstance(projection, dict)
        or projection.get("contract") != WORKFLOW
        or projection.get("device_write_executed") is not False
        or projection.get("Current State")
        != {
            "fixed_schedule_assignment_exists": True,
            "user_disabled": True,
            "user_local": True,
            "fixed_role_preserved": True,
            "complete_user_record_digest_matches": True,
            "complete_schedule_record_digest_matches": True,
            "schedule_rest_and_ssh_projection_matches": True,
            "schedule_reference_count": 1,
            "only_fixed_user_references_schedule": True,
            "read_transports": ["rest_api", "ssh_cli"],
        }
        or projection.get("Proposed Changes")
        != {
            "operation": "detach_fixed_login_schedule_via_api",
            "user_count_affected": 1,
            "request_body": "product_ui_existing_user_projection_schedule_only_clear",
            "password_mfa_trust_or_role_change": False,
            "effective_login_or_session_effect": False,
        }
        or projection.get("Expected State")
        != {
            "fixed_user_schedule_unassigned": True,
            "all_non_schedule_user_state_preserved": True,
            "fixed_role_preserved": True,
            "complete_schedule_preserved": True,
            "schedule_reference_count": 0,
            "readback_transports": ["rest_api", "ssh_cli"],
        }
        or not isinstance(projection.get("preview_ref"), str)
        or not str(projection["preview_ref"]).startswith(PREVIEW_PREFIX)
        or "mcp-v4-user" in repr(projection)
        or "mcp-v4-schedule" in repr(projection)
    ):
        raise ScheduleAssignDetachMcpOAuthAcceptanceError(
            "Schedule detach C/P/E projection was invalid."
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
        != "separate_schedule_assignment_action_required"
        or result.get("user_or_schedule_identifier_returned") is not False
        or result.get("non_schedule_user_state_preserved") is not True
        or result.get("schedule_preserved") is not True
        or result.get("schedule_reference_count") != 0
        or result.get("password_mfa_trust_or_role_change") is not False
        or result.get("effective_login_or_session_effect") is not False
        or result.get("raw_api_or_cli_response_returned") is not False
    ):
        raise ScheduleAssignDetachMcpOAuthAcceptanceError(
            "Schedule detach MCP execution readback failed."
        )


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, ScheduleAssignDetachMcpOAuthAcceptanceError)
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
        raise ScheduleAssignDetachMcpOAuthAcceptanceError(
            "Preview state reference is invalid."
        )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(
            descriptor,
            json.dumps({"preview_ref": preview_ref}, separators=(",", ":")).encode(),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ScheduleAssignDetachMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        )
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScheduleAssignDetachMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        ) from exc
    preview_ref = stored.get("preview_ref") if isinstance(stored, dict) else None
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise ScheduleAssignDetachMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        )
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_schedule_assign_detach_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
            )
        )
    except ScheduleAssignDetachMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
