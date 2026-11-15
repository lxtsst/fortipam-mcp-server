#!/usr/bin/env python3
"""Accept the fixed b44 Automation Action recovery OAuth/MCP flow."""

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
        "preview_v4_automation_action_delete",
        "confirm_v4_automation_action_delete",
        "execute_confirmed_v4_automation_action_delete",
    }
)
WORKFLOW = "fortipam_v4_automation_action_delete_api_workflow_v1"
EXECUTION = "fortipam_v4_automation_action_delete_api_execution_v1"
PREVIEW_PREFIX = "automation-action-delete-preview-"
AUTHORIZATION_PREFIX = "automation-action-delete-authorized-"
EXPECTED_TOOL_COUNT = 283
EXPECTED_SELECTED_CAPABILITY_COUNT = 284


class AutomationActionDeleteMcpOAuthAcceptanceError(RuntimeError):
    """Raised when the fixed Action recovery acceptance fails."""


async def run_automation_action_delete_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify Tool surface, or save/execute exactly one recovery C/P/E."""

    if preview_state_file is not None and execute_preview_state_file is not None:
        raise AutomationActionDeleteMcpOAuthAcceptanceError(
            "Automation Action delete preview and execution cannot be combined."
        )
    preview_verified = False
    execution_verified = False
    observed_tool_count = 0
    observed_capability_count = 0

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        nonlocal observed_tool_count, observed_capability_count
        names = {tool.name for tool in (await session.list_tools()).tools}
        observed_tool_count = len(names)
        if not TOOLS <= names or observed_tool_count != EXPECTED_TOOL_COUNT:
            raise AutomationActionDeleteMcpOAuthAcceptanceError(
                "Automation Action delete MCP Tool surface is incomplete."
            )
        matrix_result = await session.call_tool("get_capability_matrix", {})
        matrix = matrix_result.structured_content
        capability_count = matrix.get("tool_count") if isinstance(matrix, dict) else 0
        observed_capability_count = capability_count if type(capability_count) is int else 0
        if matrix_result.is_error or observed_capability_count != EXPECTED_SELECTED_CAPABILITY_COUNT:
            raise AutomationActionDeleteMcpOAuthAcceptanceError(
                "Automation Action delete capability surface is incomplete."
            )
        if preview_state_file is not None:
            preview = await session.call_tool("preview_v4_automation_action_delete", {})
            _validate_preview(preview.structured_content, preview.is_error)
            projection = preview.structured_content
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(preview_state_file, preview_ref)
            preview_verified = True
        if execute_preview_state_file is not None:
            preview_ref = _read_preview_ref(execute_preview_state_file)
            confirmation = await session.call_tool(
                "confirm_v4_automation_action_delete",
                {"preview_ref": preview_ref},
            )
            confirmed = confirmation.structured_content
            authorization_ref = confirmed.get("authorization_ref") if isinstance(confirmed, dict) else None
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
                raise AutomationActionDeleteMcpOAuthAcceptanceError(
                    "Automation Action delete MCP confirmation failed."
                )
            execution = await session.call_tool(
                "execute_confirmed_v4_automation_action_delete",
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
        raise AutomationActionDeleteMcpOAuthAcceptanceError(str(exc)) from None

    return {
        "contract": "fortipam_v4_automation_action_delete_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "tool_count": observed_tool_count,
        "selected_capability_count": observed_capability_count,
        "automation_action_delete_tool_surface_complete": True,
        "automation_action_delete_preview_verified": preview_verified,
        "automation_action_delete_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(projection: Any, is_error: bool) -> None:
    if not isinstance(projection, dict):
        raise AutomationActionDeleteMcpOAuthAcceptanceError(
            "Automation Action delete MCP preview failed."
        )
    if (
        is_error
        or projection.get("contract") != WORKFLOW
        or projection.get("device_write_executed") is not False
        or projection.get("Current State")
        != {
            "accepted_unbound_automation_action_exists": True,
            "exact_fixed_projection_observed": True,
            "complete_api_record_digest_matches": True,
            "accepted_trigger_absent": True,
            "accepted_stitch_absent": True,
            "action_reference_count": 0,
            "read_transports": ["rest_api", "ssh_cli"],
        }
        or projection.get("Proposed Changes")
        != {
            "operation": "delete_exact_unreferenced_automation_action_via_api",
            "action_count_affected": 1,
            "irreversible_after_execution": True,
            "automation_test_or_execution": False,
            "email_or_external_side_effect": False,
        }
        or projection.get("Expected State")
        != {
            "accepted_automation_action_absent": True,
            "automation_test_or_execution": False,
            "email_or_external_side_effect": False,
            "readback_transports": ["rest_api", "ssh_cli"],
        }
        or not isinstance(projection.get("preview_ref"), str)
        or not str(projection["preview_ref"]).startswith(PREVIEW_PREFIX)
        or "mcp-v4-automation" in repr(projection)
    ):
        raise AutomationActionDeleteMcpOAuthAcceptanceError(
            "Automation Action delete C/P/E projection was invalid."
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
        != "separate_automation_action_create_action_required"
        or result.get("irreversible_after_execution") is not True
        or result.get("action_fields_returned") is not False
        or result.get("automation_test_or_execution") is not False
        or result.get("email_or_external_side_effect") is not False
        or result.get("raw_api_or_cli_response_returned") is not False
    ):
        raise AutomationActionDeleteMcpOAuthAcceptanceError(
            "Automation Action delete MCP execution readback failed."
        )


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise AutomationActionDeleteMcpOAuthAcceptanceError("Preview state directory is invalid.")
    if path.exists() or path.is_symlink() or not preview_ref.startswith(PREVIEW_PREFIX):
        raise AutomationActionDeleteMcpOAuthAcceptanceError("Preview state file is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": preview_ref}, separators=(",", ":")).encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise AutomationActionDeleteMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AutomationActionDeleteMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    preview_ref = stored.get("preview_ref") if isinstance(stored, dict) else None
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise AutomationActionDeleteMcpOAuthAcceptanceError("Preview state file is invalid.")
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
            run_automation_action_delete_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
            )
        )
    except AutomationActionDeleteMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
