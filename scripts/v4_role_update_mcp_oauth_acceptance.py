#!/usr/bin/env python3
"""Accept the bounded V4 Role diagnostics-enable OAuth/MCP C/P/E flow."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys
from typing import Any

from mcp import ClientSession

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import v4_address_mcp_oauth_surface_acceptance as oauth
from scripts.v4_role_create_mcp_oauth_acceptance import (
    _is_private_ip_lab_url,
    _read_preview_ref,
    _write_preview_state,
)


TOOLS = frozenset(
    {
        "preview_v4_role_diagnostics_enable",
        "confirm_v4_role_diagnostics_enable",
        "execute_confirmed_v4_role_diagnostics_enable",
    }
)
WORKFLOW = "fortipam_v4_role_diagnostics_enable_workflow_v1"
EXECUTION = "fortipam_v4_role_diagnostics_enable_execution_v1"
PREFIX = "role-update-preview-"
AUTHORIZATION_PREFIX = "role-update-authorized-"


class RoleUpdateMcpOAuthAcceptanceError(RuntimeError):
    """Raised when the bounded Role-update acceptance fails."""


async def run_role_update_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_role_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify the Tool surface, or save/execute exactly one C/P/E request."""

    preview_requested = any(
        value is not None for value in (preview_role_name, preview_state_file)
    )
    if preview_requested and execute_preview_state_file is not None:
        raise RoleUpdateMcpOAuthAcceptanceError(
            "Role-update preview and execution inputs cannot be combined."
        )
    if preview_requested and (
        not isinstance(preview_role_name, str) or preview_state_file is None
    ):
        raise RoleUpdateMcpOAuthAcceptanceError("Role-update preview inputs are incomplete.")

    preview_verified = False
    execution_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not TOOLS <= names:
            raise RoleUpdateMcpOAuthAcceptanceError("Role-update MCP Tool surface is incomplete.")
        if preview_role_name is not None:
            assert preview_state_file is not None
            preview = await session.call_tool(
                "preview_v4_role_diagnostics_enable", {"role_name": preview_role_name}
            )
            projection = preview.structured_content
            _validate_preview(projection, preview_role_name, preview.is_error)
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(preview_state_file, preview_ref, prefix=PREFIX)
            preview_verified = True
        if execute_preview_state_file is not None:
            preview_ref = _read_preview_ref(execute_preview_state_file, prefix=PREFIX)
            confirmation = await session.call_tool(
                "confirm_v4_role_diagnostics_enable", {"preview_ref": preview_ref}
            )
            confirmed = confirmation.structured_content
            authorization_ref = (
                confirmed.get("authorization_ref") if isinstance(confirmed, dict) else None
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
                raise RoleUpdateMcpOAuthAcceptanceError("Role-update MCP confirmation failed.")
            execution = await session.call_tool(
                "execute_confirmed_v4_role_diagnostics_enable",
                {"authorization_ref": authorization_ref},
            )
            result = execution.structured_content
            if (
                execution.is_error
                or not isinstance(result, dict)
                or result.get("contract") != EXECUTION
                or result.get("outcome") != "succeeded"
                or result.get("verification") != "verified"
                or result.get("idempotent_replay") is not False
                or result.get("role_assignment_changes") is not False
                or result.get("folder_target_secret_or_credential_changes") is not False
                or result.get("raw_cli_returned") is not False
            ):
                raise RoleUpdateMcpOAuthAcceptanceError("Role-update MCP execution readback failed.")
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
            allow_insecure_private_ip_lab=_is_private_ip_lab_url(url),
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise RoleUpdateMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_role_update_acceptance_error(exc):
            raise RoleUpdateMcpOAuthAcceptanceError(
                "Role-update MCP execution readback failed."
            ) from None
        raise

    return {
        "contract": "fortipam_v4_role_update_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "role_update_tool_surface_complete": True,
        "role_update_preview_verified": preview_verified,
        "role_update_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(projection: Any, name: str, is_error: bool) -> None:
    """Reject any projection outside the fixed diagnostics-enable contract."""

    if not isinstance(projection, dict):
        raise RoleUpdateMcpOAuthAcceptanceError("Role-update MCP preview failed.")
    current = projection.get("Current State")
    proposed = projection.get("Proposed Changes")
    expected = projection.get("Expected State")
    preview_ref = projection.get("preview_ref")
    write_transport = current.get("write_transport") if isinstance(current, dict) else None
    operation_suffix = "cli_fallback" if write_transport == "ssh_cli_fallback" else "rest_api"
    if (
        is_error
        or not isinstance(current, dict)
        or not isinstance(proposed, dict)
        or not isinstance(expected, dict)
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(PREFIX)
        or projection.get("contract") != WORKFLOW
        or projection.get("device_write_executed") is not False
        or current.get("requested_role_name") != name
        or current.get("role_exists") is not True
        or current.get("guide_example_permissions_match") is not True
        or current.get("system_diagnostics_disabled") is not True
        or current.get("role_assigned_to_any_local_user") is not False
        or write_transport not in {"ssh_cli_fallback", "rest_api"}
        or proposed.get("operation")
        != "enable_role_system_diagnostics_via_" + operation_suffix
        or proposed.get("role_name") != name
        or proposed.get("configuration_profile")
        != "pam_standard_user_diagnostics_enable_v1"
        or proposed.get("system_diagnostics") != "enable"
        or proposed.get("role_assignment_changes") is not False
        or proposed.get("folder_target_secret_or_credential_changes") is not False
        or proposed.get("rest_write_attempted") is not (write_transport == "rest_api")
        or expected.get("role_name_matches") is not True
        or expected.get("role_exists") is not True
        or expected.get("guide_example_permissions_preserved") is not True
        or expected.get("system_diagnostics_enabled") is not True
        or expected.get("role_assigned_to_any_local_user") is not False
        or expected.get("role_assignment_changes") is not False
        or expected.get("folder_target_secret_or_credential_changes") is not False
        or expected.get("readback_transport") != write_transport
    ):
        raise RoleUpdateMcpOAuthAcceptanceError("Role-update C/P/E projection was invalid.")


def _contains_role_update_acceptance_error(error: BaseExceptionGroup) -> bool:
    """Recognize this wrapper's callback failure inside task groups."""

    for nested in error.exceptions:
        if isinstance(nested, RoleUpdateMcpOAuthAcceptanceError):
            return True
        if isinstance(nested, BaseExceptionGroup) and _contains_role_update_acceptance_error(
            nested
        ):
            return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-role-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_role_update_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_role_name=args.preview_role_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
            )
        )
    except RoleUpdateMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
