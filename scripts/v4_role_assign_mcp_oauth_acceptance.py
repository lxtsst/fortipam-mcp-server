#!/usr/bin/env python3
"""Accept the bounded V4 Role-assignment OAuth/MCP C/P/E flow."""

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
    _read_preview_ref,
    _write_preview_state,
)


TOOLS = frozenset(
    {
        "preview_v4_role_assign",
        "confirm_v4_role_assign",
        "execute_confirmed_v4_role_assign",
    }
)
WORKFLOW = "fortipam_v4_role_assign_api_workflow_v1"
EXECUTION = "fortipam_v4_role_assign_execution_v1"
PREFIX = "role-assign-preview-"
AUTHORIZATION_PREFIX = "role-assign-authorized-"


class RoleAssignMcpOAuthAcceptanceError(RuntimeError):
    """Raised when the bounded Role-assignment acceptance fails."""


async def run_role_assign_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_username: str | None = None,
    preview_role_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify Tool surface, or save/execute one bounded Role assignment."""

    preview_requested = any(
        value is not None
        for value in (preview_username, preview_role_name, preview_state_file)
    )
    if preview_requested and execute_preview_state_file is not None:
        raise RoleAssignMcpOAuthAcceptanceError(
            "Role-assignment preview and execution inputs cannot be combined."
        )
    if preview_requested and (
        not isinstance(preview_username, str)
        or not isinstance(preview_role_name, str)
        or preview_state_file is None
    ):
        raise RoleAssignMcpOAuthAcceptanceError(
            "Role-assignment preview inputs are incomplete."
        )

    preview_verified = False
    execution_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not TOOLS <= names:
            raise RoleAssignMcpOAuthAcceptanceError(
                "Role-assignment MCP Tool surface is incomplete."
            )
        if preview_username is not None:
            assert preview_role_name is not None and preview_state_file is not None
            preview = await session.call_tool(
                "preview_v4_role_assign",
                {"username": preview_username, "role_name": preview_role_name},
            )
            projection = preview.structured_content
            _validate_preview(
                projection,
                username=preview_username,
                role_name=preview_role_name,
                is_error=preview.is_error,
            )
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(preview_state_file, preview_ref, prefix=PREFIX)
            preview_verified = True
        if execute_preview_state_file is not None:
            preview_ref = _read_preview_ref(execute_preview_state_file, prefix=PREFIX)
            confirmation = await session.call_tool(
                "confirm_v4_role_assign", {"preview_ref": preview_ref}
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
                raise RoleAssignMcpOAuthAcceptanceError(
                    "Role-assignment MCP confirmation failed."
                )
            execution = await session.call_tool(
                "execute_confirmed_v4_role_assign",
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
                or result.get("user_status_changed") is not False
                or result.get("raw_api_response_returned") is not False
            ):
                raise RoleAssignMcpOAuthAcceptanceError(
                    "Role-assignment MCP execution readback failed."
                )
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
        raise RoleAssignMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_role_assign_acceptance_error(exc):
            raise RoleAssignMcpOAuthAcceptanceError(
                "Role-assignment MCP execution readback failed."
            ) from None
        raise

    return {
        "contract": "fortipam_v4_role_assign_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "role_assign_tool_surface_complete": True,
        "role_assign_preview_verified": preview_verified,
        "role_assign_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(
    projection: Any,
    *,
    username: str,
    role_name: str,
    is_error: bool,
) -> None:
    """Reject any projection outside the fixed Role-assignment contract."""

    if not isinstance(projection, dict):
        raise RoleAssignMcpOAuthAcceptanceError("Role-assignment MCP preview failed.")
    current = projection.get("Current State")
    proposed = projection.get("Proposed Changes")
    expected = projection.get("Expected State")
    preview_ref = projection.get("preview_ref")
    if (
        is_error
        or not isinstance(current, dict)
        or not isinstance(proposed, dict)
        or not isinstance(expected, dict)
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(PREFIX)
        or projection.get("contract") != WORKFLOW
        or projection.get("device_write_executed") is not False
        or current.get("requested_username") != username
        or current.get("requested_role_name") != role_name
        or current.get("laboratory_user_exists") is not True
        or current.get("laboratory_user_status") != "disable"
        or current.get("requested_laboratory_role_exists") is not True
        or current.get("requested_role_already_assigned") is not False
        or current.get("write_transport") != "rest_api"
        or proposed.get("operation")
        != "assign_existing_laboratory_role_to_disabled_laboratory_local_user_via_api"
        or proposed.get("username") != username
        or proposed.get("role_name") != role_name
        or proposed.get("user_status_change") is not False
        or proposed.get("folder_target_or_secret_changes") is not False
        or expected.get("username_matches") is not True
        or expected.get("role_name_matches") is not True
        or expected.get("laboratory_user_exists") is not True
        or expected.get("laboratory_user_status") != "disable"
        or expected.get("requested_laboratory_role_exists") is not True
        or expected.get("requested_role_assigned") is not True
    ):
        raise RoleAssignMcpOAuthAcceptanceError(
            "Role-assignment C/P/E projection was invalid."
        )


def _contains_role_assign_acceptance_error(error: BaseExceptionGroup) -> bool:
    """Recognize this wrapper's callback failure inside task groups."""

    for nested in error.exceptions:
        if isinstance(nested, RoleAssignMcpOAuthAcceptanceError):
            return True
        if isinstance(nested, BaseExceptionGroup) and _contains_role_assign_acceptance_error(
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
    parser.add_argument("--preview-username")
    parser.add_argument("--preview-role-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_role_assign_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_username=args.preview_username,
                preview_role_name=args.preview_role_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
            )
        )
    except RoleAssignMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
