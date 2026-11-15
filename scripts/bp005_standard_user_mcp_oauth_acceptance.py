#!/usr/bin/env python3
"""Accept one enabled FortiPAM 7.0 Standard User through OAuth/MCP."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fortipam_mcp.local_user_create_live_workflow import BP005_STANDARD_USER_WORKFLOW_CONTRACT
from fortipam_mcp.local_user_reset_fixture_create import BP005_STANDARD_USERNAME_PATTERN

TOOLS = frozenset({
    "preview_v4_local_user_create",
    "confirm_v4_local_user_create",
    "execute_confirmed_v4_local_user_create",
})
WORKFLOW = BP005_STANDARD_USER_WORKFLOW_CONTRACT
EXECUTION = "bp005_standard_user_create_execution_v1"
PREVIEW_PREFIX = "local-user-create-preview-"
AUTHORIZATION_PREFIX = "local-user-create-authorized-"


class Bp005StandardUserMcpAcceptanceError(RuntimeError):
    """Raised for a non-disclosing BP005 Standard User acceptance failure."""


async def run_bp005_standard_user_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    username: str,
    dispatch_state_file: Path,
    ca_file: Path | None = None,
    lab_connect_host: str | None = None,
    lab_connect_port: int | None = None,
    allow_loopback_tunnel: bool = False,
) -> dict[str, object]:
    """Preview, confirm, and execute one exact enabled Standard User create."""

    if BP005_STANDARD_USERNAME_PATTERN.fullmatch(username) is None:
        raise Bp005StandardUserMcpAcceptanceError("BP005 Standard User inputs are invalid.")
    _validate_dispatch_path(dispatch_state_file, must_not_exist=True)
    try:
        from scripts import v4_address_mcp_oauth_surface_acceptance as oauth
        from mcp import ClientSession
    except Exception:
        raise Bp005StandardUserMcpAcceptanceError("BP005 Standard User OAuth/MCP client is unavailable.") from None

    preview_verified = False
    confirmation_verified = False
    execution_verified = False
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, confirmation_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise Bp005StandardUserMcpAcceptanceError("BP005 Standard User Tool surface is incomplete.")
        phase = "preview"
        preview = await session.call_tool("preview_v4_local_user_create", {"username": username})
        preview_ref = _validate_preview(preview.structured_content, username, preview.is_error)
        preview_verified = True

        phase = "confirmation"
        confirmation = await session.call_tool(
            "confirm_v4_local_user_create", {"preview_ref": preview_ref},
        )
        authorization_ref = _validate_confirmation(
            confirmation.structured_content, confirmation.is_error,
        )
        confirmation_verified = True

        # The O_EXCL record is the client-side no-retry boundary. It precedes
        # the one MCP execution call and is intentionally retained on failure.
        _consume_dispatch_state(dispatch_state_file)
        phase = "execution readback"
        result = await session.call_tool(
            "execute_confirmed_v4_local_user_create",
            {"authorization_ref": authorization_ref},
        )
        _validate_execution(result.structured_content, result.is_error)
        execution_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(
            url,
            login_file,
            client_state_file,
            ca_file=ca_file,
            tool_session_callback=callback,
            required_tools=TOOLS,
            lab_connect_host=lab_connect_host,
            lab_connect_port=lab_connect_port,
            allow_loopback_tunnel=allow_loopback_tunnel,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError:
        raise Bp005StandardUserMcpAcceptanceError(f"BP005 Standard User MCP {phase} failed.") from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise Bp005StandardUserMcpAcceptanceError(f"BP005 Standard User MCP {phase} failed.") from None
        raise
    if common.get("token_revoked") is not True or common.get("credential_values_returned") is not False:
        raise Bp005StandardUserMcpAcceptanceError("BP005 Standard User OAuth cleanup was not verified.")
    return {
        "contract": "bp005_standard_user_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "tool_surface_complete": True,
        "preview_verified": preview_verified,
        "confirmation_verified": confirmation_verified,
        "execution_verified": execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": True,
        "credential_values_returned": False,
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(value: Any, username: str, is_error: bool) -> str:
    current = value.get("Current State") if isinstance(value, dict) else None
    proposed = value.get("Proposed Changes") if isinstance(value, dict) else None
    expected = value.get("Expected State") if isinstance(value, dict) else None
    preview_ref = value.get("preview_ref") if isinstance(value, dict) else None
    if (
        is_error
        or not isinstance(current, dict)
        or not isinstance(proposed, dict)
        or not isinstance(expected, dict)
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(PREVIEW_PREFIX)
        or value.get("contract") != WORKFLOW
        or value.get("device_write_executed") is not False
        or current.get("requested_username") != username
        or current.get("user_exists") is not False
        or proposed.get("operation") != "create_enabled_standard_local_user"
        or proposed.get("username") != username
        or proposed.get("access_profile") != "pam_standard_user"
        or proposed.get("status") != "enable"
        or proposed.get("initial_password") != "generated_not_returned"
        or expected.get("username_matches") is not True
        or expected.get("user_exists") is not True
        or expected.get("access_profile_matches") is not True
        or expected.get("status_enabled") is not True
        or expected.get("credentials_returned") is not False
    ):
        raise Bp005StandardUserMcpAcceptanceError("BP005 Standard User C/P/E projection was invalid.")
    return preview_ref


def _validate_confirmation(value: Any, is_error: bool) -> str:
    authorization_ref = value.get("authorization_ref") if isinstance(value, dict) else None
    if (
        is_error
        or not isinstance(value, dict)
        or not isinstance(authorization_ref, str)
        or not authorization_ref.startswith(AUTHORIZATION_PREFIX)
        or value.get("contract") != WORKFLOW
        or value.get("confirmation") != "recorded"
        or value.get("execution") != "authorized_once"
        or value.get("device_write_executed") is not False
    ):
        raise Bp005StandardUserMcpAcceptanceError("BP005 Standard User confirmation failed.")
    return authorization_ref


def _validate_execution(value: Any, is_error: bool) -> None:
    if (
        is_error
        or not isinstance(value, dict)
        or value.get("contract") != EXECUTION
        or value.get("outcome") != "succeeded"
        or value.get("verification") != "verified"
        or value.get("idempotent_replay") is not False
        or value.get("compensation") != "not_requested"
        or value.get("credentials_returned") is not False
        or value.get("raw_cli_returned") is not False
    ):
        raise Bp005StandardUserMcpAcceptanceError("BP005 Standard User execution readback failed.")


def _validate_dispatch_path(path: Path, *, must_not_exist: bool) -> None:
    parent = path.parent
    try:
        details = parent.lstat()
        if (
            not path.is_absolute()
            or parent.is_symlink()
            or not stat.S_ISDIR(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o700
            or details.st_uid != os.getuid()
            or path.is_symlink()
            or (must_not_exist and path.exists())
        ):
            raise ValueError
    except Exception:
        raise Bp005StandardUserMcpAcceptanceError("BP005 Standard User dispatch state is unavailable.") from None


def _consume_dispatch_state(path: Path) -> None:
    _validate_dispatch_path(path, must_not_exist=True)
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, b'{"contract":"bp005-standard-user-create/v1","dispatch":"consumed"}\n')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        raise Bp005StandardUserMcpAcceptanceError("BP005 Standard User dispatch state is unavailable.") from None


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, Bp005StandardUserMcpAcceptanceError)
        or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item))
        for item in error.exceptions
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--dispatch-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--lab-connect-host")
    parser.add_argument("--lab-connect-port", type=int)
    parser.add_argument("--allow-loopback-tunnel", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(run_bp005_standard_user_mcp_oauth_acceptance(
            args.url, args.login_file, args.client_state_file,
            username=args.username, dispatch_state_file=args.dispatch_state_file,
            ca_file=args.ca_file, lab_connect_host=args.lab_connect_host,
            lab_connect_port=args.lab_connect_port,
            allow_loopback_tunnel=args.allow_loopback_tunnel,
        ))
    except Bp005StandardUserMcpAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
