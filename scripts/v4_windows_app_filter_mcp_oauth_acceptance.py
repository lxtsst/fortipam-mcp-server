#!/usr/bin/env python3
"""Accept the bounded V4 Windows App Filter OAuth/MCP C/P/E flow."""

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


TOOLS = frozenset({"preview_v4_windows_app_filter_create", "confirm_v4_windows_app_filter_create", "execute_confirmed_v4_windows_app_filter_create"})
WORKFLOW = "fortipam_v4_windows_app_filter_create_api_workflow_v1"
EXECUTION = "fortipam_v4_windows_app_filter_create_api_execution_v1"
PREFIX = "windows-app-filter-preview-"


class WindowsAppFilterMcpOAuthAcceptanceError(RuntimeError):
    """Raised when the bounded Windows App Filter acceptance fails."""


async def run_windows_app_filter_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, *, ca_file: Path | None = None,
    preview_profile_name: str | None = None, preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    preview_requested = preview_profile_name is not None or preview_state_file is not None
    if preview_requested == (execute_preview_state_file is not None):
        if preview_requested:
            raise WindowsAppFilterMcpOAuthAcceptanceError("Windows App Filter preview and execution inputs cannot be combined.")
    if preview_requested and (not isinstance(preview_profile_name, str) or preview_state_file is None):
        raise WindowsAppFilterMcpOAuthAcceptanceError("Windows App Filter preview inputs are incomplete.")
    preview_verified = False
    execution_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise WindowsAppFilterMcpOAuthAcceptanceError("Windows App Filter MCP Tool surface is incomplete.")
        if preview_profile_name is not None:
            assert preview_state_file is not None
            reply = await session.call_tool("preview_v4_windows_app_filter_create", {"name": preview_profile_name})
            _validate_preview(reply.structured_content, preview_profile_name, reply.is_error)
            assert isinstance(reply.structured_content, dict)
            _write_state(preview_state_file, str(reply.structured_content["preview_ref"]))
            preview_verified = True
        if execute_preview_state_file is not None:
            confirmation = await session.call_tool("confirm_v4_windows_app_filter_create", {"preview_ref": _read_state(execute_preview_state_file)})
            content = confirmation.structured_content
            authorization = content.get("authorization_ref") if isinstance(content, dict) else None
            if confirmation.is_error or not isinstance(content, dict) or not isinstance(authorization, str) or not authorization.startswith("windows-app-filter-authorized-") or content.get("contract") != WORKFLOW or content.get("confirmation") != "recorded" or content.get("execution") != "authorized_once" or content.get("device_write_executed") is not False:
                raise WindowsAppFilterMcpOAuthAcceptanceError("Windows App Filter MCP confirmation failed.")
            reply = await session.call_tool("execute_confirmed_v4_windows_app_filter_create", {"authorization_ref": authorization})
            result = reply.structured_content
            if reply.is_error or not isinstance(result, dict) or result.get("contract") != EXECUTION or result.get("outcome") != "succeeded" or result.get("verification") != "verified" or result.get("idempotent_replay") is not False or result.get("profile_name_returned") is not False or result.get("filter_or_exception_content_returned") is not False or result.get("secret_target_or_policy_association_changes") is not False or result.get("raw_api_response_returned") is not False:
                raise WindowsAppFilterMcpOAuthAcceptanceError("Windows App Filter MCP execution readback failed.")
            execute_preview_state_file.unlink()
            execution_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(url, login_file, client_state_file, ca_file=ca_file, tool_session_callback=callback, required_tools=TOOLS)
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise WindowsAppFilterMcpOAuthAcceptanceError(str(exc)) from None
    return {"contract": "fortipam_v4_windows_app_filter_mcp_oauth_acceptance_v1", "oauth_metadata_verified": common["oauth_metadata_verified"], "mcp_initialized": common["mcp_initialized"], "windows_app_filter_tool_surface_complete": True, "windows_app_filter_preview_verified": preview_verified, "windows_app_filter_execution_verified": execution_verified, "device_tool_invoked": preview_verified or execution_verified, "device_write_executed": execution_verified, "token_revoked": common["token_revoked"], "credential_values_returned": common["credential_values_returned"], "token_returned": False, "client_id_returned": False}


def _validate_preview(value: Any, name: str, is_error: bool) -> None:
    current = value.get("Current State") if isinstance(value, dict) else None
    proposed = value.get("Proposed Changes") if isinstance(value, dict) else None
    expected = value.get("Expected State") if isinstance(value, dict) else None
    reference = value.get("preview_ref") if isinstance(value, dict) else None
    if is_error or not isinstance(current, dict) or not isinstance(proposed, dict) or not isinstance(expected, dict) or not isinstance(reference, str) or not reference.startswith(PREFIX) or value.get("contract") != WORKFLOW or value.get("device_write_executed") is not False or current.get("requested_profile_name") != name or current.get("windows_app_filter_profile_exists") is not False or proposed.get("profile_name") != name or proposed.get("request_body") != "fixed_name_only" or proposed.get("caller_supplied_filters_or_exceptions") is not False or proposed.get("secret_target_or_policy_association_changes") is not False or expected.get("windows_app_filter_profile_exists") is not True or expected.get("profile_name_matches") is not True or expected.get("filter_or_exception_content_returned") is not False or expected.get("secret_target_or_policy_association_changes") is not False:
        raise WindowsAppFilterMcpOAuthAcceptanceError("Windows App Filter C/P/E projection was invalid.")


def _write_state(path: Path, reference: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077 or path.exists() or path.is_symlink() or not reference.startswith(PREFIX):
        raise WindowsAppFilterMcpOAuthAcceptanceError("Preview state is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": reference}, separators=(",", ":")).encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_state(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise WindowsAppFilterMcpOAuthAcceptanceError("Preview state is invalid.")
    try:
        reference = json.loads(path.read_text()).get("preview_ref")
    except (OSError, json.JSONDecodeError) as exc:
        raise WindowsAppFilterMcpOAuthAcceptanceError("Preview state is invalid.") from exc
    if not isinstance(reference, str) or not reference.startswith(PREFIX):
        raise WindowsAppFilterMcpOAuthAcceptanceError("Preview state is invalid.")
    return reference


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True); parser.add_argument("--login-file", type=Path, required=True); parser.add_argument("--client-state-file", type=Path, required=True); parser.add_argument("--ca-file", type=Path); parser.add_argument("--preview-profile-name"); parser.add_argument("--preview-state-file", type=Path); parser.add_argument("--execute-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(run_windows_app_filter_mcp_oauth_acceptance(args.url, args.login_file, args.client_state_file, ca_file=args.ca_file, preview_profile_name=args.preview_profile_name, preview_state_file=args.preview_state_file, execute_preview_state_file=args.execute_preview_state_file))
    except WindowsAppFilterMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
