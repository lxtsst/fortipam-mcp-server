#!/usr/bin/env python3
"""Accept one bounded V4 Folder direct-user ACL revoke OAuth/MCP flow."""

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

TOOLS = frozenset({
    "preview_v4_folder_user_acl_revoke",
    "confirm_v4_folder_user_acl_revoke",
    "execute_confirmed_v4_folder_user_acl_revoke",
})
WORKFLOW = "fortipam_v4_folder_user_acl_revoke_workflow_v1"
EXECUTION = "fortipam_v4_folder_user_acl_revoke_execution_v1"
PREVIEW_PREFIX = "folder-acl-revoke-preview-"
AUTHORIZATION_PREFIX = "folder-acl-revoke-authorized-"


class FolderAclRevokeMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded Folder ACL revoke acceptance fails."""


async def run_folder_acl_revoke_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    folder_id: int | None = None,
    username: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    ca_file: Path | None = None,
) -> dict[str, object]:
    """Verify or execute one exact direct-user ACL revoke flow."""

    preview_requested = any(value is not None for value in (folder_id, username, preview_state_file))
    if preview_requested and execute_preview_state_file is not None:
        raise FolderAclRevokeMcpOAuthAcceptanceError("Folder ACL revoke preview and execution inputs cannot be combined.")
    if preview_requested and (folder_id is None or username is None or preview_state_file is None):
        raise FolderAclRevokeMcpOAuthAcceptanceError("Folder ACL revoke preview inputs are incomplete.")
    preview_verified = execution_verified = False
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise FolderAclRevokeMcpOAuthAcceptanceError("Folder ACL revoke MCP Tool surface is incomplete.")
        if preview_requested:
            assert folder_id is not None and username is not None and preview_state_file is not None
            phase = "preview"
            reply = await session.call_tool("preview_v4_folder_user_acl_revoke", {"folder_id": folder_id, "username": username})
            _validate_preview(reply.structured_content, folder_id, username, reply.is_error)
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(preview_state_file, str(reply.structured_content["preview_ref"]))
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool("confirm_v4_folder_user_acl_revoke", {"preview_ref": _read_preview_ref(execute_preview_state_file)})
            body = confirmation.structured_content
            authorization_ref = body.get("authorization_ref") if isinstance(body, dict) else None
            if (confirmation.is_error or not isinstance(body, dict) or not isinstance(authorization_ref, str)
                    or not authorization_ref.startswith(AUTHORIZATION_PREFIX) or body.get("contract") != WORKFLOW
                    or body.get("confirmation") != "recorded" or body.get("execution") != "authorized_once"
                    or body.get("device_write_executed") is not False):
                raise FolderAclRevokeMcpOAuthAcceptanceError("Folder ACL revoke MCP confirmation failed.")
            phase = "execution readback"
            reply = await session.call_tool("execute_confirmed_v4_folder_user_acl_revoke", {"authorization_ref": authorization_ref})
            _validate_execution(reply.structured_content, reply.is_error)
            execute_preview_state_file.unlink()
            execution_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(url, login_file, client_state_file, ca_file=ca_file, tool_session_callback=callback, required_tools=TOOLS)
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise FolderAclRevokeMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise FolderAclRevokeMcpOAuthAcceptanceError(f"Folder ACL revoke MCP {phase} failed.") from None
        raise
    return {"contract": "fortipam_v4_folder_acl_revoke_mcp_oauth_acceptance_v1", "oauth_metadata_verified": common["oauth_metadata_verified"], "mcp_initialized": common["mcp_initialized"], "folder_acl_revoke_tool_surface_complete": True, "folder_acl_revoke_preview_verified": preview_verified, "folder_acl_revoke_execution_verified": execution_verified, "device_tool_invoked": preview_verified or execution_verified, "device_write_executed": execution_verified, "token_revoked": common["token_revoked"], "credential_values_returned": common["credential_values_returned"], "token_returned": False, "client_id_returned": False}


def _validate_preview(projection: Any, folder_id: int, username: str, is_error: bool) -> None:
    current = projection.get("Current State") if isinstance(projection, dict) else None
    proposed = projection.get("Proposed Changes") if isinstance(projection, dict) else None
    expected = projection.get("Expected State") if isinstance(projection, dict) else None
    preview_ref = projection.get("preview_ref") if isinstance(projection, dict) else None
    if (is_error or not isinstance(current, dict) or not isinstance(proposed, dict) or not isinstance(expected, dict)
            or not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX) or projection.get("contract") != WORKFLOW
            or projection.get("device_write_executed") is not False or current.get("selected_folder_id") != folder_id
            or current.get("requested_username") != username or current.get("folder_exists") is not True
            or current.get("folder_scope") != "public_child" or current.get("permission_inheritance") != "disable"
            or current.get("requested_direct_user_relation_present") is not True
            or proposed.get("operation") != "revoke_public_folder_direct_user_acl" or proposed.get("folder_id") != folder_id
            or proposed.get("username") != username or proposed.get("direct_user_relation_count_delta") != -1
            or proposed.get("permission_inheritance_preserved") is not True
            or any(expected.get(key) is not True for key in ("folder_exists", "other_direct_user_relations_preserved", "direct_group_relations_preserved"))
            or expected.get("folder_scope") != "public_child" or expected.get("permission_inheritance") != "disable"
            or expected.get("requested_username_direct_relation_present") is not False):
        raise FolderAclRevokeMcpOAuthAcceptanceError("Folder ACL revoke C/P/E projection was invalid.")


def _validate_execution(result: Any, is_error: bool) -> None:
    if (is_error or not isinstance(result, dict) or result.get("contract") != EXECUTION
            or result.get("outcome") != "succeeded" or result.get("verification") != "verified"
            or result.get("idempotent_replay") is not False or result.get("compensation") != "grant_new_direct_relation_required"
            or result.get("credentials_returned") is not False or result.get("raw_response_returned") is not False):
        raise FolderAclRevokeMcpOAuthAcceptanceError("Folder ACL revoke MCP execution readback failed.")


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(isinstance(item, FolderAclRevokeMcpOAuthAcceptanceError) or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item)) for item in error.exceptions)


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077 or path.exists() or path.is_symlink() or not preview_ref.startswith(PREVIEW_PREFIX):
        raise FolderAclRevokeMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": preview_ref}).encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise FolderAclRevokeMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        preview_ref = json.loads(path.read_text(encoding="utf-8")).get("preview_ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise FolderAclRevokeMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise FolderAclRevokeMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--folder-id", type=int)
    parser.add_argument("--username")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(run_folder_acl_revoke_mcp_oauth_acceptance(args.url, args.login_file, args.client_state_file, folder_id=args.folder_id, username=args.username, preview_state_file=args.preview_state_file, execute_preview_state_file=args.execute_preview_state_file, ca_file=args.ca_file))
    except FolderAclRevokeMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
