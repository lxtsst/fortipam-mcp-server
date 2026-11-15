#!/usr/bin/env python3
"""Accept one bounded V4 inherited Public child Folder OAuth/MCP flow."""

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

TOOLS = frozenset({"preview_v4_child_folder_create", "confirm_v4_child_folder_create", "execute_confirmed_v4_child_folder"})
WORKFLOW = "fortipam_v4_child_folder_workflow_v1"
EXECUTION = "fortipam_v4_child_folder_execution_v1"
PREVIEW_PREFIX = "folder-preview-"
AUTHORIZATION_PREFIX = "folder-authorized-"


class FolderCreateMcpOAuthAcceptanceError(RuntimeError):
    """Raised for non-disclosing Child Folder acceptance failures."""


async def run_folder_create_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, *, folder_name: str | None = None,
    parent_folder_id: int | None = None, preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None, ca_file: Path | None = None,
) -> dict[str, object]:
    preview_requested = any(value is not None for value in (folder_name, parent_folder_id, preview_state_file))
    if preview_requested == (execute_preview_state_file is not None):
        raise FolderCreateMcpOAuthAcceptanceError("Folder create phase inputs are invalid.")
    if preview_requested and (folder_name is None or parent_folder_id is None or preview_state_file is None):
        raise FolderCreateMcpOAuthAcceptanceError("Folder create preview inputs are incomplete.")
    preview_verified = execution_verified = False
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise FolderCreateMcpOAuthAcceptanceError("Folder create MCP Tool surface is incomplete.")
        if preview_requested:
            assert folder_name is not None and parent_folder_id is not None and preview_state_file is not None
            phase = "preview"
            reply = await session.call_tool("preview_v4_child_folder_create", {"folder_name": folder_name, "parent_folder_id": parent_folder_id})
            _validate_preview(reply.structured_content, folder_name, parent_folder_id, reply.is_error)
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(preview_state_file, str(reply.structured_content["preview_ref"]))
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool("confirm_v4_child_folder_create", {"preview_ref": _read_preview_ref(execute_preview_state_file)})
            authorization_ref = _validate_confirmation(confirmation.structured_content, confirmation.is_error)
            phase = "execution readback"
            reply = await session.call_tool("execute_confirmed_v4_child_folder", {"authorization_ref": authorization_ref})
            _validate_execution(reply.structured_content, reply.is_error)
            execute_preview_state_file.unlink()
            execution_verified = True
    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(url, login_file, client_state_file, ca_file=ca_file, tool_session_callback=callback, required_tools=TOOLS)
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise FolderCreateMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_error(exc):
            raise FolderCreateMcpOAuthAcceptanceError(f"Folder create MCP {phase} failed.") from None
        raise
    return {"contract": "fortipam_v4_folder_create_mcp_oauth_acceptance_v1", "oauth_metadata_verified": common["oauth_metadata_verified"], "mcp_initialized": common["mcp_initialized"], "folder_create_tool_surface_complete": True, "folder_create_preview_verified": preview_verified, "folder_create_execution_verified": execution_verified, "device_tool_invoked": preview_verified or execution_verified, "device_write_executed": execution_verified, "token_revoked": common["token_revoked"], "credential_values_returned": common["credential_values_returned"], "token_returned": False, "client_id_returned": False}


def _validate_preview(value: Any, folder_name: str, parent_folder_id: int, is_error: bool) -> None:
    current = value.get("Current State") if isinstance(value, dict) else None
    proposed = value.get("Proposed Changes") if isinstance(value, dict) else None
    expected = value.get("Expected State") if isinstance(value, dict) else None
    ref = value.get("preview_ref") if isinstance(value, dict) else None
    if (is_error or not isinstance(current, dict) or not isinstance(proposed, dict) or not isinstance(expected, dict) or not isinstance(ref, str) or not ref.startswith(PREVIEW_PREFIX) or value.get("contract") != WORKFLOW or value.get("device_write_executed") is not False or current.get("selected_parent_folder_id") != parent_folder_id or current.get("requested_child_folder_name") != folder_name or current.get("parent_exists") is not True or current.get("matching_child_exists") is not False or proposed.get("operation") != "create_inherited_public_child_folder" or proposed.get("parent_folder_id") != parent_folder_id or proposed.get("folder_name") != folder_name or expected.get("child_folder_name_matches") is not True or expected.get("matching_child_exists") is not True or expected.get("inherit_policy") != "enable" or expected.get("inherit_permission") != "enable" or expected.get("inherit_folder_ztna") != "enable"):
        raise FolderCreateMcpOAuthAcceptanceError("Folder create C/P/E projection was invalid.")


def _validate_confirmation(value: Any, is_error: bool) -> str:
    ref = value.get("authorization_ref") if isinstance(value, dict) else None
    if (is_error or not isinstance(value, dict) or not isinstance(ref, str) or not ref.startswith(AUTHORIZATION_PREFIX) or value.get("contract") != WORKFLOW or value.get("confirmation") != "recorded" or value.get("execution") != "authorized_once" or value.get("device_write_executed") is not False):
        raise FolderCreateMcpOAuthAcceptanceError("Folder create MCP confirmation failed.")
    return ref


def _validate_execution(value: Any, is_error: bool) -> None:
    if (is_error or not isinstance(value, dict) or value.get("contract") != EXECUTION or value.get("outcome") != "succeeded" or value.get("verification") != "verified" or value.get("idempotent_replay") is not False or value.get("compensation") != "not_requested" or value.get("credentials_returned") is not False or value.get("raw_response_returned") is not False):
        raise FolderCreateMcpOAuthAcceptanceError("Folder create MCP execution readback failed.")


def _write_preview_state(path: Path, ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077 or path.exists() or path.is_symlink() or not ref.startswith(PREVIEW_PREFIX):
        raise FolderCreateMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": ref}).encode()); os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise FolderCreateMcpOAuthAcceptanceError("Preview state file is invalid.")
    try: ref = json.loads(path.read_text()).get("preview_ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc: raise FolderCreateMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(ref, str) or not ref.startswith(PREVIEW_PREFIX): raise FolderCreateMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return ref


def _contains_error(error: BaseExceptionGroup) -> bool:
    return any(isinstance(item, FolderCreateMcpOAuthAcceptanceError) or (isinstance(item, BaseExceptionGroup) and _contains_error(item)) for item in error.exceptions)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True); parser.add_argument("--login-file", type=Path, required=True); parser.add_argument("--client-state-file", type=Path, required=True); parser.add_argument("--folder-name"); parser.add_argument("--parent-folder-id", type=int); parser.add_argument("--preview-state-file", type=Path); parser.add_argument("--execute-preview-state-file", type=Path); parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try: result = asyncio.run(run_folder_create_mcp_oauth_acceptance(args.url, args.login_file, args.client_state_file, folder_name=args.folder_name, parent_folder_id=args.parent_folder_id, preview_state_file=args.preview_state_file, execute_preview_state_file=args.execute_preview_state_file, ca_file=args.ca_file))
    except FolderCreateMcpOAuthAcceptanceError as exc: raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__": main()
