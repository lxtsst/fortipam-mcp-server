#!/usr/bin/env python3
"""Accept one bounded V4 Public child Folder rename OAuth/MCP flow."""

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
        "preview_v4_public_child_folder_rename",
        "confirm_v4_public_child_folder_rename",
        "execute_confirmed_v4_public_child_folder_rename",
    }
)
WORKFLOW = "fortipam_v4_public_child_folder_rename_api_workflow_v1"
EXECUTION = "fortipam_v4_public_child_folder_rename_api_execution_v1"
PREVIEW_PREFIX = "folder-rename-preview-"
AUTHORIZATION_PREFIX = "folder-rename-authorized-"


class FolderRenameMcpOAuthAcceptanceError(RuntimeError):
    """Raised for a non-disclosing Folder rename acceptance failure."""


async def run_folder_rename_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    folder_id: int | None = None,
    new_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    ca_file: Path | None = None,
) -> dict[str, object]:
    """Verify or execute one exact Public child Folder rename once."""

    preview_requested = any(
        value is not None for value in (folder_id, new_name, preview_state_file)
    )
    if preview_requested == (execute_preview_state_file is not None):
        raise FolderRenameMcpOAuthAcceptanceError("Folder rename phase inputs are invalid.")
    if preview_requested and (
        folder_id is None or new_name is None or preview_state_file is None
    ):
        raise FolderRenameMcpOAuthAcceptanceError("Folder rename preview inputs are incomplete.")

    preview_verified = False
    execution_verified = False
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal execution_verified, phase, preview_verified
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise FolderRenameMcpOAuthAcceptanceError(
                "Folder rename MCP Tool surface is incomplete."
            )
        if preview_requested:
            assert folder_id is not None and new_name is not None
            assert preview_state_file is not None
            phase = "preview"
            reply = await session.call_tool(
                "preview_v4_public_child_folder_rename",
                {"folder_id": folder_id, "new_name": new_name},
            )
            _validate_preview(reply.structured_content, folder_id, new_name, reply.is_error)
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(preview_state_file, str(reply.structured_content["preview_ref"]))
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool(
                "confirm_v4_public_child_folder_rename",
                {"preview_ref": _read_preview_ref(execute_preview_state_file)},
            )
            authorization_ref = _validate_confirmation(
                confirmation.structured_content, confirmation.is_error
            )
            phase = "execution readback"
            reply = await session.call_tool(
                "execute_confirmed_v4_public_child_folder_rename",
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
        raise FolderRenameMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise FolderRenameMcpOAuthAcceptanceError(
                f"Folder rename MCP {phase} failed."
            ) from None
        raise
    return {
        "contract": "fortipam_v4_folder_rename_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "folder_rename_tool_surface_complete": True,
        "folder_rename_preview_verified": preview_verified,
        "folder_rename_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(value: Any, folder_id: int, new_name: str, is_error: bool) -> None:
    current = value.get("Current State") if isinstance(value, dict) else None
    proposed = value.get("Proposed Changes") if isinstance(value, dict) else None
    expected = value.get("Expected State") if isinstance(value, dict) else None
    preview_ref = value.get("preview_ref") if isinstance(value, dict) else None
    if (
        is_error
        or type(folder_id) is not int
        or folder_id <= 0
        or not isinstance(new_name, str)
        or not isinstance(current, dict)
        or not isinstance(proposed, dict)
        or not isinstance(expected, dict)
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(PREVIEW_PREFIX)
        or value.get("contract") != WORKFLOW
        or value.get("device_write_executed") is not False
        or current.get("selected_folder_id") != folder_id
        or current.get("requested_new_name") != new_name
        or current.get("folder_exists") is not True
        or current.get("folder_scope") != "public_child"
        or current.get("permission_inheritance") != "disable"
        or current.get("requested_name_already_matches") is not False
        or current.get("write_transport") != "rest_api"
        or proposed.get("operation") != "rename_public_child_folder_via_api"
        or proposed.get("folder_id") != folder_id
        or proposed.get("current_name_returned") is not False
        or proposed.get("new_name") != new_name
        or proposed.get("acl_and_policy_projection_preserved") is not True
        or proposed.get("ztna_projection_preserved") is not True
        or expected.get("folder_id_matches") is not True
        or expected.get("folder_exists") is not True
        or expected.get("folder_scope") != "public_child"
        or expected.get("requested_name_matches") is not True
        or expected.get("parent_relation_preserved") is not True
        or expected.get("acl_and_policy_projection_preserved") is not True
        or expected.get("ztna_projection_preserved") is not True
    ):
        raise FolderRenameMcpOAuthAcceptanceError("Folder rename C/P/E projection was invalid.")


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
        raise FolderRenameMcpOAuthAcceptanceError("Folder rename MCP confirmation failed.")
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
        or value.get("folder_id_returned") is not False
        or value.get("folder_name_returned") is not False
        or value.get("raw_api_response_returned") is not False
    ):
        raise FolderRenameMcpOAuthAcceptanceError("Folder rename MCP execution readback failed.")


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if (
        path.parent.is_symlink()
        or not path.parent.is_dir()
        or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
        or path.exists()
        or path.is_symlink()
        or not preview_ref.startswith(PREVIEW_PREFIX)
    ):
        raise FolderRenameMcpOAuthAcceptanceError("Preview state reference is invalid.")
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
        raise FolderRenameMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        preview_ref = json.loads(path.read_text(encoding="utf-8")).get("preview_ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise FolderRenameMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise FolderRenameMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, FolderRenameMcpOAuthAcceptanceError)
        or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item))
        for item in error.exceptions
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--folder-id", type=int)
    parser.add_argument("--new-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_folder_rename_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                folder_id=args.folder_id,
                new_name=args.new_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
                ca_file=args.ca_file,
            )
        )
    except FolderRenameMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
