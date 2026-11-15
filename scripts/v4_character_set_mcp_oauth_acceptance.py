#!/usr/bin/env python3
"""Accept the bounded V4 Character Set OAuth/MCP surface and C/P/E flow."""

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

from fortipam_mcp.character_set_http_transport import CHARACTER_SET_VALUE
from scripts import v4_address_mcp_oauth_surface_acceptance as oauth_acceptance


CHARACTER_SET_TOOLS = frozenset(
    {
        "preview_v4_character_set_create",
        "confirm_v4_character_set_create",
        "execute_confirmed_v4_character_set_create",
    }
)
_WORKFLOW_CONTRACT = "fortipam_v4_character_set_create_api_workflow_v1"
_EXECUTION_CONTRACT = "fortipam_v4_character_set_create_api_execution_v1"
_PREVIEW_PREFIX = "character-set-preview-"


class CharacterSetMcpOAuthAcceptanceError(RuntimeError):
    """Raised when the bounded Character Set OAuth/MCP contract fails."""


async def run_character_set_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_character_set_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify the Tool surface, or save/execute exactly one C/P/E request."""

    preview_requested = any(
        value is not None for value in (preview_character_set_name, preview_state_file)
    )
    if preview_requested and execute_preview_state_file is not None:
        raise CharacterSetMcpOAuthAcceptanceError(
            "Character Set preview and execution inputs cannot be combined."
        )
    if preview_requested and (
        not isinstance(preview_character_set_name, str) or preview_state_file is None
    ):
        raise CharacterSetMcpOAuthAcceptanceError(
            "Character Set preview inputs are incomplete."
        )

    preview_verified = False
    execution_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not CHARACTER_SET_TOOLS <= names:
            raise CharacterSetMcpOAuthAcceptanceError(
                "Character Set MCP Tool surface is incomplete."
            )
        if preview_character_set_name is not None:
            assert preview_state_file is not None
            preview = await session.call_tool(
                "preview_v4_character_set_create",
                {"name": preview_character_set_name},
            )
            projection = preview.structured_content
            _validate_preview(projection, preview_character_set_name, preview.is_error)
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(preview_state_file, preview_ref)
            preview_verified = True
        if execute_preview_state_file is not None:
            preview_ref = _read_preview_ref(execute_preview_state_file)
            confirmation = await session.call_tool(
                "confirm_v4_character_set_create",
                {"preview_ref": preview_ref},
            )
            confirmed = confirmation.structured_content
            authorization_ref = (
                confirmed.get("authorization_ref") if isinstance(confirmed, dict) else None
            )
            if (
                confirmation.is_error
                or not isinstance(confirmed, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith("character-set-authorized-")
                or confirmed.get("contract") != _WORKFLOW_CONTRACT
                or confirmed.get("confirmation") != "recorded"
                or confirmed.get("execution") != "authorized_once"
                or confirmed.get("device_write_executed") is not False
            ):
                raise CharacterSetMcpOAuthAcceptanceError(
                    "Character Set MCP confirmation failed."
                )
            execution = await session.call_tool(
                "execute_confirmed_v4_character_set_create",
                {"authorization_ref": authorization_ref},
            )
            result = execution.structured_content
            if (
                execution.is_error
                or not isinstance(result, dict)
                or result.get("contract") != _EXECUTION_CONTRACT
                or result.get("outcome") != "succeeded"
                or result.get("verification") != "verified"
                or result.get("idempotent_replay") is not False
                or result.get("character_set_name_returned") is not False
                or result.get("character_set_value_returned") is not False
                or result.get("password_policy_or_template_association_changes") is not False
                or result.get("raw_api_response_returned") is not False
            ):
                raise CharacterSetMcpOAuthAcceptanceError(
                    "Character Set MCP execution readback failed."
                )
            execute_preview_state_file.unlink()
            execution_verified = True

    try:
        common = await oauth_acceptance.run_address_mcp_oauth_surface_acceptance(
            url,
            login_file,
            client_state_file,
            ca_file=ca_file,
            tool_session_callback=callback,
            required_tools=CHARACTER_SET_TOOLS,
        )
    except oauth_acceptance.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise CharacterSetMcpOAuthAcceptanceError(str(exc)) from None

    return {
        "contract": "fortipam_v4_character_set_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "character_set_tool_surface_complete": True,
        "character_set_preview_verified": preview_verified,
        "character_set_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(projection: Any, name: str, is_error: bool) -> None:
    if not isinstance(projection, dict):
        raise CharacterSetMcpOAuthAcceptanceError("Character Set MCP preview failed.")
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
        or not preview_ref.startswith(_PREVIEW_PREFIX)
        or projection.get("contract") != _WORKFLOW_CONTRACT
        or projection.get("device_write_executed") is not False
        or current.get("requested_character_set_name") != name
        or current.get("character_set_exists") is not False
        or current.get("write_transport") != "rest_api"
        or proposed.get("operation") != "create_documented_symbol_character_set_via_api"
        or proposed.get("character_set_name") != name
        or proposed.get("character_set_value") != CHARACTER_SET_VALUE
        or proposed.get("configuration_profile") != "documented-symbol-set-v1"
        or proposed.get("password_policy_or_template_association_changes") is not False
        or expected.get("character_set_exists") is not True
        or expected.get("character_set_name_matches") is not True
        or expected.get("character_set_value_matches") is not True
        or expected.get("password_policy_or_template_association_changes") is not False
        or expected.get("readback_transport") != "rest_api"
    ):
        raise CharacterSetMcpOAuthAcceptanceError(
            "Character Set C/P/E projection was invalid."
        )


def _write_preview_state(path: Path, preview_ref: str) -> None:
    """Persist one owner-only opaque Character Set preview reference."""

    if path.parent.is_symlink() or not path.parent.is_dir():
        raise CharacterSetMcpOAuthAcceptanceError("Preview state directory is invalid.")
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise CharacterSetMcpOAuthAcceptanceError(
            "Preview state directory must be owner-only."
        )
    if path.exists() or path.is_symlink():
        raise CharacterSetMcpOAuthAcceptanceError("Preview state file already exists.")
    if not isinstance(preview_ref, str) or not preview_ref.startswith(_PREVIEW_PREFIX):
        raise CharacterSetMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(
            descriptor,
            json.dumps({"preview_ref": preview_ref}, separators=(",", ":")).encode(
                "utf-8"
            ),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    """Read one owner-only opaque Character Set preview reference."""

    if path.is_symlink() or not path.is_file():
        raise CharacterSetMcpOAuthAcceptanceError("Preview state file is invalid.")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise CharacterSetMcpOAuthAcceptanceError(
            "Preview state file must be owner-only."
        )
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CharacterSetMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    preview_ref = stored.get("preview_ref") if isinstance(stored, dict) else None
    if not isinstance(preview_ref, str) or not preview_ref.startswith(_PREVIEW_PREFIX):
        raise CharacterSetMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-character-set-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_character_set_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_character_set_name=args.preview_character_set_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
            )
        )
    except CharacterSetMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
