#!/usr/bin/env python3
"""Accept the bounded V4 Address Group OAuth/MCP C/P/E flow."""

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
        "preview_v4_address_group_create",
        "confirm_v4_address_group_create",
        "execute_confirmed_v4_address_group_create",
    }
)
WORKFLOW = "fortipam_v4_address_group_create_cli_fallback_workflow_v1"
EXECUTION = "fortipam_v4_address_group_create_cli_fallback_execution_v1"
PREFIX = "address-group-preview-"
AUTHORIZATION_PREFIX = "address-group-authorized-"


class AddressGroupMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded Address Group acceptance fails."""


async def run_address_group_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_group_name: str | None = None,
    preview_member_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify the Tool surface, or save/execute one fixed Group C/P/E flow."""

    preview_inputs = (preview_group_name, preview_member_name, preview_state_file)
    preview_requested = any(value is not None for value in preview_inputs)
    if preview_requested and execute_preview_state_file is not None:
        raise AddressGroupMcpOAuthAcceptanceError(
            "Address Group preview and execution inputs cannot be combined."
        )
    if preview_requested and any(value is None for value in preview_inputs):
        raise AddressGroupMcpOAuthAcceptanceError(
            "Address Group preview inputs are incomplete."
        )

    preview_verified = False
    execution_verified = False
    callback_phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal callback_phase, preview_verified, execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not TOOLS <= names:
            raise AddressGroupMcpOAuthAcceptanceError(
                "Address Group MCP Tool surface is incomplete."
            )
        if preview_requested:
            assert preview_group_name is not None
            assert preview_member_name is not None
            assert preview_state_file is not None
            callback_phase = "preview"
            preview = await session.call_tool(
                "preview_v4_address_group_create",
                {"group_name": preview_group_name, "member_name": preview_member_name},
            )
            projection = preview.structured_content
            _validate_preview(
                projection,
                preview_group_name,
                preview_member_name,
                preview.is_error,
            )
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(preview_state_file, preview_ref)
            preview_verified = True
        if execute_preview_state_file is not None:
            callback_phase = "confirmation"
            preview_ref = _read_preview_ref(execute_preview_state_file)
            confirmation = await session.call_tool(
                "confirm_v4_address_group_create", {"preview_ref": preview_ref}
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
                raise AddressGroupMcpOAuthAcceptanceError(
                    "Address Group MCP confirmation failed."
                )
            callback_phase = "execution readback"
            execution = await session.call_tool(
                "execute_confirmed_v4_address_group_create",
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
                or result.get("address_group_name_returned") is not False
                or result.get("member_address_name_returned") is not False
                or result.get("raw_cli_returned") is not False
            ):
                raise AddressGroupMcpOAuthAcceptanceError(
                    "Address Group MCP execution readback failed."
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
        raise AddressGroupMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise AddressGroupMcpOAuthAcceptanceError(
                f"Address Group MCP {callback_phase} failed."
            ) from None
        raise

    return {
        "contract": "fortipam_v4_address_group_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "address_group_tool_surface_complete": True,
        "address_group_preview_verified": preview_verified,
        "address_group_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(
    projection: Any,
    group_name: str,
    member_name: str,
    is_error: bool,
) -> None:
    """Reject projections outside the fixed single-ipmask-member contract."""

    if not isinstance(projection, dict):
        raise AddressGroupMcpOAuthAcceptanceError("Address Group MCP preview failed.")
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
        or current.get("requested_address_group_name") != group_name
        or current.get("requested_member_address_name") != member_name
        or current.get("address_group_exists") is not False
        or current.get("member_address_exists") is not True
        or current.get("member_address_type") != "ipv4_ipmask"
        or current.get("write_transport") != "ssh_cli_fallback"
        or proposed.get("operation")
        != "create_single_member_address_group_via_cli_fallback"
        or proposed.get("address_group_name") != group_name
        or proposed.get("member_address_name") != member_name
        or proposed.get("member_count") != 1
        or proposed.get("rest_write_attempted") is not False
        or proposed.get("compiled_cli_sequence") != "firewall_addrgrp_edit_set_member"
        or expected.get("address_group_name_matches") is not True
        or expected.get("member_address_name_matches") is not True
        or expected.get("address_group_exists") is not True
        or expected.get("exactly_one_member_matches") is not True
        or expected.get("readback_transport") != "ssh_cli"
    ):
        raise AddressGroupMcpOAuthAcceptanceError(
            "Address Group C/P/E projection was invalid."
        )


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    for nested in error.exceptions:
        if isinstance(nested, AddressGroupMcpOAuthAcceptanceError):
            return True
        if isinstance(nested, BaseExceptionGroup) and _contains_acceptance_error(nested):
            return True
    return False


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise AddressGroupMcpOAuthAcceptanceError("Preview state directory is invalid.")
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise AddressGroupMcpOAuthAcceptanceError(
            "Preview state directory must be owner-only."
        )
    if path.exists() or path.is_symlink() or not preview_ref.startswith(PREFIX):
        raise AddressGroupMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(
            descriptor,
            json.dumps({"preview_ref": preview_ref}, separators=(",", ":")).encode("utf-8"),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise AddressGroupMcpOAuthAcceptanceError("Preview state file is invalid.")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise AddressGroupMcpOAuthAcceptanceError("Preview state file must be owner-only.")
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AddressGroupMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    preview_ref = stored.get("preview_ref") if isinstance(stored, dict) else None
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREFIX):
        raise AddressGroupMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-group-name")
    parser.add_argument("--preview-member-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_address_group_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_group_name=args.preview_group_name,
                preview_member_name=args.preview_member_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
            )
        )
    except AddressGroupMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
