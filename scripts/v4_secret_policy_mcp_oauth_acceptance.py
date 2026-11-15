#!/usr/bin/env python3
"""Accept the bounded V4 Secret Policy OAuth/MCP surface and C/P/E flow."""

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

from scripts import v4_address_mcp_oauth_surface_acceptance as oauth_acceptance


SECRET_POLICY_TOOLS = frozenset(
    {
        "preview_v4_secret_policy_create",
        "confirm_v4_secret_policy_create",
        "execute_confirmed_v4_secret_policy_create",
        "preview_v4_secret_policy_update",
        "confirm_v4_secret_policy_update",
        "execute_confirmed_v4_secret_policy_update",
    }
)
_CREATE_WORKFLOW_CONTRACT = "fortipam_v4_secret_policy_create_cli_fallback_workflow_v1"
_CREATE_EXECUTION_CONTRACT = "fortipam_v4_secret_policy_create_cli_fallback_execution_v1"
_UPDATE_WORKFLOW_CONTRACT = "fortipam_v4_secret_policy_update_cli_workflow_v1"
_UPDATE_EXECUTION_CONTRACT = "fortipam_v4_secret_policy_update_cli_execution_v1"
_CREATE_PREVIEW_PREFIX = "secret-policy-preview-"
_UPDATE_PREVIEW_PREFIX = "secret-policy-update-preview-"


class SecretPolicyMcpOAuthAcceptanceError(RuntimeError):
    """Raised when the bounded Secret Policy OAuth/MCP contract fails."""


async def run_secret_policy_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_policy_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    preview_update_policy_name: str | None = None,
    update_preview_state_file: Path | None = None,
    execute_update_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify the surface, optionally save a no-write preview or execute it."""

    operations = (
        execute_preview_state_file is not None,
        any(value is not None for value in (preview_policy_name, preview_state_file)),
        execute_update_preview_state_file is not None,
        any(
            value is not None
            for value in (preview_update_policy_name, update_preview_state_file)
        ),
    )
    if sum(operations) > 1:
        raise SecretPolicyMcpOAuthAcceptanceError(
            "Secret Policy preview and execution inputs cannot be combined."
        )
    if operations[1] and (
        not isinstance(preview_policy_name, str) or preview_state_file is None
    ):
        raise SecretPolicyMcpOAuthAcceptanceError(
            "Secret Policy create preview inputs are incomplete."
        )
    if operations[3] and (
        not isinstance(preview_update_policy_name, str)
        or update_preview_state_file is None
    ):
        raise SecretPolicyMcpOAuthAcceptanceError(
            "Secret Policy update preview inputs are incomplete."
        )

    preview_verified = False
    execution_verified = False
    update_preview_verified = False
    update_execution_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        nonlocal update_preview_verified, update_execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not SECRET_POLICY_TOOLS <= names:
            raise SecretPolicyMcpOAuthAcceptanceError(
                "Secret Policy MCP Tool surface is incomplete."
            )
        if preview_policy_name is not None:
            assert preview_state_file is not None
            preview = await session.call_tool(
                "preview_v4_secret_policy_create",
                {"policy_name": preview_policy_name},
            )
            projection = preview.structured_content
            _validate_preview(projection, preview_policy_name, preview.is_error)
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(
                preview_state_file,
                preview_ref,
                prefix=_CREATE_PREVIEW_PREFIX,
            )
            preview_verified = True
        if execute_preview_state_file is not None:
            preview_ref = _read_preview_ref(
                execute_preview_state_file,
                prefix=_CREATE_PREVIEW_PREFIX,
            )
            confirmation = await session.call_tool(
                "confirm_v4_secret_policy_create",
                {"preview_ref": preview_ref},
            )
            confirmed = confirmation.structured_content
            authorization_ref = (
                confirmed.get("authorization_ref") if isinstance(confirmed, dict) else None
            )
            if (
                confirmation.is_error
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith("secret-policy-authorized-")
                or not isinstance(confirmed, dict)
                or confirmed.get("contract") != _CREATE_WORKFLOW_CONTRACT
                or confirmed.get("confirmation") != "recorded"
                or confirmed.get("execution") != "authorized_once"
                or confirmed.get("device_write_executed") is not False
            ):
                raise SecretPolicyMcpOAuthAcceptanceError(
                    "Secret Policy MCP confirmation failed."
                )
            execution = await session.call_tool(
                "execute_confirmed_v4_secret_policy_create",
                {"authorization_ref": authorization_ref},
            )
            result = execution.structured_content
            if (
                execution.is_error
                or not isinstance(result, dict)
                or result.get("contract") != _CREATE_EXECUTION_CONTRACT
                or result.get("outcome") != "succeeded"
                or result.get("verification") != "verified"
                or result.get("idempotent_replay") is not False
                or result.get("policy_name_returned") is not False
                or result.get("folder_or_secret_association_changes") is not False
                or result.get("raw_cli_returned") is not False
            ):
                raise SecretPolicyMcpOAuthAcceptanceError(
                    "Secret Policy MCP execution readback failed."
                )
            execute_preview_state_file.unlink()
            execution_verified = True
        if preview_update_policy_name is not None:
            assert update_preview_state_file is not None
            preview = await session.call_tool(
                "preview_v4_secret_policy_update",
                {"policy_name": preview_update_policy_name},
            )
            projection = preview.structured_content
            _validate_update_preview(
                projection,
                preview_update_policy_name,
                preview.is_error,
            )
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(
                update_preview_state_file,
                preview_ref,
                prefix=_UPDATE_PREVIEW_PREFIX,
            )
            update_preview_verified = True
        if execute_update_preview_state_file is not None:
            preview_ref = _read_preview_ref(
                execute_update_preview_state_file,
                prefix=_UPDATE_PREVIEW_PREFIX,
            )
            confirmation = await session.call_tool(
                "confirm_v4_secret_policy_update",
                {"preview_ref": preview_ref},
            )
            confirmed = confirmation.structured_content
            authorization_ref = (
                confirmed.get("authorization_ref") if isinstance(confirmed, dict) else None
            )
            if (
                confirmation.is_error
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith("secret-policy-update-authorized-")
                or not isinstance(confirmed, dict)
                or confirmed.get("contract") != _UPDATE_WORKFLOW_CONTRACT
                or confirmed.get("confirmation") != "recorded"
                or confirmed.get("execution") != "authorized_once"
                or confirmed.get("device_write_executed") is not False
            ):
                raise SecretPolicyMcpOAuthAcceptanceError(
                    "Secret Policy update MCP confirmation failed."
                )
            execution = await session.call_tool(
                "execute_confirmed_v4_secret_policy_update",
                {"authorization_ref": authorization_ref},
            )
            result = execution.structured_content
            if (
                execution.is_error
                or not isinstance(result, dict)
                or result.get("contract") != _UPDATE_EXECUTION_CONTRACT
                or result.get("outcome") != "succeeded"
                or result.get("verification") != "verified"
                or result.get("idempotent_replay") is not False
                or result.get("policy_name_returned") is not False
                or result.get("folder_or_secret_association_changes") is not False
                or result.get("raw_cli_returned") is not False
            ):
                raise SecretPolicyMcpOAuthAcceptanceError(
                    "Secret Policy update MCP execution readback failed."
                )
            execute_update_preview_state_file.unlink()
            update_execution_verified = True

    try:
        common = await oauth_acceptance.run_address_mcp_oauth_surface_acceptance(
            url,
            login_file,
            client_state_file,
            ca_file=ca_file,
            tool_session_callback=callback,
            required_tools=SECRET_POLICY_TOOLS,
        )
    except oauth_acceptance.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise SecretPolicyMcpOAuthAcceptanceError(str(exc)) from None

    return {
        "contract": "fortipam_v4_secret_policy_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "secret_policy_tool_surface_complete": True,
        "secret_policy_preview_verified": preview_verified,
        "secret_policy_execution_verified": execution_verified,
        "secret_policy_update_preview_verified": update_preview_verified,
        "secret_policy_update_execution_verified": update_execution_verified,
        "device_tool_invoked": any(
            (
                preview_verified,
                execution_verified,
                update_preview_verified,
                update_execution_verified,
            )
        ),
        "device_write_executed": execution_verified or update_execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(
    projection: Any,
    policy_name: str,
    is_error: bool,
) -> None:
    if not isinstance(projection, dict):
        raise SecretPolicyMcpOAuthAcceptanceError("Secret Policy MCP preview failed.")
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
        or not preview_ref.startswith("secret-policy-preview-")
        or projection.get("contract") != _CREATE_WORKFLOW_CONTRACT
        or projection.get("device_write_executed") is not False
        or current.get("requested_policy_name") != policy_name
        or current.get("policy_name_exists") is not False
        or proposed.get("policy_name") != policy_name
        or proposed.get("ssh_filter") != "disable"
        or proposed.get("rdp_clipboard_block") != "enable"
        or proposed.get("folder_or_secret_association_changes") is not False
        or expected.get("policy_name_exists") is not True
        or expected.get("ssh_filter_disabled") is not True
        or expected.get("rdp_clipboard_block_enabled") is not True
        or expected.get("folder_or_secret_association_changes") is not False
    ):
        raise SecretPolicyMcpOAuthAcceptanceError(
            "Secret Policy C/P/E projection was invalid."
        )


def _validate_update_preview(
    projection: Any,
    policy_name: str,
    is_error: bool,
) -> None:
    if not isinstance(projection, dict):
        raise SecretPolicyMcpOAuthAcceptanceError("Secret Policy update MCP preview failed.")
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
        or not preview_ref.startswith(_UPDATE_PREVIEW_PREFIX)
        or projection.get("contract") != _UPDATE_WORKFLOW_CONTRACT
        or projection.get("device_write_executed") is not False
        or current.get("requested_policy_name") != policy_name
        or current.get("policy_name_exists") is not True
        or current.get("known_create_baseline_verified") is not True
        or current.get("ssh_filter_disabled") is not True
        or current.get("rdp_clipboard_block_enabled") is not True
        or proposed.get("policy_name") != policy_name
        or proposed.get("rdp_clipboard_block") != "disable"
        or proposed.get("ssh_filter_changes") is not False
        or proposed.get("folder_or_secret_association_changes") is not False
        or expected.get("policy_name_exists") is not True
        or expected.get("ssh_filter_disabled") is not True
        or expected.get("rdp_clipboard_block_disabled") is not True
        or expected.get("ssh_filter_changes") is not False
        or expected.get("folder_or_secret_association_changes") is not False
    ):
        raise SecretPolicyMcpOAuthAcceptanceError(
            "Secret Policy update C/P/E projection was invalid."
        )


def _write_preview_state(path: Path, preview_ref: str, *, prefix: str = _CREATE_PREVIEW_PREFIX) -> None:
    """Persist only one owner-only opaque preview reference of the requested type."""

    if path.parent.is_symlink() or not path.parent.is_dir():
        raise SecretPolicyMcpOAuthAcceptanceError("Preview state directory is invalid.")
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise SecretPolicyMcpOAuthAcceptanceError(
            "Preview state directory must be owner-only."
        )
    if path.exists() or path.is_symlink():
        raise SecretPolicyMcpOAuthAcceptanceError("Preview state file already exists.")
    if not isinstance(preview_ref, str) or not preview_ref.startswith(prefix):
        raise SecretPolicyMcpOAuthAcceptanceError("Preview state reference is invalid.")
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


def _read_preview_ref(path: Path, *, prefix: str = _CREATE_PREVIEW_PREFIX) -> str:
    """Read one owner-only opaque Secret Policy reference of the requested type."""

    if path.is_symlink() or not path.is_file():
        raise SecretPolicyMcpOAuthAcceptanceError("Preview state file is invalid.")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise SecretPolicyMcpOAuthAcceptanceError(
            "Preview state file must be owner-only."
        )
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecretPolicyMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    preview_ref = stored.get("preview_ref") if isinstance(stored, dict) else None
    if not isinstance(preview_ref, str) or not preview_ref.startswith(prefix):
        raise SecretPolicyMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-policy-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--preview-update-policy-name")
    parser.add_argument("--update-preview-state-file", type=Path)
    parser.add_argument("--execute-update-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_secret_policy_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_policy_name=args.preview_policy_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
                preview_update_policy_name=args.preview_update_policy_name,
                update_preview_state_file=args.update_preview_state_file,
                execute_update_preview_state_file=args.execute_update_preview_state_file,
            )
        )
    except SecretPolicyMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
