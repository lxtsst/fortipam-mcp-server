#!/usr/bin/env python3
"""Accept the fixed AntiVirus Profile delete/recovery OAuth/MCP flow."""

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
        "preview_v4_antivirus_profile_delete",
        "confirm_v4_antivirus_profile_delete",
        "execute_confirmed_v4_antivirus_profile_delete",
    }
)
WORKFLOW = "fortipam_v4_antivirus_profile_delete_api_workflow_v1"
EXECUTION = "fortipam_v4_antivirus_profile_delete_api_execution_v1"
PREFIX = "antivirus-profile-delete-preview-"


class AntivirusProfileDeleteMcpOAuthAcceptanceError(RuntimeError):
    """Raised when the fixed AntiVirus Profile recovery acceptance fails."""


async def run_antivirus_profile_delete_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify Tool surface, or save/execute exactly one recovery C/P/E."""

    if preview_state_file is not None and execute_preview_state_file is not None:
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "AntiVirus Profile delete preview and execution cannot be combined."
        )
    preview_verified = False
    execution_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not TOOLS <= names:
            raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
                "AntiVirus Profile delete MCP Tool surface is incomplete."
            )
        if preview_state_file is not None:
            preview = await session.call_tool(
                "preview_v4_antivirus_profile_delete",
                {},
            )
            projection = preview.structured_content
            _validate_preview(projection, preview.is_error)
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(preview_state_file, preview_ref)
            preview_verified = True
        if execute_preview_state_file is not None:
            preview_ref = _read_preview_ref(execute_preview_state_file)
            confirmation = await session.call_tool(
                "confirm_v4_antivirus_profile_delete",
                {"preview_ref": preview_ref},
            )
            confirmed = confirmation.structured_content
            authorization_ref = (
                confirmed.get("authorization_ref")
                if isinstance(confirmed, dict)
                else None
            )
            if (
                confirmation.is_error
                or not isinstance(confirmed, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith(
                    "antivirus-profile-delete-authorized-"
                )
                or confirmed.get("contract") != WORKFLOW
                or confirmed.get("confirmation") != "recorded"
                or confirmed.get("execution") != "authorized_once"
                or confirmed.get("device_write_executed") is not False
            ):
                raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
                    "AntiVirus Profile delete MCP confirmation failed."
                )
            execution = await session.call_tool(
                "execute_confirmed_v4_antivirus_profile_delete",
                {"authorization_ref": authorization_ref},
            )
            _validate_execution(execution.structured_content, execution.is_error)
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
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(str(exc)) from None

    return {
        "contract": "fortipam_v4_antivirus_profile_delete_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "antivirus_profile_delete_tool_surface_complete": True,
        "antivirus_profile_delete_preview_verified": preview_verified,
        "antivirus_profile_delete_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(projection: Any, is_error: bool) -> None:
    if not isinstance(projection, dict):
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "AntiVirus Profile delete MCP preview failed."
        )
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
        or current.get("accepted_antivirus_profile_exists") is not True
        or current.get("exact_fixed_http_ssh_block_profile_observed") is not True
        or current.get("complete_api_record_digest_matches") is not True
        or current.get("secret_reference_count") != 0
        or current.get("read_transports") != ["rest_api", "ssh_cli"]
        or proposed.get("operation")
        != "delete_exact_unreferenced_antivirus_profile_via_api"
        or proposed.get("antivirus_profile_count_affected") != 1
        or proposed.get("irreversible_after_execution") is not True
        or proposed.get("secret_association_changes") is not False
        or proposed.get("fortisandbox_or_license_changes") is not False
        or proposed.get("protocol_or_scan_mode_changes") is not False
        or expected.get("accepted_antivirus_profile_absent") is not True
        or expected.get("secret_association_changes") is not False
        or expected.get("fortisandbox_or_license_changes") is not False
        or expected.get("protocol_or_scan_mode_changes") is not False
        or expected.get("readback_transports") != ["rest_api", "ssh_cli"]
        or "mcp-v4-av-profile" in repr(projection)
    ):
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "AntiVirus Profile delete C/P/E projection was invalid."
        )


def _validate_execution(result: Any, is_error: bool) -> None:
    if (
        is_error
        or not isinstance(result, dict)
        or result.get("contract") != EXECUTION
        or result.get("outcome") != "succeeded"
        or result.get("verification") != "verified"
        or result.get("idempotent_replay") is not False
        or result.get("compensation")
        != "separate_antivirus_profile_create_action_required"
        or result.get("irreversible_after_execution") is not True
        or result.get("antivirus_profile_name_returned") is not False
        or result.get("profile_content_returned") is not False
        or result.get("secret_association_changes") is not False
        or result.get("fortisandbox_or_license_changes") is not False
        or result.get("protocol_or_scan_mode_changes") is not False
        or result.get("raw_api_or_cli_response_returned") is not False
    ):
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "AntiVirus Profile delete MCP execution readback failed."
        )


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "Preview state directory is invalid."
        )
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "Preview state directory must be owner-only."
        )
    if path.exists() or path.is_symlink():
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "Preview state file already exists."
        )
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREFIX):
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "Preview state reference is invalid."
        )
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
    if path.is_symlink() or not path.is_file():
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        )
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "Preview state file must be owner-only."
        )
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        ) from exc
    preview_ref = stored.get("preview_ref") if isinstance(stored, dict) else None
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREFIX):
        raise AntivirusProfileDeleteMcpOAuthAcceptanceError(
            "Preview state reference is invalid."
        )
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_antivirus_profile_delete_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
            )
        )
    except AntivirusProfileDeleteMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
