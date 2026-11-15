#!/usr/bin/env python3
"""Accept one bounded V4 native-RDP Launcher OAuth/MCP C/P/E flow."""

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
        "preview_v4_launcher_create",
        "confirm_v4_launcher_create",
        "execute_confirmed_v4_launcher_create",
    }
)
WORKFLOW = "fortipam_v4_launcher_create_cli_fallback_workflow_v1"
EXECUTION = "fortipam_v4_launcher_create_cli_fallback_execution_v1"
PREVIEW_PREFIX = "launcher-preview-"
AUTHORIZATION_PREFIX = "launcher-authorized-"


class LauncherMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded Launcher acceptance fails."""


async def run_launcher_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    launcher_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    ca_file: Path | None = None,
    allow_insecure_private_ip_lab: bool = False,
) -> dict[str, object]:
    """Verify or execute one unassociated native-RDP Launcher flow."""

    preview_requested = launcher_name is not None or preview_state_file is not None
    if preview_requested and execute_preview_state_file is not None:
        raise LauncherMcpOAuthAcceptanceError(
            "Launcher preview and execution inputs cannot be combined."
        )
    if preview_requested and (launcher_name is None or preview_state_file is None):
        raise LauncherMcpOAuthAcceptanceError("Launcher preview inputs are incomplete.")
    preview_verified = execution_verified = False
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise LauncherMcpOAuthAcceptanceError("Launcher MCP Tool surface is incomplete.")
        if preview_requested:
            assert launcher_name is not None and preview_state_file is not None
            phase = "preview"
            reply = await session.call_tool(
                "preview_v4_launcher_create", {"launcher_name": launcher_name}
            )
            _validate_preview(reply.structured_content, launcher_name, reply.is_error)
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(
                preview_state_file, str(reply.structured_content["preview_ref"])
            )
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool(
                "confirm_v4_launcher_create",
                {"preview_ref": _read_preview_ref(execute_preview_state_file)},
            )
            body = confirmation.structured_content
            authorization_ref = body.get("authorization_ref") if isinstance(body, dict) else None
            if (
                confirmation.is_error
                or not isinstance(body, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith(AUTHORIZATION_PREFIX)
                or body.get("contract") != WORKFLOW
                or body.get("confirmation") != "recorded"
                or body.get("execution") != "authorized_once"
                or body.get("device_write_executed") is not False
            ):
                raise LauncherMcpOAuthAcceptanceError("Launcher MCP confirmation failed.")
            phase = "execution readback"
            reply = await session.call_tool(
                "execute_confirmed_v4_launcher_create",
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
            allow_insecure_private_ip_lab=allow_insecure_private_ip_lab,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise LauncherMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise LauncherMcpOAuthAcceptanceError(
                f"Launcher MCP {phase} failed."
            ) from None
        raise
    return {
        "contract": "fortipam_v4_launcher_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "launcher_tool_surface_complete": True,
        "launcher_preview_verified": preview_verified,
        "launcher_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(projection: Any, name: str, is_error: bool) -> None:
    current = projection.get("Current State") if isinstance(projection, dict) else None
    proposed = projection.get("Proposed Changes") if isinstance(projection, dict) else None
    expected = projection.get("Expected State") if isinstance(projection, dict) else None
    preview_ref = projection.get("preview_ref") if isinstance(projection, dict) else None
    if (
        is_error
        or not isinstance(current, dict)
        or not isinstance(proposed, dict)
        or not isinstance(expected, dict)
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(PREVIEW_PREFIX)
        or projection.get("contract") != WORKFLOW
        or projection.get("device_write_executed") is not False
        or current.get("requested_launcher_name") != name
        or current.get("launcher_name_exists") is not False
        or current.get("write_transport") != "ssh_cli_fallback"
        or proposed.get("operation") != "create_native_rdp_launcher_via_cli_fallback"
        or proposed.get("launcher_name") != name
        or proposed.get("configuration_profile")
        != "windows-rdp-mstsc-cmdkey-timeout-15-v2"
        or proposed.get("launcher_type") != "rdp"
        or proposed.get("client_executable") != "mstsc.exe"
        or proposed.get("rdp_parameter_template") != "/V:$HOST:$PORT /noConsentPrompt"
        or proposed.get("initial_command") != "cmdkey_setup"
        or proposed.get("cleanup_command") != "cmdkey_delete"
        or proposed.get("launch_timeout_seconds") != 15
        or any(proposed.get(key) is not False for key in (
            "secret_or_template_association_changes",
            "session_or_target_changes",
            "rest_write_attempted",
        ))
        or any(expected.get(key) is not True for key in (
            "launcher_name_matches",
            "launcher_name_exists",
            "type_is_rdp",
            "mstsc_executable_present",
            "native_rdp_parameter_present",
            "cmdkey_initial_command_present",
            "cmdkey_clean_command_present",
        ))
        or expected.get("launch_timeout_seconds") != 15
        or expected.get("secret_or_template_association_changes") is not False
        or expected.get("readback_transport") != "ssh_cli"
    ):
        raise LauncherMcpOAuthAcceptanceError("Launcher C/P/E projection was invalid.")


def _validate_execution(result: Any, is_error: bool) -> None:
    if (
        is_error
        or not isinstance(result, dict)
        or result.get("contract") != EXECUTION
        or result.get("outcome") != "succeeded"
        or result.get("verification") != "verified"
        or result.get("idempotent_replay") is not False
        or result.get("compensation") != "separate_launcher_archive_action_required"
        or result.get("launcher_name_returned") is not False
        or result.get("secret_or_template_association_changes") is not False
        or result.get("raw_cli_returned") is not False
    ):
        raise LauncherMcpOAuthAcceptanceError("Launcher MCP execution readback failed.")


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, LauncherMcpOAuthAcceptanceError)
        or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item))
        for item in error.exceptions
    )


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if (
        path.parent.is_symlink()
        or not path.parent.is_dir()
        or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
        or path.exists()
        or path.is_symlink()
        or not preview_ref.startswith(PREVIEW_PREFIX)
    ):
        raise LauncherMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": preview_ref}).encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise LauncherMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        preview_ref = json.loads(path.read_text(encoding="utf-8")).get("preview_ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise LauncherMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise LauncherMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--launcher-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--allow-insecure-private-ip-lab", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_launcher_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                launcher_name=args.launcher_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
                ca_file=args.ca_file,
                allow_insecure_private_ip_lab=args.allow_insecure_private_ip_lab,
            )
        )
    except LauncherMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
