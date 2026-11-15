#!/usr/bin/env python3
"""Accept the bounded V4 Role-create OAuth/MCP C/P/E flow."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any
from urllib.parse import urlsplit

from mcp import ClientSession

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import v4_address_mcp_oauth_surface_acceptance as oauth


TOOLS = frozenset(
    {
        "preview_v4_role_create",
        "confirm_v4_role_create",
        "execute_confirmed_v4_role_create",
    }
)
WORKFLOW = "fortipam_v4_role_create_workflow_v1"
EXECUTION = "fortipam_v4_role_create_execution_v1"
PREFIX = "role-create-preview-"


class RoleCreateMcpOAuthAcceptanceError(RuntimeError):
    """Raised when the bounded Role-create acceptance fails."""


async def run_role_create_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_role_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify the Tool surface, or save/execute exactly one C/P/E request."""

    preview_requested = any(
        value is not None for value in (preview_role_name, preview_state_file)
    )
    if preview_requested and execute_preview_state_file is not None:
        raise RoleCreateMcpOAuthAcceptanceError(
            "Role-create preview and execution inputs cannot be combined."
        )
    if preview_requested and (
        not isinstance(preview_role_name, str) or preview_state_file is None
    ):
        raise RoleCreateMcpOAuthAcceptanceError("Role-create preview inputs are incomplete.")

    preview_verified = False
    execution_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not TOOLS <= names:
            raise RoleCreateMcpOAuthAcceptanceError("Role-create MCP Tool surface is incomplete.")
        if preview_role_name is not None:
            assert preview_state_file is not None
            preview = await session.call_tool(
                "preview_v4_role_create", {"role_name": preview_role_name}
            )
            projection = preview.structured_content
            _validate_preview(projection, preview_role_name, preview.is_error)
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(preview_state_file, preview_ref)
            preview_verified = True
        if execute_preview_state_file is not None:
            preview_ref = _read_preview_ref(execute_preview_state_file)
            confirmation = await session.call_tool(
                "confirm_v4_role_create", {"preview_ref": preview_ref}
            )
            confirmed = confirmation.structured_content
            authorization_ref = (
                confirmed.get("authorization_ref") if isinstance(confirmed, dict) else None
            )
            if (
                confirmation.is_error
                or not isinstance(confirmed, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith("role-create-authorized-")
                or confirmed.get("contract") != WORKFLOW
                or confirmed.get("confirmation") != "recorded"
                or confirmed.get("execution") != "authorized_once"
                or confirmed.get("device_write_executed") is not False
            ):
                raise RoleCreateMcpOAuthAcceptanceError("Role-create MCP confirmation failed.")
            execution = await session.call_tool(
                "execute_confirmed_v4_role_create",
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
                or result.get("role_assignments_changed") is not False
                or result.get("raw_cli_returned") is not False
            ):
                raise RoleCreateMcpOAuthAcceptanceError("Role-create MCP execution readback failed.")
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
            allow_insecure_private_ip_lab=_is_private_ip_lab_url(url),
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise RoleCreateMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_role_create_acceptance_error(exc):
            raise RoleCreateMcpOAuthAcceptanceError(
                "Role-create MCP execution readback failed."
            ) from None
        raise

    return {
        "contract": "fortipam_v4_role_create_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "role_create_tool_surface_complete": True,
        "role_create_preview_verified": preview_verified,
        "role_create_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(projection: Any, name: str, is_error: bool) -> None:
    """Reject any projection outside the fixed unassigned-Role contract."""

    if not isinstance(projection, dict):
        raise RoleCreateMcpOAuthAcceptanceError("Role-create MCP preview failed.")
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
        or current.get("requested_role_name") != name
        or current.get("role_exists") is not False
        or proposed.get("operation") != "create_unassigned_guide_example_role"
        or proposed.get("role_name") != name
        or proposed.get("configuration_profile") != "pam_standard_user_guide_profile_v1"
        or proposed.get("user_or_group_assignment_changes") is not False
        or proposed.get("folder_target_or_secret_changes") is not False
        or expected.get("role_name_matches") is not True
        or expected.get("role_exists") is not True
        or expected.get("core_access_matches") is not True
        or expected.get("secret_permissions_match") is not True
        or expected.get("system_diagnostics_disabled") is not True
        or expected.get("user_or_group_assignment_changes") is not False
    ):
        raise RoleCreateMcpOAuthAcceptanceError("Role-create C/P/E projection was invalid.")


def _contains_role_create_acceptance_error(error: BaseExceptionGroup) -> bool:
    """Recognize callback failures wrapped by streamable HTTP task groups."""

    for nested in error.exceptions:
        if isinstance(nested, RoleCreateMcpOAuthAcceptanceError):
            return True
        if isinstance(nested, BaseExceptionGroup) and _contains_role_create_acceptance_error(
            nested
        ):
            return True
    return False


def _is_private_ip_lab_url(url: str) -> bool:
    """Allow only the V4 direct-HTTP laboratory resource shape."""

    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.port is not None
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.path.rstrip("/")
    ):
        return False
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return False
    return address.version == 4 and address in ipaddress.ip_network((0x0A000000, 8))


def _write_preview_state(
    path: Path,
    preview_ref: str,
    *,
    prefix: str = PREFIX,
) -> None:
    """Persist one owner-only opaque Role-action preview reference."""

    if path.parent.is_symlink() or not path.parent.is_dir():
        raise RoleCreateMcpOAuthAcceptanceError("Preview state directory is invalid.")
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise RoleCreateMcpOAuthAcceptanceError(
            "Preview state directory must be owner-only."
        )
    if path.exists() or path.is_symlink():
        raise RoleCreateMcpOAuthAcceptanceError("Preview state file already exists.")
    if not isinstance(preview_ref, str) or not preview_ref.startswith(prefix):
        raise RoleCreateMcpOAuthAcceptanceError("Preview state reference is invalid.")
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


def _read_preview_ref(path: Path, *, prefix: str = PREFIX) -> str:
    """Read one owner-only opaque Role-action preview reference."""

    if path.is_symlink() or not path.is_file():
        raise RoleCreateMcpOAuthAcceptanceError("Preview state file is invalid.")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RoleCreateMcpOAuthAcceptanceError("Preview state file must be owner-only.")
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RoleCreateMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    preview_ref = stored.get("preview_ref") if isinstance(stored, dict) else None
    if not isinstance(preview_ref, str) or not preview_ref.startswith(prefix):
        raise RoleCreateMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-role-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_role_create_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_role_name=args.preview_role_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
            )
        )
    except RoleCreateMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
