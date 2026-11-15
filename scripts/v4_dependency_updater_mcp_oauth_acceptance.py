#!/usr/bin/env python3
"""Accept one bounded V4 Dependency Updater OAuth/MCP C/P/E flow."""

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


TOOLS = frozenset({"preview_v4_dependency_updater_create", "confirm_v4_dependency_updater_create", "execute_confirmed_v4_dependency_updater_create"})
WORKFLOW = "fortipam_v4_dependency_updater_create_cli_fallback_workflow_v1"
EXECUTION = "fortipam_v4_dependency_updater_create_cli_fallback_execution_v1"
PREVIEW_PREFIX = "dependency-updater-preview-"
AUTHORIZATION_PREFIX = "dependency-updater-authorized-"


class DependencyUpdaterMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded Dependency Updater acceptance fails."""


async def run_dependency_updater_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, *, updater_name: str | None = None,
    service_name: str | None = None, preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None, ca_file: Path | None = None,
) -> dict[str, object]:
    """Verify or execute one fixed unattached Windows-service Updater flow."""

    preview_requested = any(value is not None for value in (updater_name, service_name, preview_state_file))
    if preview_requested and execute_preview_state_file is not None:
        raise DependencyUpdaterMcpOAuthAcceptanceError("Dependency Updater preview and execution inputs cannot be combined.")
    if preview_requested and (updater_name is None or service_name is None or preview_state_file is None):
        raise DependencyUpdaterMcpOAuthAcceptanceError("Dependency Updater preview inputs are incomplete.")
    preview_verified = execution_verified = False
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise DependencyUpdaterMcpOAuthAcceptanceError("Dependency Updater MCP Tool surface is incomplete.")
        if preview_requested:
            assert updater_name is not None and service_name is not None and preview_state_file is not None
            phase = "preview"
            reply = await session.call_tool("preview_v4_dependency_updater_create", {"updater_name": updater_name, "service_name": service_name})
            _validate_preview(reply.structured_content, updater_name, service_name, reply.is_error)
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(preview_state_file, str(reply.structured_content["preview_ref"]))
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool("confirm_v4_dependency_updater_create", {"preview_ref": _read_preview_ref(execute_preview_state_file)})
            body = confirmation.structured_content
            authorization_ref = body.get("authorization_ref") if isinstance(body, dict) else None
            if (confirmation.is_error or not isinstance(body, dict) or not isinstance(authorization_ref, str)
                    or not authorization_ref.startswith(AUTHORIZATION_PREFIX) or body.get("contract") != WORKFLOW
                    or body.get("confirmation") != "recorded" or body.get("execution") != "authorized_once"
                    or body.get("device_write_executed") is not False):
                raise DependencyUpdaterMcpOAuthAcceptanceError("Dependency Updater MCP confirmation failed.")
            phase = "execution readback"
            reply = await session.call_tool("execute_confirmed_v4_dependency_updater_create", {"authorization_ref": authorization_ref})
            _validate_execution(reply.structured_content, reply.is_error)
            execute_preview_state_file.unlink()
            execution_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(url, login_file, client_state_file, ca_file=ca_file, tool_session_callback=callback, required_tools=TOOLS)
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise DependencyUpdaterMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise DependencyUpdaterMcpOAuthAcceptanceError(f"Dependency Updater MCP {phase} failed.") from None
        raise
    return {"contract": "fortipam_v4_dependency_updater_mcp_oauth_acceptance_v1", "oauth_metadata_verified": common["oauth_metadata_verified"], "mcp_initialized": common["mcp_initialized"], "dependency_updater_tool_surface_complete": True, "dependency_updater_preview_verified": preview_verified, "dependency_updater_execution_verified": execution_verified, "device_tool_invoked": preview_verified or execution_verified, "device_write_executed": execution_verified, "token_revoked": common["token_revoked"], "credential_values_returned": common["credential_values_returned"], "token_returned": False, "client_id_returned": False}


def _validate_preview(projection: Any, updater_name: str, service_name: str, is_error: bool) -> None:
    current = projection.get("Current State") if isinstance(projection, dict) else None
    proposed = projection.get("Proposed Changes") if isinstance(projection, dict) else None
    expected = projection.get("Expected State") if isinstance(projection, dict) else None
    preview_ref = projection.get("preview_ref") if isinstance(projection, dict) else None
    if (is_error or not isinstance(current, dict) or not isinstance(proposed, dict) or not isinstance(expected, dict)
            or not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX) or projection.get("contract") != WORKFLOW
            or projection.get("device_write_executed") is not False or current.get("requested_updater_name") != updater_name
            or current.get("requested_service_name") != service_name or current.get("updater_name_exists") is not False
            or current.get("write_transport") != "ssh_cli_fallback" or proposed.get("operation") != "create_dependency_updater_via_cli_fallback"
            or proposed.get("updater_name") != updater_name or proposed.get("service_name") != service_name
            or proposed.get("configuration_profile") != "win-service-restart-disabled-v1" or proposed.get("updater_type") != "win-service"
            or proposed.get("restart_after_updates") != "disable" or any(proposed.get(key) is not False for key in ("secret_or_target_association_changes", "service_operation_executed", "rest_write_attempted"))
            or any(expected.get(key) is not True for key in ("updater_name_matches", "updater_name_exists", "win_service_type_enabled", "restart_disabled", "service_name_matches"))
            or any(expected.get(key) is not False for key in ("secret_or_target_association_changes", "service_operation_executed"))
            or expected.get("readback_transport") != "ssh_cli"):
        raise DependencyUpdaterMcpOAuthAcceptanceError("Dependency Updater C/P/E projection was invalid.")


def _validate_execution(result: Any, is_error: bool) -> None:
    if (is_error or not isinstance(result, dict) or result.get("contract") != EXECUTION or result.get("outcome") != "succeeded"
            or result.get("verification") != "verified" or result.get("idempotent_replay") is not False
            or result.get("compensation") != "separate_dependency_updater_delete_action_required"
            or any(result.get(key) is not False for key in ("updater_name_returned", "service_name_returned", "secret_or_target_association_changes", "service_operation_executed", "raw_cli_returned"))):
        raise DependencyUpdaterMcpOAuthAcceptanceError("Dependency Updater MCP execution readback failed.")


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(isinstance(item, DependencyUpdaterMcpOAuthAcceptanceError) or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item)) for item in error.exceptions)


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077 or path.exists() or path.is_symlink() or not preview_ref.startswith(PREVIEW_PREFIX):
        raise DependencyUpdaterMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": preview_ref}).encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise DependencyUpdaterMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        preview_ref = json.loads(path.read_text(encoding="utf-8")).get("preview_ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise DependencyUpdaterMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise DependencyUpdaterMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--updater-name")
    parser.add_argument("--service-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(run_dependency_updater_mcp_oauth_acceptance(args.url, args.login_file, args.client_state_file, updater_name=args.updater_name, service_name=args.service_name, preview_state_file=args.preview_state_file, execute_preview_state_file=args.execute_preview_state_file, ca_file=args.ca_file))
    except DependencyUpdaterMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
