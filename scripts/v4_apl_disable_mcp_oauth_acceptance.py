#!/usr/bin/env python3
"""Accept one bounded V4 Auto-Provision Rule disable OAuth/MCP flow."""

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


TOOLS = frozenset({"preview_v4_auto_provision_rule_disable", "confirm_v4_auto_provision_rule_disable", "execute_confirmed_v4_auto_provision_rule_disable"})
WORKFLOW = "fortipam_v4_auto_provision_rule_disable_cli_workflow_v1"
EXECUTION = "fortipam_v4_auto_provision_rule_disable_cli_execution_v1"
PREVIEW_PREFIX = "apl-disable-preview-"
AUTHORIZATION_PREFIX = "apl-disable-authorized-"


class AplDisableMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded Auto-Provision Rule disable acceptance fails."""


async def run_apl_disable_mcp_oauth_acceptance(url: str, login_file: Path, client_state_file: Path, *, auto_provision_rule_name: str | None = None, remote_user_group_name: str | None = None, role_name: str | None = None, preview_state_file: Path | None = None, execute_preview_state_file: Path | None = None, ca_file: Path | None = None, allow_insecure_private_ip_lab: bool = False, write_transport: str = "ssh_cli_fallback") -> dict[str, object]:
    """Verify or execute one exact enabled Auto-Provision Rule disable."""
    workflow_contract, _ = _contracts(write_transport)
    inputs = (auto_provision_rule_name, remote_user_group_name, role_name, preview_state_file)
    preview_requested = any(value is not None for value in inputs)
    if preview_requested and execute_preview_state_file is not None:
        raise AplDisableMcpOAuthAcceptanceError("Auto-Provision Rule disable preview and execution inputs cannot be combined.")
    if preview_requested and any(value is None for value in inputs):
        raise AplDisableMcpOAuthAcceptanceError("Auto-Provision Rule disable preview inputs are incomplete.")
    preview_verified = execution_verified = False
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise AplDisableMcpOAuthAcceptanceError("Auto-Provision Rule disable MCP Tool surface is incomplete.")
        if preview_requested:
            assert all(value is not None for value in inputs)
            assert isinstance(auto_provision_rule_name, str) and isinstance(remote_user_group_name, str) and isinstance(role_name, str) and preview_state_file is not None
            phase = "preview"
            reply = await session.call_tool("preview_v4_auto_provision_rule_disable", {"auto_provision_rule_name": auto_provision_rule_name, "remote_user_group_name": remote_user_group_name, "role_name": role_name})
            _validate_preview(reply.structured_content, auto_provision_rule_name, remote_user_group_name, role_name, reply.is_error, write_transport=write_transport)
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(preview_state_file, str(reply.structured_content["preview_ref"]))
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool("confirm_v4_auto_provision_rule_disable", {"preview_ref": _read_preview_ref(execute_preview_state_file)})
            body = confirmation.structured_content
            authorization_ref = body.get("authorization_ref") if isinstance(body, dict) else None
            if confirmation.is_error or not isinstance(body, dict) or not isinstance(authorization_ref, str) or not authorization_ref.startswith(AUTHORIZATION_PREFIX) or body.get("contract") != workflow_contract or body.get("confirmation") != "recorded" or body.get("execution") != "authorized_once" or body.get("device_write_executed") is not False:
                raise AplDisableMcpOAuthAcceptanceError("Auto-Provision Rule disable MCP confirmation failed.")
            phase = "execution readback"
            reply = await session.call_tool("execute_confirmed_v4_auto_provision_rule_disable", {"authorization_ref": authorization_ref})
            _validate_execution(reply.structured_content, reply.is_error, write_transport=write_transport)
            execute_preview_state_file.unlink()
            execution_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(url, login_file, client_state_file, ca_file=ca_file, tool_session_callback=callback, required_tools=TOOLS, allow_insecure_private_ip_lab=allow_insecure_private_ip_lab)
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise AplDisableMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise AplDisableMcpOAuthAcceptanceError(f"Auto-Provision Rule disable MCP {phase} failed.") from None
        raise
    return {"contract": "fortipam_v4_auto_provision_rule_disable_mcp_oauth_acceptance_v1", "oauth_metadata_verified": common["oauth_metadata_verified"], "mcp_initialized": common["mcp_initialized"], "auto_provision_rule_disable_tool_surface_complete": True, "auto_provision_rule_disable_preview_verified": preview_verified, "auto_provision_rule_disable_execution_verified": execution_verified, "device_tool_invoked": preview_verified or execution_verified, "device_write_executed": execution_verified, "token_revoked": common["token_revoked"], "credential_values_returned": common["credential_values_returned"], "token_returned": False, "client_id_returned": False}


def _validate_preview(projection: Any, rule: str, group: str, role: str, is_error: bool, *, write_transport: str = "ssh_cli_fallback") -> None:
    workflow_contract, _ = _contracts(write_transport)
    current = projection.get("Current State") if isinstance(projection, dict) else None
    proposed = projection.get("Proposed Changes") if isinstance(projection, dict) else None
    expected = projection.get("Expected State") if isinstance(projection, dict) else None
    preview_ref = projection.get("preview_ref") if isinstance(projection, dict) else None
    if (is_error or not isinstance(current, dict) or not isinstance(proposed, dict) or not isinstance(expected, dict) or not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX) or projection.get("contract") != workflow_contract or projection.get("device_write_executed") is not False or current.get("requested_auto_provision_rule_name") != rule or current.get("requested_remote_user_group_name") != group or current.get("requested_role_name") != role or any(current.get(key) is not True for key in ("auto_provision_rule_exists", "status_enabled", "remote_user_group_matches", "role_matches", "existing_v4_remote_user_group_exists", "existing_v4_role_exists")) or current.get("write_transport") != write_transport or proposed.get("operation") != ("disable_existing_auto_provision_rule_via_cli_fallback" if write_transport == "ssh_cli_fallback" else "disable_existing_auto_provision_rule_via_rest_700") or proposed.get("auto_provision_rule_name") != rule or proposed.get("remote_user_group_name") != group or proposed.get("role_name") != role or proposed.get("configuration_profile") != "enabled-existing-v4-apl-to-disabled-v1" or proposed.get("status") != "disabled" or any(proposed.get(key) is not True for key in ("remote_user_group_reference_preserved", "role_reference_preserved", "auto_provisioning_disabled")) or any(proposed.get(key) is not False for key in ("existing_rule_fields_other_than_status_modified", "user_group_or_role_created", "identity_server_or_login_flow_changed", "rest_write_attempted")) or any(expected.get(key) is not True for key in ("auto_provision_rule_name_matches", "auto_provision_rule_exists", "status_disabled", "remote_user_group_matches", "role_matches", "auto_provisioning_disabled")) or any(expected.get(key) is not False for key in ("existing_rule_fields_other_than_status_modified", "user_group_or_role_created", "identity_server_or_login_flow_changed")) or expected.get("readback_transport") != write_transport):
        raise AplDisableMcpOAuthAcceptanceError("Auto-Provision Rule disable C/P/E projection was invalid.")


def _validate_execution(result: Any, is_error: bool, *, write_transport: str = "ssh_cli_fallback") -> None:
    _, execution_contract = _contracts(write_transport)
    if (is_error or not isinstance(result, dict) or result.get("contract") != execution_contract or result.get("outcome") != "succeeded" or result.get("verification") != "verified" or result.get("idempotent_replay") is not False or result.get("compensation") != "separate_auto_provision_rule_enable_action_required" or result.get("status") != "disabled" or result.get("auto_provisioning_disabled") is not True or any(result.get(key) is not False for key in ("auto_provision_rule_name_returned", "remote_user_group_identifier_returned", "role_identifier_returned", "existing_rule_fields_other_than_status_modified", "user_group_or_role_created", "identity_server_or_login_flow_changed", "raw_cli_returned"))):
        raise AplDisableMcpOAuthAcceptanceError("Auto-Provision Rule disable MCP execution readback failed.")


def _contracts(write_transport: str) -> tuple[str, str]:
    if write_transport == "ssh_cli_fallback":
        return WORKFLOW, EXECUTION
    if write_transport == "rest_700":
        return ("fortipam_v4_auto_provision_rule_disable_rest_700_workflow_v1",
                "fortipam_v4_auto_provision_rule_disable_rest_700_execution_v1")
    raise AplDisableMcpOAuthAcceptanceError("Unsupported Auto-Provision Rule disable transport.")


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(isinstance(item, AplDisableMcpOAuthAcceptanceError) or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item)) for item in error.exceptions)


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077 or path.exists() or path.is_symlink() or not preview_ref.startswith(PREVIEW_PREFIX):
        raise AplDisableMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": preview_ref}).encode("utf-8")); os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise AplDisableMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        preview_ref = json.loads(path.read_text(encoding="utf-8")).get("preview_ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise AplDisableMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise AplDisableMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True); parser.add_argument("--login-file", type=Path, required=True); parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--auto-provision-rule-name"); parser.add_argument("--remote-user-group-name"); parser.add_argument("--role-name"); parser.add_argument("--preview-state-file", type=Path); parser.add_argument("--execute-preview-state-file", type=Path); parser.add_argument("--ca-file", type=Path); parser.add_argument("--allow-insecure-private-ip-lab", action="store_true")
    parser.add_argument("--write-transport", choices=("ssh_cli_fallback", "rest_700"), default="ssh_cli_fallback")
    args = parser.parse_args()
    try:
        result = asyncio.run(run_apl_disable_mcp_oauth_acceptance(args.url, args.login_file, args.client_state_file, auto_provision_rule_name=args.auto_provision_rule_name, remote_user_group_name=args.remote_user_group_name, role_name=args.role_name, preview_state_file=args.preview_state_file, execute_preview_state_file=args.execute_preview_state_file, ca_file=args.ca_file, allow_insecure_private_ip_lab=args.allow_insecure_private_ip_lab, write_transport=args.write_transport))
    except AplDisableMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
