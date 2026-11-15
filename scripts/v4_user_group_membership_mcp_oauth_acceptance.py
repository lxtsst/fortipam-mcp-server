#!/usr/bin/env python3
"""Accept one bounded V4 remote-LDAP User Group membership OAuth/MCP flow."""

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
        "preview_v4_user_group_membership_change",
        "confirm_v4_user_group_membership_change",
        "execute_confirmed_v4_user_group_membership_change",
    }
)
WORKFLOW = "fortipam_v4_user_group_membership_change_cli_workflow_v1"
EXECUTION = "fortipam_v4_user_group_membership_change_cli_execution_v1"
PREVIEW_PREFIX = "user-group-membership-preview-"
AUTHORIZATION_PREFIX = "user-group-membership-authorized-"


class UserGroupMembershipMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded User Group membership acceptance fails."""


async def run_user_group_membership_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    user_group_name: str | None = None,
    ldap_server_name: str | None = None,
    primary_ldap_group_dn: str | None = None,
    additional_ldap_group_dn: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    ca_file: Path | None = None,
    allow_insecure_private_ip_lab: bool = False,
) -> dict[str, object]:
    """Verify or execute one exact second remote-LDAP group match."""

    preview_inputs = (
        user_group_name,
        ldap_server_name,
        primary_ldap_group_dn,
        additional_ldap_group_dn,
        preview_state_file,
    )
    preview_requested = any(value is not None for value in preview_inputs)
    if preview_requested and execute_preview_state_file is not None:
        raise UserGroupMembershipMcpOAuthAcceptanceError(
            "User Group membership preview and execution inputs cannot be combined."
        )
    if preview_requested and any(value is None for value in preview_inputs):
        raise UserGroupMembershipMcpOAuthAcceptanceError(
            "User Group membership preview inputs are incomplete."
        )
    preview_verified = execution_verified = False
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise UserGroupMembershipMcpOAuthAcceptanceError(
                "User Group membership MCP Tool surface is incomplete."
            )
        if preview_requested:
            assert all(value is not None for value in preview_inputs)
            assert isinstance(user_group_name, str)
            assert isinstance(ldap_server_name, str)
            assert isinstance(primary_ldap_group_dn, str)
            assert isinstance(additional_ldap_group_dn, str)
            assert preview_state_file is not None
            phase = "preview"
            reply = await session.call_tool(
                "preview_v4_user_group_membership_change",
                {
                    "user_group_name": user_group_name,
                    "ldap_server_name": ldap_server_name,
                    "primary_ldap_group_dn": primary_ldap_group_dn,
                    "additional_ldap_group_dn": additional_ldap_group_dn,
                },
            )
            _validate_preview(
                reply.structured_content,
                user_group_name,
                ldap_server_name,
                primary_ldap_group_dn,
                additional_ldap_group_dn,
                reply.is_error,
            )
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(
                preview_state_file,
                str(reply.structured_content["preview_ref"]),
            )
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool(
                "confirm_v4_user_group_membership_change",
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
                raise UserGroupMembershipMcpOAuthAcceptanceError(
                    "User Group membership MCP confirmation failed."
                )
            phase = "execution readback"
            reply = await session.call_tool(
                "execute_confirmed_v4_user_group_membership_change",
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
        raise UserGroupMembershipMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise UserGroupMembershipMcpOAuthAcceptanceError(
                f"User Group membership MCP {phase} failed."
            ) from None
        raise
    return {
        "contract": "fortipam_v4_user_group_membership_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "user_group_membership_tool_surface_complete": True,
        "user_group_membership_preview_verified": preview_verified,
        "user_group_membership_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(
    projection: Any,
    user_group_name: str,
    ldap_server_name: str,
    primary_ldap_group_dn: str,
    additional_ldap_group_dn: str,
    is_error: bool,
) -> None:
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
        or current.get("requested_user_group_name") != user_group_name
        or current.get("requested_ldap_server_name") != ldap_server_name
        or current.get("requested_primary_ldap_group_dn") != primary_ldap_group_dn
        or current.get("requested_additional_ldap_group_dn") != additional_ldap_group_dn
        or current.get("user_group_exists") is not True
        or current.get("known_single_match_baseline_verified") is not True
        or current.get("additional_remote_group_match_present") is not False
        or current.get("write_transport") != "ssh_cli_fallback"
        or proposed.get("operation")
        != "add_second_remote_ldap_group_match_via_cli_fallback"
        or proposed.get("user_group_name") != user_group_name
        or proposed.get("ldap_server_name") != ldap_server_name
        or proposed.get("primary_ldap_group_dn") != primary_ldap_group_dn
        or proposed.get("additional_ldap_group_dn") != additional_ldap_group_dn
        or proposed.get("configuration_profile")
        != "remote-ldap-second-match-unbound-v1"
        or proposed.get("existing_remote_group_match_preserved") is not True
        or proposed.get("additional_remote_group_match_added") is not True
        or any(
            proposed.get(key) is not False
            for key in (
                "role_assignment",
                "auto_provision_rule_created",
                "folder_or_secret_acl_change",
                "user_import_or_session_change",
                "rest_write_attempted",
            )
        )
        or any(
            expected.get(key) is not True
            for key in (
                "user_group_name_matches",
                "user_group_exists",
                "ldap_server_member_present",
                "primary_remote_group_match_preserved",
                "additional_remote_group_match_present",
            )
        )
        or any(
            expected.get(key) is not False
            for key in (
                "role_assignment",
                "auto_provision_rule_created",
                "folder_or_secret_acl_change",
                "user_import_or_session_change",
            )
        )
        or expected.get("readback_transport") != "ssh_cli_fallback"
    ):
        raise UserGroupMembershipMcpOAuthAcceptanceError(
            "User Group membership C/P/E projection was invalid."
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
        != "separate_user_group_membership_remove_action_required"
        or any(
            result.get(key) is not False
            for key in (
                "user_group_name_returned",
                "ldap_server_identifier_returned",
                "primary_ldap_group_identifier_returned",
                "additional_ldap_group_identifier_returned",
                "role_assignment",
                "auto_provision_rule_created",
                "folder_or_secret_acl_change",
                "user_import_or_session_change",
                "raw_cli_returned",
            )
        )
        or result.get("existing_remote_group_match_preserved") is not True
        or result.get("additional_remote_group_match_added") is not True
    ):
        raise UserGroupMembershipMcpOAuthAcceptanceError(
            "User Group membership MCP execution readback failed."
        )


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, UserGroupMembershipMcpOAuthAcceptanceError)
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
        raise UserGroupMembershipMcpOAuthAcceptanceError("Preview state reference is invalid.")
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
        raise UserGroupMembershipMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        preview_ref = json.loads(path.read_text(encoding="utf-8")).get("preview_ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise UserGroupMembershipMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise UserGroupMembershipMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--user-group-name")
    parser.add_argument("--ldap-server-name")
    parser.add_argument("--primary-ldap-group-dn")
    parser.add_argument("--additional-ldap-group-dn")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--allow-insecure-private-ip-lab", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_user_group_membership_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                user_group_name=args.user_group_name,
                ldap_server_name=args.ldap_server_name,
                primary_ldap_group_dn=args.primary_ldap_group_dn,
                additional_ldap_group_dn=args.additional_ldap_group_dn,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
                ca_file=args.ca_file,
                allow_insecure_private_ip_lab=args.allow_insecure_private_ip_lab,
            )
        )
    except UserGroupMembershipMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
