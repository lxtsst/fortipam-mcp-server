#!/usr/bin/env python3
"""Accept one bounded V4 fixed Profile OAuth/MCP C/P/E flow."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class _ProfileSpec:
    kind: str
    preview_tool: str
    confirm_tool: str
    execute_tool: str
    workflow: str
    execution: str
    preview_prefix: str
    authorization_prefix: str


_SPECS = {
    "antivirus": _ProfileSpec(
        "antivirus",
        "preview_v4_antivirus_profile_create",
        "confirm_v4_antivirus_profile_create",
        "execute_confirmed_v4_antivirus_profile_create",
        "fortipam_v4_antivirus_profile_create_workflow_v1",
        "fortipam_v4_antivirus_profile_create_execution_v1",
        "antivirus-profile-preview-",
        "antivirus-profile-authorized-",
    ),
    "rdp_event_filter": _ProfileSpec(
        "rdp_event_filter",
        "preview_v4_rdp_event_filter_create",
        "confirm_v4_rdp_event_filter_create",
        "execute_confirmed_v4_rdp_event_filter_create",
        "fortipam_v4_rdp_event_filter_create_workflow_v1",
        "fortipam_v4_rdp_event_filter_create_execution_v1",
        "rdp-event-filter-preview-",
        "rdp-event-filter-authorized-",
    ),
    "approval_profile": _ProfileSpec(
        "approval_profile",
        "preview_v4_approval_profile_create",
        "confirm_v4_approval_profile_create",
        "execute_confirmed_v4_approval_profile_create",
        "fortipam_v4_approval_profile_create_cli_workflow_v1",
        "fortipam_v4_approval_profile_create_cli_execution_v1",
        "approval-profile-preview-",
        "approval-profile-authorized-",
    ),
    "approval_profile_update": _ProfileSpec(
        "approval_profile_update",
        "preview_v4_approval_profile_description_update",
        "confirm_v4_approval_profile_description_update",
        "execute_confirmed_v4_approval_profile_description_update",
        "fortipam_v4_approval_profile_update_cli_workflow_v1",
        "fortipam_v4_approval_profile_update_cli_execution_v1",
        "approval-profile-update-preview-",
        "approval-profile-update-authorized-",
    ),
}


class ProfileCreateMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded Profile-create MCP acceptance fails."""


async def run_profile_create_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    profile_kind: str,
    ca_file: Path | None = None,
    preview_profile_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify or execute one fixed, absent-name Profile create C/P/E flow."""

    spec = _spec(profile_kind)
    preview_requested = any(value is not None for value in (preview_profile_name, preview_state_file))
    if preview_requested and execute_preview_state_file is not None:
        raise ProfileCreateMcpOAuthAcceptanceError(
            "Profile preview and execution inputs cannot be combined."
        )
    if preview_requested and (preview_profile_name is None or preview_state_file is None):
        raise ProfileCreateMcpOAuthAcceptanceError("Profile preview inputs are incomplete.")

    preview_verified = False
    execution_verified = False
    callback_phase = "Tool-surface discovery"
    required_tools = frozenset(
        {spec.preview_tool, spec.confirm_tool, spec.execute_tool}
    )

    async def callback(session: ClientSession) -> None:
        nonlocal callback_phase, preview_verified, execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not required_tools <= names:
            raise ProfileCreateMcpOAuthAcceptanceError("Profile MCP Tool surface is incomplete.")
        if preview_requested:
            assert preview_profile_name is not None
            assert preview_state_file is not None
            callback_phase = "preview"
            preview = await session.call_tool(
                spec.preview_tool, {"profile_name": preview_profile_name}
            )
            projection = preview.structured_content
            _validate_preview(spec, projection, preview_profile_name, preview.is_error)
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(preview_state_file, spec, preview_ref)
            preview_verified = True
        if execute_preview_state_file is not None:
            callback_phase = "confirmation"
            preview_ref = _read_preview_ref(execute_preview_state_file, spec)
            confirmation = await session.call_tool(
                spec.confirm_tool, {"preview_ref": preview_ref}
            )
            confirmed = confirmation.structured_content
            authorization_ref = (
                confirmed.get("authorization_ref") if isinstance(confirmed, dict) else None
            )
            if (
                confirmation.is_error
                or not isinstance(confirmed, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith(spec.authorization_prefix)
                or confirmed.get("contract") != spec.workflow
                or confirmed.get("confirmation") != "recorded"
                or confirmed.get("execution") != "authorized_once"
                or confirmed.get("device_write_executed") is not False
            ):
                raise ProfileCreateMcpOAuthAcceptanceError("Profile MCP confirmation failed.")
            callback_phase = "execution readback"
            execution = await session.call_tool(
                spec.execute_tool, {"authorization_ref": authorization_ref}
            )
            result = execution.structured_content
            if not _execution_is_verified(spec, result, execution.is_error):
                raise ProfileCreateMcpOAuthAcceptanceError(
                    "Profile MCP execution readback failed."
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
            required_tools=required_tools,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise ProfileCreateMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise ProfileCreateMcpOAuthAcceptanceError(
                f"Profile MCP {callback_phase} failed."
            ) from None
        raise
    return {
        "contract": "fortipam_v4_profile_create_mcp_oauth_acceptance_v1",
        "profile_kind": spec.kind,
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "profile_tool_surface_complete": True,
        "profile_preview_verified": preview_verified,
        "profile_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _spec(kind: str) -> _ProfileSpec:
    spec = _SPECS.get(kind)
    if spec is None:
        raise ProfileCreateMcpOAuthAcceptanceError("Profile kind is unavailable.")
    return spec


def _validate_preview(
    spec: _ProfileSpec,
    projection: Any,
    profile_name: str,
    is_error: bool,
) -> None:
    if not isinstance(projection, dict):
        raise ProfileCreateMcpOAuthAcceptanceError("Profile MCP preview failed.")
    current = projection.get("Current State")
    proposed = projection.get("Proposed Changes")
    expected = projection.get("Expected State")
    preview_ref = projection.get("preview_ref")
    current_exists = spec.kind == "approval_profile_update"
    common = (
        is_error
        or not isinstance(current, dict)
        or not isinstance(proposed, dict)
        or not isinstance(expected, dict)
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(spec.preview_prefix)
        or projection.get("contract") != spec.workflow
        or projection.get("device_write_executed") is not False
        or current.get("requested_profile_name") != profile_name
        or current.get("profile_name_exists") is not current_exists
        or proposed.get("profile_name") != profile_name
        or expected.get("profile_name_matches") is not True
        or expected.get("profile_name_exists") is not True
    )
    assert isinstance(proposed, dict)
    assert isinstance(expected, dict)
    if common or not _preview_matches_fixed_profile(spec, proposed, expected):
        raise ProfileCreateMcpOAuthAcceptanceError("Profile C/P/E projection was invalid.")


def _preview_matches_fixed_profile(
    spec: _ProfileSpec,
    proposed: dict[str, object],
    expected: dict[str, object],
) -> bool:
    if spec.kind == "antivirus":
        return (
            proposed.get("operation") == "create_http_ssh_block_antivirus_profile"
            and proposed.get("configuration_profile") == "http_ssh_block_v1"
            and proposed.get("http_av_scan") == "block"
            and proposed.get("ssh_av_scan") == "block"
            and proposed.get("secret_association_changes") is False
            and proposed.get("fortisandbox_or_license_changes") is False
            and expected.get("http_context_matches") is True
            and expected.get("http_scan_block_matches") is True
            and expected.get("ssh_context_matches") is True
            and expected.get("ssh_scan_block_matches") is True
            and expected.get("secret_association_changes") is False
            and expected.get("fortisandbox_or_license_changes") is False
        )
    if spec.kind == "rdp_event_filter":
        return (
        proposed.get("operation") == "create_rdp_event_filter_profile"
        and proposed.get("configuration_profile") == "all_event_categories_enabled_v1"
        and proposed.get("process_log") == "enable"
        and proposed.get("filesystem_log") == "enable"
        and proposed.get("user_management") == "enable"
        and proposed.get("secret_or_policy_association_changes") is False
        and proposed.get("target_or_winrm_changes") is False
        and expected.get("process_log_enabled") is True
        and expected.get("filesystem_log_enabled") is True
        and expected.get("user_management_enabled") is True
        and expected.get("secret_or_policy_association_changes") is False
        and expected.get("target_or_winrm_changes") is False
    )
    if spec.kind == "approval_profile":
        return (
        proposed.get("operation") == "create_approval_profile_via_cli_fallback"
        and proposed.get("configuration_profile") == "single-tier-admin-unbound-v1"
        and proposed.get("approval_type") == "single"
        and proposed.get("approval_tier_count") == 1
        and proposed.get("approver_identity_returned") is False
        and proposed.get("secret_association_changes") is False
        and proposed.get("approval_request_or_email_execution") is False
        and proposed.get("rest_write_attempted") is False
        and expected.get("single_tier_enabled") is True
        and expected.get("first_approval_count_one") is True
        and expected.get("fixed_approver_present") is True
        and expected.get("fixed_description_present") is True
        and expected.get("remote_group_email_disabled") is True
        and expected.get("approver_permission_requirement_none") is True
        and expected.get("email_template_unset") is True
        and expected.get("email_approval_link_expiry_default") is True
        and expected.get("secret_association_changes") is False
        and expected.get("approval_request_or_email_execution") is False
    )
    return (
        proposed.get("operation")
        == "update_approval_profile_description_via_cli_fallback"
        and proposed.get("configuration_profile")
        == "single-tier-admin-description-update-v1"
        and proposed.get("description_value_returned") is False
        and proposed.get("approval_type_or_tier_changes") is False
        and proposed.get("approver_changes") is False
        and proposed.get("remote_group_email_or_permission_changes") is False
        and proposed.get("email_template_or_link_expiry_changes") is False
        and proposed.get("secret_association_changes") is False
        and proposed.get("approval_request_or_email_execution") is False
        and proposed.get("rest_write_attempted") is False
        and expected.get("single_tier_enabled") is True
        and expected.get("first_approval_count_one") is True
        and expected.get("fixed_approver_present") is True
        and expected.get("updated_description_present") is True
        and expected.get("remote_group_email_disabled") is True
        and expected.get("approver_permission_requirement_none") is True
        and expected.get("email_template_unset") is True
        and expected.get("email_approval_link_expiry_default") is True
        and expected.get("approval_type_or_tier_changes") is False
        and expected.get("approver_changes") is False
        and expected.get("remote_group_email_or_permission_changes") is False
        and expected.get("secret_association_changes") is False
        and expected.get("approval_request_or_email_execution") is False
    )


def _execution_is_verified(
    spec: _ProfileSpec, result: Any, is_error: bool
) -> bool:
    if (
        is_error
        or not isinstance(result, dict)
        or result.get("contract") != spec.execution
        or result.get("outcome") != "succeeded"
        or result.get("verification") != "verified"
        or result.get("idempotent_replay") is not False
        or result.get("raw_cli_returned") is not False
    ):
        return False
    if spec.kind == "antivirus":
        return (
            result.get("secret_association_changes") is False
            and result.get("fortisandbox_or_license_changes") is False
        )
    if spec.kind == "rdp_event_filter":
        return (
        result.get("secret_or_policy_association_changes") is False
        and result.get("target_or_winrm_changes") is False
    )
    if spec.kind == "approval_profile":
        return (
        result.get("profile_name_returned") is False
        and result.get("approver_identity_returned") is False
        and result.get("secret_association_changes") is False
        and result.get("approval_request_or_email_execution") is False
    )
    return (
        result.get("profile_name_returned") is False
        and result.get("description_value_returned") is False
        and result.get("approval_type_or_tier_changes") is False
        and result.get("approver_changes") is False
        and result.get("remote_group_email_or_permission_changes") is False
        and result.get("secret_association_changes") is False
        and result.get("approval_request_or_email_execution") is False
    )


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    for nested in error.exceptions:
        if isinstance(nested, ProfileCreateMcpOAuthAcceptanceError):
            return True
        if isinstance(nested, BaseExceptionGroup) and _contains_acceptance_error(nested):
            return True
    return False


def _write_preview_state(path: Path, spec: _ProfileSpec, preview_ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ProfileCreateMcpOAuthAcceptanceError("Preview state directory is invalid.")
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise ProfileCreateMcpOAuthAcceptanceError(
            "Preview state directory must be owner-only."
        )
    if path.exists() or path.is_symlink() or not preview_ref.startswith(spec.preview_prefix):
        raise ProfileCreateMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(
            descriptor,
            json.dumps(
                {"profile_kind": spec.kind, "preview_ref": preview_ref},
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path, spec: _ProfileSpec) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProfileCreateMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileCreateMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    preview_ref = stored.get("preview_ref") if isinstance(stored, dict) else None
    if (
        not isinstance(stored, dict)
        or stored.get("profile_kind") != spec.kind
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(spec.preview_prefix)
    ):
        raise ProfileCreateMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--profile-kind", choices=sorted(_SPECS), required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-profile-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_profile_create_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                profile_kind=args.profile_kind,
                ca_file=args.ca_file,
                preview_profile_name=args.preview_profile_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
            )
        )
    except ProfileCreateMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
