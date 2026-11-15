from __future__ import annotations

import asyncio
from pathlib import Path
import stat

import pytest

from scripts.v4_user_group_mcp_oauth_acceptance import (
    UserGroupMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_private_ip_lab_flag_is_forwarded(monkeypatch) -> None:
    import scripts.v4_user_group_mcp_oauth_acceptance as subject

    observed: dict[str, object] = {}

    async def stub(*_args, **kwargs):
        observed.update(kwargs)
        callback = kwargs["tool_session_callback"]

        class Tools:
            tools = [type("Tool", (), {"name": name})() for name in subject.TOOLS]

        class Session:
            async def list_tools(self):
                return Tools()

        await callback(Session())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(subject.oauth, "run_address_mcp_oauth_surface_acceptance", stub)
    result = asyncio.run(
        subject.run_user_group_mcp_oauth_acceptance(
            "http://192.0.2.10/mcp",
            Path("login"),
            Path("state"),
            allow_insecure_private_ip_lab=True,
        )
    )

    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["user_group_tool_surface_complete"] is True


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "user-group-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "user-group-preview-opaque"
    with pytest.raises(UserGroupMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_user_group_contract() -> None:
    group = "mcp-v4-user-group-b86"
    ldap_server = "lab-ldap"
    ldap_group_dn = "cn=PAM,cn=users,dc=example,dc=com"
    projection = {
        "contract": "fortipam_v4_user_group_create_cli_workflow_v1",
        "preview_ref": "user-group-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_user_group_name": group,
            "requested_ldap_server_name": ldap_server,
            "requested_ldap_group_dn": ldap_group_dn,
            "user_group_name_exists": False,
            "write_transport": "ssh_cli_fallback",
        },
        "Proposed Changes": {
            "operation": "create_remote_ldap_user_group_via_cli_fallback",
            "user_group_name": group,
            "ldap_server_name": ldap_server,
            "ldap_group_dn": ldap_group_dn,
            "configuration_profile": "remote-ldap-single-match-unbound-v1",
            "one_ldap_server_member_created": True,
            "one_remote_group_match_created": True,
            "role_assignment": False,
            "auto_provision_rule_created": False,
            "folder_or_secret_acl_change": False,
            "user_import_or_session_change": False,
            "rest_write_attempted": False,
        },
        "Expected State": {
            "user_group_name_matches": True,
            "user_group_name_exists": True,
            "ldap_server_member_matches": True,
            "remote_group_match_matches": True,
            "role_assignment": False,
            "auto_provision_rule_created": False,
            "folder_or_secret_acl_change": False,
            "user_import_or_session_change": False,
            "readback_transport": "ssh_cli_fallback",
        },
    }

    _validate_preview(projection, group, ldap_server, ldap_group_dn, False)
    result = {
        "contract": "fortipam_v4_user_group_create_cli_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "separate_user_group_delete_action_required",
        "user_group_name_returned": False,
        "ldap_server_identifier_returned": False,
        "ldap_group_identifier_returned": False,
        "role_assignment": False,
        "auto_provision_rule_created": False,
        "folder_or_secret_acl_change": False,
        "user_import_or_session_change": False,
        "raw_cli_returned": False,
    }

    _validate_execution(result, False)
    result["raw_cli_returned"] = True
    with pytest.raises(UserGroupMcpOAuthAcceptanceError):
        _validate_execution(result, False)
