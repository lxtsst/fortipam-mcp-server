from __future__ import annotations

import asyncio
from pathlib import Path
import stat
import pytest
from scripts.v4_apl_disable_mcp_oauth_acceptance import AplDisableMcpOAuthAcceptanceError, _read_preview_ref, _validate_execution, _validate_preview, _write_preview_state


def test_private_ip_lab_flag_is_forwarded(monkeypatch) -> None:
    import scripts.v4_apl_disable_mcp_oauth_acceptance as subject
    observed: dict[str, object] = {}

    async def stub(*_args, **kwargs):
        observed.update(kwargs)
        callback = kwargs["tool_session_callback"]
        class Tools:
            tools = [type("Tool", (), {"name": name})() for name in subject.TOOLS]
        class Session:
            async def list_tools(self): return Tools()
        await callback(Session())
        return {"oauth_metadata_verified": True, "mcp_initialized": True, "token_revoked": True, "credential_values_returned": False}

    monkeypatch.setattr(subject.oauth, "run_address_mcp_oauth_surface_acceptance", stub)
    result = asyncio.run(subject.run_apl_disable_mcp_oauth_acceptance("http://192.0.2.10/mcp", Path("login"), Path("state"), allow_insecure_private_ip_lab=True))
    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["auto_provision_rule_disable_tool_surface_complete"] is True


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"; directory.mkdir(mode=0o700); directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "apl-disable-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "apl-disable-preview-opaque"
    with pytest.raises(AplDisableMcpOAuthAcceptanceError): _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_disable_contract() -> None:
    rule, group, role = "mcp-v4-apl-01", "mcp-v4-user-group-01", "mcp-v4-role-01"
    projection = {"contract": "fortipam_v4_auto_provision_rule_disable_cli_workflow_v1", "preview_ref": "apl-disable-preview-opaque", "device_write_executed": False, "Current State": {"requested_auto_provision_rule_name": rule, "requested_remote_user_group_name": group, "requested_role_name": role, "auto_provision_rule_exists": True, "status_enabled": True, "remote_user_group_matches": True, "role_matches": True, "existing_v4_remote_user_group_exists": True, "existing_v4_role_exists": True, "write_transport": "ssh_cli_fallback"}, "Proposed Changes": {"operation": "disable_existing_auto_provision_rule_via_cli_fallback", "auto_provision_rule_name": rule, "remote_user_group_name": group, "role_name": role, "configuration_profile": "enabled-existing-v4-apl-to-disabled-v1", "status": "disabled", "remote_user_group_reference_preserved": True, "role_reference_preserved": True, "auto_provisioning_disabled": True, "existing_rule_fields_other_than_status_modified": False, "user_group_or_role_created": False, "identity_server_or_login_flow_changed": False, "rest_write_attempted": False}, "Expected State": {"auto_provision_rule_name_matches": True, "auto_provision_rule_exists": True, "status_disabled": True, "remote_user_group_matches": True, "role_matches": True, "auto_provisioning_disabled": True, "existing_rule_fields_other_than_status_modified": False, "user_group_or_role_created": False, "identity_server_or_login_flow_changed": False, "readback_transport": "ssh_cli_fallback"}}
    _validate_preview(projection, rule, group, role, False)
    result = {"contract": "fortipam_v4_auto_provision_rule_disable_cli_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "separate_auto_provision_rule_enable_action_required", "auto_provision_rule_name_returned": False, "remote_user_group_identifier_returned": False, "role_identifier_returned": False, "status": "disabled", "auto_provisioning_disabled": True, "existing_rule_fields_other_than_status_modified": False, "user_group_or_role_created": False, "identity_server_or_login_flow_changed": False, "raw_cli_returned": False}
    _validate_execution(result, False); result["auto_provisioning_disabled"] = False
    with pytest.raises(AplDisableMcpOAuthAcceptanceError): _validate_execution(result, False)
