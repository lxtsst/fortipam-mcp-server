from __future__ import annotations

import stat

import pytest

from scripts.v4_ztna_user_control_mcp_oauth_acceptance import (
    ZtnaUserControlMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"; directory.mkdir(mode=0o700); directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "ztna-user-control-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "ztna-user-control-preview-opaque"
    with pytest.raises(ZtnaUserControlMcpOAuthAcceptanceError): _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_access_level_contract() -> None:
    projection = {"contract": "fortipam_v4_ztna_user_control_access_level_workflow_v1", "preview_ref": "ztna-user-control-preview-opaque", "device_write_executed": False, "Current State": {"client_certificate_mode": "enable", "empty_certificate_action": "block", "policy_is_access_proxy": True, "existing_ems_tag_configured": True, "ztna_status": "disable", "access_proxy_reference_returned": False, "policy_reference_returned": False, "ems_tag_reference_returned": False, "write_transport": "ssh_cli_fallback"}, "Proposed Changes": {"operation": "enable_access_level_ztna_for_existing_ems_tag_via_cli_fallback", "configuration_profile": "managed-only-access-level-enable-v1", "ztna_status": "enable", "existing_ems_tag_preserved": True, "access_proxy_client_certificate_changed": False, "empty_certificate_action_changed": False, "access_proxy_binding_changed": False, "ems_connector_or_tag_sync_changed": False, "folder_or_secret_control_changed": False, "wad_debug_enabled": False, "session_or_secret_launch_executed": False, "rest_write_attempted": False}, "Expected State": {"ztna_status": "enable", "existing_ems_tag_preserved": True, "managed_only_portal_login_required": True, "unmanaged_portal_access_allowed": False, "access_proxy_client_certificate_changed": False, "empty_certificate_action_changed": False, "folder_or_secret_control_changed": False, "session_or_secret_launch_effect_verified": False, "readback_transport": "ssh_cli"}}
    _validate_preview(projection, False)
    result = {"contract": "fortipam_v4_ztna_user_control_access_level_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "separate_ztna_user_control_disable_action_required", "ztna_scope": "access_level_only", "existing_ems_tag_preserved": True, "access_proxy_reference_returned": False, "policy_reference_returned": False, "ems_tag_reference_returned": False, "access_proxy_client_certificate_changed": False, "empty_certificate_action_changed": False, "folder_or_secret_control_changed": False, "wad_debug_enabled": False, "session_or_secret_launch_effect_verified": False, "raw_cli_returned": False}
    _validate_execution(result, False); result["wad_debug_enabled"] = True
    with pytest.raises(ZtnaUserControlMcpOAuthAcceptanceError): _validate_execution(result, False)
