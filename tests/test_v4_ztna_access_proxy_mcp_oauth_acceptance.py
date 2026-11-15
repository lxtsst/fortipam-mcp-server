from __future__ import annotations
import stat
import pytest
from scripts.v4_ztna_access_proxy_mcp_oauth_acceptance import ZtnaAccessProxyMcpOAuthAcceptanceError, _read_preview_ref, _validate_execution, _validate_preview, _write_preview_state

def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"; directory.mkdir(mode=0o700); directory.chmod(0o700); path = directory / "preview.json"
    _write_preview_state(path, "ztna-access-proxy-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600; assert _read_preview_ref(path) == "ztna-access-proxy-preview-opaque"
    with pytest.raises(ZtnaAccessProxyMcpOAuthAcceptanceError): _write_preview_state(path, "invalid")

def test_managed_only_preview_and_execution_require_exact_contract() -> None:
    projection = {"contract": "fortipam_v4_ztna_access_proxy_client_certificate_workflow_v1", "preview_ref": "ztna-access-proxy-preview-opaque", "device_write_executed": False, "Current State": {"requested_endpoint_access_mode": "managed_only", "client_certificate_mode": "disable", "empty_certificate_action": "block", "access_proxy_reference_returned": False, "write_transport": "ssh_cli_fallback"}, "Proposed Changes": {"operation": "configure_ztna_access_proxy_client_certificate_prerequisite_via_cli_fallback", "configuration_profile": "secret-level-prerequisite-only-v1", "endpoint_access_mode": "managed_only", "client_certificate_mode": "enable", "empty_certificate_action": "block", "access_level_proxy_policy_changed": False, "folder_or_secret_control_changed": False, "ems_connector_or_tag_changed": False, "wad_debug_enabled": False, "session_or_secret_launch_executed": False, "rest_write_attempted": False}, "Expected State": {"endpoint_access_mode_matches": True, "client_certificate_mode": "enable", "empty_certificate_action": "block", "managed_only_portal_login_required": True, "unmanaged_portal_access_allowed": False, "access_level_proxy_policy_changed": False, "folder_or_secret_control_changed": False, "ems_connector_or_tag_changed": False, "session_or_secret_launch_effect_verified": False, "readback_transport": "ssh_cli"}}
    _validate_preview(projection, "managed_only", False)
    result = {"contract": "fortipam_v4_ztna_access_proxy_client_certificate_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "separate_ztna_access_proxy_rollback_action_required", "endpoint_access_mode": "managed_only", "access_proxy_reference_returned": False, "access_level_proxy_policy_changed": False, "folder_or_secret_control_changed": False, "ems_connector_or_tag_changed": False, "wad_debug_enabled": False, "session_or_secret_launch_effect_verified": False, "raw_cli_returned": False}
    _validate_execution(result, False); result["folder_or_secret_control_changed"] = True
    with pytest.raises(ZtnaAccessProxyMcpOAuthAcceptanceError): _validate_execution(result, False)
