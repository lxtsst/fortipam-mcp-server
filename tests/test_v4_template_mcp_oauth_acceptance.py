from __future__ import annotations

import stat

import pytest

from scripts.v4_template_mcp_oauth_acceptance import TemplateMcpOAuthAcceptanceError, _read_preview_ref, _validate_execution, _validate_preview, _write_preview_state


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "template-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "template-preview-opaque"
    with pytest.raises(TemplateMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_rejects_secret_value_or_association_effect() -> None:
    name = "mcp-v4-template-b53"
    projection = {"contract": "fortipam_v4_template_create_cli_fallback_workflow_v1", "preview_ref": "template-preview-opaque", "device_write_executed": False, "Current State": {"requested_template_name": name, "template_name_exists": False, "write_transport": "ssh_cli_fallback"}, "Proposed Changes": {"operation": "create_web_vnc_template_via_cli_fallback", "template_name": name, "configuration_profile": "web-vnc-username-password-v1", "template_access": "everyone", "mandatory_fields": ["username", "password"], "launcher": "Web VNC", "launcher_port": 5900, "secret_or_target_association_changes": False, "secret_field_values_supplied": False, "rest_write_attempted": False}, "Expected State": {"template_name_matches": True, "template_name_exists": True, "access_everyone": True, "username_field_present": True, "username_field_mandatory": True, "password_field_present": True, "password_field_mandatory": True, "web_vnc_launcher_present": True, "web_vnc_port_matches": True, "secret_or_target_association_changes": False, "secret_field_values_supplied": False, "readback_transport": "ssh_cli"}}
    _validate_preview(projection, name, False)
    projection["Proposed Changes"]["secret_field_values_supplied"] = True
    with pytest.raises(TemplateMcpOAuthAcceptanceError):
        _validate_preview(projection, name, False)


def test_execution_requires_no_secret_value_or_association_readback() -> None:
    result = {"contract": "fortipam_v4_template_create_cli_fallback_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "separate_template_archive_action_required", "template_name_returned": False, "secret_or_target_association_changes": False, "secret_field_values_returned": False, "raw_cli_returned": False}
    _validate_execution(result, False)
    result["secret_field_values_returned"] = True
    with pytest.raises(TemplateMcpOAuthAcceptanceError):
        _validate_execution(result, False)
