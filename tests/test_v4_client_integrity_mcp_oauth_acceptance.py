from __future__ import annotations

import stat

import pytest

from scripts.v4_client_integrity_mcp_oauth_acceptance import (
    ClientIntegrityMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "client-integrity-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "client-integrity-preview-opaque"
    with pytest.raises(ClientIntegrityMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_rejects_a_client_integrity_effect_claim() -> None:
    name = "mcp-v4-client-integrity-b48"
    projection = {
        "contract": "fortipam_v4_client_integrity_cli_fallback_workflow_v1",
        "preview_ref": "client-integrity-preview-opaque", "device_write_executed": False,
        "Current State": {"requested_client_software_name": name, "client_software_name_exists": False, "write_transport": "ssh_cli_fallback"},
        "Proposed Changes": {"operation": "configure_client_integrity_precondition_via_cli_fallback", "client_software_name": name, "configuration_profile": "putty-x64-external-certificate-v1", "package_architecture": "x64", "integrity_check": "certificate", "download_source": "external", "launcher_or_template_binding_changes": False, "secret_or_target_association_changes": False, "external_download_or_session_launch_executed": False, "rest_write_attempted": False},
        "Expected State": {"client_software_name_matches": True, "client_software_name_exists": True, "x64_package_present": True, "certificate_integrity_check_enabled": True, "external_download_enabled": True, "external_url_matches": True, "ca_certificate_matches": True, "putty_client_name_matches": True, "launcher_or_template_binding_changes": False, "secret_or_target_association_changes": False, "session_integrity_enforcement_verified": False, "readback_transport": "ssh_cli"},
    }
    _validate_preview(projection, name, False)
    projection["Proposed Changes"]["external_download_or_session_launch_executed"] = True
    with pytest.raises(ClientIntegrityMcpOAuthAcceptanceError):
        _validate_preview(projection, name, False)


def test_execution_requires_no_external_effect() -> None:
    result = {"contract": "fortipam_v4_client_integrity_cli_fallback_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "separate_client_software_delete_action_required", "client_software_name_returned": False, "launcher_or_template_binding_changes": False, "secret_or_target_association_changes": False, "external_download_or_session_launch_executed": False, "session_integrity_enforcement_verified": False, "raw_cli_returned": False}
    _validate_execution(result, False)
    result["external_download_or_session_launch_executed"] = True
    with pytest.raises(ClientIntegrityMcpOAuthAcceptanceError):
        _validate_execution(result, False)
