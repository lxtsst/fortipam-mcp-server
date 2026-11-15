from __future__ import annotations

import stat

import pytest

from scripts.v4_dependency_updater_mcp_oauth_acceptance import (
    DependencyUpdaterMcpOAuthAcceptanceError,
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
    _write_preview_state(path, "dependency-updater-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "dependency-updater-preview-opaque"
    with pytest.raises(DependencyUpdaterMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_requires_fixed_unattached_no_service_operation_contract() -> None:
    name, service = "mcp-v4-dependency-updater-b47", "McpV4LabService"
    projection = {"contract": "fortipam_v4_dependency_updater_create_cli_fallback_workflow_v1", "preview_ref": "dependency-updater-preview-opaque", "device_write_executed": False, "Current State": {"requested_updater_name": name, "requested_service_name": service, "updater_name_exists": False, "write_transport": "ssh_cli_fallback"}, "Proposed Changes": {"operation": "create_dependency_updater_via_cli_fallback", "updater_name": name, "service_name": service, "configuration_profile": "win-service-restart-disabled-v1", "updater_type": "win-service", "restart_after_updates": "disable", "secret_or_target_association_changes": False, "service_operation_executed": False, "rest_write_attempted": False}, "Expected State": {"updater_name_matches": True, "updater_name_exists": True, "win_service_type_enabled": True, "restart_disabled": True, "service_name_matches": True, "secret_or_target_association_changes": False, "service_operation_executed": False, "readback_transport": "ssh_cli"}}
    _validate_preview(projection, name, service, False)
    projection["Proposed Changes"]["service_operation_executed"] = True
    with pytest.raises(DependencyUpdaterMcpOAuthAcceptanceError):
        _validate_preview(projection, name, service, False)


def test_execution_requires_categorical_unattached_readback() -> None:
    result = {"contract": "fortipam_v4_dependency_updater_create_cli_fallback_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "separate_dependency_updater_delete_action_required", "updater_name_returned": False, "service_name_returned": False, "secret_or_target_association_changes": False, "service_operation_executed": False, "raw_cli_returned": False}
    _validate_execution(result, False)
    result["service_operation_executed"] = True
    with pytest.raises(DependencyUpdaterMcpOAuthAcceptanceError):
        _validate_execution(result, False)
