from __future__ import annotations

import stat

import pytest

from scripts.v4_launcher_matcher_mcp_oauth_acceptance import (
    LauncherMatcherMcpOAuthAcceptanceError,
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

    _write_preview_state(path, "launcher-matcher-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "launcher-matcher-preview-opaque"
    with pytest.raises(LauncherMatcherMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_matcher_contract() -> None:
    launcher_name = "mcp-v4-launcher-b84"
    projection = {
        "contract": "fortipam_v4_launcher_command_line_matcher_cli_workflow_v1",
        "preview_ref": "launcher-matcher-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_launcher_name": launcher_name,
            "launcher_name_exists": True,
            "known_native_rdp_create_baseline_verified": True,
            "launch_timeout_seconds": 15,
            "custom_process_matcher_configured": False,
            "write_transport": "ssh_cli_fallback",
        },
        "Proposed Changes": {
            "operation": "configure_native_rdp_launcher_command_line_matcher_via_cli_fallback",
            "launcher_name": launcher_name,
            "configuration_profile": "windows-rdp-mstsc-command-line-matcher-v1",
            "process_matcher": "fixed_native_rdp_command_line",
            "multiprocess_mode": "enable",
            "fullscreen_recording": "enable",
            "launch_timeout_changes": False,
            "launcher_type_or_command_changes": False,
            "secret_or_template_association_changes": False,
            "session_or_target_changes": False,
            "rest_write_attempted": False,
        },
        "Expected State": {
            "launcher_name_matches": True,
            "launcher_name_exists": True,
            "native_rdp_create_baseline_preserved": True,
            "process_matcher": "fixed_native_rdp_command_line",
            "multiprocess_mode": "enabled",
            "fullscreen_recording": "enabled",
            "launch_timeout_seconds": 15,
            "launcher_type_or_command_changes": False,
            "secret_or_template_association_changes": False,
            "session_or_target_changes": False,
            "readback_transport": "ssh_cli_fallback",
        },
    }

    _validate_preview(projection, launcher_name, False)
    result = {
        "contract": "fortipam_v4_launcher_command_line_matcher_cli_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "separate_launcher_matcher_restore_action_required",
        "launcher_name_returned": False,
        "launcher_type_or_command_changes": False,
        "secret_or_template_association_changes": False,
        "raw_cli_returned": False,
    }
    _validate_execution(result, False)
    result["raw_cli_returned"] = True
    with pytest.raises(LauncherMatcherMcpOAuthAcceptanceError):
        _validate_execution(result, False)
