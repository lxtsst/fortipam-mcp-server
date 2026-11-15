from __future__ import annotations

import stat

import pytest

from scripts.v4_automation_trigger_mcp_oauth_acceptance import (
    AutomationTriggerMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_preview,
    _write_preview_state,
)


def test_preview_reference_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "automation-trigger-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "automation-trigger-preview-opaque"
    with pytest.raises(AutomationTriggerMcpOAuthAcceptanceError):
        _write_preview_state(path, "automation-trigger-preview-other")


def test_preview_requires_fixed_unbound_event_log_contract() -> None:
    projection = {
        "contract": "fortipam_v4_automation_trigger_create_cli_workflow_v1",
        "preview_ref": "automation-trigger-preview-opaque", "device_write_executed": False,
        "Current State": {"requested_trigger_name": "mcp-v4-automation-trigger-b40", "trigger_name_exists": False, "write_transport": "ssh_cli"},
        "Proposed Changes": {"operation": "create_automation_trigger_via_cli", "trigger_name": "mcp-v4-automation-trigger-b40", "configuration_profile": "event-log-44547-msg-regex-no-action-v1", "event_type": "event-log", "automation_action_or_stitch_changes": False, "direct_automation_execution": False, "rest_write_attempted": False},
        "Expected State": {"trigger_name_matches": True, "trigger_name_exists": True, "event_log_type_enabled": True, "fixed_logid_present": True, "category_one_present": True, "logic_and_enabled": True, "msg_regex_field_present": True, "automation_action_or_stitch_changes": False, "direct_automation_execution": False, "readback_transport": "ssh_cli"},
    }
    _validate_preview(projection, "mcp-v4-automation-trigger-b40", False)
    projection["Proposed Changes"]["direct_automation_execution"] = True
    with pytest.raises(AutomationTriggerMcpOAuthAcceptanceError):
        _validate_preview(projection, "mcp-v4-automation-trigger-b40", False)
