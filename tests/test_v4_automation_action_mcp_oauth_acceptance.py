from __future__ import annotations

import stat

import pytest

from scripts.v4_automation_action_mcp_oauth_acceptance import (
    AutomationActionMcpOAuthAcceptanceError,
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
    _write_preview_state(path, "automation-action-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "automation-action-preview-opaque"
    with pytest.raises(AutomationActionMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_requires_fixed_unbound_no_send_contract() -> None:
    name = "mcp-v4-automation-action-b44"
    projection = {
        "contract": "fortipam_v4_automation_action_create_cli_workflow_v1",
        "preview_ref": "automation-action-preview-opaque",
        "device_write_executed": False,
        "Current State": {"requested_action_name": name, "action_name_exists": False, "write_transport": "ssh_cli_fallback"},
        "Proposed Changes": {"operation": "create_automation_action_via_cli_fallback", "action_name": name, "configuration_profile": "email-fixed-recipient-no-stitch-v1", "action_type": "email", "recipient_returned": False, "automation_action_or_stitch_association_changes": False, "direct_email_execution": False, "rest_write_attempted": False},
        "Expected State": {"action_name_matches": True, "action_name_exists": True, "email_type_enabled": True, "fixed_subject_present": True, "fixed_recipient_present": True, "fixed_message_present": True, "fixed_description_present": True, "automation_action_or_stitch_association_changes": False, "direct_email_execution": False, "readback_transport": "ssh_cli_fallback"},
    }
    _validate_preview(projection, name, False)
    projection["Proposed Changes"]["direct_email_execution"] = True
    with pytest.raises(AutomationActionMcpOAuthAcceptanceError):
        _validate_preview(projection, name, False)


def test_execution_requires_categorical_no_send_readback() -> None:
    result = {
        "contract": "fortipam_v4_automation_action_create_cli_execution_v1",
        "outcome": "succeeded", "verification": "verified", "idempotent_replay": False,
        "compensation": "separate_automation_action_delete_action_required",
        "action_name_returned": False, "recipient_returned": False,
        "automation_action_or_stitch_association_changes": False,
        "direct_email_execution": False, "raw_cli_returned": False,
    }
    _validate_execution(result, False)
    result["direct_email_execution"] = True
    with pytest.raises(AutomationActionMcpOAuthAcceptanceError):
        _validate_execution(result, False)
