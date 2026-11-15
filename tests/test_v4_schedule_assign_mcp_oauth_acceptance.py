from __future__ import annotations

import stat

import pytest

from scripts.v4_schedule_assign_mcp_oauth_acceptance import (
    ScheduleAssignMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


USERNAME = "mcp-v4-user-b57"
SCHEDULE_NAME = "mcp-v4-schedule-b66"


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "schedule-assign-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "schedule-assign-preview-opaque"
    with pytest.raises(ScheduleAssignMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_requires_exact_schedule_only_contract() -> None:
    projection = {
        "contract": "fortipam_v4_schedule_assign_api_workflow_v1",
        "preview_ref": "schedule-assign-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_username": USERNAME,
            "user_exists": True,
            "user_status": "disabled",
            "user_type": "local",
            "current_schedule_unassigned": True,
            "requested_schedule_name": SCHEDULE_NAME,
            "schedule_exists": True,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "assign_existing_login_schedule_to_disabled_local_user_via_api",
            "username": USERNAME,
            "schedule_name": SCHEDULE_NAME,
            "request_body": "product_ui_existing_user_projection_schedule_only_change",
        },
        "Expected State": {
            "user_exists": True,
            "schedule_exists": True,
            "user_remains_disabled": True,
            "user_remains_local": True,
            "schedule_matches": True,
            "user_non_schedule_state_preserved": True,
            "schedule_state_preserved": True,
            "readback_transport": "rest_api",
        },
    }
    _validate_preview(projection, USERNAME, SCHEDULE_NAME, False)
    projection["Proposed Changes"]["unexpected"] = True
    with pytest.raises(ScheduleAssignMcpOAuthAcceptanceError):
        _validate_preview(projection, USERNAME, SCHEDULE_NAME, False)


def test_execution_requires_categorical_preservation_readback() -> None:
    result = {
        "contract": "fortipam_v4_schedule_assign_api_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "separate_confirmed_login_schedule_change_required",
        "username_returned": False,
        "schedule_name_returned": False,
        "user_payload_returned": False,
        "schedule_payload_returned": False,
        "credential_material_returned": False,
        "raw_api_response_returned": False,
    }
    _validate_execution(result, False)
    result["user_payload_returned"] = True
    with pytest.raises(ScheduleAssignMcpOAuthAcceptanceError):
        _validate_execution(result, False)
