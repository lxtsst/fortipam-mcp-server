from __future__ import annotations

import pytest

from scripts.v4_role_assign_mcp_oauth_acceptance import (
    RoleAssignMcpOAuthAcceptanceError,
    _contains_role_assign_acceptance_error,
    _validate_preview,
)


def _preview() -> dict[str, object]:
    return {
        "contract": "fortipam_v4_role_assign_api_workflow_v1",
        "preview_ref": "role-assign-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_username": "mcp-v4-user-01",
            "requested_role_name": "mcp-v4-role-01",
            "laboratory_user_exists": True,
            "laboratory_user_status": "disable",
            "requested_laboratory_role_exists": True,
            "requested_role_already_assigned": False,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "assign_existing_laboratory_role_to_disabled_laboratory_local_user_via_api",
            "username": "mcp-v4-user-01",
            "role_name": "mcp-v4-role-01",
            "user_status_change": False,
            "folder_target_or_secret_changes": False,
        },
        "Expected State": {
            "username_matches": True,
            "role_name_matches": True,
            "laboratory_user_exists": True,
            "laboratory_user_status": "disable",
            "requested_laboratory_role_exists": True,
            "requested_role_assigned": True,
        },
    }


def test_preview_accepts_only_the_fixed_role_assignment_transition() -> None:
    _validate_preview(
        _preview(),
        username="mcp-v4-user-01",
        role_name="mcp-v4-role-01",
        is_error=False,
    )

    invalid = _preview()
    current = invalid["Current State"]
    assert isinstance(current, dict)
    current["laboratory_user_status"] = "enable"
    with pytest.raises(RoleAssignMcpOAuthAcceptanceError):
        _validate_preview(
            invalid,
            username="mcp-v4-user-01",
            role_name="mcp-v4-role-01",
            is_error=False,
        )


def test_callback_error_recognition_is_specific_to_role_assignment() -> None:
    nested = ExceptionGroup(
        "nested",
        [ExceptionGroup("callback", [RoleAssignMcpOAuthAcceptanceError("failed")])],
    )

    assert _contains_role_assign_acceptance_error(nested) is True
    assert _contains_role_assign_acceptance_error(
        ExceptionGroup("other", [RuntimeError("failed")])
    ) is False
