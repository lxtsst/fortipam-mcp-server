from __future__ import annotations

import stat

import pytest

from scripts.v4_profile_create_mcp_oauth_acceptance import (
    ProfileCreateMcpOAuthAcceptanceError,
    _SPECS,
    _contains_acceptance_error,
    _execution_is_verified,
    _preview_matches_fixed_profile,
    _read_preview_ref,
    _validate_preview,
    _write_preview_state,
)


def test_preview_reference_is_owner_only_and_profile_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    antivirus = _SPECS["antivirus"]
    _write_preview_state(path, antivirus, "antivirus-profile-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path, antivirus) == "antivirus-profile-preview-opaque"
    with pytest.raises(ProfileCreateMcpOAuthAcceptanceError):
        _read_preview_ref(path, _SPECS["rdp_event_filter"])


def test_preview_reference_rejects_reuse_and_wrong_prefix(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    with pytest.raises(ProfileCreateMcpOAuthAcceptanceError):
        _write_preview_state(path, _SPECS["antivirus"], "rdp-event-filter-preview-opaque")
    _write_preview_state(path, _SPECS["rdp_event_filter"], "rdp-event-filter-preview-opaque")
    with pytest.raises(ProfileCreateMcpOAuthAcceptanceError):
        _write_preview_state(path, _SPECS["rdp_event_filter"], "rdp-event-filter-preview-other")


def test_callback_failure_is_recognized_inside_task_groups() -> None:
    wrapped = ExceptionGroup(
        "outer",
        [ExceptionGroup("inner", [ProfileCreateMcpOAuthAcceptanceError("failed")])],
    )
    assert _contains_acceptance_error(wrapped) is True
    assert _contains_acceptance_error(ExceptionGroup("other", [ValueError()])) is False


def test_approval_profile_contract_is_fixed_and_value_minimized() -> None:
    spec = _SPECS["approval_profile"]
    proposed = {
        "operation": "create_approval_profile_via_cli_fallback",
        "configuration_profile": "single-tier-admin-unbound-v1",
        "approval_type": "single",
        "approval_tier_count": 1,
        "approver_identity_returned": False,
        "secret_association_changes": False,
        "approval_request_or_email_execution": False,
        "rest_write_attempted": False,
    }
    expected = {
        "single_tier_enabled": True,
        "first_approval_count_one": True,
        "fixed_approver_present": True,
        "fixed_description_present": True,
        "remote_group_email_disabled": True,
        "approver_permission_requirement_none": True,
        "email_template_unset": True,
        "email_approval_link_expiry_default": True,
        "secret_association_changes": False,
        "approval_request_or_email_execution": False,
    }
    execution = {
        "contract": spec.execution,
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "raw_cli_returned": False,
        "profile_name_returned": False,
        "approver_identity_returned": False,
        "secret_association_changes": False,
        "approval_request_or_email_execution": False,
    }

    assert _preview_matches_fixed_profile(spec, proposed, expected) is True
    assert _execution_is_verified(spec, execution, False) is True

    proposed["approval_request_or_email_execution"] = True
    assert _preview_matches_fixed_profile(spec, proposed, expected) is False


def test_approval_profile_update_contract_preserves_create_baseline() -> None:
    spec = _SPECS["approval_profile_update"]
    proposed = {
        "operation": "update_approval_profile_description_via_cli_fallback",
        "configuration_profile": "single-tier-admin-description-update-v1",
        "description_value_returned": False,
        "approval_type_or_tier_changes": False,
        "approver_changes": False,
        "remote_group_email_or_permission_changes": False,
        "email_template_or_link_expiry_changes": False,
        "secret_association_changes": False,
        "approval_request_or_email_execution": False,
        "rest_write_attempted": False,
    }
    expected = {
        "single_tier_enabled": True,
        "first_approval_count_one": True,
        "fixed_approver_present": True,
        "updated_description_present": True,
        "remote_group_email_disabled": True,
        "approver_permission_requirement_none": True,
        "email_template_unset": True,
        "email_approval_link_expiry_default": True,
        "approval_type_or_tier_changes": False,
        "approver_changes": False,
        "remote_group_email_or_permission_changes": False,
        "secret_association_changes": False,
        "approval_request_or_email_execution": False,
    }
    execution = {
        "contract": spec.execution,
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "raw_cli_returned": False,
        "profile_name_returned": False,
        "description_value_returned": False,
        "approval_type_or_tier_changes": False,
        "approver_changes": False,
        "remote_group_email_or_permission_changes": False,
        "secret_association_changes": False,
        "approval_request_or_email_execution": False,
    }

    assert _preview_matches_fixed_profile(spec, proposed, expected) is True
    assert _execution_is_verified(spec, execution, False) is True

    expected["updated_description_present"] = False
    assert _preview_matches_fixed_profile(spec, proposed, expected) is False


def test_approval_profile_update_preview_requires_existing_baseline() -> None:
    spec = _SPECS["approval_profile_update"]
    projection = {
        "contract": spec.workflow,
        "preview_ref": "approval-profile-update-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_profile_name": "mcp-v4-approval-profile-b36",
            "profile_name_exists": True,
        },
        "Proposed Changes": {
            "operation": "update_approval_profile_description_via_cli_fallback",
            "profile_name": "mcp-v4-approval-profile-b36",
            "configuration_profile": "single-tier-admin-description-update-v1",
            "description_value_returned": False,
            "approval_type_or_tier_changes": False,
            "approver_changes": False,
            "remote_group_email_or_permission_changes": False,
            "email_template_or_link_expiry_changes": False,
            "secret_association_changes": False,
            "approval_request_or_email_execution": False,
            "rest_write_attempted": False,
        },
        "Expected State": {
            "profile_name_matches": True,
            "profile_name_exists": True,
            "single_tier_enabled": True,
            "first_approval_count_one": True,
            "fixed_approver_present": True,
            "updated_description_present": True,
            "remote_group_email_disabled": True,
            "approver_permission_requirement_none": True,
            "email_template_unset": True,
            "email_approval_link_expiry_default": True,
            "approval_type_or_tier_changes": False,
            "approver_changes": False,
            "remote_group_email_or_permission_changes": False,
            "secret_association_changes": False,
            "approval_request_or_email_execution": False,
        },
    }

    _validate_preview(spec, projection, "mcp-v4-approval-profile-b36", False)
    projection["Current State"]["profile_name_exists"] = False
    with pytest.raises(ProfileCreateMcpOAuthAcceptanceError):
        _validate_preview(spec, projection, "mcp-v4-approval-profile-b36", False)
