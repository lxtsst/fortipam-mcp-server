from __future__ import annotations

import stat

import pytest

from scripts.v4_approval_email_template_mcp_oauth_acceptance import (
    ApprovalEmailTemplateMcpOAuthAcceptanceError,
    _contains_acceptance_error,
    _read_preview_ref,
    _validate_preview,
    _write_preview_state,
)


def test_preview_reference_is_owner_only_and_single_use(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "approval-email-template-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "approval-email-template-preview-opaque"
    with pytest.raises(ApprovalEmailTemplateMcpOAuthAcceptanceError):
        _write_preview_state(path, "approval-email-template-preview-other")


def test_preview_reference_rejects_wrong_prefix(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    path.write_text('{"preview_ref":"approval-profile-preview-opaque"}', encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(ApprovalEmailTemplateMcpOAuthAcceptanceError):
        _read_preview_ref(path)


def test_callback_failure_is_recognized_inside_task_groups() -> None:
    wrapped = ExceptionGroup(
        "outer",
        [
            ExceptionGroup(
                "inner", [ApprovalEmailTemplateMcpOAuthAcceptanceError("failed")]
            )
        ],
    )

    assert _contains_acceptance_error(wrapped) is True
    assert _contains_acceptance_error(ExceptionGroup("other", [ValueError()])) is False


def test_preview_accepts_only_the_fixed_unassociated_template_contract() -> None:
    projection = {
        "contract": "fortipam_v4_approval_email_template_create_cli_workflow_v1",
        "preview_ref": "approval-email-template-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_template_name": "mcp-v4-approval-email-template-b37",
            "template_name_exists": False,
        },
        "Proposed Changes": {
            "operation": "create_approval_email_template_via_cli_fallback",
            "template_name": "mcp-v4-approval-email-template-b37",
            "configuration_profile": "unassociated-fixed-template-v1",
            "fixed_subject_and_content": True,
            "email_server_changes": False,
            "approval_profile_or_secret_association_changes": False,
            "email_delivery_or_approval_execution": False,
            "rest_write_attempted": False,
        },
        "Expected State": {
            "template_name_matches": True,
            "template_name_exists": True,
            "fixed_subject_present": True,
            "fixed_content_present": True,
            "email_server_changes": False,
            "approval_profile_or_secret_association_changes": False,
            "email_delivery_or_approval_execution": False,
        },
    }

    _validate_preview(projection, "mcp-v4-approval-email-template-b37", False)
    projection["Proposed Changes"]["email_delivery_or_approval_execution"] = True
    with pytest.raises(ApprovalEmailTemplateMcpOAuthAcceptanceError):
        _validate_preview(projection, "mcp-v4-approval-email-template-b37", False)
