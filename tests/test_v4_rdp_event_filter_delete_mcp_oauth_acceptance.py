from __future__ import annotations

import stat

import pytest

from scripts.v4_rdp_event_filter_delete_mcp_oauth_acceptance import (
    RdpEventFilterDeleteMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_preview_reference_is_owner_only_and_single_use(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "rdp-event-filter-delete-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "rdp-event-filter-delete-preview-opaque"
    with pytest.raises(RdpEventFilterDeleteMcpOAuthAcceptanceError):
        _write_preview_state(path, "rdp-event-filter-delete-preview-other")


def test_preview_reference_rejects_create_prefix(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    path.write_text(
        '{"preview_ref":"rdp-event-filter-preview-opaque"}',
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(RdpEventFilterDeleteMcpOAuthAcceptanceError):
        _read_preview_ref(path)


def test_exact_categorical_preview_and_execution_contracts() -> None:
    _validate_preview(
        {
            "contract": "fortipam_v4_rdp_event_filter_delete_api_workflow_v1",
            "preview_ref": "rdp-event-filter-delete-preview-opaque",
            "Current State": {
                "accepted_rdp_event_filter_exists": True,
                "exact_fixed_three_event_profile_observed": True,
                "complete_api_record_digest_matches": True,
                "secret_reference_count": 0,
                "policy_reference_count": 0,
                "read_transports": ["rest_api", "ssh_cli"],
            },
            "Proposed Changes": {
                "operation": "delete_exact_unreferenced_rdp_event_filter_via_api",
                "rdp_event_filter_count_affected": 1,
                "irreversible_after_execution": True,
                "secret_or_policy_association_changes": False,
                "target_winrm_or_audit_policy_changes": False,
                "monitoring_or_session_changes": False,
            },
            "Expected State": {
                "accepted_rdp_event_filter_absent": True,
                "secret_or_policy_association_changes": False,
                "target_winrm_or_audit_policy_changes": False,
                "monitoring_or_session_changes": False,
                "readback_transports": ["rest_api", "ssh_cli"],
            },
            "device_write_executed": False,
        },
        False,
    )
    _validate_execution(
        {
            "contract": "fortipam_v4_rdp_event_filter_delete_api_execution_v1",
            "outcome": "succeeded",
            "verification": "verified",
            "idempotent_replay": False,
            "compensation": "separate_rdp_event_filter_create_action_required",
            "irreversible_after_execution": True,
            "rdp_event_filter_name_returned": False,
            "profile_content_returned": False,
            "secret_or_policy_association_changes": False,
            "target_winrm_or_audit_policy_changes": False,
            "monitoring_or_session_changes": False,
            "raw_api_or_cli_response_returned": False,
        },
        False,
    )
