from __future__ import annotations

import stat

import pytest

from scripts.v4_windows_app_filter_delete_mcp_oauth_acceptance import (
    WindowsAppFilterDeleteMcpOAuthAcceptanceError,
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

    _write_preview_state(path, "windows-app-filter-delete-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "windows-app-filter-delete-preview-opaque"
    with pytest.raises(WindowsAppFilterDeleteMcpOAuthAcceptanceError):
        _write_preview_state(path, "windows-app-filter-delete-preview-other")


def test_preview_reference_rejects_create_prefix(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    path.write_text(
        '{"preview_ref":"windows-app-filter-preview-opaque"}',
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(WindowsAppFilterDeleteMcpOAuthAcceptanceError):
        _read_preview_ref(path)


def test_exact_categorical_preview_and_execution_contracts() -> None:
    _validate_preview(
        {
            "contract": "fortipam_v4_windows_app_filter_delete_api_workflow_v1",
            "preview_ref": "windows-app-filter-delete-preview-opaque",
            "Current State": {
                "accepted_windows_app_filter_profile_exists": True,
                "exact_fixed_empty_profile_observed": True,
                "secret_reference_count": 0,
                "read_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": (
                    "delete_exact_unreferenced_windows_app_filter_profile_via_api"
                ),
                "windows_app_filter_profile_count_affected": 1,
                "irreversible_after_execution": True,
                "filter_or_exception_changes": False,
                "secret_target_or_policy_association_changes": False,
            },
            "Expected State": {
                "accepted_windows_app_filter_profile_absent": True,
                "filter_or_exception_changes": False,
                "secret_target_or_policy_association_changes": False,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        },
        False,
    )
    _validate_execution(
        {
            "contract": "fortipam_v4_windows_app_filter_delete_api_execution_v1",
            "outcome": "succeeded",
            "verification": "verified",
            "idempotent_replay": False,
            "compensation": "separate_windows_app_filter_create_action_required",
            "irreversible_after_execution": True,
            "windows_app_filter_profile_name_returned": False,
            "filter_or_exception_content_returned": False,
            "secret_target_or_policy_association_changes": False,
            "raw_api_response_returned": False,
        },
        False,
    )
