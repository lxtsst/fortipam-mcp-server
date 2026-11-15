from __future__ import annotations

import stat

import pytest

from scripts.v4_antivirus_profile_delete_mcp_oauth_acceptance import (
    AntivirusProfileDeleteMcpOAuthAcceptanceError,
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

    _write_preview_state(path, "antivirus-profile-delete-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "antivirus-profile-delete-preview-opaque"
    with pytest.raises(AntivirusProfileDeleteMcpOAuthAcceptanceError):
        _write_preview_state(path, "antivirus-profile-delete-preview-other")


def test_preview_reference_rejects_create_prefix(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    path.write_text(
        '{"preview_ref":"antivirus-profile-preview-opaque"}',
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(AntivirusProfileDeleteMcpOAuthAcceptanceError):
        _read_preview_ref(path)


def test_exact_categorical_preview_and_execution_contracts() -> None:
    _validate_preview(
        {
            "contract": "fortipam_v4_antivirus_profile_delete_api_workflow_v1",
            "preview_ref": "antivirus-profile-delete-preview-opaque",
            "Current State": {
                "accepted_antivirus_profile_exists": True,
                "exact_fixed_http_ssh_block_profile_observed": True,
                "complete_api_record_digest_matches": True,
                "secret_reference_count": 0,
                "read_transports": ["rest_api", "ssh_cli"],
            },
            "Proposed Changes": {
                "operation": "delete_exact_unreferenced_antivirus_profile_via_api",
                "antivirus_profile_count_affected": 1,
                "irreversible_after_execution": True,
                "secret_association_changes": False,
                "fortisandbox_or_license_changes": False,
                "protocol_or_scan_mode_changes": False,
            },
            "Expected State": {
                "accepted_antivirus_profile_absent": True,
                "secret_association_changes": False,
                "fortisandbox_or_license_changes": False,
                "protocol_or_scan_mode_changes": False,
                "readback_transports": ["rest_api", "ssh_cli"],
            },
            "device_write_executed": False,
        },
        False,
    )
    _validate_execution(
        {
            "contract": "fortipam_v4_antivirus_profile_delete_api_execution_v1",
            "outcome": "succeeded",
            "verification": "verified",
            "idempotent_replay": False,
            "compensation": "separate_antivirus_profile_create_action_required",
            "irreversible_after_execution": True,
            "antivirus_profile_name_returned": False,
            "profile_content_returned": False,
            "secret_association_changes": False,
            "fortisandbox_or_license_changes": False,
            "protocol_or_scan_mode_changes": False,
            "raw_api_or_cli_response_returned": False,
        },
        False,
    )
