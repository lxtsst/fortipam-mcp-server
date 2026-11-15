from __future__ import annotations

import stat

import pytest

from scripts.v4_folder_archive_mcp_oauth_acceptance import (
    FolderArchiveMcpOAuthAcceptanceError,
    _contains_acceptance_error,
    _read_preview_ref,
    _validate_confirmation,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_owner_only_state_and_fixed_archive_contract(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    state = directory / "preview.json"
    preview_ref = "folder-archive-preview-opaque"
    folder_id = 100
    _write_preview_state(state, preview_ref)
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert _read_preview_ref(state) == preview_ref

    preview = {
        "contract": "fortipam_v4_empty_public_child_folder_archive_api_workflow_v1",
        "preview_ref": preview_ref,
        "device_write_executed": False,
        "Current State": {
            "selected_folder_id": folder_id,
            "folder_exists": True,
            "folder_scope": "isolated_v4_public_child",
            "folder_has_no_child_folders": True,
            "folder_hierarchy_checked_by_cli": True,
            "folder_has_no_cmdb_references": True,
            "folder_has_owner_only_permissions": True,
            "delete_actor_matches_folder_owner": True,
            "delete_authentication": "api_bearer",
            "folder_name_returned": False,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "archive_by_deleting_empty_v4_public_child_folder_via_api",
            "folder_id": folder_id,
            "folder_name_returned": False,
            "product_requires_empty_folder": True,
            "irreversible_after_execution": True,
            "secret_or_child_relocation_attempted": False,
        },
        "Expected State": {
            "folder_id_absent": True,
            "folder_exists": False,
            "folder_deletion_verified_by_collection_readback": True,
            "other_folder_configuration_modified": False,
            "secret_or_child_relocation_attempted": False,
        },
    }
    _validate_preview(preview, folder_id, False)
    for field in ("folder_hierarchy_checked_by_cli", "folder_has_no_cmdb_references", "folder_has_owner_only_permissions",
                  "delete_actor_matches_folder_owner"):
        for missing_evidence in (False, None):
            preview["Current State"][field] = missing_evidence
            with pytest.raises(FolderArchiveMcpOAuthAcceptanceError):
                _validate_preview(preview, folder_id, False)
        preview["Current State"][field] = True
    authorization_ref = _validate_confirmation(
        {
            "contract": "fortipam_v4_empty_public_child_folder_archive_api_workflow_v1",
            "authorization_ref": "folder-archive-authorized-opaque",
            "confirmation": "recorded",
            "execution": "authorized_once",
            "device_write_executed": False,
        },
        False,
    )
    assert authorization_ref == "folder-archive-authorized-opaque"
    execution = {
        "contract": "fortipam_v4_empty_public_child_folder_archive_api_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "manual_recreation_or_backup_restore_required",
        "irreversible_after_execution": True,
        "folder_id_returned": False,
        "folder_name_returned": False,
        "raw_api_response_returned": False,
    }
    _validate_execution(execution, False)


@pytest.mark.parametrize("field,value", [("folder_name_returned", True), ("raw_api_response_returned", True)])
def test_archive_execution_rejects_disclosure(field: str, value: object) -> None:
    execution = {
        "contract": "fortipam_v4_empty_public_child_folder_archive_api_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "manual_recreation_or_backup_restore_required",
        "irreversible_after_execution": True,
        "folder_id_returned": False,
        "folder_name_returned": False,
        "raw_api_response_returned": False,
    }
    execution[field] = value
    with pytest.raises(FolderArchiveMcpOAuthAcceptanceError):
        _validate_execution(execution, False)


def test_archive_preview_rejects_non_empty_or_non_isolated_baseline() -> None:
    preview = {
        "contract": "fortipam_v4_empty_public_child_folder_archive_api_workflow_v1",
        "preview_ref": "folder-archive-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "selected_folder_id": 100,
            "folder_exists": True,
            "folder_scope": "isolated_v4_public_child",
            "folder_has_no_child_folders": False,
            "folder_name_returned": False,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "archive_by_deleting_empty_v4_public_child_folder_via_api",
            "folder_id": 100,
            "folder_name_returned": False,
            "product_requires_empty_folder": True,
            "irreversible_after_execution": True,
            "secret_or_child_relocation_attempted": False,
        },
        "Expected State": {
            "folder_id_absent": True,
            "folder_exists": False,
            "folder_deletion_verified_by_collection_readback": True,
            "other_folder_configuration_modified": False,
            "secret_or_child_relocation_attempted": False,
        },
    }
    with pytest.raises(FolderArchiveMcpOAuthAcceptanceError):
        _validate_preview(preview, 100, False)


def test_archive_state_rejects_unprotected_directory(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o755)
    with pytest.raises(FolderArchiveMcpOAuthAcceptanceError):
        _write_preview_state(directory / "preview.json", "folder-archive-preview-opaque")


def test_archive_callback_error_detection_handles_nested_task_groups() -> None:
    nested = ExceptionGroup(
        "nested",
        [FolderArchiveMcpOAuthAcceptanceError("opaque failure")],
    )
    assert _contains_acceptance_error(ExceptionGroup("outer", [nested])) is True
    assert _contains_acceptance_error(ExceptionGroup("outer", [ValueError("other")])) is False
