from __future__ import annotations

import json
from pathlib import Path
import stat

import pytest

from scripts.v4_folder_rename_mcp_oauth_acceptance import (
    FolderRenameMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_confirmation,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


FOLDER_ID = 901
NEW_NAME = "mcp-v4-rename-b60"
PREVIEW = "folder-rename-preview-test"


def _preview() -> dict[str, object]:
    return {
        "contract": "fortipam_v4_public_child_folder_rename_api_workflow_v1",
        "preview_ref": PREVIEW,
        "device_write_executed": False,
        "Current State": {
            "selected_folder_id": FOLDER_ID,
            "requested_new_name": NEW_NAME,
            "folder_exists": True,
            "folder_scope": "public_child",
            "permission_inheritance": "disable",
            "requested_name_already_matches": False,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "rename_public_child_folder_via_api",
            "folder_id": FOLDER_ID,
            "current_name_returned": False,
            "new_name": NEW_NAME,
            "acl_and_policy_projection_preserved": True,
            "ztna_projection_preserved": True,
        },
        "Expected State": {
            "folder_id_matches": True,
            "folder_exists": True,
            "folder_scope": "public_child",
            "requested_name_matches": True,
            "parent_relation_preserved": True,
            "acl_and_policy_projection_preserved": True,
            "ztna_projection_preserved": True,
        },
    }


def test_validates_exact_preview_confirmation_and_execution() -> None:
    _validate_preview(_preview(), FOLDER_ID, NEW_NAME, False)
    assert _validate_confirmation(
        {
            "contract": "fortipam_v4_public_child_folder_rename_api_workflow_v1",
            "authorization_ref": "folder-rename-authorized-test",
            "confirmation": "recorded",
            "execution": "authorized_once",
            "device_write_executed": False,
        },
        False,
    ).startswith("folder-rename-authorized-")
    _validate_execution(
        {
            "contract": "fortipam_v4_public_child_folder_rename_api_execution_v1",
            "outcome": "succeeded",
            "verification": "verified",
            "idempotent_replay": False,
            "compensation": "not_requested",
            "folder_id_returned": False,
            "folder_name_returned": False,
            "raw_api_response_returned": False,
        },
        False,
    )


def test_rejects_unsafe_or_incomplete_projections() -> None:
    bad = _preview()
    assert isinstance(bad["Proposed Changes"], dict)
    bad["Proposed Changes"]["current_name_returned"] = True
    with pytest.raises(FolderRenameMcpOAuthAcceptanceError):
        _validate_preview(bad, FOLDER_ID, NEW_NAME, False)
    with pytest.raises(FolderRenameMcpOAuthAcceptanceError):
        _validate_execution({}, False)


def test_owner_only_preview_reference_state(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    state = tmp_path / "preview.json"
    _write_preview_state(state, PREVIEW)
    assert _read_preview_ref(state) == PREVIEW
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    state.write_text(json.dumps({"preview_ref": "bad"}), encoding="utf-8")
    with pytest.raises(FolderRenameMcpOAuthAcceptanceError):
        _read_preview_ref(state)
