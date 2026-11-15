from __future__ import annotations

import json
from pathlib import Path
import stat

import pytest

from scripts.v4_folder_create_mcp_oauth_acceptance import (
    FolderCreateMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_confirmation,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


PARENT_ID = 88
NAME = "mcp-v4-rename-src-b62"
PREVIEW_REF = "folder-preview-test"


def _preview() -> dict[str, object]:
    return {
        "contract": "fortipam_v4_child_folder_workflow_v1",
        "preview_ref": PREVIEW_REF,
        "device_write_executed": False,
        "Current State": {
            "selected_parent_folder_id": PARENT_ID,
            "requested_child_folder_name": NAME,
            "parent_exists": True,
            "matching_child_exists": False,
        },
        "Proposed Changes": {
            "operation": "create_inherited_public_child_folder",
            "parent_folder_id": PARENT_ID,
            "folder_name": NAME,
        },
        "Expected State": {
            "child_folder_name_matches": True,
            "matching_child_exists": True,
            "inherit_policy": "enable",
            "inherit_permission": "enable",
            "inherit_folder_ztna": "enable",
        },
    }


def test_validates_exact_create_cpe_confirmation_and_execution() -> None:
    _validate_preview(_preview(), NAME, PARENT_ID, False)
    assert _validate_confirmation(
        {
            "contract": "fortipam_v4_child_folder_workflow_v1",
            "authorization_ref": "folder-authorized-test",
            "confirmation": "recorded",
            "execution": "authorized_once",
            "device_write_executed": False,
        },
        False,
    ).startswith("folder-authorized-")
    _validate_execution(
        {
            "contract": "fortipam_v4_child_folder_execution_v1",
            "outcome": "succeeded",
            "verification": "verified",
            "idempotent_replay": False,
            "compensation": "not_requested",
            "credentials_returned": False,
            "raw_response_returned": False,
        },
        False,
    )


def test_rejects_non_inherited_or_non_categorical_result() -> None:
    invalid = _preview()
    assert isinstance(invalid["Expected State"], dict)
    invalid["Expected State"]["inherit_permission"] = "disable"
    with pytest.raises(FolderCreateMcpOAuthAcceptanceError):
        _validate_preview(invalid, NAME, PARENT_ID, False)
    with pytest.raises(FolderCreateMcpOAuthAcceptanceError):
        _validate_execution({}, False)


def test_preview_reference_is_owner_only(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    state = tmp_path / "preview.json"
    _write_preview_state(state, PREVIEW_REF)
    assert _read_preview_ref(state) == PREVIEW_REF
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    state.write_text(json.dumps({"preview_ref": "bad"}), encoding="utf-8")
    with pytest.raises(FolderCreateMcpOAuthAcceptanceError):
        _read_preview_ref(state)
