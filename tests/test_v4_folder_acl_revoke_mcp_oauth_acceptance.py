from __future__ import annotations

import stat
import pytest

from scripts.v4_folder_acl_revoke_mcp_oauth_acceptance import FolderAclRevokeMcpOAuthAcceptanceError, _read_preview_ref, _validate_execution, _validate_preview, _write_preview_state


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"; directory.mkdir(mode=0o700); directory.chmod(0o700)
    path = directory / "preview.json"; _write_preview_state(path, "folder-acl-revoke-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "folder-acl-revoke-preview-opaque"
    with pytest.raises(FolderAclRevokeMcpOAuthAcceptanceError): _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_acl_contract() -> None:
    folder_id, username = 8, "mcp-folder-acl-user-01"
    projection = {"contract": "fortipam_v4_folder_user_acl_revoke_workflow_v1", "preview_ref": "folder-acl-revoke-preview-opaque", "device_write_executed": False, "Current State": {"selected_folder_id": folder_id, "requested_username": username, "folder_exists": True, "folder_scope": "public_child", "permission_inheritance": "disable", "requested_direct_user_relation_present": True}, "Proposed Changes": {"operation": "revoke_public_folder_direct_user_acl", "folder_id": folder_id, "username": username, "direct_user_relation_count_delta": -1, "permission_inheritance_preserved": True}, "Expected State": {"folder_exists": True, "folder_scope": "public_child", "permission_inheritance": "disable", "requested_username_direct_relation_present": False, "other_direct_user_relations_preserved": True, "direct_group_relations_preserved": True}}
    _validate_preview(projection, folder_id, username, False)
    result = {"contract": "fortipam_v4_folder_user_acl_revoke_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "grant_new_direct_relation_required", "credentials_returned": False, "raw_response_returned": False}
    _validate_execution(result, False)
    result["raw_response_returned"] = True
    with pytest.raises(FolderAclRevokeMcpOAuthAcceptanceError): _validate_execution(result, False)
