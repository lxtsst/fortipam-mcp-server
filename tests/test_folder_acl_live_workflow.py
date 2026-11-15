from __future__ import annotations

import copy
import json

import pytest

from fortipam_mcp.folder_acl_live_workflow import (
    FolderAclGrantLiveWorkflow,
    FolderAclLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_USER = "mcp-folder-acl-user-01"


class FakeFolderAclTransport:
    def __init__(self) -> None:
        self.records: dict[int, dict[str, object]] = {
            2: _folder(
                folder_id=2,
                parent_id=1,
                inherit_permission="disable",
                users=[_user("existing-owner", "owner", "owner")],
                groups=[_group("existing-group", "view", "view")],
            ),
            4: _folder(
                folder_id=4,
                parent_id=2,
                inherit_permission="enable",
                users=[],
                groups=[],
            ),
        }
        self.update_calls: list[tuple[int, dict[str, object]]] = []
        self.fail_update = False
        self.ztna_readback_mismatch = False
        self.assign_new_relation_id = False

    def read_folder(self, folder_id: int) -> dict[str, object]:
        return copy.deepcopy(self.records[folder_id])

    def update_folder(
        self,
        folder_id: int,
        body: dict[str, object],
    ) -> dict[str, object]:
        self.update_calls.append((folder_id, copy.deepcopy(body)))
        if self.fail_update:
            raise RuntimeError("provider unavailable")
        self.records[folder_id] = copy.deepcopy(body)
        if self.assign_new_relation_id:
            for relation in self.records[folder_id]["user-permission"]:
                if relation["id"] == 0:
                    relation["id"] = 27
        if self.ztna_readback_mismatch:
            self.records[folder_id]["ztna-tags-match-logic"] = "and"
        return {"ok": True, "http_status": 200}


def _folder(
    *,
    folder_id: int,
    parent_id: int,
    inherit_permission: str,
    users: list[dict[str, object]],
    groups: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "id": folder_id,
        "name": f"Folder-{folder_id}",
        "parent-folder": parent_id,
        "folder-type": "public",
        "secret-policy": "default",
        "inherit-policy": "enable",
        "inherit-permission": inherit_permission,
        "inherit-folder-ztna": "enable",
        "ztna-ems-tag": [],
        "ztna-tags-match-logic": "or",
        "user-permission": users,
        "group-permission": groups,
    }


def _user(name: str, folder_permission: str, secret_permission: str) -> dict[str, object]:
    return {
        "id": 11,
        "user-name": [name],
        "folder-permission": folder_permission,
        "secret-permission": secret_permission,
        "allowed-launcher-type": "all",
    }


def _group(name: str, folder_permission: str, secret_permission: str) -> dict[str, object]:
    return {
        "id": 19,
        "group-name": [{"name": name}],
        "folder-permission": folder_permission,
        "secret-permission": secret_permission,
    }


def _preview(workflow: FolderAclGrantLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        folder_id=4,
        username=TARGET_USER,
        folder_permission="view",
        secret_permission="view",
        requester_digest=REQUESTER,
    )


def test_preview_uses_effective_parent_acl_and_shows_requested_acl_subject() -> None:
    workflow = FolderAclGrantLiveWorkflow(FakeFolderAclTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "selected_folder_id": 4,
        "requested_username": TARGET_USER,
        "requested_folder_permission": "view",
        "requested_secret_permission": "view",
        "folder_exists": True,
        "folder_scope": "public_child",
        "permission_inheritance": "enable",
        "effective_user_relation_count": 1,
        "effective_group_relation_count": 1,
        "requested_user_relation_present": False,
    }
    assert preview["Proposed Changes"] == {
        "operation": "grant_public_folder_user_acl",
        "folder_id": 4,
        "username": TARGET_USER,
        "folder_permission": "view",
        "secret_permission": "view",
        "permission_inheritance_after_change": "disable",
    }
    assert preview["Expected State"]["requested_username_relation_present"] is True
    assert preview["Expected State"]["requested_folder_permission_matches"] is True
    assert preview["Expected State"]["requested_secret_permission_matches"] is True
    assert TARGET_USER in json.dumps(preview)
    assert preview["device_write_executed"] is False

    group_preview = workflow.preview_group(
        folder_id=4,
        group_name="existing-group",
        folder_permission="view",
        secret_permission="view",
        requester_digest=REQUESTER,
    )
    assert group_preview["Current State"]["requested_group_relation_present"] is True
    assert group_preview["Proposed Changes"]["operation"] == (
        "grant_public_folder_group_acl"
    )


def test_execute_requires_confirmation_writes_once_and_reads_back() -> None:
    transport = FakeFolderAclTransport()
    workflow = FolderAclGrantLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(FolderAclLiveWorkflowError):
        workflow.execute("folder-acl-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["credentials_returned"] is False
    assert result["raw_response_returned"] is False
    assert len(transport.update_calls) == 1
    written = transport.update_calls[0][1]
    assert written["inherit-permission"] == "disable"
    assert written["ztna-ems-tag"] == []
    assert written["ztna-tags-match-logic"] == "or"
    assert "allowed-launcher-type" not in json.dumps(written)
    assert written["user-permission"][0]["id"] == 11
    assert written["group-permission"] == [
        {
            "id": 19,
            "group-name": [{"name": "existing-group"}],
            "folder-permission": "view",
            "secret-permission": "view",
        }
    ]
    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.update_calls) == 1


def test_folder_view_without_secret_access_preserves_existing_acl() -> None:
    transport = FakeFolderAclTransport()
    initial_groups = copy.deepcopy(transport.records[2]["group-permission"])
    workflow = FolderAclGrantLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(
        folder_id=2, username=TARGET_USER, folder_permission="view",
        secret_permission="none", requester_digest=REQUESTER,
    )
    assert preview["Proposed Changes"]["secret_permission"] == "none"
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    written = transport.update_calls[0][1]
    assert written["group-permission"] == initial_groups
    users = written["user-permission"]
    assert any(r["user-name"] == [{"name": "existing-owner"}]
               and r["folder-permission"] == "owner" and r["secret-permission"] == "owner"
               for r in users)
    assert any(r["user-name"] == [{"name": TARGET_USER}]
               and r["folder-permission"] == "view" and r["secret-permission"] == "none"
               for r in users)


def test_assigned_relation_id_preserves_exact_acl_readback() -> None:
    transport = FakeFolderAclTransport()
    transport.assign_new_relation_id = True
    workflow = FolderAclGrantLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert transport.update_calls[0][1]["user-permission"][-1]["id"] == 0
    assert transport.records[4]["user-permission"][-1]["id"] == 27


def test_confirm_invalidates_when_effective_acl_drifts() -> None:
    transport = FakeFolderAclTransport()
    workflow = FolderAclGrantLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.records[2]["group-permission"] = [_group("changed-group", "view", "view")]

    with pytest.raises(FolderAclLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.update_calls == []


def test_provider_failure_requires_reconciliation_without_raw_data() -> None:
    transport = FakeFolderAclTransport()
    transport.fail_update = True
    workflow = FolderAclGrantLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    assert result["raw_response_returned"] is False


def test_ztna_readback_mismatch_requires_reconciliation() -> None:
    transport = FakeFolderAclTransport()
    transport.ztna_readback_mismatch = True
    workflow = FolderAclGrantLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"


def test_preview_rejects_root_non_public_and_ambiguous_multiname_relation() -> None:
    transport = FakeFolderAclTransport()
    workflow = FolderAclGrantLiveWorkflow(transport)
    transport.records[4]["parent-folder"] = 0
    with pytest.raises(FolderAclLiveWorkflowError):
        _preview(workflow)

    transport = FakeFolderAclTransport()
    transport.records[4]["folder-type"] = "private"
    with pytest.raises(FolderAclLiveWorkflowError):
        _preview(FolderAclGrantLiveWorkflow(transport))

    transport = FakeFolderAclTransport()
    transport.records[2]["user-permission"] = [
        {
            "id": 0,
            "user-name": [TARGET_USER, "other-user"],
            "folder-permission": "view",
            "secret-permission": "view",
        }
    ]
    with pytest.raises(FolderAclLiveWorkflowError):
        _preview(FolderAclGrantLiveWorkflow(transport))
