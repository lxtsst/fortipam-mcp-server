from __future__ import annotations

import copy
import json

import pytest

from fortipam_mcp.folder_acl_revoke_live_workflow import (
    FolderAclRevokeLiveWorkflow,
    FolderAclRevokeLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_USER = "mcp-folder-acl-user-01"


class FakeFolderAclRevokeTransport:
    def __init__(self) -> None:
        self.records: dict[int, dict[str, object]] = {
            4: _folder(
                folder_id=4,
                parent_id=2,
                inherit_permission="disable",
                users=[
                    _user(TARGET_USER, "view", "view"),
                    _user("existing-owner", "owner", "owner"),
                ],
                groups=[_group("existing-group", "view", "view")],
            )
        }
        self.update_calls: list[tuple[int, dict[str, object]]] = []
        self.fail_update = False
        self.readback_mismatch = False
        self.ztna_readback_mismatch = False

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
        if self.readback_mismatch:
            users = self.records[folder_id]["user-permission"]
            assert isinstance(users, list)
            users.append(_user(TARGET_USER, "view", "view"))
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
        "id": 0,
        "user-name": [name],
        "folder-permission": folder_permission,
        "secret-permission": secret_permission,
        "allowed-launcher-type": "all",
    }


def _group(name: str, folder_permission: str, secret_permission: str) -> dict[str, object]:
    return {
        "id": 0,
        "group-name": [{"name": name}],
        "folder-permission": folder_permission,
        "secret-permission": secret_permission,
    }


def _preview(workflow: FolderAclRevokeLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        folder_id=4,
        username=TARGET_USER,
        requester_digest=REQUESTER,
    )


def test_preview_limits_revoke_to_one_direct_relation_and_shows_requested_subject() -> None:
    workflow = FolderAclRevokeLiveWorkflow(
        FakeFolderAclRevokeTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "selected_folder_id": 4,
        "requested_username": TARGET_USER,
        "folder_exists": True,
        "folder_scope": "public_child",
        "permission_inheritance": "disable",
        "direct_user_relation_count": 2,
        "direct_group_relation_count": 1,
        "requested_direct_user_relation_present": True,
    }
    assert preview["Proposed Changes"] == {
        "operation": "revoke_public_folder_direct_user_acl",
        "folder_id": 4,
        "username": TARGET_USER,
        "direct_user_relation_count_delta": -1,
        "permission_inheritance_preserved": True,
    }
    assert preview["Expected State"]["requested_username_direct_relation_present"] is False
    rendered = json.dumps(preview)
    assert TARGET_USER in rendered
    assert "Folder-4" not in rendered
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_preserves_other_relations_and_reads_back() -> None:
    transport = FakeFolderAclRevokeTransport()
    workflow = FolderAclRevokeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(FolderAclRevokeLiveWorkflowError):
        workflow.execute("folder-acl-revoke-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["credentials_returned"] is False
    assert result["raw_response_returned"] is False
    assert len(transport.update_calls) == 1
    written = transport.update_calls[0][1]
    assert written["inherit-permission"] == "disable"
    assert written["user-permission"] == [
        {
            "id": 0,
            "user-name": [{"name": "existing-owner"}],
            "folder-permission": "owner",
            "secret-permission": "owner",
        }
    ]
    assert written["group-permission"] == [
        {
            "id": 0,
            "group-name": [{"name": "existing-group"}],
            "folder-permission": "view",
            "secret-permission": "view",
        }
    ]
    assert "allowed-launcher-type" not in json.dumps(written)
    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.update_calls) == 1


def test_confirm_invalidates_on_acl_drift_before_write() -> None:
    transport = FakeFolderAclRevokeTransport()
    workflow = FolderAclRevokeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.records[4]["group-permission"] = [_group("changed-group", "view", "view")]

    with pytest.raises(FolderAclRevokeLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.update_calls == []


def test_preview_rejects_unsupported_folder_and_relation_shapes() -> None:
    transport = FakeFolderAclRevokeTransport()
    transport.records[4]["inherit-permission"] = "enable"
    with pytest.raises(FolderAclRevokeLiveWorkflowError):
        _preview(FolderAclRevokeLiveWorkflow(transport))


def test_preview_canonicalizes_only_proven_read_only_acl_metadata() -> None:
    transport = FakeFolderAclRevokeTransport()
    user = transport.records[4]["user-permission"][0]
    group = transport.records[4]["group-permission"][0]
    assert isinstance(user, dict)
    assert isinstance(group, dict)
    user["q_origin_key"] = 1
    group["q_origin_key"] = 1
    group["allowed-launcher-type"] = "all"
    user_name = user["user-name"][0]
    group_name = group["group-name"][0]
    assert isinstance(user_name, str)
    assert isinstance(group_name, dict)
    user["user-name"] = [{"name": user_name, "q_origin_key": user_name}]
    group_name["q_origin_key"] = group_name["name"]

    preview = _preview(FolderAclRevokeLiveWorkflow(transport))

    assert preview["Current State"]["requested_direct_user_relation_present"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    (("allowed-launcher-type", "ssh"), ("unexpected-read-only-field", "value")),
)
def test_preview_rejects_unproven_acl_metadata(field: str, value: str) -> None:
    transport = FakeFolderAclRevokeTransport()
    user = transport.records[4]["user-permission"][0]
    assert isinstance(user, dict)
    user[field] = value

    with pytest.raises(FolderAclRevokeLiveWorkflowError):
        _preview(FolderAclRevokeLiveWorkflow(transport))

    transport = FakeFolderAclRevokeTransport()
    transport.records[4]["folder-type"] = "private"
    with pytest.raises(FolderAclRevokeLiveWorkflowError):
        _preview(FolderAclRevokeLiveWorkflow(transport))

    transport = FakeFolderAclRevokeTransport()
    transport.records[4]["parent-folder"] = 0
    with pytest.raises(FolderAclRevokeLiveWorkflowError):
        _preview(FolderAclRevokeLiveWorkflow(transport))

    transport = FakeFolderAclRevokeTransport()
    transport.records[4]["user-permission"] = [_user("other-user", "view", "view")]
    with pytest.raises(FolderAclRevokeLiveWorkflowError):
        _preview(FolderAclRevokeLiveWorkflow(transport))

    transport = FakeFolderAclRevokeTransport()
    transport.records[4]["user-permission"] = [
        {
            "id": 0,
            "user-name": [TARGET_USER, "other-user"],
            "folder-permission": "view",
            "secret-permission": "view",
        }
    ]
    with pytest.raises(FolderAclRevokeLiveWorkflowError):
        _preview(FolderAclRevokeLiveWorkflow(transport))

    transport = FakeFolderAclRevokeTransport()
    transport.records[4]["user-permission"] = [
        _user(TARGET_USER, "view", "view"),
        _user(TARGET_USER, "owner", "owner"),
    ]
    with pytest.raises(FolderAclRevokeLiveWorkflowError):
        _preview(FolderAclRevokeLiveWorkflow(transport))


def test_provider_or_readback_failure_requires_reconciliation_without_raw_data() -> None:
    transport = FakeFolderAclRevokeTransport()
    transport.fail_update = True
    workflow = FolderAclRevokeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    assert result["raw_response_returned"] is False

    transport = FakeFolderAclRevokeTransport()
    transport.readback_mismatch = True
    workflow = FolderAclRevokeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    mismatch = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert mismatch["outcome"] == "reconciliation_required"
    assert mismatch["verification"] == "unknown"

    transport = FakeFolderAclRevokeTransport()
    transport.ztna_readback_mismatch = True
    workflow = FolderAclRevokeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    ztna_mismatch = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert ztna_mismatch["outcome"] == "reconciliation_required"
    assert ztna_mismatch["verification"] == "unknown"
