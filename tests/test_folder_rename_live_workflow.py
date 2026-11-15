from __future__ import annotations

import copy

import pytest

from fortipam_mcp.folder_rename_live_workflow import (
    FolderRenameLiveWorkflow,
    FolderRenameLiveWorkflowError,
)


REQUESTER = "a" * 64


class FakeFolderRenameTransport:
    def __init__(self) -> None:
        self.folder = _folder()
        self.update_calls: list[tuple[int, dict[str, object]]] = []
        self.fail_update = False
        self.preserve_old_name = False

    def read_folder(self, folder_id: int) -> dict[str, object]:
        assert folder_id == 42
        return {"results": [copy.deepcopy(self.folder)]}

    def update_folder(
        self,
        folder_id: int,
        body: dict[str, object],
    ) -> dict[str, object]:
        assert folder_id == 42
        self.update_calls.append(copy.deepcopy((folder_id, body)))
        if self.fail_update:
            raise RuntimeError("unavailable")
        if not self.preserve_old_name:
            self.folder = copy.deepcopy(body)
        return {"status": "success"}


def _folder() -> dict[str, object]:
    return {
        "id": 42,
        "name": "Current-Folder-Name",
        "parent-folder": 7,
        "folder-type": "public",
        "secret-policy": "default",
        "inherit-policy": "enable",
        "inherit-permission": "disable",
        "inherit-folder-ztna": "enable",
        "ztna-ems-tag": [],
        "ztna-tags-match-logic": "or",
        "user-permission": [
            {
                "id": 11,
                "user-name": [{"name": "operator-a"}],
                "folder-permission": "edit",
                "secret-permission": "view",
            }
        ],
        "group-permission": [],
    }


def _preview(workflow: FolderRenameLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        folder_id=42,
        new_name="Requested-Folder-Name",
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_discloses_only_requested_folder_values() -> None:
    workflow = FolderRenameLiveWorkflow(FakeFolderRenameTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "selected_folder_id": 42,
        "requested_new_name": "Requested-Folder-Name",
        "folder_exists": True,
        "folder_scope": "public_child",
        "permission_inheritance": "disable",
        "requested_name_already_matches": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "rename_public_child_folder_via_api",
        "folder_id": 42,
        "current_name_returned": False,
        "new_name": "Requested-Folder-Name",
        "acl_and_policy_projection_preserved": True,
        "ztna_projection_preserved": True,
    }
    assert preview["Expected State"] == {
        "folder_id_matches": True,
        "folder_exists": True,
        "folder_scope": "public_child",
        "requested_name_matches": True,
        "parent_relation_preserved": True,
        "acl_and_policy_projection_preserved": True,
        "ztna_projection_preserved": True,
    }
    rendered = str(preview)
    assert "Current-Folder-Name" not in rendered
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_preserves_projection_and_is_idempotent() -> None:
    transport = FakeFolderRenameTransport()
    workflow = FolderRenameLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(FolderRenameLiveWorkflowError):
        workflow.execute("folder-rename-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert len(transport.update_calls) == 1
    _, body = transport.update_calls[0]
    assert body["name"] == "Requested-Folder-Name"
    assert body["parent-folder"] == 7
    assert body["secret-policy"] == "default"
    assert body["ztna-ems-tag"] == []
    assert body["ztna-tags-match-logic"] == "or"
    assert body["user-permission"] == _folder()["user-permission"]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["folder_id_returned"] is False
    assert result["folder_name_returned"] is False
    assert result["raw_api_response_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.update_calls) == 1


def test_known_read_only_acl_metadata_is_normalized_before_fixed_put() -> None:
    transport = FakeFolderRenameTransport()
    user_relation = transport.folder["user-permission"][0]  # type: ignore[index]
    assert isinstance(user_relation, dict)
    user_relation["allowed-launcher-type"] = "all"
    user_relation["q_origin_key"] = 101
    user_principal = user_relation["user-name"][0]  # type: ignore[index]
    assert isinstance(user_principal, dict)
    user_principal["q_origin_key"] = 102
    transport.folder["group-permission"] = [
        {
            "id": 12,
            "group-name": [{"name": "operators", "q_origin_key": 103}],
            "folder-permission": "view",
            "secret-permission": "list",
            "allowed-launcher-type": "all",
            "q_origin_key": 104,
        }
    ]
    workflow = FolderRenameLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "succeeded"
    assert len(transport.update_calls) == 1
    body = transport.update_calls[0][1]
    assert body["user-permission"] == _folder()["user-permission"]
    assert body["group-permission"] == [
        {
            "id": 12,
            "group-name": [{"name": "operators"}],
            "folder-permission": "view",
            "secret-permission": "list",
        }
    ]


def test_unknown_or_restrictive_acl_response_metadata_is_rejected() -> None:
    for field, value in (
        ("allowed-launcher-type", "rdp"),
        ("unknown-response-field", "value"),
    ):
        transport = FakeFolderRenameTransport()
        relation = transport.folder["user-permission"][0]  # type: ignore[index]
        assert isinstance(relation, dict)
        relation[field] = value

        with pytest.raises(FolderRenameLiveWorkflowError):
            _preview(FolderRenameLiveWorkflow(transport))


def test_confirm_invalidates_when_ztna_projection_drifts() -> None:
    transport = FakeFolderRenameTransport()
    workflow = FolderRenameLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.folder["ztna-tags-match-logic"] = "and"

    with pytest.raises(FolderRenameLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.update_calls == []


def test_failed_update_or_readback_requires_reconciliation_without_replay() -> None:
    transport = FakeFolderRenameTransport()
    workflow = FolderRenameLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.preserve_old_name = True

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(FolderRenameLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_noop_unsafe_name_or_outside_scope() -> None:
    transport = FakeFolderRenameTransport()
    workflow = FolderRenameLiveWorkflow(transport)

    transport.folder["name"] = "Requested-Folder-Name"
    with pytest.raises(FolderRenameLiveWorkflowError):
        _preview(workflow)
    transport.folder = _folder()
    with pytest.raises(FolderRenameLiveWorkflowError):
        workflow.preview(folder_id=42, new_name="unsafe/name", requester_digest=REQUESTER)
    transport.folder["inherit-permission"] = "enable"
    with pytest.raises(FolderRenameLiveWorkflowError):
        _preview(workflow)
