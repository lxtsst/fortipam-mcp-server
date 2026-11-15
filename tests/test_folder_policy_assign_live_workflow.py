from __future__ import annotations

import copy

import pytest

from fortipam_mcp.folder_policy_assign_live_workflow import (
    FolderPolicyAssignLiveWorkflow,
    FolderPolicyAssignLiveWorkflowError,
)


REQUESTER = "a" * 64


class FakeFolderPolicyAssignTransport:
    def __init__(self) -> None:
        self.folder = _folder()
        self.update_calls: list[tuple[int, dict[str, object]]] = []
        self.fail_update = False
        self.preserve_old_policy = False

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
        if not self.preserve_old_policy:
            self.folder = copy.deepcopy(body)
        return {"status": "success"}


def _folder() -> dict[str, object]:
    return {
        "id": 42,
        "name": "Current-Folder-Name",
        "parent-folder": 7,
        "folder-type": "public",
        "secret-policy": "Current-Policy",
        "inherit-policy": "disable",
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
        "group-permission": [
            {
                "id": 12,
                "group-name": [{"name": "operators"}],
                "folder-permission": "view",
                "secret-permission": "view",
            }
        ],
    }


def _preview(workflow: FolderPolicyAssignLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        folder_id=42,
        policy_name="Requested-Policy",
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_discloses_only_requested_folder_and_policy_values() -> None:
    workflow = FolderPolicyAssignLiveWorkflow(
        FakeFolderPolicyAssignTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "selected_folder_id": 42,
        "requested_policy_name": "Requested-Policy",
        "folder_exists": True,
        "folder_scope": "public_child",
        "policy_inheritance": "disable",
        "permission_inheritance": "disable",
        "explicit_policy_binding_present": True,
        "requested_policy_already_matches": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "assign_public_child_folder_secret_policy_via_api",
        "folder_id": 42,
        "current_policy_identifier_returned": False,
        "secret_policy": "Requested-Policy",
        "policy_inheritance_preserved": True,
        "non_policy_projection_preserved": True,
    }
    assert preview["Expected State"] == {
        "folder_id_matches": True,
        "folder_exists": True,
        "folder_scope": "public_child",
        "policy_inheritance": "disable",
        "requested_explicit_policy_matches": True,
        "parent_relation_preserved": True,
        "permission_and_ztna_projection_preserved": True,
    }
    rendered = str(preview)
    assert "Current-Folder-Name" not in rendered
    assert "Current-Policy" not in rendered
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_preserves_projection_and_is_idempotent() -> None:
    transport = FakeFolderPolicyAssignTransport()
    workflow = FolderPolicyAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(FolderPolicyAssignLiveWorkflowError):
        workflow.execute(
            "folder-policy-assign-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert len(transport.update_calls) == 1
    _, body = transport.update_calls[0]
    assert body["secret-policy"] == "Requested-Policy"
    assert body["name"] == "Current-Folder-Name"
    assert body["parent-folder"] == 7
    assert body["inherit-policy"] == "disable"
    assert body["inherit-permission"] == "disable"
    assert body["inherit-folder-ztna"] == "enable"
    assert body["user-permission"] == _folder()["user-permission"]
    assert body["group-permission"] == _folder()["group-permission"]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["folder_id_returned"] is False
    assert result["policy_identifier_returned"] is False
    assert result["raw_api_response_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.update_calls) == 1


def test_confirm_invalidates_when_full_projection_drifts() -> None:
    transport = FakeFolderPolicyAssignTransport()
    workflow = FolderPolicyAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.folder["inherit-folder-ztna"] = "disable"

    with pytest.raises(FolderPolicyAssignLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.update_calls == []


@pytest.mark.parametrize("drift_at", [None, "confirm", "execute"])
def test_original_policy_remains_bound_before_confirmation_and_dispatch(
    drift_at: str | None,
) -> None:
    transport = FakeFolderPolicyAssignTransport()
    workflow = FolderPolicyAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    preview_ref = str(preview["preview_ref"])

    if drift_at == "confirm":
        transport.folder["secret-policy"] = "Different-Current-Policy"
        with pytest.raises(FolderPolicyAssignLiveWorkflowError):
            workflow.confirm(preview_ref, requester_digest=REQUESTER)
        transport.folder["secret-policy"] = "Current-Policy"
        with pytest.raises(FolderPolicyAssignLiveWorkflowError):
            workflow.confirm(preview_ref, requester_digest=REQUESTER)
        assert transport.update_calls == []
        return

    confirmation = workflow.confirm(preview_ref, requester_digest=REQUESTER)
    authorization_ref = str(confirmation["authorization_ref"])
    if drift_at == "execute":
        transport.folder["secret-policy"] = "Different-Current-Policy"
        with pytest.raises(FolderPolicyAssignLiveWorkflowError):
            workflow.execute(authorization_ref, requester_digest=REQUESTER)
        transport.folder["secret-policy"] = "Current-Policy"
        with pytest.raises(FolderPolicyAssignLiveWorkflowError):
            workflow.execute(authorization_ref, requester_digest=REQUESTER)
        assert transport.update_calls == []
        return

    result = workflow.execute(authorization_ref, requester_digest=REQUESTER)
    assert result["outcome"] == "succeeded"
    assert len(transport.update_calls) == 1
    assert transport.folder["secret-policy"] == "Requested-Policy"


def test_failed_update_or_readback_requires_reconciliation_without_replay() -> None:
    transport = FakeFolderPolicyAssignTransport()
    workflow = FolderPolicyAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.preserve_old_policy = True

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(FolderPolicyAssignLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda folder: folder.update({"folder-type": "private"}),
        lambda folder: folder.update({"parent-folder": 0}),
        lambda folder: folder.update({"inherit-policy": "enable"}),
        lambda folder: folder.update({"inherit-permission": "enable"}),
    ],
)
def test_preview_rejects_outside_explicit_public_child_scope(mutate) -> None:
    transport = FakeFolderPolicyAssignTransport()
    mutate(transport.folder)
    workflow = FolderPolicyAssignLiveWorkflow(transport)

    with pytest.raises(FolderPolicyAssignLiveWorkflowError):
        _preview(workflow)


@pytest.mark.parametrize("policy_name", ["Current-Policy", "unsafe/policy", " policy"])
def test_preview_rejects_noop_or_unsafe_policy_name(policy_name: str) -> None:
    workflow = FolderPolicyAssignLiveWorkflow(FakeFolderPolicyAssignTransport())

    with pytest.raises(FolderPolicyAssignLiveWorkflowError):
        workflow.preview(
            folder_id=42,
            policy_name=policy_name,
            requester_digest=REQUESTER,
        )


def test_preview_rejects_invalid_requester_without_leaking_transport_details() -> None:
    workflow = FolderPolicyAssignLiveWorkflow(FakeFolderPolicyAssignTransport())

    with pytest.raises(FolderPolicyAssignLiveWorkflowError):
        workflow.preview(
            folder_id=42,
            policy_name="Requested-Policy",
            requester_digest="wrong",
        )
