from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp.folder_live_workflow import ChildFolderWorkflowError
from fortipam_mcp.folder_traversal_candidate import prepare_folder_traversal
from fortipam_mcp.folder_traversal_live_workflow import FolderTraversalLiveWorkflow
from fortipam_mcp.folder_traversal_m4_adapter import FolderTraversalBinding
from test_folder_traversal_candidate import record


class Transport:
    def __init__(self, failure=None):
        self.value = record()
        self.failure = failure
        self.writes = 0

    def read_product_version_and_build(self):
        return "7.0.0", 29

    def owner_is_available(self, name):
        return name == "gui-user"

    def read_folder(self, folder_id):
        assert folder_id == 12
        return deepcopy(self.value)

    def update_traversal(self, binding):
        self.writes += 1
        candidate = prepare_folder_traversal(self.value, folder_id=binding.folder_id,
            parent_id=binding.parent_id, username=binding.username, version="7.0.0", build=29)
        self.value = candidate.body
        self.value["user-permission"][-1]["id"] = 27
        if self.failure == "ambiguous":
            raise TimeoutError
        if self.failure == "acl":
            self.value["user-permission"][0]["allowed-launcher-type"] = "custom"
        if self.failure == "secret":
            self.value["user-permission"][-1]["secret-permission"] = "view"


@pytest.mark.parametrize("failure", [None, "ambiguous", "acl", "secret"])
def test_durable_once_only_execution_and_complete_acl_readback(tmp_path, failure):
    key = tmp_path / "key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    transport = Transport(failure)
    candidate = prepare_folder_traversal(transport.value, folder_id=12,
        parent_id=0, username="gui-user", version="7.0.0", build=29)
    binding = FolderTraversalBinding(12, 0, "gui-user", candidate.current_digest, candidate.proposed_digest)
    def workflow(selected=binding):
        return FolderTraversalLiveWorkflow(tmp_path / "state.sqlite3", key,
            transport, binding=selected, clock=lambda: 1000)
    preview = workflow().preview(folder_name="folder-traversal", parent_folder_id=12,
                                 requester_digest="b" * 64)
    assert "gui-user" not in json.dumps(preview)
    confirmation = workflow().confirm(preview["preview_ref"], requester_digest="b" * 64)
    with pytest.raises(ChildFolderWorkflowError):
        workflow(replace(binding, expected_digest="c" * 64)).execute(
            confirmation["authorization_ref"], requester_digest="b" * 64)
    assert transport.writes == 0
    result = workflow().execute(confirmation["authorization_ref"], requester_digest="b" * 64)
    assert (result["outcome"] == "succeeded") is (failure is None)
    if failure is None:
        assert workflow().execute(confirmation["authorization_ref"], requester_digest="b" * 64)["idempotent_replay"]
    else:
        with pytest.raises(ChildFolderWorkflowError):
            workflow().execute(confirmation["authorization_ref"], requester_digest="b" * 64)
    assert transport.writes == 1


def test_state_drift_after_confirmation_prevents_dispatch(tmp_path):
    key = tmp_path / "key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    transport = Transport()
    candidate = prepare_folder_traversal(transport.value, folder_id=12,
        parent_id=0, username="gui-user", version="7.0.0", build=29)
    workflow = FolderTraversalLiveWorkflow(tmp_path / "state.sqlite3", key, transport,
        binding=FolderTraversalBinding(12, 0, "gui-user", candidate.current_digest, candidate.proposed_digest),
        clock=lambda: 1000)
    preview = workflow.preview(folder_name="folder-traversal", parent_folder_id=12, requester_digest="b" * 64)
    confirmation = workflow.confirm(preview["preview_ref"], requester_digest="b" * 64)
    transport.value["secret-policy"] = "changed"
    result = workflow.execute(confirmation["authorization_ref"], requester_digest="b" * 64)
    assert result["outcome"] == "reconciliation_required"
    assert transport.writes == 0
