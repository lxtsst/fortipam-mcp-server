from dataclasses import replace
import json
import pytest
from fortipam_mcp.isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from fortipam_mcp.isolated_folder_m4_adapter import IsolatedFolderBinding
from fortipam_mcp.folder_live_workflow import ChildFolderWorkflowError
from test_isolated_folder_m4_adapter import Transport


@pytest.mark.parametrize("failure", [None, "acl", "ambiguous"])
def test_signed_confirmation_and_restart_do_not_repeat_isolated_folder_write(tmp_path, failure, caplog):
    key = tmp_path / "key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
    transport = Transport(failure)
    def workflow(selected=binding):
        return IsolatedFolderLiveWorkflow(tmp_path / "workflow.sqlite3", key, transport,
            binding=selected, clock=lambda: 1000)
    first = workflow()
    preview = first.preview(folder_name=binding.name, parent_folder_id=17, requester_digest="b" * 64)
    rendered = json.dumps(preview)
    assert "synthetic-owner" not in rendered
    assert preview["Proposed Changes"]["disable_permission_inheritance"] is True
    confirmation = first.confirm(preview["preview_ref"], requester_digest="b" * 64)
    with pytest.raises(ChildFolderWorkflowError):
        workflow(replace(binding, owner_name="another-owner")).execute(
            confirmation["authorization_ref"], requester_digest="b" * 64)
    assert transport.posts == 0
    result = workflow().execute(confirmation["authorization_ref"], requester_digest="b" * 64)
    assert (result["outcome"] == "succeeded") is (failure is None)
    if failure is not None:
        expected_stage = "readback" if failure == "acl" else "dispatch"
        assert f"stage={expected_stage}" in caplog.text
        assert binding.owner_name not in caplog.text
        assert confirmation["authorization_ref"] not in caplog.text
    assert transport.posts == 1
    if failure is None:
        replay = workflow().execute(confirmation["authorization_ref"], requester_digest="b" * 64)
        assert replay["idempotent_replay"] is True
    else:
        with pytest.raises(ChildFolderWorkflowError):
            workflow().execute(confirmation["authorization_ref"], requester_digest="b" * 64)
    assert transport.posts == 1


def test_parallel_requests_cannot_both_reserve_signed_folder_execution(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    key = tmp_path / "key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
    workflow = IsolatedFolderLiveWorkflow(tmp_path / "workflow.sqlite3", key, Transport(None),
        binding=binding, clock=lambda: 1000)
    preview = workflow.preview(folder_name=binding.name, parent_folder_id=17, requester_digest="b" * 64)
    workflow.confirm(preview["preview_ref"], requester_digest="b" * 64)
    barrier = Barrier(2)
    original = workflow._transition
    def transition(current, updated):
        barrier.wait(timeout=5)
        return original(current, updated)
    workflow._transition = transition
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: workflow._reserve(preview["preview_ref"]), range(2)))
    assert sorted(outcomes) == [False, True]


@pytest.mark.parametrize("phase", ("confirm", "execute", "transport_execute"))
def test_slow_final_read_rejects_expiry_without_reviving_authorization(tmp_path, monkeypatch, phase):
    now = [1000]
    key = tmp_path / "key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
    transport = Transport(None)

    def workflow():
        return IsolatedFolderLiveWorkflow(tmp_path / "workflow.sqlite3", key, transport,
            binding=binding, clock=lambda: now[0])

    first = workflow()
    preview = first.preview(folder_name=binding.name, parent_folder_id=17, requester_digest="b" * 64)
    preview_ref = preview["preview_ref"]
    authorization_ref = None
    if phase != "confirm":
        authorization_ref = first.confirm(preview_ref, requester_digest="b" * 64)["authorization_ref"]
    find_child_ids = transport.find_child_ids
    reads = 0

    def slow_final_lookup(name, parent):
        nonlocal reads
        result = find_child_ids(name, parent)
        reads += 1
        if phase != "transport_execute" and reads == (1 if phase == "confirm" else 2):
            now[0] = preview["expires_at"]
        return result

    monkeypatch.setattr(transport, "find_child_ids", slow_final_lookup)
    if phase == "transport_execute":
        create_isolated_child = transport.create_isolated_child

        def slow_parent_read_before_create(**kwargs):
            now[0] = preview["expires_at"]
            return create_isolated_child(**kwargs)

        monkeypatch.setattr(transport, "create_isolated_child", slow_parent_read_before_create)
    if phase == "confirm":
        with pytest.raises(ChildFolderWorkflowError):
            first.confirm(preview_ref, requester_digest="b" * 64)
        record = workflow()._get_by_preview(preview_ref)
        assert record.state == "invalidated" and record.authorization_ref is None
    else:
        result = first.execute(authorization_ref, requester_digest="b" * 64)
        assert result["outcome"] == "reconciliation_required"
        assert result["verification"] == "unknown"
        assert workflow()._get_by_preview(preview_ref).state == "reconciliation_required"
    assert transport.posts == 0
    assert reads == (1 if phase == "confirm" else 2)
    now[0] = 1000
    with pytest.raises(ChildFolderWorkflowError):
        if phase == "confirm":
            workflow().confirm(preview_ref, requester_digest="b" * 64)
        else:
            workflow().execute(authorization_ref, requester_digest="b" * 64)
    assert transport.posts == 0
