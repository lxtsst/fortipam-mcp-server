from __future__ import annotations

import copy
import os
from pathlib import Path
import stat

import pytest

from fortipam_mcp.folder_archive_live_workflow import (
    FolderArchiveLiveWorkflow,
    FolderArchiveLiveWorkflowError,
)


REQUESTER = "a" * 64


class FakeFolderArchiveTransport:
    def __init__(self) -> None:
        self.records = [_archive_folder()]
        self.delete_calls: list[int] = []
        self.fail_delete = False
        self.no_references = True
        self.reference_checks: list[tuple[int, int]] = []
        self.keep_folder_after_delete = False
        self.collection_overrides: dict[str, object] = {}
        self.delete_response: dict[str, object] = {"http_status": 200, "status": "success", "serial": "FPA-SYNTHETIC"}

    def inspect(self, expected_requester: str) -> None:
        if expected_requester != "synthetic-owner":
            raise ValueError("Synthetic actor mismatch")

    def read_collection(self) -> dict[str, object]:
        return {
            "http_status": 200,
            "status": "success",
            "version": "v7.0.0",
            "build": 29,
            "serial": "FPA-SYNTHETIC",
            "matched_count": len(self.records),
            "results": copy.deepcopy(self.records),
            **self.collection_overrides,
        }

    def verify_no_references(self, folder_id: int, parent_folder_id: int, device_serial: str) -> bool:
        assert device_serial == "FPA-SYNTHETIC"
        self.reference_checks.append((folder_id, parent_folder_id))
        return self.no_references

    def delete_empty_folder(self, folder_id: int) -> dict[str, object]:
        self.delete_calls.append(folder_id)
        if self.fail_delete:
            raise RuntimeError("unavailable")
        if not self.keep_folder_after_delete:
            self.records = [
                record for record in self.records if record.get("id") != folder_id
            ]
        return self.delete_response


def _archive_folder() -> dict[str, object]:
    return {
        "id": 42,
        "name": "mcp-v4-archive-disposable-01",
        "parent-folder": 7,
        "folder-type": "public",
        "inherit-permission": "disable",
        "user-permission": [{"id": 1, "user-name": [{"name": "synthetic-owner"}],
                             "folder-permission": "owner", "secret-permission": "owner"}],
        "group-permission": [],
    }


def _preview(workflow: FolderArchiveLiveWorkflow) -> dict[str, object]:
    return workflow.preview(folder_id=42, requester_digest=REQUESTER)


def test_preview_is_live_destructive_cpe_and_discloses_only_requested_folder_id() -> None:
    transport = FakeFolderArchiveTransport()
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "selected_folder_id": 42,
        "folder_exists": True,
        "folder_scope": "isolated_v4_public_child",
        "folder_has_no_child_folders": True,
        "folder_hierarchy_checked_by_cli": True,
        "folder_has_no_cmdb_references": True,
        "folder_has_owner_only_permissions": True,
        "delete_actor_matches_folder_owner": True,
        "folder_name_returned": False,
        "write_transport": "rest_api",
        "delete_authentication": "api_bearer",
    }
    assert preview["Proposed Changes"] == {
        "operation": "archive_by_deleting_empty_v4_public_child_folder_via_api",
        "folder_id": 42,
        "folder_name_returned": False,
        "product_requires_empty_folder": True,
        "irreversible_after_execution": True,
        "secret_or_child_relocation_attempted": False,
    }
    assert preview["Expected State"] == {
        "folder_id_absent": True,
        "folder_exists": False,
        "folder_deletion_verified_by_collection_readback": True,
        "other_folder_configuration_modified": False,
        "secret_or_child_relocation_attempted": False,
    }
    rendered = str(preview)
    assert "mcp-v4-archive-disposable-01" not in rendered
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_deletes_once_and_verifies_absence(tmp_path: Path) -> None:
    transport = FakeFolderArchiveTransport()
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, clock=lambda: 100, claim_path=tmp_path / "claim.json")
    preview = _preview(workflow)

    with pytest.raises(FolderArchiveLiveWorkflowError):
        workflow.execute("folder-archive-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.delete_calls == [42]
    assert stat.S_IMODE((tmp_path / "claim.json").stat().st_mode) == 0o600
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["compensation"] == "manual_recreation_or_backup_restore_required"
    assert result["folder_id_returned"] is False
    assert result["folder_name_returned"] is False
    assert result["raw_api_response_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert transport.delete_calls == [42]


def test_confirm_invalidates_on_folder_or_child_drift() -> None:
    transport = FakeFolderArchiveTransport()
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.records[0]["name"] = "mcp-v4-archive-renamed-01"

    with pytest.raises(FolderArchiveLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = FakeFolderArchiveTransport()
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.records.append(
        {
            "id": 43,
            "name": "mcp-v4-archive-child-01",
            "parent-folder": 42,
            "folder-type": "public",
        }
    )
    with pytest.raises(FolderArchiveLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []


@pytest.mark.parametrize("phase", ("confirm", "execute"))
def test_archive_refuses_expiry_reached_during_prewrite_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    now = [100]
    transport = FakeFolderArchiveTransport()
    claim = tmp_path / "claim.json"
    workflow = FolderArchiveLiveWorkflow(
        transport, reference_reader=transport, actor_reader=transport,
        clock=lambda: now[0], claim_path=claim,
    )
    preview = _preview(workflow)
    reference = str(preview["preview_ref"])
    if phase == "execute":
        reference = str(workflow.confirm(reference, requester_digest=REQUESTER)["authorization_ref"])
    read_references = transport.verify_no_references

    def finish_read_at_expiry(folder_id: int, parent_id: int, serial: str) -> bool:
        result = read_references(folder_id, parent_id, serial)
        now[0] = int(preview["expires_at"])
        return result

    monkeypatch.setattr(transport, "verify_no_references", finish_read_at_expiry)
    with pytest.raises(FolderArchiveLiveWorkflowError):
        getattr(workflow, phase)(reference, requester_digest=REQUESTER)

    assert transport.delete_calls == []
    assert not claim.exists()


def test_delete_failure_or_missing_readback_requires_reconciliation(tmp_path: Path) -> None:
    transport = FakeFolderArchiveTransport()
    claim = tmp_path / "claim.json"
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, clock=lambda: 100, claim_path=claim)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.keep_folder_after_delete = True

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    assert transport.delete_calls == [42]
    with pytest.raises(FolderArchiveLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    class NoNetwork:
        def read_collection(self):
            pytest.fail("A consumed attempt must be refused before a read.")
        def delete_empty_folder(self, folder_id):
            pytest.fail("A consumed attempt must never be redispatched.")

    restarted = FolderArchiveLiveWorkflow(NoNetwork(), claim_path=claim)
    with pytest.raises(FolderArchiveLiveWorkflowError):
        _preview(restarted)


@pytest.mark.parametrize("mode", ("unbound", "dangling_symlink", "directory_fsync_failure"))
def test_archive_refuses_unbound_or_unsafe_durable_dispatch(tmp_path: Path, monkeypatch, mode: str) -> None:
    transport = FakeFolderArchiveTransport()
    claim = tmp_path / "claim.json"
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, claim_path=None if mode == "unbound" else claim)
    if mode == "dangling_symlink":
        claim.symlink_to(tmp_path / "missing.json")
        with pytest.raises(FolderArchiveLiveWorkflowError):
            _preview(workflow)
    else:
        preview = _preview(workflow)
        confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
        if mode == "directory_fsync_failure":
            original = os.fsync
            def fail_directory(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError("Synthetic directory durability failure")
                original(fd)
            monkeypatch.setattr(os, "fsync", fail_directory)
        with pytest.raises(FolderArchiveLiveWorkflowError):
            workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
        if mode == "directory_fsync_failure":
            assert claim.is_file()
    assert transport.delete_calls == []


@pytest.mark.parametrize(
    "mutation",
    (
        lambda record: record.update({"name": "outside-v4-scope"}),
        lambda record: record.update({"folder-type": "private"}),
        lambda record: record.update({"parent-folder": 0}),
        lambda record: record.update({"id": "42"}),
    ),
)
def test_preview_rejects_non_archive_scope_or_root_shapes(mutation: object) -> None:
    transport = FakeFolderArchiveTransport()
    assert callable(mutation)
    mutation(transport.records[0])
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport)

    with pytest.raises(FolderArchiveLiveWorkflowError):
        _preview(workflow)
    assert transport.delete_calls == []


def test_preview_rejects_folder_with_a_child() -> None:
    transport = FakeFolderArchiveTransport()
    transport.records.append(
        {
            "id": 43,
            "name": "mcp-v4-archive-child-01",
            "parent-folder": 42,
            "folder-type": "public",
        }
    )
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport)

    with pytest.raises(FolderArchiveLiveWorkflowError):
        _preview(workflow)
    assert transport.delete_calls == []


@pytest.mark.parametrize("phase", ("preview", "confirm", "execute", "readback", "delete"))
@pytest.mark.parametrize(
    "response",
    (
        {"http_status": 403, "status": "error"},
        {"http_status": 500, "status": "success"},
        {"http_status": 200, "status": "error"},
        {"http_status": 200, "status": None},
        {"http_status": 200, "status": "success", "serial": "FPA-OTHER"},
    ),
)
def test_error_envelopes_never_authorize_or_verify_archive(
    tmp_path: Path, phase: str, response: dict[str, object], monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FakeFolderArchiveTransport()
    claim = tmp_path / "claim.json"
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, claim_path=claim)

    if phase == "preview":
        transport.collection_overrides = response
        with pytest.raises(FolderArchiveLiveWorkflowError):
            _preview(workflow)
    else:
        preview = _preview(workflow)
        if phase == "confirm":
            transport.collection_overrides = response
            with pytest.raises(FolderArchiveLiveWorkflowError):
                workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
        else:
            confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
            authorization = str(confirmation["authorization_ref"])
            if phase == "execute":
                transport.collection_overrides = response
                with pytest.raises(FolderArchiveLiveWorkflowError):
                    workflow.execute(authorization, requester_digest=REQUESTER)
            else:
                if phase == "delete":
                    transport.delete_response = response
                else:
                    original_delete = transport.delete_empty_folder

                    def delete_with_failed_readback(folder_id: int) -> dict[str, object]:
                        result = original_delete(folder_id)
                        transport.collection_overrides = response
                        return result

                    monkeypatch.setattr(transport, "delete_empty_folder", delete_with_failed_readback)
                result = workflow.execute(authorization, requester_digest=REQUESTER)
                assert result["outcome"] == "reconciliation_required"
                assert result["verification"] == "unknown"
                assert transport.delete_calls == [42]
                retained_claim = claim.read_bytes()
                with pytest.raises(FolderArchiveLiveWorkflowError):
                    workflow.execute(authorization, requester_digest=REQUESTER)
                with pytest.raises(FolderArchiveLiveWorkflowError):
                    _preview(FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, claim_path=claim))
                assert transport.delete_calls == [42]
                assert claim.read_bytes() == retained_claim
                return
    assert transport.delete_calls == []
    assert not claim.exists()


@pytest.mark.parametrize("marker", (True, "false", 0, None))
def test_incomplete_or_invalid_collection_marker_cannot_prove_absence(marker: object) -> None:
    transport = FakeFolderArchiveTransport()
    transport.records = []
    transport.collection_overrides = {"limit_reached": marker}
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport)
    with pytest.raises(FolderArchiveLiveWorkflowError):
        workflow._folder_absent(42, "FPA-SYNTHETIC")


@pytest.mark.parametrize("phase", ("preview", "confirm", "execute"))
def test_secret_reference_blocks_archive_before_consuming_attempt(tmp_path: Path, phase: str) -> None:
    transport = FakeFolderArchiveTransport()
    claim = tmp_path / "claim.json"
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, claim_path=claim)
    if phase == "preview":
        operation = lambda: _preview(workflow)
    else:
        preview = _preview(workflow)
        if phase == "confirm":
            operation = lambda: workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
        else:
            confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
            operation = lambda: workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    transport.no_references = False
    with pytest.raises(FolderArchiveLiveWorkflowError):
        operation()
    assert transport.reference_checks[-1] == (42, 7)
    assert transport.delete_calls == []
    assert not claim.exists()


def test_unbound_reference_evidence_cannot_render_empty_folder_preview() -> None:
    transport = FakeFolderArchiveTransport()
    with pytest.raises(FolderArchiveLiveWorkflowError):
        _preview(FolderArchiveLiveWorkflow(transport))
    assert transport.delete_calls == []


def test_native_ok_success_label_supports_preview_and_delete(tmp_path: Path) -> None:
    transport = FakeFolderArchiveTransport()
    transport.collection_overrides = {"status": "OK"}
    transport.delete_response = {"http_status": 200, "status": "OK", "serial": "FPA-SYNTHETIC"}
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, claim_path=tmp_path / "claim.json")
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    assert result["outcome"] == "succeeded"
    assert transport.reference_checks == [(42, 7)] * 3
    assert transport.delete_calls == [42]


@pytest.mark.parametrize("overrides", (
    {"version": "v1.9.1"}, {"build": 30}, {"build": True},
    {"matched_count": None}, {"matched_count": 2},
    {"results": [{"id": 42, "name": "mcp-v4-archive-test", "folder-type": "public"}]},
))
def test_unqualified_or_incomplete_folder_collection_refuses_reference_probe(overrides: dict[str, object]) -> None:
    transport = FakeFolderArchiveTransport()
    transport.collection_overrides = overrides
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport)
    with pytest.raises(FolderArchiveLiveWorkflowError):
        _preview(workflow)
    assert transport.reference_checks == []
    assert transport.delete_calls == []


@pytest.mark.parametrize("change", (
    {"inherit-permission": "enable"},
    {"inherit-permission": None},
    {"group-permission": [{"id": 2, "group-name": [{"name": "synthetic-group"}]}]},
    {"user-permission": []},
    {"user-permission": [{"id": 1, "user-name": ["synthetic-owner", "second-owner"],
                          "folder-permission": "owner", "secret-permission": "owner"}]},
    {"user-permission": [{"id": 1, "user-name": ["synthetic-owner"],
                          "folder-permission": "view", "secret-permission": "owner"}]},
))
def test_archive_refuses_nonisolated_permissions_before_reference_probe(change) -> None:
    transport = FakeFolderArchiveTransport()
    transport.records[0].update(change)
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport)
    with pytest.raises(FolderArchiveLiveWorkflowError):
        _preview(workflow)
    assert transport.reference_checks == []
    assert transport.delete_calls == []


@pytest.mark.parametrize("phase", ("confirm", "execute"))
def test_archive_refuses_owner_drift_without_reserving_delete(tmp_path: Path, phase: str) -> None:
    transport = FakeFolderArchiveTransport()
    claim = tmp_path / "claim.json"
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport, claim_path=claim)
    preview = _preview(workflow)
    ref = str(preview["preview_ref"])
    if phase == "execute":
        ref = str(workflow.confirm(ref, requester_digest=REQUESTER)["authorization_ref"])
    changed = _archive_folder()
    changed["user-permission"][0]["user-name"] = [{"name": "different-owner"}]
    transport.records[0] = changed
    transport.inspect = lambda expected_requester: None
    with pytest.raises(FolderArchiveLiveWorkflowError):
        getattr(workflow, phase)(ref, requester_digest=REQUESTER)
    assert transport.delete_calls == []
    assert not claim.exists()


@pytest.mark.parametrize("bound", (False, True))
def test_archive_requires_actual_api_actor_to_match_owner(bound: bool) -> None:
    transport = FakeFolderArchiveTransport()
    changed = _archive_folder()
    changed["user-permission"][0]["user-name"] = ["different-owner"]
    transport.records[0] = changed
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport,
                                         actor_reader=transport if bound else None)
    with pytest.raises(FolderArchiveLiveWorkflowError):
        _preview(workflow)
    assert transport.reference_checks == []
    assert transport.delete_calls == []


def test_owner_session_preview_is_bound_to_the_private_fixture_name() -> None:
    transport = FakeFolderArchiveTransport()
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport,
        bound_folder_name="mcp-v4-archive-another", delete_authentication="owner_session")
    with pytest.raises(FolderArchiveLiveWorkflowError):
        _preview(workflow)
    assert not transport.delete_calls and not transport.reference_checks
    workflow = FolderArchiveLiveWorkflow(transport, reference_reader=transport, actor_reader=transport,
        bound_folder_name=str(transport.records[0]["name"]), delete_authentication="owner_session")
    preview = _preview(workflow)
    assert preview["Current State"]["delete_authentication"] == "owner_session"
    assert "synthetic-owner" not in str(preview)
