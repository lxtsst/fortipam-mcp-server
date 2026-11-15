from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
from threading import Barrier

import pytest

from fortipam_mcp.folder_live_workflow import ChildFolderWorkflowError
from fortipam_mcp.isolated_folder_creation_ownership import IsolatedFolderCreationSnapshot
from fortipam_mcp.isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from fortipam_mcp.isolated_folder_m4_adapter import IsolatedFolderBinding
from v4_planning import M4AdapterDenied
from test_isolated_folder_m4_adapter import Transport


SERIAL = "SYNTHETIC_SERIAL"
REQUESTER = "b" * 64


def folder():
    return {"id": 23, "name": "Collector", "folder-type": "public", "parent-folder": 17,
            "inherit-policy": "enable", "inherit-permission": "disable", "inherit-folder-ztna": "enable",
            "secret-policy": "", "ztna-ems-tag": [], "ztna-tags-match-logic": "and", "group-permission": [],
            "user-permission": [{"id": 1, "q_origin_key": 1, "user-name": [{"name": "synthetic-owner",
                "q_origin_key": "synthetic-owner"}], "folder-permission": "owner", "secret-permission": "owner",
                "allowed-launcher-type": "all"}]}


class SnapshotTransport(Transport):
    def __init__(self):
        super().__init__(None)
        self.serial = SERIAL
        self.folder = folder()
        self.snapshot_calls = 0
        self.snapshot_error = False
        self.ack_error = False

    def read_creation_device_serial(self):
        return SERIAL

    def create_isolated_child(self, **kwargs):
        result = super().create_isolated_child(**kwargs)
        return {"http_status": 200, "mkey": True} if self.ack_error else result

    def read_created_folder_snapshot(self, folder_id, *, name, parent_folder_id, owner_name):
        assert self.posts == 1 and folder_id == 23
        assert (name, parent_folder_id, owner_name) == ("Collector", 17, "synthetic-owner")
        self.snapshot_calls += 1
        if self.snapshot_error: raise RuntimeError("synthetic private snapshot failure")
        return IsolatedFolderCreationSnapshot(self.serial, self.folder)


@pytest.fixture
def setup(tmp_path):
    key = tmp_path / "key"
    key.write_bytes(b"a" * 32); key.chmod(0o600)
    database = tmp_path / "workflow.sqlite3"
    transport = SnapshotTransport()
    binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
    def build(selected=binding, serial=SERIAL):
        return IsolatedFolderLiveWorkflow(database, key, transport, binding=selected,
            ownership_expected_serial=serial, clock=lambda: 1000)
    return build, transport, binding, database


def authorize(workflow):
    preview = workflow.preview(folder_name="Collector", parent_folder_id=17, requester_digest=REQUESTER)
    confirmation = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    return preview["preview_ref"], confirmation["authorization_ref"]


def receipts(workflow):
    with workflow._connect() as connection:
        return connection.execute("SELECT * FROM v4_isolated_folder_creation_ownership").fetchall()


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("policy", ["", "synthetic-inactive-policy"])
def test_empty_inactive_policy_complete_snapshot_and_legacy_signed_receipt_compatibility(setup, enabled, policy):
    build, transport, binding, database = setup
    selected = replace(binding, empty_inactive_policy=enabled)
    transport.folder["secret-policy"] = policy
    workflow = build(selected)
    preview, authorization = authorize(workflow)
    result = workflow.execute(authorization, requester_digest=REQUESTER)
    rejected = enabled and policy != ""
    assert result["outcome"] == ("reconciliation_required" if rejected else "succeeded")
    assert transport.posts == transport.snapshot_calls == 1
    if rejected:
        assert receipts(workflow) == []
        with pytest.raises(ChildFolderWorkflowError): build(selected).read_creation_ownership(preview, REQUESTER)
    else:
        stored = [(row["payload"], row["receipt_mac"]) for row in receipts(workflow)]
        owned = build(selected).read_creation_ownership(preview, REQUESTER)
        assert owned.snapshot.folder["secret-policy"] == policy
        assert owned.parameters_digest == selected.parameters_digest
        if not enabled:
            assert selected.parameters_digest == binding.parameters_digest
            assert build(binding).read_creation_ownership(preview, REQUESTER) == owned
        with pytest.raises(ChildFolderWorkflowError):
            build(replace(binding, empty_inactive_policy=not enabled)).read_creation_ownership(preview, REQUESTER)
        assert [(row["payload"], row["receipt_mac"]) for row in receipts(workflow)] == stored
    if rejected:
        with pytest.raises(ChildFolderWorkflowError): build(selected).execute(authorization, requester_digest=REQUESTER)
    else:
        assert build(selected).execute(authorization, requester_digest=REQUESTER)["idempotent_replay"] is True
    assert transport.posts == 1


def test_fresh_verified_creation_commits_private_ownership_atomically_and_survives_restart(setup):
    build, transport, binding, database = setup
    workflow = build()
    preview, authorization = authorize(workflow)
    with pytest.raises(ChildFolderWorkflowError): workflow.read_creation_ownership(preview, REQUESTER)
    result = workflow.execute(authorization, requester_digest=REQUESTER)
    assert result["outcome"] == "succeeded" and transport.posts == transport.snapshot_calls == 1
    assert database.stat().st_mode & 0o777 == 0o600
    owned = build().read_creation_ownership(preview, REQUESTER)
    assert owned.native_folder_id == 23 and owned.serial == SERIAL
    assert owned.parameters_digest == binding.parameters_digest
    assert owned.snapshot.folder == transport.folder
    assert owned.baseline_digest and owned.workflow_record_mac
    with pytest.raises(FrozenInstanceError): owned.serial = "OTHER"
    first = owned.snapshot
    first.folder["user-permission"][0]["allowed-launcher-type"] = "changed"
    transport.folder["user-permission"][0]["allowed-launcher-type"] = "also-changed"
    assert owned.snapshot.folder["user-permission"][0]["allowed-launcher-type"] == "all"
    assert "synthetic-owner" not in repr(owned) and SERIAL not in repr(owned)
    assert "baseline" not in json.dumps(result) and SERIAL not in json.dumps(result)
    replay = build().execute(authorization, requester_digest=REQUESTER)
    assert replay["idempotent_replay"] and transport.posts == transport.snapshot_calls == 1
    assert len(receipts(workflow)) == 1


@pytest.mark.parametrize("fault", (
    "serial", "id", "id_bool", "parent", "owner", "personal", "policy", "permission", "ztna",
    "groups", "multiple_owners", "owner_permission", "launcher_missing", "launcher_array", "launcher_scope",
    "relation_origin", "relation_origin_string", "principal_origin", "unknown", "missing", "nested_unknown", "snapshot",
    "ack", "readback",
))
def test_failed_or_unqualified_creation_never_imports_ownership_or_reposts(setup, fault, caplog):
    build, transport, binding, database = setup
    row = transport.folder
    if fault == "serial": transport.serial = "OTHER_SERIAL"
    elif fault == "id": row["id"] = 24
    elif fault == "id_bool": row["id"] = True
    elif fault == "parent": row["parent-folder"] = 18
    elif fault == "owner": row["user-permission"][0]["user-name"][0]["name"] = "other"
    elif fault == "personal": row["folder-type"] = "personal"
    elif fault == "policy": row["inherit-policy"] = "disable"
    elif fault == "permission": row["inherit-permission"] = "enable"
    elif fault == "ztna": row["inherit-folder-ztna"] = "disable"
    elif fault == "groups": row["group-permission"] = [{}]
    elif fault == "multiple_owners": row["user-permission"].append(deepcopy(row["user-permission"][0]))
    elif fault == "owner_permission": row["user-permission"][0]["secret-permission"] = "view"
    elif fault == "launcher_missing": del row["user-permission"][0]["allowed-launcher-type"]
    elif fault == "launcher_array": row["user-permission"][0]["allowed-launcher-type"] = ["all"]
    elif fault == "launcher_scope": row["user-permission"][0]["allowed-launcher-type"] = "http"
    elif fault == "relation_origin": row["user-permission"][0]["q_origin_key"] = True
    elif fault == "relation_origin_string": row["user-permission"][0]["q_origin_key"] = "1"
    elif fault == "principal_origin": row["user-permission"][0]["user-name"][0]["q_origin_key"] = "other"
    elif fault == "unknown": row["unknown-field"] = "unexpected"
    elif fault == "missing": del row["secret-policy"]
    elif fault == "nested_unknown": row["user-permission"][0]["unexpected"] = True
    elif fault == "snapshot": transport.snapshot_error = True
    elif fault == "ack": transport.ack_error = True
    elif fault == "readback": transport.failure = "acl"
    workflow = build(); preview, authorization = authorize(workflow)
    result = workflow.execute(authorization, requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required" and receipts(workflow) == []
    assert workflow._get_by_preview(preview).state == "reconciliation_required"
    with pytest.raises(ChildFolderWorkflowError): build().read_creation_ownership(preview, REQUESTER)
    with pytest.raises(ChildFolderWorkflowError): build().execute(authorization, requester_digest=REQUESTER)
    assert transport.posts == 1
    assert SERIAL not in caplog.text and "synthetic-owner" not in caplog.text
    if fault in {"ack", "readback"}: assert transport.snapshot_calls == 0


@pytest.mark.parametrize("fault", ("wrong_requester", "wrong_binding", "wrong_serial", "payload", "mac", "record"))
def test_restart_validates_every_signed_binding_and_refuses_tampering_without_network(setup, fault):
    build, transport, binding, database = setup
    workflow = build(); preview, authorization = authorize(workflow)
    workflow.execute(authorization, requester_digest=REQUESTER)
    selected = build()
    requester = REQUESTER
    if fault == "wrong_requester": requester = "c" * 64
    elif fault == "wrong_binding": selected = build(replace(binding, owner_name="other"))
    elif fault == "wrong_serial": selected = build(serial="OTHER_SERIAL")
    else:
        with workflow._connect() as connection:
            if fault == "payload":
                row = receipts(workflow)[0]
                value = json.loads(row["payload"]); value["native_folder_id"] = 24
                connection.execute("UPDATE v4_isolated_folder_creation_ownership SET payload = ?",
                                   (json.dumps(value),))
            elif fault == "mac": connection.execute("UPDATE v4_isolated_folder_creation_ownership SET receipt_mac = 'bad'")
            else: connection.execute("UPDATE v4_child_folder_workflows SET name = 'foreign'")
    with pytest.raises(ChildFolderWorkflowError): selected.read_creation_ownership(preview, requester)
    assert transport.posts == transport.snapshot_calls == 1


def test_completed_legacy_workflow_cannot_be_reobserved_or_upgraded_into_ownership(setup):
    build, transport, binding, database = setup
    legacy = build(serial=None); preview, authorization = authorize(legacy)
    assert legacy.execute(authorization, requester_digest=REQUESTER)["outcome"] == "succeeded"
    assert transport.snapshot_calls == 0
    opted = build()
    with pytest.raises(ChildFolderWorkflowError): opted.read_creation_ownership(preview, REQUESTER)
    assert opted.execute(authorization, requester_digest=REQUESTER)["idempotent_replay"] is True
    assert receipts(opted) == [] and transport.snapshot_calls == 0 and transport.posts == 1


@pytest.mark.parametrize("failure", ("receipt", "completion"))
def test_atomic_receipt_or_completion_failure_rolls_back_and_consumes_attempt(setup, failure):
    build, transport, binding, database = setup
    workflow = build(); preview, authorization = authorize(workflow)
    with workflow._connect() as connection:
        if failure == "receipt":
            connection.execute("CREATE TRIGGER deny_receipt BEFORE INSERT ON v4_isolated_folder_creation_ownership "
                               "BEGIN SELECT RAISE(ABORT, 'synthetic receipt failure'); END")
        else:
            connection.execute("CREATE TRIGGER deny_completion BEFORE UPDATE ON v4_child_folder_workflows "
                               "WHEN NEW.state = 'completed' BEGIN SELECT RAISE(ABORT, 'synthetic completion failure'); END")
    result = workflow.execute(authorization, requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required" and receipts(workflow) == []
    assert workflow._get_by_preview(preview).state == "reconciliation_required"
    with pytest.raises(ChildFolderWorkflowError): build().execute(authorization, requester_digest=REQUESTER)
    assert transport.posts == transport.snapshot_calls == 1


def test_concurrent_reservations_produce_one_post_and_one_signed_receipt(setup, monkeypatch):
    build, transport, binding, database = setup
    workflow = build(); preview, authorization = authorize(workflow)
    barrier = Barrier(2); transition = workflow._transition
    def racing_transition(current, updated):
        barrier.wait(timeout=5)
        return transition(current, updated)
    monkeypatch.setattr(workflow, "_transition", racing_transition)
    def execute(_):
        try: return workflow.execute(authorization, requester_digest=REQUESTER)["outcome"]
        except ChildFolderWorkflowError: return "refused"
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(execute, range(2)))
    assert sorted(outcomes) == ["refused", "succeeded"]
    assert transport.posts == transport.snapshot_calls == 1 and len(receipts(workflow)) == 1


def test_verified_id_is_unavailable_before_successful_exact_postcondition(setup):
    build, transport, binding, database = setup
    workflow = build(); preview, authorization = authorize(workflow)
    plan, adapter = workflow._adapter(workflow._get_by_preview(preview))
    with pytest.raises(Exception): _ = adapter.verified_created_id
    adapter.dispatch(plan)
    with pytest.raises(Exception): _ = adapter.verified_created_id
    assert adapter.read_postcondition(plan) == binding.state_digest(exists=True)
    assert adapter.verified_created_id == 23
    transport.failure = "acl"
    with pytest.raises(Exception): adapter.read_postcondition(plan)
    with pytest.raises(Exception): _ = adapter.verified_created_id


def test_owner_only_database_permissions_are_enforced_before_private_receipt_reads(setup):
    build, transport, binding, database = setup
    workflow = build(); preview, authorization = authorize(workflow)
    workflow.execute(authorization, requester_digest=REQUESTER)
    database.chmod(0o644)
    with pytest.raises(ChildFolderWorkflowError): workflow.read_creation_ownership(preview, REQUESTER)
    assert transport.posts == transport.snapshot_calls == 1
    # An explicit restart secures the owned existing database before opening it.
    assert build().read_creation_ownership(preview, REQUESTER).native_folder_id == 23
    assert database.stat().st_mode & 0o777 == 0o600


def test_receipt_signed_with_workflow_mac_cannot_cross_the_ownership_domain(setup):
    build, transport, binding, database = setup
    workflow = build(); preview, authorization = authorize(workflow)
    workflow.execute(authorization, requester_digest=REQUESTER)
    record = workflow._get_by_preview(preview)
    with workflow._connect() as connection:
        connection.execute("UPDATE v4_isolated_folder_creation_ownership SET receipt_mac = ?", (workflow._mac(record),))
    with pytest.raises(ChildFolderWorkflowError): build().read_creation_ownership(preview, REQUESTER)
    assert transport.posts == transport.snapshot_calls == 1


@pytest.mark.parametrize("phase", ("preview", "confirm", "execution_current", "dispatch_current",
                                  "before_transport", "transport_final_guard"))
def test_serial_mismatch_at_each_prewrite_boundary_denies_post_and_cannot_revive_claim(setup, phase):
    build, transport, binding, database = setup
    workflow = build()
    preview = None
    authorization = None
    if phase != "preview":
        preview = workflow.preview(folder_name="Collector", parent_folder_id=17, requester_digest=REQUESTER)["preview_ref"]
        if phase != "confirm":
            authorization = workflow.confirm(preview, requester_digest=REQUESTER)["authorization_ref"]
    calls = 0
    fail_at = {"preview": 1, "confirm": 1, "execution_current": 1, "dispatch_current": 2,
               "before_transport": 3, "transport_final_guard": 4}[phase]
    def observed_serial():
        nonlocal calls
        calls += 1
        return "OTHER_SERIAL" if calls == fail_at else SERIAL
    transport.read_creation_device_serial = observed_serial
    if phase == "preview":
        with pytest.raises(M4AdapterDenied):
            workflow.preview(folder_name="Collector", parent_folder_id=17, requester_digest=REQUESTER)
        with workflow._connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM v4_child_folder_workflows").fetchone()[0] == 0
    elif phase == "confirm":
        with pytest.raises(ChildFolderWorkflowError): workflow.confirm(preview, requester_digest=REQUESTER)
        assert workflow._get_by_preview(preview).state == "invalidated"
        transport.read_creation_device_serial = lambda: SERIAL
        with pytest.raises(ChildFolderWorkflowError): workflow.confirm(preview, requester_digest=REQUESTER)
    else:
        assert workflow.execute(authorization, requester_digest=REQUESTER)["outcome"] == "reconciliation_required"
        transport.read_creation_device_serial = lambda: SERIAL
        with pytest.raises(ChildFolderWorkflowError): build().execute(authorization, requester_digest=REQUESTER)
    assert calls == fail_at and transport.posts == transport.snapshot_calls == 0
    assert receipts(workflow) == []


def test_slow_transport_final_serial_read_expires_consumed_claim_before_post(setup):
    build, transport, binding, database = setup
    now = [1000]
    workflow = build(); workflow._clock = lambda: now[0]
    preview, authorization = authorize(workflow)
    expires = workflow._get_by_preview(preview).expires_at
    calls = 0
    def slow_serial():
        nonlocal calls
        calls += 1
        if calls == 4: now[0] = expires
        return SERIAL
    transport.read_creation_device_serial = slow_serial
    result = workflow.execute(authorization, requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required" and calls == 4
    assert workflow._get_by_preview(preview).state == "reconciliation_required"
    now[0] = 1000
    transport.read_creation_device_serial = lambda: SERIAL
    with pytest.raises(ChildFolderWorkflowError): build().execute(authorization, requester_digest=REQUESTER)
    assert transport.posts == transport.snapshot_calls == 0 and receipts(workflow) == []


def test_default_scope_never_reads_opt_in_device_observer(setup):
    build, transport, binding, database = setup
    def denied(): raise AssertionError("default scope must not read ownership serial")
    transport.read_creation_device_serial = denied
    workflow = build(serial=None); preview, authorization = authorize(workflow)
    assert workflow.execute(authorization, requester_digest=REQUESTER)["outcome"] == "succeeded"
    assert transport.posts == 1 and transport.snapshot_calls == 0
