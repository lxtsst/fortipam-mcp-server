"""Synthetic workflow lifecycle checks; no device or signed-source qualification."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp.isolated_folder_creation_ownership import (
    CONTRACT as CREATION_CONTRACT, IsolatedFolderCreationOwnership, IsolatedFolderCreationSnapshot,
    _canonical, _digest,
)
from fortipam_mcp.isolated_folder_m4_adapter import IsolatedFolderBinding
from fortipam_mcp.isolated_folder_policy_transition_contract import (
    IsolatedFolderPolicyTransitionBinding, IsolatedFolderPolicyTransitionReadback,
    qualify_isolated_folder_policy_transition_inspection,
)
from fortipam_mcp.isolated_folder_policy_transition_live_workflow import (
    IsolatedFolderPolicyTransitionLiveWorkflow, IsolatedFolderPolicyTransitionLiveWorkflowError,
)
from fortipam_mcp.single_secret_folder_membership_source import (
    SingleSecretFolderMembershipBinding, SingleSecretFolderMembershipObservation,
)

REQUESTER = "b" * 64
OTHER = "e" * 64
SERIAL = "SYNTHETIC_SERIAL"
POLICY = "Synthetic Fixed Policy"


def inspection(phase="inherited", *, drift=None, creator=REQUESTER):
    row = {"id": 23, "name": "Synthetic Isolated Folder", "folder-type": "public", "parent-folder": 17,
        "inherit-policy": "enable", "inherit-permission": "disable", "inherit-folder-ztna": "enable",
        "secret-policy": "", "ztna-ems-tag": [], "ztna-tags-match-logic": "and", "group-permission": [],
        "user-permission": [{"id": 1, "q_origin_key": 1, "user-name": [{"name": "synthetic-owner",
            "q_origin_key": "synthetic-owner"}], "folder-permission": "owner", "secret-permission": "owner",
            "allowed-launcher-type": "all"}]}
    if drift == "acl":
        row["user-permission"][0]["id"] = row["user-permission"][0]["q_origin_key"] = 2
    bound = IsolatedFolderPolicyTransitionBinding(
        IsolatedFolderBinding("Synthetic Isolated Folder", 17, "synthetic-owner", "a" * 64),
        SingleSecretFolderMembershipBinding(23, "Synthetic Isolated Folder", 42, "Synthetic Bound Secret",
            SERIAL, "Synthetic Folder Witness", "Synthetic Secret Witness"), POLICY)
    ownership = IsolatedFolderCreationOwnership(CREATION_CONTRACT, "folder-preview-synthetic",
        "folder-authorization-synthetic", creator, bound.creation_binding.parameters_digest, "c" * 64,
        23, SERIAL, _canonical(row), _digest(row))
    membership = SingleSecretFolderMembershipObservation(True, True, True, True,
        "f" * 64 if drift == "membership" else "d" * 64)
    policy = {"name": POLICY, "recording": "disable" if drift == "policy" else "enable",
              "block-clipboard": "disable", "rdp-event-filter": "not-set"}
    current = deepcopy(row)
    if phase == "explicit": current.update({"inherit-policy": "disable", "secret-policy": POLICY})
    return qualify_isolated_folder_policy_transition_inspection(bound, ownership=ownership,
        snapshot=IsolatedFolderCreationSnapshot(SERIAL, current), membership=membership,
        policy_definition=policy, phase=phase)


class Clock:
    value = 1000
    def __call__(self): return self.value


class Transport:
    def __init__(self, clock):
        self.clock = clock
        self.current = inspection()
        self.assign_calls = self.restore_calls = self.writes = 0
        self.inspect_delay = self.dispatch_delay = 0
        self.fail = None

    def inspect_transition(self):
        self.clock.value += self.inspect_delay
        return self.current

    def inspect_owned_restore(self): return self.inspect_transition()

    def transition_and_readback(self, expected_state_digest, *, expires_at, clock):
        self.assign_calls += 1
        return self._dispatch(expected_state_digest, expires_at, clock, "explicit")

    def restore_and_readback(self, expected_state_digest, *, expires_at, clock):
        self.restore_calls += 1
        return self._dispatch(expected_state_digest, expires_at, clock, "inherited")

    def _dispatch(self, digest, expiry, clock, phase):
        assert digest == self.current.state_digest
        self.clock.value += self.dispatch_delay
        if clock() >= expiry: raise RuntimeError("synthetic final expiry")
        if self.fail == "raise": raise RuntimeError("synthetic private upstream detail")
        self.writes += 1
        self.current = inspection(phase)
        after = self.current
        if self.fail in {"acl", "membership", "policy"}: after = inspection(phase, drift=self.fail)
        if self.fail == "creator": after = inspection(phase, creator=OTHER)
        if self.fail == "phase": after = inspection("inherited" if phase == "explicit" else "explicit")
        if self.fail == "missing": after = None
        return IsolatedFolderPolicyTransitionReadback(self.fail != "ack", self.fail != "logout", after)


@pytest.fixture
def setup():
    clock = Clock()
    transport = Transport(clock)
    workflow = IsolatedFolderPolicyTransitionLiveWorkflow(transport, execution_enabled=True, clock=clock)
    return workflow, transport, clock


def authorize(workflow, operation="assign"):
    method = workflow.preview_transition if operation == "assign" else workflow.preview_restore
    preview = method(requester_digest=REQUESTER)
    confirmed = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    return preview, confirmed["authorization_ref"]


def assign(workflow):
    _, reference = authorize(workflow)
    return workflow.execute(reference, requester_digest=REQUESTER)


def test_default_closed_and_constructor_requires_exact_transport_methods():
    clock = Clock()
    transport = Transport(clock)
    workflow = IsolatedFolderPolicyTransitionLiveWorkflow(transport, clock=clock)
    _, reference = authorize(workflow)
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError):
        workflow.execute(reference, requester_digest=REQUESTER)
    assert transport.assign_calls == transport.writes == 0
    for selected in (object(), replace(inspection(), creator_digest=OTHER)):
        with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError):
            IsolatedFolderPolicyTransitionLiveWorkflow(selected)
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError):
        IsolatedFolderPolicyTransitionLiveWorkflow(transport, execution_enabled=1)


def test_separately_confirmed_assign_restore_with_safe_results_and_cached_once(setup):
    workflow, transport, clock = setup
    baseline = transport.current.state_digest
    preview, reference = authorize(workflow)
    assert preview["expires_at"] == 1600 and transport.writes == 0
    assigned = workflow.execute(reference, requester_digest=REQUESTER)
    assert assigned["outcome"] == "succeeded" and assigned["verification"] == "verified"
    assert transport.current.phase == "explicit"
    restored_preview, restored_ref = authorize(workflow, "restore")
    assert restored_preview["preview_ref"] != preview["preview_ref"]
    restored = workflow.execute(restored_ref, requester_digest=REQUESTER)
    assert restored["outcome"] == "succeeded" and transport.current.state_digest == baseline
    for ref in (reference, restored_ref):
        assert workflow.execute(ref, requester_digest=REQUESTER)["idempotent_replay"] is True
    assert transport.assign_calls == transport.restore_calls == 1 and transport.writes == 2
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError):
        workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    assert workflow.execute(reference, requester_digest=REQUESTER)["outcome"] == "succeeded"
    for method in (workflow.preview_transition, workflow.preview_restore):
        with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): method(requester_digest=REQUESTER)
    for result in (preview, assigned, restored_preview, restored):
        public = json.dumps(result)
        for private in (SERIAL, POLICY, "Synthetic Isolated Folder", "synthetic-owner", "Synthetic Bound Secret",
                        "current_folder_json", "native_body_json", "creation_ownership_json"):
            assert private not in public


@pytest.mark.parametrize("operation", ("assign", "restore"))
@pytest.mark.parametrize("stage", ("confirm", "execute"))
@pytest.mark.parametrize("drift", ("acl", "membership", "policy"))
def test_exact_digest_drift_invalidates_refs_permanently(setup, operation, stage, drift):
    workflow, transport, clock = setup
    if operation == "restore": assert assign(workflow)["outcome"] == "succeeded"
    method = workflow.preview_transition if operation == "assign" else workflow.preview_restore
    preview = method(requester_digest=REQUESTER)
    ref = None
    if stage == "execute": ref = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)["authorization_ref"]
    original = transport.current
    transport.current = inspection(original.phase, drift=drift)
    calls = transport.assign_calls + transport.restore_calls
    if stage == "confirm":
        with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError):
            workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    else:
        assert workflow.execute(ref, requester_digest=REQUESTER)["outcome"] == "not_executed"
    transport.current = original
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError):
        workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    if ref: assert workflow.execute(ref, requester_digest=REQUESTER)["outcome"] == "not_executed"
    assert transport.assign_calls + transport.restore_calls == calls


@pytest.mark.parametrize("stage", ("preview", "confirm", "execute", "final_guard"))
def test_slow_source_or_final_guard_expiry_cannot_write(setup, stage):
    workflow, transport, clock = setup
    if stage == "preview":
        transport.inspect_delay = 600
        with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): workflow.preview_transition(requester_digest=REQUESTER)
        assert transport.assign_calls == transport.writes == 0
        return
    preview = workflow.preview_transition(requester_digest=REQUESTER)
    if stage == "confirm":
        transport.inspect_delay = 600
        with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError):
            workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
        assert transport.assign_calls == transport.writes == 0
        return
    reference = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)["authorization_ref"]
    if stage == "execute": transport.inspect_delay = 600
    else: transport.dispatch_delay = 600
    result = workflow.execute(reference, requester_digest=REQUESTER)
    assert result["outcome"] == ("not_executed" if stage == "execute" else "reconciliation_required")
    assert transport.writes == 0
    clock.value = 1000
    assert workflow.execute(reference, requester_digest=REQUESTER)["idempotent_replay"]
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): workflow.preview_restore(requester_digest=REQUESTER)


@pytest.mark.parametrize("stage", ("confirm", "execute", "final_guard"))
def test_monotonic_clock_rollback_cannot_authorize_or_dispatch(setup, stage):
    workflow, transport, clock = setup
    preview = workflow.preview_transition(requester_digest=REQUESTER)
    if stage == "confirm":
        clock.value = 999
        with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError):
            workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    else:
        ref = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)["authorization_ref"]
        if stage == "execute": clock.value = 999
        else: transport.dispatch_delay = -1
        result = workflow.execute(ref, requester_digest=REQUESTER)
        assert result["outcome"] == ("not_executed" if stage == "execute" else "reconciliation_required")
    assert transport.writes == 0


@pytest.mark.parametrize("fault", ("raise", "ack", "logout", "missing", "acl", "membership", "policy", "creator", "phase"))
def test_uncertain_or_unqualified_readback_consumes_attempt_without_restore_ownership(setup, fault, caplog):
    workflow, transport, clock = setup
    preview, ref = authorize(workflow)
    transport.fail = fault
    result = workflow.execute(ref, requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required" and result["device_write_may_have_occurred"]
    transport.fail = None
    assert workflow.execute(ref, requester_digest=REQUESTER)["idempotent_replay"]
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): workflow.preview_transition(requester_digest=REQUESTER)
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): workflow.preview_restore(requester_digest=REQUESTER)
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    assert workflow.execute(ref, requester_digest=REQUESTER)["outcome"] == "reconciliation_required"
    assert transport.assign_calls == 1 and not caplog.records


def test_restore_uncertainty_is_consumed_and_restart_cannot_import_assignment(setup):
    workflow, transport, clock = setup
    assert assign(workflow)["outcome"] == "succeeded"
    restarted = IsolatedFolderPolicyTransitionLiveWorkflow(transport, execution_enabled=True, clock=clock)
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): restarted.preview_restore(requester_digest=REQUESTER)
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): restarted.preview_transition(requester_digest=REQUESTER)
    _, reference = authorize(workflow, "restore")
    transport.fail = "logout"
    assert workflow.execute(reference, requester_digest=REQUESTER)["outcome"] == "reconciliation_required"
    transport.fail = None
    assert workflow.execute(reference, requester_digest=REQUESTER)["idempotent_replay"]
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): workflow.preview_restore(requester_digest=REQUESTER)
    assert transport.restore_calls == 1


def test_creator_and_requester_refs_never_cross_authority(setup):
    workflow, transport, clock = setup
    transport.current = inspection(creator=OTHER)
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): workflow.preview_transition(requester_digest=REQUESTER)
    transport.current = inspection()
    preview, ref = authorize(workflow)
    for request in (OTHER, "malformed"):
        with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): workflow.confirm(preview["preview_ref"], requester_digest=request)
        with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): workflow.execute(ref, requester_digest=request)
    assert transport.writes == 0
    assert workflow.execute(ref, requester_digest=REQUESTER)["outcome"] == "succeeded"
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError): workflow.preview_restore(requester_digest=OTHER)


@pytest.mark.parametrize("stage", ("confirm", "execute"))
def test_fresh_creator_change_invalidates_without_write_or_ref_revival(setup, stage):
    workflow, transport, clock = setup
    preview = workflow.preview_transition(requester_digest=REQUESTER)
    reference = None
    if stage == "execute":
        reference = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)["authorization_ref"]
    transport.current = inspection(creator=OTHER)
    if stage == "confirm":
        with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError):
            workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    else:
        assert workflow.execute(reference, requester_digest=REQUESTER)["outcome"] == "not_executed"
    transport.current = inspection()
    with pytest.raises(IsolatedFolderPolicyTransitionLiveWorkflowError):
        workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    if reference: assert workflow.execute(reference, requester_digest=REQUESTER)["outcome"] == "not_executed"
    assert transport.assign_calls == transport.writes == 0


def test_concurrent_authorizations_enter_transport_only_once(setup):
    workflow, transport, clock = setup
    _, first = authorize(workflow)
    _, second = authorize(workflow)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda ref: workflow.execute(ref, requester_digest=REQUESTER), (first, second)))
    assert sorted(result["outcome"] for result in results) == ["not_executed", "succeeded"]
    assert transport.assign_calls == transport.writes == 1
