from __future__ import annotations

import pytest

from fortipam_mcp.active_launch_live_workflow import (
    ActiveLaunchLiveWorkflow,
    ActiveLaunchLiveWorkflowError,
)
from fortipam_mcp.active_launch_ssh_transport import (
    ActiveLaunchClearReadback,
    ActiveLaunchListing,
)


REQUESTER = "a" * 64
OTHER_REQUESTER = "b" * 64


class FakeActiveLaunchTransport:
    def __init__(self) -> None:
        self.tokens = ["launch-private-001", "launch-private-002"]
        self.recognized = True
        self.clear_calls: list[str] = []
        self.readback = ActiveLaunchClearReadback(True, True, True)

    def list_active_launches(self) -> ActiveLaunchListing:
        return ActiveLaunchListing(self.recognized, tuple(self.tokens))

    def clear_active_launch_and_readback(
        self,
        token_id: str,
    ) -> ActiveLaunchClearReadback:
        self.clear_calls.append(token_id)
        self.tokens.remove(token_id)
        return self.readback


def _observe(workflow: ActiveLaunchLiveWorkflow) -> dict[str, object]:
    return workflow.observe(requester_digest=REQUESTER)


def _first_ref(observation: dict[str, object]) -> str:
    refs = observation["active_launch_refs"]
    assert isinstance(refs, list)
    assert refs and isinstance(refs[0], dict)
    reference = refs[0]["launch_ref"]
    assert isinstance(reference, str)
    return reference


def test_observation_returns_only_opaque_refs_and_no_raw_launch_data() -> None:
    workflow = ActiveLaunchLiveWorkflow(FakeActiveLaunchTransport(), clock=lambda: 100)

    observation = _observe(workflow)

    assert observation["observation"] == "verified"
    assert observation["active_launch_count"] == 2
    assert observation["raw_cli_returned"] is False
    assert observation["wad_token_returned"] is False
    assert observation["identity_target_secret_or_session_data_returned"] is False
    assert "launch-private-001" not in repr(observation)
    assert _first_ref(observation).startswith("active-launch-ref-")


def test_unrecognized_listing_is_not_reported_as_zero_active_launches() -> None:
    transport = FakeActiveLaunchTransport()
    transport.recognized = False
    workflow = ActiveLaunchLiveWorkflow(transport, clock=lambda: 100)

    observation = _observe(workflow)

    assert observation["observation"] == "unavailable_or_unrecognized"
    assert observation["active_launch_count"] is None
    assert observation["active_launch_refs"] == []


def test_disconnect_requires_observation_cpe_confirmation_and_single_token_readback() -> None:
    transport = FakeActiveLaunchTransport()
    workflow = ActiveLaunchLiveWorkflow(transport, clock=lambda: 100)
    observation = _observe(workflow)

    launch_ref = _first_ref(observation)
    preview = workflow.preview_disconnect(launch_ref, requester_digest=REQUESTER)

    assert preview["Current State"]["requested_active_launch_reference"] == launch_ref
    assert preview["Current State"]["selected_active_launch_present"] is True
    assert preview["Proposed Changes"]["selected_active_launch_reference"] == launch_ref
    assert preview["Proposed Changes"]["clear_all_active_launches"] is False
    assert preview["Expected State"]["selected_active_launch_reference_matches"] is True
    assert preview["Expected State"]["single_active_launch_disconnect_command_used"] is True
    assert preview["device_write_executed"] is False
    confirmation = workflow.confirm_disconnect(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    result = workflow.execute_disconnect(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.clear_calls == ["launch-private-001"]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["clear_all_active_launches"] is False
    assert result["wad_token_returned"] is False
    assert workflow.execute_disconnect(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )["idempotent_replay"] is True


def test_disconnect_rejects_drift_and_other_requester_before_clear() -> None:
    transport = FakeActiveLaunchTransport()
    workflow = ActiveLaunchLiveWorkflow(transport, clock=lambda: 100)
    observation = _observe(workflow)
    reference = _first_ref(observation)

    with pytest.raises(ActiveLaunchLiveWorkflowError):
        workflow.preview_disconnect(reference, requester_digest=OTHER_REQUESTER)

    preview = workflow.preview_disconnect(reference, requester_digest=REQUESTER)
    transport.tokens.remove("launch-private-001")
    with pytest.raises(ActiveLaunchLiveWorkflowError):
        workflow.confirm_disconnect(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.clear_calls == []


def test_unverified_clear_requires_reconciliation() -> None:
    transport = FakeActiveLaunchTransport()
    transport.readback = ActiveLaunchClearReadback(True, False)
    workflow = ActiveLaunchLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview_disconnect(_first_ref(_observe(workflow)), requester_digest=REQUESTER)
    confirmation = workflow.confirm_disconnect(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )

    result = workflow.execute_disconnect(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"


@pytest.mark.parametrize("ending", ["succeeded", "unknown", "drift", "expired_before_clear"])
def test_fixed_original_launch_consumption_survives_new_preview_and_restart(tmp_path, ending) -> None:
    from dataclasses import replace
    from fortipam_mcp.active_launch_live_workflow import FixedActiveLaunchBinding, FixedActiveLaunchLiveWorkflow
    from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore

    class NativeTransport(FakeActiveLaunchTransport):
        identity = "c" * 64

        def list_active_launches(self):
            return ActiveLaunchListing(True, tuple(self.tokens), tuple(
                (token, self.identity if token == "launch-private-001" else "d" * 64)
                for token in self.tokens), "e" * 64)

        def clear_active_launch_and_readback(self, token_id, *, expected_identity_digest=None, guard=None):
            assert expected_identity_digest == self.identity
            if ending == "expired_before_clear":
                now[0] = 400
            guard()
            self.clear_calls.append(token_id)
            if ending == "unknown":
                raise TimeoutError("Synthetic lost ACK")
            self.tokens.remove(token_id)
            return ActiveLaunchClearReadback(True, True, True)

    tmp_path.chmod(0o700)
    key = tmp_path / "execution.key"
    key.write_bytes(b"x" * 32); key.chmod(0o600)
    database = tmp_path / "execution.sqlite"
    store = PersistentM4ExecutionStateStore(database, key)
    binding = FixedActiveLaunchBinding("e" * 64, "launch-private-001", "c" * 64,
        "owner", REQUESTER, "f" * 64, 100, 400)
    transport = NativeTransport()
    now = [100]
    workflow = FixedActiveLaunchLiveWorkflow(transport, binding, store, authority_key=b"y" * 32,
        clock=lambda: now[0])
    workflow.validate_principal(REQUESTER, "f" * 64)
    with pytest.raises(ActiveLaunchLiveWorkflowError):
        workflow.validate_principal(REQUESTER, "0" * 64)
    observation = _observe(workflow)
    assert observation["active_launch_count"] == 1
    preview = workflow.preview_disconnect(_first_ref(observation), requester_digest=REQUESTER)
    confirmation = workflow.confirm_disconnect(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert store.claim_count == 0
    if ending == "drift":
        transport.identity = "9" * 64
    result = workflow.execute_disconnect(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    assert result["outcome"] == ("succeeded" if ending == "succeeded" else "reconciliation_required")
    assert result["audit_recorded"] and result["durable_execution_consumed"]
    assert store.claim_count == 1 and len(store.audit_events) == 1
    expected_calls = 0 if ending in ("drift", "expired_before_clear") else 1
    assert len(transport.clear_calls) == expected_calls
    assert "launch-private-002" in transport.tokens
    assert "launch-private-001" not in repr(result)
    with pytest.raises(ActiveLaunchLiveWorkflowError):
        workflow.preview_disconnect(_first_ref(observation), requester_digest=REQUESTER)
    if ending == "expired_before_clear":
        with pytest.raises(ActiveLaunchLiveWorkflowError):
            workflow.execute_disconnect(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    else:
        repeat = workflow.execute_disconnect(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
        assert repeat["idempotent_replay"]
    assert store.claim_count == 1 and len(transport.clear_calls) == expected_calls
    workflow.close()
    reopened = FixedActiveLaunchLiveWorkflow(transport, replace(binding, expires_at=500,
        identity_digest="8" * 64), PersistentM4ExecutionStateStore(database, key),
        authority_key=b"y" * 32, clock=lambda: 100)
    assert reopened._object_digest == workflow._object_digest
    with pytest.raises(ActiveLaunchLiveWorkflowError):
        reopened.preview_disconnect(_first_ref(observation), requester_digest=REQUESTER)
    assert len(transport.clear_calls) == expected_calls
    reopened.close()
