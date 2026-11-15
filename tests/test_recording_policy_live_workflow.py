from __future__ import annotations

import pytest

from fortipam_mcp.recording_policy_http_transport import (
    RecordingPolicyInspection,
    RecordingPolicyReadback,
)
from fortipam_mcp.recording_policy_live_workflow import (
    RecordingPolicyEnableLiveWorkflow,
    RecordingPolicyLiveWorkflowError,
)


REQUESTER = "a" * 64
NAME = "mcp-v4-secret-policy-recording-01"


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.recording_enabled = False
        self.enable_calls: list[str] = []
        self.readback = RecordingPolicyReadback(True, True)

    def inspect(self, policy_name: str) -> RecordingPolicyInspection:
        assert policy_name == NAME
        state = "enable" if self.recording_enabled else "not-set"
        return RecordingPolicyInspection(
            self.exists,
            self.recording_enabled,
            (state * 64)[:64],
        )

    def enable_and_readback(self, policy_name: str) -> RecordingPolicyReadback:
        assert policy_name == NAME
        self.enable_calls.append(policy_name)
        self.recording_enabled = True
        return self.readback


def _preview(workflow: RecordingPolicyEnableLiveWorkflow) -> dict[str, object]:
    return workflow.preview(policy_name=NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_includes_the_selected_non_secret_policy_name() -> None:
    workflow = RecordingPolicyEnableLiveWorkflow(_Transport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "secret_policy_name": NAME,
        "secret_policy_exists": True,
        "recording_enabled": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "enable_session_recording_on_existing_secret_policy_via_api",
        "secret_policy_name": NAME,
        "recording": "enable",
        "other_policy_fields_modified": False,
        "folder_or_secret_association_changes": False,
    }
    assert preview["Expected State"] == {
        "secret_policy_name": NAME,
        "secret_policy_exists": True,
        "recording_enabled": True,
        "other_policy_fields_modified": False,
        "folder_or_secret_association_changes": False,
        "readback_transport": "rest_api",
    }
    assert NAME in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_is_idempotent_after_success() -> None:
    transport = _Transport()
    workflow = RecordingPolicyEnableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(RecordingPolicyLiveWorkflowError):
        workflow.execute("recording-policy-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.enable_calls == [NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["policy_name_returned"] is False
    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.enable_calls) == 1


def test_confirmation_and_execution_reject_recording_state_drift() -> None:
    transport = _Transport()
    workflow = RecordingPolicyEnableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.recording_enabled = True

    with pytest.raises(RecordingPolicyLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    transport = _Transport()
    workflow = RecordingPolicyEnableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.recording_enabled = True
    with pytest.raises(RecordingPolicyLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.enable_calls == []


def test_unverifiable_readback_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = RecordingPolicyReadback(True, False)
    workflow = RecordingPolicyEnableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(RecordingPolicyLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_enabled_absent_or_invalid_policy() -> None:
    transport = _Transport()
    workflow = RecordingPolicyEnableLiveWorkflow(transport)

    with pytest.raises(RecordingPolicyLiveWorkflowError):
        workflow.preview(policy_name="default", requester_digest=REQUESTER)
    transport.recording_enabled = True
    with pytest.raises(RecordingPolicyLiveWorkflowError):
        _preview(workflow)
    transport.recording_enabled = False
    transport.exists = False
    with pytest.raises(RecordingPolicyLiveWorkflowError):
        _preview(workflow)
