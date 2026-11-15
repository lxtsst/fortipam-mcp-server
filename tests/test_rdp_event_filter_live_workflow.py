from __future__ import annotations

import pytest

from fortipam_mcp.rdp_event_filter_live_workflow import (
    RdpEventFilterLiveWorkflow,
    RdpEventFilterLiveWorkflowError,
)
from fortipam_mcp.rdp_event_filter_ssh_transport import (
    RdpEventFilterInspection,
    RdpEventFilterReadback,
)


REQUESTER = "a" * 64
PROFILE_NAME = "mcp-v4-rdp-event-filter-01"


class FakeRdpEventFilterTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = RdpEventFilterReadback(True, True, True, True)

    def inspect(self, profile_name: str) -> RdpEventFilterInspection:
        return RdpEventFilterInspection(self.exists)

    def create_and_readback(self, profile_name: str) -> RdpEventFilterReadback:
        self.create_calls.append(profile_name)
        self.exists = True
        return self.readback


def _preview(workflow: RdpEventFilterLiveWorkflow) -> dict[str, object]:
    return workflow.preview(profile_name=PROFILE_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_association_target_and_winrm_changes() -> None:
    workflow = RdpEventFilterLiveWorkflow(
        FakeRdpEventFilterTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_profile_name": PROFILE_NAME,
        "profile_name_exists": False,
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_rdp_event_filter_profile",
        "profile_name": PROFILE_NAME,
        "configuration_profile": "all_event_categories_enabled_v1",
        "process_log": "enable",
        "filesystem_log": "enable",
        "user_management": "enable",
        "secret_or_policy_association_changes": False,
        "target_or_winrm_changes": False,
    }
    assert preview["Expected State"]["profile_name_matches"] is True
    assert preview["Expected State"]["user_management_enabled"] is True
    assert preview["device_write_executed"] is False
    assert "password" not in repr(preview).lower()


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeRdpEventFilterTransport()
    workflow = RdpEventFilterLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(RdpEventFilterLiveWorkflowError):
        workflow.execute("rdp-event-filter-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [PROFILE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["secret_or_policy_association_changes"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_profile_appears_after_preview() -> None:
    transport = FakeRdpEventFilterTransport()
    workflow = RdpEventFilterLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(RdpEventFilterLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeRdpEventFilterTransport()
    workflow = RdpEventFilterLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(RdpEventFilterLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeRdpEventFilterTransport()
    transport.readback = RdpEventFilterReadback(True, True, False, True)
    workflow = RdpEventFilterLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(RdpEventFilterLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeRdpEventFilterTransport()
    workflow = RdpEventFilterLiveWorkflow(transport)

    with pytest.raises(RdpEventFilterLiveWorkflowError):
        workflow.preview(profile_name="event-filter", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(RdpEventFilterLiveWorkflowError):
        _preview(workflow)
