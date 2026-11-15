from __future__ import annotations

import pytest

from fortipam_mcp.ssh_filter_live_workflow import (
    SshFilterCreateLiveWorkflow,
    SshFilterLiveWorkflowError,
)
from fortipam_mcp.ssh_filter_ssh_transport import SshFilterInspection, SshFilterReadback


REQUESTER = "a" * 64
PROFILE_NAME = "mcp-v4-ssh-filter-01"


class FakeSshFilterTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = SshFilterReadback(True, True, True, True, True)

    def inspect(self, profile_name: str) -> SshFilterInspection:
        return SshFilterInspection(self.exists)

    def create_and_readback(self, profile_name: str) -> SshFilterReadback:
        self.create_calls.append(profile_name)
        self.exists = True
        return self.readback


def _preview(workflow: SshFilterCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(profile_name=PROFILE_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_association_changes() -> None:
    workflow = SshFilterCreateLiveWorkflow(FakeSshFilterTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_profile_name": PROFILE_NAME,
        "profile_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_ssh_filter_profile_via_cli_fallback",
        "profile_name": PROFILE_NAME,
        "configuration_profile": "deny-rm-with-log-and-alert-v1",
        "mode": "deny",
        "shell_pattern": "rm",
        "pattern_log": "enable",
        "pattern_alert": "enable",
        "secret_or_policy_association_changes": False,
        "target_or_session_changes": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["profile_name_matches"] is True
    assert preview["Expected State"]["pattern_alert_enabled"] is True
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeSshFilterTransport()
    workflow = SshFilterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(SshFilterLiveWorkflowError):
        workflow.execute("ssh-filter-authorized-missing", requester_digest=REQUESTER)

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
    transport = FakeSshFilterTransport()
    workflow = SshFilterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(SshFilterLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeSshFilterTransport()
    workflow = SshFilterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(SshFilterLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeSshFilterTransport()
    transport.readback = SshFilterReadback(True, False, True, True, True)
    workflow = SshFilterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(SshFilterLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeSshFilterTransport()
    workflow = SshFilterCreateLiveWorkflow(transport)

    with pytest.raises(SshFilterLiveWorkflowError):
        workflow.preview(profile_name="default", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(SshFilterLiveWorkflowError):
        _preview(workflow)
