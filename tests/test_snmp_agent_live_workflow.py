from __future__ import annotations

import pytest

from fortipam_mcp.snmp_agent_live_workflow import (
    SnmpAgentLiveWorkflow,
    SnmpAgentLiveWorkflowError,
    SnmpAgentRollbackLiveWorkflow,
)
from fortipam_mcp.snmp_agent_ssh_transport import SnmpAgentInspection, SnmpAgentReadback


REQUESTER = "a" * 64


class FakeSnmpAgentTransport:
    def __init__(self) -> None:
        self.current = SnmpAgentInspection("disable")
        self.enable_calls = 0
        self.disable_calls = 0
        self.readback = SnmpAgentReadback("enable")
        self.rollback_readback = SnmpAgentReadback("disable")

    def inspect(self) -> SnmpAgentInspection:
        return self.current

    def enable_and_readback(self) -> SnmpAgentReadback:
        self.enable_calls += 1
        self.current = SnmpAgentInspection("enable")
        return self.readback

    def disable_and_readback(self) -> SnmpAgentReadback:
        self.disable_calls += 1
        self.current = SnmpAgentInspection("disable")
        return self.rollback_readback


def _preview(workflow: SnmpAgentLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_cpe_and_excludes_snmp_visibility_expansion() -> None:
    workflow = SnmpAgentLiveWorkflow(FakeSnmpAgentTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"]["snmp_agent_status"] == "disable"
    proposed = preview["Proposed Changes"]
    assert proposed["snmp_agent_status"] == "enable"
    assert proposed["snmp_community_configuration_changed"] is False
    assert proposed["snmpv3_user_configuration_changed"] is False
    assert proposed["notification_host_configuration_changed"] is False
    assert proposed["interface_administrative_access_changed"] is False
    assert proposed["rest_write_attempted"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_has_one_fixed_transition() -> None:
    transport = FakeSnmpAgentTransport()
    workflow = SnmpAgentLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(SnmpAgentLiveWorkflowError):
        workflow.execute("snmp-agent-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.enable_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["interface_administrative_access_changed"] is False
    assert result["raw_cli_returned"] is False
    assert workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )["idempotent_replay"] is True


def test_prewrite_drift_or_prerequisite_gap_rejects_execution() -> None:
    transport = FakeSnmpAgentTransport()
    workflow = SnmpAgentLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.current = SnmpAgentInspection("enable")

    with pytest.raises(SnmpAgentLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )

    assert transport.enable_calls == 0


def test_failed_readback_requires_reconciliation() -> None:
    transport = FakeSnmpAgentTransport()
    transport.readback = SnmpAgentReadback("disable")
    workflow = SnmpAgentLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(SnmpAgentLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )


def test_rollback_requires_enabled_state_and_restores_disabled() -> None:
    transport = FakeSnmpAgentTransport()
    transport.current = SnmpAgentInspection("enable")
    workflow = SnmpAgentRollbackLiveWorkflow(transport, clock=lambda: 100)

    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["Current State"]["snmp_agent_status"] == "enable"
    assert preview["Proposed Changes"]["snmp_agent_status"] == "disable"
    assert preview["Expected State"]["pre_action_state_restored"] is True
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.disable_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["pre_action_state_restored"] is True
    assert result["raw_cli_returned"] is False


def test_rollback_rejects_drift_and_ambiguous_readback() -> None:
    transport = FakeSnmpAgentTransport()
    transport.current = SnmpAgentInspection("enable")
    workflow = SnmpAgentRollbackLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    transport.current = SnmpAgentInspection("disable")
    with pytest.raises(SnmpAgentLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.disable_calls == 0

    transport = FakeSnmpAgentTransport()
    transport.current = SnmpAgentInspection("enable")
    transport.rollback_readback = SnmpAgentReadback("enable")
    workflow = SnmpAgentRollbackLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert result["outcome"] == "reconciliation_required"
