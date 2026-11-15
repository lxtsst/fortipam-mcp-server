from __future__ import annotations

import pytest

from fortipam_mcp.apl_disable_live_workflow import (
    AplDisableLiveWorkflow,
    AplDisableLiveWorkflowError,
)
from fortipam_mcp.apl_ssh_transport import AplDisableInspection, AplReadback


REQUESTER = "a" * 64
RULE = "mcp-v4-apl-01"
USER_GROUP = "mcp-v4-user-group-01"
ROLE = "mcp-v4-role-01"


class FakeAplDisableTransport:
    def __init__(self) -> None:
        self.current = AplDisableInspection(True, True, True, True, True, True)
        self.disable_calls: list[tuple[str, str, str]] = []
        self.readback = AplReadback(True, True, True, True)

    def inspect_disable(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplDisableInspection:
        assert auto_provision_rule_name == RULE
        assert remote_user_group_name == USER_GROUP
        assert role_name == ROLE
        return self.current

    def disable_and_readback(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplReadback:
        self.disable_calls.append(
            (auto_provision_rule_name, remote_user_group_name, role_name)
        )
        return self.readback


def _preview(workflow: AplDisableLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        auto_provision_rule_name=RULE,
        remote_user_group_name=USER_GROUP,
        role_name=ROLE,
        requester_digest=REQUESTER,
    )


def test_preview_requires_exact_enabled_baseline_and_shows_requested_identifiers() -> None:
    workflow = AplDisableLiveWorkflow(FakeAplDisableTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"]["requested_auto_provision_rule_name"] == RULE
    assert preview["Current State"]["requested_remote_user_group_name"] == USER_GROUP
    assert preview["Current State"]["requested_role_name"] == ROLE
    assert preview["Current State"]["status_enabled"] is True
    assert preview["Proposed Changes"]["auto_provision_rule_name"] == RULE
    assert preview["Proposed Changes"]["remote_user_group_name"] == USER_GROUP
    assert preview["Proposed Changes"]["role_name"] == ROLE
    assert preview["Proposed Changes"]["status"] == "disabled"
    assert preview["Proposed Changes"]["auto_provisioning_disabled"] is True
    assert preview["Expected State"]["auto_provision_rule_name_matches"] is True
    assert preview["Expected State"]["status_disabled"] is True
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_disables_one_apl() -> None:
    transport = FakeAplDisableTransport()
    workflow = AplDisableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(AplDisableLiveWorkflowError):
        workflow.execute("apl-disable-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.disable_calls == [(RULE, USER_GROUP, ROLE)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["status"] == "disabled"


def test_confirm_rejects_status_or_dependency_drift() -> None:
    transport = FakeAplDisableTransport()
    workflow = AplDisableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.current = AplDisableInspection(True, False, True, True, True, True)

    with pytest.raises(AplDisableLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.disable_calls == []


def test_bad_readback_requires_reconciliation() -> None:
    transport = FakeAplDisableTransport()
    transport.readback = AplReadback(True, True, False, True)
    workflow = AplDisableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
