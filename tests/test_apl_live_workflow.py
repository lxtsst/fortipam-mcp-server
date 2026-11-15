from __future__ import annotations

import pytest

from fortipam_mcp.apl_live_workflow import AplCreateLiveWorkflow, AplLiveWorkflowError
from fortipam_mcp.apl_ssh_transport import AplInspection, AplReadback


REQUESTER = "a" * 64
RULE = "mcp-v4-apl-01"
USER_GROUP = "mcp-v4-user-group-01"
ROLE = "mcp-v4-role-01"


class FakeAplTransport:
    def __init__(self) -> None:
        self.current = AplInspection(False, True, True)
        self.change_calls: list[tuple[str, str, str]] = []
        self.readback = AplReadback(True, True, True, True)

    def inspect(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplInspection:
        assert auto_provision_rule_name == RULE
        assert remote_user_group_name == USER_GROUP
        assert role_name == ROLE
        return self.current

    def create_disabled_and_readback(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplReadback:
        self.change_calls.append(
            (auto_provision_rule_name, remote_user_group_name, role_name)
        )
        return self.readback


def _preview(workflow: AplCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        auto_provision_rule_name=RULE,
        remote_user_group_name=USER_GROUP,
        role_name=ROLE,
        requester_digest=REQUESTER,
    )


def test_preview_requires_absent_rule_existing_dependencies_and_shows_requested_identifiers() -> None:
    workflow = AplCreateLiveWorkflow(FakeAplTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_auto_provision_rule_name": RULE,
        "requested_remote_user_group_name": USER_GROUP,
        "requested_role_name": ROLE,
        "auto_provision_rule_exists": False,
        "existing_v4_remote_user_group_exists": True,
        "existing_v4_role_exists": True,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"]["auto_provision_rule_name"] == RULE
    assert preview["Proposed Changes"]["remote_user_group_name"] == USER_GROUP
    assert preview["Proposed Changes"]["role_name"] == ROLE
    assert preview["Proposed Changes"]["status"] == "disabled"
    assert preview["Proposed Changes"]["user_auto_provisioning_enabled"] is False
    assert preview["Expected State"]["auto_provision_rule_name_matches"] is True
    assert preview["Expected State"]["status_disabled"] is True
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_performs_one_disabled_apl_create() -> None:
    transport = FakeAplTransport()
    workflow = AplCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(AplLiveWorkflowError):
        workflow.execute("apl-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.change_calls == [(RULE, USER_GROUP, ROLE)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["status"] == "disabled"
    assert result["user_auto_provisioning_enabled"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.change_calls) == 1


def test_confirm_and_execute_reject_dependency_or_rule_drift() -> None:
    transport = FakeAplTransport()
    workflow = AplCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.current = AplInspection(True, True, True)

    with pytest.raises(AplLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.change_calls == []


def test_bad_readback_requires_reconciliation() -> None:
    transport = FakeAplTransport()
    transport.readback = AplReadback(True, False, True, True)
    workflow = AplCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"


def test_preview_rejects_nonv4_inputs_or_absent_dependency() -> None:
    transport = FakeAplTransport()
    workflow = AplCreateLiveWorkflow(transport)

    with pytest.raises(AplLiveWorkflowError):
        workflow.preview(
            auto_provision_rule_name="rule",
            remote_user_group_name=USER_GROUP,
            role_name=ROLE,
            requester_digest=REQUESTER,
        )
    with pytest.raises(AplLiveWorkflowError):
        workflow.preview(
            auto_provision_rule_name=RULE,
            remote_user_group_name=USER_GROUP,
            role_name="pam_standard_user",
            requester_digest=REQUESTER,
        )
    transport.current = AplInspection(False, False, True)
    with pytest.raises(AplLiveWorkflowError):
        _preview(workflow)
