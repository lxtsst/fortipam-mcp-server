from __future__ import annotations

import pytest

from fortipam_mcp.role_create_ssh_transport import (
    RoleUpdateInspection,
    RoleUpdateReadback,
)
from fortipam_mcp.role_update_live_workflow import (
    RoleUpdateLiveWorkflow,
    RoleUpdateLiveWorkflowError,
)


REQUESTER = "a" * 64
ROLE_NAME = "mcp-v4-role-01"


class FakeRoleUpdateTransport:
    def __init__(self) -> None:
        self.current = RoleUpdateInspection(True, True, True, True, False)
        self.update_calls: list[str] = []
        self.updated = RoleUpdateReadback(True, True, True, True, False)

    def inspect_update(self, role_name: str) -> RoleUpdateInspection:
        return self.current

    def enable_diagnostics_and_readback(self, role_name: str) -> RoleUpdateReadback:
        self.update_calls.append(role_name)
        return self.updated


def _preview(workflow: RoleUpdateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(role_name=ROLE_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_for_only_unassigned_guide_example_role() -> None:
    workflow = RoleUpdateLiveWorkflow(FakeRoleUpdateTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_role_name": ROLE_NAME,
        "role_exists": True,
        "guide_example_permissions_match": True,
        "system_diagnostics_disabled": True,
        "role_assigned_to_any_local_user": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "enable_role_system_diagnostics_via_cli_fallback",
        "role_name": ROLE_NAME,
        "configuration_profile": "pam_standard_user_diagnostics_enable_v1",
        "system_diagnostics": "enable",
        "role_assignment_changes": False,
        "folder_target_secret_or_credential_changes": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["role_name_matches"] is True
    assert preview["Expected State"]["system_diagnostics_enabled"] is True
    assert preview["Expected State"]["role_assigned_to_any_local_user"] is False
    assert preview["device_write_executed"] is False


def test_rest_preview_identifies_its_actual_readback_transport() -> None:
    workflow = RoleUpdateLiveWorkflow(FakeRoleUpdateTransport(), write_transport="rest_api")
    preview = _preview(workflow)
    assert preview["Expected State"]["readback_transport"] == "rest_api"


def test_execute_requires_confirmation_and_performs_one_fixed_update() -> None:
    transport = FakeRoleUpdateTransport()
    workflow = RoleUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(RoleUpdateLiveWorkflowError):
        workflow.execute("role-update-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.update_calls == [ROLE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["role_assignment_changes"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.update_calls) == 1


def test_confirm_and_prewrite_reject_assignment_or_baseline_drift() -> None:
    transport = FakeRoleUpdateTransport()
    workflow = RoleUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.current = RoleUpdateInspection(True, True, True, True, True)

    with pytest.raises(RoleUpdateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.update_calls == []

    transport = FakeRoleUpdateTransport()
    workflow = RoleUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.current = RoleUpdateInspection(True, False, True, True, False)

    with pytest.raises(RoleUpdateLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.update_calls == []


def test_bad_readback_requires_reconciliation_and_out_of_scope_role_is_rejected() -> None:
    transport = FakeRoleUpdateTransport()
    transport.updated = RoleUpdateReadback(True, True, True, False, False)
    workflow = RoleUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"

    with pytest.raises(RoleUpdateLiveWorkflowError):
        workflow.preview(role_name="pam_standard_user", requester_digest=REQUESTER)
