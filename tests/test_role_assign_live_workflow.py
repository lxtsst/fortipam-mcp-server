from __future__ import annotations

import pytest

from fortipam_mcp.role_assign_http_transport import (
    RoleAssignInspection,
    RoleAssignReadback,
)
from fortipam_mcp.role_assign_live_workflow import (
    RoleAssignLiveWorkflow,
    RoleAssignLiveWorkflowError,
)


REQUESTER = "a" * 64
USER = "mcp-v4-user-01"
ROLE = "mcp-v4-role-01"


class FakeRoleAssignTransport:
    def __init__(self) -> None:
        self.user_exists = True
        self.role_exists = True
        self.user_disabled = True
        self.current_role = "Guest"
        self.assign_calls: list[tuple[str, str]] = []
        self.readback = RoleAssignReadback(True, True, True, True)

    def inspect_assignment(self, username: str, role_name: str) -> RoleAssignInspection:
        return RoleAssignInspection(
            user_exists=self.user_exists,
            role_exists=self.role_exists,
            user_disabled=self.user_disabled,
            assignment_matches=self.current_role == role_name,
            state_digest=(
                f"state:{self.user_exists}:{self.role_exists}:{self.user_disabled}:"
                f"{self.current_role}:{role_name}"
            ),
        )

    def assign_and_readback(self, username: str, role_name: str) -> RoleAssignReadback:
        self.assign_calls.append((username, role_name))
        self.current_role = role_name
        return self.readback


def _preview(workflow: RoleAssignLiveWorkflow) -> dict[str, object]:
    return workflow.preview(username=USER, role_name=ROLE, requester_digest=REQUESTER)


@pytest.mark.parametrize("phase", ["confirm", "execute"])
def test_expiry_during_current_state_read_refuses_authorization_and_write(
    phase: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [100]
    transport = FakeRoleAssignTransport()
    workflow = RoleAssignLiveWorkflow(transport, clock=lambda: now[0])
    preview = _preview(workflow)
    reference = str(preview["preview_ref"])
    if phase == "execute":
        confirmation = workflow.confirm(reference, requester_digest=REQUESTER)
        reference = str(confirmation["authorization_ref"])
    expires_at = int(str(preview["expires_at"]))
    now[0] = expires_at - 1
    inspect = transport.inspect_assignment

    def expire_during_query(username: str, role_name: str) -> RoleAssignInspection:
        result = inspect(username, role_name)
        now[0] = expires_at
        return result

    monkeypatch.setattr(transport, "inspect_assignment", expire_during_query)
    with pytest.raises(RoleAssignLiveWorkflowError):
        if phase == "confirm":
            workflow.confirm(reference, requester_digest=REQUESTER)
        else:
            workflow.execute(reference, requester_digest=REQUESTER)

    assert now[0] == expires_at
    assert transport.assign_calls == []


def test_preview_is_live_cpe_for_one_disabled_laboratory_user() -> None:
    workflow = RoleAssignLiveWorkflow(FakeRoleAssignTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_username": USER,
        "requested_role_name": ROLE,
        "laboratory_user_exists": True,
        "laboratory_user_status": "disable",
        "requested_laboratory_role_exists": True,
        "requested_role_already_assigned": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "assign_existing_laboratory_role_to_disabled_laboratory_local_user_via_api",
        "username": USER,
        "role_name": ROLE,
        "user_status_change": False,
        "folder_target_or_secret_changes": False,
    }
    assert preview["Expected State"] == {
        "username_matches": True,
        "role_name_matches": True,
        "laboratory_user_exists": True,
        "laboratory_user_status": "disable",
        "requested_laboratory_role_exists": True,
        "requested_role_assigned": True,
    }
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_assignment() -> None:
    transport = FakeRoleAssignTransport()
    workflow = RoleAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(RoleAssignLiveWorkflowError):
        workflow.execute("role-assign-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.assign_calls == [(USER, ROLE)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["user_status_changed"] is False
    assert result["raw_api_response_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.assign_calls) == 1


def test_confirm_and_execute_reject_prewrite_drift() -> None:
    transport = FakeRoleAssignTransport()
    workflow = RoleAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.current_role = "Other"

    with pytest.raises(RoleAssignLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.assign_calls == []

    transport.current_role = "Guest"
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.user_disabled = False
    with pytest.raises(RoleAssignLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    assert transport.assign_calls == []


def test_failed_readback_requires_reconciliation_without_replay() -> None:
    transport = FakeRoleAssignTransport()
    transport.readback = RoleAssignReadback(True, True, True, False)
    workflow = RoleAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(RoleAssignLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_active_absent_existing_or_unprefixed_inputs() -> None:
    transport = FakeRoleAssignTransport()
    workflow = RoleAssignLiveWorkflow(transport)

    transport.user_disabled = False
    with pytest.raises(RoleAssignLiveWorkflowError):
        _preview(workflow)
    transport.user_disabled = True
    transport.role_exists = False
    with pytest.raises(RoleAssignLiveWorkflowError):
        _preview(workflow)
    transport.role_exists = True
    transport.current_role = ROLE
    with pytest.raises(RoleAssignLiveWorkflowError):
        _preview(workflow)
    with pytest.raises(RoleAssignLiveWorkflowError):
        workflow.preview(username="admin", role_name=ROLE, requester_digest=REQUESTER)
