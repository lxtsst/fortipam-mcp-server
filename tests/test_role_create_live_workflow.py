from __future__ import annotations

import pytest

from fortipam_mcp.role_create_live_workflow import (
    RoleCreateLiveWorkflow,
    RoleCreateLiveWorkflowError,
)
from fortipam_mcp.role_create_ssh_transport import (
    RoleCreateInspection,
    RoleCreateReadback,
)


REQUESTER = "a" * 64
ROLE_NAME = "mcp-v4-role-01"


class FakeRoleCreateTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = RoleCreateReadback(True, True, True, True)

    def inspect(self, role_name: str) -> RoleCreateInspection:
        return RoleCreateInspection(self.exists)

    def create_and_readback(self, role_name: str) -> RoleCreateReadback:
        self.create_calls.append(role_name)
        self.exists = True
        return self.readback


def _preview(workflow: RoleCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(role_name=ROLE_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_assignments_and_credentials() -> None:
    workflow = RoleCreateLiveWorkflow(FakeRoleCreateTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_role_name": ROLE_NAME,
        "role_exists": False,
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_unassigned_guide_example_role",
        "role_name": ROLE_NAME,
        "configuration_profile": "pam_standard_user_guide_profile_v1",
        "user_or_group_assignment_changes": False,
        "folder_target_or_secret_changes": False,
    }
    assert preview["Expected State"] == {
        "role_name_matches": True,
        "role_exists": True,
        "core_access_matches": True,
        "secret_permissions_match": True,
        "system_diagnostics_disabled": True,
        "user_or_group_assignment_changes": False,
    }
    assert preview["device_write_executed"] is False
    assert "password" not in repr(preview).lower()


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeRoleCreateTransport()
    workflow = RoleCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(RoleCreateLiveWorkflowError):
        workflow.execute("role-create-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.create_calls == [ROLE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["role_assignments_changed"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_role_appears_after_preview() -> None:
    transport = FakeRoleCreateTransport()
    workflow = RoleCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(RoleCreateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeRoleCreateTransport()
    workflow = RoleCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(RoleCreateLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeRoleCreateTransport()
    transport.readback = RoleCreateReadback(True, True, False, True)
    workflow = RoleCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(RoleCreateLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_unprefixed_role() -> None:
    transport = FakeRoleCreateTransport()
    workflow = RoleCreateLiveWorkflow(transport)

    with pytest.raises(RoleCreateLiveWorkflowError):
        workflow.preview(role_name="pam_standard_user", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(RoleCreateLiveWorkflowError):
        _preview(workflow)
