from __future__ import annotations

import pytest

from fortipam_mcp.local_user_create_live_workflow import (
    LocalUserCreateLiveWorkflow,
    LocalUserCreateLiveWorkflowError,
)
from fortipam_mcp.local_user_create_ssh_transport import (
    LocalUserCreateInspection,
    LocalUserCreateReadback,
)


REQUESTER = "a" * 64


class FakeLocalUserCreateTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = LocalUserCreateReadback(True, True, True)

    def inspect(self, username: str) -> LocalUserCreateInspection:
        return LocalUserCreateInspection(self.exists)

    def create_and_readback(self, username: str) -> LocalUserCreateReadback:
        self.create_calls.append(username)
        self.exists = True
        return self.readback


def _preview(workflow: LocalUserCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(username="mcp-user-create-01", requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_never_returns_password_material() -> None:
    workflow = LocalUserCreateLiveWorkflow(FakeLocalUserCreateTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_username": "mcp-user-create-01",
        "user_exists": False,
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_disabled_local_user",
        "username": "mcp-user-create-01",
        "access_profile": "Guest",
        "status": "disable",
        "initial_password": "generated_not_returned",
    }
    assert preview["Expected State"] == {
        "username_matches": True,
        "user_exists": True,
        "access_profile_matches": True,
        "status_disabled": True,
        "credentials_returned": False,
    }
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeLocalUserCreateTransport()
    workflow = LocalUserCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(LocalUserCreateLiveWorkflowError):
        workflow.execute("local-user-create-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.create_calls == ["mcp-user-create-01"]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["credentials_returned"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_the_user_appears_after_preview() -> None:
    transport = FakeLocalUserCreateTransport()
    workflow = LocalUserCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(LocalUserCreateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


@pytest.mark.parametrize("readback", [
    LocalUserCreateReadback(True, True, False),
    LocalUserCreateReadback(True, True, False, status_enabled=True),
])
def test_create_readback_failure_requires_reconciliation(readback: LocalUserCreateReadback) -> None:
    transport = FakeLocalUserCreateTransport()
    transport.readback = readback
    workflow = LocalUserCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(LocalUserCreateLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_user_and_unsafe_name() -> None:
    transport = FakeLocalUserCreateTransport()
    workflow = LocalUserCreateLiveWorkflow(transport)

    with pytest.raises(LocalUserCreateLiveWorkflowError):
        workflow.preview(username="unsafe name", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(LocalUserCreateLiveWorkflowError):
        _preview(workflow)
