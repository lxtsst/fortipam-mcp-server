from __future__ import annotations

import pytest

from fortipam_mcp.local_user_reset_live_workflow import (
    LocalUserResetLiveWorkflow,
    LocalUserResetLiveWorkflowError,
)
from fortipam_mcp.local_user_reset_ssh_transport import (
    LocalUserResetInspection,
    LocalUserResetReadback,
)


REQUESTER = "a" * 64
USER = "mcp-v4-user-01"


class FakeLocalUserResetTransport:
    def __init__(self) -> None:
        self.inspection = LocalUserResetInspection(True, True, "disable")
        self.reset_calls: list[str] = []
        self.readback = LocalUserResetReadback(True, True, True)

    def inspect(self, username: str) -> LocalUserResetInspection:
        assert username == USER
        return self.inspection

    def reset_and_readback(self, username: str) -> LocalUserResetReadback:
        self.reset_calls.append(username)
        return self.readback


def _preview(workflow: LocalUserResetLiveWorkflow) -> dict[str, object]:
    return workflow.preview(username=USER, requester_digest=REQUESTER)


def test_preview_is_cpe_and_never_contains_the_replacement_password() -> None:
    workflow = LocalUserResetLiveWorkflow(FakeLocalUserResetTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_username": USER,
        "user_exists": True,
        "access_profile": "Guest",
        "status": "disable",
    }
    assert preview["Proposed Changes"] == {
        "operation": "reset_disabled_guest_local_user_password",
        "username": USER,
        "replacement_password": "generated_not_returned",
    }
    assert preview["Expected State"] == {
        "username_matches": True,
        "user_exists": True,
        "access_profile": "Guest",
        "status": "disable",
        "replacement_password_returned": False,
    }
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_reset() -> None:
    transport = FakeLocalUserResetTransport()
    workflow = LocalUserResetLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(LocalUserResetLiveWorkflowError):
        workflow.execute("local-user-reset-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.reset_calls == [USER]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["credentials_returned"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.reset_calls) == 1


def test_confirm_invalidates_when_the_reset_baseline_changes() -> None:
    transport = FakeLocalUserResetTransport()
    workflow = LocalUserResetLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.inspection = LocalUserResetInspection(True, True, "enable")

    with pytest.raises(LocalUserResetLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.reset_calls == []


def test_failed_readback_requires_reconciliation_without_replay() -> None:
    transport = FakeLocalUserResetTransport()
    transport.readback = LocalUserResetReadback(True, True, False)
    workflow = LocalUserResetLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(LocalUserResetLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_unscoped_or_noneligible_user() -> None:
    transport = FakeLocalUserResetTransport()
    workflow = LocalUserResetLiveWorkflow(transport)

    with pytest.raises(LocalUserResetLiveWorkflowError):
        workflow.preview(username="mcp-user-create-01", requester_digest=REQUESTER)
    transport.inspection = LocalUserResetInspection(True, False, "disable")
    with pytest.raises(LocalUserResetLiveWorkflowError):
        _preview(workflow)
