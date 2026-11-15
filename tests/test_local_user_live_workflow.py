from __future__ import annotations

import pytest

from fortipam_mcp.local_user_live_workflow import (
    LocalUserDisableLiveWorkflow,
    LocalUserLiveWorkflowError,
)
from fortipam_mcp.local_user_ssh_transport import LocalUserInspection, LocalUserReadback


REQUESTER = "a" * 64


class FakeLocalUserTransport:
    def __init__(self) -> None:
        self.exists = True
        self.status = "enable"
        self.disable_calls: list[str] = []
        self.readback = LocalUserReadback(True, True)

    def inspect(self, username: str) -> LocalUserInspection:
        return LocalUserInspection(self.exists, self.status)  # type: ignore[arg-type]

    def disable_and_readback(self, username: str) -> LocalUserReadback:
        self.disable_calls.append(username)
        self.status = "disable"
        return self.readback


def _preview(workflow: LocalUserDisableLiveWorkflow) -> dict[str, object]:
    return workflow.preview(username="mcp-user-01", requester_digest=REQUESTER)


def test_preview_is_live_cpe_for_an_enabled_local_user() -> None:
    workflow = LocalUserDisableLiveWorkflow(FakeLocalUserTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_username": "mcp-user-01",
        "user_exists": True,
        "status": "enable",
    }
    assert preview["Proposed Changes"] == {
        "operation": "disable_local_user",
        "username": "mcp-user-01",
    }
    assert preview["Expected State"] == {
        "username_matches": True,
        "user_exists": True,
        "status": "disable",
    }
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_disable() -> None:
    transport = FakeLocalUserTransport()
    workflow = LocalUserDisableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(LocalUserLiveWorkflowError):
        workflow.execute("local-user-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.disable_calls == ["mcp-user-01"]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["credentials_returned"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.disable_calls) == 1


def test_confirm_invalidates_when_live_status_changes() -> None:
    transport = FakeLocalUserTransport()
    workflow = LocalUserDisableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.status = "disable"

    with pytest.raises(LocalUserLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.disable_calls == []


def test_disable_readback_failure_requires_reconciliation_without_replay() -> None:
    transport = FakeLocalUserTransport()
    transport.readback = LocalUserReadback(True, False)
    workflow = LocalUserDisableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(LocalUserLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_requires_an_existing_enabled_safe_name() -> None:
    transport = FakeLocalUserTransport()
    workflow = LocalUserDisableLiveWorkflow(transport)

    with pytest.raises(LocalUserLiveWorkflowError):
        workflow.preview(username="unsafe name", requester_digest=REQUESTER)
    transport.exists = False
    with pytest.raises(LocalUserLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    transport.status = "disable"
    with pytest.raises(LocalUserLiveWorkflowError):
        _preview(workflow)
