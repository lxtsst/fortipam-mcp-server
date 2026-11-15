from __future__ import annotations

from pathlib import Path

import pytest

from fortipam_mcp.local_user_create_live_workflow import (
    BP005_STANDARD_USER_WORKFLOW_CONTRACT,
    LocalUserCreateLiveWorkflow,
    LocalUserCreateLiveWorkflowError,
)
from fortipam_mcp.local_user_create_ssh_transport import (
    LocalUserCreateInspection,
    LocalUserCreateReadback,
)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from v4_planning import M4Outcome


REQUESTER = "a" * 64
NAME = "mcp-v4-user-bp005-standard-synthetic"


class StandardUserTransport:
    requires_durable_execution = True
    workflow_contract_id = BP005_STANDARD_USER_WORKFLOW_CONTRACT

    def __init__(self) -> None:
        self.exists = False
        self.calls = 0

    def inspect(self, username: str) -> LocalUserCreateInspection:
        assert username == NAME
        return LocalUserCreateInspection(self.exists, "b" * 64)

    def create_and_readback(self, username: str) -> LocalUserCreateReadback:
        raise AssertionError("durable transports must reject the unguarded entry")

    def _create_with_dispatch_guard(self, username: str, guard: object) -> LocalUserCreateReadback:
        assert username == NAME and callable(guard)
        guard()
        self.calls += 1
        self.exists = True
        return LocalUserCreateReadback(
            True, True, False, evidence_digest="c" * 64, status_enabled=True,
        )


def _state(root: Path) -> PersistentM4ExecutionStateStore:
    key = root / "execution.key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    return PersistentM4ExecutionStateStore(root / "execution.sqlite3", key)


def test_bp005_preview_is_explicit_standard_role_and_enabled(tmp_path: Path) -> None:
    workflow = LocalUserCreateLiveWorkflow(
        StandardUserTransport(), execution_store=_state(tmp_path),
        workflow_contract=BP005_STANDARD_USER_WORKFLOW_CONTRACT,
    )
    preview = workflow.preview(username=NAME, requester_digest=REQUESTER)
    assert preview["contract"] == BP005_STANDARD_USER_WORKFLOW_CONTRACT
    assert preview["Proposed Changes"] == {
        "operation": "create_enabled_standard_local_user",
        "username": NAME,
        "access_profile": "pam_standard_user",
        "status": "enable",
        "initial_password": "generated_not_returned",
    }
    assert preview["Expected State"] == {
        "username_matches": True,
        "user_exists": True,
        "access_profile_matches": True,
        "status_enabled": True,
        "credentials_returned": False,
    }


def test_bp005_workflow_consumes_durable_claim_and_accepts_only_enabled_readback(tmp_path: Path) -> None:
    transport = StandardUserTransport()
    state = _state(tmp_path)
    workflow = LocalUserCreateLiveWorkflow(
        transport, execution_store=state,
        workflow_contract=BP005_STANDARD_USER_WORKFLOW_CONTRACT,
    )
    preview = workflow.preview(username=NAME, requester_digest=REQUESTER)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    assert result["contract"] == "bp005_standard_user_create_execution_v1"
    assert result["outcome"] == "succeeded"
    assert state.audit_events[-1].outcome is M4Outcome.SUCCEEDED
    assert transport.calls == 1
    assert workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)[
        "idempotent_replay"
    ] is True
    assert transport.calls == 1


def test_enabled_standard_variant_cannot_use_non_durable_or_guest_transport(tmp_path: Path) -> None:
    with pytest.raises(LocalUserCreateLiveWorkflowError):
        LocalUserCreateLiveWorkflow(
            StandardUserTransport(), workflow_contract=BP005_STANDARD_USER_WORKFLOW_CONTRACT,
        )
    class GuestLikeTransport:
        def inspect(self, username: str) -> LocalUserCreateInspection:
            return LocalUserCreateInspection(False)

        def create_and_readback(self, username: str) -> LocalUserCreateReadback:
            return LocalUserCreateReadback(True, True, True)

    with pytest.raises(LocalUserCreateLiveWorkflowError):
        LocalUserCreateLiveWorkflow(
            GuestLikeTransport(), execution_store=_state(tmp_path),
            workflow_contract=BP005_STANDARD_USER_WORKFLOW_CONTRACT,
        )
