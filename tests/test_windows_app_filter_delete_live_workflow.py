from __future__ import annotations

import pytest

from fortipam_mcp.windows_app_filter_delete_live_workflow import (
    WindowsAppFilterDeleteLiveWorkflow,
    WindowsAppFilterDeleteLiveWorkflowError,
)
from fortipam_mcp.windows_app_filter_http_transport import (
    WindowsAppFilterDeleteInspection,
    WindowsAppFilterDeleteReadback,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.reference_count = 0
        self.target_digest = TARGET_DIGEST
        self.delete_calls: list[str] = []
        self.readback = WindowsAppFilterDeleteReadback(True)

    def inspect_delete_target(self) -> WindowsAppFilterDeleteInspection:
        return WindowsAppFilterDeleteInspection(
            self.exists,
            self.eligible,
            self.reference_count,
            self.target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> WindowsAppFilterDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def _preview(workflow: WindowsAppFilterDeleteLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_fixed_destructive_cpe_without_name_filter_or_exception() -> None:
    preview = _preview(
        WindowsAppFilterDeleteLiveWorkflow(_Transport(), clock=lambda: 100)
    )

    assert preview["Current State"] == {
        "accepted_windows_app_filter_profile_exists": True,
        "exact_fixed_empty_profile_observed": True,
        "secret_reference_count": 0,
        "read_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_unreferenced_windows_app_filter_profile_via_api",
        "windows_app_filter_profile_count_affected": 1,
        "irreversible_after_execution": True,
        "filter_or_exception_changes": False,
        "secret_target_or_policy_association_changes": False,
    }
    assert preview["Expected State"][
        "accepted_windows_app_filter_profile_absent"
    ] is True
    assert preview["device_write_executed"] is False
    assert "mcp-v4-winapp-filter" not in repr(preview)


def test_execute_requires_confirmation_and_is_idempotent_after_success() -> None:
    transport = _Transport()
    workflow = WindowsAppFilterDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "succeeded"
    assert result["windows_app_filter_profile_name_returned"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_target_drift_or_new_reference_is_rejected_before_delete() -> None:
    transport = _Transport()
    workflow = WindowsAppFilterDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.target_digest = "c" * 64
    with pytest.raises(WindowsAppFilterDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    workflow = WindowsAppFilterDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    transport.reference_count = 1
    transport.eligible = False
    with pytest.raises(WindowsAppFilterDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )
    assert transport.delete_calls == []


def test_unverified_absence_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = WindowsAppFilterDeleteReadback(False)
    workflow = WindowsAppFilterDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(WindowsAppFilterDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )


def test_absent_referenced_and_wrong_requester_fail_closed() -> None:
    transport = _Transport()
    workflow = WindowsAppFilterDeleteLiveWorkflow(transport)
    transport.exists = False
    with pytest.raises(WindowsAppFilterDeleteLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    transport.reference_count = 1
    transport.eligible = False
    with pytest.raises(WindowsAppFilterDeleteLiveWorkflowError):
        _preview(workflow)
    transport.reference_count = 0
    transport.eligible = True
    with pytest.raises(WindowsAppFilterDeleteLiveWorkflowError):
        workflow.preview(requester_digest="invalid")
