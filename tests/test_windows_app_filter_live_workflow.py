from __future__ import annotations

import pytest

from fortipam_mcp.windows_app_filter_http_transport import (
    WindowsAppFilterInspection,
    WindowsAppFilterReadback,
)
from fortipam_mcp.windows_app_filter_live_workflow import (
    WindowsAppFilterCreateLiveWorkflow,
    WindowsAppFilterLiveWorkflowError,
)


REQUESTER = "a" * 64
NAME = "mcp-v4-winapp-filter-01"


class _Transport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = WindowsAppFilterReadback(True, True)

    def inspect(self, name: str) -> WindowsAppFilterInspection:
        assert name == NAME
        return WindowsAppFilterInspection(self.exists)

    def create_and_readback(self, name: str) -> WindowsAppFilterReadback:
        assert name == NAME
        self.create_calls.append(name)
        self.exists = True
        return self.readback


def _preview(workflow: WindowsAppFilterCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(name=NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_profile_filter_values_or_associations() -> None:
    workflow = WindowsAppFilterCreateLiveWorkflow(_Transport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_profile_name": NAME,
        "windows_app_filter_profile_exists": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_minimal_windows_app_filter_profile_via_api",
        "profile_name": NAME,
        "configuration_profile": "empty-profile-name-only-v1",
        "request_body": "fixed_name_only",
        "caller_supplied_filters_or_exceptions": False,
        "secret_target_or_policy_association_changes": False,
    }
    assert preview["Expected State"] == {
        "windows_app_filter_profile_exists": True,
        "profile_name_matches": True,
        "filter_or_exception_content_returned": False,
        "secret_target_or_policy_association_changes": False,
        "readback_transport": "rest_api",
    }
    assert NAME in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_is_idempotent_after_success() -> None:
    transport = _Transport()
    workflow = WindowsAppFilterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(WindowsAppFilterLiveWorkflowError):
        workflow.execute("windows-app-filter-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.create_calls == [NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["profile_name_returned"] is False
    assert result["filter_or_exception_content_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirmation_and_execution_reject_current_state_drift() -> None:
    transport = _Transport()
    workflow = WindowsAppFilterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(WindowsAppFilterLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    transport = _Transport()
    workflow = WindowsAppFilterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(WindowsAppFilterLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.create_calls == []


def test_unverifiable_readback_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = WindowsAppFilterReadback(True, False)
    workflow = WindowsAppFilterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(WindowsAppFilterLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_out_of_scope_or_invalid_requester() -> None:
    transport = _Transport()
    workflow = WindowsAppFilterCreateLiveWorkflow(transport)

    with pytest.raises(WindowsAppFilterLiveWorkflowError):
        workflow.preview(name="global-winapp-filter", requester_digest=REQUESTER)
    with pytest.raises(WindowsAppFilterLiveWorkflowError):
        workflow.preview(name=NAME, requester_digest=object())  # type: ignore[arg-type]
    transport.exists = True
    with pytest.raises(WindowsAppFilterLiveWorkflowError):
        _preview(workflow)
