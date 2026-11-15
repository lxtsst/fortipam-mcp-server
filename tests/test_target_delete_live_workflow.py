from __future__ import annotations

import pytest

from fortipam_mcp.target_delete_http_transport import (
    TargetDeleteInspection,
    TargetDeleteReadback,
)
from fortipam_mcp.target_delete_live_workflow import (
    TargetDeleteLiveWorkflow,
    TargetDeleteLiveWorkflowError,
)


REQUESTER = "a" * 64


def _inspection(*, eligible: bool = True) -> TargetDeleteInspection:
    return TargetDeleteInspection(
        exists=True,
        eligible_fixed_target=eligible,
        target_reference_count=0 if eligible else 1,
        target_class_is_other=True,
        classification_tag_absent=True,
        ssh_target_exists=True,
        target_non_class_state_digest="2" * 64,
        target_digest="3" * 64,
    )


class _Transport:
    def __init__(self) -> None:
        self.inspections = [_inspection(), _inspection(), _inspection()]
        self.delete_calls: list[tuple[str, str]] = []

    def inspect_delete_target(self) -> TargetDeleteInspection:
        return self.inspections.pop(0)

    def delete_and_readback(
        self,
        expected_target_digest: str,
        expected_target_non_class_state_digest: str,
    ) -> TargetDeleteReadback:
        self.delete_calls.append(
            (expected_target_digest, expected_target_non_class_state_digest)
        )
        return TargetDeleteReadback(True, True, True, True)


def test_fixed_delete_cpe_is_requester_bound_and_value_minimized() -> None:
    transport = _Transport()
    workflow = TargetDeleteLiveWorkflow(transport, clock=lambda: 100)

    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["Current State"] == {
        "accepted_target_exists": True,
        "complete_api_record_digest_matches": True,
        "target_class_is_other": True,
        "accepted_classification_tag_absent": True,
        "target_reference_count": 0,
        "selectors_returned": False,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert result["outcome"] == "succeeded"
    assert result["target_name_or_configuration_returned"] is False
    assert result["classification_tag_name_returned"] is False
    assert transport.delete_calls == [("3" * 64, "2" * 64)]


def test_preview_rejects_references_and_execute_stops_on_drift() -> None:
    blocked = _Transport()
    blocked.inspections = [_inspection(eligible=False)]
    with pytest.raises(TargetDeleteLiveWorkflowError):
        TargetDeleteLiveWorkflow(blocked).preview(requester_digest=REQUESTER)

    drifted = _Transport()
    drifted.inspections = [_inspection(), _inspection(), _inspection(eligible=False)]
    workflow = TargetDeleteLiveWorkflow(drifted)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    with pytest.raises(TargetDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )
    assert drifted.delete_calls == []
