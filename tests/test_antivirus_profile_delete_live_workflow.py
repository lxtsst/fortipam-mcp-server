from __future__ import annotations

import pytest

from fortipam_mcp.antivirus_profile_delete_http_transport import (
    AntivirusProfileDeleteInspection,
    AntivirusProfileDeleteReadback,
)
from fortipam_mcp.antivirus_profile_delete_live_workflow import (
    AntivirusProfileDeleteLiveWorkflow,
    AntivirusProfileDeleteLiveWorkflowError,
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
        self.readback = AntivirusProfileDeleteReadback(True, True)

    def inspect_delete_target(self) -> AntivirusProfileDeleteInspection:
        return AntivirusProfileDeleteInspection(
            self.exists,
            self.eligible,
            self.reference_count,
            self.target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> AntivirusProfileDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def _preview(workflow: AntivirusProfileDeleteLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_fixed_destructive_cpe_without_name_or_content() -> None:
    preview = _preview(AntivirusProfileDeleteLiveWorkflow(_Transport(), clock=lambda: 100))

    assert preview["Current State"] == {
        "accepted_antivirus_profile_exists": True,
        "exact_fixed_http_ssh_block_profile_observed": True,
        "complete_api_record_digest_matches": True,
        "secret_reference_count": 0,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_unreferenced_antivirus_profile_via_api",
        "antivirus_profile_count_affected": 1,
        "irreversible_after_execution": True,
        "secret_association_changes": False,
        "fortisandbox_or_license_changes": False,
        "protocol_or_scan_mode_changes": False,
    }
    assert preview["Expected State"] == {
        "accepted_antivirus_profile_absent": True,
        "secret_association_changes": False,
        "fortisandbox_or_license_changes": False,
        "protocol_or_scan_mode_changes": False,
        "readback_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["device_write_executed"] is False
    assert "mcp-v4-av-profile" not in repr(preview)


def test_execute_requires_confirmation_and_is_idempotent_only_after_success() -> None:
    transport = _Transport()
    workflow = AntivirusProfileDeleteLiveWorkflow(transport, clock=lambda: 100)
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
    assert result["antivirus_profile_name_returned"] is False
    assert result["profile_content_returned"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_target_drift_or_new_reference_is_rejected_before_delete() -> None:
    transport = _Transport()
    workflow = AntivirusProfileDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.target_digest = "c" * 64
    with pytest.raises(AntivirusProfileDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    workflow = AntivirusProfileDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    transport.reference_count = 1
    transport.eligible = False
    with pytest.raises(AntivirusProfileDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )
    assert transport.delete_calls == []


def test_unverified_dual_absence_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = AntivirusProfileDeleteReadback(True, False)
    workflow = AntivirusProfileDeleteLiveWorkflow(transport, clock=lambda: 100)
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
    with pytest.raises(AntivirusProfileDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )


def test_absent_referenced_expired_and_wrong_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = AntivirusProfileDeleteLiveWorkflow(transport, clock=lambda: now)
    transport.exists = False
    with pytest.raises(AntivirusProfileDeleteLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    transport.reference_count = 1
    transport.eligible = False
    with pytest.raises(AntivirusProfileDeleteLiveWorkflowError):
        _preview(workflow)
    transport.reference_count = 0
    transport.eligible = True
    with pytest.raises(AntivirusProfileDeleteLiveWorkflowError):
        workflow.preview(requester_digest="invalid")

    preview = _preview(workflow)
    now = 701
    with pytest.raises(AntivirusProfileDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
