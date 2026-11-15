from __future__ import annotations

import pytest

from fortipam_mcp.target_live_workflow import (
    TargetLiveWorkflow,
    TargetLiveWorkflowError,
)
from fortipam_mcp.target_http_transport import TargetHttpTransportError
from fortipam_mcp.target_ssh_transport import TargetInspection, TargetReadback


REQUESTER = "a" * 64


class FakeTargetTransport:
    def __init__(self) -> None:
        self.exists = False
        self.product_version = "7.0.0"
        self.product_build = 29
        self.create_calls: list[tuple[str, str]] = []
        self.readback = TargetReadback(True, True, True, True, True, True, True)

    def inspect(self, target_name: str) -> TargetInspection:
        return TargetInspection(self.exists, self.product_version, self.product_build)

    def create_and_readback(
        self,
        target_name: str,
        address: str,
        *,
        expected_product_version: str,
        expected_product_build: int,
    ) -> TargetReadback:
        assert (expected_product_version, expected_product_build) == ("7.0.0", 29)
        self.create_calls.append((target_name, address))
        self.exists = True
        return self.readback


class RejectedTargetTransport(FakeTargetTransport):
    def create_and_readback(
        self,
        target_name: str,
        address: str,
        *,
        expected_product_version: str,
        expected_product_build: int,
    ) -> TargetReadback:
        assert (expected_product_version, expected_product_build) == ("7.0.0", 29)
        self.create_calls.append((target_name, address))
        raise TargetHttpTransportError(
            failure_stage="target_create_post",
            http_status=500,
            product_error_code=-15,
            product_status="error",
            product_error_class="duplicate_target_address",
        )


def _preview(workflow: TargetLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        target_name="mcp-target-01",
        address="192.0.2.10",
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_shows_requested_non_secret_target_values() -> None:
    workflow = TargetLiveWorkflow(FakeTargetTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_target_name": "mcp-target-01",
        "requested_target_address": "192.0.2.10",
        "target_exists": False,
        "write_transport": "rest_api",
        "product_version": "7.0.0",
        "product_build": 29,
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_target_via_api",
        "request_projection": "fortipam_7_0_0_build_29_target_frontend_unparse",
        "product_version": "7.0.0",
        "product_build": 29,
        "target_name": "mcp-target-01",
        "target_class": "other",
        "template": "Unix Account (SSH Password)",
        "endpoint_type": "ipv4",
        "target_address": "192.0.2.10",
        "web_proxy_status": "disable",
        "owner_binding": "verified_admin_principal",
        "create_secret_group_binding": "everyone",
    }
    assert preview["Expected State"] == {
        "target_exists": True,
        "target_name_matches": True,
        "class_matches": True,
        "template_matches": True,
        "address_matches": True,
        "web_proxy_disabled": True,
        "owner_relation_matches": True,
        "create_secret_group_relation_matches": True,
    }
    assert "mcp-target-01" in str(preview)
    assert "192.0.2.10" in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeTargetTransport()
    workflow = TargetLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(TargetLiveWorkflowError):
        workflow.execute("target-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.create_calls == [("mcp-target-01", "192.0.2.10")]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["endpoint_value_returned"] is False
    assert result["raw_api_response_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_live_current_state_changes() -> None:
    transport = FakeTargetTransport()
    workflow = TargetLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(TargetLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_preview_fails_closed_for_unsupported_firmware_and_version_drift() -> None:
    transport = FakeTargetTransport()
    transport.product_version = "7.1.0"
    workflow = TargetLiveWorkflow(transport, clock=lambda: 100)
    with pytest.raises(TargetLiveWorkflowError):
        _preview(workflow)

    transport.product_version = "7.0.0"
    preview = _preview(workflow)
    transport.product_build = 30
    with pytest.raises(TargetLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.create_calls == []


def test_create_readback_failure_requires_reconciliation_without_replay() -> None:
    transport = FakeTargetTransport()
    transport.readback = TargetReadback(True, True, True, False, True, True, True)
    workflow = TargetLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(TargetLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_transport_rejection_returns_only_categorical_failure_evidence() -> None:
    transport = RejectedTargetTransport()
    workflow = TargetLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["failure_stage"] == "target_create_post"
    assert result["failure_http_status"] == 500
    assert result["failure_product_error_code"] == -15
    assert result["failure_product_status"] == "error"
    assert result["failure_product_error_class"] == "duplicate_target_address"
    assert result["raw_api_response_returned"] is False
    assert transport.create_calls == [("mcp-target-01", "192.0.2.10")]


def test_preview_rejects_invalid_name_or_non_ipv4_address() -> None:
    workflow = TargetLiveWorkflow(FakeTargetTransport())

    with pytest.raises(TargetLiveWorkflowError):
        workflow.preview(
            target_name="unsafe name",
            address="192.0.2.10",
            requester_digest=REQUESTER,
        )
    with pytest.raises(TargetLiveWorkflowError):
        workflow.preview(
            target_name="safe-name",
            address="ssh.example.local",
            requester_digest=REQUESTER,
        )
