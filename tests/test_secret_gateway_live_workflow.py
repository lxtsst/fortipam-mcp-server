from __future__ import annotations

import pytest

from fortipam_mcp.secret_gateway_live_workflow import (
    SecretGatewayCreateLiveWorkflow,
    SecretGatewayLiveWorkflowError,
)
from fortipam_mcp.secret_gateway_ssh_transport import (
    SecretGatewayInspection,
    SecretGatewayReadback,
)


REQUESTER = "a" * 64
GATEWAY_NAME = "mcp-v4-secret-gateway-01"


class FakeSecretGatewayTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = SecretGatewayReadback(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        )

    def inspect(self, gateway_name: str) -> SecretGatewayInspection:
        return SecretGatewayInspection(self.exists)

    def create_and_readback(self, gateway_name: str) -> SecretGatewayReadback:
        self.create_calls.append(gateway_name)
        self.exists = True
        return self.readback


def _preview(workflow: SecretGatewayCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        gateway_name=GATEWAY_NAME,
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_excludes_connectivity_effects() -> None:
    workflow = SecretGatewayCreateLiveWorkflow(
        FakeSecretGatewayTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_gateway_name": GATEWAY_NAME,
        "gateway_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_secret_gateway_via_cli_fallback",
        "gateway_name": GATEWAY_NAME,
        "configuration_profile": "disabled-forward-documentation-ipv4-v1",
        "gateway_status": "disable",
        "gateway_type": "forward",
        "gateway_address_class": "documentation_ipv4",
        "gateway_port": 443,
        "url_map": "tcp",
        "ssl_maximum_version": "tls-1.3",
        "target_or_secret_association_changes": False,
        "gateway_chain_changes": False,
        "reverse_service_changes": False,
        "traffic_forwarding_enabled": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["gateway_name_matches"] is True
    assert preview["Expected State"]["description_matches"] is True
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeSecretGatewayTransport()
    workflow = SecretGatewayCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(SecretGatewayLiveWorkflowError):
        workflow.execute(
            "secret-gateway-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [GATEWAY_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["traffic_forwarding_enabled"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_gateway_appears_after_preview() -> None:
    transport = FakeSecretGatewayTransport()
    workflow = SecretGatewayCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(SecretGatewayLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeSecretGatewayTransport()
    workflow = SecretGatewayCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(SecretGatewayLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeSecretGatewayTransport()
    transport.readback = SecretGatewayReadback(
        True,
        False,
        True,
        True,
        True,
        True,
        True,
        True,
    )
    workflow = SecretGatewayCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(SecretGatewayLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeSecretGatewayTransport()
    workflow = SecretGatewayCreateLiveWorkflow(transport)

    with pytest.raises(SecretGatewayLiveWorkflowError):
        workflow.preview(gateway_name="default", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(SecretGatewayLiveWorkflowError):
        _preview(workflow)
