from __future__ import annotations

import pytest

from fortipam_mcp.secret_audit_live_workflow import (
    SecretAuditGenerateLiveWorkflow,
    SecretAuditLiveWorkflowError,
)
from fortipam_mcp.secret_audit_ssh_transport import (
    SecretAuditInspection,
    SecretAuditReadback,
)


REQUESTER = "a" * 64


class FakeSecretAuditTransport:
    def __init__(self) -> None:
        self.current = SecretAuditInspection(cli_reachable=True)
        self.generate_calls = 0
        self.readback = SecretAuditReadback(generated_report_name_observed=True)

    def inspect(self) -> SecretAuditInspection:
        return self.current

    def generate_and_readback(self) -> SecretAuditReadback:
        self.generate_calls += 1
        return self.readback


def _preview(workflow: SecretAuditGenerateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_cpe_and_never_returns_report_content_or_identity_metadata() -> None:
    workflow = SecretAuditGenerateLiveWorkflow(FakeSecretAuditTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"]["fixed_cli_preflight_reachable"] is True
    assert preview["Current State"]["report_inventory_read"] is False
    proposed = preview["Proposed Changes"]
    assert proposed["caller_controlled_report_scope"] is False
    assert proposed["report_content_returned"] is False
    assert proposed["report_name_returned"] is False
    assert proposed["identity_target_folder_secret_data_returned"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_categorically_verifies_generation() -> None:
    transport = FakeSecretAuditTransport()
    workflow = SecretAuditGenerateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(SecretAuditLiveWorkflowError):
        workflow.execute("secret-audit-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.generate_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["report_content_returned"] is False
    assert result["report_name_returned"] is False
    assert result["raw_cli_returned"] is False
    assert workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )["idempotent_replay"] is True


def test_prewrite_drift_or_unreachable_cli_rejects_execution() -> None:
    transport = FakeSecretAuditTransport()
    workflow = SecretAuditGenerateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.current = SecretAuditInspection(cli_reachable=False)

    with pytest.raises(SecretAuditLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )

    assert transport.generate_calls == 0


def test_unverified_generation_requires_reconciliation() -> None:
    transport = FakeSecretAuditTransport()
    transport.readback = SecretAuditReadback(generated_report_name_observed=False)
    workflow = SecretAuditGenerateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(SecretAuditLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
