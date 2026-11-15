from __future__ import annotations

import pytest

from fortipam_mcp.certificate_csr_contract import (
    CertificateCsrInspection,
    CertificateCsrReadback,
)
from fortipam_mcp.certificate_csr_live_workflow import (
    CertificateCsrLiveWorkflow,
    CertificateCsrLiveWorkflowError,
)


REQUESTER = "a" * 64


class _Transport:
    def __init__(self) -> None:
        self.inspection = CertificateCsrInspection(False, True)
        self.readback = CertificateCsrReadback(True, True, True, True)
        self.generate_calls: list[tuple[str, str]] = []

    def inspect(self, certificate_name: str) -> CertificateCsrInspection:
        return self.inspection

    def generate_and_readback(
        self,
        certificate_name: str,
        subject_ipv4: str,
    ) -> CertificateCsrReadback:
        self.generate_calls.append((certificate_name, subject_ipv4))
        return self.readback


def _preview(workflow: CertificateCsrLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        certificate_name="mcp-v4-cert-unit",
        subject_ipv4="127.0.0.1",
        requester_digest=REQUESTER,
    )


def test_preview_is_exact_cpe_and_contains_no_protected_material() -> None:
    workflow = CertificateCsrLiveWorkflow(_Transport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_certificate_name": "mcp-v4-cert-unit",
        "requested_subject_ipv4": "127.0.0.1",
        "certificate_entry_exists": False,
        "certificate_name_available": True,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "generate_certificate_signing_request",
        "certificate_name": "mcp-v4-cert-unit",
        "subject_type": "host_ipv4",
        "subject_ipv4": "127.0.0.1",
        "key_type": "rsa",
        "key_size": 2048,
        "scope": "global",
        "organization_units": [],
        "enrollment_method": "file_based",
        "private_key_password_supplied": False,
    }
    assert preview["Expected State"] == {
        "certificate_entry_exists": True,
        "certificate_name_matches": True,
        "csr_present": True,
        "private_key_present": True,
        "certificate_or_private_key_value_returned": False,
    }
    assert "private-key" not in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_runs_once_and_returns_categories() -> None:
    transport = _Transport()
    workflow = CertificateCsrLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(CertificateCsrLiveWorkflowError):
        workflow.execute("certificate-csr-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.generate_calls == [("mcp-v4-cert-unit", "127.0.0.1")]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["csr_value_returned"] is False
    assert result["private_key_value_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.generate_calls) == 1


def test_confirm_rejects_drift_and_partial_readback_is_nonretry() -> None:
    transport = _Transport()
    workflow = CertificateCsrLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.inspection = CertificateCsrInspection(True, False)

    with pytest.raises(CertificateCsrLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.generate_calls == []

    transport = _Transport()
    transport.readback = CertificateCsrReadback(True, True, True, False)
    workflow = CertificateCsrLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(CertificateCsrLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )


def test_preview_rejects_non_lab_name_or_non_ipv4_subject() -> None:
    workflow = CertificateCsrLiveWorkflow(_Transport())

    with pytest.raises(CertificateCsrLiveWorkflowError):
        workflow.preview(
            certificate_name="certificate-unit",
            subject_ipv4="127.0.0.1",
            requester_digest=REQUESTER,
        )
    with pytest.raises(CertificateCsrLiveWorkflowError):
        workflow.preview(
            certificate_name="mcp-v4-cert-unit",
            subject_ipv4="example.test",
            requester_digest=REQUESTER,
        )
