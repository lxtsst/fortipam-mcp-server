from __future__ import annotations

from typing import cast

import pytest

from fortipam_mcp.client_integrity_live_workflow import (
    ClientIntegrityConfigureLiveWorkflow,
    ClientIntegrityLiveWorkflowError,
)
from fortipam_mcp.client_integrity_ssh_transport import (
    ClientIntegrityInspection,
    ClientIntegrityReadback,
)


REQUESTER = "a" * 64
CLIENT_SOFTWARE_NAME = "mcp-v4-client-integrity-01"


class FakeClientIntegrityTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = ClientIntegrityReadback(True, True, True, True, True, True, True)

    def inspect(self, client_software_name: str) -> ClientIntegrityInspection:
        assert client_software_name == CLIENT_SOFTWARE_NAME
        return ClientIntegrityInspection(self.exists)

    def create_and_readback(
        self,
        client_software_name: str,
    ) -> ClientIntegrityReadback:
        self.create_calls.append(client_software_name)
        self.exists = True
        return self.readback


def _preview(workflow: ClientIntegrityConfigureLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        client_software_name=CLIENT_SOFTWARE_NAME,
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_excludes_bindings_or_session_effects() -> None:
    workflow = ClientIntegrityConfigureLiveWorkflow(
        FakeClientIntegrityTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_client_software_name": CLIENT_SOFTWARE_NAME,
        "client_software_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "configure_client_integrity_precondition_via_cli_fallback",
        "client_software_name": CLIENT_SOFTWARE_NAME,
        "configuration_profile": "putty-x64-external-certificate-v1",
        "package_architecture": "x64",
        "integrity_check": "certificate",
        "download_source": "external",
        "launcher_or_template_binding_changes": False,
        "secret_or_target_association_changes": False,
        "external_download_or_session_launch_executed": False,
        "rest_write_attempted": False,
    }
    expected = cast(dict[str, object], preview["Expected State"])
    assert expected["client_software_name_matches"] is True
    assert expected["certificate_integrity_check_enabled"] is True
    assert expected["session_integrity_enforcement_verified"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeClientIntegrityTransport()
    workflow = ClientIntegrityConfigureLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(ClientIntegrityLiveWorkflowError):
        workflow.execute(
            "client-integrity-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [CLIENT_SOFTWARE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["external_download_or_session_launch_executed"] is False
    assert result["session_integrity_enforcement_verified"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_client_software_appears_after_preview() -> None:
    transport = FakeClientIntegrityTransport()
    workflow = ClientIntegrityConfigureLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(ClientIntegrityLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeClientIntegrityTransport()
    workflow = ClientIntegrityConfigureLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(ClientIntegrityLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeClientIntegrityTransport()
    transport.readback = ClientIntegrityReadback(True, True, False, True, True, True, True)
    workflow = ClientIntegrityConfigureLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(ClientIntegrityLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeClientIntegrityTransport()
    workflow = ClientIntegrityConfigureLiveWorkflow(transport)

    with pytest.raises(ClientIntegrityLiveWorkflowError):
        workflow.preview(client_software_name="putty", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(ClientIntegrityLiveWorkflowError):
        _preview(workflow)
