from __future__ import annotations

import pytest

from fortipam_mcp.antivirus_profile_live_workflow import (
    AntivirusProfileLiveWorkflow,
    AntivirusProfileLiveWorkflowError,
)
from fortipam_mcp.antivirus_profile_ssh_transport import (
    AntivirusProfileInspection,
    AntivirusProfileReadback,
)


REQUESTER = "a" * 64
PROFILE_NAME = "mcp-v4-av-profile-01"


class FakeAntivirusProfileTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = AntivirusProfileReadback(True, True, True, True, True)

    def inspect(self, profile_name: str) -> AntivirusProfileInspection:
        return AntivirusProfileInspection(self.exists)

    def create_and_readback(self, profile_name: str) -> AntivirusProfileReadback:
        self.create_calls.append(profile_name)
        self.exists = True
        return self.readback


def _preview(workflow: AntivirusProfileLiveWorkflow) -> dict[str, object]:
    return workflow.preview(profile_name=PROFILE_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_secret_license_and_sandbox_changes() -> None:
    workflow = AntivirusProfileLiveWorkflow(
        FakeAntivirusProfileTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_profile_name": PROFILE_NAME,
        "profile_name_exists": False,
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_http_ssh_block_antivirus_profile",
        "profile_name": PROFILE_NAME,
        "configuration_profile": "http_ssh_block_v1",
        "http_av_scan": "block",
        "ssh_av_scan": "block",
        "secret_association_changes": False,
        "fortisandbox_or_license_changes": False,
    }
    assert preview["Expected State"]["profile_name_matches"] is True
    assert preview["Expected State"]["ssh_scan_block_matches"] is True
    assert preview["device_write_executed"] is False
    assert "password" not in repr(preview).lower()


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeAntivirusProfileTransport()
    workflow = AntivirusProfileLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(AntivirusProfileLiveWorkflowError):
        workflow.execute("antivirus-profile-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [PROFILE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["fortisandbox_or_license_changes"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_profile_appears_after_preview() -> None:
    transport = FakeAntivirusProfileTransport()
    workflow = AntivirusProfileLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(AntivirusProfileLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeAntivirusProfileTransport()
    workflow = AntivirusProfileLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(AntivirusProfileLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeAntivirusProfileTransport()
    transport.readback = AntivirusProfileReadback(True, True, True, True, False)
    workflow = AntivirusProfileLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(AntivirusProfileLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeAntivirusProfileTransport()
    workflow = AntivirusProfileLiveWorkflow(transport)

    with pytest.raises(AntivirusProfileLiveWorkflowError):
        workflow.preview(profile_name="profile", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(AntivirusProfileLiveWorkflowError):
        _preview(workflow)
