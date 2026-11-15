from __future__ import annotations

import pytest

from fortipam_mcp.ztna_user_control_live_workflow import (
    ZtnaUserControlLiveWorkflow,
    ZtnaUserControlLiveWorkflowError,
    ZtnaUserControlRollbackLiveWorkflow,
)
from fortipam_mcp.ztna_user_control_ssh_transport import (
    ZtnaUserControlInspection,
    ZtnaUserControlReadback,
)


REQUESTER = "a" * 64


class FakeZtnaUserControlTransport:
    def __init__(self) -> None:
        self.current = ZtnaUserControlInspection(
            "enable", "block", True, True, True, "disable"
        )
        self.enable_calls = 0
        self.disable_calls = 0
        self.readback = ZtnaUserControlReadback(
            "enable", "block", True, True, True, "enable"
        )
        self.rollback_readback = ZtnaUserControlReadback(
            "enable", "block", True, True, True, "disable"
        )

    def inspect(self) -> ZtnaUserControlInspection:
        return self.current

    def enable_and_readback(self) -> ZtnaUserControlReadback:
        self.enable_calls += 1
        self.current = ZtnaUserControlInspection(
            "enable", "block", True, True, True, "enable"
        )
        return self.readback

    def disable_and_readback(self) -> ZtnaUserControlReadback:
        self.disable_calls += 1
        self.current = ZtnaUserControlInspection(
            "enable", "block", True, True, True, "disable"
        )
        return self.rollback_readback


def _preview(workflow: ZtnaUserControlLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_cpe_and_excludes_secret_level_or_access_proxy_changes() -> None:
    workflow = ZtnaUserControlLiveWorkflow(
        FakeZtnaUserControlTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "client_certificate_mode": "enable",
        "empty_certificate_action": "block",
        "policy_is_access_proxy": True,
        "existing_ems_tag_configured": True,
        "ztna_status": "disable",
        "access_proxy_reference_returned": False,
        "policy_reference_returned": False,
        "ems_tag_reference_returned": False,
        "write_transport": "ssh_cli_fallback",
    }
    proposed = preview["Proposed Changes"]
    assert proposed["ztna_status"] == "enable"
    assert proposed["access_proxy_client_certificate_changed"] is False
    assert proposed["folder_or_secret_control_changed"] is False
    assert proposed["rest_write_attempted"] is False
    expected = preview["Expected State"]
    assert expected["managed_only_portal_login_required"] is True
    assert expected["unmanaged_portal_access_allowed"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_has_one_fixed_transition() -> None:
    transport = FakeZtnaUserControlTransport()
    workflow = ZtnaUserControlLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(ZtnaUserControlLiveWorkflowError):
        workflow.execute("ztna-user-control-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.enable_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["ztna_scope"] == "access_level_only"
    assert result["folder_or_secret_control_changed"] is False
    assert result["raw_cli_returned"] is False
    assert workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )["idempotent_replay"] is True


def test_prewrite_drift_or_prerequisite_gap_rejects_execution() -> None:
    transport = FakeZtnaUserControlTransport()
    workflow = ZtnaUserControlLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.current = ZtnaUserControlInspection(
        "enable", "block", True, True, True, "enable"
    )

    with pytest.raises(ZtnaUserControlLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )

    assert transport.enable_calls == 0
    with pytest.raises(ZtnaUserControlLiveWorkflowError):
        ZtnaUserControlLiveWorkflow(
            type("NotReady", (), {"inspect": lambda self: ZtnaUserControlInspection("disable", "block", True, True, True, "disable")})()
        ).preview(requester_digest=REQUESTER)


def test_failed_readback_requires_reconciliation() -> None:
    transport = FakeZtnaUserControlTransport()
    transport.readback = ZtnaUserControlReadback(
        "enable", "block", True, True, True, "disable"
    )
    workflow = ZtnaUserControlLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(ZtnaUserControlLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )


def test_rollback_preview_confirmation_and_execution_restore_disabled_state() -> None:
    transport = FakeZtnaUserControlTransport()
    transport.current = ZtnaUserControlInspection(
        "enable", "block", True, True, True, "enable"
    )
    workflow = ZtnaUserControlRollbackLiveWorkflow(transport, clock=lambda: 100)

    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["Current State"]["ztna_status"] == "enable"
    assert preview["Proposed Changes"] == {
        "operation": "restore_access_level_ztna_pre_action_state_via_cli_fallback",
        "configuration_profile": "access-level-disable-existing-ems-tag-v1",
        "ztna_status": "disable",
        "existing_ems_tag_preserved": True,
        "access_proxy_client_certificate_changed": False,
        "empty_certificate_action_changed": False,
        "access_proxy_binding_changed": False,
        "ems_connector_or_tag_sync_changed": False,
        "folder_or_secret_control_changed": False,
        "wad_debug_enabled": False,
        "session_or_secret_launch_executed": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["portal_login_effect_verified"] is False
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.disable_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["pre_action_state_restored"] is True
    assert result["raw_cli_returned"] is False
    assert workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )["idempotent_replay"] is True


def test_rollback_rejects_ineligible_state_and_prewrite_drift() -> None:
    transport = FakeZtnaUserControlTransport()
    workflow = ZtnaUserControlRollbackLiveWorkflow(transport, clock=lambda: 100)
    with pytest.raises(ZtnaUserControlLiveWorkflowError):
        workflow.preview(requester_digest=REQUESTER)

    transport.current = ZtnaUserControlInspection(
        "enable", "block", True, True, True, "enable"
    )
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    transport.current = ZtnaUserControlInspection(
        "enable", "block", True, True, True, "disable"
    )
    with pytest.raises(ZtnaUserControlLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.disable_calls == 0


def test_rollback_failed_readback_requires_reconciliation() -> None:
    transport = FakeZtnaUserControlTransport()
    transport.current = ZtnaUserControlInspection(
        "enable", "block", True, True, True, "enable"
    )
    transport.rollback_readback = ZtnaUserControlReadback(
        "enable", "block", True, True, True, "enable"
    )
    workflow = ZtnaUserControlRollbackLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(ZtnaUserControlLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
