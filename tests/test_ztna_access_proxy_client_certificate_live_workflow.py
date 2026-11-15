from __future__ import annotations

import pytest

from fortipam_mcp.ztna_access_proxy_client_certificate_live_workflow import (
    ZtnaAccessProxyClientCertificateLiveWorkflow,
    ZtnaAccessProxyClientCertificateRollbackLiveWorkflow,
    ZtnaAccessProxyLiveWorkflowError,
)
from fortipam_mcp.ztna_access_proxy_client_certificate_ssh_transport import (
    ZTNA_MANAGED_ONLY,
    ZTNA_MIXED_ACCESS,
    ZtnaAccessProxyInspection,
    ZtnaAccessProxyReadback,
)


REQUESTER = "a" * 64


class FakeZtnaAccessProxyTransport:
    def __init__(self) -> None:
        self.current = ZtnaAccessProxyInspection("disable", "block")
        self.configure_calls: list[str] = []
        self.rollback_calls = 0
        self.readback = ZtnaAccessProxyReadback("enable", "accept")
        self.rollback_readback = ZtnaAccessProxyReadback("disable", "block")

    def inspect(self) -> ZtnaAccessProxyInspection:
        return self.current

    def configure_and_readback(self, endpoint_access_mode: str) -> ZtnaAccessProxyReadback:
        self.configure_calls.append(endpoint_access_mode)
        self.current = ZtnaAccessProxyInspection(
            "enable",
            "block" if endpoint_access_mode == ZTNA_MANAGED_ONLY else "accept",
        )
        return self.readback

    def restore_disabled_block_and_readback(self) -> ZtnaAccessProxyReadback:
        self.rollback_calls += 1
        self.current = ZtnaAccessProxyInspection("disable", "block")
        return self.rollback_readback


def _preview(
    workflow: ZtnaAccessProxyClientCertificateLiveWorkflow,
    mode: str = ZTNA_MIXED_ACCESS,
) -> dict[str, object]:
    return workflow.preview(endpoint_access_mode=mode, requester_digest=REQUESTER)


def test_preview_is_cpe_and_excludes_global_or_secret_control_changes() -> None:
    workflow = ZtnaAccessProxyClientCertificateLiveWorkflow(
        FakeZtnaAccessProxyTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_endpoint_access_mode": ZTNA_MIXED_ACCESS,
        "client_certificate_mode": "disable",
        "empty_certificate_action": "block",
        "access_proxy_reference_returned": False,
        "write_transport": "ssh_cli_fallback",
    }
    proposed = preview["Proposed Changes"]
    assert proposed["endpoint_access_mode"] == ZTNA_MIXED_ACCESS
    assert proposed["empty_certificate_action"] == "accept"
    assert proposed["access_level_proxy_policy_changed"] is False
    assert proposed["folder_or_secret_control_changed"] is False
    assert proposed["wad_debug_enabled"] is False
    expected = preview["Expected State"]
    assert expected["endpoint_access_mode_matches"] is True
    assert expected["unmanaged_portal_access_allowed"] is True
    assert expected["session_or_secret_launch_effect_verified"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_uses_only_selected_mode() -> None:
    transport = FakeZtnaAccessProxyTransport()
    workflow = ZtnaAccessProxyClientCertificateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow, ZTNA_MANAGED_ONLY)

    with pytest.raises(ZtnaAccessProxyLiveWorkflowError):
        workflow.execute("ztna-access-proxy-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.readback = ZtnaAccessProxyReadback("enable", "block")
    result = workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    assert transport.configure_calls == [ZTNA_MANAGED_ONLY]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["access_level_proxy_policy_changed"] is False
    assert result["raw_cli_returned"] is False
    assert workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)["idempotent_replay"] is True


def test_prewrite_drift_or_nonbaseline_rejects_execution() -> None:
    transport = FakeZtnaAccessProxyTransport()
    workflow = ZtnaAccessProxyClientCertificateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.current = ZtnaAccessProxyInspection("enable", "block")

    with pytest.raises(ZtnaAccessProxyLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    assert transport.configure_calls == []


def test_failed_readback_requires_reconciliation_and_baseline_is_required() -> None:
    transport = FakeZtnaAccessProxyTransport()
    workflow = ZtnaAccessProxyClientCertificateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.readback = ZtnaAccessProxyReadback("enable", "block")

    result = workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(ZtnaAccessProxyLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    with pytest.raises(ZtnaAccessProxyLiveWorkflowError):
        workflow.preview(endpoint_access_mode="portal-wide", requester_digest=REQUESTER)


@pytest.mark.parametrize(
    ("source_mode", "empty_action"),
    ((ZTNA_MANAGED_ONLY, "block"), (ZTNA_MIXED_ACCESS, "accept")),
)
def test_rollback_preview_confirmation_and_execution_restore_exact_baseline(
    source_mode: str,
    empty_action: str,
) -> None:
    transport = FakeZtnaAccessProxyTransport()
    transport.current = ZtnaAccessProxyInspection("enable", empty_action)
    workflow = ZtnaAccessProxyClientCertificateRollbackLiveWorkflow(
        transport,
        clock=lambda: 100,
    )

    preview = workflow.preview(requester_digest=REQUESTER)

    assert preview["Current State"] == {
        "endpoint_access_mode": source_mode,
        "client_certificate_mode": "enable",
        "empty_certificate_action": empty_action,
        "access_proxy_reference_returned": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"]["client_certificate_mode"] == "disable"
    assert preview["Proposed Changes"]["empty_certificate_action"] == "block"
    assert preview["Expected State"]["pre_action_state_restored"] is True
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.rollback_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["source_endpoint_access_mode"] == source_mode
    assert result["pre_action_state_restored"] is True
    assert result["raw_cli_returned"] is False
    assert workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )["idempotent_replay"] is True


def test_rollback_requires_enabled_known_mode_and_rejects_drift() -> None:
    transport = FakeZtnaAccessProxyTransport()
    workflow = ZtnaAccessProxyClientCertificateRollbackLiveWorkflow(
        transport,
        clock=lambda: 100,
    )

    with pytest.raises(ZtnaAccessProxyLiveWorkflowError):
        workflow.preview(requester_digest=REQUESTER)

    transport.current = ZtnaAccessProxyInspection("enable", "accept")
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    transport.current = ZtnaAccessProxyInspection("enable", "block")

    with pytest.raises(ZtnaAccessProxyLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )

    assert transport.rollback_calls == 0


def test_rollback_failed_readback_requires_reconciliation() -> None:
    transport = FakeZtnaAccessProxyTransport()
    transport.current = ZtnaAccessProxyInspection("enable", "block")
    transport.rollback_readback = ZtnaAccessProxyReadback("enable", "block")
    workflow = ZtnaAccessProxyClientCertificateRollbackLiveWorkflow(
        transport,
        clock=lambda: 100,
    )
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    assert result["pre_action_state_restored"] is False
