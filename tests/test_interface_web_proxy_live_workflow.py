from __future__ import annotations

import pytest

from fortipam_mcp.interface_web_proxy_live_workflow import (
    InterfaceWebProxyLiveWorkflow,
    InterfaceWebProxyLiveWorkflowError,
    InterfaceWebProxyRollbackLiveWorkflow,
)
from fortipam_mcp.interface_web_proxy_ssh_transport import (
    InterfaceWebProxyInspection,
    InterfaceWebProxyReadback,
)


REQUESTER = "a" * 64


class FakeInterfaceWebProxyTransport:
    def __init__(self) -> None:
        self.current = InterfaceWebProxyInspection("disable", 0)
        self.enable_calls = 0
        self.disable_calls = 0
        self.readback = InterfaceWebProxyReadback("enable", 1)
        self.rollback_readback = InterfaceWebProxyReadback("disable", 0)

    def inspect(self) -> InterfaceWebProxyInspection:
        return self.current

    def enable_and_readback(self) -> InterfaceWebProxyReadback:
        self.enable_calls += 1
        self.current = InterfaceWebProxyInspection("enable", 1)
        return self.readback

    def disable_and_readback(self) -> InterfaceWebProxyReadback:
        self.disable_calls += 1
        self.current = InterfaceWebProxyInspection("disable", 0)
        return self.rollback_readback


def _preview(workflow: InterfaceWebProxyLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_cpe_and_excludes_network_or_secret_side_effects() -> None:
    workflow = InterfaceWebProxyLiveWorkflow(
        FakeInterfaceWebProxyTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "selected_interface_explicit_web_proxy": "disable",
        "enabled_explicit_web_proxy_interface_count": 0,
        "interface_reference_returned": False,
        "proxy_port_changed": False,
        "proxy_ca_changed": False,
        "write_transport": "ssh_cli_fallback",
    }
    proposed = preview["Proposed Changes"]
    assert proposed["selected_interface_explicit_web_proxy"] == "enable"
    assert proposed["other_interfaces_changed"] is False
    assert proposed["proxy_port_changed"] is False
    assert proposed["vip_or_route_changed"] is False
    assert proposed["secret_or_target_changed"] is False
    expected = preview["Expected State"]
    assert expected["enabled_explicit_web_proxy_interface_count"] == 1
    assert expected["web_proxy_reachability_verified"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_uses_only_enable_transition() -> None:
    transport = FakeInterfaceWebProxyTransport()
    workflow = InterfaceWebProxyLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(InterfaceWebProxyLiveWorkflowError):
        workflow.execute(
            "interface-web-proxy-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    assert transport.enable_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["proxy_port_changed"] is False
    assert result["raw_cli_returned"] is False
    assert workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )["idempotent_replay"] is True


def test_prewrite_drift_or_global_proxy_conflict_rejects_execution() -> None:
    transport = FakeInterfaceWebProxyTransport()
    workflow = InterfaceWebProxyLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.current = InterfaceWebProxyInspection("disable", 1)

    with pytest.raises(InterfaceWebProxyLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    assert transport.enable_calls == 0


def test_failed_readback_requires_reconciliation_and_safe_baseline_is_required() -> None:
    transport = FakeInterfaceWebProxyTransport()
    workflow = InterfaceWebProxyLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.readback = InterfaceWebProxyReadback("enable", 2)

    result = workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(InterfaceWebProxyLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    with pytest.raises(InterfaceWebProxyLiveWorkflowError):
        InterfaceWebProxyLiveWorkflow(
            FakeInterfaceWebProxyTransport(),
            clock=lambda: 100,
        ).preview(requester_digest="not-a-digest")


def test_rollback_requires_exact_enabled_state_and_restores_disabled() -> None:
    transport = FakeInterfaceWebProxyTransport()
    transport.current = InterfaceWebProxyInspection("enable", 1)
    workflow = InterfaceWebProxyRollbackLiveWorkflow(transport, clock=lambda: 100)

    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["Current State"]["selected_interface_explicit_web_proxy"] == "enable"
    assert preview["Proposed Changes"]["selected_interface_explicit_web_proxy"] == "disable"
    assert preview["Expected State"]["enabled_explicit_web_proxy_interface_count"] == 0
    assert preview["Expected State"]["web_proxy_reachability_verified"] is False

    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.disable_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["pre_action_state_restored"] is True
    assert result["raw_cli_returned"] is False
    assert workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )["idempotent_replay"] is True


def test_rollback_rejects_drift_and_ambiguous_readback() -> None:
    transport = FakeInterfaceWebProxyTransport()
    transport.current = InterfaceWebProxyInspection("enable", 1)
    workflow = InterfaceWebProxyRollbackLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    transport.current = InterfaceWebProxyInspection("enable", 2)

    with pytest.raises(InterfaceWebProxyLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.disable_calls == 0

    transport = FakeInterfaceWebProxyTransport()
    transport.current = InterfaceWebProxyInspection("enable", 1)
    transport.rollback_readback = InterfaceWebProxyReadback("disable", 1)
    workflow = InterfaceWebProxyRollbackLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert result["outcome"] == "reconciliation_required"
