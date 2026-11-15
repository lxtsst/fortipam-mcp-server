from __future__ import annotations

import pytest

from fortipam_mcp.target_contract import (
    TargetWebProxyEnableInspection,
    TargetWebProxyEnableReadback,
)
from fortipam_mcp.target_web_proxy_enable_live_workflow import (
    TargetWebProxyEnableLiveWorkflow,
    TargetWebProxyEnableLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_NAME = "mcp-target-web-01"


class FakeTargetWebProxyTransport:
    def __init__(self) -> None:
        self.exists = True
        self.web_proxy_status = "disable"
        self.enable_calls: list[str] = []
        self.readback = TargetWebProxyEnableReadback(True, True)

    def inspect_web_proxy_enable(self, target_name: str) -> TargetWebProxyEnableInspection:
        assert target_name == TARGET_NAME
        return TargetWebProxyEnableInspection(
            exists=self.exists,
            web_proxy_disabled=self.web_proxy_status == "disable",
            state_digest=f"state:{self.exists}:{self.web_proxy_status}",
        )

    def enable_web_proxy_and_readback(self, target_name: str) -> TargetWebProxyEnableReadback:
        assert target_name == TARGET_NAME
        self.enable_calls.append(target_name)
        self.web_proxy_status = "enable"
        return self.readback


def _preview(workflow: TargetWebProxyEnableLiveWorkflow) -> dict[str, object]:
    return workflow.preview(target_name=TARGET_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_discloses_only_requested_target_identifier() -> None:
    workflow = TargetWebProxyEnableLiveWorkflow(
        FakeTargetWebProxyTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_target_name": TARGET_NAME,
        "target_exists": True,
        "web_proxy_disabled": True,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "enable_target_web_proxy_via_api",
        "target_name": TARGET_NAME,
        "web_proxy_status": "enable",
    }
    assert preview["Expected State"] == {
        "target_name_matches": True,
        "target_exists": True,
        "web_proxy_enabled": True,
    }
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_performs_one_api_update() -> None:
    transport = FakeTargetWebProxyTransport()
    workflow = TargetWebProxyEnableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(TargetWebProxyEnableLiveWorkflowError):
        workflow.execute(
            "target-web-proxy-enable-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.enable_calls == [TARGET_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["target_name_returned"] is False
    assert result["raw_api_response_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.enable_calls) == 1


def test_confirm_invalidates_when_web_proxy_state_changes() -> None:
    transport = FakeTargetWebProxyTransport()
    workflow = TargetWebProxyEnableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.web_proxy_status = "enable"

    with pytest.raises(TargetWebProxyEnableLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.enable_calls == []


@pytest.mark.parametrize("phase", ["confirm", "execute"])
def test_expiry_during_current_state_read_refuses_authorization_and_write(
    phase: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [100]
    transport = FakeTargetWebProxyTransport()
    workflow = TargetWebProxyEnableLiveWorkflow(transport, clock=lambda: now[0])
    preview = _preview(workflow)
    reference = str(preview["preview_ref"])
    if phase == "execute":
        confirmation = workflow.confirm(reference, requester_digest=REQUESTER)
        reference = str(confirmation["authorization_ref"])
    expires_at = int(str(preview["expires_at"]))
    now[0] = expires_at - 1
    inspect = transport.inspect_web_proxy_enable

    def expire_during_query(target_name: str) -> TargetWebProxyEnableInspection:
        current = inspect(target_name)
        now[0] = expires_at
        return current

    monkeypatch.setattr(transport, "inspect_web_proxy_enable", expire_during_query)
    with pytest.raises(TargetWebProxyEnableLiveWorkflowError):
        if phase == "confirm":
            workflow.confirm(reference, requester_digest=REQUESTER)
        else:
            workflow.execute(reference, requester_digest=REQUESTER)

    assert now[0] == expires_at
    assert transport.enable_calls == []


def test_failed_readback_requires_reconciliation_without_replay() -> None:
    transport = FakeTargetWebProxyTransport()
    transport.readback = TargetWebProxyEnableReadback(True, False)
    workflow = TargetWebProxyEnableLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(TargetWebProxyEnableLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_absent_enabled_or_unsafe_target() -> None:
    transport = FakeTargetWebProxyTransport()
    workflow = TargetWebProxyEnableLiveWorkflow(transport)

    transport.exists = False
    with pytest.raises(TargetWebProxyEnableLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    transport.web_proxy_status = "enable"
    with pytest.raises(TargetWebProxyEnableLiveWorkflowError):
        _preview(workflow)
    with pytest.raises(TargetWebProxyEnableLiveWorkflowError):
        workflow.preview(target_name="unsafe name", requester_digest=REQUESTER)
