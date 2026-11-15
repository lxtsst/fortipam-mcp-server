from __future__ import annotations

import pytest

from fortipam_mcp.template_live_workflow import (
    TemplateCreateLiveWorkflow,
    TemplateLiveWorkflowError,
)
from fortipam_mcp.template_ssh_transport import TemplateInspection, TemplateReadback


REQUESTER = "a" * 64
TEMPLATE_NAME = "mcp-v4-template-01"


class FakeTemplateTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = TemplateReadback(True, True, True, True, True, True, True, True)

    def inspect(self, template_name: str) -> TemplateInspection:
        return TemplateInspection(self.exists)

    def create_and_readback(self, template_name: str) -> TemplateReadback:
        self.create_calls.append(template_name)
        self.exists = True
        return self.readback


def _preview(workflow: TemplateCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(template_name=TEMPLATE_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_secret_values_and_associations() -> None:
    workflow = TemplateCreateLiveWorkflow(FakeTemplateTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_template_name": TEMPLATE_NAME,
        "template_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_web_vnc_template_via_cli_fallback",
        "template_name": TEMPLATE_NAME,
        "configuration_profile": "web-vnc-username-password-v1",
        "template_access": "everyone",
        "mandatory_fields": ["username", "password"],
        "launcher": "Web VNC",
        "launcher_port": 5900,
        "secret_or_target_association_changes": False,
        "secret_field_values_supplied": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["template_name_matches"] is True
    assert preview["Expected State"]["web_vnc_port_matches"] is True
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeTemplateTransport()
    workflow = TemplateCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(TemplateLiveWorkflowError):
        workflow.execute("template-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [TEMPLATE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["secret_or_target_association_changes"] is False
    assert result["secret_field_values_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_template_appears_after_preview() -> None:
    transport = FakeTemplateTransport()
    workflow = TemplateCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(TemplateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeTemplateTransport()
    transport.readback = TemplateReadback(True, True, True, True, True, True, True, False)
    workflow = TemplateCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(TemplateLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeTemplateTransport()
    workflow = TemplateCreateLiveWorkflow(transport)

    with pytest.raises(TemplateLiveWorkflowError):
        workflow.preview(template_name="web-vnc-template", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(TemplateLiveWorkflowError):
        _preview(workflow)
