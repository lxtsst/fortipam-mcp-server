from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.automation_trigger_mcp_action import (
    ProtectedAutomationTriggerMcpAction,
    V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV,
    V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE,
    V4_AUTOMATION_TRIGGER_DELETE_EXECUTION_ENV,
    V4_AUTOMATION_TRIGGER_EXECUTION_ENV,
    V4AutomationTriggerActionConfigurationError,
    V4AutomationTriggerActionRuntimeError,
    automation_trigger_action_principal_from_access_token,
    build_v4_automation_trigger_action,
    load_v4_automation_trigger_action_feature,
    load_v4_automation_trigger_delete_execution_feature,
    load_v4_automation_trigger_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_automation_trigger_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_automation_trigger_action_feature({}) is False
    assert (
        load_v4_automation_trigger_action_feature(
            {V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_automation_trigger_action_feature(
            {V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4AutomationTriggerActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_automation_trigger_action_feature(
            {V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_automation_trigger_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_automation_trigger_execution_feature({}) is False
    assert (
        load_v4_automation_trigger_execution_feature(
            {V4_AUTOMATION_TRIGGER_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4AutomationTriggerActionConfigurationError):
        load_v4_automation_trigger_execution_feature(
            {V4_AUTOMATION_TRIGGER_EXECUTION_ENV: "yes"}
        )


def test_automation_trigger_delete_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_automation_trigger_delete_execution_feature({}) is False
    assert load_v4_automation_trigger_delete_execution_feature(
        {V4_AUTOMATION_TRIGGER_DELETE_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4AutomationTriggerActionConfigurationError):
        load_v4_automation_trigger_delete_execution_feature(
            {V4_AUTOMATION_TRIGGER_DELETE_EXECUTION_ENV: "yes"}
        )


def test_automation_trigger_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedAutomationTriggerMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview("mcp-v4-automation-trigger-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4AutomationTriggerActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_automation_trigger_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4AutomationTriggerActionConfigurationError,
        match=V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE,
    ):
        build_v4_automation_trigger_action(
            {V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV: "true"}
        )


def test_automation_trigger_requires_the_non_default_operation_scope() -> None:
    resource = "https://mcp.example.test/fpamcp-v4"
    settings = V4PlanningAuthorizationSettings(resource, b"p" * 32)

    def token(scopes: list[str]) -> AccessToken:
        return AccessToken(
            token="opaque-sdk-validated-access-token",
            client_id="client-0001",
            scopes=scopes,
            expires_at=2_000_000_000,
            resource=resource,
            subject="operator-0001",
            claims={"iss": "https://mcp.example.test/oauth"},
        )

    with pytest.raises(
        V4AutomationTriggerActionRuntimeError,
        match=V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE,
    ):
        automation_trigger_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        automation_trigger_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_automation_trigger_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedAutomationTriggerMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-automation-trigger-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4AutomationTriggerActionRuntimeError,
        match=V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-v4-automation-trigger-02", object())


def test_automation_trigger_delete_is_no_input_and_independently_gated() -> None:
    create = _Workflow()
    delete = _DeleteWorkflow()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    denied = ProtectedAutomationTriggerMcpAction(
        create,
        delete_workflow=delete,
        delete_execution_enabled=False,
    )
    preview = denied.preview_delete(principal)
    confirmation = denied.confirm_delete(str(preview["preview_ref"]), principal)
    with pytest.raises(V4AutomationTriggerActionRuntimeError):
        denied.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert delete.calls == ["preview", "confirm"]

    enabled = ProtectedAutomationTriggerMcpAction(
        create,
        delete_workflow=delete,
        delete_execution_enabled=True,
    )
    result = enabled.execute_delete("automation-trigger-delete-authorized-00000001", principal)
    assert result["outcome"] == "succeeded"
    assert delete.calls[-1] == "execute"


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["trigger_name"] == "mcp-v4-automation-trigger-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "automation-trigger-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "automation-trigger-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "automation-trigger-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "automation-trigger-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _DeleteWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "automation-trigger-delete-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "automation-trigger-delete-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "automation-trigger-delete-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "automation-trigger-delete-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
