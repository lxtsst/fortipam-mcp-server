from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.report_layout_mcp_action import (
    ProtectedReportLayoutMcpAction,
    V4_REPORT_LAYOUT_ACTION_FEATURE_ENV,
    V4_REPORT_LAYOUT_ACTION_UNAVAILABLE,
    V4_REPORT_LAYOUT_DELETE_EXECUTION_ENV,
    V4_REPORT_LAYOUT_EXECUTION_ENV,
    V4ReportLayoutActionConfigurationError,
    V4ReportLayoutActionRuntimeError,
    build_v4_report_layout_action,
    load_v4_report_layout_action_feature,
    load_v4_report_layout_delete_execution_feature,
    load_v4_report_layout_execution_feature,
    report_layout_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_feature_and_execution_gates_default_false_and_require_exact_values() -> None:
    assert load_v4_report_layout_action_feature({}) is False
    assert load_v4_report_layout_execution_feature({}) is False
    assert load_v4_report_layout_delete_execution_feature({}) is False
    assert load_v4_report_layout_action_feature(
        {V4_REPORT_LAYOUT_ACTION_FEATURE_ENV: "true"}
    ) is True
    assert load_v4_report_layout_execution_feature(
        {V4_REPORT_LAYOUT_EXECUTION_ENV: "true"}
    ) is True
    assert load_v4_report_layout_delete_execution_feature(
        {V4_REPORT_LAYOUT_DELETE_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4ReportLayoutActionConfigurationError):
        load_v4_report_layout_action_feature(
            {V4_REPORT_LAYOUT_ACTION_FEATURE_ENV: "TRUE"}
        )
    with pytest.raises(V4ReportLayoutActionConfigurationError):
        load_v4_report_layout_delete_execution_feature(
            {V4_REPORT_LAYOUT_DELETE_EXECUTION_ENV: "yes"}
        )


def test_builder_reuses_central_identity_but_never_falls_back() -> None:
    with pytest.raises(
        V4ReportLayoutActionConfigurationError,
        match=V4_REPORT_LAYOUT_ACTION_UNAVAILABLE,
    ):
        build_v4_report_layout_action({V4_REPORT_LAYOUT_ACTION_FEATURE_ENV: "true"})


def test_action_requires_operation_scope_and_independent_execution_gate() -> None:
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

    with pytest.raises(V4ReportLayoutActionRuntimeError):
        report_layout_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]), settings
        )
    principal = report_layout_action_principal_from_access_token(
        token(["fortipam:read", "fortipam:plan", "fortipam:operate"]), settings
    )
    assert isinstance(principal, V4PlanningPrincipal)

    action = ProtectedReportLayoutMcpAction(
        _Workflow(expected_digest=principal.requester.digest),
        execution_enabled=False,
    )
    preview = action.preview("MCPV4ReportB163Test", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(V4ReportLayoutActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedReportLayoutMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("MCPV4ReportB163Test", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(V4ReportLayoutActionRuntimeError):
        action.preview("MCPV4ReportB163Other", object())


def test_delete_flow_requires_its_independent_execution_gate() -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    delete_workflow = _DeleteWorkflow()
    action = ProtectedReportLayoutMcpAction(
        _Workflow(),
        delete_workflow=delete_workflow,
        delete_execution_enabled=False,
    )

    preview = action.preview_delete(principal)
    confirmation = action.confirm_delete(str(preview["preview_ref"]), principal)
    with pytest.raises(V4ReportLayoutActionRuntimeError):
        action.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert delete_workflow.calls == ["preview", "confirm"]

    delete_workflow = _DeleteWorkflow()
    action = ProtectedReportLayoutMcpAction(
        _Workflow(),
        delete_workflow=delete_workflow,
        execution_enabled=False,
        delete_execution_enabled=True,
    )
    preview = action.preview_delete(principal)
    confirmation = action.confirm_delete(str(preview["preview_ref"]), principal)
    result = action.execute_delete(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert delete_workflow.calls == ["preview", "confirm", "execute"]


class _Workflow:
    def __init__(self, *, expected_digest: str | None = None) -> None:
        self.calls: list[str] = []
        self.expected_digest = expected_digest or _requester().digest

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["name"] == "MCPV4ReportB163Test"
        assert kwargs["requester_digest"] == self.expected_digest
        return {"preview_ref": "report-layout-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "report-layout-preview-00000001"
        assert requester_digest == self.expected_digest
        return {"authorization_ref": "report-layout-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "report-layout-authorized-00000001"
        assert requester_digest == self.expected_digest
        return {"outcome": "succeeded"}


class _DeleteWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "report-layout-delete-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "report-layout-delete-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "report-layout-delete-authorized-00000001"}

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "report-layout-delete-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
