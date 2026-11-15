from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.schedule_assign_mcp_action import (
    ProtectedScheduleAssignMcpAction,
    V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV,
    V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE,
    V4_SCHEDULE_ASSIGN_DETACH_EXECUTION_ENV,
    V4_SCHEDULE_ASSIGN_EXECUTION_ENV,
    V4ScheduleAssignActionConfigurationError,
    V4ScheduleAssignActionRuntimeError,
    build_v4_schedule_assign_action,
    load_v4_schedule_assign_action_feature,
    load_v4_schedule_assign_detach_execution_feature,
    load_v4_schedule_assign_execution_feature,
    schedule_assign_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


USER = "mcp-v4-user-b57"
SCHEDULE = "mcp-v4-schedule-b66"


def test_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_schedule_assign_action_feature({}) is False
    assert (
        load_v4_schedule_assign_action_feature(
            {V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_schedule_assign_action_feature(
            {V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4ScheduleAssignActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_schedule_assign_action_feature(
            {V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_schedule_assign_execution_feature({}) is False
    assert (
        load_v4_schedule_assign_execution_feature(
            {V4_SCHEDULE_ASSIGN_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4ScheduleAssignActionConfigurationError):
        load_v4_schedule_assign_execution_feature(
            {V4_SCHEDULE_ASSIGN_EXECUTION_ENV: "yes"}
        )


def test_detach_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_schedule_assign_detach_execution_feature({}) is False
    assert (
        load_v4_schedule_assign_detach_execution_feature(
            {V4_SCHEDULE_ASSIGN_DETACH_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4ScheduleAssignActionConfigurationError):
        load_v4_schedule_assign_detach_execution_feature(
            {V4_SCHEDULE_ASSIGN_DETACH_EXECUTION_ENV: "yes"}
        )


def test_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedScheduleAssignMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview(USER, SCHEDULE, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4ScheduleAssignActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_builder_never_falls_back_to_other_credentials() -> None:
    with pytest.raises(
        V4ScheduleAssignActionConfigurationError,
        match=V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE,
    ):
        build_v4_schedule_assign_action(
            {V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV: "true"}
        )


def test_action_requires_explicit_operation_scope() -> None:
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
        V4ScheduleAssignActionRuntimeError,
        match=V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE,
    ):
        schedule_assign_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]), settings
        )
    assert isinstance(
        schedule_assign_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_failures() -> None:
    workflow = _Workflow()
    action = ProtectedScheduleAssignMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(USER, SCHEDULE, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4ScheduleAssignActionRuntimeError,
        match=V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE,
    ):
        action.preview(USER, SCHEDULE, object())


def test_detach_action_is_requester_bound_and_independently_gated() -> None:
    workflow = _Workflow()
    detach_workflow = _DetachWorkflow()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    denied = ProtectedScheduleAssignMcpAction(
        workflow,
        detach_workflow=detach_workflow,
        detach_execution_enabled=False,
    )
    preview = denied.preview_detach(principal)
    confirmation = denied.confirm_detach(str(preview["preview_ref"]), principal)

    with pytest.raises(V4ScheduleAssignActionRuntimeError):
        denied.execute_detach(str(confirmation["authorization_ref"]), principal)
    assert detach_workflow.calls == ["preview", "confirm"]

    enabled_workflow = _DetachWorkflow()
    enabled = ProtectedScheduleAssignMcpAction(
        workflow,
        detach_workflow=enabled_workflow,
        detach_execution_enabled=True,
    )
    preview = enabled.preview_detach(principal)
    confirmation = enabled.confirm_detach(str(preview["preview_ref"]), principal)
    result = enabled.execute_detach(
        str(confirmation["authorization_ref"]), principal
    )

    assert result["outcome"] == "succeeded"
    assert enabled_workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(V4ScheduleAssignActionRuntimeError):
        enabled.preview_detach(object())


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs == {
            "username": USER,
            "schedule_name": SCHEDULE,
            "requester_digest": _requester().digest,
        }
        return {"preview_ref": "schedule-assign-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "schedule-assign-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "schedule-assign-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "schedule-assign-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _DetachWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "schedule-detach-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "schedule-detach-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "schedule-detach-authorized-00000001"}

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "schedule-detach-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
