from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.schedule_mcp_action import (
    ProtectedScheduleMcpAction,
    V4_SCHEDULE_ACTION_FEATURE_ENV,
    V4_SCHEDULE_ACTION_UNAVAILABLE,
    V4_SCHEDULE_DELETE_EXECUTION_ENV,
    V4_SCHEDULE_EXECUTION_ENV,
    V4ScheduleActionConfigurationError,
    V4ScheduleActionRuntimeError,
    build_v4_schedule_action,
    load_v4_schedule_action_feature,
    load_v4_schedule_delete_execution_feature,
    load_v4_schedule_execution_feature,
    schedule_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import (
    V4PlanningAuthorizationSettings,
    V4PlanningPrincipal,
)
from test_v4_m3 import _requester


SCHEDULE_NAME = "mcp-v4-schedule-01"


def test_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_schedule_action_feature({}) is False
    assert load_v4_schedule_action_feature({V4_SCHEDULE_ACTION_FEATURE_ENV: "false"}) is False
    assert load_v4_schedule_action_feature({V4_SCHEDULE_ACTION_FEATURE_ENV: "true"}) is True
    with pytest.raises(V4ScheduleActionConfigurationError, match="exactly true or false"):
        load_v4_schedule_action_feature({V4_SCHEDULE_ACTION_FEATURE_ENV: "TRUE"})


def test_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_schedule_execution_feature({}) is False
    assert load_v4_schedule_execution_feature({V4_SCHEDULE_EXECUTION_ENV: "true"}) is True
    with pytest.raises(V4ScheduleActionConfigurationError):
        load_v4_schedule_execution_feature({V4_SCHEDULE_EXECUTION_ENV: "yes"})


def test_schedule_delete_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_schedule_delete_execution_feature({}) is False
    assert load_v4_schedule_delete_execution_feature(
        {V4_SCHEDULE_DELETE_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4ScheduleActionConfigurationError):
        load_v4_schedule_delete_execution_feature(
            {V4_SCHEDULE_DELETE_EXECUTION_ENV: "yes"}
        )


def test_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedScheduleMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview(SCHEDULE_NAME, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4ScheduleActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4ScheduleActionConfigurationError,
        match=V4_SCHEDULE_ACTION_UNAVAILABLE,
    ):
        build_v4_schedule_action({V4_SCHEDULE_ACTION_FEATURE_ENV: "true"})


def test_schedule_requires_the_non_default_operation_scope() -> None:
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
        V4ScheduleActionRuntimeError,
        match=V4_SCHEDULE_ACTION_UNAVAILABLE,
    ):
        schedule_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        schedule_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedScheduleMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(SCHEDULE_NAME, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4ScheduleActionRuntimeError,
        match=V4_SCHEDULE_ACTION_UNAVAILABLE,
    ):
        action.preview(SCHEDULE_NAME, object())


def test_schedule_delete_is_no_input_and_independently_gated() -> None:
    create = _Workflow()
    delete = _DeleteWorkflow()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    denied = ProtectedScheduleMcpAction(
        create,
        delete_workflow=delete,
        delete_execution_enabled=False,
    )
    preview = denied.preview_delete(principal)
    confirmation = denied.confirm_delete(str(preview["preview_ref"]), principal)
    with pytest.raises(V4ScheduleActionRuntimeError):
        denied.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert delete.calls == ["preview", "confirm"]

    enabled = ProtectedScheduleMcpAction(
        create,
        delete_workflow=delete,
        delete_execution_enabled=True,
    )
    result = enabled.execute_delete(
        "schedule-delete-authorized-00000001",
        principal,
    )
    assert result["outcome"] == "succeeded"
    assert delete.calls[-1] == "execute"


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["schedule_name"] == SCHEDULE_NAME
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "schedule-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "schedule-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "schedule-authorized-00000001"}

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "schedule-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _DeleteWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "schedule-delete-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "schedule-delete-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "schedule-delete-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "schedule-delete-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
