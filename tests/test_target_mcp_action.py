from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.target_mcp_action import (
    ProtectedSshTargetMcpAction,
    V4_TARGET_ACTION_FEATURE_ENV,
    V4_TARGET_ACTION_UNAVAILABLE,
    V4_TARGET_DELETE_ACTION_FEATURE_ENV,
    V4_TARGET_DELETE_EXECUTION_ENV,
    V4_TARGET_EXECUTION_ENV,
    V4TargetActionConfigurationError,
    V4TargetActionRuntimeError,
    load_v4_target_action_feature,
    load_v4_target_delete_action_feature,
    load_v4_target_delete_execution_feature,
    load_v4_target_execution_feature,
    target_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_target_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_target_action_feature({}) is False
    assert load_v4_target_action_feature({V4_TARGET_ACTION_FEATURE_ENV: "false"}) is False
    assert load_v4_target_action_feature({V4_TARGET_ACTION_FEATURE_ENV: "true"}) is True
    with pytest.raises(V4TargetActionConfigurationError, match="exactly true or false"):
        load_v4_target_action_feature({V4_TARGET_ACTION_FEATURE_ENV: "TRUE"})


def test_target_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_target_execution_feature({}) is False
    assert load_v4_target_execution_feature({V4_TARGET_EXECUTION_ENV: "true"}) is True
    with pytest.raises(V4TargetActionConfigurationError):
        load_v4_target_execution_feature({V4_TARGET_EXECUTION_ENV: "yes"})


def test_target_delete_host_and_dispatch_gates_default_false_and_are_exact() -> None:
    assert load_v4_target_delete_action_feature({}) is False
    assert load_v4_target_delete_action_feature(
        {V4_TARGET_DELETE_ACTION_FEATURE_ENV: "true"}
    ) is True
    assert load_v4_target_delete_execution_feature({}) is False
    assert load_v4_target_delete_execution_feature(
        {V4_TARGET_DELETE_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4TargetActionConfigurationError):
        load_v4_target_delete_action_feature(
            {V4_TARGET_DELETE_ACTION_FEATURE_ENV: "yes"}
        )
    with pytest.raises(V4TargetActionConfigurationError):
        load_v4_target_delete_execution_feature(
            {V4_TARGET_DELETE_EXECUTION_ENV: "yes"}
        )


def test_target_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedSshTargetMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview("mcp-target-01", "192.0.2.10", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4TargetActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_target_action_requires_the_non_default_operation_scope() -> None:
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

    with pytest.raises(V4TargetActionRuntimeError, match=V4_TARGET_ACTION_UNAVAILABLE):
        target_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]), settings
        )

    assert isinstance(
        target_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_target_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedSshTargetMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-target-01", "192.0.2.10", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(V4TargetActionRuntimeError, match=V4_TARGET_ACTION_UNAVAILABLE):
        action.preview("mcp-target-02", "192.0.2.10", object())


def test_target_delete_has_no_selector_input_and_an_independent_gate() -> None:
    workflow = _Workflow()
    delete_workflow = _DeleteWorkflow()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    action = ProtectedSshTargetMcpAction(
        workflow,
        delete_workflow=delete_workflow,
        delete_execution_enabled=False,
    )

    preview = action.preview_delete(principal)
    confirmation = action.confirm_delete(str(preview["preview_ref"]), principal)
    with pytest.raises(V4TargetActionRuntimeError):
        action.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert delete_workflow.calls == ["preview", "confirm"]

    enabled = ProtectedSshTargetMcpAction(
        workflow,
        execution_enabled=False,
        delete_workflow=delete_workflow,
        delete_execution_enabled=True,
    )
    result = enabled.execute_delete("target-delete-authorized-00000001", principal)
    assert result == {"outcome": "succeeded"}
    assert delete_workflow.calls == ["preview", "confirm", "execute"]


def test_target_delete_tools_fail_closed_when_delete_host_is_not_bound() -> None:
    action = ProtectedSshTargetMcpAction(
        _Workflow(),
        delete_execution_enabled=True,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    with pytest.raises(V4TargetActionRuntimeError):
        action.preview_delete(principal)
    with pytest.raises(V4TargetActionRuntimeError):
        action.confirm_delete("target-delete-preview-00000001", principal)
    with pytest.raises(V4TargetActionRuntimeError):
        action.execute_delete("target-delete-authorized-00000001", principal)


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "target-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "target-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "target-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "target-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _DeleteWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "target-delete-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "target-delete-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "target-delete-authorized-00000001"}

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "target-delete-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


def test_web_target_action_separates_transport_namespaces_and_default_execution(tmp_path) -> None:
    from test_web_target_live_workflow import build
    workflow, transport, _, _ = build(tmp_path, enabled=True)
    action = ProtectedSshTargetMcpAction(object(), execution_enabled=False, web_workflow=workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    other_client = V4PlanningPrincipal(_requester(), "b" * 64)
    preview = action.preview_web(principal)
    with pytest.raises(V4TargetActionRuntimeError):
        action.confirm_web(preview["preview_ref"], other_client)
    confirmed = action.confirm_web(preview["preview_ref"], principal)
    with pytest.raises(V4TargetActionRuntimeError):
        action.execute_web(confirmed["authorization_ref"], other_client)
    assert action.execute_web(confirmed["authorization_ref"], principal)["verified"]
    assert transport.writes == 1
    assert not ProtectedSshTargetMcpAction(object()).web_create_enabled
    with pytest.raises(V4TargetActionRuntimeError):
        action.preview_web(object())
