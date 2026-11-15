from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.template_mcp_action import (
    ProtectedTemplateMcpAction,
    V4_TEMPLATE_ACTION_FEATURE_ENV,
    V4_TEMPLATE_ACTION_UNAVAILABLE,
    V4_TEMPLATE_EXECUTION_ENV,
    V4_TEMPLATE_UPDATE_EXECUTION_ENV,
    V4TemplateActionConfigurationError,
    V4TemplateActionRuntimeError,
    build_v4_template_action,
    load_v4_template_action_feature,
    load_v4_template_execution_feature,
    load_v4_template_update_execution_feature,
    template_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_template_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_template_action_feature({}) is False
    assert load_v4_template_action_feature({V4_TEMPLATE_ACTION_FEATURE_ENV: "false"}) is False
    assert load_v4_template_action_feature({V4_TEMPLATE_ACTION_FEATURE_ENV: "true"}) is True
    with pytest.raises(V4TemplateActionConfigurationError, match="exactly true or false"):
        load_v4_template_action_feature({V4_TEMPLATE_ACTION_FEATURE_ENV: "TRUE"})


@pytest.mark.parametrize(
    ("loader", "variable"),
    (
        (load_v4_template_execution_feature, V4_TEMPLATE_EXECUTION_ENV),
        (load_v4_template_update_execution_feature, V4_TEMPLATE_UPDATE_EXECUTION_ENV),
    ),
)
def test_template_execution_gates_are_disabled_by_default_and_exact(
    loader: object,
    variable: str,
) -> None:
    assert callable(loader)
    assert loader({}) is False
    assert loader({variable: "false"}) is False
    assert loader({variable: "true"}) is True
    with pytest.raises(V4TemplateActionConfigurationError, match="exactly true or false"):
        loader({variable: "TRUE"})


def test_template_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4TemplateActionConfigurationError,
        match=V4_TEMPLATE_ACTION_UNAVAILABLE,
    ):
        build_v4_template_action({V4_TEMPLATE_ACTION_FEATURE_ENV: "true"})


def test_update_gate_requires_a_claim_before_loading_protected_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fortipam_mcp.template_ssh_transport as transport_module
    monkeypatch.setattr(
        transport_module, "load_template_ssh_transport_config",
        lambda _: pytest.fail("missing claim must be rejected before loading login"),
    )

    with pytest.raises(V4TemplateActionConfigurationError):
        build_v4_template_action({V4_TEMPLATE_UPDATE_EXECUTION_ENV: "true"})


@pytest.mark.parametrize("direction", ["restore_default_port", "RESTORE", "arbitrary_port"])
def test_restore_or_invalid_direction_without_rest_rejects_before_login(monkeypatch, direction):
    import fortipam_mcp.template_ssh_transport as transport_module
    monkeypatch.setattr(
        transport_module, "load_template_ssh_transport_config",
        lambda _: pytest.fail("unsupported direction must reject before loading login"),
    )
    with pytest.raises(V4TemplateActionConfigurationError):
        build_v4_template_action({"FORTIPAM_MCP_V4_TEMPLATE_UPDATE_DIRECTION": direction})


def test_template_requires_the_non_default_operation_scope() -> None:
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

    with pytest.raises(V4TemplateActionRuntimeError, match=V4_TEMPLATE_ACTION_UNAVAILABLE):
        template_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        template_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_template_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedTemplateMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-template-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(V4TemplateActionRuntimeError, match=V4_TEMPLATE_ACTION_UNAVAILABLE):
        action.preview("mcp-v4-template-02", object())


def test_template_update_action_binds_requester_and_requires_a_bound_workflow() -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    action = ProtectedTemplateMcpAction(_Workflow(), update_workflow=_UpdateWorkflow())

    preview = action.preview_update("mcp-v4-template-01", principal)
    confirmation = action.confirm_update(str(preview["preview_ref"]), principal)
    result = action.execute_update(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    with pytest.raises(V4TemplateActionRuntimeError, match=V4_TEMPLATE_ACTION_UNAVAILABLE):
        ProtectedTemplateMcpAction(_Workflow()).preview_update(
            "mcp-v4-template-01",
            principal,
        )


def test_template_create_and_update_execution_gates_are_independent() -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    create_workflow = _Workflow()
    update_workflow = _UpdateWorkflow()
    action = ProtectedTemplateMcpAction(
        create_workflow,
        update_workflow=update_workflow,
        execution_enabled=False,
        update_execution_enabled=False,
    )

    create_preview = action.preview("mcp-v4-template-01", principal)
    create_confirmation = action.confirm(str(create_preview["preview_ref"]), principal)
    with pytest.raises(V4TemplateActionRuntimeError, match=V4_TEMPLATE_ACTION_UNAVAILABLE):
        action.execute(str(create_confirmation["authorization_ref"]), principal)

    update_preview = action.preview_update("mcp-v4-template-01", principal)
    update_confirmation = action.confirm_update(str(update_preview["preview_ref"]), principal)
    with pytest.raises(V4TemplateActionRuntimeError, match=V4_TEMPLATE_ACTION_UNAVAILABLE):
        action.execute_update(str(update_confirmation["authorization_ref"]), principal)

    assert create_workflow.calls == ["preview", "confirm"]
    assert update_workflow.calls == ["preview", "confirm"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["template_name"] == "mcp-v4-template-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "template-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "template-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "template-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "template-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _UpdateWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["template_name"] == "mcp-v4-template-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "template-update-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "template-update-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "template-update-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "template-update-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
