from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.classification_tag_mcp_action import (
    ProtectedClassificationTagMcpAction,
    V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV,
    V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE,
    V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV,
    V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV,
    V4_CLASSIFICATION_TAG_EXECUTION_ENV,
    V4ClassificationTagActionConfigurationError,
    V4ClassificationTagActionRuntimeError,
    classification_tag_action_principal_from_access_token,
    load_v4_classification_tag_action_feature,
    load_v4_classification_tag_delete_execution_feature,
    load_v4_classification_tag_delete_action_feature,
    load_v4_classification_tag_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_feature_flag_is_disabled_by_default_and_requires_exact_value() -> None:
    assert load_v4_classification_tag_action_feature({}) is False
    assert (
        load_v4_classification_tag_action_feature(
            {V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_classification_tag_action_feature(
            {V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4ClassificationTagActionConfigurationError, match="exactly true or false"):
        load_v4_classification_tag_action_feature(
            {V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_classification_tag_execution_feature({}) is False
    assert load_v4_classification_tag_execution_feature(
        {V4_CLASSIFICATION_TAG_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4ClassificationTagActionConfigurationError):
        load_v4_classification_tag_execution_feature(
            {V4_CLASSIFICATION_TAG_EXECUTION_ENV: "yes"}
        )


def test_delete_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_classification_tag_delete_execution_feature({}) is False
    assert load_v4_classification_tag_delete_execution_feature(
        {V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4ClassificationTagActionConfigurationError):
        load_v4_classification_tag_delete_execution_feature(
            {V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV: "yes"}
        )


def test_delete_host_feature_defaults_false_and_is_exact() -> None:
    assert load_v4_classification_tag_delete_action_feature({}) is False
    assert load_v4_classification_tag_delete_action_feature(
        {V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV: "true"}
    ) is True
    with pytest.raises(V4ClassificationTagActionConfigurationError):
        load_v4_classification_tag_delete_action_feature(
            {V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV: "yes"}
        )


def test_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedClassificationTagMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview("mcp-classification-tag-01", "Lab marker", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4ClassificationTagActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_action_requires_the_non_default_operation_scope() -> None:
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
        V4ClassificationTagActionRuntimeError,
        match=V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE,
    ):
        classification_tag_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]), settings
        )

    assert isinstance(
        classification_tag_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedClassificationTagMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-classification-tag-01", "Lab marker", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4ClassificationTagActionRuntimeError,
        match=V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-classification-tag-02", "Lab marker", object())


def test_delete_has_no_selector_input_and_independent_gate() -> None:
    workflow = _Workflow()
    delete_workflow = _DeleteWorkflow()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    action = ProtectedClassificationTagMcpAction(
        workflow,
        delete_workflow=delete_workflow,
        execution_enabled=True,
        delete_execution_enabled=False,
    )

    preview = action.preview_delete(principal)
    confirmation = action.confirm_delete(str(preview["preview_ref"]), principal)
    with pytest.raises(V4ClassificationTagActionRuntimeError):
        action.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert delete_workflow.calls == ["preview", "confirm"]

    enabled = ProtectedClassificationTagMcpAction(
        workflow,
        delete_workflow=delete_workflow,
        execution_enabled=False,
        delete_execution_enabled=True,
    )
    result = enabled.execute_delete(
        "classification-tag-delete-authorized-00000001",
        principal,
    )
    assert result == {"outcome": "succeeded"}
    assert delete_workflow.calls == ["preview", "confirm", "execute"]


def test_delete_tools_fail_closed_when_delete_host_is_not_bound() -> None:
    action = ProtectedClassificationTagMcpAction(
        _Workflow(),
        delete_execution_enabled=True,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    with pytest.raises(
        V4ClassificationTagActionRuntimeError,
        match=V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE,
    ):
        action.preview_delete(principal)
    with pytest.raises(
        V4ClassificationTagActionRuntimeError,
        match=V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE,
    ):
        action.confirm_delete("classification-tag-delete-preview-00000001", principal)
    with pytest.raises(
        V4ClassificationTagActionRuntimeError,
        match=V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE,
    ):
        action.execute_delete(
            "classification-tag-delete-authorized-00000001",
            principal,
        )


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "classification-tag-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "classification-tag-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "classification-tag-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "classification-tag-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _DeleteWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "classification-tag-delete-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "classification-tag-delete-preview-00000001"
        assert requester_digest == _requester().digest
        return {
            "authorization_ref": "classification-tag-delete-authorized-00000001"
        }

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "classification-tag-delete-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
