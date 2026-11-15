from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.classification_tag_assign_mcp_action import (
    ProtectedClassificationTagAssignMcpAction,
    V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV,
    V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE,
    V4_CLASSIFICATION_TAG_ASSIGN_EXECUTION_ENV,
    V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_EXECUTION_ENV,
    V4ClassificationTagAssignActionConfigurationError,
    V4ClassificationTagAssignActionRuntimeError,
    classification_tag_assign_action_principal_from_access_token,
    load_v4_classification_tag_assign_action_feature,
    load_v4_classification_tag_assign_execution_feature,
    load_v4_classification_tag_assign_rollback_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_assignment_feature_is_disabled_by_default_and_exact() -> None:
    assert load_v4_classification_tag_assign_action_feature({}) is False
    assert (
        load_v4_classification_tag_assign_action_feature(
            {V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_classification_tag_assign_action_feature(
            {V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4ClassificationTagAssignActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_classification_tag_assign_action_feature(
            {V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_assignment_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_classification_tag_assign_execution_feature({}) is False
    assert load_v4_classification_tag_assign_execution_feature(
        {V4_CLASSIFICATION_TAG_ASSIGN_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4ClassificationTagAssignActionConfigurationError):
        load_v4_classification_tag_assign_execution_feature(
            {V4_CLASSIFICATION_TAG_ASSIGN_EXECUTION_ENV: "yes"}
        )


def test_assignment_rollback_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_classification_tag_assign_rollback_execution_feature({}) is False
    assert load_v4_classification_tag_assign_rollback_execution_feature(
        {V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4ClassificationTagAssignActionConfigurationError):
        load_v4_classification_tag_assign_rollback_execution_feature(
            {V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_EXECUTION_ENV: "yes"}
        )


def test_assignment_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedClassificationTagAssignMcpAction(
        workflow,
        execution_enabled=False,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview(
        "mcp-v4-target-update-01",
        "mcp-v4-classification-tag-01",
        principal,
    )
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4ClassificationTagAssignActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_assignment_requires_explicit_operation_scope() -> None:
    resource = "https://mcp.example.test/fpamcp-v4"
    settings = V4PlanningAuthorizationSettings(resource, b"p" * 32)
    token = AccessToken(
        token="opaque-sdk-validated-access-token",
        client_id="client-0001",
        scopes=["fortipam:read", "fortipam:plan"],
        expires_at=2_000_000_000,
        resource=resource,
        subject="operator-0001",
        claims={"iss": "https://mcp.example.test/oauth"},
    )

    with pytest.raises(
        V4ClassificationTagAssignActionRuntimeError,
        match=V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE,
    ):
        classification_tag_assign_action_principal_from_access_token(token, settings)


def test_assignment_action_binds_requester_and_hides_failures() -> None:
    workflow = _Workflow()
    action = ProtectedClassificationTagAssignMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(
        "mcp-v4-target-update-01",
        "mcp-v4-classification-tag-01",
        principal,
    )
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4ClassificationTagAssignActionRuntimeError,
        match=V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE,
    ):
        action.preview(
            "mcp-v4-target-update-01",
            "mcp-v4-classification-tag-01",
            object(),
        )


def test_assignment_rollback_has_no_selector_input_and_independent_gate() -> None:
    workflow = _Workflow()
    rollback_workflow = _RollbackWorkflow()
    action = ProtectedClassificationTagAssignMcpAction(
        workflow,
        rollback_workflow=rollback_workflow,
        execution_enabled=True,
        rollback_execution_enabled=False,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview_rollback(principal)
    confirmation = action.confirm_rollback(str(preview["preview_ref"]), principal)

    with pytest.raises(V4ClassificationTagAssignActionRuntimeError):
        action.execute_rollback(str(confirmation["authorization_ref"]), principal)
    assert rollback_workflow.calls == ["preview", "confirm"]

    enabled = ProtectedClassificationTagAssignMcpAction(
        workflow,
        rollback_workflow=rollback_workflow,
        execution_enabled=False,
        rollback_execution_enabled=True,
    )
    result = enabled.execute_rollback(
        "classification-tag-assign-rollback-authorized-00000001",
        principal,
    )
    assert result == {"outcome": "succeeded"}
    assert rollback_workflow.calls == ["preview", "confirm", "execute"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs == {
            "target_name": "mcp-v4-target-update-01",
            "classification_tag_name": "mcp-v4-classification-tag-01",
            "requester_digest": _requester().digest,
        }
        return {"preview_ref": "classification-tag-assign-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "classification-tag-assign-preview-00000001"
        assert requester_digest == _requester().digest
        return {
            "authorization_ref": "classification-tag-assign-authorized-00000001"
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "classification-tag-assign-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _RollbackWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {
            "preview_ref": "classification-tag-assign-rollback-preview-00000001"
        }

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "classification-tag-assign-rollback-preview-00000001"
        assert requester_digest == _requester().digest
        return {
            "authorization_ref": (
                "classification-tag-assign-rollback-authorized-00000001"
            )
        }

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert (
            authorization_ref
            == "classification-tag-assign-rollback-authorized-00000001"
        )
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
