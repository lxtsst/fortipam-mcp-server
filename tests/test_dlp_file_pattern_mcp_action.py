from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.dlp_file_pattern_mcp_action import (
    ProtectedDlpFilePatternMcpAction,
    V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV,
    V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE,
    V4_DLP_FILE_PATTERN_DELETE_EXECUTION_ENV,
    V4_DLP_FILE_PATTERN_EXECUTION_ENV,
    V4DlpFilePatternActionConfigurationError,
    V4DlpFilePatternActionRuntimeError,
    build_v4_dlp_file_pattern_action,
    dlp_file_pattern_action_principal_from_access_token,
    load_v4_dlp_file_pattern_action_feature,
    load_v4_dlp_file_pattern_delete_execution_feature,
    load_v4_dlp_file_pattern_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_dlp_file_pattern_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_dlp_file_pattern_action_feature({}) is False
    assert (
        load_v4_dlp_file_pattern_action_feature(
            {V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_dlp_file_pattern_action_feature(
            {V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4DlpFilePatternActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_dlp_file_pattern_action_feature(
            {V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_dlp_file_pattern_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_dlp_file_pattern_execution_feature({}) is False
    assert (
        load_v4_dlp_file_pattern_execution_feature(
            {V4_DLP_FILE_PATTERN_EXECUTION_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_dlp_file_pattern_execution_feature(
            {V4_DLP_FILE_PATTERN_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4DlpFilePatternActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_dlp_file_pattern_execution_feature(
            {V4_DLP_FILE_PATTERN_EXECUTION_ENV: "TRUE"}
        )


def test_dlp_file_pattern_delete_gate_is_independent_default_false_and_exact() -> None:
    assert load_v4_dlp_file_pattern_delete_execution_feature({}) is False
    assert (
        load_v4_dlp_file_pattern_delete_execution_feature(
            {V4_DLP_FILE_PATTERN_DELETE_EXECUTION_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_dlp_file_pattern_delete_execution_feature(
            {V4_DLP_FILE_PATTERN_DELETE_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4DlpFilePatternActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_dlp_file_pattern_delete_execution_feature(
            {V4_DLP_FILE_PATTERN_DELETE_EXECUTION_ENV: "TRUE"}
        )


def test_dlp_file_pattern_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4DlpFilePatternActionConfigurationError,
        match=V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE,
    ):
        build_v4_dlp_file_pattern_action(
            {V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV: "true"}
        )


def test_dlp_file_pattern_requires_the_non_default_operation_scope() -> None:
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
        V4DlpFilePatternActionRuntimeError,
        match=V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE,
    ):
        dlp_file_pattern_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        dlp_file_pattern_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_dlp_file_pattern_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedDlpFilePatternMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(1001, "mcp-v4-dlp-pattern-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4DlpFilePatternActionRuntimeError,
        match=V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE,
    ):
        action.preview(1002, "mcp-v4-dlp-pattern-02", object())


def test_dlp_file_pattern_execution_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedDlpFilePatternMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(1001, "mcp-v4-dlp-pattern-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4DlpFilePatternActionRuntimeError,
        match=V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE,
    ):
        action.execute(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["preview", "confirm"]


def test_dlp_file_pattern_delete_boundary_has_no_selector_and_separate_gate() -> None:
    workflow = _DeleteWorkflow()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    denied = ProtectedDlpFilePatternMcpAction(
        _Workflow(),
        delete_workflow=workflow,
        delete_execution_enabled=False,
    )

    preview = denied.preview_delete(principal)
    confirmation = denied.confirm_delete(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4DlpFilePatternActionRuntimeError,
        match=V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE,
    ):
        denied.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview_delete", "confirm_delete"]

    workflow = _DeleteWorkflow()
    enabled = ProtectedDlpFilePatternMcpAction(
        _Workflow(),
        delete_workflow=workflow,
        delete_execution_enabled=True,
    )
    preview = enabled.preview_delete(principal)
    confirmation = enabled.confirm_delete(str(preview["preview_ref"]), principal)
    result = enabled.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview_delete", "confirm_delete", "execute_delete"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["pattern_id"] == 1001
        assert kwargs["pattern_name"] == "mcp-v4-dlp-pattern-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "dlp-file-pattern-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "dlp-file-pattern-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "dlp-file-pattern-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "dlp-file-pattern-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _DeleteWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview_delete")
        assert requester_digest == _requester().digest
        return {"preview_ref": "dlp-file-pattern-delete-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm_delete")
        assert preview_ref == "dlp-file-pattern-delete-preview-00000001"
        assert requester_digest == _requester().digest
        return {
            "authorization_ref": "dlp-file-pattern-delete-authorized-00000001"
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute_delete")
        assert authorization_ref == "dlp-file-pattern-delete-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
