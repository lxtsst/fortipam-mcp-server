from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.dlp_sensor_mcp_action import (
    DLP_PROFILE_REGEXP_SENTINEL,
    ProtectedDlpSensorMcpAction,
    V4_DLP_SENSOR_ACTION_FEATURE_ENV,
    V4_DLP_SENSOR_ACTION_UNAVAILABLE,
    V4_DLP_SENSOR_DELETE_EXECUTION_ENV,
    V4_DLP_SENSOR_EXECUTION_ENV,
    V4DlpSensorActionConfigurationError,
    V4DlpSensorActionRuntimeError,
    build_v4_dlp_sensor_action,
    dlp_sensor_action_principal_from_access_token,
    load_v4_dlp_sensor_action_feature,
    load_v4_dlp_sensor_delete_execution_feature,
    load_v4_dlp_sensor_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_dlp_sensor_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_dlp_sensor_action_feature({}) is False
    assert (
        load_v4_dlp_sensor_action_feature({V4_DLP_SENSOR_ACTION_FEATURE_ENV: "false"})
        is False
    )
    assert (
        load_v4_dlp_sensor_action_feature({V4_DLP_SENSOR_ACTION_FEATURE_ENV: "true"})
        is True
    )
    with pytest.raises(V4DlpSensorActionConfigurationError, match="exactly true or false"):
        load_v4_dlp_sensor_action_feature({V4_DLP_SENSOR_ACTION_FEATURE_ENV: "TRUE"})


def test_dlp_sensor_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_dlp_sensor_execution_feature({}) is False
    assert load_v4_dlp_sensor_execution_feature({V4_DLP_SENSOR_EXECUTION_ENV: "false"}) is False
    assert load_v4_dlp_sensor_execution_feature({V4_DLP_SENSOR_EXECUTION_ENV: "true"}) is True
    with pytest.raises(V4DlpSensorActionConfigurationError, match="exactly true or false"):
        load_v4_dlp_sensor_execution_feature({V4_DLP_SENSOR_EXECUTION_ENV: "TRUE"})


def test_dlp_sensor_delete_gate_is_independent_disabled_by_default_and_exact() -> None:
    assert load_v4_dlp_sensor_delete_execution_feature({}) is False
    assert (
        load_v4_dlp_sensor_delete_execution_feature(
            {V4_DLP_SENSOR_DELETE_EXECUTION_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_dlp_sensor_delete_execution_feature(
            {V4_DLP_SENSOR_DELETE_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4DlpSensorActionConfigurationError, match="exactly true or false"):
        load_v4_dlp_sensor_delete_execution_feature(
            {V4_DLP_SENSOR_DELETE_EXECUTION_ENV: "TRUE"}
        )


def test_dlp_sensor_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4DlpSensorActionConfigurationError,
        match=V4_DLP_SENSOR_ACTION_UNAVAILABLE,
    ):
        build_v4_dlp_sensor_action({V4_DLP_SENSOR_ACTION_FEATURE_ENV: "true"})


def test_dlp_sensor_requires_the_non_default_operation_scope() -> None:
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
        V4DlpSensorActionRuntimeError,
        match=V4_DLP_SENSOR_ACTION_UNAVAILABLE,
    ):
        dlp_sensor_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        dlp_sensor_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_dlp_sensor_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedDlpSensorMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(
        "mcp-v4-dlp-sensor-01",
        1001,
        "mcp-v4-dlp-pattern-01",
        principal,
    )
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4DlpSensorActionRuntimeError,
        match=V4_DLP_SENSOR_ACTION_UNAVAILABLE,
    ):
        action.preview(
            "mcp-v4-dlp-sensor-02",
            1002,
            "mcp-v4-dlp-pattern-02",
            object(),
        )


def test_dlp_sensor_execution_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedDlpSensorMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(
        "mcp-v4-dlp-sensor-01",
        1001,
        "mcp-v4-dlp-pattern-01",
        principal,
    )
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4DlpSensorActionRuntimeError,
        match=V4_DLP_SENSOR_ACTION_UNAVAILABLE,
    ):
        action.execute(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["preview", "confirm"]


def test_dlp_sensor_delete_flow_is_no_input_and_independently_gated() -> None:
    workflow = _Workflow()
    delete_workflow = _DeleteWorkflow()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    denied = ProtectedDlpSensorMcpAction(
        workflow,
        delete_workflow=delete_workflow,
        delete_execution_enabled=False,
    )

    preview = denied.preview_delete(principal)
    confirmation = denied.confirm_delete(str(preview["preview_ref"]), principal)
    with pytest.raises(V4DlpSensorActionRuntimeError, match=V4_DLP_SENSOR_ACTION_UNAVAILABLE):
        denied.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert delete_workflow.calls == ["preview", "confirm"]

    delete_workflow = _DeleteWorkflow()
    allowed = ProtectedDlpSensorMcpAction(
        workflow,
        delete_workflow=delete_workflow,
        delete_execution_enabled=True,
    )
    preview = allowed.preview_delete(principal)
    confirmation = allowed.confirm_delete(str(preview["preview_ref"]), principal)
    result = allowed.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert result["outcome"] == "succeeded"
    assert delete_workflow.calls == ["preview", "confirm", "execute"]


def test_dlp_sensor_action_routes_fixed_regexp_profile_without_expanding_tools() -> None:
    pdf_workflow = _Workflow()
    regexp_workflow = _RegexpWorkflow()
    action = ProtectedDlpSensorMcpAction(pdf_workflow, regexp_workflow=regexp_workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(
        "mcp-v4-dlp-regexp-sensor-01",
        None,
        None,
        principal,
        DLP_PROFILE_REGEXP_SENTINEL,
    )
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert pdf_workflow.calls == []
    assert regexp_workflow.calls == ["preview", "confirm", "execute"]


def test_dlp_sensor_action_rejects_unbound_or_nonfixed_regexp_profile() -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    action = ProtectedDlpSensorMcpAction(_Workflow())

    with pytest.raises(
        V4DlpSensorActionRuntimeError,
        match=V4_DLP_SENSOR_ACTION_UNAVAILABLE,
    ):
        action.preview(
            "mcp-v4-dlp-regexp-sensor-01",
            None,
            None,
            principal,
            DLP_PROFILE_REGEXP_SENTINEL,
        )
    with pytest.raises(
        V4DlpSensorActionRuntimeError,
        match=V4_DLP_SENSOR_ACTION_UNAVAILABLE,
    ):
        action.preview(
            "mcp-v4-dlp-regexp-sensor-01",
            1001,
            "mcp-v4-dlp-pattern-01",
            principal,
            DLP_PROFILE_REGEXP_SENTINEL,
        )
    with pytest.raises(
        V4DlpSensorActionRuntimeError,
        match=V4_DLP_SENSOR_ACTION_UNAVAILABLE,
    ):
        action.confirm("dlp-regexp-sensor-preview-00000001", principal)


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["sensor_name"] == "mcp-v4-dlp-sensor-01"
        assert kwargs["file_pattern_id"] == 1001
        assert kwargs["file_pattern_name"] == "mcp-v4-dlp-pattern-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "dlp-sensor-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "dlp-sensor-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "dlp-sensor-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "dlp-sensor-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _RegexpWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["sensor_name"] == "mcp-v4-dlp-regexp-sensor-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "dlp-regexp-sensor-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "dlp-regexp-sensor-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "dlp-regexp-sensor-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "dlp-regexp-sensor-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _DeleteWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "dlp-sensor-delete-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "dlp-sensor-delete-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "dlp-sensor-delete-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "dlp-sensor-delete-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
