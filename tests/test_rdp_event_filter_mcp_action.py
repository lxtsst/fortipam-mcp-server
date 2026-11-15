from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.rdp_event_filter_mcp_action import (
    ProtectedRdpEventFilterMcpAction,
    V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV,
    V4_RDP_EVENT_FILTER_ACTION_UNAVAILABLE,
    V4_RDP_EVENT_FILTER_DELETE_EXECUTION_ENV,
    V4_RDP_EVENT_FILTER_EXECUTION_ENV,
    V4RdpEventFilterActionConfigurationError,
    V4RdpEventFilterActionRuntimeError,
    build_v4_rdp_event_filter_action,
    load_v4_rdp_event_filter_action_feature,
    load_v4_rdp_event_filter_delete_execution_feature,
    load_v4_rdp_event_filter_execution_feature,
    rdp_event_filter_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_rdp_event_filter_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_rdp_event_filter_action_feature({}) is False
    assert (
        load_v4_rdp_event_filter_action_feature(
            {V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_rdp_event_filter_action_feature(
            {V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4RdpEventFilterActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_rdp_event_filter_action_feature(
            {V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_rdp_event_filter_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4RdpEventFilterActionConfigurationError,
        match=V4_RDP_EVENT_FILTER_ACTION_UNAVAILABLE,
    ):
        build_v4_rdp_event_filter_action(
            {V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV: "true"}
        )


def test_rdp_event_filter_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_rdp_event_filter_execution_feature({}) is False
    assert load_v4_rdp_event_filter_execution_feature(
        {V4_RDP_EVENT_FILTER_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4RdpEventFilterActionConfigurationError):
        load_v4_rdp_event_filter_execution_feature(
            {V4_RDP_EVENT_FILTER_EXECUTION_ENV: "yes"}
        )


def test_rdp_event_filter_delete_dispatch_gate_is_independent_and_exact() -> None:
    assert load_v4_rdp_event_filter_delete_execution_feature({}) is False
    assert load_v4_rdp_event_filter_delete_execution_feature(
        {V4_RDP_EVENT_FILTER_DELETE_EXECUTION_ENV: "false"}
    ) is False
    assert load_v4_rdp_event_filter_delete_execution_feature(
        {V4_RDP_EVENT_FILTER_DELETE_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4RdpEventFilterActionConfigurationError):
        load_v4_rdp_event_filter_delete_execution_feature(
            {V4_RDP_EVENT_FILTER_DELETE_EXECUTION_ENV: "TRUE"}
        )


def test_rdp_event_filter_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedRdpEventFilterMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview("mcp-v4-rdp-event-filter-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4RdpEventFilterActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_rdp_event_filter_requires_the_non_default_operation_scope() -> None:
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
        V4RdpEventFilterActionRuntimeError,
        match=V4_RDP_EVENT_FILTER_ACTION_UNAVAILABLE,
    ):
        rdp_event_filter_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        rdp_event_filter_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_rdp_event_filter_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedRdpEventFilterMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-rdp-event-filter-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4RdpEventFilterActionRuntimeError,
        match=V4_RDP_EVENT_FILTER_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-v4-rdp-event-filter-02", object())


def test_rdp_event_filter_delete_binds_requester_and_has_independent_gate() -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    workflow = _DeleteWorkflow()
    denied = ProtectedRdpEventFilterMcpAction(
        _Workflow(),
        delete_workflow=workflow,
    )
    preview = denied.preview_delete(principal)
    confirmation = denied.confirm_delete(str(preview["preview_ref"]), principal)
    with pytest.raises(V4RdpEventFilterActionRuntimeError):
        denied.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]

    workflow = _DeleteWorkflow()
    action = ProtectedRdpEventFilterMcpAction(
        _Workflow(),
        execution_enabled=False,
        delete_workflow=workflow,
        delete_execution_enabled=True,
    )
    preview = action.preview_delete(principal)
    confirmation = action.confirm_delete(str(preview["preview_ref"]), principal)
    result = action.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["profile_name"] == "mcp-v4-rdp-event-filter-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "rdp-event-filter-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "rdp-event-filter-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "rdp-event-filter-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "rdp-event-filter-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _DeleteWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "rdp-event-filter-delete-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "rdp-event-filter-delete-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "rdp-event-filter-delete-authorized-00000001"}

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "rdp-event-filter-delete-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
