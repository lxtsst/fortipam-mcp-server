from __future__ import annotations

import inspect

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.address_group_mcp_action import (
    ProtectedAddressGroupMcpAction,
    V4_ADDRESS_GROUP_ACTION_FEATURE_ENV,
    V4_ADDRESS_GROUP_ACTION_UNAVAILABLE,
    V4_ADDRESS_GROUP_DELETE_EXECUTION_ENV,
    V4_ADDRESS_GROUP_EXECUTION_ENV,
    V4AddressGroupActionConfigurationError,
    V4AddressGroupActionRuntimeError,
    address_group_action_principal_from_access_token,
    build_v4_address_group_action,
    load_v4_address_group_action_feature,
    load_v4_address_group_delete_execution_feature,
    load_v4_address_group_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_feature_flag_is_disabled_by_default_and_requires_exact_value() -> None:
    assert load_v4_address_group_action_feature({}) is False
    assert (
        load_v4_address_group_action_feature(
            {V4_ADDRESS_GROUP_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_address_group_action_feature(
            {V4_ADDRESS_GROUP_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4AddressGroupActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_address_group_action_feature(
            {V4_ADDRESS_GROUP_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_address_group_execution_feature({}) is False
    assert load_v4_address_group_execution_feature(
        {V4_ADDRESS_GROUP_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4AddressGroupActionConfigurationError):
        load_v4_address_group_execution_feature(
            {V4_ADDRESS_GROUP_EXECUTION_ENV: "yes"}
        )


def test_delete_dispatch_gate_is_independent_default_false_and_exact() -> None:
    assert load_v4_address_group_delete_execution_feature({}) is False
    assert load_v4_address_group_delete_execution_feature(
        {V4_ADDRESS_GROUP_DELETE_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4AddressGroupActionConfigurationError):
        load_v4_address_group_delete_execution_feature(
            {V4_ADDRESS_GROUP_DELETE_EXECUTION_ENV: "TRUE"}
        )


def test_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedAddressGroupMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview("mcp-address-group-01", "mcp-address-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4AddressGroupActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_builder_requires_dedicated_cli_and_member_read_configuration() -> None:
    with pytest.raises(
        V4AddressGroupActionConfigurationError,
        match=V4_ADDRESS_GROUP_ACTION_UNAVAILABLE,
    ):
        build_v4_address_group_action(
            {V4_ADDRESS_GROUP_ACTION_FEATURE_ENV: "true"}
        )


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
        V4AddressGroupActionRuntimeError,
        match=V4_ADDRESS_GROUP_ACTION_UNAVAILABLE,
    ):
        address_group_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )
    assert isinstance(
        address_group_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedAddressGroupMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-address-group-01", "mcp-address-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4AddressGroupActionRuntimeError,
        match=V4_ADDRESS_GROUP_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-address-group-02", "mcp-address-02", object())


def test_delete_boundary_has_no_selector_and_obeys_separate_gate() -> None:
    delete = _DeleteWorkflow()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    action = ProtectedAddressGroupMcpAction(
        _Workflow(),
        delete_workflow=delete,
        delete_execution_enabled=False,
    )

    preview = action.preview_delete(principal)
    confirmation = action.confirm_delete(str(preview["preview_ref"]), principal)
    with pytest.raises(V4AddressGroupActionRuntimeError):
        action.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert delete.calls == ["preview", "confirm"]
    assert list(inspect.signature(action.preview_delete).parameters) == ["principal"]

    enabled = ProtectedAddressGroupMcpAction(
        _Workflow(),
        delete_workflow=delete,
        delete_execution_enabled=True,
    )
    result = enabled.execute_delete("address-group-delete-authorized-1", principal)
    assert result["outcome"] == "succeeded"
    assert delete.calls[-1] == "execute"


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["group_name"] == "mcp-address-group-01"
        assert kwargs["member_name"] == "mcp-address-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "address-group-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "address-group-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "address-group-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "address-group-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _DeleteWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "address-group-delete-preview-1"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "address-group-delete-preview-1"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "address-group-delete-authorized-1"}

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "address-group-delete-authorized-1"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
