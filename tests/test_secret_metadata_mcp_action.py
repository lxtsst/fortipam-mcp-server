from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.secret_metadata_mcp_action import (
    ProtectedSecretMetadataMcpAction,
    V4_SECRET_METADATA_ACTION_FEATURE_ENV,
    V4_SECRET_METADATA_ACTION_UNAVAILABLE,
    V4SecretMetadataActionConfigurationError,
    V4SecretMetadataActionRuntimeError,
    load_v4_secret_metadata_action_feature,
    secret_metadata_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_secret_metadata_action_feature({}) is False
    assert load_v4_secret_metadata_action_feature(
        {V4_SECRET_METADATA_ACTION_FEATURE_ENV: "false"}
    ) is False
    assert load_v4_secret_metadata_action_feature(
        {V4_SECRET_METADATA_ACTION_FEATURE_ENV: "true"}
    ) is True
    with pytest.raises(V4SecretMetadataActionConfigurationError, match="exactly true or false"):
        load_v4_secret_metadata_action_feature(
            {V4_SECRET_METADATA_ACTION_FEATURE_ENV: "TRUE"}
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
        V4SecretMetadataActionRuntimeError,
        match=V4_SECRET_METADATA_ACTION_UNAVAILABLE,
    ):
        secret_metadata_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]), settings
        )

    assert isinstance(
        secret_metadata_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedSecretMetadataMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(
        "Public/mcp-v4-folder-01",
        "mcp-v4-secret-metadata-01",
        "Unix Account (SSH Password)",
        principal,
    )
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4SecretMetadataActionRuntimeError,
        match=V4_SECRET_METADATA_ACTION_UNAVAILABLE,
    ):
        action.preview(
            "Public/mcp-v4-folder-01",
            "mcp-v4-secret-metadata-02",
            "Unix Account (SSH Password)",
            object(),
        )


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "secret-metadata-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "secret-metadata-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "secret-metadata-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "secret-metadata-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
