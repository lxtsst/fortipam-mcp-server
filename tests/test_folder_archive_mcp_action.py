from __future__ import annotations

import pytest
from types import SimpleNamespace
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.folder_archive_mcp_action import (
    ProtectedFolderArchiveMcpAction,
    V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV,
    V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE,
    V4_FOLDER_ARCHIVE_EXECUTION_ENV,
    V4FolderArchiveActionConfigurationError,
    V4FolderArchiveActionRuntimeError,
    build_v4_folder_archive_action,
    folder_archive_action_principal_from_access_token,
    load_v4_folder_archive_action_feature,
    load_v4_folder_archive_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_folder_archive_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_folder_archive_action_feature({}) is False
    assert (
        load_v4_folder_archive_action_feature(
            {V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_folder_archive_action_feature(
            {V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4FolderArchiveActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_folder_archive_action_feature(
            {V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_folder_archive_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_folder_archive_execution_feature({}) is False
    assert (
        load_v4_folder_archive_execution_feature(
            {V4_FOLDER_ARCHIVE_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4FolderArchiveActionConfigurationError):
        load_v4_folder_archive_execution_feature(
            {V4_FOLDER_ARCHIVE_EXECUTION_ENV: "TRUE"}
        )


def test_enabled_archive_requires_durable_binding_before_transport_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_transport(environment: object) -> None:
        pytest.fail("A missing durable claim must be rejected before transport setup.")

    monkeypatch.setattr(
        "fortipam_mcp.folder_http_transport.load_folder_acl_transport_config",
        unexpected_transport,
    )
    with pytest.raises(
        V4FolderArchiveActionConfigurationError,
        match=V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE,
    ):
        build_v4_folder_archive_action({V4_FOLDER_ARCHIVE_EXECUTION_ENV: "true"})


@pytest.mark.parametrize("reference_flag", ("false", "invalid"))
def test_archive_execution_refuses_missing_or_invalid_reference_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path, reference_flag: str,
) -> None:
    from fortipam_mcp.folder_archive_reference_ssh_transport import ENV_PREFIX
    from fortipam_mcp.folder_archive_mcp_action import V4_FOLDER_ARCHIVE_CLAIM_PATH_ENV

    monkeypatch.setattr("fortipam_mcp.folder_http_transport.load_folder_acl_transport_config",
                        lambda env: SimpleNamespace(base_url="https://pam.example.test"))
    monkeypatch.setattr("fortipam_mcp.folder_archive_reference_ssh_transport.load_folder_archive_reference_config",
                        lambda env: pytest.fail("An invalid reference flag must not load credentials."))
    with pytest.raises(V4FolderArchiveActionConfigurationError):
        build_v4_folder_archive_action({
            V4_FOLDER_ARCHIVE_EXECUTION_ENV: "true",
            V4_FOLDER_ARCHIVE_CLAIM_PATH_ENV: str(tmp_path / "claim.json"),
            ENV_PREFIX + "ENABLED": reference_flag,
        })


def test_folder_archive_action_requires_non_default_operation_scope() -> None:
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
        V4FolderArchiveActionRuntimeError,
        match=V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE,
    ):
        folder_archive_action_principal_from_access_token(token, settings)


def test_folder_archive_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedFolderArchiveMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(42, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4FolderArchiveActionRuntimeError,
        match=V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE,
    ):
        action.preview(42, object())


def test_folder_archive_action_denies_final_dispatch_when_policy_is_off() -> None:
    workflow = _Workflow()
    action = ProtectedFolderArchiveMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(42, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4FolderArchiveActionRuntimeError,
        match=V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE,
    ):
        action.execute(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["preview", "confirm"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["requester_digest"] == _requester().digest
        assert kwargs["folder_id"] == 42
        return {"preview_ref": "folder-archive-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "folder-archive-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "folder-archive-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "folder-archive-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
