from __future__ import annotations

from pathlib import Path

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.antivirus_profile_ssh_transport import (
    ENV_PREFIX as PROFILE_SSH_ENV_PREFIX,
)
from fortipam_mcp.active_launch_mcp_action import (
    ProtectedActiveLaunchMcpAction,
    V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV,
    V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE,
    V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENV,
    V4ActiveLaunchActionConfigurationError,
    V4ActiveLaunchActionRuntimeError,
    active_launch_action_principal_from_access_token,
    build_v4_active_launch_action,
    load_v4_active_launch_action_feature,
    load_v4_active_launch_disconnect_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_active_launch_action_feature({}) is False
    assert load_v4_active_launch_action_feature(
        {V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV: "true"}
    ) is True
    with pytest.raises(V4ActiveLaunchActionConfigurationError):
        load_v4_active_launch_action_feature(
            {V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV: "yes"}
        )


def test_disconnect_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_active_launch_disconnect_execution_feature({}) is False
    assert load_v4_active_launch_disconnect_execution_feature(
        {V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4ActiveLaunchActionConfigurationError):
        load_v4_active_launch_disconnect_execution_feature(
            {V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENV: "yes"}
        )


def test_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4ActiveLaunchActionConfigurationError,
        match=V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE,
    ):
        build_v4_active_launch_action({V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV: "true"})


def test_builder_reuses_current_profile_ssh_binding(tmp_path: Path) -> None:
    password_file = tmp_path / "ssh-password"
    known_hosts_file = tmp_path / "known-hosts"
    for path, content in (
        (password_file, "opaque-test-password"),
        (known_hosts_file, "fpa.example.test ssh-ed25519 AAAA"),
    ):
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)

    action = build_v4_active_launch_action(
        {
            PROFILE_SSH_ENV_PREFIX + "ENABLED": "true",
            PROFILE_SSH_ENV_PREFIX + "SSH_HOST": "fpa.example.test",
            PROFILE_SSH_ENV_PREFIX + "SSH_USERNAME": "adminapi",
            PROFILE_SSH_ENV_PREFIX + "SSH_PASSWORD_FILE": str(password_file),
            PROFILE_SSH_ENV_PREFIX + "SSH_KNOWN_HOSTS_FILE": str(known_hosts_file),
            V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENV: "false",
        }
    )

    assert isinstance(action, ProtectedActiveLaunchMcpAction)


def test_action_requires_the_nondefault_operation_scope() -> None:
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

    with pytest.raises(V4ActiveLaunchActionRuntimeError):
        active_launch_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )
    assert isinstance(
        active_launch_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedActiveLaunchMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    observation = action.observe(principal)
    preview = action.preview_disconnect(str(observation["launch_ref"]), principal)
    confirmation = action.confirm_disconnect(str(preview["preview_ref"]), principal)
    result = action.execute_disconnect(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["observe", "preview", "confirm", "execute"]
    with pytest.raises(V4ActiveLaunchActionRuntimeError):
        action.observe(object())


def test_action_denies_disconnect_dispatch_when_policy_is_off() -> None:
    workflow = _Workflow()
    action = ProtectedActiveLaunchMcpAction(
        workflow,
        disconnect_execution_enabled=False,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    observation = action.observe(principal)
    preview = action.preview_disconnect(str(observation["launch_ref"]), principal)
    confirmation = action.confirm_disconnect(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4ActiveLaunchActionRuntimeError,
        match=V4_ACTIVE_LAUNCH_ACTION_UNAVAILABLE,
    ):
        action.execute_disconnect(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["observe", "preview", "confirm"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def observe(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("observe")
        assert requester_digest == _requester().digest
        return {"launch_ref": "active-launch-ref-00000001"}

    def preview_disconnect(
        self,
        launch_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("preview")
        assert launch_ref == "active-launch-ref-00000001"
        assert requester_digest == _requester().digest
        return {"preview_ref": "active-launch-disconnect-preview-00000001"}

    def confirm_disconnect(
        self,
        preview_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "active-launch-disconnect-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "active-launch-disconnect-authorized-00000001"}

    def execute_disconnect(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "active-launch-disconnect-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
