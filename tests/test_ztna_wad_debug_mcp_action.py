from __future__ import annotations

from pathlib import Path

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.antivirus_profile_ssh_transport import (
    ENV_PREFIX as PROFILE_SSH_ENV_PREFIX,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from fortipam_mcp.ztna_wad_debug_mcp_action import (
    ProtectedZtnaWadDebugMcpAction,
    V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV,
    V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE,
    V4_ZTNA_WAD_DEBUG_CAPTURE_WINDOW_ENV,
    V4_ZTNA_WAD_DEBUG_EXECUTION_ENV,
    V4ZtnaWadDebugActionConfigurationError,
    V4ZtnaWadDebugActionRuntimeError,
    build_v4_ztna_wad_debug_action,
    load_v4_ztna_wad_debug_action_feature,
    load_v4_ztna_wad_debug_execution_feature,
    ztna_wad_debug_action_principal_from_access_token,
)
from test_v4_m3 import _requester


def test_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_ztna_wad_debug_action_feature({}) is False
    assert load_v4_ztna_wad_debug_action_feature(
        {V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV: "true"}
    ) is True
    with pytest.raises(V4ZtnaWadDebugActionConfigurationError):
        load_v4_ztna_wad_debug_action_feature(
            {V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV: "yes"}
        )


def test_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4ZtnaWadDebugActionConfigurationError,
        match=V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE,
    ):
        build_v4_ztna_wad_debug_action(
            {V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV: "true"}
        )


def test_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_ztna_wad_debug_execution_feature({}) is False
    assert load_v4_ztna_wad_debug_execution_feature(
        {V4_ZTNA_WAD_DEBUG_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4ZtnaWadDebugActionConfigurationError):
        load_v4_ztna_wad_debug_execution_feature(
            {V4_ZTNA_WAD_DEBUG_EXECUTION_ENV: "yes"}
        )


def test_builder_reuses_current_profile_ssh_binding(tmp_path: Path) -> None:
    password_file = tmp_path / "ssh-password"
    known_hosts_file = tmp_path / "known-hosts"
    for path, content in (
        (password_file, "opaque-test-password"),
        (known_hosts_file, "fpa.example.test ssh-ed25519 AAAA"),
    ):
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)

    action = build_v4_ztna_wad_debug_action(
        {
            PROFILE_SSH_ENV_PREFIX + "ENABLED": "true",
            PROFILE_SSH_ENV_PREFIX + "SSH_HOST": "fpa.example.test",
            PROFILE_SSH_ENV_PREFIX + "SSH_USERNAME": "adminapi",
            PROFILE_SSH_ENV_PREFIX + "SSH_PASSWORD_FILE": str(password_file),
            PROFILE_SSH_ENV_PREFIX + "SSH_KNOWN_HOSTS_FILE": str(known_hosts_file),
            V4_ZTNA_WAD_DEBUG_CAPTURE_WINDOW_ENV: "10",
            V4_ZTNA_WAD_DEBUG_EXECUTION_ENV: "false",
        }
    )

    assert isinstance(action, ProtectedZtnaWadDebugMcpAction)


def test_action_requires_the_nondefault_operation_scope() -> None:
    resource = "https://mcp.example.test/fpamcp-v4"
    settings = V4PlanningAuthorizationSettings(resource, b"p" * 32)
    token = AccessToken(
        token="opaque-sdk-validated-access-token",
        client_id="client-0001",
        scopes=["fortipam:read", "fortipam:plan", "fortipam:operate"],
        expires_at=2_000_000_000,
        resource=resource,
        subject="operator-0001",
        claims={"iss": "https://mcp.example.test/oauth"},
    )
    assert isinstance(
        ztna_wad_debug_action_principal_from_access_token(token, settings),
        V4PlanningPrincipal,
    )
    missing_scope = AccessToken(
        token="opaque-sdk-validated-access-token",
        client_id="client-0001",
        scopes=["fortipam:read", "fortipam:plan"],
        expires_at=2_000_000_000,
        resource=resource,
        subject="operator-0001",
        claims={"iss": "https://mcp.example.test/oauth"},
    )
    with pytest.raises(V4ZtnaWadDebugActionRuntimeError):
        ztna_wad_debug_action_principal_from_access_token(missing_scope, settings)


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedZtnaWadDebugMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview(principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)
    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(V4ZtnaWadDebugActionRuntimeError):
        action.preview(object())


def test_action_denies_final_dispatch_when_policy_is_off() -> None:
    workflow = _Workflow()
    action = ProtectedZtnaWadDebugMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4ZtnaWadDebugActionRuntimeError,
        match=V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE,
    ):
        action.execute(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["preview", "confirm"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "ztna-wad-debug-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "ztna-wad-debug-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "ztna-wad-debug-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "ztna-wad-debug-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
