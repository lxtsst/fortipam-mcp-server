from __future__ import annotations

from pathlib import Path

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.antivirus_profile_ssh_transport import (
    ENV_PREFIX as PROFILE_SSH_ENV_PREFIX,
)
from fortipam_mcp.client_integrity_mcp_action import (
    ProtectedClientIntegrityMcpAction,
    V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV,
    V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE,
    V4_CLIENT_INTEGRITY_EXECUTION_ENV,
    V4ClientIntegrityActionConfigurationError,
    V4ClientIntegrityActionRuntimeError,
    build_v4_client_integrity_action,
    client_integrity_action_principal_from_access_token,
    load_v4_client_integrity_action_feature,
    load_v4_client_integrity_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_client_integrity_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_client_integrity_action_feature({}) is False
    assert (
        load_v4_client_integrity_action_feature(
            {V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_client_integrity_action_feature(
            {V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4ClientIntegrityActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_client_integrity_action_feature(
            {V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_client_integrity_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_client_integrity_execution_feature({}) is False
    assert load_v4_client_integrity_execution_feature(
        {V4_CLIENT_INTEGRITY_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4ClientIntegrityActionConfigurationError):
        load_v4_client_integrity_execution_feature(
            {V4_CLIENT_INTEGRITY_EXECUTION_ENV: "yes"}
        )


def test_client_integrity_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4ClientIntegrityActionConfigurationError,
        match=V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE,
    ):
        build_v4_client_integrity_action(
            {V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV: "true"}
        )


def test_client_integrity_builder_reuses_current_profile_ssh_binding(
    tmp_path: Path,
) -> None:
    password_file = tmp_path / "ssh-password"
    known_hosts_file = tmp_path / "known-hosts"
    for path, content in (
        (password_file, "opaque-test-password"),
        (known_hosts_file, "fpa.example.test ssh-ed25519 AAAA"),
    ):
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)

    action = build_v4_client_integrity_action(
        {
            PROFILE_SSH_ENV_PREFIX + "ENABLED": "true",
            PROFILE_SSH_ENV_PREFIX + "SSH_HOST": "fpa.example.test",
            PROFILE_SSH_ENV_PREFIX + "SSH_USERNAME": "adminapi",
            PROFILE_SSH_ENV_PREFIX + "SSH_PASSWORD_FILE": str(password_file),
            PROFILE_SSH_ENV_PREFIX + "SSH_KNOWN_HOSTS_FILE": str(known_hosts_file),
            V4_CLIENT_INTEGRITY_EXECUTION_ENV: "false",
        }
    )

    assert isinstance(action, ProtectedClientIntegrityMcpAction)


def test_client_integrity_requires_the_non_default_operation_scope() -> None:
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
        V4ClientIntegrityActionRuntimeError,
        match=V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE,
    ):
        client_integrity_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        client_integrity_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_client_integrity_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedClientIntegrityMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-client-integrity-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4ClientIntegrityActionRuntimeError,
        match=V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-v4-client-integrity-02", object())


def test_client_integrity_action_denies_final_dispatch_when_policy_is_off() -> None:
    workflow = _Workflow()
    action = ProtectedClientIntegrityMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-client-integrity-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4ClientIntegrityActionRuntimeError,
        match=V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE,
    ):
        action.execute(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["preview", "confirm"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["client_software_name"] == "mcp-v4-client-integrity-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "client-integrity-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "client-integrity-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "client-integrity-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "client-integrity-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
