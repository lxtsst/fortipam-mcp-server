from __future__ import annotations

from pathlib import Path

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.template_archive_mcp_action import (
    ProtectedTemplateArchiveMcpAction,
    V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV,
    V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE,
    V4_TEMPLATE_ARCHIVE_EXECUTION_ENV,
    V4TemplateArchiveActionConfigurationError,
    V4TemplateArchiveActionRuntimeError,
    _TemplateArchiveApiSshInspectionTransport,
    build_v4_template_archive_action,
    load_v4_template_archive_action_feature,
    load_v4_template_archive_execution_feature,
    template_archive_action_principal_from_access_token,
)
from fortipam_mcp.template_reconciliation_http_transport import TemplateBaselineReadback
from fortipam_mcp.template_ssh_transport import (
    ENV_PREFIX as TEMPLATE_SSH_ENV_PREFIX,
    TemplateArchiveAbsenceReadback,
    TemplateArchivePreflightReadback,
)
from fortipam_mcp.template_reconciliation_http_transport import (
    ENV_PREFIX as TEMPLATE_API_ENV_PREFIX,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


NAME = "mcp-v4-template-archive-01"


def test_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_template_archive_action_feature({}) is False
    assert load_v4_template_archive_action_feature(
        {V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV: "true"}
    ) is True
    with pytest.raises(V4TemplateArchiveActionConfigurationError):
        load_v4_template_archive_action_feature(
            {V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV: "yes"}
        )


def test_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_template_archive_execution_feature({}) is False
    assert load_v4_template_archive_execution_feature(
        {V4_TEMPLATE_ARCHIVE_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4TemplateArchiveActionConfigurationError):
        load_v4_template_archive_execution_feature(
            {V4_TEMPLATE_ARCHIVE_EXECUTION_ENV: "yes"}
        )


def test_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4TemplateArchiveActionConfigurationError,
        match=V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE,
    ):
        build_v4_template_archive_action(
            {V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV: "true"}
        )


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

    with pytest.raises(V4TemplateArchiveActionRuntimeError):
        template_archive_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )
    assert isinstance(
        template_archive_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedTemplateArchiveMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(NAME, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(V4TemplateArchiveActionRuntimeError):
        action.preview(NAME, object())


def test_action_denies_final_dispatch_when_policy_is_off() -> None:
    workflow = _Workflow()
    action = ProtectedTemplateArchiveMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(NAME, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4TemplateArchiveActionRuntimeError,
        match=V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE,
    ):
        action.execute(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["preview", "confirm"]


def test_builder_reuses_current_template_api_and_ssh_bindings(tmp_path: Path) -> None:
    token_file = tmp_path / "api-token"
    password_file = tmp_path / "ssh-password"
    known_hosts_file = tmp_path / "known-hosts"
    for path, content in (
        (token_file, "opaque-test-token"),
        (password_file, "opaque-test-password"),
        (known_hosts_file, "fpa.example.test ssh-ed25519 AAAA"),
    ):
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)

    action = build_v4_template_archive_action(
        {
            TEMPLATE_API_ENV_PREFIX + "ENABLED": "true",
            TEMPLATE_API_ENV_PREFIX + "BASE_URL": "https://fpa.example.test",
            TEMPLATE_API_ENV_PREFIX + "API_TOKEN_FILE": str(token_file),
            TEMPLATE_SSH_ENV_PREFIX + "ENABLED": "true",
            TEMPLATE_SSH_ENV_PREFIX + "SSH_HOST": "fpa.example.test",
            TEMPLATE_SSH_ENV_PREFIX + "SSH_USERNAME": "adminapi",
            TEMPLATE_SSH_ENV_PREFIX + "SSH_PASSWORD_FILE": str(password_file),
            TEMPLATE_SSH_ENV_PREFIX + "SSH_KNOWN_HOSTS_FILE": str(known_hosts_file),
            V4_TEMPLATE_ARCHIVE_EXECUTION_ENV: "false",
        }
    )

    assert isinstance(action, ProtectedTemplateArchiveMcpAction)


def test_archive_inspection_uses_api_shape_and_ssh_reference_evidence() -> None:
    api = _ApiInspection()
    ssh = _SshInspection()
    inspection = _TemplateArchiveApiSshInspectionTransport(api, ssh)

    preflight = inspection.archive_preflight_readback(NAME)

    assert preflight.verified is True
    assert api.calls == [NAME]
    assert ssh.preflight_calls == [NAME]
    assert inspection.archive_absence_readback(NAME).verified is True
    assert ssh.absence_calls == [NAME]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["template_name"] == NAME
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "template-archive-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "template-archive-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "template-archive-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "template-archive-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _ApiInspection:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def read_default_web_vnc_baseline(self, template_name: str) -> TemplateBaselineReadback:
        self.calls.append(template_name)
        return TemplateBaselineReadback(True, True, True, True, True, True, True, True)


class _SshInspection:
    def __init__(self) -> None:
        self.preflight_calls: list[str] = []
        self.absence_calls: list[str] = []

    def archive_preflight_readback(self, template_name: str) -> TemplateArchivePreflightReadback:
        self.preflight_calls.append(template_name)
        return TemplateArchivePreflightReadback(
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            True,
            True,
        )

    def archive_absence_readback(self, template_name: str) -> TemplateArchiveAbsenceReadback:
        self.absence_calls.append(template_name)
        return TemplateArchiveAbsenceReadback(True, True, True)
