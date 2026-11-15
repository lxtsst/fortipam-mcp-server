from __future__ import annotations

from pathlib import Path

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.certificate_csr_mcp_action import (
    ProtectedCertificateCsrMcpAction,
    V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV,
    V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE,
    V4_CERTIFICATE_CSR_EXECUTION_ENV,
    V4CertificateCsrActionConfigurationError,
    V4CertificateCsrActionRuntimeError,
    build_v4_certificate_csr_action,
    certificate_csr_action_principal_from_access_token,
    load_v4_certificate_csr_action_feature,
    load_v4_certificate_csr_execution_feature,
)
from fortipam_mcp.target_http_transport import ENV_PREFIX as TARGET_API_ENV_PREFIX
from fortipam_mcp.v4_plan_runtime import (
    V4PlanningAuthorizationSettings,
    V4PlanningPrincipal,
)
from test_v4_m3 import _requester


def test_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_certificate_csr_action_feature({}) is False
    assert (
        load_v4_certificate_csr_action_feature(
            {V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_certificate_csr_action_feature(
            {V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4CertificateCsrActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_certificate_csr_action_feature(
            {V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_certificate_csr_execution_feature({}) is False
    assert (
        load_v4_certificate_csr_execution_feature(
            {V4_CERTIFICATE_CSR_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4CertificateCsrActionConfigurationError):
        load_v4_certificate_csr_execution_feature(
            {V4_CERTIFICATE_CSR_EXECUTION_ENV: "TRUE"}
        )


def test_action_requires_non_default_operation_scope() -> None:
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
        V4CertificateCsrActionRuntimeError,
        match=V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE,
    ):
        certificate_csr_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        certificate_csr_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedCertificateCsrMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-cert-unit", "127.0.0.1", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4CertificateCsrActionRuntimeError,
        match=V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-v4-cert-unit", "127.0.0.1", object())


def test_action_denies_final_dispatch_when_policy_is_off() -> None:
    workflow = _Workflow()
    action = ProtectedCertificateCsrMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-cert-unit", "127.0.0.1", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4CertificateCsrActionRuntimeError,
        match=V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE,
    ):
        action.execute(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["preview", "confirm"]


def test_builder_reuses_current_central_api_binding(
    tmp_path: Path,
) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("test-ca", encoding="utf-8")
    action = build_v4_certificate_csr_action(
        {
            TARGET_API_ENV_PREFIX + "ENABLED": "true",
            TARGET_API_ENV_PREFIX + "BASE_URL": "https://fpa.example.test",
            TARGET_API_ENV_PREFIX + "API_TOKEN": "opaque-test-token",
            TARGET_API_ENV_PREFIX + "CA_FILE": str(ca_file),
            V4_CERTIFICATE_CSR_EXECUTION_ENV: "false",
        }
    )

    assert isinstance(action, ProtectedCertificateCsrMcpAction)


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "certificate-csr-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "certificate-csr-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "certificate-csr-authorized-00000001"}

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "certificate-csr-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
