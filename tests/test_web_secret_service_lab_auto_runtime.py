from dataclasses import replace
from types import SimpleNamespace

import pytest

from fortipam_mcp.web_secret_service_lab_auto_runtime import (
    ENV_PREFIX,
    LAB_AUTO_WEB_SECRET_SERVICE_AUTHORITY_REF,
    LabAutoWebSecretServicePromoter,
    LabAutoWebSecretServiceRunnerFactory,
    WebSecretServiceLabAutoConfigurationError,
    _metadata_target_matches_ssh_host,
    _service_from_confirmed_summary,
    load_web_secret_service_ssh_transport,
)
from fortipam_mcp.web_secret_service_ssh_transport import FortiPamWebSecretServiceSshTransport
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataProjectionInspection
from fortipam_mcp.onboarding_execution_mcp_action import (
    ProtectedSecretOnboardingMcpAction,
    V4OnboardingExecutionRuntimeError,
)
from v4_planning import InMemoryM4ExecutionStateStore
from test_web_secret_service_m4_authorization import (
    _claimed_chain,
    _onboarding_binding,
    _service_binding,
)


def _transport_environment(tmp_path):
    password = tmp_path / "password"
    password.write_text("synthetic-test-password\n", encoding="utf-8")
    password.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("test-host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n")
    known_hosts.chmod(0o600)
    return {
        f"{ENV_PREFIX}ENABLED": "true",
        f"{ENV_PREFIX}API_UNAVAILABLE_REASON": "rest-field-replacement-20260915",
        f"{ENV_PREFIX}SSH_HOST": "test-host",
        f"{ENV_PREFIX}SSH_USERNAME": "operator",
        f"{ENV_PREFIX}SSH_PASSWORD_FILE": str(password),
        f"{ENV_PREFIX}SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }


def test_fixed_ssh_loader_requires_the_documented_rest_fallback_reason(tmp_path) -> None:
    environment = _transport_environment(tmp_path)

    transport = load_web_secret_service_ssh_transport(environment)

    assert type(transport).__name__ == "FortiPamWebSecretServiceSshTransport"
    environment[f"{ENV_PREFIX}API_UNAVAILABLE_REASON"] = "other-reason"
    with pytest.raises(WebSecretServiceLabAutoConfigurationError):
        load_web_secret_service_ssh_transport(environment)


def test_rest_observer_and_ssh_writer_must_address_the_same_appliance(tmp_path) -> None:
    environment = _transport_environment(tmp_path)

    assert _metadata_target_matches_ssh_host("https://test-host", environment) is True
    assert _metadata_target_matches_ssh_host("https://other-host", environment) is False


def test_service_binding_is_derived_only_from_the_exact_confirmed_transition() -> None:
    planning, _, plan, _ = _claimed_chain()
    summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
    onboarding = _onboarding_binding()

    binding = _service_from_confirmed_summary(summary, onboarding)

    assert binding.object_ref == onboarding.service_object_ref
    assert binding.secret_id == onboarding.existing_secret_id
    bad_changes = tuple(
        replace(
            change,
            expected_fields=(
                ("exists", True), ("http_service_enabled", False),
            ),
        )
        if change.object_ref == onboarding.service_object_ref else change
        for change in summary.object_changes
    )
    with pytest.raises(Exception):
        _service_from_confirmed_summary(
            replace(summary, object_changes=bad_changes),
            onboarding,
        )


def test_lab_auto_promotes_confirmed_bp007_without_an_m3_receipt() -> None:
    planning, _, plan, _ = _claimed_chain()
    summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
    confirmation = planning.get_confirmation(plan.confirmation_ref)
    promoter = LabAutoWebSecretServicePromoter(
        b"a" * 32,
        authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
    )

    artifacts = promoter.promote(
        summary, confirmation, plan, _service_binding(),
        onboarding_binding=_onboarding_binding(), now_epoch=summary.created_at + 5,
    )

    assert artifacts.binding.authorization.approval_ref == LAB_AUTO_WEB_SECRET_SERVICE_AUTHORITY_REF
    assert artifacts.binding.authorization.one_time is True


def test_lab_auto_factory_executes_one_cpe_chain_without_receipt_access() -> None:
    claimed, _, plan, _ = _claimed_chain()
    summary = claimed.get_summary(plan.summary_ref, plan.summary_revision)
    confirmation = claimed.get_confirmation(plan.confirmation_ref)

    class NoReceiptPlanningReader:
        def get_plan(self, plan_ref):
            assert plan_ref == plan.plan_ref
            return plan

        def get_summary(self, summary_ref, revision):
            assert (summary_ref, revision) == (plan.summary_ref, plan.summary_revision)
            return summary

        def get_confirmation(self, confirmation_ref):
            assert confirmation_ref == plan.confirmation_ref
            return confirmation

        def __getattr__(self, name):
            raise AssertionError(f"receipt path must not be used: {name}")

    baseline = SecretMetadataProjectionInspection(
        True, True, True, True, True, True, True, False,
        recording_matches=True,
    )

    class Reader:
        value = baseline

        def inspect_web_projection(self, folder, name, template, *, expected_secret_id):
            assert (folder, name, template, expected_secret_id) == (
                "Public/folder", "mcp-v4-web-secret", "Web Account", 24,
            )
            return self.value

    reader = Reader()

    class MockWriter:
        calls = 0

        def enable_http_service(self, secret_id, *, prewrite):
            assert secret_id == 24 and prewrite == baseline
            self.calls += 1
            reader.value = replace(baseline, http_service_enabled=True)

    mock_writer = MockWriter()
    writer = object.__new__(FortiPamWebSecretServiceSshTransport)
    writer.enable_http_service = mock_writer.enable_http_service
    factory = LabAutoWebSecretServiceRunnerFactory(
        planning=NoReceiptPlanningReader(),
        promoter=LabAutoWebSecretServicePromoter(
            b"a" * 32,
            authorized_environment_ref=plan.environment_ref,
            authorized_scope_ref=plan.scope_ref,
        ),
        reader=reader,
        writer=writer,
        execution_store=InMemoryM4ExecutionStateStore(),
        authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
        clock=lambda: summary.created_at + 5,
    )
    principal = SimpleNamespace(requester=SimpleNamespace(digest=plan.requester_digest))
    draft = SimpleNamespace(
        scheme_id=plan.scheme_id,
        environment_ref=plan.environment_ref,
        scope_ref=plan.scope_ref,
    )

    runner = factory.bind(
        plan, plan.lines[0].line_ref, principal,
        draft=draft, onboarding_binding=_onboarding_binding(),
    )

    result = runner.execute_bound()
    assert result["outcome"] == "succeeded", result
    assert mock_writer.calls == 1

    closed_action = ProtectedSecretOnboardingMcpAction(
        object(), object(),
        authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
        execution_enabled=False,
    )
    with pytest.raises(V4OnboardingExecutionRuntimeError):
        closed_action.execute(plan.plan_ref, "synthetic-draft-ref", principal)
    assert mock_writer.calls == 1
