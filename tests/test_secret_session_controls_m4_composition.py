from __future__ import annotations

from pathlib import Path

import pytest

from fortipam_mcp.approval_profile_ssh_transport import ApprovalProfileSshTransportConfig
from fortipam_mcp.rdp_event_filter_ssh_transport import RdpEventFilterReadback
from fortipam_mcp.secret_metadata_http_transport import (
    SecretSessionControlsFolderPolicy,
    SecretSessionControlsProjectionInspection,
    secret_session_controls_event_filter_profile_digest,
)
from fortipam_mcp.secret_session_controls_m4_runtime import (
    SecretSessionControlsWriteTransport,
)
from fortipam_mcp.secret_session_controls_ssh_transport import (
    FortiPamSecretSessionControlsSshTransport,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.v4_runtime_host import V4PlanHostComponents, V4RuntimeHostError
from fortipam_mcp.onboarding_execution_mcp_action import (
    V4OnboardingExecutionRuntimeError,
)
from test_m4_execution_store import _store
from test_secret_session_controls_m4_authorization import (
    OLD_PROFILE,
    PROFILE as EVENT_FILTER_PROFILE,
    _binding,
    _claimed_chain,
    _onboarding_binding,
)
from test_v4_m3 import ExactApproverAuthority
from test_v4_planning import NOW, _projection


class _ProductTransport:
    """Local product-state simulation; it performs no device operation."""

    def __init__(self) -> None:
        self.recording = True
        self.clipboard = False
        self.event_filter = False
        self.profile = OLD_PROFILE
        self.writes = 0
        self.ssh_commands: list[tuple[str, ...]] = []

    def apply_controls(self, secret_id: int, profile_name: str) -> None:
        assert (secret_id, profile_name) == (42, EVENT_FILTER_PROFILE)
        self.writes += 1
        self.recording = self.clipboard = self.event_filter = True
        self.profile = profile_name

    def readback(self, profile_name: str) -> RdpEventFilterReadback:
        assert profile_name == EVENT_FILTER_PROFILE
        return RdpEventFilterReadback(True, True, True, True)

    def inspect_session_controls_projection(
        self, *_args: object, **kwargs: object
    ) -> SecretSessionControlsProjectionInspection:
        assert kwargs == {"expected_secret_id": 42}
        return SecretSessionControlsProjectionInspection(
            original_name=_onboarding_binding().secret_name,
            original_template=_onboarding_binding().template_name,
            folder_policy=SecretSessionControlsFolderPolicy(
                17, "folder", "mcp-v4-secret-policy-test", "not-set", "not-set", "not-set"
            ),
            recording_enabled=self.recording,
            clipboard_blocking_enabled=self.clipboard,
            rdp_event_filter_enabled=self.event_filter,
            rdp_event_filter_profile_matches=self.profile == EVENT_FILTER_PROFILE,
            rdp_event_filter_profile_digest=(
                secret_session_controls_event_filter_profile_digest(self.profile)
            ),
            proxy_enabled=True,
            rdp_tcp_forwarding_disabled=True,
            inherit_permission_matches=True,
            preserved_identity_relations_digest="1" * 64,
        )


class _PlanServices:
    """Use the actual M2 comparison engine over the local product simulation."""

    def __init__(self, engine: object, plan: object, draft: object, product: _ProductTransport) -> None:
        self.engine, self.plan, self.draft, self.product = engine, plan, draft, product

    def resolve_execution_context(self, plan_ref: str, draft_ref: str, principal: V4PlanningPrincipal):
        assert plan_ref == self.plan.plan_ref and draft_ref == "controls-draft-ref01"
        assert principal.requester.digest == self.plan.requester_digest
        return self.plan, self.draft

    def _projections(self):
        return [
            _projection(
                self.engine,
                self.draft.scheme_id,
                item,
                {
                    "exists": True,
                    **dict(item.desired_fields),
                    **(
                        {
                            "recording_enabled": self.product.recording,
                            "clipboard_blocking_enabled": self.product.clipboard,
                            "rdp_event_filter_enabled": self.product.event_filter,
                            "rdp_event_filter_profile_matches": self.product.profile == EVENT_FILTER_PROFILE,
                            "preserved_identity_digest": "1" * 64,
                            "event_filter_profile_digest": secret_session_controls_event_filter_profile_digest(
                                self.product.profile
                            ),
                        }
                        if item.object_class.value == "SecretSessionControlsBinding"
                        else {}
                    ),
                },
                observed_at=NOW + 5,
                fresh_until=NOW + 100,
            )
            for item in self.draft.desired_objects
        ]

    def evaluate_pre_write(self, plan_ref: str, *_args: object) -> dict[str, object]:
        evaluation = self.engine.evaluate_pre_write(plan_ref, self._projections(), now_epoch=NOW + 5)
        return {"status": evaluation.status.value}

    def evaluate_post_write(self, plan_ref: str, *_args: object) -> dict[str, object]:
        evaluation = self.engine.evaluate_post_write(plan_ref, self._projections(), now_epoch=NOW + 6)
        return {"status": evaluation.status.value}


class _Source:
    def resolve_private_binding(self, *_args: object, **_kwargs: object):
        return _onboarding_binding()


def _ssh_write_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    product: _ProductTransport,
) -> FortiPamSecretSessionControlsSshTransport:
    tmp_path.mkdir(parents=True, exist_ok=True)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    writer = FortiPamSecretSessionControlsSshTransport(
        ApprovalProfileSshTransportConfig(
            host="fpa.example",
            port=22,
            username="writer",
            password="test-password",
            known_hosts_file=known_hosts,
            timeout_seconds=15,
        )
    )

    async def apply(secret_id: int, commands: tuple[str, ...]) -> None:
        assert secret_id == 42
        product.ssh_commands.append(commands)
        product.apply_controls(secret_id, EVENT_FILTER_PROFILE)

    monkeypatch.setattr(writer, "_enable_controls", apply)
    return writer


def _action(
    tmp_path: Path,
    *,
    enabled: bool,
    product: _ProductTransport,
    monkeypatch: pytest.MonkeyPatch,
    write_transport: SecretSessionControlsWriteTransport | None = None,
):
    planning, authenticator, plan, receipt, engine, draft = _claimed_chain(include_engine=True)
    services = _PlanServices(engine, plan, draft, product)
    components = V4PlanHostComponents(
        plan_services=services,
        confirmation_service=object(),
        secret_onboarding_projection_source=_Source(),
        _secret_approval_planning_reader=planning,
        _secret_approval_receipt_authenticator=authenticator,
        _secret_approval_approver_authority_ref=ExactApproverAuthority.authority_ref,
        _clock=lambda: NOW + 5,
    )
    return components.bind_trusted_secret_session_controls_execution_mcp_action(
        source_plan_ref=plan.plan_ref,
        scheme_draft_ref="controls-draft-ref01",
        approval_receipt_ref=receipt.receipt_ref,
        authorization_ref="session-controls-authorization-ref01",
        principal=V4PlanningPrincipal(_requester(), "a" * 64),
        session_controls_binding=_binding(),
        read_transport=product,
        write_transport=(
            _ssh_write_transport(tmp_path, monkeypatch, product)
            if write_transport is None
            else write_transport
        ),
        rdp_event_filter_transport=product,
        execution_store=_store(tmp_path),
        authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
        execution_enabled=enabled,
    ), plan


def _requester():
    from v4_planning import AuthenticatedRequester

    return AuthenticatedRequester(
        "operator-subject-0001", "operator",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )


def test_composed_controls_action_honors_gate_and_independent_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product = _ProductTransport()
    denied, plan = _action(tmp_path, enabled=False, product=product, monkeypatch=monkeypatch)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    with pytest.raises(V4OnboardingExecutionRuntimeError):
        denied.execute(plan.plan_ref, "controls-draft-ref01", principal)
    assert product.writes == 0

    action, plan = _action(tmp_path / "enabled", enabled=True, product=product, monkeypatch=monkeypatch)
    result = action.execute(plan.plan_ref, "controls-draft-ref01", principal)
    assert result["outcome"] == "succeeded"
    assert result["policy_mode"] == "independent_approval"
    assert product.writes == 1
    assert product.ssh_commands == [
        (
            "set block-clipboard enable",
            "set rdp-event-filter enable",
            f'set rdp-event-filter-profile "{EVENT_FILTER_PROFILE}"',
        )
    ]
    assert _store(tmp_path / "enabled").audit_events[0].authorization == "verified"


def test_rebuilt_coordinator_rejects_the_old_plan_after_controls_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product = _ProductTransport()
    action, plan = _action(tmp_path, enabled=True, product=product, monkeypatch=monkeypatch)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    assert action.execute(plan.plan_ref, "controls-draft-ref01", principal)["outcome"] == "succeeded"
    assert product.writes == 1
    rebuilt, _ = _action(tmp_path, enabled=True, product=product, monkeypatch=monkeypatch)
    stale = rebuilt.execute(plan.plan_ref, "controls-draft-ref01", principal)
    assert stale["outcome"] == "precondition_failed"
    assert stale["pre_write_status"] == "invalidated"
    assert product.writes == 1
    assert _store(tmp_path).audit_events[0].authorization == "verified"


def test_composed_controls_rejects_changed_unmatched_profile_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product = _ProductTransport()
    action, plan = _action(tmp_path, enabled=True, product=product, monkeypatch=monkeypatch)
    product.profile = "mcp-v4-rdp-event-filter-unconfirmed02"
    result = action.execute(plan.plan_ref, "controls-draft-ref01", V4PlanningPrincipal(_requester(), "a" * 64))
    assert result["outcome"] == "precondition_failed"
    assert product.writes == 0


def test_trusted_composition_rejects_structural_nonssh_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product = _ProductTransport()
    with pytest.raises(V4RuntimeHostError):
        _action(
            tmp_path, enabled=True, product=product, monkeypatch=monkeypatch,
            write_transport=product,
        )
    assert product.writes == 0


def test_lab_auto_host_uses_confirmed_records_without_independent_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    product = _ProductTransport()
    planning, _, plan, _, engine, draft = _claimed_chain(include_engine=True)

    class ConfirmedRecordsOnly:
        get_plan = planning.get_plan
        get_summary = planning.get_summary
        get_confirmation = planning.get_confirmation

    components = V4PlanHostComponents(
        plan_services=_PlanServices(engine, plan, draft, product),
        confirmation_service=object(),
        secret_onboarding_projection_source=_Source(),
        _secret_approval_planning_reader=ConfirmedRecordsOnly(),
        _clock=lambda: NOW + 5,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    kwargs = dict(
        session_controls_binding=_binding(),
        authority_key=b"lab-policy-test-key-00000000000000",
        read_transport=product,
        write_transport=_ssh_write_transport(tmp_path, monkeypatch, product),
        rdp_event_filter_transport=product,
        execution_store=_store(tmp_path),
        authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
    )
    denied = components.bind_lab_auto_secret_session_controls_execution_mcp_action(**kwargs)
    with pytest.raises(V4OnboardingExecutionRuntimeError):
        denied.execute(plan.plan_ref, "controls-draft-ref01", principal)
    assert product.writes == 0
    action = components.bind_lab_auto_secret_session_controls_execution_mcp_action(**kwargs, execution_enabled=True)
    result = action.execute(plan.plan_ref, "controls-draft-ref01", principal)
    assert result["outcome"] == "succeeded"
    assert result["policy_mode"] == "lab_auto"
    assert result["lab_exception_applied"] is True
    assert product.writes == 1
    assert len(product.ssh_commands) == 1


@pytest.mark.parametrize("secret_only", [False, True])
def test_http_controls_mode_dispatches_only_confirmed_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, secret_only: bool,
) -> None:
    import fortipam_mcp.http_server as server
    from fortipam_mcp.secret_session_controls_lab_auto_runtime import (
        LabAutoSecretSessionControlsPromoter,
        LabAutoSecretSessionControlsRunnerFactory,
    )

    product = _ProductTransport()
    planning, _, plan, _, engine, draft = _claimed_chain(include_engine=True)
    components = V4PlanHostComponents(
        plan_services=_PlanServices(engine, plan, draft, product),
        confirmation_service=object(),
        secret_onboarding_projection_source=_Source(),
        access_domain_projection_source=None if secret_only else object(),
        _secret_approval_planning_reader=planning,
        _clock=lambda: NOW + 5,
    )
    writer = _ssh_write_transport(tmp_path, monkeypatch, product)
    for name in ("build_v4_folder_action", "build_v4_folder_acl_action", "build_v4_target_action"):
        monkeypatch.setattr(server, name, lambda *_: object())
    for name in ("load_v4_access_domain_authorized_scope", "load_lab_auto_secret_create_authorized_scope"):
        monkeypatch.setattr(server, name, lambda *_: (plan.environment_ref, plan.scope_ref))
    monkeypatch.setattr(server, "load_secret_metadata_http_transport_config", lambda *_: object())
    monkeypatch.setattr(server, "FortiPamSecretMetadataHttpTransport", lambda *a, **k: product)
    monkeypatch.setattr(server, "load_secret_session_controls_ssh_transport_config", lambda *_: object())
    monkeypatch.setattr(server, "FortiPamSecretSessionControlsSshTransport", lambda *_: writer)
    monkeypatch.setattr(server, "_build_optional_onboarding_rdp_event_filter_transport", lambda *_: product)

    def build_controls(environment, **kwargs):
        return LabAutoSecretSessionControlsRunnerFactory(
            planning=kwargs["planning"],
            promoter=LabAutoSecretSessionControlsPromoter(
                b"lab-policy-test-key-00000000000000",
                authorized_environment_ref=plan.environment_ref,
                authorized_scope_ref=plan.scope_ref,
            ),
            read_transport=kwargs["read_transport"],
            write_transport=kwargs["write_transport"],
            rdp_event_filter_transport=kwargs["rdp_event_filter_transport"],
            execution_store=_store(tmp_path),
            clock=kwargs["clock"],
        )

    monkeypatch.setattr(server, "build_lab_auto_secret_session_controls_runner_factory", build_controls)
    monkeypatch.setattr(
        server, "build_fortipam_191_lab_auto_secret_runner_factory",
        lambda *_: pytest.fail("Controls mode must not initialize credential creation."),
    )
    environment = {
        "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_MODE": "existing_session_controls_lab_auto",
        "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_ENABLED": "true",
    }
    if secret_only:
        environment[server.V4_SYNTHETIC_HOST_MODE_ENV] = "source-backed-secret-onboarding"
        for name in ("build_v4_folder_action", "build_v4_folder_acl_action", "build_v4_target_action", "load_v4_access_domain_authorized_scope"):
            monkeypatch.setattr(server, name, lambda *_: pytest.fail("Access Domain is unbound"))

    class BindingResolver:
        def bound_secret_name(self):
            return _onboarding_binding().secret_name

    access, controls = server._build_default_onboarding_execution_factory(
        environment, secret_binding_resolver=BindingResolver(),
    )(components)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    if secret_only:
        assert access is None
    else:
        assert access is not None
        with pytest.raises(V4OnboardingExecutionRuntimeError):
            access.execute(plan.plan_ref, "controls-draft-ref01", principal)
    assert product.writes == 0
    result = controls.execute(plan.plan_ref, "controls-draft-ref01", principal)
    assert result["outcome"] == "succeeded"
    assert result["policy_mode"] == "lab_auto"
    assert len(product.ssh_commands) == 1
