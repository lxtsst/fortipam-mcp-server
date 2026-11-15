from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

from mcp import Client
import pytest
from v4_planning import SchemeId

from fortipam_mcp import http_server as http_server_module
from fortipam_mcp import server as server_module
from fortipam_mcp.folder_acl_mcp_action import V4_FOLDER_ACL_EXECUTION_ENV
from fortipam_mcp.folder_mcp_action import V4_FOLDER_EXECUTION_ENV
from fortipam_mcp.http_server import HttpConfigurationError, HttpServerSettings
from fortipam_mcp.launcher_ssh_transport import (
    ENV_PREFIX as LAUNCHER_TRANSPORT_ENV_PREFIX,
)
from fortipam_mcp.target_mcp_action import (
    V4_TARGET_DELETE_ACTION_FEATURE_ENV,
    V4_TARGET_DELETE_EXECUTION_ENV,
    V4_TARGET_EXECUTION_ENV,
)
from fortipam_mcp.onboarding_execution_mcp_action import (
    ProtectedAccessDomainOnboardingMcpAction,
    ProtectedSecretOnboardingMcpAction,
    V4_ACCESS_DOMAIN_AUTHORIZED_ENVIRONMENT_ENV,
    V4_ACCESS_DOMAIN_AUTHORIZED_SCOPE_ENV,
    V4_ACCESS_DOMAIN_EXECUTION_TOOL,
    V4_ONBOARDING_EXECUTION_FEATURE_ENV,
    V4_ONBOARDING_EXECUTION_GATE_ENV,
    V4_SECRET_ONBOARDING_EXECUTION_TOOL,
)
from fortipam_mcp.onboarding_action_coordinator import OnboardingActionCoordinatorError
from fortipam_mcp.secret_create_lab_auto_runtime import (
    LAB_AUTO_SECRET_CREATE_ENV_PREFIX,
)
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
from fortipam_mcp.v4_runtime_host import (
    V4PlanHostComponents,
    V4_SYNTHETIC_HOST_MODE_ENV,
    synthetic_v4_plan_host_factory,
)
from test_http_server import _v4_bound_environment


def test_http_environment_file_loads_complete_onboarding_runtime_prefixes(
    tmp_path,
    monkeypatch,
) -> None:
    values = {
        V4_ONBOARDING_EXECUTION_FEATURE_ENV: "true",
        V4_ONBOARDING_EXECUTION_GATE_ENV: "false",
        V4_ACCESS_DOMAIN_AUTHORIZED_ENVIRONMENT_ENV: "access-environment-ref01",
        V4_ACCESS_DOMAIN_AUTHORIZED_SCOPE_ENV: "access-scope-ref000001",
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_ENVIRONMENT_REF": (
            "secret-environment-ref01"
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_SCOPE_REF": (
            "secret-scope-ref000001"
        ),
    }
    environment_file = tmp_path / "onboarding-http.env"
    environment_file.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items())
        + "UNRELATED_VALUE=must-not-load\n",
        encoding="utf-8",
    )
    environment_file.chmod(0o600)
    for key in (*values, "UNRELATED_VALUE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv(
        http_server_module.HTTP_ENV_FILE_VARIABLE,
        str(environment_file),
    )

    assert http_server_module.load_http_runtime_environment() is True
    assert {key: http_server_module.os.environ.get(key) for key in values} == values
    assert "UNRELATED_VALUE" not in http_server_module.os.environ


def test_default_http_factory_binds_distinct_access_and_secret_scopes(
    monkeypatch,
) -> None:
    folder_action = object()
    acl_action = object()
    target_action = object()
    class _RunnerFactory:
        def execution_preflight_available(self):
            return True

    runner_factory = _RunnerFactory()
    environment = {
        V4_ACCESS_DOMAIN_AUTHORIZED_ENVIRONMENT_ENV: "access-environment-ref01",
        V4_ACCESS_DOMAIN_AUTHORIZED_SCOPE_ENV: "access-scope-ref000001",
        V4_ONBOARDING_EXECUTION_GATE_ENV: "true",
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_ENVIRONMENT_REF": (
            "secret-environment-ref01"
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_SCOPE_REF": (
            "secret-scope-ref000001"
        ),
    }
    monkeypatch.setattr(
        http_server_module,
        "build_fortipam_191_lab_auto_secret_runner_factory",
        lambda selected: runner_factory,
    )
    child_environments: list[dict[str, str]] = []
    monkeypatch.setattr(
        http_server_module,
        "build_v4_folder_action",
        lambda selected: child_environments.append(dict(selected)) or folder_action,
    )
    monkeypatch.setattr(
        http_server_module,
        "build_v4_folder_acl_action",
        lambda selected: child_environments.append(dict(selected)) or acl_action,
    )
    monkeypatch.setattr(
        http_server_module,
        "build_v4_target_action",
        lambda selected: child_environments.append(dict(selected)) or target_action,
    )
    captured: dict[str, object] = {}

    class _Components:
        @property
        def plan_services(self):
            return self

        def bind_secret_create_execution_preflight_probe(self, probe):
            assert "args" in captured
            captured["preflight"] = probe

        def bind_onboarding_execution_mcp_actions(self, *args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return (object(), object())

    factory = http_server_module._build_default_onboarding_execution_factory(
        environment,
    )
    result = factory(_Components())  # type: ignore[arg-type]

    assert len(result) == 2
    assert captured["preflight"] == runner_factory.execution_preflight_available
    assert captured["args"] == (acl_action, runner_factory)
    assert captured["kwargs"] == {
        "folder_action": folder_action,
        "group_acl_action": acl_action,
        "target_action": target_action,
        "authorized_environment_ref": "access-environment-ref01",
        "authorized_scope_ref": "access-scope-ref000001",
        "authorized_secret_environment_ref": "secret-environment-ref01",
        "authorized_secret_scope_ref": "secret-scope-ref000001",
        "execution_enabled": True,
    }
    assert len(child_environments) == 3
    assert all(
        selected[V4_FOLDER_EXECUTION_ENV] == "true"
        and selected[V4_FOLDER_ACL_EXECUTION_ENV] == "true"
        and selected[V4_TARGET_EXECUTION_ENV] == "true"
        and selected[V4_TARGET_DELETE_ACTION_FEATURE_ENV] == "false"
        and selected[V4_TARGET_DELETE_EXECUTION_ENV] == "false"
        for selected in child_environments
    )

    with pytest.raises(HttpConfigurationError, match="binding is unavailable"):
        http_server_module._build_default_onboarding_execution_factory(
            {
                key: value
                for key, value in environment.items()
                if key != V4_ACCESS_DOMAIN_AUTHORIZED_SCOPE_ENV
            },
        )


def test_default_http_factory_rejects_unknown_onboarding_mode_before_create_binding(
    monkeypatch,
) -> None:
    environment = {
        V4_ACCESS_DOMAIN_AUTHORIZED_ENVIRONMENT_ENV: "access-environment-ref01",
        V4_ACCESS_DOMAIN_AUTHORIZED_SCOPE_ENV: "access-scope-ref000001",
        V4_ONBOARDING_EXECUTION_GATE_ENV: "false",
        "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_MODE": "unrecognized",
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_ENVIRONMENT_REF": "secret-environment-ref01",
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_SCOPE_REF": "secret-scope-ref000001",
    }
    called = False

    def _unexpected_create_binding(_environment):
        nonlocal called
        called = True
        raise AssertionError("must not build create runner")

    monkeypatch.setattr(
        http_server_module,
        "build_fortipam_191_lab_auto_secret_runner_factory",
        _unexpected_create_binding,
    )

    with pytest.raises(HttpConfigurationError, match="binding is unavailable"):
        http_server_module._build_default_onboarding_execution_factory(environment)

    assert called is False


def test_onboarding_launcher_transport_is_optional_until_enabled(monkeypatch) -> None:
    assert http_server_module._build_optional_onboarding_launcher_transport({}) is None
    assert (
        http_server_module._build_optional_onboarding_launcher_transport(
            {f"{LAUNCHER_TRANSPORT_ENV_PREFIX}ENABLED": "false"}
        )
        is None
    )

    config = object()
    transport = object()
    monkeypatch.setattr(
        http_server_module,
        "load_launcher_ssh_transport_config",
        lambda environment: config,
    )
    monkeypatch.setattr(
        http_server_module,
        "FortiPamLauncherSshTransport",
        lambda supplied: transport if supplied is config else None,
    )
    assert (
        http_server_module._build_optional_onboarding_launcher_transport(
            {f"{LAUNCHER_TRANSPORT_ENV_PREFIX}ENABLED": "true"}
        )
        is transport
    )


def test_onboarding_rdp_policy_transports_are_optional_until_enabled(
    monkeypatch,
) -> None:
    assert (
        http_server_module._build_optional_onboarding_secret_policy_transport({})
        is None
    )
    assert (
        http_server_module._build_optional_onboarding_recording_policy_transport({})
        is None
    )
    assert (
        http_server_module._build_optional_onboarding_rdp_event_filter_transport({})
        is None
    )

    secret_policy_config = object()
    secret_policy_transport = object()
    recording_config = object()
    recording_transport = object()
    event_filter_config = object()
    event_filter_transport = object()
    monkeypatch.setattr(
        http_server_module,
        "load_secret_policy_ssh_transport_config",
        lambda environment: secret_policy_config,
    )
    monkeypatch.setattr(
        http_server_module,
        "FortiPamSecretPolicySshTransport",
        lambda supplied: (
            secret_policy_transport
            if supplied is secret_policy_config
            else None
        ),
    )
    monkeypatch.setattr(
        http_server_module,
        "load_recording_policy_http_transport_config",
        lambda environment: recording_config,
    )
    monkeypatch.setattr(
        http_server_module,
        "FortiPamRecordingPolicyHttpTransport",
        lambda supplied: recording_transport if supplied is recording_config else None,
    )
    monkeypatch.setattr(
        http_server_module,
        "load_rdp_event_filter_ssh_transport_config",
        lambda environment: event_filter_config,
    )
    monkeypatch.setattr(
        http_server_module,
        "FortiPamRdpEventFilterSshTransport",
        lambda supplied: event_filter_transport if supplied is event_filter_config else None,
    )

    assert (
        http_server_module._build_optional_onboarding_secret_policy_transport(
            {
                f"{http_server_module.SECRET_POLICY_TRANSPORT_ENV_PREFIX}ENABLED": (
                    "true"
                )
            }
        )
        is secret_policy_transport
    )
    assert (
        http_server_module._build_optional_onboarding_recording_policy_transport(
            {
                f"{http_server_module.RECORDING_POLICY_TRANSPORT_ENV_PREFIX}ENABLED": (
                    "true"
                )
            }
        )
        is recording_transport
    )
    assert (
        http_server_module._build_optional_onboarding_rdp_event_filter_transport(
            {
                f"{http_server_module.RDP_EVENT_FILTER_TRANSPORT_ENV_PREFIX}ENABLED": (
                    "true"
                )
            }
        )
        is event_filter_transport
    )


@pytest.mark.parametrize("secret_only", [False, True])
def test_create_http_app_composes_only_one_complete_trusted_onboarding_factory(
    tmp_path,
    monkeypatch,
    secret_only,
) -> None:
    environment, host_settings = _v4_bound_environment(tmp_path)
    environment.update(
        {
            RUNTIME_PROFILE_ENV: "v4-controlled",
            V4_SYNTHETIC_HOST_MODE_ENV: (
                "source-backed-secret-onboarding" if secret_only
                else "source-backed-onboarding"
            ),
        }
    )
    disabled_settings = HttpServerSettings.from_environment(environment)
    enabled_settings = HttpServerSettings.from_environment(
        {
            **environment,
            V4_ONBOARDING_EXECUTION_FEATURE_ENV: "true",
        }
    )
    base_host_factory = synthetic_v4_plan_host_factory(host_settings)

    def host_factory(provider, confirmation_settings) -> V4PlanHostComponents:
        components = base_host_factory(provider, confirmation_settings)
        return replace(
            components,
            access_domain_projection_source=None if secret_only else object(),  # type: ignore[arg-type]
            secret_onboarding_projection_source=object(),  # type: ignore[arg-type]
        )

    factory_calls: list[V4PlanHostComponents] = []

    def execution_factory(components: V4PlanHostComponents):
        factory_calls.append(components)
        return (
            None if secret_only else ProtectedAccessDomainOnboardingMcpAction(
                components.plan_services,
                object(),  # type: ignore[arg-type]
                authorized_environment_ref="http-test-environment-ref01",
                authorized_scope_ref="http-test-scope-ref0001",
            ),
            ProtectedSecretOnboardingMcpAction(
                components.plan_services,
                object(),  # type: ignore[arg-type]
                authorized_environment_ref="http-test-environment-ref01",
                authorized_scope_ref="http-test-scope-ref0001",
            ),
        )

    servers: list[server_module.FortiPamMcpServer] = []
    real_server = server_module.FortiPamMcpServer

    def capture_server(**kwargs):
        server = real_server(**kwargs)
        servers.append(server)
        return server

    monkeypatch.setattr(http_server_module, "FortiPamMcpServer", capture_server)

    http_server_module.create_http_app(
        disabled_settings,
        v4_plan_host_factory=host_factory,
    )
    with pytest.raises(HttpConfigurationError, match="feature is disabled"):
        http_server_module.create_http_app(
            disabled_settings,
            v4_plan_host_factory=host_factory,
            v4_onboarding_execution_factory=execution_factory,
        )
    with pytest.raises(HttpConfigurationError, match="trusted execution factory"):
        http_server_module.create_http_app(
            enabled_settings,
            v4_plan_host_factory=host_factory,
        )
    with pytest.raises(HttpConfigurationError, match="invalid binding"):
        http_server_module.create_http_app(
            enabled_settings,
            v4_plan_host_factory=host_factory,
            v4_onboarding_execution_factory=(
                lambda components: (execution_factory(components)[0],)  # type: ignore[arg-type,return-value]
            ),
        )
    with pytest.raises(HttpConfigurationError, match="source-backed onboarding"):
        http_server_module.create_http_app(
            enabled_settings,
            v4_plan_host_factory=base_host_factory,
            v4_onboarding_execution_factory=execution_factory,
        )

    if secret_only:
        def invalid_access_factory(components):
            return (
                ProtectedAccessDomainOnboardingMcpAction(
                    components.plan_services, object(),
                    authorized_environment_ref="http-test-environment-ref01",
                    authorized_scope_ref="http-test-scope-ref0001",
                ),
                execution_factory(components)[1],
            )

        with pytest.raises(HttpConfigurationError, match="invalid binding"):
            http_server_module.create_http_app(
                enabled_settings,
                v4_plan_host_factory=host_factory,
                v4_onboarding_execution_factory=invalid_access_factory,
            )

    http_server_module.create_http_app(
        enabled_settings,
        v4_plan_host_factory=host_factory,
        v4_onboarding_execution_factory=execution_factory,
    )

    async def tool_names(server):
        async with Client(server.mcp) as client:
            return {tool.name for tool in (await client.list_tools()).tools}

    disabled_tools = asyncio.run(tool_names(servers[0]))
    enabled_tools = asyncio.run(tool_names(servers[-1]))
    expected = {
        V4_ACCESS_DOMAIN_EXECUTION_TOOL,
        V4_SECRET_ONBOARDING_EXECUTION_TOOL,
    }
    assert disabled_tools.isdisjoint(expected)
    assert V4_SECRET_ONBOARDING_EXECUTION_TOOL in enabled_tools
    if secret_only:
        assert V4_ACCESS_DOMAIN_EXECUTION_TOOL not in enabled_tools
        assert factory_calls[-1].access_domain_projection_source is None
        with pytest.raises(RuntimeError):
            servers[-1]._require_v4_access_domain_execution_action()
    else:
        assert expected <= enabled_tools
        assert factory_calls[-1].access_domain_projection_source is not None
    assert factory_calls[-1].secret_onboarding_projection_source is not None


def test_secret_only_create_factory_needs_no_access_domain_runtime(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Secret-only composition must not initialize Access Domain actions or scope")

    for name in ("build_v4_folder_action", "build_v4_folder_acl_action",
                 "build_v4_target_action", "load_v4_access_domain_authorized_scope"):
        monkeypatch.setattr(http_server_module, name, unexpected)

    class Factory:
        def execution_preflight_available(self):
            return True

    factory = Factory()
    monkeypatch.setattr(http_server_module,
                        "build_fortipam_191_lab_auto_secret_runner_factory",
                        lambda environment: factory)
    bound = []

    class Services:
        def bind_secret_create_execution_preflight_probe(self, probe):
            bound.append(probe)

    components = V4PlanHostComponents(
        plan_services=Services(), confirmation_service=object(),
        secret_onboarding_projection_source=object(),
    )
    environment = {
        V4_SYNTHETIC_HOST_MODE_ENV: "source-backed-secret-onboarding",
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_ENVIRONMENT_REF": "secret-environment-ref01",
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_SCOPE_REF": "secret-scope-ref000001",
    }
    access, secret = http_server_module._build_default_onboarding_execution_factory(
        environment,
    )(components)
    assert access is None
    assert isinstance(secret, ProtectedSecretOnboardingMcpAction)
    assert bound == [factory.execution_preflight_available]


def test_existing_web_http_mode_selects_only_web_factory_without_receipt_services(monkeypatch):
    from types import SimpleNamespace
    from fortipam_mcp.onboarding_execution_mcp_action import V4OnboardingExecutionRuntimeError

    def forbidden(*args, **kwargs):
        pytest.fail("Web service mode must not bind CREATE or RDP controls")

    for name in ("build_fortipam_191_lab_auto_secret_runner_factory",
                 "build_lab_auto_secret_session_controls_runner_factory",
                 "_build_optional_onboarding_rdp_event_filter_transport"):
        monkeypatch.setattr(http_server_module, name, forbidden)
    config = SimpleNamespace(base_url="https://fpa.example.test")
    reader, runner = object(), object()
    planning = object()
    calls = []
    monkeypatch.setattr(http_server_module, "load_secret_metadata_http_transport_config", lambda env: config)
    monkeypatch.setattr(http_server_module, "FortiPamSecretMetadataHttpTransport", lambda *a, **k: reader)

    def build(environment, **kwargs):
        assert kwargs["planning"] is planning
        assert kwargs["reader"] is reader
        assert kwargs["metadata_base_url"] == config.base_url
        assert "receipt_authenticator" not in kwargs
        calls.append(True)
        return runner

    monkeypatch.setattr(http_server_module, "build_lab_auto_web_secret_service_runner_factory", build)
    components = V4PlanHostComponents(
        plan_services=object(), confirmation_service=object(),
        secret_onboarding_projection_source=object(),
        _secret_approval_planning_reader=planning,
    )
    environment = {
        V4_SYNTHETIC_HOST_MODE_ENV: "source-backed-secret-onboarding",
        "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_MODE": "existing_web_service_lab_auto",
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_ENVIRONMENT_REF": "secret-environment-ref01",
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_SCOPE_REF": "secret-scope-ref000001",
    }
    access, secret = http_server_module._build_default_onboarding_execution_factory(
        environment, secret_binding_resolver=SimpleNamespace(bound_secret_name=lambda: "synthetic-web"),
    )(components)
    assert access is None and calls == [True]
    with pytest.raises(V4OnboardingExecutionRuntimeError):
        secret.execute("synthetic-plan-ref", "synthetic-draft-ref", object())


def test_main_targetless_web_needs_no_target_api_configuration(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from fortipam_mcp import owner_collector_runtime
    from fortipam_mcp.secret_create_lab_auto_runtime import (
        LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE,
    )

    monkeypatch.setenv(
        LAB_AUTO_SECRET_CREATE_ENV_PREFIX + "PROFILE",
        LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE,
    )
    settings = SimpleNamespace(v4_confirmation=object())
    host_settings = SimpleNamespace(
        host_mode="source-backed-secret-onboarding",
        secret_onboarding_binding_path=tmp_path / "binding.json",
    )
    resolver = SimpleNamespace(bound_secret_name=lambda: "private-web-secret")
    monkeypatch.setattr(http_server_module, "load_http_runtime_environment", lambda: False)
    monkeypatch.setattr(HttpServerSettings, "from_environment", classmethod(lambda cls: settings))
    monkeypatch.setattr(http_server_module, "synthetic_host_settings_from_environment", lambda env: host_settings)
    monkeypatch.setattr(http_server_module, "OwnerOnlySecretOnboardingBindingResolver", lambda path: resolver)
    monkeypatch.setattr(http_server_module, "load_secret_metadata_http_transport_config", lambda env: "metadata-config")
    monkeypatch.setattr(http_server_module, "FortiPamSecretMetadataHttpTransport", lambda *args, **kwargs: "metadata-reader")
    monkeypatch.setattr(owner_collector_runtime, "owner_login_provider", lambda env: None)

    def forbidden_target(*args, **kwargs):
        pytest.fail("Targetless Web startup must not load Target API configuration")

    monkeypatch.setattr(http_server_module, "load_target_http_transport_config", forbidden_target)

    class HostSelected(Exception):
        pass

    def select_host(actual_settings, **kwargs):
        assert actual_settings is host_settings
        assert kwargs["binding_resolver"] is resolver
        assert kwargs["secret_transport"] == "metadata-reader"
        assert kwargs["target_transport"] is None
        raise HostSelected

    monkeypatch.setattr(http_server_module, "secret_onboarding_v4_plan_host_factory", select_host)
    with pytest.raises(HostSelected):
        http_server_module.main()


def test_secret_execution_preserves_only_safe_coordinator_resolution_stage():
    environment_ref = "http-test-environment-ref01"
    scope_ref = "http-test-scope-ref0001"
    requester_digest = "a" * 64

    class Services:
        def resolve_execution_context(self, plan_ref, scheme_draft_ref, principal):
            assert plan_ref == "synthetic-plan-ref"
            assert scheme_draft_ref == "synthetic-draft-ref"
            return (
                SimpleNamespace(
                    plan_ref=plan_ref,
                    requester_digest=requester_digest,
                    scheme_id=SchemeId.SECRET_ONBOARDING,
                    environment_ref=environment_ref,
                    scope_ref=scope_ref,
                ),
                SimpleNamespace(
                    scheme_id=SchemeId.SECRET_ONBOARDING,
                    blueprint_ref="FPA-BP-005",
                    outcome_code="onboard_privileged_resource",
                    environment_ref=environment_ref,
                    scope_ref=scope_ref,
                ),
            )

    class Coordinator:
        def execute(self, plan_ref, scheme_draft_ref, principal):
            raise OnboardingActionCoordinatorError("private resolver detail")

    principal = SimpleNamespace(
        requester=SimpleNamespace(digest=requester_digest),
    )
    action = ProtectedSecretOnboardingMcpAction(
        Services(),
        Coordinator(),  # type: ignore[arg-type]
        authorized_environment_ref=environment_ref,
        authorized_scope_ref=scope_ref,
        execution_enabled=True,
    )

    result = action.execute(
        "synthetic-plan-ref", "synthetic-draft-ref", principal,  # type: ignore[arg-type]
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["failure_stage"] == "fixed_action_resolution"
    assert result["reconciliation_required"] is True
    assert result["completed_line_refs"] == []
    assert "private resolver detail" not in repr(result)


def test_secret_execution_preserves_context_resolution_stage_without_details():
    class Services:
        def resolve_execution_context(self, plan_ref, scheme_draft_ref, principal):
            del plan_ref, scheme_draft_ref, principal
            raise RuntimeError("private persisted-plan detail")

    class Coordinator:
        def execute(self, *args):
            pytest.fail("coordinator must not run without a resolved context")

    action = ProtectedSecretOnboardingMcpAction(
        Services(),  # type: ignore[arg-type]
        Coordinator(),  # type: ignore[arg-type]
        authorized_environment_ref="http-test-environment-ref01",
        authorized_scope_ref="http-test-scope-ref0001",
        execution_enabled=True,
    )

    result = action.execute(
        "synthetic-plan-ref",
        "synthetic-draft-ref",
        SimpleNamespace(requester=SimpleNamespace(digest="a" * 64)),  # type: ignore[arg-type]
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["failure_stage"] == "fixed_action_context"
    assert result["pre_write_status"] == "unavailable"
    assert "private persisted-plan detail" not in repr(result)


def test_target_bound_web_http_composition_keeps_execution_gate_closed(monkeypatch):
    from test_target_bound_web_projection_reader import planning_source, Transport
    from test_v4_planning import _requester
    from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
    from fortipam_mcp.secret_create_lab_auto_runtime import LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE

    _, source = planning_source(Transport())
    class Factory:
        def execution_preflight_available(self):
            return True
        def bind(self, *args, **kwargs):
            pytest.fail("Closed gate must not bind a runner")
    runner_factory = Factory()
    monkeypatch.setattr(http_server_module, "build_fortipam_191_lab_auto_secret_runner_factory",
                        lambda env: runner_factory)
    probes = []
    services = SimpleNamespace(bind_secret_create_execution_preflight_probe=probes.append)
    components = V4PlanHostComponents(
        plan_services=services, confirmation_service=object(),
        secret_onboarding_projection_source=source,
    )
    env = {
        V4_SYNTHETIC_HOST_MODE_ENV: "source-backed-secret-onboarding",
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE": LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE,
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_ENVIRONMENT_REF": source._binding.environment_ref,
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_SCOPE_REF": source._binding.scope_ref,
    }
    access, secret = http_server_module._build_default_onboarding_execution_factory(env)(components)
    assert access is None and secret._execution_enabled is False
    assert secret._coordinator._resolver._target_bound_web_runner_factory is runner_factory
    from fortipam_mcp.onboarding_execution_mcp_action import V4OnboardingExecutionRuntimeError
    with pytest.raises(V4OnboardingExecutionRuntimeError):
        secret.execute("unused-plan-ref01", "unused-draft-ref01", V4PlanningPrincipal(_requester(), "a" * 64))
    assert source._transport.calls == []
