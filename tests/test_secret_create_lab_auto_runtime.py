from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from fortipam_mcp.onboarding_action_coordinator import (
    FixedActionResolutionError,
    OnboardingActionCoordinatorError,
)
from fortipam_mcp.secret_create_lab_auto_runtime import (
    FortiPam191LabAutoSecretCreateRunnerFactory,
    LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE,
    LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_ADAPTER_REF,
    LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE,
    LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_ADAPTER_REF,
    LAB_AUTO_SECRET_CREATE_ENV_PREFIX,
    LabAutoSecretCreatePromoter,
    build_fortipam_191_lab_auto_secret_runner_factory,
    load_lab_auto_secret_create_authorized_scope,
)
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
)
from fortipam_mcp.secret_onboarding_action_sequence import (
    SecretOnboardingFixedActionSequenceResolver,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_secret_create_191_projection_reader import _binding
from test_secret_onboarding_action_sequence import (
    _Services,
    _combined_context,
    _new_domain_combined_context,
    _new_domain_new_target_context,
)
from test_secret_onboarding_projection_source import (
    _rdp_binding,
    _rdp_draft,
    _web_binding,
    _web_draft,
)
from v4_planning import (
    ChangeKind,
    InMemoryM4ExecutionStateStore,
    MaterialReferenceMetadata,
    ObjectClass,
    SchemeDraft,
    SchemeId,
    canonical_digest,
)
from v4_planning.material_runtime import InMemoryMaterialUseStateStore


def _central_lab_draft(services: _Services) -> SchemeDraft:
    return replace(
        services.draft,
        desired_objects=tuple(
            item
            for item in services.draft.desired_objects
            if item.object_class is not ObjectClass.LAUNCHER_BINDING
        ),
        verification_codes=("association_readback",),
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="central_lab_inventory_reference",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )


def _promoter(services: _Services, profile="fortipam-191") -> LabAutoSecretCreatePromoter:
    return LabAutoSecretCreatePromoter(
        b"a" * 32,
        authorized_environment_ref=services.plan.environment_ref,
        authorized_scope_ref=services.plan.scope_ref,
        product_profile=profile,
    )


def test_lab_auto_promotion_is_deterministic_and_exactly_source_bound() -> None:
    services = _Services()
    line = services.plan.lines[0]
    principal = V4PlanningPrincipal(services.requester, "a" * 64)
    draft = _central_lab_draft(services)
    promoter = _promoter(services)

    first = promoter.promote(
        services.plan,
        line.line_ref,
        principal,
        draft=draft,
        onboarding_binding=_binding(),
        now_epoch=services.plan.created_at + 1,
    )
    second = promoter.promote(
        services.plan,
        line.line_ref,
        principal,
        draft=draft,
        onboarding_binding=_binding(),
        now_epoch=services.plan.created_at + 2,
    )

    assert first == second
    assert first.plan.plan_ref == services.plan.plan_ref
    assert first.plan.target_ref == line.target_ref
    assert first.authorization.plan_digest == first.plan.plan_digest
    assert first.authorization.requester_digest == services.requester.digest
    assert first.authorization.approver_digest != services.requester.digest
    assert first.lease_request.authorization_digest == (
        first.authorization.authorization_digest
    )
    assert first.lease_request.expires_at - first.lease_request.requested_at == 60
    assert repr(promoter) == "<LabAutoSecretCreatePromoter redacted>"

    wrong_provider = replace(
        draft,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="external_vault_lease",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )
    with pytest.raises(FixedActionResolutionError) as exc_info:
        promoter.promote(
            services.plan,
            line.line_ref,
            principal,
            draft=wrong_provider,
            onboarding_binding=_binding(),
            now_epoch=services.plan.created_at + 1,
        )
    assert exc_info.value.failure_stage == "fixed_action_runner_promotion_material"


def test_build29_linux_ssh_profile_is_exact_and_distinct_from_legacy() -> None:
    services = _Services()
    line = services.plan.lines[0]
    principal = V4PlanningPrincipal(services.requester, "a" * 64)
    draft = _central_lab_draft(services)
    candidate = _promoter(services, LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE)
    binding = replace(_binding(), template_name="Unix Account (SSH Password)")

    artifacts = candidate.promote(
        services.plan, line.line_ref, principal, draft=draft,
        onboarding_binding=binding, now_epoch=services.plan.created_at + 1,
    )
    assert artifacts.plan.adapter_ref == LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_ADAPTER_REF
    with pytest.raises(FixedActionResolutionError):
        candidate.promote(
            services.plan, line.line_ref, principal, draft=draft,
            onboarding_binding=_binding(), now_epoch=services.plan.created_at + 1,
        )

@pytest.mark.parametrize("profile", ["fortipam-191", LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE])
def test_lab_auto_promotion_accepts_exact_existing_target_windows_rdp_profile(profile) -> None:
    services = _Services()
    services.draft = replace(
        _rdp_draft(),
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="central_lab_inventory_reference",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )
    line = services.plan.lines[0]

    artifacts = _promoter(services, profile).promote(
        services.plan,
        line.line_ref,
        V4PlanningPrincipal(services.requester, "a" * 64),
        draft=services.draft,
        onboarding_binding=replace(_rdp_binding(), template_name="Windows Machine"),
        now_epoch=services.plan.created_at + 1,
    )

    assert artifacts.plan.target_ref == line.target_ref
    assert artifacts.authorization.execution_authorized is True
    if profile == LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE:
        assert artifacts.plan.adapter_ref == LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_ADAPTER_REF


def test_build29_rdp_profile_cannot_promote_linux() -> None:
    services = _Services()
    with pytest.raises(FixedActionResolutionError):
        _promoter(services, LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE).promote(
            services.plan, services.plan.lines[0].line_ref,
            V4PlanningPrincipal(services.requester, "a" * 64),
            draft=_central_lab_draft(services), onboarding_binding=_binding(),
            now_epoch=services.plan.created_at + 1,
        )


@pytest.mark.parametrize("profile", ["fortipam-191", "fortipam-700-build29-web-create-candidate"])
def test_lab_auto_promotion_accepts_exact_recorded_web_account_profile(profile) -> None:
    services = _Services()
    draft = replace(
        _web_draft(),
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="central_lab_inventory_reference",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )
    desired = next(
        item
        for item in draft.desired_objects
        if item.object_class is ObjectClass.WEB_SECRET_METADATA
    )
    line = replace(
        services.plan.lines[0],
        target_ref=desired.object_ref,
        target_class=ObjectClass.WEB_SECRET_METADATA,
        change_kind=ChangeKind.CREATE,
        depends_on=(),
    )
    content = dict(services.plan.canonical_content())
    content["lines"] = [line.as_dict()]
    content["scheme_id"] = SchemeId.SECRET_ONBOARDING.value
    services.plan = replace(
        services.plan,
        lines=(line,),
        scheme_id=SchemeId.SECRET_ONBOARDING,
        plan_digest=canonical_digest(content),
    )

    artifacts = _promoter(services, profile).promote(
        services.plan,
        line.line_ref,
        V4PlanningPrincipal(services.requester, "a" * 64),
        draft=draft,
        onboarding_binding=_web_binding(),
        now_epoch=services.plan.created_at + 1,
    )

    assert artifacts.plan.target_ref == desired.object_ref
    assert artifacts.authorization.execution_authorized is True

    expected_adapter = ("fortipam-191-secret-create-private-adapter" if profile == "fortipam-191"
                        else "fortipam-700-build29-web-secret-create-candidate-adapter")
    assert artifacts.plan.adapter_ref == expected_adapter
    assert artifacts.authorization.plan_digest == artifacts.plan.plan_digest


def test_lab_auto_promotion_binds_one_existing_domain_parent_plan() -> None:
    requester, draft, plan, _grant_line, secret_line = _combined_context()
    draft = replace(
        draft,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="central_lab_inventory_reference",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )
    promoter = LabAutoSecretCreatePromoter(
        b"a" * 32,
        authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
    )

    artifacts = promoter.promote(
        plan,
        secret_line.line_ref,
        V4PlanningPrincipal(requester, "a" * 64),
        draft=draft,
        onboarding_binding=replace(
            _binding(),
            folder_ref="combined-public-folder-ref",
        ),
        now_epoch=plan.created_at + 1,
    )

    assert artifacts.plan.plan_ref == plan.plan_ref
    assert artifacts.plan.target_ref == secret_line.target_ref


def test_lab_auto_promotion_binds_one_new_domain_parent_plan() -> None:
    requester, draft, plan, _folder_line, _grant_line, secret_line = (
        _new_domain_combined_context()
    )
    draft = replace(
        draft,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="central_lab_inventory_reference",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )
    promoter = LabAutoSecretCreatePromoter(
        b"a" * 32,
        authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
    )

    artifacts = promoter.promote(
        plan,
        secret_line.line_ref,
        V4PlanningPrincipal(requester, "a" * 64),
        draft=draft,
        onboarding_binding=replace(
            _binding(),
            folder_ref="combined-public-folder-ref",
        ),
        now_epoch=plan.created_at + 1,
    )

    assert artifacts.plan.plan_ref == plan.plan_ref
    assert artifacts.plan.target_ref == secret_line.target_ref


def test_lab_auto_promotion_binds_new_domain_and_target_parent_plan() -> None:
    (
        requester,
        draft,
        plan,
        _folder_line,
        _grant_line,
        _target_line,
        secret_line,
    ) = _new_domain_new_target_context()
    draft = replace(
        draft,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="central_lab_inventory_reference",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )
    promoter = LabAutoSecretCreatePromoter(
        b"a" * 32,
        authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
    )

    artifacts = promoter.promote(
        plan,
        secret_line.line_ref,
        V4PlanningPrincipal(requester, "a" * 64),
        draft=draft,
        onboarding_binding=replace(
            _binding(),
            folder_ref="combined-public-folder-ref",
        ),
        now_epoch=plan.created_at + 1,
    )

    assert artifacts.plan.plan_ref == plan.plan_ref
    assert artifacts.plan.target_ref == secret_line.target_ref


def test_build29_linux_promotion_accepts_existing_access_domain_with_new_target() -> None:
    (
        requester,
        draft,
        original,
        _folder_line,
        _grant_line,
        target_line,
        original_secret_line,
    ) = _new_domain_new_target_context()
    secret_line = replace(
        original_secret_line,
        depends_on=(target_line.line_ref,),
    )
    lines = (target_line, secret_line)
    content = dict(original.canonical_content())
    content["lines"] = [item.as_dict() for item in lines]
    plan = replace(
        original,
        lines=lines,
        plan_digest=canonical_digest(content),
    )
    draft = replace(
        draft,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="central_lab_inventory_reference",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )
    promoter = LabAutoSecretCreatePromoter(
        b"a" * 32,
        authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
        product_profile=LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE,
    )

    artifacts = promoter.promote(
        plan,
        secret_line.line_ref,
        V4PlanningPrincipal(requester, "a" * 64),
        draft=draft,
        onboarding_binding=replace(
            _binding(),
            folder_ref="combined-public-folder-ref",
            template_name="Unix Account (SSH Password)",
        ),
        now_epoch=plan.created_at + 1,
    )

    assert artifacts.plan.plan_ref == plan.plan_ref
    assert artifacts.plan.target_ref == secret_line.target_ref


def test_build29_linux_promotion_rejects_malformed_target_secret_plan() -> None:
    (
        requester,
        draft,
        original,
        _folder_line,
        _grant_line,
        target_line,
        original_secret_line,
    ) = _new_domain_new_target_context()
    draft = replace(
        draft,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="central_lab_inventory_reference",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )
    promoter = LabAutoSecretCreatePromoter(
        b"a" * 32,
        authorized_environment_ref=original.environment_ref,
        authorized_scope_ref=original.scope_ref,
        product_profile=LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE,
    )
    binding = replace(
        _binding(),
        folder_ref="combined-public-folder-ref",
        template_name="Unix Account (SSH Password)",
    )

    for bad_secret_line in (
        replace(original_secret_line, depends_on=()),
        replace(original_secret_line, depends_on=("unexpected-dependency-ref",)),
    ):
        lines = (target_line, bad_secret_line)
        content = dict(original.canonical_content())
        content["lines"] = [item.as_dict() for item in lines]
        plan = replace(original, lines=lines, plan_digest=canonical_digest(content))
        with pytest.raises(FixedActionResolutionError) as exc_info:
            promoter.promote(
                plan,
                bad_secret_line.line_ref,
                V4PlanningPrincipal(requester, "a" * 64),
                draft=draft,
                onboarding_binding=binding,
                now_epoch=plan.created_at + 1,
            )
        assert exc_info.value.failure_stage == "fixed_action_runner_promotion_shape"


def test_dynamic_runner_binds_after_plan_without_device_or_material_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    services = _Services()
    line = services.plan.lines[0]
    credential_bindings = tmp_path / "credential-bindings.local.yaml"
    credential_bindings.write_text(
        "schema_version: credential-bindings-v1\n"
        "bindings:\n"
        "  - id: fixed-secret-create\n"
        "    provider: env-file\n"
        "    variables:\n"
        "      username: FIXED_TEST_USERNAME\n"
        "      password: FIXED_TEST_PASSWORD\n",
        encoding="utf-8",
    )
    credential_bindings.chmod(0o600)
    missing_secret_env = tmp_path / "material-must-not-be-read-during-bind.env"
    factory = FortiPam191LabAutoSecretCreateRunnerFactory(
        promoter=_promoter(services),
        credential_bindings_path=credential_bindings,
        secret_env_path=missing_secret_env,
        material_binding_ref="private-material-binding-ref01",
        credential_binding_id="fixed-secret-create",
        transport_config=SecretMetadataHttpTransportConfig(
            "https://fortipam.example.test",
            "test-token",
            5,
            None,
        ),
        material_state_store=InMemoryMaterialUseStateStore(),
        execution_store=InMemoryM4ExecutionStateStore(),
        clock=lambda: services.plan.created_at + 1,
    )

    runner = factory.bind(
        services.plan,
        line.line_ref,
        V4PlanningPrincipal(services.requester, "a" * 64),
        draft=_central_lab_draft(services),
        onboarding_binding=_binding(),
    )

    assert runner.line_ref == line.line_ref
    assert not missing_secret_env.exists()
    assert repr(factory) == (
        "<FortiPam191LabAutoSecretCreateRunnerFactory redacted>"
    )

    services.draft = _central_lab_draft(services)
    binding = _binding()

    class _Source:
        @staticmethod
        def resolve_private_binding(draft, requester):
            assert draft == services.draft
            assert requester == services.requester
            return binding

    sequence = SecretOnboardingFixedActionSequenceResolver(  # type: ignore[arg-type]
        services,
        _Source(),
        factory,
    ).resolve(
        services.plan.plan_ref,
        "secret-onboarding-draft01",
        V4PlanningPrincipal(services.requester, "a" * 64),
    )

    assert sequence.plan_ref == services.plan.plan_ref
    assert [item.line_ref for item in sequence.runners] == [line.line_ref]

    web_draft = replace(
        _web_draft(),
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="central_lab_inventory_reference",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )
    web_desired = next(
        item
        for item in web_draft.desired_objects
        if item.object_class is ObjectClass.WEB_SECRET_METADATA
    )
    web_line = replace(
        line,
        target_ref=web_desired.object_ref,
        target_class=ObjectClass.WEB_SECRET_METADATA,
        change_kind=ChangeKind.CREATE,
        depends_on=(),
    )
    web_content = dict(services.plan.canonical_content())
    web_content["lines"] = [web_line.as_dict()]
    web_plan = replace(
        services.plan,
        lines=(web_line,),
        scheme_id=SchemeId.SECRET_ONBOARDING,
        plan_digest=canonical_digest(web_content),
    )
    web_runner = factory.bind(
        web_plan,
        web_line.line_ref,
        V4PlanningPrincipal(services.requester, "a" * 64),
        draft=web_draft,
        onboarding_binding=_web_binding(),
    )

    assert web_runner.line_ref == web_line.line_ref
    factory._promoter = _promoter(services, "fortipam-700-build29-web-create-candidate")
    candidate_runner = factory.bind(
        web_plan, web_line.line_ref, V4PlanningPrincipal(services.requester, "a" * 64),
        draft=web_draft, onboarding_binding=_web_binding(),
    )
    assert candidate_runner.line_ref == web_line.line_ref
    assert not missing_secret_env.exists()

    from fortipam_mcp import secret_create_lab_auto_runtime as runtime
    original_binding = runtime.SecretCreate191TargetBinding
    captured = []

    def capture_binding(*args, **kwargs):
        bound = original_binding(*args, **kwargs)
        captured.append(bound)
        return bound

    monkeypatch.setattr(runtime, "SecretCreate191TargetBinding", capture_binding)
    factory._promoter = _promoter(services, LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE)
    rdp_runner = factory.bind(
        services.plan, line.line_ref, V4PlanningPrincipal(services.requester, "a" * 64),
        draft=replace(_rdp_draft(), material_reference_metadata=web_draft.material_reference_metadata),
        onboarding_binding=replace(_rdp_binding(), template_name="Windows Machine"),
    )
    assert rdp_runner.line_ref == line.line_ref
    assert len(captured) == 1
    assert captured[0].contract_ref == "fortipam-700-build29-windows-rdp-create-candidate-v1"
    assert (captured[0].target_product_version, captured[0].target_product_build) == ("7.0.0", 29)
    assert captured[0].rdp_service_enabled is True
    assert not missing_secret_env.exists()


@pytest.mark.parametrize("broken_input", ["binding", "env", "material", "execution"])
def test_environment_builder_keeps_protected_state_domains_independent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    broken_input: str,
) -> None:
    def owner_key(name: str, byte: bytes) -> Path:
        path = tmp_path / name
        path.write_bytes(byte * 32)
        path.chmod(0o600)
        return path

    authority_key = owner_key("authority.key", b"a")
    material_key = owner_key("material.key", b"m")
    execution_key = owner_key("execution.key", b"e")
    missing_secret_env = tmp_path / "material-must-not-be-read-at-startup.env"
    environment = {
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORITY_KEY_FILE": str(
            authority_key
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_ENVIRONMENT_REF": (
            "lab-auto-environment-ref01"
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}AUTHORIZED_SCOPE_REF": (
            "lab-auto-scope-ref000001"
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}CREDENTIAL_BINDINGS_FILE": str(
            tmp_path / "credential-bindings.local.yaml"
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}SECRET_ENV_FILE": str(
            missing_secret_env
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}MATERIAL_BINDING_REF": (
            "private-material-binding-ref01"
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}CREDENTIAL_BINDING_ID": (
            "fixed-secret-create"
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}MATERIAL_STATE_DB": str(
            tmp_path / "material.sqlite3"
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}MATERIAL_STATE_HMAC_KEY_FILE": str(
            material_key
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}EXECUTION_STATE_DB": str(
            tmp_path / "execution.sqlite3"
        ),
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}EXECUTION_STATE_HMAC_KEY_FILE": str(
            execution_key
        ),
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_BASE_URL": (
            "https://fortipam.example.test"
        ),
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_API_TOKEN": "test-token",
    }

    factory = build_fortipam_191_lab_auto_secret_runner_factory(environment)

    assert isinstance(factory, FortiPam191LabAutoSecretCreateRunnerFactory)
    assert factory._promoter.product_profile == "fortipam-191"
    candidate_environment = {**environment, f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE": "fortipam-700-build29-web-create-candidate"}
    candidate = build_fortipam_191_lab_auto_secret_runner_factory(candidate_environment)
    assert candidate._promoter.product_profile == "fortipam-700-build29-web-create-candidate"
    candidate_environment[f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE"] = "7.0.0"
    with pytest.raises(OnboardingActionCoordinatorError):
        build_fortipam_191_lab_auto_secret_runner_factory(candidate_environment)
    assert load_lab_auto_secret_create_authorized_scope(environment) == (
        "lab-auto-environment-ref01",
        "lab-auto-scope-ref000001",
    )
    assert not missing_secret_env.exists()
    assert (tmp_path / "material.sqlite3").is_file()
    assert (tmp_path / "execution.sqlite3").is_file()

    from fortipam_mcp import secret_create_lab_auto_runtime as runtime

    forbidden_calls = []

    def forbidden(*args, **kwargs):
        forbidden_calls.append(True)
        raise AssertionError("readiness must not acquire, claim, promote, or dispatch")

    for owner, name in (
        (runtime, "MaterialLeaseRequest"),
        (runtime, "M4ExecutionAuthorization"),
        (runtime.LabAutoSecretCreatePromoter, "promote"),
        (runtime.CentralLabInventorySecretCreateProvider, "acquire_lease"),
        (runtime.OwnerOnlyCentralLabSecretCreateEnvFileLoader, "load_secret_create_material_once"),
        (runtime.PersistentMaterialUseStateStore, "claim"),
        (runtime.PersistentMaterialUseStateStore, "finalize"),
        (runtime.PersistentM4ExecutionStateStore, "claim"),
        (runtime.PersistentM4ExecutionStateStore, "finalize"),
        (runtime.FortiPam191SecretCreateHttpTransport, "__init__"),
        (runtime.FortiPamSecretMetadataHttpTransport, "__init__"),
    ):
        monkeypatch.setattr(owner, name, forbidden)
    assert factory.execution_preflight_available() is False
    binding_file = tmp_path / "credential-bindings.local.yaml"
    binding_file.write_text(
        "schema_version: credential-bindings-v1\nbindings:\n"
        "  - id: fixed-secret-create\n    provider: env-file\n"
        "    variables:\n      username: TEST_USERNAME\n      password: TEST_PASSWORD\n",
        encoding="utf-8",
    )
    binding_file.chmod(0o600)
    missing_secret_env.write_text(
        "TEST_USERNAME=synthetic-user\nTEST_PASSWORD=synthetic-value\n", encoding="utf-8"
    )
    missing_secret_env.chmod(0o600)
    state_paths = (tmp_path / "material.sqlite3", tmp_path / "execution.sqlite3")
    before = tuple(path.read_bytes() for path in state_paths)
    assert factory.execution_preflight_available() is True
    assert factory.execution_preflight_available() is True
    assert tuple(path.read_bytes() for path in state_paths) == before
    if broken_input == "binding":
        binding_file.write_text("schema_version: invalid\n", encoding="utf-8")
    elif broken_input == "env":
        missing_secret_env.write_text("TEST_USERNAME=synthetic-user\n", encoding="utf-8")
    else:
        (tmp_path / f"{broken_input}.sqlite3").write_bytes(b"invalid ledger")
    assert factory.execution_preflight_available() is False
    assert forbidden_calls == []

    environment[
        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}EXECUTION_STATE_HMAC_KEY_FILE"
    ] = str(material_key)
    with pytest.raises(OnboardingActionCoordinatorError, match="unavailable"):
        build_fortipam_191_lab_auto_secret_runner_factory(environment)


def test_web_candidate_rejects_target_profile():
    services = _Services()
    draft, line = _central_lab_draft(services), services.plan.lines[0]
    with pytest.raises(OnboardingActionCoordinatorError):
        _promoter(services, "fortipam-700-build29-web-create-candidate").promote(
            services.plan, line.line_ref, V4PlanningPrincipal(services.requester, "a" * 64),
            draft=draft, onboarding_binding=_binding(), now_epoch=services.plan.created_at + 1,
        )


def test_unknown_product_profile_is_rejected():
    with pytest.raises(OnboardingActionCoordinatorError):
        _promoter(_Services(), "7.0.0")


def _collector_context():
    from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700WinrmBinding
    from fortipam_mcp.winrm_collector_projection_reader import WinrmCollectorProjectionReader, winrm_collector_projection_contract
    from test_v4_planning import _winrm_collector_draft, _desired

    services = _Services()
    bound = replace(_binding(), template_name="Windows Machine", target_protocol="rdp")
    private = SecretCreate700WinrmBinding(
        "fortipam-700-build29-winrm-collector-create-candidate-v2", "7.0.0", "1" * 64,
        bound.folder_path, bound.secret_name, bound.template_name, bound.target_name,
        bound.target_ipv4_address, "collector-owner", "Public/witness-folder", "existing-witness",
        "mcp-v4-rdp-event-filter-example",
    )
    draft = replace(_winrm_collector_draft(),
        environment_ref=services.plan.environment_ref, scope_ref=services.plan.scope_ref,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="central_lab_inventory_reference", purpose="initial_onboarding", lifecycle="available"),
        desired_objects=(
            _desired(bound.folder_object_ref, ObjectClass.FOLDER_BINDING, {"folder_ref": bound.folder_ref}),
            _desired(bound.target_object_ref, ObjectClass.TARGET, {"protocol": "rdp", "connectivity_profile_ref": bound.connectivity_profile_ref}),
            _desired(bound.template_object_ref, ObjectClass.TEMPLATE_BINDING, {"compatibility": "compatible", "template_ref": bound.template_ref}),
            _desired(bound.secret_object_ref, ObjectClass.WINRM_COLLECTOR_METADATA, {
                "inherit_permission": True, "privileged_account": True, "owner_only_folder": True,
                "rdp_service_enabled": True, "recording_enabled": True,
                "rdp_event_filter_enabled": True, "rdp_event_filter_profile_matches": True,
                "non_rdp_services_disabled": True, "target_association_matches": True}),
        ))
    reader = WinrmCollectorProjectionReader(private, bound.secret_object_ref, None)  # type: ignore[arg-type]
    line = replace(services.plan.lines[0], target_ref=bound.secret_object_ref,
        target_class=ObjectClass.WINRM_COLLECTOR_METADATA,
        expected_current_digest=reader.state_digest(exists=False), expected_state_digest=reader.state_digest(exists=True),
        projection_contract_ref=winrm_collector_projection_contract().contract_id)
    content = {**services.plan.canonical_content(), "lines": [line.as_dict()]}
    plan = replace(services.plan, lines=(line,), plan_digest=canonical_digest(content))
    return services, bound, private, draft, plan


def test_collector_promotion_and_factory_preserve_protected_material_boundary(tmp_path):
    from fortipam_mcp.secret_create_lab_auto_runtime import LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE
    from fortipam_mcp.winrm_collector_projection_reader import ADAPTER_REF, winrm_collector_binding_digest
    services, bound, private, draft, plan = _collector_context()
    promoter = LabAutoSecretCreatePromoter(b"a" * 32,
        authorized_environment_ref=plan.environment_ref, authorized_scope_ref=plan.scope_ref,
        product_profile=LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE, collector_binding=private)
    principal = V4PlanningPrincipal(services.requester, "a" * 64)
    artifacts = promoter.promote(plan, plan.lines[0].line_ref, principal, draft=draft,
                                 onboarding_binding=bound, now_epoch=plan.created_at + 1)
    assert artifacts.plan.adapter_ref == ADAPTER_REF
    assert artifacts.plan.parameters_digest == winrm_collector_binding_digest(private, bound.secret_object_ref)
    credentials = tmp_path / "bindings.yaml"
    credentials.write_text("schema_version: credential-bindings-v1\nbindings:\n  - id: fixed-secret-create\n    provider: env-file\n    variables:\n      username: FIXED_TEST_USERNAME\n      password: FIXED_TEST_PASSWORD\n")
    credentials.chmod(0o600)
    missing_material = tmp_path / "must-not-be-read.env"
    factory = FortiPam191LabAutoSecretCreateRunnerFactory(
        promoter=promoter, credential_bindings_path=credentials, secret_env_path=missing_material,
        material_binding_ref="private-material-binding-ref01", credential_binding_id="fixed-secret-create",
        transport_config=SecretMetadataHttpTransportConfig("https://fortipam.example.test", "test-token", 5, None),
        material_state_store=InMemoryMaterialUseStateStore(), execution_store=InMemoryM4ExecutionStateStore(),
        clock=lambda: plan.created_at + 1)
    runner = factory.bind(plan, plan.lines[0].line_ref, principal, draft=draft, onboarding_binding=bound)
    assert runner.line_ref == plan.lines[0].line_ref and not missing_material.exists()
    assert runner.onboarding_binding_digest == artifacts.plan.parameters_digest

    from fortipam_mcp.winrm_collector_projection_reader import WinrmCollectorPlanningSource

    class Resolver:
        def resolve(self, requested, requester):
            assert requested is draft and requester == principal.requester
            return bound

    source = WinrmCollectorPlanningSource(private, Resolver(), None)  # type: ignore[arg-type]
    sequence = SecretOnboardingFixedActionSequenceResolver(services, source, factory).bind_prepared(plan, draft, principal)
    assert len(sequence.runners) == 1 and sequence.runners[0].line_ref == plan.lines[0].line_ref
    changed_source = WinrmCollectorPlanningSource(replace(private, folder_owner_name="different-owner"), Resolver(), None)  # type: ignore[arg-type]
    with pytest.raises(FixedActionResolutionError) as mismatch:
        SecretOnboardingFixedActionSequenceResolver(services, changed_source, factory).bind_prepared(plan, draft, principal)
    assert mismatch.value.failure_stage == "fixed_action_private_binding"
    assert not missing_material.exists()


@pytest.mark.parametrize("mode", ["missing_binding", "ordinary_profile", "different_target", "wrong_secret_class", "update", "wrong_readback", "wrong_folder_relation"])
def test_collector_requires_exact_opt_in_profile_and_private_binding(mode):
    from fortipam_mcp.secret_create_lab_auto_runtime import LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE
    services, bound, private, draft, plan = _collector_context()
    if mode in {"missing_binding", "ordinary_profile"}:
        with pytest.raises(OnboardingActionCoordinatorError):
            LabAutoSecretCreatePromoter(b"a" * 32,
                authorized_environment_ref=plan.environment_ref, authorized_scope_ref=plan.scope_ref,
                product_profile="fortipam-191" if mode == "ordinary_profile" else LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE,
                collector_binding=None if mode == "missing_binding" else private)
        return
    promoter = LabAutoSecretCreatePromoter(b"a" * 32,
        authorized_environment_ref=plan.environment_ref, authorized_scope_ref=plan.scope_ref,
        product_profile=LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE, collector_binding=private)
    if mode == "different_target":
        bound = replace(bound, target_name="different-target")
    elif mode == "wrong_folder_relation":
        draft = replace(draft, desired_objects=tuple(
            replace(o, desired_fields=(("folder_ref", "unrelated-folder-ref01"),))
            if o.object_class is ObjectClass.FOLDER_BINDING else o for o in draft.desired_objects))
    elif mode in {"update", "wrong_readback"}:
        line = replace(plan.lines[0], **({"change_kind": ChangeKind.UPDATE} if mode == "update" else {"expected_state_digest": "f" * 64}))
        plan = replace(plan, lines=(line,), plan_digest=canonical_digest({**plan.canonical_content(), "lines": [line.as_dict()]}))
    else:
        draft = replace(draft, desired_objects=tuple(
            replace(o, object_class=ObjectClass.SECRET_METADATA) if o.object_class is ObjectClass.WINRM_COLLECTOR_METADATA else o
            for o in draft.desired_objects))
    with pytest.raises(FixedActionResolutionError):
        promoter.promote(plan, plan.lines[0].line_ref, V4PlanningPrincipal(services.requester, "a" * 64),
                         draft=draft, onboarding_binding=bound, now_epoch=plan.created_at + 1)


@pytest.mark.parametrize("mode", ["valid", "shared", "symlink", "extra_key"])
def test_collector_private_file_loader_is_closed_and_owner_only(tmp_path, mode):
    import json
    from dataclasses import asdict
    from fortipam_mcp.secret_create_191_private_adapter import load_winrm_collector_private_binding
    from v4_planning.secret_create_adapter import SecretCreateAdapterDenied

    _, _, private, _, _ = _collector_context()
    payload = asdict(private)
    payload.pop("plan_digest")
    if mode == "extra_key":
        payload["unqualified_option"] = True
    path = tmp_path / "collector.json"
    path.write_text(json.dumps(payload))
    path.chmod(0o644 if mode == "shared" else 0o600)
    if mode == "symlink":
        link = tmp_path / "linked.json"
        link.symlink_to(path)
        path = link
    if mode == "valid":
        loaded = load_winrm_collector_private_binding(path)
        assert loaded == replace(private, plan_digest="0" * 64)
    else:
        with pytest.raises(SecretCreateAdapterDenied):
            load_winrm_collector_private_binding(path)


@pytest.mark.parametrize("readback_matches", [True, False])
@pytest.mark.parametrize("owner_session", [False, True])
def test_collector_real_factory_executes_protected_material_and_http_body(tmp_path, monkeypatch, readback_matches, owner_session):
    import json
    from fortipam_mcp import secret_create_191_http_transport as http_module
    from fortipam_mcp.secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, SecretMetadataInspection
    from fortipam_mcp.secret_create_lab_auto_runtime import LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE
    from test_secret_create_191_http_transport import _Response

    services, bound, private, draft, plan = _collector_context()
    credentials = tmp_path / "bindings.yaml"
    credentials.write_text("schema_version: credential-bindings-v1\nbindings:\n  - id: fixed-secret-create\n    provider: env-file\n    variables:\n      username: FIXED_TEST_USERNAME\n      password: FIXED_TEST_PASSWORD\n")
    credentials.chmod(0o600)
    material = tmp_path / "synthetic.env"
    material.write_text("FIXED_TEST_USERNAME=synthetic-user\nFIXED_TEST_PASSWORD=synthetic-password\n")
    material.chmod(0o600)
    calls = []
    buffers = []
    session_events = []

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, path, body, headers):
            if owner_session:
                assert session_events[-1] == "login"
            assert method == "POST" and path == "/api/v2/cmdb/secret/database"
            payload = json.loads(bytes(body))
            assert payload["target-privilege-account"] == "enable"
            assert payload["recording"] == "enable"
            assert payload["rdp-event-filter"] == "enable"
            assert payload["rdp-event-filter-profile"] == private.rdp_event_filter_profile_name
            assert payload["rdp-service-status"] == "up"
            assert all(payload[name + "-service-status"] == "down" for name in ("ssh", "http", "samba", "telnet"))
            values = {item["name"]: item["value"] for item in payload["field"]}
            assert values == {"Host": private.target_ipv4_address, "Username": "synthetic-user", "Password": "synthetic-password"}
            buffers.append(body.obj)
            calls.append("post")

        def getresponse(self):
            return _Response(200)

        def close(self):
            pass

    monkeypatch.setattr(http_module.http.client, "HTTPSConnection", Connection)
    metadata = FortiPamSecretMetadataHttpTransport
    monkeypatch.setattr(metadata, "inspect", lambda *args: SecretMetadataInspection(False, True, True))
    monkeypatch.setattr(metadata, "verify_winrm_collector_preflight", lambda *args: True)
    monkeypatch.setattr(metadata, "read_product_version_and_build", lambda *args: ("7.0.0", 29))
    monkeypatch.setattr(metadata, "resolve_folder_id", lambda *args: 17)
    monkeypatch.setattr(metadata, "resolve_secret_create_uuid", lambda *args: "11111111-2222-4333-8444-555555555555")
    monkeypatch.setattr(metadata, "resolve_existing_secret_id", lambda *args: 23)
    def readback(*args, **kwargs):
        if owner_session:
            assert session_events[-1] == "login"
        calls.append("readback")
        return readback_matches
    monkeypatch.setattr(metadata, "verify_winrm_collector", readback)
    if owner_session:
        from contextlib import contextmanager
        from fortipam_mcp import owner_collector_runtime
        @contextmanager
        def authenticated():
            session_events.append("login")
            try:
                yield
            finally:
                session_events.append("logout")
        def build_owner(config, binding, credentials, *, allow_secret_create):
            assert binding == private and allow_secret_create is True
            assert session_events == []
            selected = metadata(config, bound_secret_name=bound.secret_name)
            selected.authenticated = authenticated
            selected.secret_create_connection = Connection
            return selected
        monkeypatch.setattr(owner_collector_runtime, "owner_collector_transport", build_owner)
    factory = FortiPam191LabAutoSecretCreateRunnerFactory(
        promoter=LabAutoSecretCreatePromoter(b"a" * 32,
            authorized_environment_ref=plan.environment_ref, authorized_scope_ref=plan.scope_ref,
            product_profile=LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE, collector_binding=private),
        credential_bindings_path=credentials, secret_env_path=material,
        material_binding_ref="private-material-binding-ref01", credential_binding_id="fixed-secret-create",
        transport_config=SecretMetadataHttpTransportConfig("https://fortipam.example.test", "test-token", 5, None),
        material_state_store=InMemoryMaterialUseStateStore(), execution_store=InMemoryM4ExecutionStateStore(),
        owner_credentials=(lambda: ("gui-owner", "synthetic")) if owner_session else None,
        clock=lambda: plan.created_at + 1)
    runner = factory.bind(plan, plan.lines[0].line_ref,
        V4PlanningPrincipal(services.requester, "a" * 64), draft=draft, onboarding_binding=bound)
    assert session_events == []
    result = runner.execute_bound()
    assert (result["outcome"] == "succeeded") is readback_matches, result
    assert calls == ["post", "readback"]
    assert buffers and all(not any(buffer) for buffer in buffers)
    assert session_events == (["login", "logout"] if owner_session else [])
    runner.execute_bound()
    assert calls == ["post", "readback"]


def _target_bound_web_context():
    from test_target_bound_web_projection_reader import planning_source, Transport
    from fortipam_mcp.target_bound_web_projection_reader import target_bound_web_state_digest

    services = _Services()
    draft, source = planning_source(Transport())
    bound = replace(source._binding, requester_digest=services.requester.digest,
                    environment_ref=services.plan.environment_ref, scope_ref=services.plan.scope_ref)
    draft = replace(draft, environment_ref=bound.environment_ref, scope_ref=bound.scope_ref)
    line = replace(services.plan.lines[0], target_ref=bound.secret_object_ref,
                   target_class=ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA,
                   expected_current_digest=target_bound_web_state_digest(bound.secret_object_ref, exists=False),
                   expected_state_digest=target_bound_web_state_digest(bound.secret_object_ref, exists=True),
                   projection_contract_ref="fortipam-target-bound-web-observation-v1")
    plan = replace(services.plan, lines=(line,), plan_digest=canonical_digest({
        **services.plan.canonical_content(), "lines": [line.as_dict()],
    }))
    return services, bound, draft, plan


def _target_bound_web_promoter(bound, plan):
    from fortipam_mcp.secret_create_lab_auto_runtime import LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE

    return LabAutoSecretCreatePromoter(
        b"a" * 32, authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref, product_profile=LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE,
        bound_web_binding=bound,
    )


@pytest.mark.parametrize("readback_matches", [True, False])
def test_target_bound_web_factory_uses_real_material_transport_and_independent_readback(
    tmp_path, monkeypatch, readback_matches,
):
    import json
    from fortipam_mcp import secret_create_lab_auto_runtime as module
    from fortipam_mcp import secret_create_191_http_transport as http_module
    from fortipam_mcp.target_bound_web_projection_reader import ADAPTER_REF, target_bound_web_binding_digest
    from test_secret_create_191_http_transport import _Connection, _MetadataTransport
    from test_target_bound_web_projection_reader import ABSENT, PRESENT

    services, bound, draft, plan = _target_bound_web_context()
    principal = V4PlanningPrincipal(services.requester, "a" * 64)
    promoter = _target_bound_web_promoter(bound, plan)
    artifacts = promoter.promote(plan, plan.lines[0].line_ref, principal, draft=draft,
                                 onboarding_binding=bound, now_epoch=plan.created_at + 1)
    assert artifacts.plan.adapter_ref == ADAPTER_REF
    assert artifacts.plan.parameters_digest == target_bound_web_binding_digest(bound.create_binding, bound.secret_object_ref)
    credentials = tmp_path / "bindings.yaml"
    credentials.write_text("schema_version: credential-bindings-v1\nbindings:\n  - id: fixed-secret-create\n    provider: env-file\n    variables:\n      username: FIXED_TEST_USERNAME\n      password: FIXED_TEST_PASSWORD\n")
    credentials.chmod(0o600)
    material = tmp_path / "synthetic.env"
    material.write_text("FIXED_TEST_USERNAME=synthetic-user\nFIXED_TEST_PASSWORD=synthetic-password\n")
    material.chmod(0o600)
    events, bodies, buffers, selectors = [], [], [], []

    class Metadata(_MetadataTransport):
        def inspect_target_bound_web_projection(self, folder, name, *, target):
            selectors.append((folder, name, target))
            events.append("read")
            if bodies:
                return replace(PRESENT, proxy_mode_enabled=readback_matches)
            return ABSENT

    class Connection(_Connection):
        def request(self, method, path, body, headers):
            events.append("post")
            bodies.append((method, path, json.loads(bytes(body))))
            buffers.append(body.obj)

    monkeypatch.setattr(module, "FortiPamSecretMetadataHttpTransport", lambda *a, **k: Metadata())
    monkeypatch.setattr(http_module.http.client, "HTTPSConnection", Connection)
    factory = FortiPam191LabAutoSecretCreateRunnerFactory(
        promoter=promoter, credential_bindings_path=credentials, secret_env_path=material,
        material_binding_ref="private-material-binding-ref01", credential_binding_id="fixed-secret-create",
        transport_config=SecretMetadataHttpTransportConfig("https://fortipam.example.test", "test-token", 5, None),
        material_state_store=InMemoryMaterialUseStateStore(), execution_store=InMemoryM4ExecutionStateStore(),
        clock=lambda: plan.created_at + 1,
    )
    from fortipam_mcp.target_bound_web_projection_reader import TargetBoundWebPlanningSource
    source = TargetBoundWebPlanningSource(bound, Metadata())
    resolver = SecretOnboardingFixedActionSequenceResolver(
        services, source, factory, target_bound_web_runner_factory=factory,
    )
    sequence = resolver.bind_prepared(plan, draft, principal)
    assert len(sequence.runners) == 1
    runner = sequence.runners[0]
    with pytest.raises(FixedActionResolutionError):
        resolver.bind_prepared(plan, draft, principal, external_dependency_refs=("extra-ref01",))
    unbound_resolver = SecretOnboardingFixedActionSequenceResolver(services, source, factory)
    with pytest.raises(FixedActionResolutionError):
        unbound_resolver.bind_prepared(plan, draft, principal)
    assert events == []
    assert runner.onboarding_binding_digest == artifacts.plan.parameters_digest
    result = runner.execute_bound()
    assert (result["outcome"] == "succeeded") is readback_matches, result
    assert events == ["read", "read", "post", "read"]
    assert selectors == [(bound.create_binding.folder_path, bound.create_binding.secret_name,
                          bound.create_binding.target)] * 3
    method, path, body = bodies[0]
    assert method == "POST" and path == "/api/v2/cmdb/secret/database"
    assert body["target"] == bound.create_binding.target.target_name
    assert body["field"] == [
        {"id": 0, "name": "Password", "value": "synthetic-password"},
        {"id": 0, "name": "Username", "value": "synthetic-user"},
    ]
    assert body["proxy"] == "enable" and body["http-service-status"] == "up"
    assert body["recording"] == "enable"
    assert all(not any(buffer) for buffer in buffers)
    runner.execute_bound()
    assert events == ["read", "read", "post", "read"]


@pytest.mark.parametrize("mode", [
    "wrong_profile", "missing_binding", "changed_binding", "legacy_binding",
    "wrong_contract", "wrong_current", "wrong_expected", "update", "dependencies",
])
def test_target_bound_web_promotion_rejects_mixed_profiles_and_plan_drift(mode):
    from fortipam_mcp.secret_create_lab_auto_runtime import LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE

    services, bound, draft, plan = _target_bound_web_context()
    if mode in {"wrong_profile", "missing_binding"}:
        with pytest.raises(OnboardingActionCoordinatorError):
            LabAutoSecretCreatePromoter(
                b"a" * 32, authorized_environment_ref=plan.environment_ref,
                authorized_scope_ref=plan.scope_ref,
                product_profile=LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE if mode == "missing_binding" else "fortipam-191",
                bound_web_binding=None if mode == "missing_binding" else bound,
            )
        return
    promoter = _target_bound_web_promoter(bound, plan)
    if mode == "changed_binding":
        bound = replace(bound, create_binding=replace(bound.create_binding, secret_name="different-secret"))
    elif mode == "legacy_binding":
        bound = _web_binding()
    else:
        changes = {
            "wrong_contract": {"projection_contract_ref": "different-contract"},
            "wrong_current": {"expected_current_digest": "a" * 64},
            "wrong_expected": {"expected_state_digest": "b" * 64},
            "update": {"change_kind": ChangeKind.UPDATE},
            "dependencies": {"depends_on": ("different-line-ref01",)},
        }[mode]
        line = replace(plan.lines[0], **changes)
        plan = replace(plan, lines=(line,), plan_digest=canonical_digest({
            **plan.canonical_content(), "lines": [line.as_dict()],
        }))
    with pytest.raises(OnboardingActionCoordinatorError):
        promoter.promote(plan, plan.lines[0].line_ref, V4PlanningPrincipal(services.requester, "a" * 64),
                         draft=draft, onboarding_binding=bound, now_epoch=plan.created_at + 1)


@pytest.mark.parametrize("mode", ["valid", "missing_path", "scope_drift", "environment_drift"])
def test_target_bound_web_environment_builder_requires_separate_exact_binding(tmp_path, mode):
    import json
    from fortipam_mcp.secret_create_lab_auto_runtime import LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE
    from test_target_bound_web_projection_reader import binding_payload

    payload = binding_payload()
    binding_path = tmp_path / "target-web-binding.json"
    binding_path.write_text(json.dumps(payload))
    binding_path.chmod(0o600)
    config = {
        "PROFILE": LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE,
        "AUTHORIZED_ENVIRONMENT_REF": payload["environment_ref"],
        "AUTHORIZED_SCOPE_REF": payload["scope_ref"],
        "TARGET_WEB_BINDING_FILE": str(binding_path),
        "CREDENTIAL_BINDINGS_FILE": str(tmp_path / "bindings.yaml"),
        "SECRET_ENV_FILE": str(tmp_path / "unread-material.env"),
        "MATERIAL_BINDING_REF": "private-material-binding-ref01",
        "CREDENTIAL_BINDING_ID": "fixed-secret-create",
        "MATERIAL_STATE_DB": str(tmp_path / "material.sqlite3"),
        "EXECUTION_STATE_DB": str(tmp_path / "execution.sqlite3"),
    }
    for key, seed in (("AUTHORITY_KEY_FILE", b"a"), ("MATERIAL_STATE_HMAC_KEY_FILE", b"m"),
                      ("EXECUTION_STATE_HMAC_KEY_FILE", b"e")):
        path = tmp_path / (key + ".key")
        path.write_bytes(seed * 32)
        path.chmod(0o600)
        config[key] = str(path)
    if mode == "missing_path":
        config.pop("TARGET_WEB_BINDING_FILE")
    elif mode == "scope_drift":
        config["AUTHORIZED_SCOPE_REF"] = "different-scope-ref01"
    elif mode == "environment_drift":
        config["AUTHORIZED_ENVIRONMENT_REF"] = "different-environment-ref01"
    env = {LAB_AUTO_SECRET_CREATE_ENV_PREFIX + key: value for key, value in config.items()}
    env.update({
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_BASE_URL": "https://fortipam.example.test",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_API_TOKEN": "synthetic-token",
    })
    if mode == "valid":
        factory = build_fortipam_191_lab_auto_secret_runner_factory(env)
        assert factory._promoter.product_profile == LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE
        assert factory._promoter._bound_web_binding.create_binding.secret_name == payload["secret_name"]
    else:
        with pytest.raises(OnboardingActionCoordinatorError):
            build_fortipam_191_lab_auto_secret_runner_factory(env)
    assert not (tmp_path / "unread-material.env").exists()
