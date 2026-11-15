from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
import re
from typing import Callable, cast

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from fortipam_mcp.local_oauth import (
    LocalOAuthProvider,
    LocalOAuthSettings,
    hash_local_password,
)
from fortipam_mcp.access_domain_projection_source import (
    SOURCE_REF as ACCESS_SOURCE_REF,
)
from fortipam_mcp.onboarding_action_coordinator import (
    FixedActionResolutionError,
    OnboardingActionCoordinator,
    OnboardingActionCoordinatorError,
    ResolvedFixedActionSequence,
)
from fortipam_mcp.linux_onboarding_action_sequence import (
    ExistingDomainLinuxOnboardingFixedActionSequenceResolver,
)
from fortipam_mcp.secret_create_191_private_adapter import (
    FortiPam191SecretCreatePrivateAdapter,
    SecretCreate191TargetBinding,
)
from fortipam_mcp.secret_create_m4_binding import (
    OwnerOnlySecretCreateM4BindingResolver,
    SECRET_CREATE_M4_BINDING_CONTRACT,
    SECRET_CREATE_M4_BINDING_VERSION,
)
from fortipam_mcp.secret_onboarding_action_sequence import (
    ExactSecretCreateM4RunnerFactory,
    OwnerOnlySecretCreateM4RunnerFactory,
    ProtectedSecretCreateRunnerBinding,
    SECRET_CREATE_RUNNER_BINDING_CONTRACT,
    SECRET_CREATE_RUNNER_BINDING_VERSION,
    SecretOnboardingFixedActionSequenceResolver,
    _SecretCreateRunner,
    _BoundTargetCreateRunner,
)
from fortipam_mcp.secret_onboarding_projection_source import (
    FortiPamSecretOnboardingProjectionSource,
    SOURCE_REF,
    SecretOnboardingBinding,
    secret_onboarding_binding_digest,
)
from fortipam_mcp.winrm_collector_projection_reader import (
    ADAPTER_REF as WINRM_COLLECTOR_ADAPTER_REF,
    WinrmCollectorProjectionReader,
    winrm_collector_binding_digest,
    winrm_collector_projection_contract,
    winrm_collector_state_digest,
)
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from fortipam_mcp.v4_runtime_host import (
    V4RuntimeHostError,
    V4PersistentReferenceAuthoritySettings,
    V4PersistentSchemeDraftAuthoritySettings,
    V4SyntheticHostSettings,
    _OnboardingProjectionProvider,
    secret_onboarding_v4_plan_host_factory,
    onboarding_v4_plan_host_factory,
)
from test_secret_onboarding_projection_source import (
    AccessResolver,
    FolderTransport,
    LauncherTransport,
    Resolver,
    SecretTransport,
    TargetTransport,
    _binding,
    _draft,
    _desired,
    _rdp_binding,
    _rdp_draft,
    _web_binding,
    _web_draft,
)
from test_v4_m3 import _plan, _requester
from v4_planning import (
    ChangeKind,
    InMemoryM4ExecutionStateStore,
    M4Compensation,
    M4ExecutionAuthorization,
    M4ExecutionPlan,
    M4ExecutionResult,
    M4Outcome,
    M4Verification,
    ObjectClass,
    SchemeId,
    canonical_digest,
)
from v4_planning.material_provider import (
    C3MaterialBinding,
    MaterialBindingStatus,
    MaterialLease,
    MaterialLeaseCompletion,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
    MaterialRevocationReason,
)
from v4_planning.material_runtime import InMemoryMaterialUseStateStore
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    SecretCreateAdapterOutcome,
)
from v4_planning.secret_create_runtime import SecretCreateMaterialRuntime


PLAN_REF = "prepared-plan-ref0001"
DRAFT_REF = "secret-onboarding-draft01"


def _context(*, target_line: bool = False):
    requester = _requester()
    draft = _draft()
    base = _plan(requester)
    target_class = ObjectClass.TARGET if target_line else ObjectClass.SECRET_METADATA
    target = next(item for item in draft.desired_objects if item.object_class is target_class)
    line = replace(
        base.lines[0],
        target_ref=target.object_ref,
        target_class=target_class,
        change_kind=ChangeKind.CREATE,
    )
    content = dict(base.canonical_content())
    content.update(
        {
            "environment_ref": draft.environment_ref,
            "lines": [line.as_dict()],
            "scheme_id": SchemeId.SECRET_ONBOARDING.value,
            "scheme_version": draft.scheme_version,
            "scope_ref": draft.scope_ref,
        }
    )
    plan = replace(
        base,
        environment_ref=draft.environment_ref,
        lines=(line,),
        scheme_id=SchemeId.SECRET_ONBOARDING,
        scheme_version=draft.scheme_version,
        scope_ref=draft.scope_ref,
        plan_digest=canonical_digest(content),
    )
    return requester, draft, plan


def test_web_account_plan_resolves_one_recorded_secret_create_without_target() -> None:
    _requester_value, _draft_value, base = _context()
    draft = _web_draft()
    desired = next(
        item
        for item in draft.desired_objects
        if item.object_class is ObjectClass.WEB_SECRET_METADATA
    )
    line = replace(
        base.lines[0],
        target_ref=desired.object_ref,
        target_class=ObjectClass.WEB_SECRET_METADATA,
        change_kind=ChangeKind.CREATE,
        depends_on=(),
    )
    content = dict(base.canonical_content())
    content["lines"] = [line.as_dict()]
    content["scheme_id"] = SchemeId.SECRET_ONBOARDING.value
    plan = replace(
        base,
        lines=(line,),
        scheme_id=SchemeId.SECRET_ONBOARDING,
        plan_digest=canonical_digest(content),
    )

    target_line, secret_line = SecretOnboardingFixedActionSequenceResolver._validate_plan(
        plan,
        draft,
        _web_binding(),
    )

    assert target_line is None
    assert secret_line.target_class is ObjectClass.WEB_SECRET_METADATA


def test_secret_plan_shape_failure_has_a_safe_resolution_stage() -> None:
    requester, draft, invalid_plan = _context(target_line=True)

    class _ProjectionSource:
        def resolve_private_binding(self, _draft, _requester):
            return _binding()

    resolver = SecretOnboardingFixedActionSequenceResolver(
        None,  # type: ignore[arg-type]
        _ProjectionSource(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
    )
    principal = V4PlanningPrincipal(requester, "a" * 64)

    with pytest.raises(FixedActionResolutionError) as caught:
        resolver.bind_prepared(invalid_plan, draft, principal)

    assert caught.value.failure_stage == "fixed_action_plan_validation"


def _combined_context():
    requester, original_draft, base = _context()
    folder_ref = "combined-public-folder-ref"
    grant_ref = "combined-access-grant-ref"
    secret_objects = tuple(
        replace(item, desired_fields=(("folder_ref", folder_ref),))
        if item.object_class is ObjectClass.FOLDER_BINDING
        else item
        for item in original_draft.desired_objects
    )
    draft = replace(
        original_draft,
        desired_objects=(
            _desired(
                folder_ref,
                ObjectClass.PUBLIC_FOLDER,
                {"enabled": True, "owner_ref": original_draft.owner_ref},
            ),
            _desired(
                grant_ref,
                ObjectClass.ACCESS_GRANT,
                {
                    "permission": "use",
                    "subject_class": "group",
                    "subject_ref": "combined-group-reference",
                },
            ),
            *secret_objects,
        ),
    )
    grant_line = replace(
        base.lines[0],
        line_ref="combined-grant-line-ref",
        target_ref=grant_ref,
        target_class=ObjectClass.ACCESS_GRANT,
        depends_on=(),
    )
    secret_line = replace(
        base.lines[0],
        line_ref="combined-secret-line-ref",
        target_ref="secret-metadata-ref",
        target_class=ObjectClass.SECRET_METADATA,
        depends_on=(grant_line.line_ref,),
    )
    content = dict(base.canonical_content())
    content.update(
        {
            "environment_ref": draft.environment_ref,
            "lines": [grant_line.as_dict(), secret_line.as_dict()],
            "scheme_id": SchemeId.SECRET_ONBOARDING.value,
            "scheme_version": draft.scheme_version,
            "scope_ref": draft.scope_ref,
        }
    )
    plan = replace(
        base,
        environment_ref=draft.environment_ref,
        lines=(grant_line, secret_line),
        scheme_id=SchemeId.SECRET_ONBOARDING,
        scheme_version=draft.scheme_version,
        scope_ref=draft.scope_ref,
        plan_digest=canonical_digest(content),
    )
    return requester, draft, plan, grant_line, secret_line


def _new_domain_combined_context():
    requester, draft, base, grant_line, secret_line = _combined_context()
    folder_line = replace(
        grant_line,
        line_ref="combined-folder-line-ref",
        target_ref="combined-public-folder-ref",
        target_class=ObjectClass.PUBLIC_FOLDER,
        depends_on=(),
    )
    grant_line = replace(grant_line, depends_on=(folder_line.line_ref,))
    secret_line = replace(
        secret_line,
        depends_on=(folder_line.line_ref, grant_line.line_ref),
    )
    content = dict(base.canonical_content())
    content["lines"] = [
        folder_line.as_dict(),
        grant_line.as_dict(),
        secret_line.as_dict(),
    ]
    plan = replace(
        base,
        lines=(folder_line, grant_line, secret_line),
        plan_digest=canonical_digest(content),
    )
    return requester, draft, plan, folder_line, grant_line, secret_line


def _new_domain_new_target_context():
    requester, draft, base, folder_line, grant_line, secret_line = (
        _new_domain_combined_context()
    )
    target = next(
        item
        for item in draft.desired_objects
        if item.object_class is ObjectClass.TARGET
    )
    target_line = replace(
        grant_line,
        line_ref="combined-target-line-ref",
        target_ref=target.object_ref,
        target_class=ObjectClass.TARGET,
        depends_on=(),
    )
    secret_line = replace(
        secret_line,
        depends_on=(
            folder_line.line_ref,
            grant_line.line_ref,
            target_line.line_ref,
        ),
    )
    content = dict(base.canonical_content())
    content["lines"] = [
        folder_line.as_dict(),
        grant_line.as_dict(),
        target_line.as_dict(),
        secret_line.as_dict(),
    ]
    plan = replace(
        base,
        lines=(folder_line, grant_line, target_line, secret_line),
        plan_digest=canonical_digest(content),
    )
    return (
        requester,
        draft,
        plan,
        folder_line,
        grant_line,
        target_line,
        secret_line,
    )


@dataclass(frozen=True)
class _CombinedRunner:
    line_ref: str
    depends_on: tuple[str, ...]

    def execute_bound(self):
        return {"outcome": "succeeded", "verification": "verified"}


class _CombinedServices:
    def __init__(self, requester, draft, plan) -> None:
        self.requester = requester
        self.draft = draft
        self.plan = plan

    def resolve_execution_context(self, plan_ref, draft_ref, principal):
        assert plan_ref == self.plan.plan_ref
        assert draft_ref == DRAFT_REF
        assert principal.requester == self.requester
        return self.plan, self.draft


class _CombinedAccessBinder:
    def bind_prepared_runners(self, plan, draft, principal, lines):
        del principal
        assert plan.scheme_id is SchemeId.SECRET_ONBOARDING
        assert draft.scheme_id is SchemeId.ACCESS_DOMAIN
        return tuple(_CombinedRunner(line.line_ref, line.depends_on) for line in lines)


class _CombinedSecretBinder:
    def bind_prepared(
        self,
        plan,
        draft,
        principal,
        *,
        external_dependency_refs=(),
    ):
        del principal
        assert draft.scheme_id is SchemeId.SECRET_ONBOARDING
        secret = next(
            line
            for line in plan.lines
            if line.target_class is ObjectClass.SECRET_METADATA
        )
        assert external_dependency_refs == secret.depends_on
        return ResolvedFixedActionSequence(
            plan.plan_ref,
            plan.requester_digest,
            (_CombinedRunner(secret.line_ref, secret.depends_on),),
        )


def test_existing_domain_combined_resolver_binds_every_parent_plan_line() -> None:
    requester, draft, plan, grant_line, secret_line = _combined_context()
    services = _CombinedServices(requester, draft, plan)
    resolver = ExistingDomainLinuxOnboardingFixedActionSequenceResolver(
        services,  # type: ignore[arg-type]
        _CombinedAccessBinder(),  # type: ignore[arg-type]
        _CombinedSecretBinder(),  # type: ignore[arg-type]
    )

    sequence = resolver.resolve(
        plan.plan_ref,
        DRAFT_REF,
        V4PlanningPrincipal(requester, "b" * 64),
    )

    assert sequence.plan_ref == plan.plan_ref
    assert tuple(runner.line_ref for runner in sequence.runners) == (
        grant_line.line_ref,
        secret_line.line_ref,
    )


def test_new_domain_combined_resolver_binds_folder_grant_and_secret_lines() -> None:
    requester, draft, plan, folder_line, grant_line, secret_line = (
        _new_domain_combined_context()
    )
    services = _CombinedServices(requester, draft, plan)
    resolver = ExistingDomainLinuxOnboardingFixedActionSequenceResolver(
        services,  # type: ignore[arg-type]
        _CombinedAccessBinder(),  # type: ignore[arg-type]
        _CombinedSecretBinder(),  # type: ignore[arg-type]
    )

    sequence = resolver.resolve(
        plan.plan_ref,
        DRAFT_REF,
        V4PlanningPrincipal(requester, "b" * 64),
    )

    assert tuple(runner.line_ref for runner in sequence.runners) == (
        folder_line.line_ref,
        grant_line.line_ref,
        secret_line.line_ref,
    )


@dataclass(frozen=True)
class _ProjectionView:
    object_ref: str
    values: dict[str, bool]


class _ExistenceProjectionSource:
    def __init__(self, existence: dict[ObjectClass, bool]) -> None:
        self._existence = existence

    def project(self, draft, requester, *, now_epoch):
        del requester, now_epoch
        return tuple(
            _ProjectionView(
                item.object_ref,
                {"exists": self._existence.get(item.object_class, True)},
            )
            for item in draft.desired_objects
        )


class _RegisteredProjectionSource:
    contract_registered = True


def test_combined_projection_registration_requires_both_source_contracts() -> None:
    registered = _RegisteredProjectionSource()
    unregistered = _ExistenceProjectionSource({})

    assert _OnboardingProjectionProvider(  # type: ignore[arg-type]
        registered,
        registered,
    ).contract_registered is True
    assert _OnboardingProjectionProvider(  # type: ignore[arg-type]
        registered,
        unregistered,
    ).contract_registered is False


def test_combined_projection_rejects_folder_view_existence_mismatch() -> None:
    requester, draft, _plan, _grant_line, _secret_line = _combined_context()
    provider = _OnboardingProjectionProvider(
        _ExistenceProjectionSource({ObjectClass.PUBLIC_FOLDER: False}),  # type: ignore[arg-type]
        _ExistenceProjectionSource({ObjectClass.FOLDER_BINDING: True}),  # type: ignore[arg-type]
    )

    with pytest.raises(V4RuntimeHostError, match="projection is unavailable"):
        provider.project(draft, requester, now_epoch=2_000)


def test_secret_validator_accepts_only_exact_combined_access_dependencies() -> None:
    _requester_value, draft, plan, grant_line, secret_line = _combined_context()
    secret_draft = replace(
        draft,
        desired_objects=tuple(
            item
            for item in draft.desired_objects
            if item.object_class
            not in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
        ),
    )

    _target, validated = SecretOnboardingFixedActionSequenceResolver._validate_plan(
        plan,
        secret_draft,
        replace(_binding(), folder_ref="combined-public-folder-ref"),
        external_dependency_refs=(grant_line.line_ref,),
    )
    assert validated.line_ref == secret_line.line_ref
    with pytest.raises(OnboardingActionCoordinatorError):
        SecretOnboardingFixedActionSequenceResolver._validate_plan(
            plan,
            secret_draft,
            replace(_binding(), folder_ref="combined-public-folder-ref"),
            external_dependency_refs=(),
        )


def test_secret_validator_accepts_new_folder_and_exact_grant_dependency() -> None:
    _requester_value, draft, plan, folder_line, grant_line, secret_line = (
        _new_domain_combined_context()
    )
    secret_draft = replace(
        draft,
        desired_objects=tuple(
            item
            for item in draft.desired_objects
            if item.object_class
            not in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
        ),
    )

    _target, validated = SecretOnboardingFixedActionSequenceResolver._validate_plan(
        plan,
        secret_draft,
        replace(_binding(), folder_ref="combined-public-folder-ref"),
        external_dependency_refs=(folder_line.line_ref, grant_line.line_ref),
    )

    assert validated.line_ref == secret_line.line_ref
    invalid_grant = replace(grant_line, depends_on=())
    content = dict(plan.canonical_content())
    content["lines"] = [
        folder_line.as_dict(),
        invalid_grant.as_dict(),
        secret_line.as_dict(),
    ]
    invalid = replace(
        plan,
        lines=(folder_line, invalid_grant, secret_line),
        plan_digest=canonical_digest(content),
    )
    with pytest.raises(OnboardingActionCoordinatorError):
        SecretOnboardingFixedActionSequenceResolver._validate_plan(
            invalid,
            secret_draft,
            replace(_binding(), folder_ref="combined-public-folder-ref"),
            external_dependency_refs=(folder_line.line_ref, grant_line.line_ref),
        )


class _Services:
    def __init__(self, *, target_line: bool = False) -> None:
        self.requester, self.draft, self.plan = _context(target_line=target_line)
        self.calls: list[str] = []

    def resolve_execution_context(self, plan_ref, draft_ref, principal):
        assert plan_ref == PLAN_REF
        assert draft_ref == DRAFT_REF
        assert principal.requester == self.requester
        self.calls.append("resolve")
        return self.plan, self.draft

    def evaluate_pre_write(self, plan_ref, draft_ref, principal):
        del plan_ref, draft_ref, principal
        self.calls.append("pre")
        return {"status": "match"}

    def evaluate_post_write(self, plan_ref, draft_ref, principal):
        del plan_ref, draft_ref, principal
        self.calls.append("post")
        return {"status": "expected_state_matches"}


class _Runtime:
    def __init__(
        self,
        plan: M4ExecutionPlan,
        *,
        binding_digest: str | None = None,
        on_execute: Callable[[], None] | None = None,
    ) -> None:
        self.plan = plan
        self.binding_digest = binding_digest or secret_onboarding_binding_digest(
            _binding()
        )
        self.calls: list[str] = []
        self.inspect_calls: list[str] = []
        self.on_execute = on_execute

    def inspect_execution_plan(self, authorization_ref: str) -> M4ExecutionPlan:
        self.inspect_calls.append(authorization_ref)
        return self.plan

    def inspect_onboarding_binding_digest(self, authorization_ref: str) -> str:
        assert authorization_ref.startswith("secret-create-authorization-ref")
        return self.binding_digest

    def execute_bound(
        self,
        authorization_ref: str,
        *,
        expected_onboarding_binding_digest: str | None = None,
    ) -> M4ExecutionResult:
        assert expected_onboarding_binding_digest == self.binding_digest
        self.calls.append(authorization_ref)
        if self.on_execute is not None:
            self.on_execute()
        return M4ExecutionResult(
            M4Outcome.SUCCEEDED,
            M4Verification.VERIFIED,
            M4Compensation.NOT_REQUESTED,
            False,
        )


def _m4_plan(scheme_plan, line, **overrides) -> M4ExecutionPlan:
    values = {
        "action_id": SECRET_CREATE_ACTION_ID,
        "action_version": SECRET_CREATE_ACTION_VERSION,
        "adapter_ref": "fortipam-191-secret-create-private-adapter",
        "approval_digest": canonical_digest("test-approval"),
        "compensation_ref": None,
        "confirmation_digest": scheme_plan.confirmation_digest,
        "expected_current_digest": line.expected_current_digest,
        "expected_state_digest": line.expected_state_digest,
        "expires_at": scheme_plan.expires_at,
        "idempotency_digest": canonical_digest("test-idempotency"),
        "parameters_digest": canonical_digest("test-parameters"),
        "plan_ref": scheme_plan.plan_ref,
        "requester_digest": scheme_plan.requester_digest,
        "revision": scheme_plan.revision,
        "summary_digest": scheme_plan.summary_digest,
        "target_ref": line.target_ref,
    }
    values.update(overrides)
    return M4ExecutionPlan(**values, plan_digest=canonical_digest(values))


def _source() -> FortiPamSecretOnboardingProjectionSource:
    return FortiPamSecretOnboardingProjectionSource(
        SecretTransport(),
        TargetTransport(),
        LauncherTransport(),
        Resolver(),
    )


def test_secret_only_plan_runs_one_exact_protected_m4_binding() -> None:
    services = _Services()
    line = services.plan.lines[0]
    runtime = _Runtime(_m4_plan(services.plan, line))
    factory = ExactSecretCreateM4RunnerFactory(
        ProtectedSecretCreateRunnerBinding(
            services.plan.plan_digest,
            line.line_ref,
            services.requester.digest,
            "secret-create-authorization-ref01",
            cast(object, runtime),  # type: ignore[arg-type]
        )
    )
    resolver = SecretOnboardingFixedActionSequenceResolver(  # type: ignore[arg-type]
        services,
        _source(),
        factory,
    )
    result = OnboardingActionCoordinator(services, resolver).execute(
        PLAN_REF,
        DRAFT_REF,
        V4PlanningPrincipal(services.requester, "a" * 64),
    )

    assert result.outcome == "succeeded"
    assert runtime.calls == ["secret-create-authorization-ref01"]
    assert services.calls == ["pre", "resolve", "post"]


def test_secret_runner_rejects_private_onboarding_binding_drift() -> None:
    services = _Services()
    line = services.plan.lines[0]
    runtime = _Runtime(
        _m4_plan(services.plan, line),
        binding_digest="0" * 64,
    )
    factory = ExactSecretCreateM4RunnerFactory(
        ProtectedSecretCreateRunnerBinding(
            services.plan.plan_digest,
            line.line_ref,
            services.requester.digest,
            "secret-create-authorization-ref01",
            runtime,
        )
    )
    resolver = SecretOnboardingFixedActionSequenceResolver(  # type: ignore[arg-type]
        services,
        _source(),
        factory,
    )

    with pytest.raises(OnboardingActionCoordinatorError, match="unavailable"):
        resolver.resolve(
            PLAN_REF,
            DRAFT_REF,
            V4PlanningPrincipal(services.requester, "a" * 64),
        )

    assert runtime.calls == []


def test_target_create_line_is_rejected_instead_of_leaving_a_half_onboarding() -> None:
    services = _Services(target_line=True)
    line = services.plan.lines[0]
    runtime = _Runtime(_m4_plan(services.plan, line))
    factory = ExactSecretCreateM4RunnerFactory(
        ProtectedSecretCreateRunnerBinding(
            services.plan.plan_digest,
            line.line_ref,
            services.requester.digest,
            "secret-create-authorization-ref01",
            cast(object, runtime),  # type: ignore[arg-type]
        )
    )
    resolver = SecretOnboardingFixedActionSequenceResolver(  # type: ignore[arg-type]
        services,
        _source(),
        factory,
    )

    result = OnboardingActionCoordinator(services, resolver).execute(
        PLAN_REF,
        DRAFT_REF,
        V4PlanningPrincipal(services.requester, "a" * 64),
    )
    assert result.outcome == "reconciliation_required"
    assert result.failure_stage == "fixed_action_plan_validation"
    assert result.completed_line_refs == ()
    assert runtime.calls == []


def test_windows_rdp_secret_only_plan_runs_one_exact_protected_m4_binding() -> None:
    rdp_services = _Services()
    rdp_draft = _rdp_draft()
    rdp_services.draft = replace(
        rdp_draft,
        desired_objects=(
            *rdp_draft.desired_objects,
            _desired(
                "rdp-event-filter-binding-ref",
                ObjectClass.RDP_EVENT_FILTER_BINDING,
                {"profile_ref": "approved-rdp-event-filter-ref"},
            ),
        ),
    )
    rdp_line = rdp_services.plan.lines[0]
    rdp_private_binding = replace(
        _rdp_binding(),
        rdp_event_filter_object_ref="rdp-event-filter-binding-ref",
        rdp_event_filter_profile_name="mcp-v4-rdp-event-filter-existing",
        rdp_event_filter_profile_ref="approved-rdp-event-filter-ref",
    )
    rdp_runtime = _Runtime(
        _m4_plan(rdp_services.plan, rdp_line),
        binding_digest=secret_onboarding_binding_digest(rdp_private_binding),
    )
    rdp_factory = ExactSecretCreateM4RunnerFactory(
        ProtectedSecretCreateRunnerBinding(
            rdp_services.plan.plan_digest,
            rdp_line.line_ref,
            rdp_services.requester.digest,
            "secret-create-authorization-ref02",
            cast(object, rdp_runtime),  # type: ignore[arg-type]
        )
    )

    class _RdpSource:
        @staticmethod
        def resolve_private_binding(draft, requester):
            assert draft == rdp_services.draft
            assert requester == rdp_services.requester
            return rdp_private_binding

    rdp_resolver = SecretOnboardingFixedActionSequenceResolver(  # type: ignore[arg-type]
        rdp_services,
        _RdpSource(),
        rdp_factory,
    )
    result = OnboardingActionCoordinator(rdp_services, rdp_resolver).execute(
        PLAN_REF,
        DRAFT_REF,
        V4PlanningPrincipal(rdp_services.requester, "a" * 64),
    )

    assert result.outcome == "succeeded"
    assert rdp_runtime.calls == ["secret-create-authorization-ref02"]
    assert rdp_services.calls == ["pre", "resolve", "post"]


def test_windows_rdp_plan_rejects_partial_policy_binding_before_dispatch() -> None:
    services = _Services()
    services.draft = _rdp_draft()
    line = services.plan.lines[0]
    runtime = _Runtime(_m4_plan(services.plan, line))
    factory = ExactSecretCreateM4RunnerFactory(
        ProtectedSecretCreateRunnerBinding(
            services.plan.plan_digest,
            line.line_ref,
            services.requester.digest,
            "secret-create-authorization-ref03",
            runtime,
        )
    )

    class _PartialRdpSource:
        @staticmethod
        def resolve_private_binding(draft, requester):
            assert draft == services.draft
            assert requester == services.requester
            return replace(
                _rdp_binding(),
                policy_object_ref=None,
                policy_folder_id=None,
                policy_folder_name=None,
                policy_profile_name=None,
                policy_profile_ref=None,
            )

    resolver = SecretOnboardingFixedActionSequenceResolver(  # type: ignore[arg-type]
        services,
        _PartialRdpSource(),
        factory,
    )

    with pytest.raises(OnboardingActionCoordinatorError, match="dependencies"):
        resolver.resolve(
            PLAN_REF,
            DRAFT_REF,
            V4PlanningPrincipal(services.requester, "a" * 64),
        )
    assert runtime.calls == []


def test_owner_only_runner_binding_reloads_after_factory_restart(tmp_path) -> None:
    services = _Services()
    line = services.plan.lines[0]
    runtime = _Runtime(_m4_plan(services.plan, line))
    path = tmp_path / "secret-runner-binding.json"
    path.write_text(
        json.dumps(
            {
                "contract": SECRET_CREATE_RUNNER_BINDING_CONTRACT,
                "version": SECRET_CREATE_RUNNER_BINDING_VERSION,
                "scheme_plan_ref": services.plan.plan_ref,
                "scheme_plan_digest": services.plan.plan_digest,
                "line_ref": line.line_ref,
                "requester_digest": services.requester.digest,
                "m4_action_id": "secret-create-from-reference",
                "m4_action_version": "1.0.0",
                "authorization_ref": "secret-create-authorization-ref01",
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    principal = V4PlanningPrincipal(services.requester, "a" * 64)
    bound_runtime = cast(ProtectedSecretCreateM4Runtime, runtime)

    first = OwnerOnlySecretCreateM4RunnerFactory(path, bound_runtime).bind(
        services.plan,
        line.line_ref,
        principal,
        onboarding_binding=_binding(),
    )
    second = OwnerOnlySecretCreateM4RunnerFactory(path, bound_runtime).bind(
        services.plan,
        line.line_ref,
        principal,
        onboarding_binding=_binding(),
    )

    assert first.execute_bound()["outcome"] == "succeeded"
    assert second.execute_bound()["verification"] == "verified"
    assert runtime.calls == [
        "secret-create-authorization-ref01",
        "secret-create-authorization-ref01",
    ]

    path.chmod(0o644)
    with pytest.raises(OnboardingActionCoordinatorError, match="unavailable"):
        OwnerOnlySecretCreateM4RunnerFactory(path, bound_runtime).bind(
            services.plan,
            line.line_ref,
            principal,
            onboarding_binding=_binding(),
        )


def test_owner_only_runner_binding_rejects_symlink_and_plan_drift(tmp_path) -> None:
    services = _Services()
    line = services.plan.lines[0]
    runtime = cast(
        ProtectedSecretCreateM4Runtime,
        _Runtime(_m4_plan(services.plan, line)),
    )
    path = tmp_path / "secret-runner-binding.json"
    payload = {
        "contract": SECRET_CREATE_RUNNER_BINDING_CONTRACT,
        "version": SECRET_CREATE_RUNNER_BINDING_VERSION,
        "scheme_plan_ref": services.plan.plan_ref,
        "scheme_plan_digest": "9" * 64,
        "line_ref": line.line_ref,
        "requester_digest": services.requester.digest,
        "m4_action_id": "secret-create-from-reference",
        "m4_action_version": "1.0.0",
        "authorization_ref": "secret-create-authorization-ref01",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    principal = V4PlanningPrincipal(services.requester, "a" * 64)

    with pytest.raises(OnboardingActionCoordinatorError, match="unavailable"):
        OwnerOnlySecretCreateM4RunnerFactory(path, runtime).bind(
            services.plan,
            line.line_ref,
            principal,
            onboarding_binding=_binding(),
        )

    payload["scheme_plan_digest"] = services.plan.plan_digest
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    symlink = tmp_path / "secret-runner-binding-link.json"
    symlink.symlink_to(path)
    with pytest.raises(OnboardingActionCoordinatorError, match="unavailable"):
        OwnerOnlySecretCreateM4RunnerFactory(symlink, runtime).bind(
            services.plan,
            line.line_ref,
            principal,
            onboarding_binding=_binding(),
        )


@pytest.mark.parametrize(
    ("field", "mismatched_value"),
    (
        ("target_ref", "different-secret-target-ref01"),
        ("expected_current_digest", "8" * 64),
        ("expected_state_digest", "9" * 64),
    ),
)
def test_m4_runner_rejects_scheme_line_integrity_drift_before_dispatch(
    field: str,
    mismatched_value: str,
) -> None:
    services = _Services()
    line = services.plan.lines[0]
    runtime = _Runtime(
        _m4_plan(services.plan, line, **{field: mismatched_value})
    )
    factory = ExactSecretCreateM4RunnerFactory(
        ProtectedSecretCreateRunnerBinding(
            services.plan.plan_digest,
            line.line_ref,
            services.requester.digest,
            "secret-create-authorization-ref01",
            runtime,
        )
    )

    with pytest.raises(OnboardingActionCoordinatorError, match="unavailable"):
        factory.bind(
            services.plan,
            line.line_ref,
            V4PlanningPrincipal(services.requester, "a" * 64),
            onboarding_binding=_binding(),
        )

    assert runtime.inspect_calls == ["secret-create-authorization-ref01"]
    assert runtime.calls == []


class _Clock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class _MaterialResolver:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.binding = C3MaterialBinding()

    def resolve(
        self,
        binding_ref: str,
        request: MaterialLeaseRequest,
    ) -> C3MaterialBinding:
        assert request.action_id == SECRET_CREATE_ACTION_ID
        self.calls.append(binding_ref)
        return self.binding


class _MaterialProvider:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.lease = MaterialLease()

    def validate_binding(self, binding, request):
        assert isinstance(binding, C3MaterialBinding)
        assert request.action_id == SECRET_CREATE_ACTION_ID
        self.events.append("validate")
        return MaterialBindingStatus.AVAILABLE

    def acquire_lease(self, binding, request):
        assert isinstance(binding, C3MaterialBinding)
        assert request.action_id == SECRET_CREATE_ACTION_ID
        self.events.append("acquire")
        return self.lease

    def release_lease(self, lease):
        assert lease is self.lease
        self.events.append("release")
        return MaterialLeaseCompletion.RELEASED

    def revoke_lease(self, lease, *, reason: MaterialRevocationReason):
        assert lease is self.lease
        self.events.append(f"revoke:{reason.value}")
        return MaterialLeaseCompletion.REVOKED


class _MutatingSecretTransport:
    def __init__(self, projection: SecretTransport) -> None:
        self._projection = projection
        self.calls = 0

    def create_and_verify(self, binding, lease, request):
        assert isinstance(binding, SecretCreate191TargetBinding)
        assert isinstance(lease, MaterialLease)
        assert request.action_id == SECRET_CREATE_ACTION_ID
        self.calls += 1
        self._projection.exists = True
        return SecretCreateAdapterOutcome.VERIFIED_CREATED


class _MutableTargetTransport:
    def __init__(self) -> None:
        self.exists = False

    def inspect(self, target_name: str):
        from fortipam_mcp.target_contract import TargetInspection

        assert target_name == "private-target"
        return TargetInspection(self.exists)


class _TargetAction:
    def __init__(
        self,
        transport: _MutableTargetTransport,
        *,
        raises_at: str | None = None,
    ) -> None:
        self._transport = transport
        self._raises_at = raises_at
        self.calls: list[str] = []

    def preview(self, target_name, address, principal):
        del principal
        self.calls.append("preview")
        if self._raises_at == "preview":
            raise RuntimeError("sensitive preview detail")
        return {
            "preview_ref": "target-preview-ref01",
            "device_write_executed": False,
            "Current State": {
                "requested_target_name": target_name,
                "requested_target_address": address,
                "target_exists": False,
                "write_transport": "rest_api",
                "product_version": "7.0.0",
                "product_build": 29,
            },
            "Proposed Changes": {
                "operation": "create_target_via_api",
                "request_projection": "fortipam_7_0_0_build_29_target_frontend_unparse",
                "product_version": "7.0.0",
                "product_build": 29,
                "target_name": target_name,
                "target_class": "other",
                "template": "Unix Account (SSH Password)",
                "endpoint_type": "ipv4",
                "target_address": address,
                "web_proxy_status": "disable",
                "owner_binding": "verified_admin_principal",
                "create_secret_group_binding": "everyone",
            },
            "Expected State": {
                "target_exists": True,
                "target_name_matches": True,
                "class_matches": True,
                "template_matches": True,
                "address_matches": True,
                "web_proxy_disabled": True,
                "owner_relation_matches": True,
                "create_secret_group_relation_matches": True,
            },
        }

    def confirm(self, preview_ref, principal):
        del principal
        assert preview_ref == "target-preview-ref01"
        self.calls.append("confirm")
        if self._raises_at == "confirm":
            raise RuntimeError("sensitive confirmation detail")
        return {"authorization_ref": "target-authorization-ref01"}

    def execute(self, authorization_ref, principal):
        del principal
        assert authorization_ref == "target-authorization-ref01"
        self.calls.append("execute")
        if self._raises_at == "execute":
            raise RuntimeError("sensitive execution detail")
        self._transport.exists = True
        return {"outcome": "succeeded", "verification": "verified"}


@pytest.mark.parametrize(
    ("raises_at", "failure_stage", "expected_calls"),
    [
        ("preview", "target_create_preview", ["preview"]),
        ("confirm", "target_create_confirmation", ["preview", "confirm"]),
        (
            "execute",
            "target_create_execution",
            ["preview", "confirm", "execute"],
        ),
    ],
)
def test_target_runner_returns_stage_only_for_unexpected_failure(
    raises_at: str,
    failure_stage: str,
    expected_calls: list[str],
) -> None:
    requester, _, _ = _context(target_line=True)
    transport = _MutableTargetTransport()
    action = _TargetAction(transport, raises_at=raises_at)
    runner = _BoundTargetCreateRunner(
        "line-target-0001",
        (),
        _binding(),
        action,
        V4PlanningPrincipal(requester, "a" * 64),
    )

    result = runner.execute_bound()

    assert result == {
        "failure_stage": failure_stage,
        "outcome": "reconciliation_required",
        "verification": "unknown",
    }
    assert action.calls == expected_calls
    assert transport.exists is False


class _SecretDigestReader:
    def __init__(
        self,
        projection: SecretTransport,
        current_digest: str,
        expected_digest: str,
        onboarding_binding_digest: str,
    ) -> None:
        self._projection = projection
        self._current = current_digest
        self._expected = expected_digest
        self._onboarding_binding_digest = onboarding_binding_digest
        self.calls: list[str] = []

    def inspect_onboarding_binding_digest(self) -> str:
        return self._onboarding_binding_digest

    def read_current(self, plan: M4ExecutionPlan) -> str:
        del plan
        self.calls.append("current")
        return self._expected if self._projection.exists else self._current

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        del plan
        self.calls.append("post")
        return self._expected if self._projection.exists else self._current


class _AuthorizationVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, plan, authorization, *, now_epoch: int) -> None:
        assert authorization.plan_digest == plan.plan_digest
        assert authorization.requester_digest == plan.requester_digest
        assert authorization.issued_at <= now_epoch < authorization.expires_at
        self.calls += 1


class _MutableGroupAclAction:
    def __init__(self, transport: FolderTransport) -> None:
        self.transport = transport
        self.calls: list[str] = []

    def preview_group(
        self,
        folder_id: int,
        group_name: str,
        folder_permission: str,
        secret_permission: str,
        principal,
    ) -> dict[str, object]:
        del principal
        assert (folder_id, group_name, folder_permission, secret_permission) == (
            17,
            "private-group-name",
            "view",
            "view",
        )
        self.calls.append("preview")
        return {
            "preview_ref": "combined-group-preview-ref01",
            "device_write_executed": False,
            "Current State": {
                "selected_folder_id": 17,
                "requested_group_name": "private-group-name",
                "requested_folder_permission": "view",
                "requested_secret_permission": "view",
                "folder_exists": True,
                "folder_scope": "public_child",
                "requested_group_relation_present": False,
            },
            "Proposed Changes": {
                "operation": "grant_public_folder_group_acl",
                "folder_id": 17,
                "group_name": "private-group-name",
                "folder_permission": "view",
                "secret_permission": "view",
                "permission_inheritance_after_change": "disable",
            },
            "Expected State": {
                "folder_exists": True,
                "folder_scope": "public_child",
                "permission_inheritance": "disable",
                "requested_group_relation_present": True,
                "requested_folder_permission_matches": True,
                "requested_secret_permission_matches": True,
                "effective_user_relations_preserved": True,
                "effective_group_relations_preserved": True,
            },
        }

    def confirm(self, preview_ref: str, principal) -> dict[str, object]:
        del principal
        assert preview_ref == "combined-group-preview-ref01"
        self.calls.append("confirm")
        return {"authorization_ref": "combined-group-authorization-ref01"}

    def execute(self, authorization_ref: str, principal) -> dict[str, object]:
        del principal
        assert authorization_ref == "combined-group-authorization-ref01"
        self.calls.append("execute")
        self.transport.grant_present = True
        return {"outcome": "succeeded", "verification": "verified"}


class _MutableFolderAction:
    def __init__(
        self,
        transport: FolderTransport,
        secret_transport: SecretTransport,
    ) -> None:
        self.transport = transport
        self.secret_transport = secret_transport
        self.calls: list[str] = []

    def preview(self, folder_name: str, parent_folder_id: int, principal):
        del principal
        assert (folder_name, parent_folder_id) == ("private-product-folder", 9)
        self.calls.append("preview")
        return {
            "preview_ref": "combined-folder-preview-ref01",
            "device_write_executed": False,
            "Current State": {
                "selected_parent_folder_id": 9,
                "requested_child_folder_name": "private-product-folder",
                "parent_exists": True,
                "matching_child_exists": False,
            },
            "Proposed Changes": {
                "operation": "create_inherited_public_child_folder",
                "parent_folder_id": 9,
                "folder_name": "private-product-folder",
            },
            "Expected State": {
                "child_folder_name_matches": True,
                "matching_child_exists": True,
                "inherit_policy": "enable",
                "inherit_permission": "enable",
                "inherit_folder_ztna": "enable",
            },
        }

    def confirm(self, preview_ref: str, principal):
        del principal
        assert preview_ref == "combined-folder-preview-ref01"
        self.calls.append("confirm")
        return {"authorization_ref": "combined-folder-authorization-ref01"}

    def execute(self, authorization_ref: str, principal):
        del principal
        assert authorization_ref == "combined-folder-authorization-ref01"
        self.calls.append("execute")
        self.transport.folder_present = True
        self.secret_transport.folder_exists = True
        return {"outcome": "succeeded", "verification": "verified"}


class _MutableUserAndGroupAclAction:
    def __init__(self, transport: FolderTransport) -> None:
        self.transport = transport
        self.calls: list[str] = []

    def preview(
        self,
        folder_id: int,
        username: str,
        folder_permission: str,
        secret_permission: str,
        principal,
    ) -> dict[str, object]:
        del principal
        assert (folder_id, username, folder_permission, secret_permission) == (
            17,
            "private-owner-name",
            "owner",
            "owner",
        )
        self.calls.append("owner-preview")
        return self._preview("user", username, "owner", "owner")

    def preview_group(
        self,
        folder_id: int,
        group_name: str,
        folder_permission: str,
        secret_permission: str,
        principal,
    ) -> dict[str, object]:
        del principal
        assert (folder_id, group_name, folder_permission, secret_permission) == (
            17,
            "private-group-name",
            "view",
            "view",
        )
        self.calls.append("group-preview")
        return self._preview("group", group_name, "view", "view")

    def _preview(
        self,
        subject_class: str,
        principal_name: str,
        folder_permission: str,
        secret_permission: str,
    ) -> dict[str, object]:
        is_group = subject_class == "group"
        return {
            "preview_ref": f"combined-{subject_class}-preview-ref01",
            "device_write_executed": False,
            "Current State": {
                "selected_folder_id": 17,
                ("requested_group_name" if is_group else "requested_username"): principal_name,
                "requested_folder_permission": folder_permission,
                "requested_secret_permission": secret_permission,
                "folder_exists": True,
                "folder_scope": "public_child",
                (
                    "requested_group_relation_present"
                    if is_group
                    else "requested_user_relation_present"
                ): False,
            },
            "Proposed Changes": {
                "operation": (
                    "grant_public_folder_group_acl"
                    if is_group
                    else "grant_public_folder_user_acl"
                ),
                "folder_id": 17,
                ("group_name" if is_group else "username"): principal_name,
                "folder_permission": folder_permission,
                "secret_permission": secret_permission,
                "permission_inheritance_after_change": "disable",
            },
            "Expected State": {
                "folder_exists": True,
                "folder_scope": "public_child",
                "permission_inheritance": "disable",
                (
                    "requested_group_relation_present"
                    if is_group
                    else "requested_username_relation_present"
                ): True,
                "requested_folder_permission_matches": True,
                "requested_secret_permission_matches": True,
                "effective_user_relations_preserved": True,
                "effective_group_relations_preserved": True,
            },
        }

    def confirm(self, preview_ref: str, principal) -> dict[str, object]:
        del principal
        subject_class = "group" if "group" in preview_ref else "user"
        assert preview_ref == f"combined-{subject_class}-preview-ref01"
        self.calls.append(f"{subject_class}-confirm")
        return {
            "authorization_ref": f"combined-{subject_class}-authorization-ref01"
        }

    def execute(self, authorization_ref: str, principal) -> dict[str, object]:
        del principal
        subject_class = "group" if "group" in authorization_ref else "user"
        assert authorization_ref == f"combined-{subject_class}-authorization-ref01"
        self.calls.append(f"{subject_class}-execute")
        if subject_class == "group":
            self.transport.grant_present = True
        else:
            self.transport.owner_present = True
        return {"outcome": "succeeded", "verification": "verified"}


@pytest.mark.parametrize(
    ("new_folder", "new_target"),
    ((False, False), (False, True), (True, False), (True, True)),
)
def test_persistent_host_runs_one_confirmation_through_combined_linux_readback(
    tmp_path: Path,
    new_folder: bool,
    new_target: bool,
) -> None:
    now = 2_000
    clock = _Clock(now)
    state = tmp_path / "combined-state"
    oauth = tmp_path / "combined-oauth"
    state.mkdir(mode=0o700)
    oauth.mkdir(mode=0o700)

    def owner_file(name: str, value: bytes) -> Path:
        path = state / name
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    requester = _requester()
    base_draft = _draft()
    folder_ref = "synthetic-public-folder-reference"
    secret_binding = replace(_binding(), folder_ref=folder_ref)
    secret_objects = tuple(
        replace(item, desired_fields=(("folder_ref", folder_ref),))
        if item.object_class is ObjectClass.FOLDER_BINDING
        else item
        for item in base_draft.desired_objects
    )
    draft = replace(
        base_draft,
        owner_ref="synthetic-owner-reference",
        scope_ref="combined-linux-scope",
        desired_objects=(
            _desired(
                folder_ref,
                ObjectClass.PUBLIC_FOLDER,
                {"enabled": True, "owner_ref": "synthetic-owner-reference"},
            ),
            _desired(
                "synthetic-access-grant-reference",
                ObjectClass.ACCESS_GRANT,
                {
                    "permission": "use",
                    "subject_class": "group",
                    "subject_ref": "synthetic-group-reference",
                },
            ),
            *secret_objects,
        ),
    )
    folder_transport = FolderTransport(
        folder_present=not new_folder,
        owner_present=not new_folder,
        grant_present=False,
    )
    secret_transport = SecretTransport(folder_exists=not new_folder)
    target_transport = TargetTransport(exists=not new_target)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                "correct-horse-battery-staple",
                salt=b"0123456789abcdef",
            ),
        )
    )
    components = onboarding_v4_plan_host_factory(
        V4SyntheticHostSettings(
            state / "planning.sqlite3",
            owner_file("planning.hmac", b"p" * 32),
            reference_authority=V4PersistentReferenceAuthoritySettings(
                state / "reference.sqlite3",
                owner_file("reference.hmac", b"r" * 32),
            ),
            scheme_draft_authority=V4PersistentSchemeDraftAuthoritySettings(
                state / "draft.sqlite3",
                owner_file("draft.hmac", b"d" * 32),
            ),
        ),
        folder_transport=folder_transport,
        access_domain_binding_resolver=AccessResolver(),
        secret_transport=secret_transport,
        target_transport=target_transport,
        launcher_transport=LauncherTransport(),
        secret_binding_resolver=Resolver(secret_binding),
        clock=clock,
    )(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            owner_file("confirmation.hmac", b"c" * 32),
            owner_file("receipt.hmac", b"e" * 32),
        ),
    )
    draft_authority = components.scheme_draft_authority
    reference_authority = components.reference_authority
    assert draft_authority is not None
    assert reference_authority is not None
    draft_ref = draft_authority.issue(
        draft,
        requester,
        expires_at=now + 300,
        now_epoch=now,
    )
    object_kinds = {
        ObjectClass.PUBLIC_FOLDER: "public_folder",
        ObjectClass.ACCESS_GRANT: "access_grant",
        ObjectClass.FOLDER_BINDING: "folder_binding",
        ObjectClass.TARGET: "target",
        ObjectClass.TEMPLATE_BINDING: "template_binding",
        ObjectClass.SECRET_METADATA: "secret_metadata",
        ObjectClass.LAUNCHER_BINDING: "launcher_binding",
    }
    bindings = {
        (ACCESS_SOURCE_REF, "projection_source"),
        (SOURCE_REF, "projection_source"),
        (draft.environment_ref, "environment"),
        (draft.scope_ref, "scope"),
        (draft.owner_ref, "owner"),
        (draft.audience_ref, "audience"),
        *((value, "evidence") for value in draft.evidence_refs),
    }
    for desired in draft.desired_objects:
        bindings.add(
            (desired.object_ref, f"object_{object_kinds[desired.object_class]}")
        )
        bindings.update(
            (value, f"field_{name}")
            for name, value in desired.desired_fields
            if name.endswith("_ref") and isinstance(value, str)
        )
    reference_authority.issue_many(
        tuple(sorted(bindings)),
        requester_digest=requester.digest,
        environment_ref=draft.environment_ref,
        scope_ref=draft.scope_ref,
        expires_at=now + 300,
        now_epoch=now,
    )
    principal = V4PlanningPrincipal(requester, "b" * 64)
    preview = components.plan_services.preview(draft_ref, principal)
    confirmation_path = str(preview["confirmation_url"]).removeprefix(
        "https://mcp.example.com"
    )
    with TestClient(
        Starlette(routes=components.confirmation_service.routes()),
        base_url="https://mcp.example.com",
    ) as client:
        page = client.get(confirmation_path)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert csrf is not None
        clock.value = now + 1
        review = client.post(
            confirmation_path,
            data={
                "csrf_token": csrf.group(1),
                "username": "operator",
                "password": "correct-horse-battery-staple",
                "action": "review",
            },
            headers={"origin": "https://mcp.example.com"},
        )
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', review.text)
        assert csrf is not None
        clock.value = now + 2
        affirmed = client.post(
            confirmation_path,
            data={"csrf_token": csrf.group(1), "action": "affirm"},
            headers={"origin": "https://mcp.example.com"},
        )
        assert affirmed.status_code == 200
    clock.value = now + 3
    confirmation = components.plan_services.confirm(
        str(preview["summary_ref"]),
        int(preview["revision"]),
        principal,
    )
    clock.value = now + 4
    prepared = components.plan_services.prepare(
        str(preview["summary_ref"]),
        str(confirmation["confirmation_ref"]),
        principal,
    )
    plan, _resolved = components.plan_services.resolve_execution_context(
        str(prepared["plan_ref"]),
        draft_ref,
        principal,
    )
    grant_line = next(
        line for line in plan.lines if line.target_class is ObjectClass.ACCESS_GRANT
    )
    folder_line = next(
        (
            line
            for line in plan.lines
            if line.target_class is ObjectClass.PUBLIC_FOLDER
        ),
        None,
    )
    secret_line = next(
        line for line in plan.lines if line.target_class is ObjectClass.SECRET_METADATA
    )
    target_line = next(
        (line for line in plan.lines if line.target_class is ObjectClass.TARGET),
        None,
    )
    runtime = _Runtime(
        _m4_plan(plan, secret_line),
        binding_digest=secret_onboarding_binding_digest(secret_binding),
        on_execute=lambda: setattr(secret_transport, "exists", True),
    )
    runner_factory = ExactSecretCreateM4RunnerFactory(
        ProtectedSecretCreateRunnerBinding(
            plan.plan_digest,
            secret_line.line_ref,
            requester.digest,
            "secret-create-authorization-ref01",
            runtime,
        )
    )
    folder_action = (
        _MutableFolderAction(folder_transport, secret_transport)
        if new_folder
        else None
    )
    group_action = (
        _MutableUserAndGroupAclAction(folder_transport)
        if new_folder
        else _MutableGroupAclAction(folder_transport)
    )
    target_action = _TargetAction(target_transport) if new_target else None  # type: ignore[arg-type]
    _access_action, action = components.bind_onboarding_execution_mcp_actions(
        group_action,  # type: ignore[arg-type]
        runner_factory,
        folder_action=folder_action,
        group_acl_action=group_action,
        target_action=target_action,
        authorized_environment_ref=draft.environment_ref,
        authorized_scope_ref=draft.scope_ref,
        authorized_secret_environment_ref=draft.environment_ref,
        authorized_secret_scope_ref=draft.scope_ref,
        execution_enabled=True,
    )
    clock.value = now + 5
    result = action.execute(plan.plan_ref, draft_ref, principal)

    assert result["outcome"] == "succeeded"
    assert result["post_write_status"] == "expected_state_matches"
    completed = result["completed_line_refs"]
    expected_lines = {
        grant_line.line_ref,
        secret_line.line_ref,
        *([folder_line.line_ref] if folder_line is not None else []),
        *([target_line.line_ref] if target_line is not None else []),
    }
    assert isinstance(completed, list)
    assert len(completed) == len(expected_lines)
    assert set(completed) == expected_lines
    assert completed.index(grant_line.line_ref) < completed.index(secret_line.line_ref)
    if folder_line is not None:
        assert completed.index(folder_line.line_ref) < completed.index(grant_line.line_ref)
    if target_line is not None:
        assert completed.index(target_line.line_ref) < completed.index(secret_line.line_ref)
    if new_folder:
        assert folder_line is not None
        assert folder_action is not None
        assert folder_action.calls == ["preview", "confirm", "execute"]
        assert group_action.calls == [
            "owner-preview",
            "user-confirm",
            "user-execute",
            "group-preview",
            "group-confirm",
            "group-execute",
        ]
    else:
        assert folder_line is None
        assert group_action.calls == ["preview", "confirm", "execute"]
    if new_target:
        assert target_line is not None
        assert target_action is not None
        assert target_action.calls == ["preview", "confirm", "execute"]
    else:
        assert target_line is None
    assert runtime.calls == ["secret-create-authorization-ref01"]
    assert folder_transport.grant_present is True
    assert secret_transport.exists is True


def test_persistent_host_runs_one_confirmation_through_secret_m4_readback(
    tmp_path: Path,
) -> None:
    now = 1_000
    clock = _Clock(now)
    state = tmp_path / "state"
    oauth = tmp_path / "oauth"
    state.mkdir(mode=0o700)
    oauth.mkdir(mode=0o700)

    def owner_file(name: str, value: bytes) -> Path:
        path = state / name
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    requester = _requester()
    draft = _draft()
    projection = SecretTransport()
    target_projection = _MutableTargetTransport()
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                "correct-horse-battery-staple",
                salt=b"0123456789abcdef",
            ),
        )
    )
    settings = V4SyntheticHostSettings(
        state / "planning.sqlite3",
        owner_file("planning.hmac", b"p" * 32),
        reference_authority=V4PersistentReferenceAuthoritySettings(
            state / "reference.sqlite3",
            owner_file("reference.hmac", b"r" * 32),
        ),
        scheme_draft_authority=V4PersistentSchemeDraftAuthoritySettings(
            state / "draft.sqlite3",
            owner_file("draft.hmac", b"d" * 32),
        ),
    )
    components = secret_onboarding_v4_plan_host_factory(
        settings,
        secret_transport=projection,
        target_transport=target_projection,
        launcher_transport=LauncherTransport(),
        binding_resolver=Resolver(),
        clock=clock,
    )(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            owner_file("confirmation.hmac", b"c" * 32),
            owner_file("receipt.hmac", b"e" * 32),
        ),
    )
    draft_authority = components.scheme_draft_authority
    reference_authority = components.reference_authority
    assert draft_authority is not None
    assert reference_authority is not None
    draft_ref = draft_authority.issue(
        draft,
        requester,
        expires_at=now + 300,
        now_epoch=now,
    )
    object_kinds = {
        ObjectClass.FOLDER_BINDING: "folder_binding",
        ObjectClass.TARGET: "target",
        ObjectClass.TEMPLATE_BINDING: "template_binding",
        ObjectClass.SECRET_METADATA: "secret_metadata",
        ObjectClass.LAUNCHER_BINDING: "launcher_binding",
    }
    bindings = {
        (SOURCE_REF, "projection_source"),
        (draft.environment_ref, "environment"),
        (draft.scope_ref, "scope"),
        (draft.owner_ref, "owner"),
        (draft.audience_ref, "audience"),
        *((value, "evidence") for value in draft.evidence_refs),
    }
    for desired in draft.desired_objects:
        bindings.add((desired.object_ref, f"object_{object_kinds[desired.object_class]}"))
        bindings.update(
            (value, f"field_{name}")
            for name, value in desired.desired_fields
            if name.endswith("_ref") and isinstance(value, str)
        )
    reference_authority.issue_many(
        tuple(sorted(bindings)),
        requester_digest=requester.digest,
        environment_ref=draft.environment_ref,
        scope_ref=draft.scope_ref,
        expires_at=now + 300,
        now_epoch=now,
    )
    principal = V4PlanningPrincipal(requester, "b" * 64)
    preview = components.plan_services.preview(draft_ref, principal)
    confirmation_path = str(preview["confirmation_url"]).removeprefix(
        "https://mcp.example.com"
    )
    with TestClient(
        Starlette(routes=components.confirmation_service.routes()),
        base_url="https://mcp.example.com",
    ) as client:
        page = client.get(confirmation_path)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert csrf is not None
        clock.value = now + 1
        review = client.post(
            confirmation_path,
            data={
                "csrf_token": csrf.group(1),
                "username": "operator",
                "password": "correct-horse-battery-staple",
                "action": "review",
            },
            headers={"origin": "https://mcp.example.com"},
        )
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', review.text)
        assert csrf is not None
        clock.value = now + 2
        affirmed = client.post(
            confirmation_path,
            data={"csrf_token": csrf.group(1), "action": "affirm"},
            headers={"origin": "https://mcp.example.com"},
        )
        assert affirmed.status_code == 200

    clock.value = now + 3
    confirmation = components.plan_services.confirm(
        str(preview["summary_ref"]),
        int(preview["revision"]),
        principal,
    )
    clock.value = now + 4
    prepared = components.plan_services.prepare(
        str(preview["summary_ref"]),
        str(confirmation["confirmation_ref"]),
        principal,
    )
    scheme_plan, _resolved_draft = components.plan_services.resolve_execution_context(
        str(prepared["plan_ref"]),
        draft_ref,
        principal,
    )
    assert len(scheme_plan.lines) == 2
    line = next(
        item
        for item in scheme_plan.lines
        if item.target_class is ObjectClass.SECRET_METADATA
    )

    approval_digest = canonical_digest(
        {"authority": "test-independent-approval", "scheme_plan": scheme_plan.plan_digest}
    )
    m4_values = {
        "action_id": SECRET_CREATE_ACTION_ID,
        "action_version": SECRET_CREATE_ACTION_VERSION,
        "adapter_ref": "fortipam-191-secret-create-private-adapter",
        "approval_digest": approval_digest,
        "compensation_ref": None,
        "confirmation_digest": scheme_plan.confirmation_digest,
        "expected_current_digest": line.expected_current_digest,
        "expected_state_digest": line.expected_state_digest,
        "expires_at": scheme_plan.expires_at,
        "idempotency_digest": canonical_digest(
            {"line_ref": line.line_ref, "scheme_plan": scheme_plan.plan_digest}
        ),
        "parameters_digest": canonical_digest(
            {"action_id": SECRET_CREATE_ACTION_ID, "line_ref": line.line_ref}
        ),
        "plan_ref": scheme_plan.plan_ref,
        "requester_digest": scheme_plan.requester_digest,
        "revision": scheme_plan.revision,
        "summary_digest": scheme_plan.summary_digest,
        "target_ref": line.target_ref,
    }
    m4_plan = M4ExecutionPlan(
        **m4_values,
        plan_digest=canonical_digest(m4_values),
    )
    authorization_values = {
        "approval_digest": approval_digest,
        "approval_ref": "secret-create-approval-ref01",
        "approver_digest": canonical_digest("independent-test-approver"),
        "authorization_ref": "secret-create-authorization-ref01",
        "confirmation_digest": scheme_plan.confirmation_digest,
        "confirmation_ref": scheme_plan.confirmation_ref,
        "execution_authorized": True,
        "expires_at": clock.value + 120,
        "issued_at": clock.value,
        "one_time": True,
        "plan_digest": m4_plan.plan_digest,
        "plan_ref": m4_plan.plan_ref,
        "requester_digest": scheme_plan.requester_digest,
    }
    authorization = M4ExecutionAuthorization(
        **authorization_values,
        authorization_digest=canonical_digest(authorization_values),
    )
    policy_digest = canonical_digest(
        {"decision": "allow", "plan_digest": m4_plan.plan_digest}
    )
    scope_digest = canonical_digest(draft.scope_ref)
    audience_digest = canonical_digest(draft.audience_ref)
    lease_request = MaterialLeaseRequest(
        action_id=SECRET_CREATE_ACTION_ID,
        action_version=SECRET_CREATE_ACTION_VERSION,
        plan_digest=m4_plan.plan_digest,
        policy_decision_digest=policy_digest,
        authorization_digest=authorization.authorization_digest,
        scope_digest=scope_digest,
        audience_digest=audience_digest,
        provider_class=MaterialProviderClass.EXTERNAL_VAULT_LEASE,
        purpose=MaterialPurpose.INITIAL_ONBOARDING,
        requested_at=clock.value,
        expires_at=min(m4_plan.expires_at, authorization.expires_at),
    )
    material_binding_path = owner_file(
        "secret-m4-binding.json",
        json.dumps(
            {
                "contract": SECRET_CREATE_M4_BINDING_CONTRACT,
                "version": SECRET_CREATE_M4_BINDING_VERSION,
                "material_binding_ref": "private-material-binding-ref01",
                "plan": {
                    **m4_plan.canonical_content(),
                    "plan_digest": m4_plan.plan_digest,
                },
                "authorization": {
                    **authorization.canonical_content(),
                    "authorization_digest": authorization.authorization_digest,
                },
                "lease_request": {
                    "action_id": lease_request.action_id,
                    "action_version": lease_request.action_version,
                    "plan_digest": lease_request.plan_digest,
                    "policy_decision_digest": lease_request.policy_decision_digest,
                    "authorization_digest": lease_request.authorization_digest,
                    "scope_digest": lease_request.scope_digest,
                    "audience_digest": lease_request.audience_digest,
                    "provider_class": lease_request.provider_class.value,
                    "purpose": lease_request.purpose.value,
                    "requested_at": lease_request.requested_at,
                    "expires_at": lease_request.expires_at,
                },
                "policy_decision_digest": policy_digest,
                "scope_digest": scope_digest,
                "audience_digest": audience_digest,
            }
        ).encode(),
    )
    runner_binding_path = owner_file(
        "secret-runner-binding.json",
        json.dumps(
            {
                "contract": SECRET_CREATE_RUNNER_BINDING_CONTRACT,
                "version": SECRET_CREATE_RUNNER_BINDING_VERSION,
                "scheme_plan_ref": scheme_plan.plan_ref,
                "scheme_plan_digest": scheme_plan.plan_digest,
                "line_ref": line.line_ref,
                "requester_digest": scheme_plan.requester_digest,
                "m4_action_id": SECRET_CREATE_ACTION_ID,
                "m4_action_version": SECRET_CREATE_ACTION_VERSION,
                "authorization_ref": authorization.authorization_ref,
            }
        ).encode(),
    )
    material_resolver = _MaterialResolver()
    material_provider = _MaterialProvider()
    private_transport = _MutatingSecretTransport(projection)
    private_adapter = FortiPam191SecretCreatePrivateAdapter(
        SecretCreate191TargetBinding(
            "fortipam-191-secret-create-private-v1",
            "1.9.1",
            m4_plan.plan_digest,
            "private/folder",
            "mcp-v4-secret-metadata-linux01",
            "private-template",
            "private-target",
            "192.0.2.10",
        ),
        private_transport,
    )
    verifier = _AuthorizationVerifier()
    reader = _SecretDigestReader(
        projection,
        line.expected_current_digest,
        line.expected_state_digest,
        secret_onboarding_binding_digest(_binding()),
    )
    m4_runtime = ProtectedSecretCreateM4Runtime(
        OwnerOnlySecretCreateM4BindingResolver(
            material_binding_path,
            material_resolver,
        ),
        verifier,
        InMemoryM4ExecutionStateStore(),
        SecretCreateMaterialRuntime(
            material_provider,  # type: ignore[arg-type]
            InMemoryMaterialUseStateStore(),
            private_adapter,
        ),
        reader,
        authenticated_requester_digest=scheme_plan.requester_digest,
        clock=clock,
    )
    target_action = _TargetAction(target_projection)
    coordinator = components.bind_secret_onboarding_action_coordinator(
        OwnerOnlySecretCreateM4RunnerFactory(runner_binding_path, m4_runtime),
        target_action,
    )
    clock.value = now + 5
    result = coordinator.execute(scheme_plan.plan_ref, draft_ref, principal)

    assert result.outcome == "succeeded", {
        "result": result.as_dict(),
        "material_events": material_provider.events,
        "material_resolutions": material_resolver.calls,
        "private_transport_calls": private_transport.calls,
        "reader_calls": reader.calls,
        "verifier_calls": verifier.calls,
    }
    assert result.pre_write_status == "match"
    assert result.post_write_status == "expected_state_matches"
    assert result.reconciliation_required is False
    assert projection.exists is True
    assert target_projection.exists is True
    assert target_action.calls == ["preview", "confirm", "execute"]
    assert private_transport.calls == 1
    assert material_provider.events == ["validate", "acquire", "release"]
    assert material_resolver.calls == [
        "private-material-binding-ref01",
        "private-material-binding-ref01",
        "private-material-binding-ref01",
    ]
    assert verifier.calls == 1
    assert reader.calls == ["current", "post"]


@pytest.mark.parametrize("postcondition_matches", [True, False])
def test_persistent_host_runs_one_confirmation_through_winrm_collector_m4_readback(
    tmp_path: Path,
    postcondition_matches: bool,
) -> None:
    from test_secret_create_191_http_transport import _winrm_binding
    from test_secret_create_m4_runtime import _Resolver as M4Resolver
    from test_secret_create_m4_runtime import _binding as m4_binding
    from test_v4_execution_kernel import NOW
    from test_v4_planning import _winrm_collector_draft
    from test_v4_secret_create_runtime import _Adapter, _Provider, _runtime
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataInspection

    class CollectorTransport:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.created = False

        def inspect_projection(self, *args: object, **kwargs: object) -> object:
            raise AssertionError("collector planning must use its dedicated projection")

        def inspect(self, *args: object) -> SecretMetadataInspection:
            self.calls.append("inspect")
            return SecretMetadataInspection(self.created, True, True)

        def verify_winrm_collector_preflight(self, *args: object) -> bool:
            self.calls.append("preflight")
            return True

        def resolve_existing_secret_id(self, *args: object) -> int:
            self.calls.append("resolve")
            return 23

        def verify_winrm_collector(
            self,
            *args: object,
            expected_secret_id: int,
            owner_name: str,
            expected_target_address: str,
            expected_rdp_event_filter_profile: str,
        ) -> bool:
            assert expected_secret_id == 23
            assert owner_name == "example-owner"
            assert expected_target_address == "192.0.2.10"
            assert expected_rdp_event_filter_profile == "mcp-v4-rdp-event-filter-example"
            self.calls.append("post")
            self.created = True
            return postcondition_matches

    class CollectorResolver:
        def __init__(self, value: SecretOnboardingBinding) -> None:
            self._value = value

        def resolve(
            self,
            draft_value: object,
            requester_value: object,
        ) -> SecretOnboardingBinding:
            assert draft_value == draft
            assert requester_value == requester
            return self._value

    class CollectorRunnerFactory:
        def bind(
            self,
            plan_value: object,
            line_ref: str,
            principal_value: object,
            *,
            draft: object | None = None,
            onboarding_binding: object | None = None,
        ) -> _SecretCreateRunner:
            assert plan_value == scheme_plan
            assert principal_value == principal
            assert draft == expected_draft
            assert onboarding_binding == binding
            return _SecretCreateRunner(
                line_ref,
                (),
                authorization.authorization_ref,
                reader.inspect_onboarding_binding_digest(),
                runtime,
            )

    now = NOW
    clock = _Clock(now)
    state, oauth = tmp_path / "state", tmp_path / "oauth"
    state.mkdir(mode=0o700)
    oauth.mkdir(mode=0o700)

    def owner_file(name: str, value: bytes) -> Path:
        path = state / name
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    requester = _requester()
    draft = replace(
        _winrm_collector_draft(),
        material_reference_metadata=replace(
            _winrm_collector_draft().material_reference_metadata,
            provider_class=MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE.value,
        ),
    )
    private_binding = _winrm_binding()
    objects = {item.object_class: item for item in draft.desired_objects}
    binding = SecretOnboardingBinding(
        folder_object_ref=objects[ObjectClass.FOLDER_BINDING].object_ref,
        folder_path=private_binding.folder_path,
        folder_ref=dict(objects[ObjectClass.FOLDER_BINDING].desired_fields)["folder_ref"],
        target_object_ref=objects[ObjectClass.TARGET].object_ref,
        target_name=private_binding.target_name,
        target_protocol="rdp",
        connectivity_profile_ref=dict(objects[ObjectClass.TARGET].desired_fields)["connectivity_profile_ref"],
        target_ipv4_address=private_binding.target_ipv4_address,
        template_object_ref=objects[ObjectClass.TEMPLATE_BINDING].object_ref,
        template_name=private_binding.template_name,
        template_ref=dict(objects[ObjectClass.TEMPLATE_BINDING].desired_fields)["template_ref"],
        secret_object_ref=objects[ObjectClass.WINRM_COLLECTOR_METADATA].object_ref,
        secret_name=private_binding.secret_name,
    )
    transport = CollectorTransport()
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                "correct-horse-battery-staple", salt=b"0123456789abcdef"
            ),
        )
    )
    settings = V4SyntheticHostSettings(
        state / "planning.sqlite3",
        owner_file("planning.hmac", b"p" * 32),
        reference_authority=V4PersistentReferenceAuthoritySettings(
            state / "reference.sqlite3", owner_file("reference.hmac", b"r" * 32)
        ),
        scheme_draft_authority=V4PersistentSchemeDraftAuthoritySettings(
            state / "draft.sqlite3", owner_file("draft.hmac", b"d" * 32)
        ),
    )
    components = secret_onboarding_v4_plan_host_factory(
        settings,
        secret_transport=transport,  # type: ignore[arg-type]
        target_transport=TargetTransport(),
        launcher_transport=None,
        binding_resolver=CollectorResolver(binding),
        collector_binding=private_binding,
        clock=clock,
    )(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            owner_file("confirmation.hmac", b"c" * 32),
            owner_file("receipt.hmac", b"e" * 32),
        ),
    )
    draft_authority = components.scheme_draft_authority
    reference_authority = components.reference_authority
    assert draft_authority is not None and reference_authority is not None
    draft_ref = draft_authority.issue(
        draft, requester, expires_at=now + 300, now_epoch=now
    )
    reference_bindings = {
        (draft.environment_ref, "environment"),
        (draft.scope_ref, "scope"),
        (draft.owner_ref, "owner"),
        (draft.audience_ref, "audience"),
        *((value, "evidence") for value in draft.evidence_refs),
    }
    object_kinds = {
        ObjectClass.FOLDER_BINDING: "folder_binding",
        ObjectClass.TARGET: "target",
        ObjectClass.TEMPLATE_BINDING: "template_binding",
        ObjectClass.WINRM_COLLECTOR_METADATA: "winrm_collector_metadata",
    }
    for desired in draft.desired_objects:
        contract = winrm_collector_projection_contract(desired.object_class)
        reference_bindings.add((contract.source_ref, "projection_source"))
        reference_bindings.add((desired.object_ref, f"object_{object_kinds[desired.object_class]}"))
        reference_bindings.update(
            (value, f"field_{name}")
            for name, value in desired.desired_fields
            if name.endswith("_ref") and isinstance(value, str)
        )
    reference_authority.issue_many(
        tuple(sorted(reference_bindings)),
        requester_digest=requester.digest,
        environment_ref=draft.environment_ref,
        scope_ref=draft.scope_ref,
        expires_at=now + 300,
        now_epoch=now,
    )
    principal = V4PlanningPrincipal(requester, "b" * 64)
    preview = components.plan_services.preview(draft_ref, principal)
    confirmation_path = str(preview["confirmation_url"]).removeprefix(
        "https://mcp.example.com"
    )
    with TestClient(
        Starlette(routes=components.confirmation_service.routes()),
        base_url="https://mcp.example.com",
    ) as client:
        page = client.get(confirmation_path)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert csrf is not None
        clock.value = now + 1
        review = client.post(
            confirmation_path,
            data={
                "csrf_token": csrf.group(1), "username": "operator",
                "password": "correct-horse-battery-staple", "action": "review",
            },
            headers={"origin": "https://mcp.example.com"},
        )
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', review.text)
        assert csrf is not None
        clock.value = now + 2
        assert client.post(
            confirmation_path,
            data={"csrf_token": csrf.group(1), "action": "affirm"},
            headers={"origin": "https://mcp.example.com"},
        ).status_code == 200
    clock.value = now + 3
    confirmation = components.plan_services.confirm(
        str(preview["summary_ref"]), int(preview["revision"]), principal
    )
    clock.value = now + 4
    prepared = components.plan_services.prepare(
        str(preview["summary_ref"]), str(confirmation["confirmation_ref"]), principal
    )
    scheme_plan, _ = components.plan_services.resolve_execution_context(
        str(prepared["plan_ref"]), draft_ref, principal
    )
    expected_draft = draft
    assert len(scheme_plan.lines) == 1
    line = scheme_plan.lines[0]
    assert line.target_class is ObjectClass.WINRM_COLLECTOR_METADATA
    assert line.expected_current_digest == winrm_collector_state_digest(
        line.target_ref, exists=False
    )
    assert line.expected_state_digest == winrm_collector_state_digest(
        line.target_ref, exists=True
    )

    reader_binding = replace(private_binding, plan_digest="0" * 64)
    parameter_digest = winrm_collector_binding_digest(reader_binding, line.target_ref)
    m4_values = {
        "action_id": SECRET_CREATE_ACTION_ID,
        "action_version": SECRET_CREATE_ACTION_VERSION,
        "adapter_ref": WINRM_COLLECTOR_ADAPTER_REF,
        "approval_digest": canonical_digest({"scheme_plan": scheme_plan.plan_digest}),
        "compensation_ref": None,
        "confirmation_digest": scheme_plan.confirmation_digest,
        "expected_current_digest": line.expected_current_digest,
        "expected_state_digest": line.expected_state_digest,
        "expires_at": scheme_plan.expires_at,
        "idempotency_digest": canonical_digest({"line": line.line_ref}),
        "parameters_digest": parameter_digest,
        "plan_ref": scheme_plan.plan_ref,
        "requester_digest": scheme_plan.requester_digest,
        "revision": scheme_plan.revision,
        "summary_digest": scheme_plan.summary_digest,
        "target_ref": line.target_ref,
    }
    m4_plan = M4ExecutionPlan(**m4_values, plan_digest=canonical_digest(m4_values))
    reader = WinrmCollectorProjectionReader(
        replace(private_binding, plan_digest=m4_plan.plan_digest), line.target_ref, transport
    )
    authorization_values = {
        "approval_digest": m4_plan.approval_digest,
        "approval_ref": "collector-approval-ref01",
        "approver_digest": canonical_digest("collector-test-approver"),
        "authorization_ref": "collector-authorization-ref01",
        "confirmation_digest": scheme_plan.confirmation_digest,
        "confirmation_ref": scheme_plan.confirmation_ref,
        "execution_authorized": True,
        "expires_at": now + 120,
        "issued_at": now + 4,
        "one_time": True,
        "plan_digest": m4_plan.plan_digest,
        "plan_ref": m4_plan.plan_ref,
        "requester_digest": scheme_plan.requester_digest,
    }
    authorization = M4ExecutionAuthorization(
        **authorization_values,
        authorization_digest=canonical_digest(authorization_values),
    )
    material_provider, private_adapter = _Provider(), _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED)
    execution_binding = m4_binding(m4_plan, authorization)
    execution_binding = replace(execution_binding, lease_request=replace(
        execution_binding.lease_request, requested_at=now + 4,
    ))
    runtime = ProtectedSecretCreateM4Runtime(
        M4Resolver(execution_binding),
        _AuthorizationVerifier(),
        InMemoryM4ExecutionStateStore(),
        _runtime(material_provider, cast(object, private_adapter)),
        reader,
        authenticated_requester_digest=scheme_plan.requester_digest,
        clock=clock,
    )
    coordinator = components.bind_secret_onboarding_action_coordinator(CollectorRunnerFactory())
    clock.value = now + 5
    result = coordinator.execute(scheme_plan.plan_ref, draft_ref, principal)

    assert (result.outcome == "succeeded") is postcondition_matches, (result, transport.calls)
    assert result.pre_write_status == "match"
    if postcondition_matches:
        assert result.post_write_status == "expected_state_matches"
    else:
        assert result.reconciliation_required is True
        assert result.outcome != "succeeded"
    assert transport.calls.count("preflight") == 3
    assert transport.calls.count("post") == (2 if postcondition_matches else 1)
    assert private_adapter.calls == 1


@pytest.mark.parametrize("configured", [False, True])
def test_web_service_sequence_requires_dedicated_factory(configured):
    from types import SimpleNamespace
    requester, _, base = _context()
    binding = replace(_web_binding(), service_object_ref="web-service-object-ref", existing_secret_id=24)
    draft = _web_draft()
    draft = replace(draft, material_reference_metadata=None, desired_objects=(
        *draft.desired_objects,
        _desired(binding.service_object_ref, ObjectClass.WEB_SECRET_SERVICE_BINDING,
                 {"http_service_enabled": True}),
    ))
    line = replace(base.lines[0], target_ref=binding.service_object_ref,
                   target_class=ObjectClass.WEB_SECRET_SERVICE_BINDING,
                   change_kind=ChangeKind.UPDATE, depends_on=())
    content = dict(base.canonical_content())
    content["lines"] = [line.as_dict()]
    content["scheme_id"] = SchemeId.SECRET_ONBOARDING.value
    plan = replace(base, lines=(line,), scheme_id=SchemeId.SECRET_ONBOARDING,
                   plan_digest=canonical_digest(content))
    calls = []
    def bind(*args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(line_ref=line.line_ref, depends_on=())
    def reject(*args, **kwargs):
        pytest.fail("Web service update reached CREATE factory")
    resolver = SecretOnboardingFixedActionSequenceResolver(
        None, SimpleNamespace(resolve_private_binding=lambda *args: binding),
        SimpleNamespace(bind=reject),
        web_service_runner_factory=SimpleNamespace(bind=bind) if configured else None,
    )
    principal = SimpleNamespace(requester=requester)
    if configured:
        result = resolver.bind_prepared(plan, draft, principal)
        assert len(calls) == 1
        assert calls[0]["onboarding_binding"] == binding
    else:
        with pytest.raises(OnboardingActionCoordinatorError):
            resolver.bind_prepared(plan, draft, principal)
        assert calls == []
