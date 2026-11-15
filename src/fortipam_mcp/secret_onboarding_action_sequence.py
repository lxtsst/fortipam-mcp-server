"""Bind the Secret-only onboarding subset to one protected M4 runtime."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Mapping, Protocol

from v4_planning import (
    ChangeKind,
    M4ExecutionPlan,
    M4ExecutionResult,
    ObjectClass,
    PlanLine,
    PreparedPlan,
    SchemeDraft,
    SchemeId,
)

from .onboarding_action_coordinator import (
    BoundFixedActionRunner,
    FixedActionResolutionError,
    OnboardingActionCoordinatorError,
    ResolvedFixedActionSequence,
)
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
)
from v4_planning.models import require_ref
from .secret_onboarding_projection_source import (
    FortiPamSecretOnboardingProjectionSource,
    SecretOnboardingBinding,
    SecretOnboardingProductBinding,
    WebSecretOnboardingBinding,
    secret_onboarding_binding_digest,
)
from .target_contract import DEFAULT_TEMPLATE
from .v4_plan_runtime import OAuthBoundV4PlanServices, V4PlanningPrincipal

from .winrm_collector_projection_reader import WinrmCollectorPlanningSource

from .target_bound_web_projection_reader import (
    TargetBoundWebPlanningBinding, TargetBoundWebPlanningSource,
)


from .domain_secret_projection_reader import (
    DomainSecretPlanningBinding, DomainSecretPlanningSource,
)


SECRET_CREATE_RUNNER_BINDING_CONTRACT = (
    "fortipam-secret-create-scheme-m4-binding-v1"
)
SECRET_CREATE_RUNNER_BINDING_VERSION = "1.0.0"
_MAX_BINDING_BYTES = 16_384


class SecretCreateM4RunnerFactory(Protocol):
    """Resolve an independently authorized M4 runner for one Scheme line."""

    def bind(
        self,
        plan: PreparedPlan,
        line_ref: str,
        principal: V4PlanningPrincipal,
        *,
        draft: SchemeDraft | None = None,
        onboarding_binding: SecretOnboardingProductBinding | None = None,
    ) -> BoundFixedActionRunner: ...


class TargetBoundWebM4RunnerFactory(Protocol):
    """Bind only the separate Target-bound Web planning profile."""

    def bind(
        self, plan: PreparedPlan, line_ref: str, principal: V4PlanningPrincipal, *,
        draft: SchemeDraft | None = None,
        onboarding_binding: TargetBoundWebPlanningBinding | None = None,
    ) -> BoundFixedActionRunner: ...


class DomainSecretM4RunnerFactory(Protocol):
    """Bind only the separate fixed Domain planning profile."""

    def bind(
        self, plan: PreparedPlan, line_ref: str, principal: V4PlanningPrincipal, *,
        draft: SchemeDraft | None = None,
        onboarding_binding: DomainSecretPlanningBinding | None = None,
    ) -> BoundFixedActionRunner: ...


class SecretOnboardingM4RunnerFactory(Protocol):
    """Bind either fixed Secret-create or fixed session-controls runners."""

    def bind(
        self,
        plan: PreparedPlan,
        line_ref: str,
        principal: V4PlanningPrincipal,
        *,
        draft: SchemeDraft | None = None,
        onboarding_binding: SecretOnboardingProductBinding | None = None,
    ) -> BoundFixedActionRunner: ...


class FixedTargetCreateAction(Protocol):
    """Existing requester-bound fixed IPv4 SSH Target C/P/E action."""

    def preview(
        self,
        target_name: str,
        address: str,
        principal: object,
    ) -> dict[str, object]: ...

    def confirm(self, preview_ref: str, principal: object) -> dict[str, object]: ...

    def execute(
        self,
        authorization_ref: str,
        principal: object,
    ) -> dict[str, object]: ...


class SecretCreateBoundRuntime(Protocol):
    def inspect_execution_plan(self, authorization_ref: str) -> M4ExecutionPlan: ...

    def inspect_onboarding_binding_digest(self, authorization_ref: str) -> str: ...

    def execute_bound(
        self,
        authorization_ref: str,
        *,
        expected_onboarding_binding_digest: str | None = None,
    ) -> M4ExecutionResult: ...


@dataclass(frozen=True, slots=True)
class ProtectedSecretCreateRunnerBinding:
    """Value-free in-process binding to one already-protected M4 authorization."""

    scheme_plan_digest: str
    line_ref: str
    requester_digest: str
    authorization_ref: str
    runtime: SecretCreateBoundRuntime


@dataclass(frozen=True, slots=True)
class _SecretCreateRunner:
    line_ref: str
    depends_on: tuple[str, ...]
    authorization_ref: str
    onboarding_binding_digest: str
    runtime: SecretCreateBoundRuntime

    def execute_bound(self) -> Mapping[str, object]:
        return self.runtime.execute_bound(
            self.authorization_ref,
            expected_onboarding_binding_digest=self.onboarding_binding_digest,
        ).as_dict()


@dataclass(frozen=True, slots=True)
class _BoundTargetCreateRunner:
    line_ref: str
    depends_on: tuple[str, ...]
    binding: SecretOnboardingBinding
    action: FixedTargetCreateAction
    principal: V4PlanningPrincipal

    def execute_bound(self) -> Mapping[str, object]:
        try:
            preview = self.action.preview(
                self.binding.target_name,
                self.binding.target_ipv4_address,
                self.principal,
            )
            _validate_target_preview(preview, self.binding)
            preview_ref = preview.get("preview_ref")
            if not isinstance(preview_ref, str) or not preview_ref:
                return _target_action_failure("target_create_preview")
        except Exception:
            return _target_action_failure("target_create_preview")

        try:
            confirmation = self.action.confirm(preview_ref, self.principal)
            authorization_ref = confirmation.get("authorization_ref")
            if not isinstance(authorization_ref, str) or not authorization_ref:
                return _target_action_failure("target_create_confirmation")
        except Exception:
            return _target_action_failure("target_create_confirmation")

        try:
            result = self.action.execute(authorization_ref, self.principal)
        except Exception:
            return _target_action_failure("target_create_execution")
        if not isinstance(result, Mapping):
            return _target_action_failure("target_create_execution")
        return result


def _target_action_failure(failure_stage: str) -> dict[str, object]:
    """Return a value-free reconciliation result for one fixed Target stage."""

    return {
        "failure_stage": failure_stage,
        "outcome": "reconciliation_required",
        "verification": "unknown",
    }


class ExactSecretCreateM4RunnerFactory:
    """Bind one exact Scheme Plan line to one protected M4 runtime."""

    def __init__(self, binding: ProtectedSecretCreateRunnerBinding) -> None:
        self._binding = binding

    def bind(
        self,
        plan: PreparedPlan,
        line_ref: str,
        principal: V4PlanningPrincipal,
        *,
        draft: SchemeDraft | None = None,
        onboarding_binding: SecretOnboardingProductBinding | None = None,
    ) -> BoundFixedActionRunner:
        del draft
        binding = self._binding
        line = next((item for item in plan.lines if item.line_ref == line_ref), None)
        if (
            binding.scheme_plan_digest != plan.plan_digest
            or binding.line_ref != line_ref
            or binding.requester_digest != principal.requester.digest
            or line is None
            or not binding.authorization_ref
            or onboarding_binding is None
        ):
            raise OnboardingActionCoordinatorError(
                "Protected Secret-create M4 runner binding is unavailable."
            )
        _validate_bound_m4_plan(
            binding.runtime,
            binding.authorization_ref,
            plan,
            line,
        )
        onboarding_binding_digest = _validate_private_onboarding_binding(
            binding.runtime,
            binding.authorization_ref,
            onboarding_binding,
        )
        return _SecretCreateRunner(
            line_ref,
            line.depends_on,
            binding.authorization_ref,
            onboarding_binding_digest,
            binding.runtime,
        )


class OwnerOnlySecretCreateM4RunnerFactory:
    """Reload one value-free Scheme-to-M4 association from an owner-only file."""

    def __init__(
        self,
        path: Path,
        runtime: SecretCreateBoundRuntime,
    ) -> None:
        self._path = Path(path)
        self._runtime = runtime
        if not self._path.is_absolute():
            raise OnboardingActionCoordinatorError(
                "Protected Secret-create runner binding is unavailable."
            )

    def bind(
        self,
        plan: PreparedPlan,
        line_ref: str,
        principal: V4PlanningPrincipal,
        *,
        draft: SchemeDraft | None = None,
        onboarding_binding: SecretOnboardingProductBinding | None = None,
    ) -> BoundFixedActionRunner:
        del draft
        if onboarding_binding is None:
            raise OnboardingActionCoordinatorError(
                "Protected Secret-create runner binding is unavailable."
            )
        payload = self._load()
        expected_keys = {
            "contract",
            "version",
            "scheme_plan_ref",
            "scheme_plan_digest",
            "line_ref",
            "requester_digest",
            "m4_action_id",
            "m4_action_version",
            "authorization_ref",
        }
        if (
            set(payload) != expected_keys
            or payload.get("contract") != SECRET_CREATE_RUNNER_BINDING_CONTRACT
            or payload.get("version") != SECRET_CREATE_RUNNER_BINDING_VERSION
            or payload.get("scheme_plan_ref") != plan.plan_ref
            or payload.get("scheme_plan_digest") != plan.plan_digest
            or payload.get("line_ref") != line_ref
            or payload.get("requester_digest") != principal.requester.digest
            or payload.get("m4_action_id") != SECRET_CREATE_ACTION_ID
            or payload.get("m4_action_version") != SECRET_CREATE_ACTION_VERSION
        ):
            raise OnboardingActionCoordinatorError(
                "Protected Secret-create runner binding is unavailable."
            )
        authorization_ref = payload.get("authorization_ref")
        if not isinstance(authorization_ref, str) or not authorization_ref:
            raise OnboardingActionCoordinatorError(
                "Protected Secret-create runner binding is unavailable."
            )
        try:
            require_ref(authorization_ref, "Secret-create authorization_ref")
        except ValueError as exc:
            raise OnboardingActionCoordinatorError(
                "Protected Secret-create runner binding is unavailable."
            ) from exc
        line = next((item for item in plan.lines if item.line_ref == line_ref), None)
        if line is None:
            raise OnboardingActionCoordinatorError(
                "Protected Secret-create runner binding is unavailable."
            )
        _validate_bound_m4_plan(
            self._runtime,
            authorization_ref,
            plan,
            line,
        )
        onboarding_binding_digest = _validate_private_onboarding_binding(
            self._runtime,
            authorization_ref,
            onboarding_binding,
        )
        return _SecretCreateRunner(
            line_ref,
            line.depends_on,
            authorization_ref,
            onboarding_binding_digest,
            self._runtime,
        )

    def _load(self) -> Mapping[str, object]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._path, flags)
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077
                    or info.st_size <= 0
                    or info.st_size > _MAX_BINDING_BYTES
                ):
                    raise OnboardingActionCoordinatorError(
                        "Protected Secret-create runner binding is unavailable."
                    )
                content = os.read(descriptor, _MAX_BINDING_BYTES + 1)
            finally:
                os.close(descriptor)
            if len(content) > _MAX_BINDING_BYTES:
                raise OnboardingActionCoordinatorError(
                    "Protected Secret-create runner binding is unavailable."
                )
            value = json.loads(content)
        except OnboardingActionCoordinatorError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise OnboardingActionCoordinatorError(
                "Protected Secret-create runner binding is unavailable."
            ) from exc
        if not isinstance(value, Mapping):
            raise OnboardingActionCoordinatorError(
                "Protected Secret-create runner binding is unavailable."
            )
        return {str(key): item for key, item in value.items()}


def _validate_bound_m4_plan(
    runtime: SecretCreateBoundRuntime,
    authorization_ref: str,
    scheme_plan: PreparedPlan,
    line: PlanLine,
) -> None:
    try:
        m4_plan = runtime.inspect_execution_plan(authorization_ref)
    except Exception as exc:
        raise OnboardingActionCoordinatorError(
            "Protected Secret-create M4 runner binding is unavailable."
        ) from exc
    if (
        not isinstance(m4_plan, M4ExecutionPlan)
        or m4_plan.action_id != SECRET_CREATE_ACTION_ID
        or m4_plan.action_version != SECRET_CREATE_ACTION_VERSION
        or m4_plan.plan_ref != scheme_plan.plan_ref
        or m4_plan.revision != scheme_plan.revision
        or m4_plan.requester_digest != scheme_plan.requester_digest
        or m4_plan.summary_digest != scheme_plan.summary_digest
        or m4_plan.confirmation_digest != scheme_plan.confirmation_digest
        or m4_plan.target_ref != line.target_ref
        or m4_plan.expected_current_digest != line.expected_current_digest
        or m4_plan.expected_state_digest != line.expected_state_digest
    ):
        raise OnboardingActionCoordinatorError(
            "Protected Secret-create M4 runner binding is unavailable."
        )


def _validate_private_onboarding_binding(
    runtime: SecretCreateBoundRuntime,
    authorization_ref: str,
    onboarding_binding: SecretOnboardingProductBinding,
) -> str:
    try:
        expected = secret_onboarding_binding_digest(onboarding_binding)
        actual = runtime.inspect_onboarding_binding_digest(authorization_ref)
    except Exception as exc:
        raise OnboardingActionCoordinatorError(
            "Protected Secret-create M4 runner binding is unavailable."
        ) from exc
    if actual != expected:
        raise OnboardingActionCoordinatorError(
            "Protected Secret-create M4 runner binding is unavailable."
        )
    return expected


class SecretOnboardingFixedActionSequenceResolver:
    """Resolve one exact source-backed Secret create action sequence."""

    def __init__(
        self,
        plan_services: OAuthBoundV4PlanServices,
        projection_source: FortiPamSecretOnboardingProjectionSource | WinrmCollectorPlanningSource | TargetBoundWebPlanningSource | DomainSecretPlanningSource,
        runner_factory: SecretOnboardingM4RunnerFactory,
        target_action: FixedTargetCreateAction | None = None,
        *,
        session_controls_runner_factory: SecretOnboardingM4RunnerFactory | None = None,
        web_service_runner_factory: SecretOnboardingM4RunnerFactory | None = None,
        target_bound_web_runner_factory: TargetBoundWebM4RunnerFactory | None = None,
        domain_secret_runner_factory: DomainSecretM4RunnerFactory | None = None,
    ) -> None:
        self._domain_secret_runner_factory = domain_secret_runner_factory
        self._target_bound_web_runner_factory = target_bound_web_runner_factory
        self._web_service_runner_factory = web_service_runner_factory
        self._session_controls_runner_factory = session_controls_runner_factory
        self._plan_services = plan_services
        self._projection_source = projection_source
        self._runner_factory = runner_factory
        self._target_action = target_action

    def resolve(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> ResolvedFixedActionSequence:
        try:
            plan, draft = self._plan_services.resolve_execution_context(
                plan_ref,
                scheme_draft_ref,
                principal,
            )
        except Exception as exc:
            raise FixedActionResolutionError(
                "fixed_action_context", str(exc)
            ) from exc
        return self.bind_prepared(plan, draft, principal)

    def bind_prepared(
        self,
        plan: PreparedPlan,
        draft: SchemeDraft,
        principal: V4PlanningPrincipal,
        *,
        external_dependency_refs: tuple[str, ...] = (),
    ) -> ResolvedFixedActionSequence:
        """Bind Secret actions from one already-resolved parent Scheme plan."""

        try:
            binding = self._projection_source.resolve_private_binding(
                draft,
                principal.requester,
            )
        except OnboardingActionCoordinatorError as exc:
            raise FixedActionResolutionError(
                "fixed_action_private_binding", str(exc)
            ) from None
        except Exception as exc:
            raise FixedActionResolutionError(
                "fixed_action_private_binding", str(exc)
            ) from exc

        if isinstance(binding, DomainSecretPlanningBinding):
            domain_factory = self._domain_secret_runner_factory
            line = plan.lines[0] if len(plan.lines) == 1 else None
            if (
                not isinstance(self._projection_source, DomainSecretPlanningSource)
                or domain_factory is None or external_dependency_refs
                or line is None or line.depends_on
                or line.target_class is not ObjectClass.DOMAIN_SECRET_METADATA
                or line.change_kind is not ChangeKind.CREATE
                or line.target_ref != binding.secret_object_ref
                or plan.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.blueprint_ref != "FPA-BP-014"
                or draft.outcome_code != "onboard_domain_account"
            ):
                raise FixedActionResolutionError("fixed_action_runner_promotion_shape")
            runner = domain_factory.bind(
                plan, line.line_ref, principal, draft=draft, onboarding_binding=binding,
            )
            if getattr(runner, "onboarding_binding_digest", None) != self._projection_source.inspect_domain_secret_binding_digest(draft, principal.requester):
                raise FixedActionResolutionError("fixed_action_private_binding")
            return ResolvedFixedActionSequence(plan.plan_ref, plan.requester_digest, (runner,))

        if isinstance(binding, TargetBoundWebPlanningBinding):
            bound_web_factory = self._target_bound_web_runner_factory
            line = plan.lines[0] if len(plan.lines) == 1 else None
            if (
                not isinstance(self._projection_source, TargetBoundWebPlanningSource)
                or bound_web_factory is None or external_dependency_refs
                or line is None or line.depends_on
                or line.target_class is not ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA
                or line.change_kind is not ChangeKind.CREATE
                or line.target_ref != binding.secret_object_ref
                or plan.scheme_id is not SchemeId.SECRET_ONBOARDING
            ):
                raise FixedActionResolutionError("fixed_action_runner_promotion_shape")
            bound_runner = bound_web_factory.bind(
                plan, line.line_ref, principal, draft=draft, onboarding_binding=binding,
            )
            if getattr(bound_runner, "onboarding_binding_digest", None) != self._projection_source.inspect_target_bound_web_binding_digest(draft, principal.requester):
                raise FixedActionResolutionError("fixed_action_private_binding")
            return ResolvedFixedActionSequence(plan.plan_ref, plan.requester_digest, (bound_runner,))

        if any(item.object_class is ObjectClass.WINRM_COLLECTOR_METADATA for item in draft.desired_objects):
            line = plan.lines[0] if len(plan.lines) == 1 else None
            if (not isinstance(self._projection_source, WinrmCollectorPlanningSource)
                or not isinstance(binding, SecretOnboardingBinding)
                or external_dependency_refs or line is None or line.depends_on
                or line.target_class is not ObjectClass.WINRM_COLLECTOR_METADATA
                or line.change_kind is not ChangeKind.CREATE
                or line.target_ref != binding.secret_object_ref
                or plan.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.blueprint_ref != "FPA-BP-006"):
                raise FixedActionResolutionError("fixed_action_runner_promotion_shape")
            runner = self._runner_factory.bind(plan, line.line_ref, principal,
                                              draft=draft, onboarding_binding=binding)
            if getattr(runner, "onboarding_binding_digest", None) != self._projection_source.inspect_collector_binding_digest(draft, principal.requester):
                raise FixedActionResolutionError("fixed_action_private_binding")
            return ResolvedFixedActionSequence(plan.plan_ref, plan.requester_digest, (runner,))

        if any(item.object_class is ObjectClass.WEB_SECRET_SERVICE_BINDING for item in draft.desired_objects):
            factory = self._web_service_runner_factory
            line = plan.lines[0] if len(plan.lines) == 1 else None
            if (
                factory is None or external_dependency_refs
                or not isinstance(binding, WebSecretOnboardingBinding)
                or binding.service_object_ref is None or binding.existing_secret_id is None
                or plan.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.blueprint_ref != "FPA-BP-007"
                or draft.outcome_code != "onboard_web_account"
                or draft.material_reference_metadata is not None or line is None
                or line.target_class is not ObjectClass.WEB_SECRET_SERVICE_BINDING
                or line.target_ref != binding.service_object_ref
                or line.change_kind is not ChangeKind.UPDATE or line.depends_on
            ):
                raise OnboardingActionCoordinatorError("Existing Web service action is unavailable.")
            runner = factory.bind(plan, line.line_ref, principal, draft=draft, onboarding_binding=binding)
            return ResolvedFixedActionSequence(plan.plan_ref, plan.requester_digest, (runner,))

        if any(
            item.object_class is ObjectClass.SECRET_SESSION_CONTROLS_BINDING
            for item in draft.desired_objects
        ):
            factory = self._session_controls_runner_factory
            line = plan.lines[0] if len(plan.lines) == 1 else None
            if (
                factory is None
                or external_dependency_refs
                or not isinstance(binding, SecretOnboardingBinding)
                or plan.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.blueprint_ref != "FPA-BP-006"
                or draft.outcome_code != "onboard_windows_rdp_resource"
                or draft.material_reference_metadata is not None
                or line is None
                or line.target_class is not ObjectClass.SECRET_SESSION_CONTROLS_BINDING
                or line.change_kind is not ChangeKind.UPDATE
                or line.depends_on
            ):
                raise OnboardingActionCoordinatorError(
                    "Existing Secret session-controls action is unavailable."
                )
            runner = factory.bind(
                plan, line.line_ref, principal,
                draft=draft, onboarding_binding=binding,
            )
            return ResolvedFixedActionSequence(
                plan.plan_ref, plan.requester_digest, (runner,),
            )

        try:
            target_line, secret_line = self._validate_plan(
                plan,
                draft,
                binding,
                external_dependency_refs=external_dependency_refs,
            )
        except OnboardingActionCoordinatorError as exc:
            raise FixedActionResolutionError(
                "fixed_action_plan_validation", str(exc)
            ) from None
        try:
            runners: list[BoundFixedActionRunner] = []
            if target_line is not None:
                if (
                    self._target_action is None
                    or not isinstance(binding, SecretOnboardingBinding)
                ):
                    raise OnboardingActionCoordinatorError(
                        "Secret onboarding Target-create action is unavailable."
                    )
                runners.append(
                    _BoundTargetCreateRunner(
                        target_line.line_ref,
                        target_line.depends_on,
                        binding,
                        self._target_action,
                        principal,
                    )
                )
            runners.append(
                self._runner_factory.bind(
                    plan,
                    secret_line.line_ref,
                    principal,
                    draft=draft,
                    onboarding_binding=binding,
                )
            )
        except FixedActionResolutionError:
            raise
        except OnboardingActionCoordinatorError as exc:
            raise FixedActionResolutionError(
                "fixed_action_runner_binding", str(exc)
            ) from None
        except Exception as exc:
            raise FixedActionResolutionError(
                "fixed_action_runner_binding", str(exc)
            ) from exc
        return ResolvedFixedActionSequence(
            plan.plan_ref,
            plan.requester_digest,
            tuple(runners),
        )

    @staticmethod
    def _validate_plan(
        plan: PreparedPlan,
        draft: SchemeDraft,
        binding: SecretOnboardingProductBinding,
        *,
        external_dependency_refs: tuple[str, ...] = (),
    ) -> tuple[PlanLine | None, PlanLine]:
        linux_profile = isinstance(binding, SecretOnboardingBinding) and (
            draft.blueprint_ref == "FPA-BP-005"
            and draft.outcome_code == "onboard_privileged_resource"
            and binding.target_protocol in {"ssh", "sftp"}
            and binding.policy_object_ref is None
        )
        windows_rdp_profile = isinstance(binding, SecretOnboardingBinding) and (
            draft.blueprint_ref == "FPA-BP-006"
            and draft.outcome_code == "onboard_windows_rdp_resource"
            and binding.target_protocol == "rdp"
            and binding.launcher_object_ref is not None
            and binding.policy_object_ref is not None
        )
        web_profile = isinstance(binding, WebSecretOnboardingBinding) and (
            draft.blueprint_ref == "FPA-BP-007"
            and draft.outcome_code == "onboard_web_account"
            and binding.template_name == "Web Account"
            and binding.session_recording is True
        )
        external_dependencies = set(external_dependency_refs)
        secret_lines = tuple(
            line
            for line in plan.lines
            if line.target_class
            in {
                ObjectClass.TARGET,
                ObjectClass.SECRET_METADATA,
                ObjectClass.WEB_SECRET_METADATA,
            }
        )
        other_lines = tuple(line for line in plan.lines if line not in secret_lines)
        public_folder_lines = tuple(
            line
            for line in other_lines
            if line.target_class is ObjectClass.PUBLIC_FOLDER
        )
        access_grant_lines = tuple(
            line
            for line in other_lines
            if line.target_class is ObjectClass.ACCESS_GRANT
        )
        folder_dependency = (
            (public_folder_lines[0].line_ref,)
            if len(public_folder_lines) == 1
            else ()
        )
        if (
            plan.scheme_id is not SchemeId.SECRET_ONBOARDING
            or not (linux_profile or windows_rdp_profile or web_profile)
            or len(external_dependencies) != len(external_dependency_refs)
            or {line.line_ref for line in other_lines} != external_dependencies
            or len(public_folder_lines) > 1
            or len(public_folder_lines) + len(access_grant_lines)
            != len(other_lines)
            or any(
                line.change_kind is not ChangeKind.CREATE or line.depends_on
                for line in public_folder_lines
            )
            or any(
                line.change_kind is not ChangeKind.CREATE
                or line.depends_on != folder_dependency
                for line in access_grant_lines
            )
            or len(secret_lines) not in {1, 2}
            or ((windows_rdp_profile or web_profile) and len(secret_lines) != 1)
        ):
            raise OnboardingActionCoordinatorError(
                "Secret onboarding dependencies are not already satisfied."
            )
        target_line = next(
            (line for line in secret_lines if line.target_class is ObjectClass.TARGET),
            None,
        )
        secret_line = next(
            (
                line
                for line in secret_lines
                if line.target_class
                is (
                    ObjectClass.WEB_SECRET_METADATA
                    if web_profile
                    else ObjectClass.SECRET_METADATA
                )
            ),
            None,
        )
        if secret_line is None or (len(secret_lines) == 1) != (target_line is None):
            raise OnboardingActionCoordinatorError(
                "Secret onboarding dependencies are not already satisfied."
            )
        desired = {
            item.object_ref: item
            for item in draft.desired_objects
        }
        secret_desired = desired.get(secret_line.target_ref)
        if (
            secret_line.target_ref != binding.secret_object_ref
            or secret_line.change_kind is not ChangeKind.CREATE
            or secret_desired is None
            or secret_desired.object_class
            is not (
                ObjectClass.WEB_SECRET_METADATA
                if web_profile
                else ObjectClass.SECRET_METADATA
            )
            or not secret_desired.desired_exists
            or dict(secret_desired.desired_fields)
            != (
                {"inherit_permission": True, "session_recording": True}
                if web_profile
                else {"inherit_permission": True}
            )
        ):
            raise OnboardingActionCoordinatorError(
                "Secret onboarding Plan is not the exact fixed create subset."
            )
        if target_line is None:
            if (
                len(secret_line.depends_on) != len(external_dependencies)
                or set(secret_line.depends_on) != external_dependencies
            ):
                raise OnboardingActionCoordinatorError(
                    "Secret onboarding Plan is not the exact fixed create subset."
                )
            if windows_rdp_profile:
                if not isinstance(binding, SecretOnboardingBinding):
                    raise OnboardingActionCoordinatorError(
                        "Secret onboarding Plan is not the exact fixed create subset."
                    )
                launcher_object_ref = binding.launcher_object_ref
                policy_object_ref = binding.policy_object_ref
                if launcher_object_ref is None or policy_object_ref is None:
                    raise OnboardingActionCoordinatorError(
                        "Secret onboarding Plan is not the exact fixed create subset."
                    )
                launcher_desired = desired.get(launcher_object_ref)
                policy_desired = desired.get(policy_object_ref)
                event_filter_desired = (
                    desired.get(binding.rdp_event_filter_object_ref)
                    if binding.rdp_event_filter_object_ref is not None
                    else None
                )
                target_desired = desired.get(binding.target_object_ref)
                if (
                    target_desired is None
                    or target_desired.object_class is not ObjectClass.TARGET
                    or dict(target_desired.desired_fields)
                    != {
                        "connectivity_profile_ref": binding.connectivity_profile_ref,
                        "protocol": "rdp",
                    }
                    or launcher_desired is None
                    or launcher_desired.object_class
                    is not ObjectClass.LAUNCHER_BINDING
                    or dict(launcher_desired.desired_fields)
                    != {"launcher_profile_ref": binding.launcher_profile_ref}
                    or policy_desired is None
                    or policy_desired.object_class is not ObjectClass.POLICY_BINDING
                    or dict(policy_desired.desired_fields)
                    != {"policy_profile_ref": binding.policy_profile_ref}
                    or (
                        binding.rdp_event_filter_object_ref is not None
                        and (
                            event_filter_desired is None
                            or event_filter_desired.object_class
                            is not ObjectClass.RDP_EVENT_FILTER_BINDING
                            or dict(event_filter_desired.desired_fields)
                            != {
                                "profile_ref": binding.rdp_event_filter_profile_ref
                            }
                        )
                    )
                ):
                    raise OnboardingActionCoordinatorError(
                        "Secret onboarding Plan is not the exact fixed create subset."
                    )
            return None, secret_line
        if windows_rdp_profile or web_profile or not isinstance(
            binding,
            SecretOnboardingBinding,
        ):
            raise OnboardingActionCoordinatorError(
                "Secret onboarding dependencies are not already satisfied."
            )
        target_desired = desired.get(target_line.target_ref)
        if (
            target_line.target_ref != binding.target_object_ref
            or target_line.change_kind is not ChangeKind.CREATE
            or target_line.depends_on
            or len(secret_line.depends_on) != len(external_dependencies) + 1
            or set(secret_line.depends_on)
            != external_dependencies | {target_line.line_ref}
            or target_desired is None
            or target_desired.object_class is not ObjectClass.TARGET
            or not target_desired.desired_exists
            or dict(target_desired.desired_fields)
            != {
                "connectivity_profile_ref": binding.connectivity_profile_ref,
                "protocol": binding.target_protocol,
            }
        ):
            raise OnboardingActionCoordinatorError(
                "Secret onboarding Plan is not the exact fixed create subset."
            )
        return target_line, secret_line


def _validate_target_preview(
    preview: Mapping[str, object],
    binding: SecretOnboardingBinding,
) -> None:
    current = preview.get("Current State")
    proposed = preview.get("Proposed Changes")
    expected = preview.get("Expected State")
    if (
        preview.get("device_write_executed") is not False
        or not isinstance(current, Mapping)
        or not isinstance(proposed, Mapping)
        or not isinstance(expected, Mapping)
        or current.get("requested_target_name") != binding.target_name
        or current.get("requested_target_address") != binding.target_ipv4_address
        or current.get("target_exists") is not False
        or current.get("write_transport") != "rest_api"
        or proposed.get("operation") != "create_target_via_api"
        or proposed.get("request_projection")
        != "fortipam_7_0_0_build_29_target_frontend_unparse"
        or current.get("product_version") != "7.0.0"
        or current.get("product_build") != 29
        or proposed.get("product_version") != "7.0.0"
        or proposed.get("product_build") != 29
        or proposed.get("target_name") != binding.target_name
        or proposed.get("target_class") != "other"
        or proposed.get("template") != DEFAULT_TEMPLATE
        or proposed.get("endpoint_type") != "ipv4"
        or proposed.get("target_address") != binding.target_ipv4_address
        or proposed.get("web_proxy_status") != "disable"
        or proposed.get("owner_binding") != "verified_admin_principal"
        or proposed.get("create_secret_group_binding") != "everyone"
        or expected.get("target_exists") is not True
        or expected.get("target_name_matches") is not True
        or expected.get("class_matches") is not True
        or expected.get("template_matches") is not True
        or expected.get("address_matches") is not True
        or expected.get("web_proxy_disabled") is not True
        or expected.get("owner_relation_matches") is not True
        or expected.get("create_secret_group_relation_matches") is not True
    ):
        raise OnboardingActionCoordinatorError(
            "Fixed Target preview does not match the protected connectivity binding."
        )


__all__ = [
    "ExactSecretCreateM4RunnerFactory",
    "FixedTargetCreateAction",
    "OwnerOnlySecretCreateM4RunnerFactory",
    "ProtectedSecretCreateRunnerBinding",
    "SECRET_CREATE_RUNNER_BINDING_CONTRACT",
    "SECRET_CREATE_RUNNER_BINDING_VERSION",
    "SecretCreateM4RunnerFactory",
    "SecretOnboardingM4RunnerFactory",
    "SecretOnboardingFixedActionSequenceResolver",
]
