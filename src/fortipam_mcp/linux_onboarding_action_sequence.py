"""One confirmed existing-or-new-domain Linux onboarding action sequence."""

from __future__ import annotations

from dataclasses import replace

from v4_planning import ObjectClass, SchemeId

from .access_domain_action_sequence import AccessDomainFixedActionSequenceResolver
from .onboarding_action_coordinator import (
    OnboardingActionCoordinatorError,
    ResolvedFixedActionSequence,
)
from .secret_onboarding_action_sequence import (
    SecretOnboardingFixedActionSequenceResolver,
)
from .v4_plan_runtime import OAuthBoundV4PlanServices, V4PlanningPrincipal


class ExistingDomainLinuxOnboardingFixedActionSequenceResolver:
    """Bind Folder, Access Grant, and Secret actions under one BP005 plan.

    The retained class name is compatibility-only.  A missing Folder is now
    represented by one PublicFolder create line; the paired FolderBinding is a
    source-verification view and never becomes a second physical action.
    """

    def __init__(
        self,
        plan_services: OAuthBoundV4PlanServices,
        access_domain: AccessDomainFixedActionSequenceResolver,
        secret_onboarding: SecretOnboardingFixedActionSequenceResolver,
    ) -> None:
        self._plan_services = plan_services
        self._access_domain = access_domain
        self._secret_onboarding = secret_onboarding

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
            access_objects = tuple(
                item
                for item in draft.desired_objects
                if item.object_class
                in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
            )
            secret_objects = tuple(
                item
                for item in draft.desired_objects
                if item.object_class
                not in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
            )
            public_folders = tuple(
                item
                for item in access_objects
                if item.object_class is ObjectClass.PUBLIC_FOLDER
            )
            access_grants = tuple(
                item
                for item in access_objects
                if item.object_class is ObjectClass.ACCESS_GRANT
            )
            folder_bindings = tuple(
                item
                for item in secret_objects
                if item.object_class is ObjectClass.FOLDER_BINDING
            )
            if (
                plan.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.blueprint_ref != "FPA-BP-005"
                or draft.outcome_code != "onboard_privileged_resource"
                or len(public_folders) != 1
                or not access_grants
                or len(folder_bindings) != 1
                or dict(folder_bindings[0].desired_fields).get("folder_ref")
                != public_folders[0].object_ref
            ):
                raise OnboardingActionCoordinatorError(
                    "Combined Linux onboarding fixed action sequence is unavailable."
                )

            access_draft = replace(
                draft,
                scheme_id=SchemeId.ACCESS_DOMAIN,
                blueprint_ref="FPA-BP-004",
                outcome_code="establish_access_domain",
                desired_objects=access_objects,
                material_reference_metadata=None,
            )
            secret_draft = replace(draft, desired_objects=secret_objects)
            access_lines = tuple(
                line
                for line in plan.lines
                if line.target_class
                in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
            )
            if any(
                line.target_class
                not in {
                    ObjectClass.PUBLIC_FOLDER,
                    ObjectClass.ACCESS_GRANT,
                    ObjectClass.TARGET,
                    ObjectClass.SECRET_METADATA,
                }
                for line in plan.lines
            ):
                raise OnboardingActionCoordinatorError(
                    "Combined Linux onboarding fixed action sequence is unavailable."
                )
            access_runners = self._access_domain.bind_prepared_runners(
                plan,
                access_draft,
                principal,
                access_lines,
            )
            secret_sequence = self._secret_onboarding.bind_prepared(
                plan,
                secret_draft,
                principal,
                external_dependency_refs=tuple(
                    line.line_ref for line in access_lines
                ),
            )
            runners = (*access_runners, *secret_sequence.runners)
            if (
                secret_sequence.plan_ref != plan.plan_ref
                or secret_sequence.requester_digest != plan.requester_digest
                or {runner.line_ref for runner in runners}
                != {line.line_ref for line in plan.lines}
                or len(runners) != len(plan.lines)
            ):
                raise OnboardingActionCoordinatorError(
                    "Combined Linux onboarding fixed action sequence is unavailable."
                )
            return ResolvedFixedActionSequence(
                plan.plan_ref,
                plan.requester_digest,
                runners,
            )
        except OnboardingActionCoordinatorError:
            raise
        except Exception as exc:
            raise OnboardingActionCoordinatorError(
                "Combined Linux onboarding fixed action sequence is unavailable."
            ) from exc


class SecretOrExistingDomainLinuxOnboardingResolver:
    """Route one protected Secret Tool by the trusted Draft object shape."""

    def __init__(
        self,
        plan_services: OAuthBoundV4PlanServices,
        secret_only: SecretOnboardingFixedActionSequenceResolver,
        combined: ExistingDomainLinuxOnboardingFixedActionSequenceResolver,
    ) -> None:
        self._plan_services = plan_services
        self._secret_only = secret_only
        self._combined = combined

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
            if (
                plan.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.scheme_id is not SchemeId.SECRET_ONBOARDING
            ):
                raise OnboardingActionCoordinatorError(
                    "Linux onboarding fixed action sequence is unavailable."
                )
            combined = any(
                item.object_class
                in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
                for item in draft.desired_objects
            )
            selected = self._combined if combined else self._secret_only
            return selected.resolve(plan_ref, scheme_draft_ref, principal)
        except OnboardingActionCoordinatorError:
            raise
        except Exception as exc:
            raise OnboardingActionCoordinatorError(
                "Linux onboarding fixed action sequence is unavailable."
            ) from exc


__all__ = [
    "ExistingDomainLinuxOnboardingFixedActionSequenceResolver",
    "SecretOrExistingDomainLinuxOnboardingResolver",
]
