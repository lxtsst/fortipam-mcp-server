"""Deterministic same-process lab-auto promotion for one Secret create.

This module closes the gap between a confirmed non-executable
``SecretOnboardingScheme`` plan and the already protected FortiPAM 1.9.1
M4/C3 runtime.  It is deliberately limited to the named local-lab policy.  It
does not provide a production approval authority or a generic action promoter.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .domain_secret_namespace_candidate import DomainSecretNamespaceSettings
    from .web_secret_fixture_creation_capture import WebSecretFixtureCaptureSettings
    from .unix_discovery_onboarding_guard import UnixDiscoveryOnboardingGuard
    from .owner_rdp_runtime import RdpOwnerSettings

from v4_planning import (
    ChangeKind,
    M4ExecutionAuthorization,
    M4ExecutionPlan,
    M4ExecutionStateStore,
    ObjectClass,
    PreparedPlan,
    SchemeDraft,
    SchemeId,
    canonical_digest,
)
from v4_planning.material_provider import (
    MaterialBindingStatus,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
)
from v4_planning.material_runtime import MaterialUseStateStore
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.models import require_ref
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
)
from v4_planning.secret_create_runtime import SecretCreateMaterialRuntime

from .onboarding_action_coordinator import (
    BoundFixedActionRunner,
    FixedActionResolutionError,
    OnboardingActionCoordinatorError,
)
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_191_http_transport import FortiPam191SecretCreateHttpTransport
from .secret_create_191_private_adapter import (
    FortiPam191SecretCreatePrivateAdapter,
    SecretCreate191TargetBinding,
    SecretCreate191WebBinding,
    SecretCreate700WinrmBinding,
    SecretCreate700WebTargetBinding,
    SecretCreate700DomainBinding,
    load_winrm_collector_private_binding,
)
from .secret_create_191_projection_reader import SecretCreate191ProjectionReader
from .secret_create_central_lab_binding import (
    OwnerOnlyCentralLabSecretCreateBindingResolver,
    _resolve_binding,
)
from .secret_create_central_lab_provider import (
    CentralLabInventorySecretCreateProvider,
    CentralLabSecretCreate191LeaseTransport,
    OwnerOnlyCentralLabSecretCreateEnvFileLoader,
)
from .secret_create_lab_authorization import SecretCreateLabAuthorizationVerifier
from .secret_create_m4_runtime import (
    ProtectedSecretCreateM4Runtime,
    SecretCreateM4ExecutionBinding,
    SecretCreateProjectionReader,
)
from .secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig,
    load_secret_metadata_http_transport_config,
)
from .secret_onboarding_action_sequence import (
    ExactSecretCreateM4RunnerFactory,
    ProtectedSecretCreateRunnerBinding,
    SecretCreateBoundRuntime,
    _SecretCreateRunner,
    _validate_bound_m4_plan,
)
from .secret_onboarding_projection_source import (
    SecretOnboardingBinding,
    SecretOnboardingProductBinding,
    WebSecretOnboardingBinding,
)
from .v4_plan_runtime import V4PlanningPrincipal
from .winrm_collector_projection_reader import (
    ADAPTER_REF as WINRM_COLLECTOR_ADAPTER_REF,
    WinrmCollectorProjectionReader, winrm_collector_binding_digest,
    winrm_collector_projection_contract, winrm_collector_state_digest,
)

from .target_bound_web_projection_reader import (
    ADAPTER_REF as TARGET_BOUND_WEB_ADAPTER_REF,
    TargetBoundWebPlanningBinding, TargetBoundWebProjectionReader,
    target_bound_web_binding_digest, target_bound_web_state_digest,
    load_target_bound_web_planning_binding,
)

from .domain_secret_projection_reader import (
    ADAPTER_REF as DOMAIN_SECRET_ADAPTER_REF, DomainSecretPlanningBinding,
    DomainSecretProjectionReader, domain_secret_binding_digest,
    domain_secret_state_digest, load_domain_secret_planning_binding,
)
from .secret_onboarding_projection_source import secret_onboarding_projection_contract

LAB_AUTO_SECRET_CREATE_AUTHORITY_REF = "fortipam-mcp-lab-auto-secret-create"
LAB_AUTO_SECRET_CREATE_ADAPTER_REF = (
    "fortipam-191-secret-create-private-adapter"
)
LAB_AUTO_SECRET_CREATE_DEFAULT_PROFILE = "fortipam-191"
LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE = "fortipam-700-build29-linux-ssh-create-candidate"
LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_ADAPTER_REF = "fortipam-700-build29-linux-ssh-create-candidate-adapter"
LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE = "fortipam-700-build29-windows-rdp-create-candidate"
LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_ADAPTER_REF = "fortipam-700-build29-windows-rdp-create-candidate-adapter"
LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE = "fortipam-700-build29-web-create-candidate"
LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_ADAPTER_REF = "fortipam-700-build29-web-secret-create-candidate-adapter"
LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE = "fortipam-700-build29-winrm-collector-candidate"
LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE = "fortipam-700-build29-target-bound-web-candidate"
LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE = "fortipam-700-build29-domain-account-candidate"
LAB_AUTO_SECRET_CREATE_TTL_SECONDS = 60
LAB_AUTO_SECRET_CREATE_ENV_PREFIX = (
    "FORTIPAM_MCP_V4_SECRET_CREATE_LAB_AUTO_"
)
_UNAVAILABLE = "Secret-create lab-auto promotion is unavailable."
_MAX_AUTHORITY_KEY_BYTES = 4096


@dataclass(frozen=True, slots=True, repr=False)
class LabAutoSecretCreateArtifacts:
    """Value-free M4 artifacts derived from one exact confirmed Scheme plan."""

    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    lease_request: MaterialLeaseRequest
    policy_decision_digest: str
    scope_digest: str
    audience_digest: str


class LabAutoSecretCreatePromoter:
    """Issue one deterministic lab-auto M4 context for a prepared plan."""

    __slots__ = (
        "_authority_key",
        "_authority_ref",
        "_product_profile",
        "_collector_binding",
        "_bound_web_binding",
        "_domain_binding",
        "_environment_ref",
        "_scope_ref",
    )

    def __init__(
        self,
        authority_key: bytes,
        *,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
        authority_ref: str = LAB_AUTO_SECRET_CREATE_AUTHORITY_REF,
        product_profile: str = LAB_AUTO_SECRET_CREATE_DEFAULT_PROFILE,
        collector_binding: SecretCreate700WinrmBinding | None = None,
        bound_web_binding: TargetBoundWebPlanningBinding | None = None,
        domain_binding: DomainSecretPlanningBinding | None = None,
    ) -> None:
        try:
            if product_profile not in {LAB_AUTO_SECRET_CREATE_DEFAULT_PROFILE, LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE, LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE, LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE, LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE, LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE, LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE}:
                raise ValueError
            if (product_profile == LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE) != isinstance(collector_binding, SecretCreate700WinrmBinding):
                raise ValueError
            if (product_profile == LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE) != isinstance(bound_web_binding, TargetBoundWebPlanningBinding):
                raise ValueError
            if (product_profile == LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE) != isinstance(domain_binding, DomainSecretPlanningBinding):
                raise ValueError
            if domain_binding is not None and (domain_binding.environment_ref != authorized_environment_ref
                    or domain_binding.scope_ref != authorized_scope_ref):
                raise ValueError
            if type(authority_key) is not bytes or len(authority_key) < 32:
                raise ValueError
            self._authority_ref = require_ref(authority_ref, "authority_ref")
            self._environment_ref = require_ref(
                authorized_environment_ref,
                "authorized_environment_ref",
            )
            self._scope_ref = require_ref(
                authorized_scope_ref,
                "authorized_scope_ref",
            )
        except Exception:
            raise OnboardingActionCoordinatorError(_UNAVAILABLE) from None
        self._authority_key = bytes(authority_key)
        self._product_profile = product_profile
        self._collector_binding = collector_binding
        self._bound_web_binding = bound_web_binding
        self._domain_binding = domain_binding

    def __repr__(self) -> str:
        return "<LabAutoSecretCreatePromoter redacted>"

    __str__ = __repr__

    @property
    def product_profile(self) -> str:
        return self._product_profile

    @property
    def collector_binding(self) -> SecretCreate700WinrmBinding | None:
        return self._collector_binding

    def promote(
        self,
        plan: PreparedPlan,
        line_ref: str,
        principal: V4PlanningPrincipal,
        *,
        draft: SchemeDraft,
        onboarding_binding: SecretOnboardingProductBinding | TargetBoundWebPlanningBinding | DomainSecretPlanningBinding,
        now_epoch: int,
        discovery_guard: UnixDiscoveryOnboardingGuard | None = None,
    ) -> LabAutoSecretCreateArtifacts:
        """Derive the exact deterministic M4 authorization and lease request."""

        try:
            line = next(item for item in plan.lines if item.line_ref == line_ref)
            material = draft.material_reference_metadata
            desired = next(
                item
                for item in draft.desired_objects
                if item.object_ref == line.target_ref
            )
            expires_at = min(
                plan.expires_at,
                plan.created_at + LAB_AUTO_SECRET_CREATE_TTL_SECONDS,
            )
            linux_profile = isinstance(onboarding_binding, SecretOnboardingBinding) and (
                draft.blueprint_ref == "FPA-BP-005"
                and draft.outcome_code == "onboard_privileged_resource"
                and onboarding_binding.target_protocol in {"ssh", "sftp"}
                and onboarding_binding.policy_object_ref is None
            )
            windows_rdp_profile = isinstance(onboarding_binding, SecretOnboardingBinding) and (
                draft.blueprint_ref == "FPA-BP-006"
                and draft.outcome_code == "onboard_windows_rdp_resource"
                and onboarding_binding.target_protocol == "rdp"
                and onboarding_binding.launcher_object_ref is not None
                and onboarding_binding.policy_object_ref is not None
            )
            web_profile = isinstance(onboarding_binding, WebSecretOnboardingBinding) and (
                draft.blueprint_ref == "FPA-BP-007"
                and draft.outcome_code == "onboard_web_account"
                and onboarding_binding.template_name == "Web Account"
                and onboarding_binding.session_recording is True
            )
            domain_profile = (
                self._product_profile == LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE
                and isinstance(onboarding_binding, DomainSecretPlanningBinding)
                and onboarding_binding == self._domain_binding
            )
            if isinstance(onboarding_binding, DomainSecretPlanningBinding):
                if not domain_profile:
                    raise ValueError
                onboarding_binding.validate_intent(draft, principal.requester)
            elif self._product_profile == LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE:
                raise ValueError
            bound_web_profile = (
                self._product_profile == LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE
                and isinstance(onboarding_binding, TargetBoundWebPlanningBinding)
                and onboarding_binding == self._bound_web_binding
            )
            if isinstance(onboarding_binding, TargetBoundWebPlanningBinding):
                if not bound_web_profile:
                    raise ValueError
                onboarding_binding.validate_intent(draft, principal.requester)
            elif self._product_profile == LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE:
                raise ValueError
            collector_profile = (
                self._product_profile == LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE
                and isinstance(self._collector_binding, SecretCreate700WinrmBinding)
                and isinstance(onboarding_binding, SecretOnboardingBinding)
                and draft.blueprint_ref == "FPA-BP-006"
                and draft.outcome_code == "onboard_windows_rdp_resource"
                and onboarding_binding.target_protocol == "rdp"
                and all(getattr(onboarding_binding, key) is None for key in (
                    "launcher_object_ref", "policy_object_ref", "rdp_event_filter_object_ref",
                    "secret_session_controls_object_ref", "existing_secret_id",
                ))
                and all(getattr(onboarding_binding, key) == getattr(self._collector_binding, key)
                        for key in ("folder_path", "secret_name", "template_name", "target_name", "target_ipv4_address"))
                and len(draft.desired_objects) == 4
                and {item.object_class for item in draft.desired_objects} == {
                    ObjectClass.FOLDER_BINDING, ObjectClass.TARGET,
                    ObjectClass.TEMPLATE_BINDING, ObjectClass.WINRM_COLLECTOR_METADATA,
                }
            )
            if self._product_profile == LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE and not collector_profile:
                raise FixedActionResolutionError("fixed_action_runner_promotion_shape")
            if self._product_profile == LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE and not (
                linux_profile
                and isinstance(onboarding_binding, SecretOnboardingBinding)
                and onboarding_binding.target_protocol == "ssh"
                and onboarding_binding.template_name == "Unix Account (SSH Password)"
                and onboarding_binding.launcher_object_ref is None
                and onboarding_binding.rdp_event_filter_profile_name is None
            ):
                raise FixedActionResolutionError("fixed_action_runner_promotion_shape")
            if self._product_profile == LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE and not web_profile:
                raise ValueError
            if self._product_profile == LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE and not (
                windows_rdp_profile
                and isinstance(onboarding_binding, SecretOnboardingBinding)
                and onboarding_binding.template_name == "Windows Machine"
                and onboarding_binding.secret_session_controls_object_ref is None
                and onboarding_binding.existing_secret_id is None
            ):
                raise FixedActionResolutionError("fixed_action_runner_promotion_shape")
            adapter_ref = (DOMAIN_SECRET_ADAPTER_REF if domain_profile else
                           TARGET_BOUND_WEB_ADAPTER_REF if bound_web_profile else
                           WINRM_COLLECTOR_ADAPTER_REF if collector_profile else
                           LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_ADAPTER_REF
                           if self._product_profile == LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE else
                           LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_ADAPTER_REF
                           if self._product_profile == LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE else
                           LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_ADAPTER_REF
                           if self._product_profile == LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE
                           else LAB_AUTO_SECRET_CREATE_ADAPTER_REF)
            access_lines = tuple(
                item
                for item in plan.lines
                if item.target_class is ObjectClass.ACCESS_GRANT
            )
            public_folder_lines = tuple(
                item
                for item in plan.lines
                if item.target_class is ObjectClass.PUBLIC_FOLDER
            )
            target_lines = tuple(
                item
                for item in plan.lines
                if item.target_class is ObjectClass.TARGET
            )
            external_access_lines = (*public_folder_lines, *access_lines)
            external_dependency_lines = (*external_access_lines, *target_lines)
            folder_dependency = (
                (public_folder_lines[0].line_ref,)
                if len(public_folder_lines) == 1
                else ()
            )
            desired_by_ref = {item.object_ref: item for item in draft.desired_objects}
            if collector_profile:
                assert isinstance(onboarding_binding, SecretOnboardingBinding)
                expected_relations = {
                    onboarding_binding.folder_object_ref: (ObjectClass.FOLDER_BINDING, {"folder_ref": onboarding_binding.folder_ref}),
                    onboarding_binding.target_object_ref: (ObjectClass.TARGET, {
                        "protocol": "rdp", "connectivity_profile_ref": onboarding_binding.connectivity_profile_ref}),
                    onboarding_binding.template_object_ref: (ObjectClass.TEMPLATE_BINDING, {
                        "compatibility": "compatible", "template_ref": onboarding_binding.template_ref}),
                }
                if len(expected_relations) != 3 or any(
                    (item := desired_by_ref.get(ref)) is None or not item.desired_exists
                    or (item.object_class, dict(item.desired_fields)) != expected
                    for ref, expected in expected_relations.items()
                ):
                    raise FixedActionResolutionError("fixed_action_runner_promotion_shape")
            target_line_matches = not target_lines or (
                len(target_lines) == 1
                and isinstance(onboarding_binding, SecretOnboardingBinding)
                and target_lines[0].target_ref == onboarding_binding.target_object_ref
                and target_lines[0].change_kind is ChangeKind.CREATE
                and not target_lines[0].depends_on
                and (
                    target_desired := desired_by_ref.get(target_lines[0].target_ref)
                )
                is not None
                and target_desired.object_class is ObjectClass.TARGET
                and target_desired.desired_exists
                and dict(target_desired.desired_fields)
                == {
                    "connectivity_profile_ref": (
                        onboarding_binding.connectivity_profile_ref
                    ),
                    "protocol": onboarding_binding.target_protocol,
                }
            )
            single_secret_plan = len(plan.lines) == 1 and not line.depends_on
            if domain_profile and (
                not single_secret_plan or line.change_kind is not ChangeKind.CREATE
                or line.projection_contract_ref != secret_onboarding_projection_contract(ObjectClass.DOMAIN_SECRET_METADATA).contract_id
                or line.expected_current_digest != domain_secret_state_digest(onboarding_binding.secret_object_ref, exists=False)
                or line.expected_state_digest != domain_secret_state_digest(onboarding_binding.secret_object_ref, exists=True)
            ):
                raise FixedActionResolutionError("fixed_action_runner_promotion_shape")
            if bound_web_profile and (
                not single_secret_plan or line.change_kind is not ChangeKind.CREATE
                or line.projection_contract_ref != "fortipam-target-bound-web-observation-v1"
                or line.expected_current_digest != target_bound_web_state_digest(onboarding_binding.secret_object_ref, exists=False)
                or line.expected_state_digest != target_bound_web_state_digest(onboarding_binding.secret_object_ref, exists=True)
            ):
                raise FixedActionResolutionError("fixed_action_runner_promotion_shape")
            if collector_profile and (
                not single_secret_plan
                or line.change_kind is not ChangeKind.CREATE
                or line.projection_contract_ref != winrm_collector_projection_contract().contract_id
                or line.expected_current_digest != winrm_collector_state_digest(onboarding_binding.secret_object_ref, exists=False)
                or line.expected_state_digest != winrm_collector_state_digest(onboarding_binding.secret_object_ref, exists=True)
            ):
                raise FixedActionResolutionError("fixed_action_runner_promotion_shape")
            combined_access_domain_plan = (
                linux_profile
                and bool(access_lines)
                and len(public_folder_lines) <= 1
                and len(target_lines) <= 1
                and target_line_matches
                and len(plan.lines) == len(external_dependency_lines) + 1
                and all(
                    item.change_kind is ChangeKind.CREATE and not item.depends_on
                    for item in public_folder_lines
                )
                and all(
                    item.change_kind is ChangeKind.CREATE
                    and item.depends_on == folder_dependency
                    for item in access_lines
                )
                and len(line.depends_on) == len(external_dependency_lines)
                and set(line.depends_on)
                == {item.line_ref for item in external_dependency_lines}
            )
            target_secret_plan = (
                linux_profile
                and not external_access_lines
                and len(target_lines) == 1
                and target_line_matches
                and len(plan.lines) == 2
                and line.change_kind is ChangeKind.CREATE
                and line.depends_on == (target_lines[0].line_ref,)
            )
            if (
                type(now_epoch) is not int
                or now_epoch < plan.created_at
                or now_epoch >= expires_at
            ):
                raise FixedActionResolutionError(
                    "fixed_action_runner_promotion_freshness"
                )
            if (
                principal.requester.digest != plan.requester_digest
                or plan.environment_ref != self._environment_ref
                or plan.scope_ref != self._scope_ref
                or draft.environment_ref != self._environment_ref
                or draft.scope_ref != self._scope_ref
                or plan.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.scheme_id is not SchemeId.SECRET_ONBOARDING
            ):
                raise FixedActionResolutionError(
                    "fixed_action_runner_promotion_context"
                )
            if (
                not (linux_profile or windows_rdp_profile or web_profile or collector_profile or bound_web_profile or domain_profile)
                or not (
                    single_secret_plan
                    or combined_access_domain_plan
                    or target_secret_plan
                )
                or line.target_class
                is not (
                    ObjectClass.DOMAIN_SECRET_METADATA if domain_profile else
                    ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA if bound_web_profile else
                    ObjectClass.WINRM_COLLECTOR_METADATA if collector_profile else
                    ObjectClass.WEB_SECRET_METADATA
                    if web_profile
                    else ObjectClass.SECRET_METADATA
                )
                or line.target_ref != onboarding_binding.secret_object_ref
                or desired.object_class
                is not (
                    ObjectClass.DOMAIN_SECRET_METADATA if domain_profile else
                    ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA if bound_web_profile else
                    ObjectClass.WINRM_COLLECTOR_METADATA if collector_profile else
                    ObjectClass.WEB_SECRET_METADATA
                    if web_profile
                    else ObjectClass.SECRET_METADATA
                )
                or not desired.desired_exists
                or dict(desired.desired_fields)
                != (
                    {"inherit_permission": True, "non_privileged_account": True,
                     "services_disabled": True, "target_association_matches": True} if domain_profile else
                    {"inherit_permission": True, "session_recording": True,
                     "http_service_enabled": True, "proxy_mode_enabled": True,
                     "target_association_matches": True} if bound_web_profile else
                    {"inherit_permission": True, "privileged_account": True,
                     "owner_only_folder": True, "rdp_service_enabled": True,
                     "recording_enabled": True, "rdp_event_filter_enabled": True,
                     "rdp_event_filter_profile_matches": True,
                     "non_rdp_services_disabled": True,
                     "target_association_matches": True} if collector_profile else
                    {"inherit_permission": True, "session_recording": True}
                    if web_profile
                    else {"inherit_permission": True}
                )
            ):
                raise FixedActionResolutionError(
                    "fixed_action_runner_promotion_shape"
                )
            if (
                material is None
                or material.provider_class
                != MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE.value
                or material.purpose != MaterialPurpose.INITIAL_ONBOARDING.value
                or material.lifecycle != "available"
            ):
                raise FixedActionResolutionError(
                    "fixed_action_runner_promotion_material"
                )

            if discovery_guard is not None:
                from .unix_discovery_onboarding_guard import UnixDiscoveryOnboardingGuard
                if (type(discovery_guard) is not UnixDiscoveryOnboardingGuard
                        or self._product_profile != LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE
                        or type(onboarding_binding) is not SecretOnboardingBinding):
                    raise ValueError
                discovery_guard.check_onboarding_binding(onboarding_binding)
                discovery_guard.observe()
            return self._derive_original_artifacts(
                plan, line_ref, draft=draft, onboarding_binding=onboarding_binding,
                adapter_ref=adapter_ref, collector_profile=collector_profile,
            )
        except OnboardingActionCoordinatorError:
            raise
        except Exception as exc:
            raise OnboardingActionCoordinatorError(_UNAVAILABLE) from exc

    def _derive_original_artifacts(
        self,
        plan: PreparedPlan,
        line_ref: str,
        *,
        draft: SchemeDraft,
        onboarding_binding: SecretOnboardingProductBinding | TargetBoundWebPlanningBinding | DomainSecretPlanningBinding,
        adapter_ref: str,
        collector_profile: bool = False,
    ) -> LabAutoSecretCreateArtifacts:
        """Pure original calculation; callers must validate authority or custody.

        This keeps the original issued_at/expires_at and adds no claim, lease,
        dispatch or current authorization. Historical readers must immediately
        verify the exact existing successful M4 claim before using the result.
        """
        line = next(item for item in plan.lines if item.line_ref == line_ref)
        expires_at = min(plan.expires_at, plan.created_at + LAB_AUTO_SECRET_CREATE_TTL_SECONDS)
        source_context: dict[str, object] = {
            "draft_audience_ref": draft.audience_ref,
            "environment_ref": plan.environment_ref,
            "line_ref": line.line_ref,
            "plan_digest": plan.plan_digest,
            "requester_digest": plan.requester_digest,
            "scope_ref": plan.scope_ref,
        }
        approval_digest = self._mac("approval", source_context)
        product_binding = (onboarding_binding.create_binding
                           if isinstance(onboarding_binding, (TargetBoundWebPlanningBinding, DomainSecretPlanningBinding))
                           else onboarding_binding)
        parameter_context: dict[str, object] = {
            **source_context,
            "folder_path": product_binding.folder_path,
            "secret_name": product_binding.secret_name,
            "template_name": product_binding.template_name,
        }
        if isinstance(onboarding_binding, SecretOnboardingBinding):
            parameter_context.update(
                {
                    "target_address": onboarding_binding.target_ipv4_address,
                    "target_name": onboarding_binding.target_name,
                }
            )
        elif isinstance(onboarding_binding, WebSecretOnboardingBinding):
            parameter_context.update(
                {
                    "session_recording": True,
                    "web_url": onboarding_binding.web_url,
                }
            )
        if self._product_profile in {
            LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE,
            LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE,
            LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE,
        }:
            parameter_context["product_profile"] = self._product_profile
        parameters_digest = (
            domain_secret_binding_digest(onboarding_binding.create_binding, onboarding_binding.secret_object_ref, dependency_refs=(onboarding_binding.folder_object_ref, onboarding_binding.target_object_ref, onboarding_binding.template_object_ref, onboarding_binding.secret_object_ref))
            if isinstance(onboarding_binding, DomainSecretPlanningBinding) else
            target_bound_web_binding_digest(onboarding_binding.create_binding, onboarding_binding.secret_object_ref)
            if isinstance(onboarding_binding, (TargetBoundWebPlanningBinding, DomainSecretPlanningBinding)) else
            winrm_collector_binding_digest(self._collector_binding, onboarding_binding.secret_object_ref)
            if collector_profile and self._collector_binding is not None
            else self._mac("parameters", parameter_context)
        )
        plan_values = {
            "action_id": SECRET_CREATE_ACTION_ID,
            "action_version": SECRET_CREATE_ACTION_VERSION,
            "adapter_ref": adapter_ref,
            "approval_digest": approval_digest,
            "compensation_ref": None,
            "confirmation_digest": plan.confirmation_digest,
            "expected_current_digest": line.expected_current_digest,
            "expected_state_digest": line.expected_state_digest,
            "expires_at": expires_at,
            "idempotency_digest": self._mac("idempotency", source_context),
            "parameters_digest": parameters_digest,
            "plan_ref": plan.plan_ref,
            "requester_digest": plan.requester_digest,
            "revision": plan.revision,
            "summary_digest": plan.summary_digest,
            "target_ref": line.target_ref,
        }
        m4_plan = M4ExecutionPlan(
            plan_ref=plan.plan_ref,
            revision=plan.revision,
            action_id=SECRET_CREATE_ACTION_ID,
            action_version=SECRET_CREATE_ACTION_VERSION,
            adapter_ref=adapter_ref,
            target_ref=line.target_ref,
            requester_digest=plan.requester_digest,
            summary_digest=plan.summary_digest,
            confirmation_digest=plan.confirmation_digest,
            approval_digest=approval_digest,
            parameters_digest=parameters_digest,
            expected_current_digest=line.expected_current_digest,
            expected_state_digest=line.expected_state_digest,
            idempotency_digest=self._mac("idempotency", source_context),
            expires_at=expires_at,
            compensation_ref=None,
            plan_digest=canonical_digest(plan_values),
        )
        authorization_ref = "lab-auto-secret-auth-" + self._mac(
            "authorization-ref",
            {"m4_plan_digest": m4_plan.plan_digest},
        )
        approval_ref = "lab-auto-secret-approval-" + self._mac(
            "approval-ref",
            {"m4_plan_digest": m4_plan.plan_digest},
        )
        approver_digest = self._mac(
            "approver",
            {"authority_ref": self._authority_ref},
        )
        if approver_digest == plan.requester_digest:
            raise ValueError
        authorization_values = {
            "approval_digest": approval_digest,
            "approval_ref": approval_ref,
            "approver_digest": approver_digest,
            "authorization_ref": authorization_ref,
            "confirmation_digest": plan.confirmation_digest,
            "confirmation_ref": plan.confirmation_ref,
            "execution_authorized": True,
            "expires_at": expires_at,
            "issued_at": plan.created_at,
            "one_time": True,
            "plan_digest": m4_plan.plan_digest,
            "plan_ref": m4_plan.plan_ref,
            "requester_digest": m4_plan.requester_digest,
        }
        authorization = M4ExecutionAuthorization(
            authorization_ref=authorization_ref,
            plan_ref=m4_plan.plan_ref,
            plan_digest=m4_plan.plan_digest,
            requester_digest=m4_plan.requester_digest,
            confirmation_ref=plan.confirmation_ref,
            confirmation_digest=plan.confirmation_digest,
            approval_ref=approval_ref,
            approval_digest=approval_digest,
            approver_digest=approver_digest,
            issued_at=plan.created_at,
            expires_at=expires_at,
            one_time=True,
            execution_authorized=True,
            authorization_digest=canonical_digest(authorization_values),
        )
        policy_decision_digest = self._mac(
            "policy",
            {**source_context, "policy_mode": "lab_auto"},
        )
        scope_digest = canonical_digest(plan.scope_ref)
        audience_digest = canonical_digest(draft.audience_ref)
        lease_request = MaterialLeaseRequest(
            action_id=SECRET_CREATE_ACTION_ID,
            action_version=SECRET_CREATE_ACTION_VERSION,
            plan_digest=m4_plan.plan_digest,
            policy_decision_digest=policy_decision_digest,
            authorization_digest=authorization.authorization_digest,
            scope_digest=scope_digest,
            audience_digest=audience_digest,
            provider_class=(
                MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
            ),
            purpose=MaterialPurpose.INITIAL_ONBOARDING,
            requested_at=plan.created_at,
            expires_at=expires_at,
        )
        return LabAutoSecretCreateArtifacts(
            m4_plan,
            authorization,
            lease_request,
            policy_decision_digest,
            scope_digest,
            audience_digest,
        )

    def _mac(self, purpose: str, value: Mapping[str, object]) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return hmac.new(
            self._authority_key,
            b"fortipam-secret-create-lab-auto-v1\x00"
            + purpose.encode("ascii")
            + b"\x00"
            + encoded,
            hashlib.sha256,
        ).hexdigest()


class _FixedSecretCreateM4BindingResolver:
    __slots__ = ("_authorization_ref", "_binding")

    def __init__(
        self,
        authorization_ref: str,
        binding: SecretCreateM4ExecutionBinding,
    ) -> None:
        self._authorization_ref = authorization_ref
        self._binding = binding

    def resolve_execution_binding(
        self,
        authorization_ref: str,
    ) -> SecretCreateM4ExecutionBinding:
        if authorization_ref != self._authorization_ref:
            raise OnboardingActionCoordinatorError(_UNAVAILABLE)
        return self._binding


class FortiPam191LabAutoSecretCreateRunnerFactory:
    """Build one deterministic protected runner after a plan is prepared."""

    __slots__ = (
        "_clock",
        "_credential_binding_id",
        "_credential_bindings_path",
        "_execution_store",
        "_material_binding_ref",
        "_material_state_store",
        "_promoter",
        "_secret_env_path",
        "_transport_config",
        "_owner_credentials",
        "_domain_namespace_settings",
        "_rdp_owner_settings",
        "_web_fixture_capture",
        "_discovery_guard",
    )

    def __init__(
        self,
        *,
        promoter: LabAutoSecretCreatePromoter,
        credential_bindings_path: Path,
        secret_env_path: Path,
        material_binding_ref: str,
        credential_binding_id: str,
        transport_config: SecretMetadataHttpTransportConfig,
        material_state_store: MaterialUseStateStore,
        execution_store: M4ExecutionStateStore,
        owner_credentials: Callable[[], tuple[str, str]] | None = None,
        rdp_owner_settings: RdpOwnerSettings | None = None,
        domain_namespace_settings: DomainSecretNamespaceSettings | None = None,
        web_fixture_capture: WebSecretFixtureCaptureSettings | None = None,
        discovery_guard: UnixDiscoveryOnboardingGuard | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        selected_clock = clock or (lambda: int(time.time()))
        if (
            not isinstance(promoter, LabAutoSecretCreatePromoter)
            or not Path(credential_bindings_path).is_absolute()
            or not Path(secret_env_path).is_absolute()
            or not isinstance(material_binding_ref, str)
            or not material_binding_ref
            or not isinstance(credential_binding_id, str)
            or not credential_binding_id
            or not isinstance(transport_config, SecretMetadataHttpTransportConfig)
            or not callable(getattr(material_state_store, "claim", None))
            or not callable(getattr(material_state_store, "finalize", None))
            or not callable(getattr(execution_store, "claim", None))
            or not callable(getattr(execution_store, "finalize", None))
            or not callable(selected_clock)
        ):
            raise OnboardingActionCoordinatorError(_UNAVAILABLE)
        self._promoter = promoter
        self._credential_bindings_path = Path(credential_bindings_path)
        self._secret_env_path = Path(secret_env_path)
        self._material_binding_ref = material_binding_ref
        self._credential_binding_id = credential_binding_id
        self._transport_config = transport_config
        self._material_state_store = material_state_store
        self._execution_store = execution_store
        if web_fixture_capture is not None:
            from .web_secret_fixture_creation_capture import WebSecretFixtureCaptureSettings
            if (type(web_fixture_capture) is not WebSecretFixtureCaptureSettings
                    or promoter.product_profile != LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or owner_credentials is not None):
                raise OnboardingActionCoordinatorError(_UNAVAILABLE)
        self._web_fixture_capture = web_fixture_capture
        if discovery_guard is not None:
            from .unix_discovery_onboarding_guard import UnixDiscoveryOnboardingGuard
            if (type(discovery_guard) is not UnixDiscoveryOnboardingGuard
                    or promoter.product_profile != LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE):
                raise OnboardingActionCoordinatorError(_UNAVAILABLE)
            discovery_guard.check_transport(transport_config)
        self._discovery_guard = discovery_guard
        self._clock = selected_clock
        if promoter.product_profile == LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE and not callable(owner_credentials):
            raise OnboardingActionCoordinatorError(_UNAVAILABLE)
        if rdp_owner_settings is not None:
            from .owner_rdp_runtime import RdpOwnerSettings
            if (type(rdp_owner_settings) is not RdpOwnerSettings
                or promoter.product_profile != LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE
                or not callable(owner_credentials)):
                raise OnboardingActionCoordinatorError(_UNAVAILABLE)
            rdp_owner_settings.__post_init__()
        self._rdp_owner_settings = rdp_owner_settings
        if owner_credentials is not None and (not callable(owner_credentials) or (
                promoter.collector_binding is None and promoter._domain_binding is None and rdp_owner_settings is None)):
            raise OnboardingActionCoordinatorError(_UNAVAILABLE)
        self._owner_credentials = owner_credentials
        if domain_namespace_settings is not None:
            from .domain_secret_namespace_candidate import DomainSecretNamespaceSettings
            if (type(domain_namespace_settings) is not DomainSecretNamespaceSettings
                or promoter.product_profile != LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE):
                raise OnboardingActionCoordinatorError(_UNAVAILABLE)
        self._domain_namespace_settings = domain_namespace_settings

    def __repr__(self) -> str:
        return "<FortiPam191LabAutoSecretCreateRunnerFactory redacted>"

    __str__ = __repr__

    def execution_preflight_available(self) -> bool:
        """Check local execution dependencies without issuing or acquiring material."""

        try:
            if self._discovery_guard is not None:
                self._discovery_guard.check_ready()
            for store in (self._material_state_store, self._execution_store):
                verify_ready = getattr(store, "verify_ready", None)
                if not callable(verify_ready):
                    return False
                if verify_ready() is not None:
                    return False
            username_name, password_name, _ = _resolve_binding(
                self._credential_bindings_path, self._credential_binding_id
            )
            loader = OwnerOnlyCentralLabSecretCreateEnvFileLoader(
                secret_env_path=self._secret_env_path,
                username_variable_name=username_name,
                password_variable_name=password_name,
            )
            return loader.validate_prebound() is MaterialBindingStatus.AVAILABLE
        except Exception:
            return False

    def bind(
        self,
        plan: PreparedPlan,
        line_ref: str,
        principal: V4PlanningPrincipal,
        *,
        draft: SchemeDraft | None = None,
        onboarding_binding: SecretOnboardingProductBinding | TargetBoundWebPlanningBinding | DomainSecretPlanningBinding | None = None,
    ) -> BoundFixedActionRunner:
        try:
            if draft is None or onboarding_binding is None:
                raise ValueError
            if self._rdp_owner_settings is not None:
                self._rdp_owner_settings.check_binding(onboarding_binding)
            if self._discovery_guard is not None:
                if type(onboarding_binding) is not SecretOnboardingBinding:
                    raise ValueError
                self._discovery_guard.check_onboarding_binding(onboarding_binding)
            now = self._clock()
            artifacts = self._promoter.promote(
                plan,
                line_ref,
                principal,
                draft=draft,
                onboarding_binding=onboarding_binding,
                now_epoch=now,
                discovery_guard=self._discovery_guard,
            )
        except FixedActionResolutionError:
            raise
        except Exception as exc:
            raise FixedActionResolutionError(
                "fixed_action_runner_promotion"
            ) from exc

        try:
            request = artifacts.lease_request
            material_resolver = OwnerOnlyCentralLabSecretCreateBindingResolver(
                credential_bindings_path=self._credential_bindings_path,
                secret_env_path=self._secret_env_path,
                binding_ref=self._material_binding_ref,
                credential_binding_id=self._credential_binding_id,
                request=request,
            )
            material_binding = material_resolver.resolve(
                self._material_binding_ref,
                request,
            )
        except Exception as exc:
            raise FixedActionResolutionError(
                "fixed_action_runner_material_binding"
            ) from exc

        try:
            provider = CentralLabInventorySecretCreateProvider(
                (self._discovery_guard.material_loader(material_resolver, onboarding_binding)
                    if self._discovery_guard is not None and type(onboarding_binding) is SecretOnboardingBinding
                    else material_resolver),
                binding=material_binding,
                request=request,
                clock=self._clock,
            )
            owner_session = None
            metadata_transport = FortiPamSecretMetadataHttpTransport(
                self._transport_config, bound_secret_name=(onboarding_binding.create_binding.secret_name
                    if isinstance(onboarding_binding, (TargetBoundWebPlanningBinding, DomainSecretPlanningBinding)) else onboarding_binding.secret_name))
            if isinstance(onboarding_binding, DomainSecretPlanningBinding):
                from .domain_secret_namespace_candidate import owner_domain_namespace_transport
                if self._owner_credentials is None:
                    raise ValueError
                owner_session = owner_domain_namespace_transport(
                    self._transport_config, onboarding_binding.create_binding,
                    self._owner_credentials, allow_secret_create=True,
                    namespace_settings=self._domain_namespace_settings,
                )
                metadata_transport = owner_session
            elif self._rdp_owner_settings is not None:
                from .owner_rdp_runtime import OwnerRdpSessionMetadataTransport
                if self._owner_credentials is None:
                    raise ValueError
                owner_session = OwnerRdpSessionMetadataTransport(self._transport_config,
                    self._rdp_owner_settings, self._owner_credentials, allow_secret_create=True)
                metadata_transport = owner_session
            elif self._owner_credentials is not None:
                from .owner_collector_runtime import owner_collector_transport
                if self._promoter.collector_binding is None:
                    raise ValueError
                owner_session = owner_collector_transport(self._transport_config,
                    self._promoter.collector_binding, self._owner_credentials, allow_secret_create=True)
                metadata_transport = owner_session
            product_transport = FortiPam191SecretCreateHttpTransport(
                self._transport_config, metadata_transport=metadata_transport,
                connection_factory=owner_session.secret_create_connection if owner_session else None,
                web_ack_capture=self._web_fixture_capture.ack_capture if self._web_fixture_capture else None)
            create_binding = (
                replace(onboarding_binding.create_binding, plan_digest=artifacts.plan.plan_digest)
                if isinstance(onboarding_binding, (TargetBoundWebPlanningBinding, DomainSecretPlanningBinding)) else
                replace(self._promoter.collector_binding, plan_digest=artifacts.plan.plan_digest)
                if self._promoter.collector_binding is not None else
                SecretCreate191TargetBinding(
                    ("fortipam-700-build29-windows-rdp-create-candidate-v1"
                     if self._promoter.product_profile == LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE else
                     "fortipam-700-build29-linux-ssh-sftp-recording-create-candidate-v2"
                     if self._promoter.product_profile == LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE
                     else "fortipam-191-secret-create-private-v1"),
                    ("7.0.0" if self._promoter.product_profile in {LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE, LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE} else "1.9.1"),
                    artifacts.plan.plan_digest,
                    onboarding_binding.folder_path,
                    onboarding_binding.secret_name,
                    onboarding_binding.template_name,
                    onboarding_binding.target_name,
                    onboarding_binding.target_ipv4_address,
                    onboarding_binding.rdp_event_filter_profile_name,
                    rdp_service_enabled=onboarding_binding.target_protocol == "rdp",
                    target_product_build=(29 if self._promoter.product_profile in {LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE, LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE} else None),
                )
                if isinstance(onboarding_binding, SecretOnboardingBinding)
                else SecretCreate191WebBinding(
                    ("fortipam-700-build29-web-secret-create-candidate-v1"
                     if self._promoter.product_profile == LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE
                     else "fortipam-191-web-secret-create-private-v1"),
                    ("7.0.0" if self._promoter.product_profile == LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE else "1.9.1"),
                    artifacts.plan.plan_digest,
                    onboarding_binding.folder_path,
                    onboarding_binding.secret_name,
                    onboarding_binding.template_name,
                    onboarding_binding.web_url,
                    onboarding_binding.session_recording,
                    target_product_build=(29 if self._promoter.product_profile == LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE else None),
                )
            )
            material_runtime = SecretCreateMaterialRuntime(
                provider,
                self._material_state_store,
                FortiPam191SecretCreatePrivateAdapter(
                    create_binding,
                    CentralLabSecretCreate191LeaseTransport(
                        provider,
                        product_transport,
                    ),
                ),
            )
            execution_binding = SecretCreateM4ExecutionBinding(
                artifacts.plan,
                artifacts.authorization,
                material_binding,
                request,
                artifacts.policy_decision_digest,
                artifacts.scope_digest,
                artifacts.audience_digest,
            )
            reader: SecretCreateProjectionReader
            if isinstance(create_binding, SecretCreate700DomainBinding):
                if not isinstance(onboarding_binding, DomainSecretPlanningBinding):
                    raise ValueError
                reader = DomainSecretProjectionReader(create_binding, onboarding_binding.secret_object_ref, metadata_transport, dependency_refs=(onboarding_binding.folder_object_ref, onboarding_binding.target_object_ref, onboarding_binding.template_object_ref, onboarding_binding.secret_object_ref))
            elif isinstance(create_binding, SecretCreate700WebTargetBinding):
                reader = TargetBoundWebProjectionReader(create_binding, onboarding_binding.secret_object_ref, metadata_transport)
            elif isinstance(create_binding, SecretCreate700WinrmBinding):
                reader = WinrmCollectorProjectionReader(create_binding, onboarding_binding.secret_object_ref, metadata_transport)
            else:
                if isinstance(onboarding_binding, (TargetBoundWebPlanningBinding, DomainSecretPlanningBinding)):
                    raise ValueError
                reader = SecretCreate191ProjectionReader(onboarding_binding, create_binding, metadata_transport)
            runtime = ProtectedSecretCreateM4Runtime(
                _FixedSecretCreateM4BindingResolver(
                    artifacts.authorization.authorization_ref,
                    execution_binding,
                ),
                SecretCreateLabAuthorizationVerifier(execution_binding),
                self._execution_store,
                material_runtime,
                reader,
                authenticated_requester_digest=plan.requester_digest,
                clock=self._clock,
            )
            if isinstance(onboarding_binding, DomainSecretPlanningBinding):
                if not isinstance(create_binding, SecretCreate700DomainBinding):
                    raise ValueError
                line = next(item for item in plan.lines if item.line_ref == line_ref)
                _validate_bound_m4_plan(runtime, artifacts.authorization.authorization_ref, plan, line)
                expected = domain_secret_binding_digest(create_binding, onboarding_binding.secret_object_ref, dependency_refs=(onboarding_binding.folder_object_ref, onboarding_binding.target_object_ref, onboarding_binding.template_object_ref, onboarding_binding.secret_object_ref))
                if runtime.inspect_onboarding_binding_digest(artifacts.authorization.authorization_ref) != expected:
                    raise ValueError
                from .owner_collector_runtime import OwnerAuthenticatedCollectorRuntime
                if owner_session is None:
                    raise ValueError
                return _SecretCreateRunner(
                    line_ref, (), artifacts.authorization.authorization_ref, expected,
                    OwnerAuthenticatedCollectorRuntime(runtime, owner_session),
                )
            if isinstance(onboarding_binding, TargetBoundWebPlanningBinding):
                if not isinstance(create_binding, SecretCreate700WebTargetBinding):
                    raise ValueError
                line = next(item for item in plan.lines if item.line_ref == line_ref)
                _validate_bound_m4_plan(runtime, artifacts.authorization.authorization_ref, plan, line)
                expected = target_bound_web_binding_digest(create_binding, onboarding_binding.secret_object_ref)
                if runtime.inspect_onboarding_binding_digest(artifacts.authorization.authorization_ref) != expected:
                    raise ValueError
                return _SecretCreateRunner(line_ref, (), artifacts.authorization.authorization_ref, expected, runtime)
            if isinstance(create_binding, SecretCreate700WinrmBinding):
                line = next(item for item in plan.lines if item.line_ref == line_ref)
                _validate_bound_m4_plan(runtime, artifacts.authorization.authorization_ref, plan, line)
                expected = winrm_collector_binding_digest(create_binding, onboarding_binding.secret_object_ref)
                if runtime.inspect_onboarding_binding_digest(artifacts.authorization.authorization_ref) != expected:
                    raise ValueError
                from .owner_collector_runtime import OwnerAuthenticatedCollectorRuntime
                return _SecretCreateRunner(
                    line_ref, (), artifacts.authorization.authorization_ref, expected,
                    OwnerAuthenticatedCollectorRuntime(runtime, owner_session) if owner_session else runtime,
                )
            bound_runtime: SecretCreateBoundRuntime = runtime
            if self._rdp_owner_settings is not None:
                from .owner_collector_runtime import OwnerAuthenticatedCollectorRuntime
                if owner_session is None:
                    raise ValueError
                bound_runtime = OwnerAuthenticatedCollectorRuntime(runtime, owner_session)
            runner = ExactSecretCreateM4RunnerFactory(
                ProtectedSecretCreateRunnerBinding(
                    plan.plan_digest,
                    line_ref,
                    principal.requester.digest,
                    artifacts.authorization.authorization_ref,
                    bound_runtime,
                )
            ).bind(
                plan,
                line_ref,
                principal,
                draft=draft,
                onboarding_binding=onboarding_binding,
            )
            if self._web_fixture_capture is not None:
                if (type(create_binding) is not SecretCreate191WebBinding
                        or type(onboarding_binding) is not WebSecretOnboardingBinding
                        or type(reader) is not SecretCreate191ProjectionReader
                        or type(runner) is not _SecretCreateRunner
                        or type(self._execution_store) is not PersistentM4ExecutionStateStore):
                    raise ValueError
                return self._web_fixture_capture.bind(config=self._transport_config,
                    transport=product_transport, create_binding=create_binding,
                    execution_binding=execution_binding, execution_store=self._execution_store,
                    onboarding_binding=onboarding_binding, runner=runner, reader=reader)
            return runner
        except FixedActionResolutionError:
            raise
        except Exception as exc:
            raise FixedActionResolutionError(
                "fixed_action_runner_runtime_binding"
            ) from exc


def build_fortipam_191_lab_auto_secret_runner_factory(
    environment: Mapping[str, str] | None = None,
) -> FortiPam191LabAutoSecretCreateRunnerFactory:
    """Build the same-process runner factory from explicit protected settings.

    The builder validates local state domains and the authority key. Credential
    metadata is resolved later while binding a prepared plan, without loading
    credential values. It does not contact FortiPAM or enable Tool registration
    or final execution.
    """

    env = os.environ if environment is None else environment
    try:
        authority_key_path = _absolute_path(env, "AUTHORITY_KEY_FILE")
        credential_bindings_path = _absolute_path(
            env,
            "CREDENTIAL_BINDINGS_FILE",
        )
        secret_env_path = _absolute_path(env, "SECRET_ENV_FILE")
        material_database_path = _absolute_path(env, "MATERIAL_STATE_DB")
        material_key_path = _absolute_path(
            env,
            "MATERIAL_STATE_HMAC_KEY_FILE",
        )
        execution_database_path = _absolute_path(env, "EXECUTION_STATE_DB")
        execution_key_path = _absolute_path(
            env,
            "EXECUTION_STATE_HMAC_KEY_FILE",
        )
        protected_paths = {
            authority_key_path,
            material_database_path,
            material_key_path,
            execution_database_path,
            execution_key_path,
        }
        if len(protected_paths) != 5:
            raise ValueError
        authority_key = _read_owner_only_authority_key(authority_key_path)
        authorized_environment_ref, authorized_scope_ref = (
            load_lab_auto_secret_create_authorized_scope(env)
        )
        selected_profile = env.get(f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE", LAB_AUTO_SECRET_CREATE_DEFAULT_PROFILE)
        collector_binding = (load_winrm_collector_private_binding(_absolute_path(env, "COLLECTOR_BINDING_FILE"))
                             if selected_profile == LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE else None)
        bound_web_binding = (
            load_target_bound_web_planning_binding(_absolute_path(env, "TARGET_WEB_BINDING_FILE"))
            if selected_profile == LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE else None
        )
        domain_binding = (
            load_domain_secret_planning_binding(_absolute_path(env, "DOMAIN_BINDING_FILE"))
            if selected_profile == LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE else None
        )
        if bound_web_binding is not None and (
            bound_web_binding.environment_ref != authorized_environment_ref
            or bound_web_binding.scope_ref != authorized_scope_ref
        ):
            raise ValueError
        promoter = LabAutoSecretCreatePromoter(
            authority_key,
            authorized_environment_ref=authorized_environment_ref,
            authorized_scope_ref=authorized_scope_ref,
            product_profile=selected_profile,
            collector_binding=collector_binding,
            bound_web_binding=bound_web_binding,
            domain_binding=domain_binding,
        )
        from .owner_collector_runtime import owner_login_provider
        from .domain_secret_namespace_candidate import load_domain_secret_namespace_settings
        from .unix_discovery_onboarding_guard import guard_from_environment
        from .owner_rdp_runtime import load_rdp_owner_settings
        transport_config = load_secret_metadata_http_transport_config(env)
        return FortiPam191LabAutoSecretCreateRunnerFactory(
            owner_credentials=owner_login_provider(env),
            rdp_owner_settings=load_rdp_owner_settings(env),
            domain_namespace_settings=load_domain_secret_namespace_settings(env),
            promoter=promoter,
            credential_bindings_path=credential_bindings_path,
            secret_env_path=secret_env_path,
            material_binding_ref=_required(env, "MATERIAL_BINDING_REF"),
            credential_binding_id=_required(env, "CREDENTIAL_BINDING_ID"),
            transport_config=transport_config,
            discovery_guard=guard_from_environment(env, transport_config),
            material_state_store=PersistentMaterialUseStateStore(
                material_database_path,
                material_key_path,
            ),
            execution_store=PersistentM4ExecutionStateStore(
                execution_database_path,
                execution_key_path,
            ),
        )
    except OnboardingActionCoordinatorError:
        raise
    except Exception as exc:
        raise OnboardingActionCoordinatorError(_UNAVAILABLE) from exc


def load_lab_auto_secret_create_authorized_scope(
    environment: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Load the exact Secret onboarding environment and scope binding."""

    env = os.environ if environment is None else environment
    try:
        return (
            require_ref(
                _required(env, "AUTHORIZED_ENVIRONMENT_REF"),
                "authorized_secret_environment_ref",
            ),
            require_ref(
                _required(env, "AUTHORIZED_SCOPE_REF"),
                "authorized_secret_scope_ref",
            ),
        )
    except (TypeError, ValueError) as exc:
        raise OnboardingActionCoordinatorError(_UNAVAILABLE) from exc


def _required(environment: Mapping[str, str], suffix: str) -> str:
    value = environment.get(f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}{suffix}")
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError
    return value


def _absolute_path(environment: Mapping[str, str], suffix: str) -> Path:
    path = Path(_required(environment, suffix))
    if not path.is_absolute():
        raise ValueError
    return path


def _read_owner_only_authority_key(path: Path) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(path, flags)
    content = bytearray()
    try:
        info = os.fstat(descriptor)
        if not _valid_authority_key_info(info):
            raise ValueError
        while len(content) <= _MAX_AUTHORITY_KEY_BYTES:
            chunk = os.read(
                descriptor,
                min(8192, _MAX_AUTHORITY_KEY_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(content) != info.st_size
            or len(content) > _MAX_AUTHORITY_KEY_BYTES
            or not _valid_authority_key_info(after)
            or info.st_dev != after.st_dev
            or info.st_ino != after.st_ino
            or info.st_size != after.st_size
            or info.st_mtime_ns != after.st_mtime_ns
        ):
            raise ValueError
        return bytes(content)
    finally:
        content[:] = b"\x00" * len(content)
        content.clear()
        os.close(descriptor)


def _valid_authority_key_info(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and 32 <= info.st_size <= _MAX_AUTHORITY_KEY_BYTES
    )


__all__ = [
    "FortiPam191LabAutoSecretCreateRunnerFactory",
    "LAB_AUTO_SECRET_CREATE_ADAPTER_REF",
    "LAB_AUTO_SECRET_CREATE_AUTHORITY_REF",
    "LAB_AUTO_SECRET_CREATE_ENV_PREFIX",
    "LAB_AUTO_SECRET_CREATE_TTL_SECONDS",
    "LabAutoSecretCreateArtifacts",
    "LabAutoSecretCreatePromoter",
    "build_fortipam_191_lab_auto_secret_runner_factory",
    "load_lab_auto_secret_create_authorized_scope",
]
