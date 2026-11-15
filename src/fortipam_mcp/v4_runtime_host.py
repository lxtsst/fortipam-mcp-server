"""Synthetic, non-device V4 plan host for human-confirmation acceptance.

This exact opt-in host exists only to exercise the V4 planning and browser
confirmation control plane. Its projection source is synthetic, it has no
FortiPAM client or product adapter, and every prepared plan is non-executable.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, cast
import secrets
import time

from v4_planning import (
    ApprovalReceiptAuthenticationAuthority,
    ApprovalReceiptAuthenticator,
    ApproverAuthorityError,
    AuthenticatedRequester,
    AuthoritativeProjection,
    DesiredObject,
    M2PlanningEngine,
    M3ApprovalGate,
    M3PlanOnlyWorkflowService,
    M3PlanPolicy,
    M4ExecutionStateStore,
    MonotonicCheckpointError,
    MonotonicPlanningCheckpoint,
    ObjectClass,
    PlanningContractError,
    PersistentApproverAuthorizationAuthority,
    PersistentPlanningCheckpointAuthority,
    PersistentReferenceAuthority,
    PersistentSchemeDraftAuthority,
    ProjectionContract,
    ReferenceAuthorityError,
    ReferenceAuthorizer,
    SchemeDraft,
    SchemeDraftAuthorityError,
    SchemeId,
    VerifiedReferenceDecision,
    canonical_digest,
)
from v4_planning.models import require_ref
from v4_planning.mcp_facade import PlanningProjectionProvider
from v4_planning.persistence import (
    PersistentPlanningStoreError,
    PersistentProtectedPlanningStore,
)

from .local_oauth import LocalOAuthProvider
from .onboarding_action_coordinator import (
    FixedActionSequenceResolver,
    OnboardingActionCoordinator,
)
from .onboarding_execution_mcp_action import (
    ProtectedAccessDomainOnboardingMcpAction,
    ProtectedSecretOnboardingMcpAction,
)
from .planning_checkpoint_sidecar import (
    UnixPlanningCheckpointClient,
    UnixPlanningCheckpointClientSettings,
)
from .reference_authority_sidecar import (
    UnixReferenceAuthorityClient,
    UnixReferenceAuthorityClientSettings,
)
from .approver_authority_sidecar import UnixApproverAuthorizationClient
from .approval_receipt_sidecar import UnixApprovalReceiptAuthenticator
from .approval_and_observe_projection_source import (
    ApprovalAndObserveBinding,
    ApprovalAndObserveBindingResolver,
    ApprovalAndObserveProjectionSourceError,
    ApprovalProfileReadTransport,
    FortiPamApprovalAndObserveProjectionSource,
    SecretApprovalReadTransport,
    approval_and_observe_projection_contract,
)
from .approval_and_observe_execution_mcp_action import (
    ProtectedApprovalAndObserveMcpAction,
)
from .secret_approval_build29_projection_source import (
    FortiPamSecretApprovalBuild29ProjectionSource,
    SecretApprovalBuild29ProfileReadTransport,
    SecretApprovalBuild29ProjectionSourceError,
    secret_approval_build29_projection_contract,
)
from .access_domain_projection_source import (
    AccessDomainBindingResolver,
    AccessDomainProjectionSourceError,
    FolderCollectionReadTransport,
    FortiPamAccessDomainProjectionSource,
    access_domain_projection_contract,
)
from .access_domain_action_sequence import (
    AccessDomainFixedActionSequenceResolver,
    FixedChildFolderAction,
    FixedFolderAclAction,
    FixedFolderGroupAclAction,
)
from .linux_onboarding_action_sequence import (
    ExistingDomainLinuxOnboardingFixedActionSequenceResolver,
    SecretOrExistingDomainLinuxOnboardingResolver,
)
from .scheme_draft_authority_sidecar import (
    UnixSchemeDraftAuthorityClient,
    UnixSchemeDraftAuthorityClientSettings,
)
from .secret_create_readiness_sidecar import (
    SecretCreateReadinessSidecarError,
    UnixSecretCreateReadinessProxyClient,
    UnixSecretCreateReadinessProxyClientSettings,
)
from .secret_create_191_private_adapter import SecretCreate700WinrmBinding
from .winrm_collector_projection_reader import (
    WinrmCollectorPlanningSource, WinrmCollectorReadTransport, winrm_collector_projection_contract,
)
from .domain_secret_projection_reader import (
    DomainSecretPlanningBinding, DomainSecretPlanningSource, DomainSecretReadTransport,
)
from .target_bound_web_projection_reader import (
    TargetBoundWebPlanningBinding, TargetBoundWebPlanningSource, TargetBoundWebReadTransport,
)
from .ad_discovery_projection_source import (
    AdDiscoveryPlanningBinding, AdDiscoveryPlanningSource, ad_discovery_projection_contract,
)
from .owner_session_metadata import OwnerSessionMetadataTransport
from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport

if TYPE_CHECKING:
    from .ad_discovery_lab_auto_runtime import AdDiscoveryLabAutoRunnerFactory
from .secret_onboarding_projection_source import (
    FolderPolicyReadTransport,
    FortiPamSecretOnboardingProjectionSource,
    LauncherReadTransport,
    RecordingPolicyReadTransport,
    RdpEventFilterReadTransport,
    SecretMetadataReadTransport,
    SecretOnboardingBinding,
    SecretOnboardingBindingResolver,
    SecretOnboardingProjectionSourceError,
    SecretPolicyClipboardReadTransport,
    TargetReadTransport,
    secret_onboarding_projection_contract,
)
from .secret_onboarding_action_sequence import (
    FixedTargetCreateAction,
    SecretCreateM4RunnerFactory,
    SecretOnboardingFixedActionSequenceResolver,
)
from .secret_approval_action_sequence import (
    SecretApprovalFixedActionSequenceResolver,
    SecretApprovalM4RunnerFactory,
)
from .secret_approval_m4_authorization import SecretApprovalPlanningChainReader
from .secret_approval_m4_composition import (
    assemble_secret_approval_m4_runner_factory,
)
from .secret_approval_m4_runtime import SecretApprovalWriteTransport
from .secret_session_controls_m4_composition import (
    assemble_secret_session_controls_m4_runner_factory,
)
from .secret_session_controls_lab_auto_runtime import (
    LabAutoSecretSessionControlsPromoter,
    LabAutoSecretSessionControlsRunnerFactory,
)
from .secret_session_controls_m4_runtime import (
    SecretSessionControlsBinding,
    SecretSessionControlsReadTransport,
    SecretSessionControlsWriteTransport,
)
from .v4_confirmation_http import (
    LocalIntentConfirmationService,
    V4ConfirmationHttpError,
    V4ConfirmationSettings,
)
from .v4_plan_runtime import (
    OAuthBoundV4PlanServices,
    TrustedSchemeDraftProvider,
    V4PlanningPrincipal,
)


V4_SYNTHETIC_HOST_MODE_ENV = "FORTIPAM_MCP_V4_PLAN_HOST_MODE"
V4_PLANNING_DATABASE_ENV = "FORTIPAM_MCP_V4_PLAN_STORE_DB"
V4_PLANNING_HMAC_KEY_FILE_ENV = "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE"
V4_REFERENCE_DATABASE_ENV = "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_DB"
V4_REFERENCE_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE"
)
V4_REFERENCE_SIDECAR_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_PLAN_REFERENCE_SIDECAR_SOCKET"
)
V4_REFERENCE_SIDECAR_AUTHORITY_REF_ENV = (
    "FORTIPAM_MCP_V4_PLAN_REFERENCE_SIDECAR_AUTHORITY_REF"
)
V4_SCHEME_DRAFT_DATABASE_ENV = "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_DB"
V4_SCHEME_DRAFT_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE"
)
V4_SCHEME_DRAFT_SIDECAR_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_SIDECAR_SOCKET"
)
V4_SCHEME_DRAFT_SIDECAR_AUTHORITY_REF_ENV = (
    "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_SIDECAR_AUTHORITY_REF"
)
V4_CHECKPOINT_DATABASE_ENV = "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_AUTHORITY_DB"
V4_CHECKPOINT_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_AUTHORITY_HMAC_KEY_FILE"
)
V4_CHECKPOINT_STORE_REF_ENV = "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_STORE_REF"
V4_CHECKPOINT_SIDECAR_SOCKET_ENV = "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_SIDECAR_SOCKET"
V4_CHECKPOINT_SIDECAR_AUTHORITY_REF_ENV = (
    "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_SIDECAR_AUTHORITY_REF"
)
V4_SECRET_CREATE_READINESS_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_PLAN_SECRET_CREATE_READINESS_SOCKET"
)
V4_ACCESS_DOMAIN_BINDING_FILE_ENV = (
    "FORTIPAM_MCP_V4_PLAN_ACCESS_DOMAIN_BINDING_FILE"
)
V4_SECRET_ONBOARDING_BINDING_FILE_ENV = (
    "FORTIPAM_MCP_V4_PLAN_SECRET_ONBOARDING_BINDING_FILE"
)
V4_APPROVAL_AND_OBSERVE_BINDING_FILE_ENV = (
    "FORTIPAM_MCP_V4_PLAN_APPROVAL_AND_OBSERVE_BINDING_FILE"
)
V4_SECRET_REQUEST_OBSERVATION_BINDING_FILE_ENV = (
    "FORTIPAM_MCP_V4_PLAN_SECRET_REQUEST_OBSERVATION_BINDING_FILE"
)
V4_PERSISTENT_REFERENCE_AUTHORITY_REF = "v4-persistent-reference-authority"
V4_PERSISTENT_SCHEME_DRAFT_AUTHORITY_REF = "v4-persistent-scheme-draft-authority"
V4_PERSISTENT_PLANNING_CHECKPOINT_AUTHORITY_REF = (
    "v4-persistent-planning-checkpoint-authority"
)
V4_SYNTHETIC_SCHEME_REF = "v4-synthetic-access-domain-demo"


class V4RuntimeHostError(RuntimeError):
    """Stable failure for an incomplete V4 synthetic host configuration."""


@dataclass(frozen=True, slots=True)
class V4PersistentReferenceAuthoritySettings:
    database_path: Path
    hmac_key_path: Path


@dataclass(frozen=True, slots=True)
class V4UnixReferenceAuthoritySettings:
    socket_path: Path
    authority_ref: str


@dataclass(frozen=True, slots=True)
class V4PersistentSchemeDraftAuthoritySettings:
    database_path: Path
    hmac_key_path: Path


@dataclass(frozen=True, slots=True)
class V4UnixSchemeDraftAuthoritySettings:
    socket_path: Path
    authority_ref: str


@dataclass(frozen=True, slots=True)
class V4PersistentPlanningCheckpointSettings:
    database_path: Path
    hmac_key_path: Path
    store_ref: str


@dataclass(frozen=True, slots=True)
class V4UnixPlanningCheckpointSettings:
    socket_path: Path
    authority_ref: str
    store_ref: str


@dataclass(frozen=True, slots=True)
class V4UnixSecretCreateRuntimeSettings:
    readiness_socket_path: Path


@dataclass(frozen=True, slots=True)
class V4SyntheticHostSettings:
    planning_database_path: Path
    planning_hmac_key_path: Path
    reference_authority: V4PersistentReferenceAuthoritySettings | None = None
    scheme_draft_authority: V4PersistentSchemeDraftAuthoritySettings | None = None
    planning_checkpoint: V4PersistentPlanningCheckpointSettings | None = None
    planning_checkpoint_sidecar: V4UnixPlanningCheckpointSettings | None = None
    scheme_draft_sidecar: V4UnixSchemeDraftAuthoritySettings | None = None
    reference_sidecar: V4UnixReferenceAuthoritySettings | None = None
    secret_create_runtime: V4UnixSecretCreateRuntimeSettings | None = None
    host_mode: str = "synthetic"
    access_domain_binding_path: Path | None = None
    secret_onboarding_binding_path: Path | None = None
    approval_and_observe_binding_path: Path | None = None
    secret_request_observation_binding_path: Path | None = None


@dataclass(frozen=True, slots=True)
class V4PlanHostComponents:
    plan_services: OAuthBoundV4PlanServices
    confirmation_service: LocalIntentConfirmationService
    scheme_draft_authority: PersistentSchemeDraftAuthority | None = None
    scheme_draft_client: UnixSchemeDraftAuthorityClient | None = None
    planning_checkpoint_authority: PersistentPlanningCheckpointAuthority | None = None
    planning_checkpoint_client: UnixPlanningCheckpointClient | None = None
    reference_authority: PersistentReferenceAuthority | None = None
    reference_client: UnixReferenceAuthorityClient | None = None
    access_domain_projection_source: FortiPamAccessDomainProjectionSource | None = None
    approval_and_observe_projection_source: (
        FortiPamApprovalAndObserveProjectionSource | FortiPamSecretApprovalBuild29ProjectionSource | None
    ) = None
    secret_onboarding_projection_source: (
        FortiPamSecretOnboardingProjectionSource | WinrmCollectorPlanningSource | TargetBoundWebPlanningSource | DomainSecretPlanningSource | None
    ) = None
    ad_discovery_projection_source: AdDiscoveryPlanningSource | None = None
    _secret_approval_planning_reader: (
        SecretApprovalPlanningChainReader | None
    ) = None
    _secret_approval_receipt_authenticator: (
        ApprovalReceiptAuthenticationAuthority | None
    ) = None
    _secret_approval_approver_authority_ref: str | None = None
    _clock: Callable[[], int] | None = None

    def bind_onboarding_action_coordinator(
        self,
        resolver: FixedActionSequenceResolver,
    ) -> OnboardingActionCoordinator:
        """Bind the internal Scheme comparisons to protected fixed actions.

        This does not register an MCP operation or enable an action resolver.
        The caller must supply the separately protected execution binding.
        """

        return OnboardingActionCoordinator(self.plan_services, resolver)

    def bind_ad_discovery_action_coordinator(
        self, runner_factory: AdDiscoveryLabAutoRunnerFactory,
    ) -> OnboardingActionCoordinator:
        """Bind the separate, explicitly gated Source runner to host comparisons."""
        from .ad_discovery_action_sequence import AdDiscoveryFixedActionSequenceResolver

        if self.ad_discovery_projection_source is None:
            raise V4RuntimeHostError("AD Discovery fixed planning source is unavailable.")
        return self.bind_onboarding_action_coordinator(
            AdDiscoveryFixedActionSequenceResolver(
                self.plan_services, self.ad_discovery_projection_source, runner_factory,
            ),
        )

    def bind_access_domain_action_coordinator(
        self,
        acl_action: FixedFolderAclAction,
        folder_action: FixedChildFolderAction | None = None,
        group_acl_action: FixedFolderGroupAclAction | None = None,
    ) -> OnboardingActionCoordinator:
        """Bind direct ACL grants and an optional inherited Folder create."""

        if self.access_domain_projection_source is None:
            raise V4RuntimeHostError(
                "V4 Access Domain fixed action source is unavailable."
            )
        resolver = AccessDomainFixedActionSequenceResolver(
            self.plan_services,
            self.access_domain_projection_source,
            acl_action,
            folder_action,
            group_acl_action,
        )
        return self.bind_onboarding_action_coordinator(resolver)

    def bind_secret_onboarding_action_coordinator(
        self,
        runner_factory: SecretCreateM4RunnerFactory,
        target_action: FixedTargetCreateAction | None = None,
    ) -> OnboardingActionCoordinator:
        """Bind Secret create and an optional protected Target dependency."""

        if self.secret_onboarding_projection_source is None:
            raise V4RuntimeHostError(
                "V4 Secret onboarding fixed action source is unavailable."
            )
        resolver = SecretOnboardingFixedActionSequenceResolver(
            self.plan_services,
            self.secret_onboarding_projection_source,
            runner_factory,
            target_action,
        )
        return self.bind_onboarding_action_coordinator(resolver)

    def bind_lab_auto_secret_session_controls_execution_mcp_action(
        self,
        *,
        session_controls_binding: SecretSessionControlsBinding | None = None,
        authority_key: bytes,
        read_transport: SecretSessionControlsReadTransport,
        write_transport: SecretSessionControlsWriteTransport,
        rdp_event_filter_transport: RdpEventFilterReadTransport,
        execution_store: M4ExecutionStateStore,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
        execution_enabled: bool = False,
    ) -> ProtectedSecretOnboardingMcpAction:
        """Bind the exact confirmed BP006 update under the named lab policy."""
        planning = self._secret_approval_planning_reader
        source = self.secret_onboarding_projection_source
        if planning is None or source is None:
            raise V4RuntimeHostError("V4 lab session-controls composition is unavailable.")
        try:
            promoter = LabAutoSecretSessionControlsPromoter(
                authority_key,
                authorized_environment_ref=authorized_environment_ref,
                authorized_scope_ref=authorized_scope_ref,
            )
            factory = LabAutoSecretSessionControlsRunnerFactory(
                planning=planning, promoter=promoter,
                session_controls_binding=session_controls_binding,
                read_transport=read_transport, write_transport=write_transport,
                rdp_event_filter_transport=rdp_event_filter_transport,
                execution_store=execution_store,
                clock=self._clock,
            )
            resolver = SecretOnboardingFixedActionSequenceResolver(
                self.plan_services, source, factory,
                session_controls_runner_factory=factory,
            )
            return ProtectedSecretOnboardingMcpAction(
                self.plan_services,
                self.bind_onboarding_action_coordinator(resolver),
                authorized_environment_ref=authorized_environment_ref,
                authorized_scope_ref=authorized_scope_ref,
                execution_enabled=execution_enabled,
                policy_mode="lab_auto",
            )
        except Exception as exc:
            raise V4RuntimeHostError("V4 lab session-controls composition is unavailable.") from exc

    def bind_trusted_secret_session_controls_execution_mcp_action(
        self,
        *,
        source_plan_ref: str,
        scheme_draft_ref: str,
        approval_receipt_ref: str,
        authorization_ref: str,
        principal: V4PlanningPrincipal,
        session_controls_binding: SecretSessionControlsBinding,
        read_transport: SecretSessionControlsReadTransport,
        write_transport: SecretSessionControlsWriteTransport,
        rdp_event_filter_transport: RdpEventFilterReadTransport,
        execution_store: M4ExecutionStateStore,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
        execution_enabled: bool = False,
    ) -> ProtectedSecretOnboardingMcpAction:
        """Compose a claimed BP006 control update with the existing MCP action.

        Registration and execution stay opt-in. The create factory is never
        used for this exact single-update plan.
        """
        planning = self._secret_approval_planning_reader
        authenticator = self._secret_approval_receipt_authenticator
        authority = self._secret_approval_approver_authority_ref
        source = self.secret_onboarding_projection_source
        if planning is None or authenticator is None or authority is None or source is None:
            raise V4RuntimeHostError("V4 trusted session-controls composition is unavailable.")
        try:
            plan, draft = self.plan_services.resolve_execution_context(
                source_plan_ref, scheme_draft_ref, principal,
            )
            binding = source.resolve_private_binding(draft, principal.requester)
            if not isinstance(binding, SecretOnboardingBinding):
                raise ValueError("invalid binding")
            factory = assemble_secret_session_controls_m4_runner_factory(
                planning=planning,
                receipt_authenticator=authenticator,
                onboarding_binding=binding,
                session_controls_binding=session_controls_binding,
                source_plan_ref=plan.plan_ref,
                approval_receipt_ref=approval_receipt_ref,
                approver_authority_ref=authority,
                authorization_ref=authorization_ref,
                read_transport=read_transport,
                write_transport=write_transport,
                rdp_event_filter_transport=rdp_event_filter_transport,
                execution_store=execution_store,
                authenticated_requester_digest=principal.requester.digest,
                clock=self._clock,
            )
            resolver = SecretOnboardingFixedActionSequenceResolver(
                self.plan_services, source, factory,
                session_controls_runner_factory=factory,
            )
            return ProtectedSecretOnboardingMcpAction(
                self.plan_services,
                self.bind_onboarding_action_coordinator(resolver),
                authorized_environment_ref=authorized_environment_ref,
                authorized_scope_ref=authorized_scope_ref,
                execution_enabled=execution_enabled,
                policy_mode="independent_approval",
            )
        except Exception as exc:
            raise V4RuntimeHostError("V4 trusted session-controls composition is unavailable.") from exc

    def bind_existing_domain_linux_onboarding_action_coordinator(
        self,
        acl_action: FixedFolderAclAction,
        runner_factory: SecretCreateM4RunnerFactory,
        *,
        folder_action: FixedChildFolderAction | None = None,
        group_acl_action: FixedFolderGroupAclAction | None = None,
        target_action: FixedTargetCreateAction | None = None,
    ) -> OnboardingActionCoordinator:
        """Bind one BP005 parent plan across a Folder and Secret."""

        if (
            self.access_domain_projection_source is None
            or self.secret_onboarding_projection_source is None
        ):
            raise V4RuntimeHostError(
                "V4 combined Linux onboarding sources are unavailable."
            )
        access = AccessDomainFixedActionSequenceResolver(
            self.plan_services,
            self.access_domain_projection_source,
            acl_action,
            folder_action,
            group_acl_action=group_acl_action,
        )
        secret = SecretOnboardingFixedActionSequenceResolver(
            self.plan_services,
            self.secret_onboarding_projection_source,
            runner_factory,
            target_action,
        )
        return self.bind_onboarding_action_coordinator(
            ExistingDomainLinuxOnboardingFixedActionSequenceResolver(
                self.plan_services,
                access,
                secret,
            )
        )

    def bind_existing_domain_linux_onboarding_execution_mcp_action(
        self,
        acl_action: FixedFolderAclAction,
        runner_factory: SecretCreateM4RunnerFactory,
        *,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
        folder_action: FixedChildFolderAction | None = None,
        group_acl_action: FixedFolderGroupAclAction | None = None,
        target_action: FixedTargetCreateAction | None = None,
        execution_enabled: bool = False,
    ) -> ProtectedSecretOnboardingMcpAction:
        """Assemble one default-off, source-bound combined BP005 action."""

        coordinator = (
            self.bind_existing_domain_linux_onboarding_action_coordinator(
                acl_action,
                runner_factory,
                folder_action=folder_action,
                group_acl_action=group_acl_action,
                target_action=target_action,
            )
        )
        return ProtectedSecretOnboardingMcpAction(
            self.plan_services,
            coordinator,
            authorized_environment_ref=authorized_environment_ref,
            authorized_scope_ref=authorized_scope_ref,
            execution_enabled=execution_enabled,
        )

    def bind_secret_or_existing_domain_linux_action_coordinator(
        self,
        acl_action: FixedFolderAclAction,
        runner_factory: SecretCreateM4RunnerFactory,
        *,
        folder_action: FixedChildFolderAction | None = None,
        group_acl_action: FixedFolderGroupAclAction | None = None,
        target_action: FixedTargetCreateAction | None = None,
    ) -> OnboardingActionCoordinator:
        """Route the existing Secret Tool without caller-selected mode input."""

        if (
            self.access_domain_projection_source is None
            or self.secret_onboarding_projection_source is None
        ):
            raise V4RuntimeHostError(
                "V4 Linux onboarding fixed action sources are unavailable."
            )
        access = AccessDomainFixedActionSequenceResolver(
            self.plan_services,
            self.access_domain_projection_source,
            acl_action,
            folder_action,
            group_acl_action=group_acl_action,
        )
        secret = SecretOnboardingFixedActionSequenceResolver(
            self.plan_services,
            self.secret_onboarding_projection_source,
            runner_factory,
            target_action,
        )
        combined = ExistingDomainLinuxOnboardingFixedActionSequenceResolver(
            self.plan_services,
            access,
            secret,
        )
        return self.bind_onboarding_action_coordinator(
            SecretOrExistingDomainLinuxOnboardingResolver(
                self.plan_services,
                secret,
                combined,
            )
        )

    def bind_approval_and_observe_action_coordinator(
        self,
        runner_factory: SecretApprovalM4RunnerFactory,
    ) -> OnboardingActionCoordinator:
        """Bind the exact BP008 line to an independently authorized M4 runner."""

        source = self.approval_and_observe_projection_source
        if source is None:
            raise V4RuntimeHostError(
                "V4 approval fixed action source is unavailable."
            )
        resolver = SecretApprovalFixedActionSequenceResolver(
            self.plan_services,
            source,
            runner_factory,
        )
        return self.bind_onboarding_action_coordinator(resolver)

    def bind_approval_and_observe_execution_mcp_action(
        self,
        runner_factory: SecretApprovalM4RunnerFactory,
        *,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
        execution_enabled: bool = False,
    ) -> ProtectedApprovalAndObserveMcpAction:
        """Assemble one default-off BP008 execution action without registering it."""

        coordinator = self.bind_approval_and_observe_action_coordinator(
            runner_factory,
        )
        return ProtectedApprovalAndObserveMcpAction(
            self.plan_services,
            coordinator,
            authorized_environment_ref=authorized_environment_ref,
            authorized_scope_ref=authorized_scope_ref,
            execution_enabled=execution_enabled,
        )

    def bind_trusted_approval_and_observe_execution_mcp_action(
        self,
        *,
        source_plan_ref: str,
        scheme_draft_ref: str,
        approval_receipt_ref: str,
        authorization_ref: str,
        principal: V4PlanningPrincipal,
        read_transport: SecretApprovalReadTransport,
        write_transport: SecretApprovalWriteTransport,
        execution_store: M4ExecutionStateStore,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
        execution_enabled: bool = False,
    ) -> ProtectedApprovalAndObserveMcpAction:
        """Bind the claimed BP008 chain without a second confirmation.

        This direct trusted-composition helper does not register the returned
        action and keeps its execution Gate false unless the caller explicitly
        supplies an already-authorized activation.
        """

        planning = self._secret_approval_planning_reader
        authenticator = self._secret_approval_receipt_authenticator
        approver_authority_ref = self._secret_approval_approver_authority_ref
        source = self.approval_and_observe_projection_source
        if (
            planning is None
            or authenticator is None
            or approver_authority_ref is None
            or source is None
        ):
            raise V4RuntimeHostError(
                "V4 trusted approval execution composition is unavailable."
            )
        try:
            plan, draft = self.plan_services.resolve_execution_context(
                source_plan_ref,
                scheme_draft_ref,
                principal,
            )
            approval_binding: ApprovalAndObserveBinding = (
                source.resolve_private_binding(draft, principal.requester)
            )
            runner_factory = assemble_secret_approval_m4_runner_factory(
                planning=planning,
                receipt_authenticator=authenticator,
                approval_binding=approval_binding,
                source_plan_ref=plan.plan_ref,
                approval_receipt_ref=approval_receipt_ref,
                approver_authority_ref=approver_authority_ref,
                authorization_ref=authorization_ref,
                read_transport=read_transport,
                write_transport=write_transport,
                execution_store=execution_store,
                authenticated_requester_digest=principal.requester.digest,
                clock=self._clock,
            )
        except Exception as exc:
            raise V4RuntimeHostError(
                "V4 trusted approval execution composition is unavailable."
            ) from exc
        return self.bind_approval_and_observe_execution_mcp_action(
            runner_factory,
            authorized_environment_ref=authorized_environment_ref,
            authorized_scope_ref=authorized_scope_ref,
            execution_enabled=execution_enabled,
        )

    def bind_onboarding_execution_mcp_actions(
        self,
        acl_action: FixedFolderAclAction,
        runner_factory: SecretCreateM4RunnerFactory,
        *,
        folder_action: FixedChildFolderAction | None = None,
        group_acl_action: FixedFolderGroupAclAction | None = None,
        target_action: FixedTargetCreateAction | None = None,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
        authorized_secret_environment_ref: str | None = None,
        authorized_secret_scope_ref: str | None = None,
        execution_enabled: bool = False,
    ) -> tuple[
        ProtectedAccessDomainOnboardingMcpAction,
        ProtectedSecretOnboardingMcpAction,
    ]:
        """Assemble the two exact source-bound onboarding MCP actions.

        This is an in-process composition helper only.  It does not load
        configuration, register Tools, or change either execution Gate.
        """

        access_coordinator = self.bind_access_domain_action_coordinator(
            acl_action,
            folder_action,
            group_acl_action,
        )
        secret_coordinator = self.bind_secret_or_existing_domain_linux_action_coordinator(
            acl_action,
            runner_factory,
            folder_action=folder_action,
            group_acl_action=group_acl_action,
            target_action=target_action,
        )
        return (
            ProtectedAccessDomainOnboardingMcpAction(
                self.plan_services,
                access_coordinator,
                authorized_environment_ref=authorized_environment_ref,
                authorized_scope_ref=authorized_scope_ref,
                execution_enabled=execution_enabled,
            ),
            ProtectedSecretOnboardingMcpAction(
                self.plan_services,
                secret_coordinator,
                authorized_environment_ref=(
                    authorized_secret_environment_ref
                    or authorized_environment_ref
                ),
                authorized_scope_ref=(
                    authorized_secret_scope_ref or authorized_scope_ref
                ),
                execution_enabled=execution_enabled,
            ),
        )


class _Issuer:
    def issue(self, purpose: str) -> str:
        return f"{purpose}-ref-{secrets.token_hex(16)}"


class _SyntheticReferenceAuthorizer:
    authority_ref = "v4-synthetic-reference-authority"

    def __init__(self, draft: SchemeDraft) -> None:
        self._grants = set(_synthetic_reference_bindings(draft))

    def authorize(
        self,
        reference: str,
        *,
        reference_kind: str,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
        now_epoch: int,
    ) -> VerifiedReferenceDecision:
        return VerifiedReferenceDecision(
            reference_digest=canonical_digest(reference),
            reference_kind=reference_kind,
            authority_ref=self.authority_ref,
            requester_digest=requester_digest,
            environment_digest=canonical_digest(environment_ref),
            scope_digest=canonical_digest(scope_ref),
            authorized=(reference, reference_kind) in self._grants,
            checked_at=now_epoch,
            expires_at=now_epoch + 300,
        )


class _SyntheticDraftProvider:
    def __init__(self, draft: SchemeDraft) -> None:
        self._draft = draft

    def resolve(
        self,
        scheme_draft_ref: str,
        requester: AuthenticatedRequester,
    ) -> SchemeDraft:
        if (
            scheme_draft_ref != V4_SYNTHETIC_SCHEME_REF
            or requester.principal_class != "operator"
        ):
            raise V4RuntimeHostError("Synthetic Scheme draft is unavailable.")
        return self._draft

    def public_refs(self) -> tuple[str, ...]:
        return (V4_SYNTHETIC_SCHEME_REF,)


class _SyntheticProjectionProvider:
    mode = "fake_only"

    def __init__(self, engine: M2PlanningEngine) -> None:
        self._engine = engine

    def project(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> Sequence[AuthoritativeProjection]:
        del requester
        return tuple(
            AuthoritativeProjection.from_mapping(
                contract=self._engine.projection_contract(
                    draft.scheme_id,
                    desired.object_class,
                ),
                object_ref=desired.object_ref,
                observed_at=now_epoch,
                fresh_until=now_epoch + 300,
                fields={"exists": False},
            )
            for desired in draft.desired_objects
        )


class _OnboardingProjectionProvider:
    """Route onboarding Schemes and the exact combined BP005 projection."""

    mode = "source_backed"

    def __init__(
        self,
        access_domain: FortiPamAccessDomainProjectionSource,
        secret_onboarding: FortiPamSecretOnboardingProjectionSource,
    ) -> None:
        self._access_domain = access_domain
        self._secret_onboarding = secret_onboarding

    @property
    def contract_registered(self) -> bool:
        """Require both routed projection contracts to be registered."""

        return all(
            getattr(provider, "contract_registered", False) is True
            for provider in (self._access_domain, self._secret_onboarding)
        )

    def project(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> Sequence[AuthoritativeProjection]:
        if draft.scheme_id is SchemeId.ACCESS_DOMAIN:
            return self._access_domain.project(
                draft,
                requester,
                now_epoch=now_epoch,
            )
        if draft.scheme_id is SchemeId.SECRET_ONBOARDING:
            access_objects = tuple(
                item
                for item in draft.desired_objects
                if item.object_class
                in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
            )
            if access_objects:
                secret_objects = tuple(
                    item
                    for item in draft.desired_objects
                    if item.object_class
                    not in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
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
                projected = (
                    *self._access_domain.project(
                        access_draft,
                        requester,
                        now_epoch=now_epoch,
                    ),
                    *self._secret_onboarding.project(
                        secret_draft,
                        requester,
                        now_epoch=now_epoch,
                    ),
                )
                by_ref = {item.object_ref: item for item in projected}
                public_folder = next(
                    (
                        item
                        for item in access_objects
                        if item.object_class is ObjectClass.PUBLIC_FOLDER
                    ),
                    None,
                )
                folder_binding = next(
                    (
                        item
                        for item in secret_objects
                        if item.object_class is ObjectClass.FOLDER_BINDING
                    ),
                    None,
                )
                if (
                    len(by_ref) != len(draft.desired_objects)
                    or public_folder is None
                    or folder_binding is None
                    or dict(folder_binding.desired_fields).get("folder_ref")
                    != public_folder.object_ref
                    or type(
                        by_ref[public_folder.object_ref].values.get("exists")
                    )
                    is not bool
                    or type(
                        by_ref[folder_binding.object_ref].values.get("exists")
                    )
                    is not bool
                    or by_ref[public_folder.object_ref].values.get("exists")
                    != by_ref[folder_binding.object_ref].values.get("exists")
                ):
                    raise V4RuntimeHostError(
                        "Combined Linux onboarding projection is unavailable."
                    )
                return tuple(by_ref[item.object_ref] for item in draft.desired_objects)
            return self._secret_onboarding.project(
                draft,
                requester,
                now_epoch=now_epoch,
            )
        raise V4RuntimeHostError("V4 onboarding projection is unavailable.")


def synthetic_host_settings_from_environment(
    environment: Mapping[str, str],
) -> V4SyntheticHostSettings | None:
    mode = _value(environment, V4_SYNTHETIC_HOST_MODE_ENV)
    database = _value(environment, V4_PLANNING_DATABASE_ENV)
    key = _value(environment, V4_PLANNING_HMAC_KEY_FILE_ENV)
    reference_database = _value(environment, V4_REFERENCE_DATABASE_ENV)
    reference_key = _value(environment, V4_REFERENCE_HMAC_KEY_FILE_ENV)
    reference_socket = _value(environment, V4_REFERENCE_SIDECAR_SOCKET_ENV)
    reference_authority_ref = _value(
        environment,
        V4_REFERENCE_SIDECAR_AUTHORITY_REF_ENV,
    )
    scheme_draft_database = _value(environment, V4_SCHEME_DRAFT_DATABASE_ENV)
    scheme_draft_key = _value(environment, V4_SCHEME_DRAFT_HMAC_KEY_FILE_ENV)
    scheme_draft_socket = _value(
        environment,
        V4_SCHEME_DRAFT_SIDECAR_SOCKET_ENV,
    )
    scheme_draft_authority_ref = _value(
        environment,
        V4_SCHEME_DRAFT_SIDECAR_AUTHORITY_REF_ENV,
    )
    checkpoint_database = _value(environment, V4_CHECKPOINT_DATABASE_ENV)
    checkpoint_key = _value(environment, V4_CHECKPOINT_HMAC_KEY_FILE_ENV)
    checkpoint_store_ref = _value(environment, V4_CHECKPOINT_STORE_REF_ENV)
    checkpoint_socket = _value(environment, V4_CHECKPOINT_SIDECAR_SOCKET_ENV)
    checkpoint_authority_ref = _value(
        environment,
        V4_CHECKPOINT_SIDECAR_AUTHORITY_REF_ENV,
    )
    secret_create_readiness_socket = _value(
        environment,
        V4_SECRET_CREATE_READINESS_SOCKET_ENV,
    )
    access_domain_binding_file = _value(
        environment,
        V4_ACCESS_DOMAIN_BINDING_FILE_ENV,
    )
    secret_onboarding_binding_file = _value(
        environment,
        V4_SECRET_ONBOARDING_BINDING_FILE_ENV,
    )
    approval_and_observe_binding_file = _value(
        environment,
        V4_APPROVAL_AND_OBSERVE_BINDING_FILE_ENV,
    )
    secret_request_observation_binding_file = _value(
        environment,
        V4_SECRET_REQUEST_OBSERVATION_BINDING_FILE_ENV,
    )
    if (
        mode is None
        and database is None
        and key is None
        and reference_database is None
        and reference_key is None
        and reference_socket is None
        and reference_authority_ref is None
        and scheme_draft_database is None
        and scheme_draft_key is None
        and scheme_draft_socket is None
        and scheme_draft_authority_ref is None
        and checkpoint_database is None
        and checkpoint_key is None
        and checkpoint_store_ref is None
        and checkpoint_socket is None
        and checkpoint_authority_ref is None
        and secret_create_readiness_socket is None
        and access_domain_binding_file is None
        and secret_onboarding_binding_file is None
        and approval_and_observe_binding_file is None
        and secret_request_observation_binding_file is None
    ):
        return None
    source_modes = {
        "source-backed-access-domain",
        "source-backed-secret-onboarding",
        "source-backed-onboarding",
        "source-backed-approval-and-observe",
        "source-backed-approval-and-observe-build29",
    }
    if mode not in {"synthetic", *source_modes} or database is None or key is None:
        raise V4RuntimeHostError(
            "V4 plan host requires an exact mode plus planning database and HMAC key paths."
        )
    local_reference_present = reference_database is not None
    sidecar_reference_values = (reference_socket, reference_authority_ref)
    sidecar_reference_present = any(
        value is not None for value in sidecar_reference_values
    )
    if (reference_database is None) is not (reference_key is None):
        raise V4RuntimeHostError(
            "V4 persistent reference authority requires both state paths."
        )
    if (
        mode in source_modes
        and not (local_reference_present or sidecar_reference_present)
    ):
        raise V4RuntimeHostError(
            "V4 source-backed host requires a Reference Authority."
        )
    if (mode in {"source-backed-access-domain", "source-backed-onboarding"}) is not (
        access_domain_binding_file is not None
    ):
        raise V4RuntimeHostError(
            "V4 source-backed Access Domain host requires one binding file."
        )
    if local_reference_present and sidecar_reference_present:
        raise V4RuntimeHostError(
            "V4 Reference Authority accepts exactly one binding."
        )
    if sidecar_reference_present and any(
        value is None for value in sidecar_reference_values
    ):
        raise V4RuntimeHostError(
            "V4 Reference sidecar requires complete socket and Authority binding."
        )
    if (scheme_draft_database is None) is not (scheme_draft_key is None):
        raise V4RuntimeHostError(
            "V4 persistent Scheme Draft authority requires both state paths."
        )
    local_draft_present = scheme_draft_database is not None
    sidecar_draft_values = (scheme_draft_socket, scheme_draft_authority_ref)
    sidecar_draft_present = any(value is not None for value in sidecar_draft_values)
    if local_draft_present and sidecar_draft_present:
        raise V4RuntimeHostError(
            "V4 Scheme Draft authority accepts exactly one binding."
        )
    if sidecar_draft_present and any(
        value is None for value in sidecar_draft_values
    ):
        raise V4RuntimeHostError(
            "V4 Scheme Draft sidecar requires complete socket and Authority binding."
        )
    if (
        mode
        in {
            "source-backed-secret-onboarding",
            "source-backed-onboarding",
            "source-backed-approval-and-observe",
            "source-backed-approval-and-observe-build29",
        }
        and not (local_draft_present or sidecar_draft_present)
    ):
        raise V4RuntimeHostError(
            "V4 source-backed Draft host requires a Scheme Draft Authority."
        )
    if (mode in {"source-backed-secret-onboarding", "source-backed-onboarding"}) is not (
        secret_onboarding_binding_file is not None
    ):
        raise V4RuntimeHostError(
            "V4 source-backed Secret onboarding host requires one binding file."
        )
    if (mode in {"source-backed-approval-and-observe", "source-backed-approval-and-observe-build29"}) is not (
        approval_and_observe_binding_file is not None
    ):
        raise V4RuntimeHostError(
            "V4 source-backed approval host requires one binding file."
        )
    if (
        secret_request_observation_binding_file is not None
        and mode != "source-backed-approval-and-observe"
    ):
        raise V4RuntimeHostError(
            "V4 Secret request observation requires the approval host mode."
        )
    local_checkpoint_values = (checkpoint_database, checkpoint_key)
    sidecar_checkpoint_values = (checkpoint_socket, checkpoint_authority_ref)
    local_checkpoint_present = any(
        value is not None for value in local_checkpoint_values
    )
    sidecar_checkpoint_present = any(
        value is not None for value in sidecar_checkpoint_values
    )
    if local_checkpoint_present and sidecar_checkpoint_present:
        raise V4RuntimeHostError(
            "V4 planning checkpoint accepts exactly one Authority binding."
        )
    if local_checkpoint_present and (
        any(value is None for value in local_checkpoint_values)
        or checkpoint_store_ref is None
    ):
        raise V4RuntimeHostError(
            "V4 planning checkpoint Authority requires complete state and store binding."
        )
    if sidecar_checkpoint_present and (
        any(value is None for value in sidecar_checkpoint_values)
        or checkpoint_store_ref is None
    ):
        raise V4RuntimeHostError(
            "V4 planning checkpoint sidecar requires complete socket, Authority, and store binding."
        )
    if (
        checkpoint_store_ref is not None
        and not local_checkpoint_present
        and not sidecar_checkpoint_present
    ):
        raise V4RuntimeHostError(
            "V4 planning checkpoint store requires an Authority binding."
        )
    reference_settings = None
    if reference_database is not None and reference_key is not None:
        reference_settings = V4PersistentReferenceAuthoritySettings(
            Path(reference_database).expanduser(),
            Path(reference_key).expanduser(),
        )
    reference_sidecar_settings = None
    if reference_socket is not None and reference_authority_ref is not None:
        reference_sidecar_settings = V4UnixReferenceAuthoritySettings(
            Path(reference_socket).expanduser(),
            reference_authority_ref,
        )
    scheme_draft_settings = None
    if scheme_draft_database is not None and scheme_draft_key is not None:
        scheme_draft_settings = V4PersistentSchemeDraftAuthoritySettings(
            Path(scheme_draft_database).expanduser(),
            Path(scheme_draft_key).expanduser(),
        )
    scheme_draft_sidecar_settings = None
    if scheme_draft_socket is not None and scheme_draft_authority_ref is not None:
        scheme_draft_sidecar_settings = V4UnixSchemeDraftAuthoritySettings(
            Path(scheme_draft_socket).expanduser(),
            scheme_draft_authority_ref,
        )
    checkpoint_settings = None
    if (
        checkpoint_database is not None
        and checkpoint_key is not None
        and checkpoint_store_ref is not None
    ):
        checkpoint_settings = V4PersistentPlanningCheckpointSettings(
            Path(checkpoint_database).expanduser(),
            Path(checkpoint_key).expanduser(),
            checkpoint_store_ref,
        )
    checkpoint_sidecar_settings = None
    if (
        checkpoint_socket is not None
        and checkpoint_authority_ref is not None
        and checkpoint_store_ref is not None
    ):
        checkpoint_sidecar_settings = V4UnixPlanningCheckpointSettings(
            Path(checkpoint_socket).expanduser(),
            checkpoint_authority_ref,
            checkpoint_store_ref,
        )
    secret_create_runtime_settings = None
    if secret_create_readiness_socket is not None:
        secret_create_runtime_settings = V4UnixSecretCreateRuntimeSettings(
            Path(secret_create_readiness_socket).expanduser()
        )
    settings = V4SyntheticHostSettings(
        planning_database_path=Path(database).expanduser(),
        planning_hmac_key_path=Path(key).expanduser(),
        reference_authority=reference_settings,
        scheme_draft_authority=scheme_draft_settings,
        planning_checkpoint=checkpoint_settings,
        planning_checkpoint_sidecar=checkpoint_sidecar_settings,
        scheme_draft_sidecar=scheme_draft_sidecar_settings,
        reference_sidecar=reference_sidecar_settings,
        secret_create_runtime=secret_create_runtime_settings,
        host_mode=mode,
        access_domain_binding_path=(
            Path(access_domain_binding_file).expanduser()
            if access_domain_binding_file is not None
            else None
        ),
        secret_onboarding_binding_path=(
            Path(secret_onboarding_binding_file).expanduser()
            if secret_onboarding_binding_file is not None
            else None
        ),
        approval_and_observe_binding_path=(
            Path(approval_and_observe_binding_file).expanduser()
            if approval_and_observe_binding_file is not None
            else None
        ),
        secret_request_observation_binding_path=(
            Path(secret_request_observation_binding_file).expanduser()
            if secret_request_observation_binding_file is not None
            else None
        ),
    )
    if not _valid_host_state_paths(settings):
        raise V4RuntimeHostError("V4 synthetic host state paths are invalid.")
    return settings


def synthetic_v4_plan_host_factory(
    settings: V4SyntheticHostSettings,
    *,
    clock: Callable[[], int] | None = None,
    monotonic_checkpoint: MonotonicPlanningCheckpoint | None = None,
    checkpoint_store_ref: str | None = None,
    approval_receipt_authenticator: (
        ApprovalReceiptAuthenticator | UnixApprovalReceiptAuthenticator | None
    ) = None,
    approver_authorization_authority: (
        PersistentApproverAuthorizationAuthority
        | UnixApproverAuthorizationClient
        | None
    ) = None,
    secret_create_readiness_proxy_client: (
        UnixSecretCreateReadinessProxyClient | None
    ) = None,
    projection_contract_resolver: (
        Callable[[SchemeId, ObjectClass], ProjectionContract] | None
    ) = None,
    projection_provider_factory: (
        Callable[[M2PlanningEngine], PlanningProjectionProvider] | None
    ) = None,
) -> Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]:
    """Return one validated factory for ``create_http_app``."""

    if not _valid_host_state_paths(settings):
        raise V4RuntimeHostError("V4 synthetic host state paths are invalid.")
    if settings.host_mode == "source-backed-ad-discovery" and projection_provider_factory is None:
        raise V4RuntimeHostError("AD Discovery requires its fixed projection binding.")
    if settings.host_mode == "source-backed-approval-and-observe-build29" and projection_provider_factory is None:
        raise V4RuntimeHostError("Build-29 approval requires its fixed projection binding.")
    if (projection_contract_resolver is None) is not (
        projection_provider_factory is None
    ):
        raise V4RuntimeHostError(
            "V4 source-backed projection binding must be complete."
        )
    if (monotonic_checkpoint is None) is not (checkpoint_store_ref is None):
        raise V4RuntimeHostError(
            "V4 monotonic checkpoint requires a complete trusted binding."
        )
    if (
        settings.planning_checkpoint is not None
        or settings.planning_checkpoint_sidecar is not None
    ) and monotonic_checkpoint is not None:
        raise V4RuntimeHostError(
            "V4 planning checkpoint Authority cannot replace a direct binding."
        )
    if approval_receipt_authenticator is not None and not isinstance(
        approval_receipt_authenticator,
        (ApprovalReceiptAuthenticator, UnixApprovalReceiptAuthenticator),
    ):
        raise V4RuntimeHostError(
            "V4 approval receipt authenticator binding is invalid."
        )
    if approver_authorization_authority is not None and not isinstance(
        approver_authorization_authority,
        (
            PersistentApproverAuthorizationAuthority,
            UnixApproverAuthorizationClient,
        ),
    ):
        raise V4RuntimeHostError(
            "V4 approver authorization Authority binding is invalid."
        )
    if secret_create_readiness_proxy_client is not None and not isinstance(
        secret_create_readiness_proxy_client,
        UnixSecretCreateReadinessProxyClient,
    ):
        raise V4RuntimeHostError(
            "V4 Secret-create private runtime binding is invalid."
        )
    if (
        secret_create_readiness_proxy_client is not None
        and settings.secret_create_runtime is not None
    ):
        raise V4RuntimeHostError(
            "V4 Secret-create private runtime accepts exactly one binding."
        )
    if (
        approver_authorization_authority is not None
        and approval_receipt_authenticator is None
    ):
        raise V4RuntimeHostError(
            "V4 approver authorization Authority requires signed receipts."
        )
    if (
        approver_authorization_authority is not None
        and not approver_authorization_authority.monotonic_checkpoint_protocol_bound
    ):
        raise V4RuntimeHostError(
            "V4 approver authorization Authority requires an external "
            "rollback checkpoint."
        )
    if (
        approver_authorization_authority is not None
        and approval_receipt_authenticator is not None
        and approver_authorization_authority.shares_key_material_with(
            approval_receipt_authenticator
        )
    ):
        raise V4RuntimeHostError(
            "V4 approver Authority and receipt HMAC keys must be independent."
        )
    selected_clock = clock or (lambda: int(time.time()))

    def build(
        provider: LocalOAuthProvider,
        confirmation_settings: V4ConfirmationSettings,
    ) -> V4PlanHostComponents:
        try:
            selected_secret_create_readiness_proxy_client = (
                secret_create_readiness_proxy_client
            )
            if settings.secret_create_runtime is not None:
                selected_secret_create_readiness_proxy_client = (
                    UnixSecretCreateReadinessProxyClient(
                        UnixSecretCreateReadinessProxyClientSettings(
                            settings.secret_create_runtime.readiness_socket_path
                        )
                    )
                )
            if isinstance(
                approval_receipt_authenticator,
                UnixApprovalReceiptAuthenticator,
            ):
                approval_receipt_authenticator.verify_ready()
            if approver_authorization_authority is not None:
                approver_authorization_authority.verify_ready()
            if selected_secret_create_readiness_proxy_client is not None:
                selected_secret_create_readiness_proxy_client.verify_ready()
            draft = _synthetic_access_draft()
            planning_checkpoint_authority = None
            planning_checkpoint_client = None
            selected_checkpoint = monotonic_checkpoint
            selected_checkpoint_store_ref = checkpoint_store_ref
            if settings.planning_checkpoint is not None:
                planning_checkpoint_authority = PersistentPlanningCheckpointAuthority(
                    settings.planning_checkpoint.database_path,
                    settings.planning_checkpoint.hmac_key_path,
                    authority_ref=V4_PERSISTENT_PLANNING_CHECKPOINT_AUTHORITY_REF,
                )
                selected_checkpoint = planning_checkpoint_authority
                selected_checkpoint_store_ref = settings.planning_checkpoint.store_ref
            if settings.planning_checkpoint_sidecar is not None:
                planning_checkpoint_client = UnixPlanningCheckpointClient(
                    UnixPlanningCheckpointClientSettings(
                        settings.planning_checkpoint_sidecar.socket_path,
                        settings.planning_checkpoint_sidecar.authority_ref,
                    )
                )
                planning_checkpoint_client.verify_ready()
                selected_checkpoint = planning_checkpoint_client
                selected_checkpoint_store_ref = (
                    settings.planning_checkpoint_sidecar.store_ref
                )
            issuer = _Issuer()
            reference_authorizer: ReferenceAuthorizer = (
                _SyntheticReferenceAuthorizer(draft)
            )
            reference_authority = None
            reference_client = None
            if settings.reference_authority is not None:
                reference_authority = PersistentReferenceAuthority(
                    settings.reference_authority.database_path,
                    settings.reference_authority.hmac_key_path,
                    authority_ref=V4_PERSISTENT_REFERENCE_AUTHORITY_REF,
                    clock=selected_clock,
                )
                reference_authorizer = reference_authority
            if settings.reference_sidecar is not None:
                reference_client = UnixReferenceAuthorityClient(
                    UnixReferenceAuthorityClientSettings(
                        settings.reference_sidecar.socket_path,
                        settings.reference_sidecar.authority_ref,
                    )
                )
                reference_client.verify_ready()
                reference_authorizer = reference_client
            reference_key_authority = reference_authority or reference_client
            scheme_draft_authority = None
            scheme_draft_client = None
            draft_provider: TrustedSchemeDraftProvider = _SyntheticDraftProvider(draft)
            if settings.scheme_draft_authority is not None:
                scheme_draft_authority = PersistentSchemeDraftAuthority(
                    settings.scheme_draft_authority.database_path,
                    settings.scheme_draft_authority.hmac_key_path,
                    authority_ref=V4_PERSISTENT_SCHEME_DRAFT_AUTHORITY_REF,
                    clock=selected_clock,
                )
                draft_provider = scheme_draft_authority
            if settings.scheme_draft_sidecar is not None:
                scheme_draft_client = UnixSchemeDraftAuthorityClient(
                    UnixSchemeDraftAuthorityClientSettings(
                        settings.scheme_draft_sidecar.socket_path,
                        settings.scheme_draft_sidecar.authority_ref,
                    ),
                    clock=selected_clock,
                )
                scheme_draft_client.verify_ready()
                draft_provider = scheme_draft_client
            scheme_draft_key_authority = (
                scheme_draft_authority or scheme_draft_client
            )
            engine = M2PlanningEngine(
                _planning_registry(source_backed=projection_provider_factory is not None),
                issuer,
                reference_authorizer,
                planner_mcp_exposed=True,
                projection_contract_resolver=projection_contract_resolver,
            )
            projection_provider: PlanningProjectionProvider = (
                _SyntheticProjectionProvider(engine)
            )
            if projection_provider_factory is not None:
                projection_provider = projection_provider_factory(engine)
                if (
                    getattr(projection_provider, "mode", None) != "source_backed"
                    or not callable(getattr(projection_provider, "project", None))
                    or (settings.host_mode == "source-backed-ad-discovery"
                        and type(projection_provider) is not AdDiscoveryPlanningSource)
                    or (settings.host_mode == "source-backed-approval-and-observe-build29"
                        and type(projection_provider) is not FortiPamSecretApprovalBuild29ProjectionSource)
                ):
                    raise V4RuntimeHostError(
                        "V4 source-backed projection provider is invalid."
                    )
            planning_store = PersistentProtectedPlanningStore(
                settings.planning_database_path,
                settings.planning_hmac_key_path,
                clock=selected_clock,
                monotonic_checkpoint=selected_checkpoint,
                checkpoint_store_ref=selected_checkpoint_store_ref,
                approval_receipt_authenticator=approval_receipt_authenticator,
            )
            if (
                reference_key_authority is not None
                and reference_key_authority.shares_key_material_with(planning_store)
            ):
                raise V4RuntimeHostError(
                    "V4 Reference Authority and planning-store HMAC keys must be "
                    "independent."
                )
            if (
                reference_key_authority is not None
                and approval_receipt_authenticator is not None
                and reference_key_authority.shares_key_material_with(
                    approval_receipt_authenticator
                )
            ):
                raise V4RuntimeHostError(
                    "V4 Reference Authority and receipt HMAC keys must be "
                    "independent."
                )
            if (
                planning_checkpoint_authority is not None
                and planning_checkpoint_authority.shares_key_material_with(
                    planning_store
                )
            ):
                raise V4RuntimeHostError(
                    "V4 checkpoint Authority and planning-store HMAC keys must be "
                    "independent."
                )
            if (
                planning_checkpoint_authority is not None
                and approval_receipt_authenticator is not None
                and planning_checkpoint_authority.shares_key_material_with(
                    approval_receipt_authenticator
                )
            ):
                raise V4RuntimeHostError(
                    "V4 checkpoint Authority and receipt HMAC keys must be "
                    "independent."
                )
            if (
                planning_checkpoint_authority is not None
                and scheme_draft_key_authority is not None
                and planning_checkpoint_authority.shares_key_material_with(
                    scheme_draft_key_authority
                )
            ):
                raise V4RuntimeHostError(
                    "V4 checkpoint and Scheme Draft Authority HMAC keys must be "
                    "independent."
                )
            if (
                scheme_draft_key_authority is not None
                and scheme_draft_key_authority.shares_key_material_with(
                    planning_store
                )
            ):
                raise V4RuntimeHostError(
                    "V4 Scheme Draft Authority and planning-store HMAC keys "
                    "must be independent."
                )
            if (
                scheme_draft_key_authority is not None
                and approval_receipt_authenticator is not None
                and scheme_draft_key_authority.shares_key_material_with(
                    approval_receipt_authenticator
                )
            ):
                raise V4RuntimeHostError(
                    "V4 Scheme Draft Authority and receipt HMAC keys must be "
                    "independent."
                )
            if (
                approver_authorization_authority is not None
                and approver_authorization_authority.shares_key_material_with(
                    planning_store
                )
            ):
                raise V4RuntimeHostError(
                    "V4 approver Authority and planning-store HMAC keys "
                    "must be independent."
                )
            workflow = M3PlanOnlyWorkflowService(
                engine,
                planning_store,
                M3PlanPolicy(issuer),
                M3ApprovalGate(
                    issuer,
                    receipt_authenticator=approval_receipt_authenticator,
                    approver_authorizer=approver_authorization_authority,
                ),
            )
            confirmation = LocalIntentConfirmationService(
                provider,
                confirmation_settings,
                planning_store,
                clock=selected_clock,
            )
            services = OAuthBoundV4PlanServices(
                workflow,
                draft_provider=draft_provider,
                projection_provider=projection_provider,
                confirmation_transport=confirmation,
                clock=selected_clock,
                monotonic_checkpoint_protocol_bound=(
                    selected_checkpoint is not None
                ),
                approval_receipt_authenticator_protocol_bound=(
                    approval_receipt_authenticator is not None
                ),
                approver_authorization_protocol_bound=(
                    approver_authorization_authority is not None
                ),
                approver_authority_checkpoint_protocol_bound=(
                    approver_authorization_authority is not None
                    and approver_authorization_authority.monotonic_checkpoint_protocol_bound
                ),
                scheme_draft_issuance_protocol_bound=(
                    scheme_draft_key_authority is not None
                ),
                scheme_draft_authority_checkpoint_protocol_bound=(
                    scheme_draft_key_authority is not None
                    and scheme_draft_key_authority.monotonic_checkpoint_protocol_bound
                ),
                reference_authorization_protocol_bound=(
                    reference_key_authority is not None
                ),
                reference_authority_checkpoint_protocol_bound=(
                    reference_key_authority is not None
                    and reference_key_authority.monotonic_checkpoint_protocol_bound
                ),
                secret_create_readiness_proxy_probe=(
                    selected_secret_create_readiness_proxy_client
                ),
            )
        except (
            ApproverAuthorityError,
            MonotonicCheckpointError,
            PersistentPlanningStoreError,
            PlanningContractError,
            ReferenceAuthorityError,
            SchemeDraftAuthorityError,
            SecretCreateReadinessSidecarError,
            V4ConfirmationHttpError,
        ) as exc:
            raise V4RuntimeHostError(
                "V4 synthetic host initialization failed closed."
            ) from exc
        access_domain_source = None
        approval_and_observe_source = None
        secret_onboarding_source = None
        ad_discovery_source = None
        if isinstance(projection_provider, FortiPamAccessDomainProjectionSource):
            access_domain_source = projection_provider
        elif isinstance(
            projection_provider,
            (FortiPamApprovalAndObserveProjectionSource, FortiPamSecretApprovalBuild29ProjectionSource),
        ):
            approval_and_observe_source = projection_provider
        elif isinstance(
            projection_provider,
            (FortiPamSecretOnboardingProjectionSource, WinrmCollectorPlanningSource, TargetBoundWebPlanningSource, DomainSecretPlanningSource),
        ):
            secret_onboarding_source = projection_provider
        elif isinstance(projection_provider, AdDiscoveryPlanningSource):
            ad_discovery_source = projection_provider
        elif isinstance(projection_provider, _OnboardingProjectionProvider):
            access_domain_source = projection_provider._access_domain
            secret_onboarding_source = projection_provider._secret_onboarding
        return V4PlanHostComponents(
            plan_services=services,
            confirmation_service=confirmation,
            scheme_draft_authority=scheme_draft_authority,
            scheme_draft_client=scheme_draft_client,
            planning_checkpoint_authority=planning_checkpoint_authority,
            planning_checkpoint_client=planning_checkpoint_client,
            reference_authority=reference_authority,
            reference_client=reference_client,
            access_domain_projection_source=access_domain_source,
            approval_and_observe_projection_source=approval_and_observe_source,
            secret_onboarding_projection_source=secret_onboarding_source,
            ad_discovery_projection_source=ad_discovery_source,
            _secret_approval_planning_reader=planning_store,
            _secret_approval_receipt_authenticator=(
                approval_receipt_authenticator
            ),
            _secret_approval_approver_authority_ref=(
                approver_authorization_authority.authority_ref
                if approver_authorization_authority is not None
                else None
            ),
            _clock=selected_clock,
        )

    return build


def access_domain_v4_plan_host_factory(
    settings: V4SyntheticHostSettings,
    *,
    folder_transport: FolderCollectionReadTransport,
    binding_resolver: AccessDomainBindingResolver,
    clock: Callable[[], int] | None = None,
) -> Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]:
    """Compose the source-backed Access Domain planner without enabling writes."""

    if (
        settings.reference_authority is None
        and settings.reference_sidecar is None
    ):
        raise V4RuntimeHostError(
            "V4 source-backed projection requires a Reference Authority."
        )
    if not callable(getattr(folder_transport, "read_collection", None)) or not callable(
        getattr(binding_resolver, "resolve", None)
    ):
        raise V4RuntimeHostError(
            "V4 source-backed projection dependencies are invalid."
        )

    def contract_resolver(
        scheme_id: SchemeId,
        object_class: ObjectClass,
    ) -> ProjectionContract:
        if scheme_id is not SchemeId.ACCESS_DOMAIN:
            raise AccessDomainProjectionSourceError(
                "FortiPAM Access Domain projection source is unavailable."
            )
        return access_domain_projection_contract(object_class)

    return synthetic_v4_plan_host_factory(
        settings,
        clock=clock,
        projection_contract_resolver=contract_resolver,
        projection_provider_factory=lambda _engine: (
            FortiPamAccessDomainProjectionSource(
                folder_transport,
                binding_resolver,
            )
        ),
    )


def target_bound_web_v4_plan_host_factory(
    settings: V4SyntheticHostSettings, *, binding: TargetBoundWebPlanningBinding,
    secret_transport: TargetBoundWebReadTransport,
    clock: Callable[[], int] | None = None,
) -> Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]:
    """Compose the distinct read-only Web profile with existing authorities."""
    if (
        settings.host_mode != "source-backed-secret-onboarding"
        or (settings.reference_authority is None and settings.reference_sidecar is None)
        or (settings.scheme_draft_authority is None and settings.scheme_draft_sidecar is None)
    ):
        raise V4RuntimeHostError("Target-bound Web planning authorities are unavailable.")
    source = TargetBoundWebPlanningSource(binding, secret_transport)

    def contract_resolver(scheme_id: SchemeId, object_class: ObjectClass) -> ProjectionContract:
        if scheme_id is not SchemeId.SECRET_ONBOARDING or object_class not in {
            ObjectClass.FOLDER_BINDING, ObjectClass.TEMPLATE_BINDING,
            ObjectClass.WEB_TARGET_BINDING, ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA,
        }:
            raise V4RuntimeHostError("Target-bound Web planning contract is unavailable.")
        return secret_onboarding_projection_contract(object_class)

    return synthetic_v4_plan_host_factory(
        settings, clock=clock, projection_contract_resolver=contract_resolver,
        projection_provider_factory=lambda _engine: source,
    )


def ad_discovery_v4_plan_host_factory(
    settings: V4SyntheticHostSettings, *, binding: AdDiscoveryPlanningBinding,
    owner_transport: OwnerSessionMetadataTransport,
    source_transport: FortiPamDiscoveryEntryCreateHttpTransport,
    clock: Callable[[], int] | None = None,
) -> Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]:
    """Explicit read-only AD host; execution requires a separate fixed factory."""
    if (
        settings.host_mode != "source-backed-ad-discovery"
        or (settings.reference_authority is None and settings.reference_sidecar is None)
        or (settings.scheme_draft_authority is None and settings.scheme_draft_sidecar is None)
    ):
        raise V4RuntimeHostError("AD Discovery planning authorities are unavailable.")
    source = AdDiscoveryPlanningSource(binding, owner_transport, source_transport)

    def contract_resolver(scheme_id: SchemeId, object_class: ObjectClass) -> ProjectionContract:
        if scheme_id is not SchemeId.BULK_ONBOARDING:
            raise V4RuntimeHostError("AD Discovery planning contract is unavailable.")
        return ad_discovery_projection_contract(object_class)

    return synthetic_v4_plan_host_factory(
        settings, clock=clock, projection_contract_resolver=contract_resolver,
        projection_provider_factory=lambda _engine: source,
    )


def domain_secret_v4_plan_host_factory(
    settings: V4SyntheticHostSettings, *, binding: DomainSecretPlanningBinding,
    secret_transport: DomainSecretReadTransport,
    clock: Callable[[], int] | None = None,
) -> Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]:
    """Compose the distinct read-only Domain profile with existing authorities."""
    if (
        settings.host_mode != "source-backed-secret-onboarding"
        or (settings.reference_authority is None and settings.reference_sidecar is None)
        or (settings.scheme_draft_authority is None and settings.scheme_draft_sidecar is None)
    ):
        raise V4RuntimeHostError("Domain Secret planning authorities are unavailable.")
    source = DomainSecretPlanningSource(binding, secret_transport)

    def contract_resolver(scheme_id: SchemeId, object_class: ObjectClass) -> ProjectionContract:
        if scheme_id is not SchemeId.SECRET_ONBOARDING or object_class not in {
            ObjectClass.FOLDER_BINDING, ObjectClass.TEMPLATE_BINDING,
            ObjectClass.DOMAIN_TARGET_BINDING, ObjectClass.DOMAIN_SECRET_METADATA,
        }:
            raise V4RuntimeHostError("Domain Secret planning contract is unavailable.")
        return secret_onboarding_projection_contract(object_class)

    return synthetic_v4_plan_host_factory(
        settings, clock=clock, projection_contract_resolver=contract_resolver,
        projection_provider_factory=lambda _engine: source,
    )


def secret_onboarding_v4_plan_host_factory(
    settings: V4SyntheticHostSettings,
    *,
    secret_transport: SecretMetadataReadTransport,
    target_transport: TargetReadTransport | None,
    launcher_transport: LauncherReadTransport | None,
    binding_resolver: SecretOnboardingBindingResolver,
    collector_binding: SecretCreate700WinrmBinding | None = None,
    folder_policy_transport: FolderPolicyReadTransport | None = None,
    secret_policy_clipboard_transport: (
        SecretPolicyClipboardReadTransport | None
    ) = None,
    recording_policy_transport: RecordingPolicyReadTransport | None = None,
    rdp_event_filter_transport: RdpEventFilterReadTransport | None = None,
    approval_receipt_authenticator: (
        ApprovalReceiptAuthenticator | UnixApprovalReceiptAuthenticator | None
    ) = None,
    approver_authorization_authority: (
        PersistentApproverAuthorizationAuthority
        | UnixApproverAuthorizationClient
        | None
    ) = None,
    clock: Callable[[], int] | None = None,
) -> Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]:
    """Compose the pre-registration new-Secret planner without writes."""

    if settings.reference_authority is None and settings.reference_sidecar is None:
        raise V4RuntimeHostError(
            "V4 source-backed projection requires a Reference Authority."
        )
    if (
        settings.scheme_draft_authority is None
        and settings.scheme_draft_sidecar is None
    ):
        raise V4RuntimeHostError(
            "V4 Secret onboarding projection requires a Scheme Draft Authority."
        )
    if (
        not callable(getattr(secret_transport, "inspect_projection", None))
        or (
            target_transport is not None
            and not callable(getattr(target_transport, "inspect", None))
        )
        or (
            launcher_transport is not None
            and not callable(getattr(launcher_transport, "inspect", None))
        )
        or not callable(getattr(binding_resolver, "resolve", None))
        or (
            folder_policy_transport is not None
            and not callable(
                getattr(folder_policy_transport, "verify_folder_policy_binding", None)
            )
        )
        or (
            secret_policy_clipboard_transport is not None
            and not callable(
                getattr(
                    secret_policy_clipboard_transport,
                    "read_session_security_baseline",
                    None,
                )
            )
        )
        or (
            recording_policy_transport is not None
            and not callable(getattr(recording_policy_transport, "inspect", None))
        )
        or (
            rdp_event_filter_transport is not None
            and not callable(getattr(rdp_event_filter_transport, "readback", None))
        )
    ):
        raise V4RuntimeHostError(
            "V4 source-backed projection dependencies are invalid."
        )

    def contract_resolver(
        scheme_id: SchemeId,
        object_class: ObjectClass,
    ) -> ProjectionContract:
        if scheme_id is not SchemeId.SECRET_ONBOARDING:
            raise SecretOnboardingProjectionSourceError(
                "FortiPAM Secret onboarding projection source is unavailable."
            )
        return (winrm_collector_projection_contract(object_class) if collector_binding is not None
                else secret_onboarding_projection_contract(object_class))

    from .owner_rdp_runtime import OwnerRdpPlanningSource, OwnerRdpSessionMetadataTransport
    source_class = (OwnerRdpPlanningSource if type(secret_transport) is OwnerRdpSessionMetadataTransport
                    else FortiPamSecretOnboardingProjectionSource)
    return synthetic_v4_plan_host_factory(
        settings,
        clock=clock,
        approval_receipt_authenticator=approval_receipt_authenticator,
        approver_authorization_authority=approver_authorization_authority,
        projection_contract_resolver=contract_resolver,
        projection_provider_factory=lambda _engine: (
            WinrmCollectorPlanningSource(collector_binding, binding_resolver,
                                         cast(WinrmCollectorReadTransport, secret_transport))
            if collector_binding is not None else source_class(
                secret_transport,
                target_transport,
                launcher_transport,
                binding_resolver,
                folder_policy_transport,
                secret_policy_clipboard_transport,
                recording_policy_transport,
                rdp_event_filter_transport,
            )
        ),
    )


def approval_and_observe_v4_plan_host_factory(
    settings: V4SyntheticHostSettings,
    *,
    secret_transport: SecretApprovalReadTransport,
    approval_profile_transport: ApprovalProfileReadTransport,
    binding_resolver: ApprovalAndObserveBindingResolver,
    approval_receipt_authenticator: (
        ApprovalReceiptAuthenticator | UnixApprovalReceiptAuthenticator | None
    ) = None,
    approver_authorization_authority: (
        PersistentApproverAuthorizationAuthority
        | UnixApproverAuthorizationClient
        | None
    ) = None,
    clock: Callable[[], int] | None = None,
) -> Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]:
    """Compose the source-backed BP008 approval preview without writes."""

    if settings.reference_authority is None and settings.reference_sidecar is None:
        raise V4RuntimeHostError(
            "V4 source-backed projection requires a Reference Authority."
        )
    if (
        settings.scheme_draft_authority is None
        and settings.scheme_draft_sidecar is None
    ):
        raise V4RuntimeHostError(
            "V4 approval projection requires a Scheme Draft Authority."
        )
    if (
        not callable(
            getattr(secret_transport, "inspect_approval_projection", None)
        )
        or not callable(getattr(approval_profile_transport, "readback", None))
        or not callable(getattr(binding_resolver, "resolve", None))
    ):
        raise V4RuntimeHostError(
            "V4 approval projection dependencies are invalid."
        )

    def contract_resolver(
        scheme_id: SchemeId,
        object_class: ObjectClass,
    ) -> ProjectionContract:
        if scheme_id is not SchemeId.APPROVAL_AND_OBSERVE:
            raise ApprovalAndObserveProjectionSourceError(
                "FortiPAM approval and observation projection is unavailable."
            )
        return approval_and_observe_projection_contract(object_class)

    return synthetic_v4_plan_host_factory(
        settings,
        clock=clock,
        approval_receipt_authenticator=approval_receipt_authenticator,
        approver_authorization_authority=approver_authorization_authority,
        projection_contract_resolver=contract_resolver,
        projection_provider_factory=lambda _engine: (
            FortiPamApprovalAndObserveProjectionSource(
                secret_transport,
                approval_profile_transport,
                binding_resolver,
            )
        ),
    )


def secret_approval_build29_v4_plan_host_factory(
    settings: V4SyntheticHostSettings,
    *,
    secret_transport: SecretApprovalReadTransport,
    approval_profile_transport: SecretApprovalBuild29ProfileReadTransport,
    binding_resolver: ApprovalAndObserveBindingResolver,
    approval_receipt_authenticator: (
        ApprovalReceiptAuthenticator | UnixApprovalReceiptAuthenticator | None
    ) = None,
    approver_authorization_authority: (
        PersistentApproverAuthorizationAuthority | UnixApproverAuthorizationClient | None
    ) = None,
    clock: Callable[[], int] | None = None,
) -> Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]:
    """Install only the independent build-29 categorical planning contract.

    Registration describes this read-only contract installation. Actual getter
    qualification and all execution gates remain independent prerequisites.
    """
    if settings.host_mode != "source-backed-approval-and-observe-build29":
        raise V4RuntimeHostError("Build-29 approval requires its exact host mode.")
    if settings.reference_authority is None and settings.reference_sidecar is None:
        raise V4RuntimeHostError("V4 source-backed projection requires a Reference Authority.")
    if settings.scheme_draft_authority is None and settings.scheme_draft_sidecar is None:
        raise V4RuntimeHostError("V4 approval projection requires a Scheme Draft Authority.")
    if (not callable(getattr(secret_transport, "inspect_approval_projection", None))
            or not callable(getattr(approval_profile_transport, "readback", None))
            or not callable(getattr(binding_resolver, "resolve", None))):
        raise V4RuntimeHostError("V4 build-29 approval projection dependencies are invalid.")

    def contract_resolver(scheme_id: SchemeId, object_class: ObjectClass) -> ProjectionContract:
        if scheme_id is not SchemeId.APPROVAL_AND_OBSERVE:
            raise SecretApprovalBuild29ProjectionSourceError(
                "FortiPAM build-29 approval projection is unavailable."
            )
        return secret_approval_build29_projection_contract(object_class)

    return synthetic_v4_plan_host_factory(
        settings, clock=clock,
        approval_receipt_authenticator=approval_receipt_authenticator,
        approver_authorization_authority=approver_authorization_authority,
        projection_contract_resolver=contract_resolver,
        projection_provider_factory=lambda _engine: FortiPamSecretApprovalBuild29ProjectionSource(
            secret_transport, approval_profile_transport, binding_resolver, contract_registered=True,
        ),
    )


def onboarding_v4_plan_host_factory(
    settings: V4SyntheticHostSettings,
    *,
    folder_transport: FolderCollectionReadTransport,
    access_domain_binding_resolver: AccessDomainBindingResolver,
    secret_transport: SecretMetadataReadTransport,
    target_transport: TargetReadTransport,
    launcher_transport: LauncherReadTransport | None,
    secret_binding_resolver: SecretOnboardingBindingResolver,
    secret_folder_policy_transport: FolderPolicyReadTransport | None = None,
    secret_policy_clipboard_transport: (
        SecretPolicyClipboardReadTransport | None
    ) = None,
    recording_policy_transport: RecordingPolicyReadTransport | None = None,
    rdp_event_filter_transport: RdpEventFilterReadTransport | None = None,
    clock: Callable[[], int] | None = None,
) -> Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]:
    """Compose both read-only onboarding Schemes in one plan Host."""

    if settings.reference_authority is None and settings.reference_sidecar is None:
        raise V4RuntimeHostError(
            "V4 source-backed projection requires a Reference Authority."
        )
    if (
        settings.scheme_draft_authority is None
        and settings.scheme_draft_sidecar is None
    ):
        raise V4RuntimeHostError(
            "V4 onboarding projection requires a Scheme Draft Authority."
        )
    if (
        not callable(getattr(folder_transport, "read_collection", None))
        or not callable(getattr(access_domain_binding_resolver, "resolve", None))
        or not callable(getattr(secret_transport, "inspect_projection", None))
        or not callable(getattr(target_transport, "inspect", None))
        or (
            launcher_transport is not None
            and not callable(getattr(launcher_transport, "inspect", None))
        )
        or not callable(getattr(secret_binding_resolver, "resolve", None))
        or (
            secret_folder_policy_transport is not None
            and not callable(
                getattr(
                    secret_folder_policy_transport,
                    "verify_folder_policy_binding",
                    None,
                )
            )
        )
        or (
            secret_policy_clipboard_transport is not None
            and not callable(
                getattr(
                    secret_policy_clipboard_transport,
                    "read_update_baseline",
                    None,
                )
            )
        )
        or (
            recording_policy_transport is not None
            and not callable(getattr(recording_policy_transport, "inspect", None))
        )
        or (
            rdp_event_filter_transport is not None
            and not callable(getattr(rdp_event_filter_transport, "readback", None))
        )
    ):
        raise V4RuntimeHostError(
            "V4 source-backed projection dependencies are invalid."
        )

    def contract_resolver(
        scheme_id: SchemeId,
        object_class: ObjectClass,
    ) -> ProjectionContract:
        if scheme_id is SchemeId.ACCESS_DOMAIN:
            return access_domain_projection_contract(object_class)
        if scheme_id is SchemeId.SECRET_ONBOARDING:
            if object_class in {
                ObjectClass.PUBLIC_FOLDER,
                ObjectClass.ACCESS_GRANT,
            }:
                return access_domain_projection_contract(object_class)
            return secret_onboarding_projection_contract(object_class)
        raise V4RuntimeHostError("V4 onboarding projection is unavailable.")

    return synthetic_v4_plan_host_factory(
        settings,
        clock=clock,
        projection_contract_resolver=contract_resolver,
        projection_provider_factory=lambda _engine: _OnboardingProjectionProvider(
            FortiPamAccessDomainProjectionSource(
                folder_transport,
                access_domain_binding_resolver,
            ),
            FortiPamSecretOnboardingProjectionSource(
                secret_transport,
                target_transport,
                launcher_transport,
                secret_binding_resolver,
                secret_folder_policy_transport,
                secret_policy_clipboard_transport,
                recording_policy_transport,
                rdp_event_filter_transport,
            ),
        ),
    )


def issue_synthetic_reference_grants(
    authority: PersistentReferenceAuthority,
    *,
    requester_digest: str,
    expires_at: int,
    now_epoch: int,
) -> tuple[str, ...]:
    """Provision the fixed synthetic fixture outside MCP/runtime startup."""

    if not isinstance(authority, PersistentReferenceAuthority):
        raise V4RuntimeHostError("Synthetic reference authority is unavailable.")
    draft = _synthetic_access_draft()
    try:
        return authority.issue_many(
            _synthetic_reference_bindings(draft),
            requester_digest=requester_digest,
            environment_ref=draft.environment_ref,
            scope_ref=draft.scope_ref,
            expires_at=expires_at,
            now_epoch=now_epoch,
        )
    except ReferenceAuthorityError as exc:
        raise V4RuntimeHostError(
            "Synthetic reference grant provisioning failed closed."
        ) from exc


def issue_synthetic_scheme_draft(
    authority: PersistentSchemeDraftAuthority,
    requester: AuthenticatedRequester,
    *,
    expires_at: int,
    now_epoch: int,
) -> str:
    """Issue the fixed non-device fixture through the trusted local Authority."""

    if not isinstance(authority, PersistentSchemeDraftAuthority):
        raise V4RuntimeHostError("Synthetic Scheme Draft authority is unavailable.")
    try:
        return authority.issue(
            _synthetic_access_draft(),
            requester,
            expires_at=expires_at,
            now_epoch=now_epoch,
        )
    except SchemeDraftAuthorityError as exc:
        raise V4RuntimeHostError(
            "Synthetic Scheme Draft provisioning failed closed."
        ) from exc


def _synthetic_access_draft() -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.ACCESS_DOMAIN,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-004",
        environment_ref="synthetic-lab-environment",
        scope_ref="synthetic-access-scope",
        owner_ref="synthetic-owner-reference",
        audience_ref="synthetic-admin-audience",
        outcome_code="establish_access_domain",
        desired_objects=(
            DesiredObject(
                object_ref="synthetic-public-folder-reference",
                object_class=ObjectClass.PUBLIC_FOLDER,
                desired_exists=True,
                desired_fields=(
                    ("enabled", True),
                    ("owner_ref", "synthetic-owner-reference"),
                ),
            ),
            DesiredObject(
                object_ref="synthetic-access-grant-reference",
                object_class=ObjectClass.ACCESS_GRANT,
                desired_exists=True,
                desired_fields=(
                    ("permission", "use"),
                    ("subject_class", "group"),
                    ("subject_ref", "synthetic-group-reference"),
                ),
            ),
        ),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("synthetic_access_scope_change",),
        assumption_codes=("synthetic_fixture_only",),
        excluded_scope_codes=("credential_material", "device_execution"),
        verification_codes=("synthetic_relation_readback",),
        stop_codes=("current_state_drift", "projection_unavailable"),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="none",
        reversibility_class="compensating_action_required",
        evidence_refs=("synthetic-evidence-reference",),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
    )


def _synthetic_reference_bindings(
    draft: SchemeDraft,
) -> tuple[tuple[str, str], ...]:
    bindings: set[tuple[str, str]] = {
        ("m2-fake-projection-source", "projection_source"),
        (draft.environment_ref, "environment"),
        (draft.scope_ref, "scope"),
        (draft.owner_ref, "owner"),
        (draft.audience_ref, "audience"),
        *((value, "evidence") for value in draft.evidence_refs),
    }
    for desired in draft.desired_objects:
        kind = (
            "public_folder"
            if desired.object_class is ObjectClass.PUBLIC_FOLDER
            else "access_grant"
        )
        bindings.add((desired.object_ref, f"object_{kind}"))
        bindings.update(
            (value, f"field_{name}")
            for name, value in desired.desired_fields
            if name.endswith("_ref") and type(value) is str
        )
    return tuple(sorted(bindings))


def _planning_registry(*, source_backed: bool = False) -> dict[str, object]:
    def family(synthetic: str, canonical: str) -> str:
        return canonical if source_backed else synthetic

    evidence = {
        "evidence_status": "contract_tested",
        "evidence_kind": "fake_only_contract",
        "profile_blueprint_refs": ["FPA-BP-004"],
        "planner_runtime_packaged": True,
        "planner_mcp_exposed": False,
        "dispatchable": False,
        "executor_runtime_packaged": False,
        "executor_mcp_exposed": False,
        "device_access": False,
    }
    secret_evidence = {
        **evidence,
        "profile_blueprint_refs": ["FPA-BP-005", "FPA-BP-006", "FPA-BP-007"],
    }
    approval_evidence = {
        **evidence,
        "profile_blueprint_refs": ["FPA-BP-008"],
    }
    identity_evidence = {
        **evidence,
        "profile_blueprint_refs": ["FPA-BP-015"],
    }
    discovery_evidence = {
        **evidence,
        "profile_blueprint_refs": ["FPA-BP-014"],
    }
    return {
        "registry_kind": "fortipam_v4_administrative_registry",
        "schema_version": "1.1.0",
        "schemes": [
            {
                "id": "BulkOnboardingScheme",
                "version": "1.0.0",
                "status": "planned",
                "maturity": "contract_tested",
                "lifecycle": "contract_tested",
                "blueprint_refs": ["FPA-BP-014"],
                "implementation_evidence": discovery_evidence,
            },
            {
                "id": "AccessDomainScheme",
                "version": "1.0.0",
                "status": "planned",
                "maturity": "contract_tested",
                "lifecycle": "contract_tested",
                "blueprint_refs": ["FPA-BP-004"],
                "implementation_evidence": evidence,
            },
            {
                "id": "ApprovalAndObserveScheme",
                "version": "1.0.0",
                "status": "planned",
                "maturity": "contract_tested",
                "lifecycle": "contract_tested",
                "blueprint_refs": ["FPA-BP-008"],
                "implementation_evidence": approval_evidence,
            },
            {
                "id": "IdentityLifecycleScheme",
                "version": "1.0.0",
                "status": "planned",
                "maturity": "contract_tested",
                "lifecycle": "contract_tested",
                "blueprint_refs": ["FPA-BP-015"],
                "implementation_evidence": identity_evidence,
            },
            {
                "id": "SecretOnboardingScheme",
                "version": "1.0.0",
                "status": "planned",
                "maturity": "contract_tested",
                "lifecycle": "contract_tested",
                "blueprint_refs": [
                    "FPA-BP-005", "FPA-BP-006", "FPA-BP-007",
                    *(["FPA-BP-014"] if source_backed else []),
                ],
                "implementation_evidence": secret_evidence,
            },
        ],
        "blueprints": [
            {"id": "FPA-BP-004", "action_refs": [family("synthetic-access-action", "access-domain-and-ownership-plan")]},
            {"id": "FPA-BP-005", "action_refs": [family("synthetic-secret-action", "linux-ssh-and-file-transfer-access-plan")]},
            {
                "id": "FPA-BP-006",
                "action_refs": [family("synthetic-windows-rdp-action", "windows-and-ad-privileged-access-plan")],
            },
            {
                "id": "FPA-BP-007",
                "action_refs": [family("synthetic-web-account-action", "web-and-application-credential-access-plan")],
            },
            {
                "id": "FPA-BP-008",
                "action_refs": [family("synthetic-approval-action", "approval-checkout-jit-and-jobs-plan")],
            },
            {
                "id": "FPA-BP-015",
                "action_refs": [
                    family(
                        "synthetic-identity-lifecycle-action",
                        "sponsored-and-temporary-access-plan",
                    )
                ],
            },
            {
                "id": "FPA-BP-014",
                "action_refs": [family("synthetic-discovery-action", "discovery-and-smart-association-plan")],
            },
        ],
        "actions": [
            _disabled_action(family("synthetic-access-action", "access-domain-and-ownership-plan")),
            _disabled_action(family("synthetic-secret-action", "linux-ssh-and-file-transfer-access-plan")),
            _disabled_action(family("synthetic-windows-rdp-action", "windows-and-ad-privileged-access-plan")),
            _disabled_action(family("synthetic-web-account-action", "web-and-application-credential-access-plan")),
            _disabled_action(family("synthetic-approval-action", "approval-checkout-jit-and-jobs-plan")),
            _disabled_action(
                family("synthetic-discovery-action", "discovery-and-smart-association-plan"),
                risk_tier="medium",
            ),
            _disabled_action(
                family(
                    "synthetic-identity-lifecycle-action",
                    "sponsored-and-temporary-access-plan",
                ),
                risk_tier="medium",
            ),
        ],
    }


def _disabled_action(identifier: str, *, risk_tier: str = "high") -> dict[str, object]:
    return {
        "id": identifier,
        "record_kind": "action_family_placeholder",
        "version": "1.0.0",
        "risk_tier": risk_tier,
        "atomic_contract": False,
        "executable": False,
        "adapter": "none",
        "status": "design_only",
        "maturity": "catalogued",
        "lifecycle": "catalogued",
    }


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def _valid_host_state_paths(settings: object) -> bool:
    if not isinstance(settings, V4SyntheticHostSettings):
        return False
    paths = [settings.planning_database_path, settings.planning_hmac_key_path]
    if settings.host_mode not in {
        "synthetic",
        "source-backed-access-domain",
        "source-backed-secret-onboarding",
        "source-backed-onboarding",
        "source-backed-approval-and-observe",
        "source-backed-approval-and-observe-build29",
        "source-backed-ad-discovery",
    }:
        return False
    if (
        settings.host_mode in {"source-backed-access-domain", "source-backed-onboarding"}
    ) is not (
        settings.access_domain_binding_path is not None
    ):
        return False
    if settings.access_domain_binding_path is not None:
        paths.append(settings.access_domain_binding_path)
    if (
        settings.host_mode
        in {"source-backed-secret-onboarding", "source-backed-onboarding"}
    ) is not (
        settings.secret_onboarding_binding_path is not None
    ):
        return False
    if settings.secret_onboarding_binding_path is not None:
        paths.append(settings.secret_onboarding_binding_path)
    if (settings.host_mode in {"source-backed-approval-and-observe", "source-backed-approval-and-observe-build29"}) is not (
        settings.approval_and_observe_binding_path is not None
    ):
        return False
    if settings.approval_and_observe_binding_path is not None:
        paths.append(settings.approval_and_observe_binding_path)
    if (
        settings.secret_request_observation_binding_path is not None
        and settings.host_mode != "source-backed-approval-and-observe"
    ):
        return False
    if settings.secret_request_observation_binding_path is not None:
        paths.append(settings.secret_request_observation_binding_path)
    if settings.reference_authority is not None:
        if not isinstance(
            settings.reference_authority,
            V4PersistentReferenceAuthoritySettings,
        ):
            return False
        paths.extend(
            (
                settings.reference_authority.database_path,
                settings.reference_authority.hmac_key_path,
            )
        )
    if settings.reference_sidecar is not None:
        if not isinstance(
            settings.reference_sidecar,
            V4UnixReferenceAuthoritySettings,
        ):
            return False
        try:
            require_ref(
                settings.reference_sidecar.authority_ref,
                "Reference sidecar authority_ref",
            )
        except PlanningContractError:
            return False
        paths.append(settings.reference_sidecar.socket_path)
    if (
        settings.reference_authority is not None
        and settings.reference_sidecar is not None
    ):
        return False
    if settings.scheme_draft_authority is not None:
        if not isinstance(
            settings.scheme_draft_authority,
            V4PersistentSchemeDraftAuthoritySettings,
        ):
            return False
        paths.extend(
            (
                settings.scheme_draft_authority.database_path,
                settings.scheme_draft_authority.hmac_key_path,
            )
        )
    if settings.scheme_draft_sidecar is not None:
        if not isinstance(
            settings.scheme_draft_sidecar,
            V4UnixSchemeDraftAuthoritySettings,
        ):
            return False
        try:
            require_ref(
                settings.scheme_draft_sidecar.authority_ref,
                "Scheme Draft sidecar authority_ref",
            )
        except PlanningContractError:
            return False
        paths.append(settings.scheme_draft_sidecar.socket_path)
    if (
        settings.scheme_draft_authority is not None
        and settings.scheme_draft_sidecar is not None
    ):
        return False
    if (
        settings.host_mode
        in {
            "source-backed-secret-onboarding",
            "source-backed-onboarding",
            "source-backed-approval-and-observe",
            "source-backed-approval-and-observe-build29",
        }
        and settings.scheme_draft_authority is None
        and settings.scheme_draft_sidecar is None
    ):
        return False
    if settings.planning_checkpoint is not None:
        if not isinstance(
            settings.planning_checkpoint,
            V4PersistentPlanningCheckpointSettings,
        ):
            return False
        try:
            require_ref(
                settings.planning_checkpoint.store_ref,
                "planning checkpoint store_ref",
            )
        except PlanningContractError:
            return False
        paths.extend(
            (
                settings.planning_checkpoint.database_path,
                settings.planning_checkpoint.hmac_key_path,
            )
        )
    if settings.planning_checkpoint_sidecar is not None:
        if not isinstance(
            settings.planning_checkpoint_sidecar,
            V4UnixPlanningCheckpointSettings,
        ):
            return False
        try:
            require_ref(
                settings.planning_checkpoint_sidecar.authority_ref,
                "planning checkpoint sidecar authority_ref",
            )
            require_ref(
                settings.planning_checkpoint_sidecar.store_ref,
                "planning checkpoint sidecar store_ref",
            )
        except PlanningContractError:
            return False
        paths.append(settings.planning_checkpoint_sidecar.socket_path)
    if (
        settings.planning_checkpoint is not None
        and settings.planning_checkpoint_sidecar is not None
    ):
        return False
    if settings.secret_create_runtime is not None:
        if not isinstance(
            settings.secret_create_runtime,
            V4UnixSecretCreateRuntimeSettings,
        ):
            return False
        paths.append(settings.secret_create_runtime.readiness_socket_path)
    return all(isinstance(path, Path) and path.is_absolute() for path in paths) and (
        len(set(paths)) == len(paths)
    )


__all__ = [
    "V4PlanHostComponents",
    "V4PersistentReferenceAuthoritySettings",
    "V4UnixReferenceAuthoritySettings",
    "V4PersistentPlanningCheckpointSettings",
    "V4PersistentSchemeDraftAuthoritySettings",
    "V4UnixSchemeDraftAuthoritySettings",
    "V4UnixPlanningCheckpointSettings",
    "V4UnixSecretCreateRuntimeSettings",
    "V4_SECRET_CREATE_READINESS_SOCKET_ENV",
    "V4RuntimeHostError",
    "V4_ACCESS_DOMAIN_BINDING_FILE_ENV",
    "V4_APPROVAL_AND_OBSERVE_BINDING_FILE_ENV",
    "V4_SECRET_REQUEST_OBSERVATION_BINDING_FILE_ENV",
    "V4_SECRET_ONBOARDING_BINDING_FILE_ENV",
    "access_domain_v4_plan_host_factory",
    "approval_and_observe_v4_plan_host_factory",
    "secret_approval_build29_v4_plan_host_factory",
    "onboarding_v4_plan_host_factory",
    "secret_onboarding_v4_plan_host_factory",
    "target_bound_web_v4_plan_host_factory",
    "domain_secret_v4_plan_host_factory",
    "ad_discovery_v4_plan_host_factory",
    "V4SyntheticHostSettings",
    "V4_PERSISTENT_REFERENCE_AUTHORITY_REF",
    "V4_PERSISTENT_PLANNING_CHECKPOINT_AUTHORITY_REF",
    "V4_PERSISTENT_SCHEME_DRAFT_AUTHORITY_REF",
    "V4_SYNTHETIC_SCHEME_REF",
    "issue_synthetic_reference_grants",
    "issue_synthetic_scheme_draft",
    "synthetic_host_settings_from_environment",
    "synthetic_v4_plan_host_factory",
]
