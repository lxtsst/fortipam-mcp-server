"""HTTP-OAuth host boundary for the non-executing V4 planning facade.

This module is imported only by the exact ``v4-plan-only`` runtime profile.
It accepts SDK-validated access-token metadata, derives one opaque requester,
and binds server-issued Scheme draft references to the repository V4 facade.
It has no FortiPAM transport, credential provider, executor, or product adapter.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import re
import stat
import time
from typing import Protocol
from urllib.parse import urlsplit

from mcp.server.auth.provider import AccessToken

from v4_planning import (
    AuthenticatedApprover,
    AuthenticatedRequester,
    FinalIntentSummary,
    M3PlanOnlyWorkflowService,
    PreparedPlan,
    SchemeDraft,
    V4PlanOnlyMcpFacade,
    VerifiedConfirmationInteraction,
)
from v4_planning.mcp_facade import (
    PlanningProjectionProvider,
    TrustedConfirmationConsumer,
)


V4_PLANNING_SCOPE = "fortipam:plan"
V4_APPROVAL_SCOPE = "fortipam:approve"
V4_PLANNING_PREFIX = "FORTIPAM_MCP_V4_PLAN_"
V4_PLANNING_PRINCIPAL_HMAC_KEY_FILE_ENV = (
    f"{V4_PLANNING_PREFIX}PRINCIPAL_HMAC_KEY_FILE"
)
V4_PLANNING_UNAVAILABLE = "FortiPAM V4 planning host services are unavailable."
V4_PLANNING_AUTHORIZATION_DENIED = "FortiPAM V4 planning authorization denied."
V4_PLANNING_TOOL_NAMES = (
    "preview_v4_administrative_intent",
    "confirm_v4_administrative_intent",
    "prepare_v4_non_executable_plan",
    "get_v4_plan_status",
    "get_v4_firmware_upgrade_plan_requirements",
    "build_v4_firmware_upgrade_plan",
    "get_v4_backup_create_plan_requirements",
    "build_v4_backup_create_plan",
    "get_v4_backup_restore_plan_requirements",
    "build_v4_backup_restore_plan",
    "get_v4_license_install_plan_requirements",
    "build_v4_license_install_plan",
    "get_v4_system_email_plan_requirements",
    "build_v4_system_email_plan",
    "get_v4_email_alert_plan_requirements",
    "build_v4_email_alert_plan",
    "get_v4_glass_break_plan_requirements",
    "get_v4_route_plan_requirements",
    "build_v4_route_plan",
    "get_v4_dns_plan_requirements",
    "build_v4_dns_plan",
    "get_v4_ha_configure_plan_requirements",
    "build_v4_ha_configure_plan",
    "get_v4_ha_maintenance_plan_requirements",
    "build_v4_ha_maintenance_plan",
    "get_v4_ha_reconcile_plan_requirements",
    "build_v4_ha_reconcile_plan",
    "get_v4_certificate_import_plan_requirements",
    "get_v4_crl_import_plan_requirements",
    "get_v4_ldap_server_plan_requirements",
    "get_v4_radius_server_plan_requirements",
    "get_v4_saml_server_plan_requirements",
    "get_v4_temporary_access_plan_requirements",
    "get_v4_jwt_key_create_plan_requirements",
    "get_v4_jwt_key_rotate_plan_requirements",
    "get_v4_scim_client_create_plan_requirements",
    "get_v4_scim_client_rotate_plan_requirements",
    "get_v4_scim_client_disable_plan_requirements",
    "get_v4_fortitoken_assign_plan_requirements",
    "get_v4_fortitoken_revoke_plan_requirements",
    "get_v4_apl_update_plan_requirements",
    "get_v4_discovery_entry_create_plan_requirements",
    "get_v4_discovery_run_plan_requirements",
    "get_v4_discovery_review_plan_requirements",
    "get_v4_job_create_plan_requirements",
    "get_v4_job_execute_plan_requirements",
    "get_v4_password_changer_create_plan_requirements",
    "get_v4_password_verification_plan_requirements",
    "get_v4_checkout_policy_plan_requirements",
    "get_v4_jit_policy_plan_requirements",
    "get_v4_service_account_update_plan_requirements",
    "get_v4_instruction_profile_create_plan_requirements",
    "get_v4_event_subscription_plan_requirements",
    "get_v4_secret_bulk_import_plan_requirements",
    "build_v4_secret_bulk_import_plan",
    "get_v4_secret_bulk_import_apply_requirements",
    "get_v4_launcher_clone_plan_requirements",
    "get_v4_policy_assign_plan_requirements",
    "get_v4_approval_delivery_plan_requirements",
    "get_v4_fabric_connector_plan_requirements",
    "get_v4_secret_gateway_chain_plan_requirements",
    "get_v4_reverse_service_plan_requirements",
    "get_v4_ztna_tag_create_plan_requirements",
    "get_v4_ztna_tag_group_create_plan_requirements",
    "get_v4_target_disable_plan_requirements",
    "get_v4_secret_metadata_update_plan_requirements",
    "get_v4_approval_profile_disable_plan_requirements",
    "get_v4_secret_disable_contract_gap",
    "get_v4_launcher_disable_contract_gap",
)
V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES = tuple(
    name
    for name in V4_PLANNING_TOOL_NAMES
    if name.startswith("get_v4_")
    and (name.endswith("_requirements") or name.endswith("_contract_gap"))
)
MIN_HMAC_KEY_BYTES = 32
MAX_TEXT_BYTES = 256
MAX_TOKEN_BYTES = 8192
_HEX_KEY = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_MISSING = object()


class V4PlanningRuntimeError(RuntimeError):
    """Stable, non-disclosing V4 runtime failure."""


@dataclass(frozen=True, slots=True)
class V4PlanningAuthorizationSettings:
    """Validated OAuth resource and owner-only requester-namespace key."""

    expected_resource: str
    namespace_hmac_key: bytes
    insecure_private_ip_lab: bool = False

    def __post_init__(self) -> None:
        parsed = urlsplit(self.expected_resource)
        if (
            type(self.namespace_hmac_key) is not bytes
            or len(self.namespace_hmac_key) < MIN_HMAC_KEY_BYTES
            or (
                parsed.scheme != "https"
                and not (
                    self.insecure_private_ip_lab
                    and _is_private_lab_http_url(self.expected_resource)
                )
            )
            or not parsed.netloc
            or not parsed.path
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)


@dataclass(frozen=True, slots=True)
class V4PlanningPrincipal:
    """Stable human requester plus client-bound transport namespace."""

    requester: AuthenticatedRequester
    transport_namespace_digest: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.requester, AuthenticatedRequester)
            or _HEX_KEY.fullmatch(self.transport_namespace_digest) is None
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)


def planning_authorization_settings_from_environment(
    environment: Mapping[str, str],
    *,
    expected_resource: str,
    allow_insecure_private_ip_lab: bool = False,
) -> V4PlanningAuthorizationSettings:
    """Load the mandatory owner-only HMAC key for the V4 OAuth profile."""

    raw_path = environment.get(V4_PLANNING_PRINCIPAL_HMAC_KEY_FILE_ENV)
    if type(raw_path) is not str or not raw_path.strip():
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    key_path = Path(raw_path.strip()).expanduser()
    if not key_path.is_absolute():
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    try:
        _assert_no_symlink_components(key_path)
        file_stat = key_path.lstat()
        parent_stat = key_path.parent.lstat()
        if (
            stat.S_ISLNK(file_stat.st_mode)
            or not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != os.getuid()
            or stat.S_IMODE(file_stat.st_mode) != 0o600
            or stat.S_ISLNK(parent_stat.st_mode)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.getuid()
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(key_path, flags)
        try:
            encoded = os.read(descriptor, 129).decode("ascii").strip()
        finally:
            os.close(descriptor)
    except (OSError, UnicodeError):
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED) from None
    if _HEX_KEY.fullmatch(encoded) is None:
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    return V4PlanningAuthorizationSettings(
        expected_resource,
        bytes.fromhex(encoded),
        insecure_private_ip_lab=(
            allow_insecure_private_ip_lab
            and _is_private_lab_http_url(expected_resource)
        ),
    )


def _is_private_lab_http_url(raw: str) -> bool:
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.port is not None
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return False
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return False
    return address.version == 4 and address in ipaddress.ip_network((0x0A000000, 8))


def requester_from_access_token(
    access_token: AccessToken | None,
    settings: V4PlanningAuthorizationSettings,
) -> AuthenticatedRequester:
    """Derive a value-free requester only from SDK-validated token metadata."""

    return planning_principal_from_access_token(access_token, settings).requester


def planning_principal_from_access_token(
    access_token: AccessToken | None,
    settings: V4PlanningAuthorizationSettings,
) -> V4PlanningPrincipal:
    """Derive stable human and client-bound namespaces from a validated token."""

    issuer, client_id, subject, resource = _validated_identity_fields(
        access_token,
        settings,
        required_scope=V4_PLANNING_SCOPE,
        forbidden_scopes=(V4_APPROVAL_SCOPE,),
    )
    subject_ref, identity_authority_ref, subject_namespace = _human_identity_binding(
        settings,
        issuer=issuer,
        subject=subject,
        resource=resource,
    )
    transport_payload = _length_prefixed(
        ("v4-plan-transport-v1", issuer, client_id, subject, resource)
    )
    transport_namespace_digest = hmac.new(
        settings.namespace_hmac_key,
        transport_payload,
        hashlib.sha256,
    ).hexdigest()
    return V4PlanningPrincipal(
        requester=AuthenticatedRequester(
            subject_ref=subject_ref,
            principal_class="operator",
            identity_authority_ref=identity_authority_ref,
            subject_namespace=subject_namespace,
        ),
        transport_namespace_digest=transport_namespace_digest,
    )


def approver_from_access_token(
    access_token: AccessToken | None,
    settings: V4PlanningAuthorizationSettings,
) -> AuthenticatedApprover:
    """Derive one comparable approver identity from a scoped trusted token."""

    issuer, _client_id, subject, resource = _validated_identity_fields(
        access_token,
        settings,
        required_scope=V4_APPROVAL_SCOPE,
        forbidden_scopes=(V4_PLANNING_SCOPE, "fortipam:operate"),
    )
    subject_ref, identity_authority_ref, subject_namespace = _human_identity_binding(
        settings,
        issuer=issuer,
        subject=subject,
        resource=resource,
    )
    return AuthenticatedApprover(
        subject_ref=subject_ref,
        identity_authority_ref=identity_authority_ref,
        subject_namespace=subject_namespace,
    )


def _validated_identity_fields(
    access_token: AccessToken | None,
    settings: V4PlanningAuthorizationSettings,
    *,
    required_scope: str,
    forbidden_scopes: tuple[str, ...],
) -> tuple[str, str, str, str]:
    if not isinstance(access_token, AccessToken):
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    token = _text(_attribute(access_token, "token"), maximum_bytes=MAX_TOKEN_BYTES)
    del token
    client_id = _text(_attribute(access_token, "client_id"))
    subject = _text(_attribute(access_token, "subject"))
    resource = _text(_attribute(access_token, "resource"))
    if resource != settings.expected_resource:
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    expires_at = _attribute(access_token, "expires_at")
    if type(expires_at) is not int or expires_at <= 0:
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    scopes = _scopes(_attribute(access_token, "scopes"))
    if required_scope not in scopes or set(forbidden_scopes) & set(scopes):
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    claims = _attribute(access_token, "claims")
    if not isinstance(claims, Mapping):
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    issuer = _text(claims.get("iss"))
    return issuer, client_id, subject, resource


def _human_identity_binding(
    settings: V4PlanningAuthorizationSettings,
    *,
    issuer: str,
    subject: str,
    resource: str,
) -> tuple[str, str, str]:
    def digest(domain: str, *values: str) -> str:
        return hmac.new(
            settings.namespace_hmac_key,
            _length_prefixed((domain, *values)),
            hashlib.sha256,
        ).hexdigest()

    return (
        digest("v4-human-subject-v1", issuer, subject, resource),
        digest("v4-identity-authority-v1", issuer),
        digest("v4-subject-namespace-v1", issuer, resource),
    )


class TrustedSchemeDraftProvider(Protocol):
    """Resolve only a previously server-issued, value-free Scheme draft ref."""

    def resolve(
        self,
        scheme_draft_ref: str,
        requester: AuthenticatedRequester,
    ) -> SchemeDraft: ...


class OAuthPlanningConfirmationTransport(Protocol):
    """Issue and consume browser confirmation bound to an OAuth client namespace."""

    def issue(
        self,
        summary: FinalIntentSummary,
        requester: AuthenticatedRequester,
        *,
        principal_namespace_digest: str,
        now_epoch: int,
    ) -> str: ...

    def verify(
        self,
        requester: AuthenticatedRequester,
        *,
        principal_namespace_digest: str,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> VerifiedConfirmationInteraction: ...

    def claim(
        self,
        requester: AuthenticatedRequester,
        *,
        principal_namespace_digest: str,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> None: ...


class SecretCreateReadinessProxyProbe(Protocol):
    """Report current downstream availability through a readiness-only proxy."""

    def is_available(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class _PlanningContext:
    requester: AuthenticatedRequester
    principal_namespace_digest: str
    seal: object


class _BoundPrincipalResolver:
    def __init__(self, seal: object) -> None:
        self._seal = seal

    def resolve(self, transport_context: object) -> AuthenticatedRequester:
        if (
            not isinstance(transport_context, _PlanningContext)
            or transport_context.seal is not self._seal
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
        return transport_context.requester


class _BoundConfirmationConsumer:
    def __init__(
        self,
        seal: object,
        transport: OAuthPlanningConfirmationTransport,
    ) -> None:
        self._seal = seal
        self._transport = transport

    def issue(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary: FinalIntentSummary,
        now_epoch: int,
    ) -> str:
        context = self._context(transport_context, requester)
        return self._transport.issue(
            summary,
            requester,
            principal_namespace_digest=context.principal_namespace_digest,
            now_epoch=now_epoch,
        )

    def verify(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> VerifiedConfirmationInteraction:
        context = self._context(transport_context, requester)
        return self._transport.verify(
            requester,
            principal_namespace_digest=context.principal_namespace_digest,
            summary_ref=summary_ref,
            summary_revision=summary_revision,
            now_epoch=now_epoch,
        )

    def claim(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> None:
        context = self._context(transport_context, requester)
        self._transport.claim(
            requester,
            principal_namespace_digest=context.principal_namespace_digest,
            summary_ref=summary_ref,
            summary_revision=summary_revision,
            now_epoch=now_epoch,
        )

    def _context(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
    ) -> _PlanningContext:
        if (
            not isinstance(transport_context, _PlanningContext)
            or transport_context.seal is not self._seal
            or transport_context.requester != requester
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
        return transport_context


class OAuthBoundV4PlanServices:
    """Bind trusted host services to the existing four-operation V4 facade."""

    def __init__(
        self,
        workflow: M3PlanOnlyWorkflowService,
        *,
        draft_provider: TrustedSchemeDraftProvider,
        projection_provider: PlanningProjectionProvider,
        confirmation_consumer: TrustedConfirmationConsumer | None = None,
        confirmation_transport: OAuthPlanningConfirmationTransport | None = None,
        clock: Callable[[], int] | None = None,
        monotonic_checkpoint_protocol_bound: bool = False,
        approval_receipt_authenticator_protocol_bound: bool = False,
        approver_authorization_protocol_bound: bool = False,
        approver_authority_checkpoint_protocol_bound: bool = False,
        scheme_draft_issuance_protocol_bound: bool = False,
        scheme_draft_authority_checkpoint_protocol_bound: bool = False,
        reference_authorization_protocol_bound: bool = False,
        reference_authority_checkpoint_protocol_bound: bool = False,
        secret_create_readiness_proxy_probe: (
            SecretCreateReadinessProxyProbe | None
        ) = None,
    ) -> None:
        self._seal = object()
        self._workflow = workflow
        self._clock = clock or (lambda: int(time.time()))
        self._draft_provider = draft_provider
        if type(monotonic_checkpoint_protocol_bound) is not bool:
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        self._monotonic_checkpoint_protocol_bound = (
            monotonic_checkpoint_protocol_bound
        )
        if type(approval_receipt_authenticator_protocol_bound) is not bool:
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        self._approval_receipt_authenticator_protocol_bound = (
            approval_receipt_authenticator_protocol_bound
        )
        if (
            type(approver_authorization_protocol_bound) is not bool
            or (
                approver_authorization_protocol_bound
                and not approval_receipt_authenticator_protocol_bound
            )
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        self._approver_authorization_protocol_bound = (
            approver_authorization_protocol_bound
        )
        if (
            type(approver_authority_checkpoint_protocol_bound) is not bool
            or (
                approver_authority_checkpoint_protocol_bound
                and not approver_authorization_protocol_bound
            )
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        self._approver_authority_checkpoint_protocol_bound = (
            approver_authority_checkpoint_protocol_bound
        )
        if type(scheme_draft_issuance_protocol_bound) is not bool:
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        self._scheme_draft_issuance_protocol_bound = (
            scheme_draft_issuance_protocol_bound
        )
        if (
            type(scheme_draft_authority_checkpoint_protocol_bound) is not bool
            or (
                scheme_draft_authority_checkpoint_protocol_bound
                and not scheme_draft_issuance_protocol_bound
            )
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        self._scheme_draft_authority_checkpoint_protocol_bound = (
            scheme_draft_authority_checkpoint_protocol_bound
        )
        if type(reference_authorization_protocol_bound) is not bool:
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        self._reference_authorization_protocol_bound = (
            reference_authorization_protocol_bound
        )
        if (
            type(reference_authority_checkpoint_protocol_bound) is not bool
            or (
                reference_authority_checkpoint_protocol_bound
                and not reference_authorization_protocol_bound
            )
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        self._reference_authority_checkpoint_protocol_bound = (
            reference_authority_checkpoint_protocol_bound
        )
        if secret_create_readiness_proxy_probe is not None and not callable(
            getattr(secret_create_readiness_proxy_probe, "is_available", None)
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        self._secret_create_readiness_proxy_protocol_bound = (
            secret_create_readiness_proxy_probe is not None
        )
        self._secret_create_readiness_proxy_probe = (
            secret_create_readiness_proxy_probe
        )
        self._secret_create_execution_preflight_probe: Callable[[], bool] | None = None
        if (confirmation_consumer is None) == (confirmation_transport is None):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        bound_confirmation = confirmation_consumer
        if confirmation_transport is not None:
            bound_confirmation = _BoundConfirmationConsumer(
                self._seal,
                confirmation_transport,
            )
        assert bound_confirmation is not None
        self._facade = V4PlanOnlyMcpFacade(
            workflow,
            principal_resolver=_BoundPrincipalResolver(self._seal),
            projection_provider=projection_provider,
            confirmation_consumer=bound_confirmation,
            clock=clock,
            planner_mcp_exposed=True,
        )

    def preview(
        self,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
        *,
        prior_summary_ref: str | None = None,
    ) -> dict[str, object]:
        _require_opaque_ref(scheme_draft_ref)
        requester = principal.requester
        draft = self._draft_provider.resolve(scheme_draft_ref, requester)
        if not isinstance(draft, SchemeDraft):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        return dict(
            self._facade.preview(
                draft,
                transport_context=self._context(principal),
                prior_summary_ref=prior_summary_ref,
            )
        )

    def confirm(
        self,
        summary_ref: str,
        summary_revision: int,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]:
        requester = principal.requester
        return dict(
            self._facade.consume_confirmation(
                summary_ref,
                summary_revision,
                transport_context=self._context(principal),
            )
        )

    def prepare(
        self,
        summary_ref: str,
        confirmation_ref: str,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]:
        requester = principal.requester
        result: dict[str, object] = dict(
            self._facade.prepare_plan(
                summary_ref,
                confirmation_ref,
                transport_context=self._context(principal),
            )
        )
        if result.get("planner_mcp_exposed") is not True:
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        return result

    def evaluate_pre_write(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]:
        """Perform the internal source-backed reread before fixed dispatch."""

        _require_opaque_ref(plan_ref)
        _require_opaque_ref(scheme_draft_ref)
        draft = self._draft_provider.resolve(
            scheme_draft_ref,
            principal.requester,
        )
        if not isinstance(draft, SchemeDraft):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        return dict(
            self._facade._evaluate_pre_write(
                plan_ref,
                draft,
                transport_context=self._context(principal),
            )
        )

    def evaluate_post_write(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]:
        """Perform the internal source-backed readback after fixed dispatch."""

        _require_opaque_ref(plan_ref)
        _require_opaque_ref(scheme_draft_ref)
        draft = self._draft_provider.resolve(
            scheme_draft_ref,
            principal.requester,
        )
        if not isinstance(draft, SchemeDraft):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        return dict(
            self._facade._evaluate_post_write(
                plan_ref,
                draft,
                transport_context=self._context(principal),
            )
        )

    def resolve_execution_context(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> tuple[PreparedPlan, SchemeDraft]:
        """Resolve the exact internal plan/draft pair without exposing it as MCP."""

        _require_opaque_ref(plan_ref)
        _require_opaque_ref(scheme_draft_ref)
        draft = self._draft_provider.resolve(
            scheme_draft_ref,
            principal.requester,
        )
        if not isinstance(draft, SchemeDraft):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        plan = self._workflow.resolve_prepared_plan(
            plan_ref,
            principal.requester,
            now_epoch=self._clock(),
        )
        if (
            plan.scheme_id is not draft.scheme_id
            or plan.scheme_version != draft.scheme_version
            or plan.environment_ref != draft.environment_ref
            or plan.scope_ref != draft.scope_ref
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        return plan, draft

    def status(self) -> dict[str, object]:
        status: dict[str, object] = dict(self._facade.status())
        blocker_value = status.get("blocker_codes")
        if not isinstance(blocker_value, list) or not all(
            type(code) is str for code in blocker_value
        ):
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        blockers: list[str] = list(blocker_value)
        if self._approval_receipt_authenticator_protocol_bound:
            try:
                blockers.remove("approval_receipt_not_independently_signed")
            except ValueError as exc:
                raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE) from exc
        if self._scheme_draft_issuance_protocol_bound:
            try:
                blockers.remove("scheme_draft_issuance_unbound")
            except ValueError as exc:
                raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE) from exc
        status["blocker_codes"] = blockers
        status["mcp_tool_names"] = list(V4_PLANNING_TOOL_NAMES)
        status["fixed_no_input_plan_tool_names"] = list(
            V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES
        )
        status["fixed_no_input_plan_tool_count"] = len(
            V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES
        )
        status["monotonic_checkpoint_protocol_bound"] = (
            self._monotonic_checkpoint_protocol_bound
        )
        status["approval_receipt_authenticator_protocol_bound"] = (
            self._approval_receipt_authenticator_protocol_bound
        )
        status["approver_authorization_protocol_bound"] = (
            self._approver_authorization_protocol_bound
        )
        status["approver_authority_checkpoint_protocol_bound"] = (
            self._approver_authority_checkpoint_protocol_bound
        )
        status["scheme_draft_issuance_protocol_bound"] = (
            self._scheme_draft_issuance_protocol_bound
        )
        status["scheme_draft_authority_checkpoint_protocol_bound"] = (
            self._scheme_draft_authority_checkpoint_protocol_bound
        )
        status["reference_authorization_protocol_bound"] = (
            self._reference_authorization_protocol_bound
        )
        status["reference_authority_checkpoint_protocol_bound"] = (
            self._reference_authority_checkpoint_protocol_bound
        )
        status["secret_create_private_runtime_protocol_bound"] = False
        status["secret_create_readiness_proxy_protocol_bound"] = (
            self._secret_create_readiness_proxy_protocol_bound
        )
        status["secret_create_private_runtime_available"] = (
            self._secret_create_private_runtime_available()
        )
        status["secret_create_execution_preflight_available"] = (
            self._secret_create_execution_preflight_available()
        )
        public_refs = getattr(self._draft_provider, "public_refs", None)
        if callable(public_refs):
            refs = public_refs()
            if (
                isinstance(refs, tuple)
                and refs
                and all(type(value) is str and _OPAQUE_REF.fullmatch(value) for value in refs)
            ):
                status["synthetic_scheme_draft_refs"] = list(refs)
        return status

    def bind_secret_create_execution_preflight_probe(
        self, probe: Callable[[], bool]
    ) -> None:
        """Bind one host-owned read-only probe after the create action is bound."""

        if not callable(probe) or self._secret_create_execution_preflight_probe is not None:
            raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
        self._secret_create_execution_preflight_probe = probe

    def _secret_create_execution_preflight_available(self) -> bool:
        probe = self._secret_create_execution_preflight_probe
        if probe is None:
            return False
        try:
            available = probe()
        except Exception:
            return False
        return available if type(available) is bool else False

    def _secret_create_private_runtime_available(self) -> bool:
        probe = self._secret_create_readiness_proxy_probe
        if probe is None:
            return False
        try:
            available = probe.is_available()
        except Exception:
            return False
        return available if type(available) is bool else False

    def _context(self, principal: V4PlanningPrincipal) -> _PlanningContext:
        if not isinstance(principal, V4PlanningPrincipal):
            raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
        return _PlanningContext(
            principal.requester,
            principal.transport_namespace_digest,
            self._seal,
        )


def unbound_v4_plan_status() -> dict[str, object]:
    """Return truthful no-host-service status without creating authority."""

    return {
        "adapter_registry_bound": True,
        "blocker_codes": [
            "approval_receipt_not_independently_signed",
            "confirmation_transport_unbound",
            "external_monotonic_checkpoint_unbound",
            "host_services_unbound",
            "independent_approver_identity_unbound",
            "live_projection_unbound",
            "product_idempotency_unproven",
            "scheme_draft_issuance_unbound",
        ],
        "device_access": False,
        "dispatchable": False,
        "executor_mcp_exposed": False,
        "executor_runtime_packaged": True,
        "host_services_bound": False,
        "operation_names": ["status", "preview", "consume_confirmation", "prepare_plan"],
        "mcp_tool_names": list(V4_PLANNING_TOOL_NAMES),
        "fixed_no_input_plan_tool_names": list(V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES),
        "fixed_no_input_plan_tool_count": len(V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES),
        "monotonic_checkpoint_protocol_bound": False,
        "approval_receipt_authenticator_protocol_bound": False,
        "approver_authorization_protocol_bound": False,
        "approver_authority_checkpoint_protocol_bound": False,
        "scheme_draft_issuance_protocol_bound": False,
        "scheme_draft_authority_checkpoint_protocol_bound": False,
        "reference_authorization_protocol_bound": False,
        "reference_authority_checkpoint_protocol_bound": False,
        "secret_create_private_runtime_protocol_bound": False,
        "secret_create_readiness_proxy_protocol_bound": False,
        "secret_create_private_runtime_available": False,
        "secret_create_execution_preflight_available": False,
        "planner_mcp_exposed": True,
        "planner_runtime_packaged": True,
        "product_write_enabled": False,
        "projection_mode": "deny_all",
        "runtime_profile": "v4-plan-only",
        "runtime_version": "4.0.0-beta.7",
    }


def _require_opaque_ref(value: object) -> str:
    if type(value) is not str or _OPAQUE_REF.fullmatch(value) is None:
        raise V4PlanningRuntimeError(V4_PLANNING_UNAVAILABLE)
    return value


def _attribute(value: object, name: str) -> object:
    try:
        result = getattr(value, name, _MISSING)
    except Exception:
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED) from None
    if result is _MISSING:
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    return result


def _text(value: object, *, maximum_bytes: int = MAX_TEXT_BYTES) -> str:
    if type(value) is not str or not value or not value.strip():
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED) from None
    if len(encoded) > maximum_bytes or any(ord(character) < 0x20 for character in value):
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    return value


def _scopes(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, (list, tuple)):
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    result = tuple(_text(item) for item in value)
    if len(result) != len(set(result)) or any(any(char.isspace() for char in item) for item in result):
        raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)
    return result


def _length_prefixed(fields: tuple[str, ...]) -> bytes:
    payload = bytearray()
    for field in fields:
        encoded = field.encode("utf-8")
        payload.extend(len(encoded).to_bytes(4, "big"))
        payload.extend(encoded)
    return bytes(payload)


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if not current.exists() and not current.is_symlink():
            return
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise V4PlanningRuntimeError(V4_PLANNING_AUTHORIZATION_DENIED)


__all__ = [
    "OAuthBoundV4PlanServices",
    "OAuthPlanningConfirmationTransport",
    "SecretCreateReadinessProxyProbe",
    "TrustedSchemeDraftProvider",
    "V4_PLANNING_AUTHORIZATION_DENIED",
    "V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES",
    "V4_PLANNING_PREFIX",
    "V4_PLANNING_PRINCIPAL_HMAC_KEY_FILE_ENV",
    "V4_PLANNING_SCOPE",
    "V4_PLANNING_TOOL_NAMES",
    "V4_PLANNING_UNAVAILABLE",
    "V4PlanningAuthorizationSettings",
    "V4PlanningPrincipal",
    "V4PlanningRuntimeError",
    "planning_principal_from_access_token",
    "planning_authorization_settings_from_environment",
    "requester_from_access_token",
    "unbound_v4_plan_status",
]
