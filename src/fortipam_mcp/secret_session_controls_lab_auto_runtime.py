"""Private lab-auto promotion for the fixed BP006 existing-Secret SSH fallback.

This module consumes already prepared, confirmed M2 records.  It does not
issue a human approval, create an endpoint, or register a runtime action.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan, M4ExecutionStateStore, ObjectClass, canonical_digest
from v4_planning.canonical import CanonicalValue
from v4_planning.models import ConfirmationRecord, FinalIntentSummary, PreparedPlan, SchemeDraft, require_ref

from .secret_session_controls_m4_authorization import (
    SecretApprovalPlanningChainReader,
    validate_secret_session_controls_lab_auto_source,
)
from .secret_session_controls_m4_composition import (
    ExactSecretSessionControlsM4RunnerFactory,
)
from .secret_session_controls_m4_runtime import (
    SECRET_SESSION_CONTROLS_ACTION_ID,
    SECRET_SESSION_CONTROLS_ACTION_VERSION,
    SECRET_SESSION_CONTROLS_ADAPTER_REF,
    ProtectedSecretSessionControlsM4Runtime,
    SecretSessionControlsBinding,
    SecretSessionControlsM4ExecutionBinding,
    RdpEventFilterReadTransport,
    SecretSessionControlsReadTransport,
    SecretSessionControlsWriteTransport,
    secret_session_controls_parameters_digest,
    secret_session_controls_state_digest,
)
from .secret_metadata_http_transport import secret_session_controls_event_filter_profile_digest
from .secret_onboarding_projection_source import SecretOnboardingBinding, SecretOnboardingProductBinding
from .onboarding_action_coordinator import BoundFixedActionRunner
from .v4_plan_runtime import V4PlanningPrincipal
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_lab_auto_runtime import (
    LAB_AUTO_SECRET_CREATE_ENV_PREFIX,
    _absolute_path,
    _read_owner_only_authority_key,
    load_lab_auto_secret_create_authorized_scope,
)


LAB_AUTO_SECRET_SESSION_CONTROLS_AUTHORITY_REF = "fortipam-mcp-lab-auto-secret-session-controls"
LAB_AUTO_SECRET_SESSION_CONTROLS_TTL_SECONDS = 60
_UNAVAILABLE = "Secret session-controls lab-auto promotion is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class LabAutoSecretSessionControlsArtifacts:
    """Value-free fixed M4 records plus the audit policy marker."""

    binding: SecretSessionControlsM4ExecutionBinding
    policy_decision_digest: str
    audit_attributes: Mapping[str, bool]


class LabAutoSecretSessionControlsPromoter:
    """Promote exactly one stored BP006 C/P/E chain under local lab policy."""

    def __init__(self, authority_key: bytes, *, authorized_environment_ref: str,
                 authorized_scope_ref: str,
                 authority_ref: str = LAB_AUTO_SECRET_SESSION_CONTROLS_AUTHORITY_REF) -> None:
        try:
            if type(authority_key) is not bytes or len(authority_key) < 32:
                raise ValueError
            self._authority_ref = require_ref(authority_ref, "authority_ref")
            self._environment_ref = require_ref(authorized_environment_ref, "environment_ref")
            self._scope_ref = require_ref(authorized_scope_ref, "scope_ref")
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None
        self._authority_key = bytes(authority_key)

    def promote(self, summary: FinalIntentSummary, confirmation: ConfirmationRecord,
                plan: PreparedPlan, controls: SecretSessionControlsBinding, *,
                onboarding_binding: SecretOnboardingBinding, now_epoch: int) -> LabAutoSecretSessionControlsArtifacts:
        try:
            if type(now_epoch) is not int or plan.environment_ref != self._environment_ref or plan.scope_ref != self._scope_ref:
                raise ValueError
            validate_secret_session_controls_lab_auto_source(
                summary, confirmation, plan, controls, onboarding_binding, now_epoch=now_epoch
            )
            line = plan.lines[0]
            expires_at = min(
                now_epoch + LAB_AUTO_SECRET_SESSION_CONTROLS_TTL_SECONDS,
                plan.expires_at, summary.expires_at, confirmation.expires_at,
                *(change.fresh_until for change in summary.object_changes),
            )
            if now_epoch >= expires_at:
                raise ValueError
            parameters_digest = secret_session_controls_parameters_digest(controls)
            current_digest = secret_session_controls_state_digest(
                controls, preserved_identity_relations_digest=controls.preserved_identity_relations_digest,
                rdp_event_filter_profile_digest=controls.prewrite_rdp_event_filter_profile_digest,
                recording_enabled=controls.prewrite_recording_enabled,
                clipboard_blocking_enabled=controls.prewrite_clipboard_blocking_enabled,
                rdp_event_filter_enabled=controls.prewrite_rdp_event_filter_enabled,
                rdp_event_filter_profile_matches=controls.prewrite_rdp_event_filter_profile_matches,
                target_ref=line.target_ref,
            )
            expected_digest = secret_session_controls_state_digest(
                controls, preserved_identity_relations_digest=controls.preserved_identity_relations_digest,
                rdp_event_filter_profile_digest=secret_session_controls_event_filter_profile_digest(controls.rdp_event_filter_profile_name),
                recording_enabled=True, clipboard_blocking_enabled=True,
                rdp_event_filter_enabled=True, rdp_event_filter_profile_matches=True,
                target_ref=line.target_ref,
            )
            context = {"confirmation_digest": plan.confirmation_digest, "plan_digest": plan.plan_digest,
                       "requester_digest": plan.requester_digest, "target_ref": line.target_ref}
            approval_digest = self._mac("policy-approval", context)
            idempotency_digest = self._mac("idempotency", context)
            values: dict[str, CanonicalValue] = {
                "action_id": SECRET_SESSION_CONTROLS_ACTION_ID, "action_version": SECRET_SESSION_CONTROLS_ACTION_VERSION,
                "adapter_ref": SECRET_SESSION_CONTROLS_ADAPTER_REF, "approval_digest": approval_digest,
                "compensation_ref": None, "confirmation_digest": plan.confirmation_digest,
                "expected_current_digest": current_digest, "expected_state_digest": expected_digest,
                "expires_at": expires_at, "idempotency_digest": idempotency_digest,
                "parameters_digest": parameters_digest, "plan_ref": plan.plan_ref, "requester_digest": plan.requester_digest,
                "revision": plan.revision, "summary_digest": plan.summary_digest, "target_ref": line.target_ref,
            }
            m4_plan = M4ExecutionPlan(plan_ref=plan.plan_ref, revision=plan.revision,
                action_id=SECRET_SESSION_CONTROLS_ACTION_ID, action_version=SECRET_SESSION_CONTROLS_ACTION_VERSION,
                adapter_ref=SECRET_SESSION_CONTROLS_ADAPTER_REF, target_ref=line.target_ref,
                requester_digest=plan.requester_digest, summary_digest=plan.summary_digest,
                confirmation_digest=plan.confirmation_digest, approval_digest=approval_digest,
                parameters_digest=parameters_digest, expected_current_digest=current_digest,
                expected_state_digest=expected_digest, idempotency_digest=idempotency_digest,
                expires_at=expires_at, compensation_ref=None, plan_digest=canonical_digest(values))
            authorization_ref = "lab-auto-controls-auth-" + self._mac("authorization", {"plan": m4_plan.plan_digest})
            approver_digest = self._mac("authority", {"ref": self._authority_ref})
            auth_values: dict[str, CanonicalValue] = {"approval_digest": approval_digest,
                "approval_ref": self._authority_ref, "approver_digest": approver_digest,
                "authorization_ref": authorization_ref, "confirmation_digest": plan.confirmation_digest,
                "confirmation_ref": plan.confirmation_ref, "execution_authorized": True, "expires_at": expires_at,
                "issued_at": now_epoch, "one_time": True, "plan_digest": m4_plan.plan_digest,
                "plan_ref": m4_plan.plan_ref, "requester_digest": m4_plan.requester_digest}
            authorization = M4ExecutionAuthorization(authorization_ref=authorization_ref, plan_ref=m4_plan.plan_ref,
                plan_digest=m4_plan.plan_digest, requester_digest=m4_plan.requester_digest,
                confirmation_ref=plan.confirmation_ref, confirmation_digest=plan.confirmation_digest,
                approval_ref=self._authority_ref, approval_digest=approval_digest, approver_digest=approver_digest,
                issued_at=now_epoch, expires_at=expires_at, one_time=True, execution_authorized=True,
                authorization_digest=canonical_digest(auth_values))
            return LabAutoSecretSessionControlsArtifacts(
                SecretSessionControlsM4ExecutionBinding(m4_plan, authorization, controls),
                self._mac("policy", {**context, "lab_auto": True}),
                MappingProxyType({"lab_auto": True}),
            )
        except M4AuthorizationDenied:
            raise
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None

    def _mac(self, purpose: str, value: Mapping[str, object]) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return hmac.new(self._authority_key, b"fortipam-session-controls-lab-auto-v1\x00" + purpose.encode() + b"\x00" + encoded, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class _FixedBindingResolver:
    authorization_ref: str
    binding: SecretSessionControlsM4ExecutionBinding

    def resolve_execution_binding(
        self, authorization_ref: str
    ) -> SecretSessionControlsM4ExecutionBinding:
        if authorization_ref != self.authorization_ref:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return self.binding


class _PinnedLabAutoAuthorizationVerifier:
    """Verify the one generated lab-policy record without reissuing it."""

    def __init__(self, artifacts: LabAutoSecretSessionControlsArtifacts) -> None:
        self._binding = artifacts.binding

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        expected = self._binding
        if (
            type(now_epoch) is not int
            or plan != expected.plan
            or authorization != expected.authorization
            or canonical_digest(plan.canonical_content()) != plan.plan_digest
            or canonical_digest(authorization.canonical_content()) != authorization.authorization_digest
            or now_epoch < authorization.issued_at
            or now_epoch >= authorization.expires_at
            or now_epoch >= plan.expires_at
        ):
            raise M4AuthorizationDenied(_UNAVAILABLE)


def assemble_lab_auto_secret_session_controls_m4_runner_factory(
    *,
    planning: SecretApprovalPlanningChainReader,
    promoter: LabAutoSecretSessionControlsPromoter,
    onboarding_binding: SecretOnboardingBinding,
    session_controls_binding: SecretSessionControlsBinding,
    source_plan_ref: str,
    authenticated_requester_digest: str,
    read_transport: SecretSessionControlsReadTransport,
    write_transport: SecretSessionControlsWriteTransport,
    rdp_event_filter_transport: RdpEventFilterReadTransport,
    execution_store: M4ExecutionStateStore,
    clock: Callable[[], int] | None = None,
) -> ExactSecretSessionControlsM4RunnerFactory:
    """Assemble one pinned lab-auto BP006 runner from stored C/P/E records."""

    trusted_clock = clock or (lambda: int(time.time()))
    try:
        now_epoch = trusted_clock()
        if type(now_epoch) is not int:
            raise ValueError
        plan = planning.get_plan(source_plan_ref)
        if plan.requester_digest != authenticated_requester_digest:
            raise ValueError
        summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
        confirmation = planning.get_confirmation(plan.confirmation_ref)
        artifacts = promoter.promote(
            summary, confirmation, plan, session_controls_binding,
            onboarding_binding=onboarding_binding, now_epoch=now_epoch,
        )
        runtime = ProtectedSecretSessionControlsM4Runtime(
            _FixedBindingResolver(
                artifacts.binding.authorization.authorization_ref, artifacts.binding
            ),
            _PinnedLabAutoAuthorizationVerifier(artifacts),
            execution_store,
            write_transport,
            read_transport,
            rdp_event_filter_transport,
            authenticated_requester_digest=authenticated_requester_digest,
            clock=trusted_clock,
        )
        return ExactSecretSessionControlsM4RunnerFactory(
            plan, onboarding_binding, artifacts.binding, runtime
        )
    except M4AuthorizationDenied:
        raise
    except Exception:
        raise M4AuthorizationDenied(_UNAVAILABLE) from None


class LabAutoSecretSessionControlsRunnerFactory:
    """Delay exact BP006 lab-auto promotion until a protected plan is bound."""

    def __init__(self, *, planning: SecretApprovalPlanningChainReader,
                 promoter: LabAutoSecretSessionControlsPromoter,
                 session_controls_binding: SecretSessionControlsBinding | None = None,
                 read_transport: SecretSessionControlsReadTransport,
                 write_transport: SecretSessionControlsWriteTransport,
                 rdp_event_filter_transport: RdpEventFilterReadTransport,
                 execution_store: M4ExecutionStateStore,
                 clock: Callable[[], int] | None = None) -> None:
        self._planning = planning
        self._promoter = promoter
        self._configured_controls = session_controls_binding
        self._read_transport = read_transport
        self._write_transport = write_transport
        self._rdp_event_filter_transport = rdp_event_filter_transport
        self._execution_store = execution_store
        self._clock = clock

    def bind(self, plan: PreparedPlan, line_ref: str, principal: V4PlanningPrincipal,
             *, draft: SchemeDraft | None = None,
             onboarding_binding: SecretOnboardingProductBinding | None = None) -> BoundFixedActionRunner:
        try:
            if (
                not isinstance(onboarding_binding, SecretOnboardingBinding)
                or plan.requester_digest != principal.requester.digest
                or line_ref != plan.lines[0].line_ref
            ):
                raise ValueError
            summary = self._planning.get_summary(
                plan.summary_ref, plan.summary_revision
            )
            controls = _controls_from_confirmed_summary(
                summary, onboarding_binding
            )
            if (
                self._configured_controls is not None
                and self._configured_controls != controls
            ):
                raise ValueError
            factory = assemble_lab_auto_secret_session_controls_m4_runner_factory(
                planning=self._planning, promoter=self._promoter,
                onboarding_binding=onboarding_binding,
                session_controls_binding=controls, source_plan_ref=plan.plan_ref,
                authenticated_requester_digest=principal.requester.digest,
                read_transport=self._read_transport, write_transport=self._write_transport,
                rdp_event_filter_transport=self._rdp_event_filter_transport,
                execution_store=self._execution_store, clock=self._clock,
            )
            if factory.source_plan != plan:
                raise ValueError
            return factory.bind(plan, line_ref, principal, draft=draft,
                                onboarding_binding=onboarding_binding)
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None


def _controls_from_confirmed_summary(
    summary: FinalIntentSummary,
    onboarding: SecretOnboardingBinding,
) -> SecretSessionControlsBinding:
    """Derive the fixed private control binding from authoritative C/P/E state."""

    try:
        changes = [
            change for change in summary.object_changes
            if change.object_class is ObjectClass.SECRET_SESSION_CONTROLS_BINDING
        ]
        if len(changes) != 1:
            raise ValueError
        current = dict(changes[0].current_fields)
        if (
            changes[0].object_ref != onboarding.secret_session_controls_object_ref
            or current.get("preserved_identity_digest")
            != onboarding.session_controls_identity_digest
            or current.get("profile_ref") != onboarding.rdp_event_filter_profile_ref
            or onboarding.existing_secret_id is None
            or onboarding.rdp_event_filter_profile_ref is None
            or onboarding.rdp_event_filter_profile_name is None
        ):
            raise ValueError
        return SecretSessionControlsBinding(
            secret_session_controls_object_ref=(
                onboarding.secret_session_controls_object_ref
            ),
            folder_ref=onboarding.folder_ref,
            folder_path=onboarding.folder_path,
            secret_name=onboarding.secret_name,
            template_ref=onboarding.template_ref,
            template_name=onboarding.template_name,
            target_ref=onboarding.target_object_ref,
            target_name=onboarding.target_name,
            secret_id=onboarding.existing_secret_id,
            rdp_event_filter_profile_ref=onboarding.rdp_event_filter_profile_ref,
            rdp_event_filter_profile_name=onboarding.rdp_event_filter_profile_name,
            prewrite_recording_enabled=_bool(current, "recording_enabled"),
            prewrite_clipboard_blocking_enabled=_bool(
                current, "clipboard_blocking_enabled"
            ),
            prewrite_rdp_event_filter_enabled=_bool(
                current, "rdp_event_filter_enabled"
            ),
            prewrite_rdp_event_filter_profile_matches=_bool(
                current, "rdp_event_filter_profile_matches"
            ),
            prewrite_rdp_event_filter_profile_digest=_digest(
                current, "event_filter_profile_digest"
            ),
            preserved_identity_relations_digest=_digest(
                current, "preserved_identity_digest"
            ),
        )
    except Exception:
        raise M4AuthorizationDenied(_UNAVAILABLE) from None


def _bool(values: Mapping[str, object], name: str) -> bool:
    value = values.get(name)
    if type(value) is not bool:
        raise ValueError
    return value


def _digest(values: Mapping[str, object], name: str) -> str:
    value = values.get(name)
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError
    return value


def build_lab_auto_secret_session_controls_runner_factory(
    environment: Mapping[str, str],
    *,
    planning: SecretApprovalPlanningChainReader,
    read_transport: SecretSessionControlsReadTransport,
    write_transport: SecretSessionControlsWriteTransport,
    rdp_event_filter_transport: RdpEventFilterReadTransport,
    clock: Callable[[], int] | None = None,
) -> LabAutoSecretSessionControlsRunnerFactory:
    """Reuse the existing owner-only lab policy key and execution ledger."""

    try:
        authority_key_path = _absolute_path(environment, "AUTHORITY_KEY_FILE")
        execution_database_path = _absolute_path(environment, "EXECUTION_STATE_DB")
        execution_key_path = _absolute_path(
            environment, "EXECUTION_STATE_HMAC_KEY_FILE"
        )
        if len({authority_key_path, execution_database_path, execution_key_path}) != 3:
            raise ValueError
        authority_key = _read_owner_only_authority_key(authority_key_path)
        environment_ref, scope_ref = load_lab_auto_secret_create_authorized_scope(
            environment
        )
        execution_store = PersistentM4ExecutionStateStore(
            execution_database_path,
            execution_key_path,
        )
        return LabAutoSecretSessionControlsRunnerFactory(
            planning=planning,
            promoter=LabAutoSecretSessionControlsPromoter(
                authority_key,
                authorized_environment_ref=environment_ref,
                authorized_scope_ref=scope_ref,
            ),
            read_transport=read_transport,
            write_transport=write_transport,
            rdp_event_filter_transport=rdp_event_filter_transport,
            execution_store=execution_store,
            clock=clock,
        )
    except Exception:
        raise M4AuthorizationDenied(_UNAVAILABLE) from None


__all__ = ["LAB_AUTO_SECRET_SESSION_CONTROLS_AUTHORITY_REF", "LAB_AUTO_SECRET_SESSION_CONTROLS_TTL_SECONDS", "LabAutoSecretSessionControlsArtifacts", "LabAutoSecretSessionControlsPromoter", "LabAutoSecretSessionControlsRunnerFactory", "assemble_lab_auto_secret_session_controls_m4_runner_factory", "build_lab_auto_secret_session_controls_runner_factory"]
