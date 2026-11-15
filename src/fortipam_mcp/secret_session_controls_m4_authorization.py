"""Promote one signed BP006 controls-only M3 chain to an exact M4 binding."""

from __future__ import annotations

from typing import cast

from v4_planning import (
    ApprovalReceiptAuthenticationAuthority,
    ChangeKind,
    M4AuthorizationDenied,
    M4ExecutionAuthorization,
    M4ExecutionPlan,
    ObjectClass,
    SchemeId,
    canonical_digest,
)
from v4_planning.canonical import CanonicalValue
from v4_planning.models import ConfirmationRecord, FinalIntentSummary, PreparedPlan

from .secret_approval_m4_authorization import (
    SecretApprovalPlanningChainReader,
    _PlanningChain,
    _validate_approval_chain,
)
from .secret_metadata_http_transport import (
    secret_session_controls_event_filter_profile_digest,
)
from .secret_onboarding_projection_source import (
    SECRET_SESSION_CONTROLS_SOURCE_CONTRACT,
    SECRET_SESSION_CONTROLS_SOURCE_REF,
    SECRET_SESSION_CONTROLS_SOURCE_VERSION,
    SOURCE_CONTRACT,
    SOURCE_REF,
    SOURCE_VERSION,
    SecretOnboardingBinding,
)
from .secret_session_controls_m4_runtime import (
    SECRET_SESSION_CONTROLS_ACTION_ID,
    SECRET_SESSION_CONTROLS_ACTION_VERSION,
    SECRET_SESSION_CONTROLS_ADAPTER_REF,
    SecretSessionControlsBinding,
    SecretSessionControlsM4ExecutionBinding,
    secret_session_controls_parameters_digest,
    secret_session_controls_state_digest,
)


_UNAVAILABLE = "Trusted Secret session-controls authorization is unavailable."
_ACTION_FAMILY = "windows-and-ad-privileged-access-plan"
_ACTION_FAMILY_VERSION = "1.0.0"


class SecretSessionControlsM4AuthorizationError(M4AuthorizationDenied):
    """Stable denial for an incomplete or mismatched BP006 approval chain."""


def promote_secret_session_controls_m4_binding(
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    session_controls_binding: SecretSessionControlsBinding,
    *,
    onboarding_binding: SecretOnboardingBinding,
    source_plan_ref: str,
    approval_receipt_ref: str,
    approver_authority_ref: str,
    authorization_ref: str,
    now_epoch: int,
) -> SecretSessionControlsM4ExecutionBinding:
    """Derive one fixed controls-only M4 binding from a claimed signed receipt."""

    chain = _validated_chain(
        planning, receipt_authenticator, session_controls_binding,
        onboarding_binding=onboarding_binding, source_plan_ref=source_plan_ref,
        approval_receipt_ref=approval_receipt_ref,
        approver_authority_ref=approver_authority_ref, now_epoch=now_epoch,
    )
    plan, receipt, claim = chain.plan, chain.receipt, chain.claim
    line = plan.lines[0]
    expires_at = min(
        plan.expires_at, chain.summary.expires_at, chain.confirmation.expires_at,
        chain.decision.expires_at, receipt.expires_at,
        *(change.fresh_until for change in chain.summary.object_changes),
    )
    parameters_digest = secret_session_controls_parameters_digest(
        session_controls_binding
    )
    current_digest = secret_session_controls_state_digest(
        session_controls_binding,
        preserved_identity_relations_digest=(
            session_controls_binding.preserved_identity_relations_digest
        ),
        rdp_event_filter_profile_digest=(
            session_controls_binding.prewrite_rdp_event_filter_profile_digest
        ),
        recording_enabled=session_controls_binding.prewrite_recording_enabled,
        clipboard_blocking_enabled=(
            session_controls_binding.prewrite_clipboard_blocking_enabled
        ),
        rdp_event_filter_enabled=(
            session_controls_binding.prewrite_rdp_event_filter_enabled
        ),
        rdp_event_filter_profile_matches=(
            session_controls_binding.prewrite_rdp_event_filter_profile_matches
        ),
        target_ref=line.target_ref,
    )
    expected_digest = secret_session_controls_state_digest(
        session_controls_binding,
        preserved_identity_relations_digest=(
            session_controls_binding.preserved_identity_relations_digest
        ),
        rdp_event_filter_profile_digest=(
            secret_session_controls_event_filter_profile_digest(
                session_controls_binding.rdp_event_filter_profile_name
            )
        ),
        recording_enabled=True, clipboard_blocking_enabled=True,
        rdp_event_filter_enabled=True, rdp_event_filter_profile_matches=True,
        target_ref=line.target_ref,
    )
    idempotency_digest = canonical_digest({
        "action_id": SECRET_SESSION_CONTROLS_ACTION_ID,
        "action_version": SECRET_SESSION_CONTROLS_ACTION_VERSION,
        "approval_digest": receipt.receipt_digest,
        "parameters_digest": parameters_digest,
        "source_plan_digest": plan.plan_digest,
        "target_ref": line.target_ref,
    })
    values: dict[str, CanonicalValue] = {
        "action_id": SECRET_SESSION_CONTROLS_ACTION_ID,
        "action_version": SECRET_SESSION_CONTROLS_ACTION_VERSION,
        "adapter_ref": SECRET_SESSION_CONTROLS_ADAPTER_REF,
        "approval_digest": receipt.receipt_digest,
        "compensation_ref": None,
        "confirmation_digest": plan.confirmation_digest,
        "expected_current_digest": current_digest,
        "expected_state_digest": expected_digest,
        "expires_at": expires_at,
        "idempotency_digest": idempotency_digest,
        "parameters_digest": parameters_digest,
        "plan_ref": plan.plan_ref,
        "requester_digest": plan.requester_digest,
        "revision": plan.revision,
        "summary_digest": plan.summary_digest,
        "target_ref": line.target_ref,
    }
    try:
        m4_plan = M4ExecutionPlan(
            plan_ref=plan.plan_ref, revision=plan.revision,
            action_id=SECRET_SESSION_CONTROLS_ACTION_ID,
            action_version=SECRET_SESSION_CONTROLS_ACTION_VERSION,
            adapter_ref=SECRET_SESSION_CONTROLS_ADAPTER_REF,
            target_ref=line.target_ref, requester_digest=plan.requester_digest,
            summary_digest=plan.summary_digest,
            confirmation_digest=plan.confirmation_digest,
            approval_digest=receipt.receipt_digest,
            parameters_digest=parameters_digest,
            expected_current_digest=current_digest,
            expected_state_digest=expected_digest,
            idempotency_digest=idempotency_digest, expires_at=expires_at,
            compensation_ref=None, plan_digest=canonical_digest(values),
        )
        authorization_values: dict[str, CanonicalValue] = {
            "approval_digest": receipt.receipt_digest,
            "approval_ref": receipt.receipt_ref,
            "approver_digest": receipt.approver_digest,
            "authorization_ref": authorization_ref,
            "confirmation_digest": plan.confirmation_digest,
            "confirmation_ref": plan.confirmation_ref,
            "execution_authorized": True, "expires_at": expires_at,
            "issued_at": claim.claimed_at, "one_time": True,
            "plan_digest": m4_plan.plan_digest, "plan_ref": m4_plan.plan_ref,
            "requester_digest": m4_plan.requester_digest,
        }
        authorization = M4ExecutionAuthorization(
            authorization_ref=authorization_ref, plan_ref=m4_plan.plan_ref,
            plan_digest=m4_plan.plan_digest,
            requester_digest=m4_plan.requester_digest,
            confirmation_ref=plan.confirmation_ref,
            confirmation_digest=plan.confirmation_digest,
            approval_ref=receipt.receipt_ref, approval_digest=receipt.receipt_digest,
            approver_digest=receipt.approver_digest, issued_at=claim.claimed_at,
            expires_at=expires_at, one_time=True, execution_authorized=True,
            authorization_digest=canonical_digest(authorization_values),
        )
    except (TypeError, ValueError) as exc:
        raise SecretSessionControlsM4AuthorizationError(_UNAVAILABLE) from exc
    return SecretSessionControlsM4ExecutionBinding(
        m4_plan, authorization, session_controls_binding
    )


class PlanningChainSecretSessionControlsM4AuthorizationVerifier:
    """Rebuild and compare the exact signed BP006 M4 promotion on execution."""

    def __init__(self, planning: SecretApprovalPlanningChainReader,
                 receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
                 session_controls_binding: SecretSessionControlsBinding, *,
                 onboarding_binding: SecretOnboardingBinding,
                 source_plan_ref: str, approval_receipt_ref: str,
                 approver_authority_ref: str, authorization_ref: str) -> None:
        self._planning = planning
        self._receipt_authenticator = receipt_authenticator
        self._session_controls_binding = session_controls_binding
        self._onboarding_binding = onboarding_binding
        self._source_plan_ref = source_plan_ref
        self._approval_receipt_ref = approval_receipt_ref
        self._approver_authority_ref = approver_authority_ref
        self._authorization_ref = authorization_ref

    def verify(self, plan: M4ExecutionPlan,
               authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            expected = promote_secret_session_controls_m4_binding(
                self._planning, self._receipt_authenticator,
                self._session_controls_binding,
                onboarding_binding=self._onboarding_binding,
                source_plan_ref=self._source_plan_ref,
                approval_receipt_ref=self._approval_receipt_ref,
                approver_authority_ref=self._approver_authority_ref,
                authorization_ref=self._authorization_ref, now_epoch=now_epoch,
            )
            if expected.plan != plan or expected.authorization != authorization:
                raise SecretSessionControlsM4AuthorizationError(_UNAVAILABLE)
        except SecretSessionControlsM4AuthorizationError:
            raise
        except Exception as exc:
            raise SecretSessionControlsM4AuthorizationError(_UNAVAILABLE) from exc


def _validated_chain(planning: SecretApprovalPlanningChainReader,
                     receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
                     controls: SecretSessionControlsBinding, *,
                     onboarding_binding: SecretOnboardingBinding,
                     source_plan_ref: str, approval_receipt_ref: str,
                     approver_authority_ref: str, now_epoch: int) -> _PlanningChain:
    try:
        plan = planning.get_plan(source_plan_ref)
        summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
        confirmation = planning.get_confirmation(plan.confirmation_ref)
        receipt = planning.get_approval_receipt(approval_receipt_ref)
        decision = planning.get_policy_decision(receipt.decision_ref)
        claim = planning.get_approval_claim(receipt.receipt_ref)
    except Exception as exc:
        raise SecretSessionControlsM4AuthorizationError(_UNAVAILABLE) from exc
    chain = _PlanningChain(summary, confirmation, plan, decision, receipt, claim)
    _validate_action_chain(chain, controls, onboarding_binding, now_epoch=now_epoch)
    _validate_approval_chain(
        chain, receipt_authenticator,
        approver_authority_ref=approver_authority_ref, now_epoch=now_epoch,
    )
    return chain


def _validate_action_chain(chain: _PlanningChain,
                           controls: SecretSessionControlsBinding,
                           onboarding: SecretOnboardingBinding, *,
                           now_epoch: int) -> None:
    _validate_controls_summary_confirmation_plan(
        chain.summary, chain.confirmation, chain.plan, controls, onboarding,
        now_epoch=now_epoch,
    )


def validate_secret_session_controls_lab_auto_source(
    summary: FinalIntentSummary,
    confirmation: ConfirmationRecord,
    plan: PreparedPlan,
    controls: SecretSessionControlsBinding,
    onboarding: SecretOnboardingBinding,
    *,
    now_epoch: int,
) -> None:
    """Validate the same authoritative BP006 C/P/E inputs without an M3 receipt."""

    _validate_controls_summary_confirmation_plan(
        summary, confirmation, plan, controls, onboarding, now_epoch=now_epoch
    )


def _validate_controls_summary_confirmation_plan(
    summary: FinalIntentSummary,
    confirmation: ConfirmationRecord,
    plan: PreparedPlan,
    controls: SecretSessionControlsBinding,
    onboarding: SecretOnboardingBinding,
    *,
    now_epoch: int,
) -> None:
    changes = {item.object_class: item for item in summary.object_changes}
    required = {
        ObjectClass.FOLDER_BINDING, ObjectClass.TARGET,
        ObjectClass.TEMPLATE_BINDING, ObjectClass.SECRET_METADATA,
        ObjectClass.RDP_EVENT_FILTER_BINDING,
        ObjectClass.SECRET_SESSION_CONTROLS_BINDING,
    }
    if len(changes) != len(summary.object_changes) or set(changes) != required:
        raise SecretSessionControlsM4AuthorizationError(_UNAVAILABLE)
    folder = changes[ObjectClass.FOLDER_BINDING]
    target = changes[ObjectClass.TARGET]
    template = changes[ObjectClass.TEMPLATE_BINDING]
    secret = changes[ObjectClass.SECRET_METADATA]
    event_filter = changes[ObjectClass.RDP_EVENT_FILTER_BINDING]
    control = changes[ObjectClass.SECRET_SESSION_CONTROLS_BINDING]
    expected_noops = (
        (folder, onboarding.folder_object_ref,
         {"exists": True, "folder_ref": onboarding.folder_ref}),
        (target, onboarding.target_object_ref,
         {"exists": True, "protocol": "rdp",
          "connectivity_profile_ref": onboarding.connectivity_profile_ref}),
        (template, onboarding.template_object_ref,
         {"exists": True, "template_ref": onboarding.template_ref,
          "compatibility": "compatible"}),
        (event_filter, cast(str, onboarding.rdp_event_filter_object_ref),
         {"exists": True, "profile_ref": cast(str, onboarding.rdp_event_filter_profile_ref)}),
    )
    current_controls = {
        "exists": True, "recording_enabled": controls.prewrite_recording_enabled,
        "clipboard_blocking_enabled": controls.prewrite_clipboard_blocking_enabled,
        "rdp_event_filter_enabled": controls.prewrite_rdp_event_filter_enabled,
        "rdp_event_filter_profile_matches": controls.prewrite_rdp_event_filter_profile_matches,
        "preserved_identity_digest": controls.preserved_identity_relations_digest,
        "event_filter_profile_digest": (
            controls.prewrite_rdp_event_filter_profile_digest
        ),
        "profile_ref": controls.rdp_event_filter_profile_ref,
    }
    expected_controls = {**current_controls, "recording_enabled": True,
                         "clipboard_blocking_enabled": True,
                         "rdp_event_filter_enabled": True,
                         "rdp_event_filter_profile_matches": True,
                         "event_filter_profile_digest": (
                             secret_session_controls_event_filter_profile_digest(
                                 controls.rdp_event_filter_profile_name
                             )
                         )}
    proposed = {key: value for key, value in expected_controls.items()
                if current_controls[key] != value}
    cross_bound = (
        controls.folder_ref == onboarding.folder_ref
        and controls.folder_path == onboarding.folder_path
        and controls.template_ref == onboarding.template_ref
        and controls.template_name == onboarding.template_name
        and controls.target_ref == onboarding.target_object_ref
        and controls.target_name == onboarding.target_name
        and controls.secret_name == onboarding.secret_name
        and controls.rdp_event_filter_profile_ref == onboarding.rdp_event_filter_profile_ref
        and controls.rdp_event_filter_profile_name == onboarding.rdp_event_filter_profile_name
        and controls.secret_session_controls_object_ref == onboarding.secret_session_controls_object_ref
        and controls.secret_id == onboarding.existing_secret_id
        and controls.preserved_identity_relations_digest
        == onboarding.session_controls_identity_digest
    )
    if (
        canonical_digest(summary.canonical_content()) != summary.summary_digest
        or canonical_digest(confirmation.canonical_content()) != confirmation.record_digest
        or canonical_digest(plan.canonical_content()) != plan.plan_digest
        or plan.requester_digest != summary.requester_digest
        or confirmation.requester_digest != summary.requester_digest
        or plan.summary_digest != summary.summary_digest
        or confirmation.summary_revision != summary.revision
        or confirmation.interaction_type != "authenticated_human_confirmation"
        or now_epoch < plan.created_at
        or now_epoch < summary.created_at
        or now_epoch >= plan.expires_at
        or now_epoch >= summary.expires_at
        or not cross_bound or onboarding.target_protocol != "rdp"
        or len(plan.lines) != 1 or summary.scheme_id is not SchemeId.SECRET_ONBOARDING
        or summary.blueprint_ref != "FPA-BP-006"
        or summary.outcome_code != "onboard_windows_rdp_resource"
        or summary.action_family_ref != _ACTION_FAMILY
        or summary.action_family_version != _ACTION_FAMILY_VERSION
        or summary.material_reference_metadata is not None
        or any(now_epoch < item.observed_at or now_epoch >= item.fresh_until
               for item in summary.object_changes)
        or any(item.change_kind is not ChangeKind.NO_OP
               or not _same_fields(dict(item.current_fields), fields)
               or not _same_fields(dict(item.expected_fields), fields)
               or item.proposed_fields
               for item, _ref, fields in expected_noops)
        or any(item.object_ref != ref for item, ref, _fields in expected_noops)
        or secret.object_ref != onboarding.secret_object_ref
        or secret.change_kind is not ChangeKind.NO_OP
        or not _same_fields(
            dict(secret.current_fields), dict(secret.expected_fields)
        )
        or secret.proposed_fields
        or dict(secret.current_fields).get("exists") is not True
        or type(dict(secret.current_fields).get("inherit_permission")) is not bool
        or control.object_ref != onboarding.secret_session_controls_object_ref
        or control.change_kind is not ChangeKind.UPDATE
        or not _same_fields(dict(control.current_fields), current_controls)
        or not _same_fields(dict(control.expected_fields), expected_controls)
        or not _same_fields(dict(control.proposed_fields), proposed)
        or any(item.projection_contract_ref != SOURCE_CONTRACT
               or item.projection_contract_version != SOURCE_VERSION
               or item.projection_source_ref != SOURCE_REF
               for item in (folder, target, template, secret, event_filter))
        or control.projection_contract_ref != SECRET_SESSION_CONTROLS_SOURCE_CONTRACT
        or control.projection_contract_version != SECRET_SESSION_CONTROLS_SOURCE_VERSION
        or control.projection_source_ref != SECRET_SESSION_CONTROLS_SOURCE_REF
        or plan.scheme_id is not SchemeId.SECRET_ONBOARDING
        or plan.summary_ref != summary.summary_ref or plan.summary_revision != summary.revision
        or plan.confirmation_ref != confirmation.confirmation_ref
        or confirmation.summary_ref != summary.summary_ref
        or confirmation.summary_digest != summary.summary_digest
        or confirmation.record_digest != plan.confirmation_digest
        or now_epoch < confirmation.confirmed_at
        or now_epoch >= confirmation.expires_at
        or plan.environment_ref != summary.environment_ref or plan.scope_ref != summary.scope_ref
    ):
        raise SecretSessionControlsM4AuthorizationError(_UNAVAILABLE)
    line = plan.lines[0]
    if (
        line.action_family_ref != _ACTION_FAMILY
        or line.action_family_version != _ACTION_FAMILY_VERSION
        or line.target_ref != control.object_ref
        or line.target_class is not ObjectClass.SECRET_SESSION_CONTROLS_BINDING
        or line.change_kind is not ChangeKind.UPDATE or line.depends_on
        or line.expected_current_digest != control.current_projection_digest
        or line.expected_state_digest != control.expected_projection_digest
        or line.projection_contract_ref != SECRET_SESSION_CONTROLS_SOURCE_CONTRACT
    ):
        raise SecretSessionControlsM4AuthorizationError(_UNAVAILABLE)


def _same_fields(
    actual: dict[str, object],
    expected: dict[str, object],
) -> bool:
    return set(actual) == set(expected) and all(
        type(actual[key]) is type(value) and actual[key] == value
        for key, value in expected.items()
    )


__all__ = [
    "PlanningChainSecretSessionControlsM4AuthorizationVerifier",
    "SecretSessionControlsM4AuthorizationError",
    "SecretApprovalPlanningChainReader",
    "promote_secret_session_controls_m4_binding",
    "validate_secret_session_controls_lab_auto_source",
]
