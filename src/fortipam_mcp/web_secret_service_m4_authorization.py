"""Promote one signed BP007 Web-service M3 chain to its exact M4 binding."""

from __future__ import annotations

from collections.abc import Mapping

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
from .secret_onboarding_projection_source import (
    WebSecretOnboardingBinding,
    secret_onboarding_projection_contract,
)
from .web_secret_service_m4_adapter import (
    ACTION_ID,
    ACTION_VERSION,
    ADAPTER_REF,
    WebSecretServiceBinding,
    parameters_digest,
    state_digest,
)
from .web_secret_service_m4_runtime import WebSecretServiceExecutionBinding


_UNAVAILABLE = "Trusted Web Secret service authorization is unavailable."
_ACTION_FAMILY = "web-and-application-credential-access-plan"
_ACTION_FAMILY_VERSION = "1.0.0"


class WebSecretServiceM4AuthorizationError(M4AuthorizationDenied):
    """Stable denial for an incomplete or mismatched BP007 approval chain."""


def promote_web_secret_service_m4_binding(
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    service_binding: WebSecretServiceBinding,
    *,
    onboarding_binding: WebSecretOnboardingBinding,
    source_plan_ref: str,
    approval_receipt_ref: str,
    approver_authority_ref: str,
    authorization_ref: str,
    now_epoch: int,
) -> WebSecretServiceExecutionBinding:
    """Derive exactly one fixed Web HTTP-service enable M4 record."""

    chain = _validated_chain(
        planning, receipt_authenticator, service_binding,
        onboarding_binding=onboarding_binding, source_plan_ref=source_plan_ref,
        approval_receipt_ref=approval_receipt_ref,
        approver_authority_ref=approver_authority_ref, now_epoch=now_epoch,
    )
    line = chain.plan.lines[0]
    receipt = chain.receipt
    expires_at = min(
        chain.plan.expires_at, chain.summary.expires_at,
        chain.confirmation.expires_at, chain.decision.expires_at,
        receipt.expires_at,
        *(change.fresh_until for change in chain.summary.object_changes),
    )
    parameters = parameters_digest(service_binding)
    current = state_digest(service_binding, enabled=False)
    expected = state_digest(service_binding, enabled=True)
    idempotency = canonical_digest({
        "action_id": ACTION_ID,
        "action_version": ACTION_VERSION,
        "approval_digest": receipt.receipt_digest,
        "parameters_digest": parameters,
        "source_plan_digest": chain.plan.plan_digest,
        "target_ref": line.target_ref,
    })
    values: dict[str, CanonicalValue] = {
        "action_id": ACTION_ID, "action_version": ACTION_VERSION,
        "adapter_ref": ADAPTER_REF, "approval_digest": receipt.receipt_digest,
        "compensation_ref": None, "confirmation_digest": chain.plan.confirmation_digest,
        "expected_current_digest": current, "expected_state_digest": expected,
        "expires_at": expires_at, "idempotency_digest": idempotency,
        "parameters_digest": parameters, "plan_ref": chain.plan.plan_ref,
        "requester_digest": chain.plan.requester_digest,
        "revision": chain.plan.revision, "summary_digest": chain.plan.summary_digest,
        "target_ref": line.target_ref,
    }
    try:
        plan = M4ExecutionPlan(
            plan_ref=chain.plan.plan_ref, revision=chain.plan.revision,
            action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF,
            target_ref=line.target_ref, requester_digest=chain.plan.requester_digest,
            summary_digest=chain.plan.summary_digest,
            confirmation_digest=chain.plan.confirmation_digest,
            approval_digest=receipt.receipt_digest, parameters_digest=parameters,
            expected_current_digest=current, expected_state_digest=expected,
            idempotency_digest=idempotency, expires_at=expires_at,
            compensation_ref=None, plan_digest=canonical_digest(values),
        )
        authorization_values: dict[str, CanonicalValue] = {
            "approval_digest": receipt.receipt_digest, "approval_ref": receipt.receipt_ref,
            "approver_digest": receipt.approver_digest, "authorization_ref": authorization_ref,
            "confirmation_digest": chain.plan.confirmation_digest,
            "confirmation_ref": chain.plan.confirmation_ref,
            "execution_authorized": True, "expires_at": expires_at,
            "issued_at": chain.claim.claimed_at, "one_time": True,
            "plan_digest": plan.plan_digest, "plan_ref": plan.plan_ref,
            "requester_digest": plan.requester_digest,
        }
        authorization = M4ExecutionAuthorization(
            authorization_ref=authorization_ref, plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref=chain.plan.confirmation_ref,
            confirmation_digest=chain.plan.confirmation_digest,
            approval_ref=receipt.receipt_ref, approval_digest=receipt.receipt_digest,
            approver_digest=receipt.approver_digest, issued_at=chain.claim.claimed_at,
            expires_at=expires_at, one_time=True, execution_authorized=True,
            authorization_digest=canonical_digest(authorization_values),
        )
    except (TypeError, ValueError) as exc:
        raise WebSecretServiceM4AuthorizationError(_UNAVAILABLE) from exc
    return WebSecretServiceExecutionBinding(plan, authorization, service_binding)


class PlanningChainWebSecretServiceM4AuthorizationVerifier:
    """Rebuild and compare the signed BP007 promotion at execution time."""

    def __init__(self, planning: SecretApprovalPlanningChainReader,
                 receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
                 service_binding: WebSecretServiceBinding, *,
                 onboarding_binding: WebSecretOnboardingBinding,
                 source_plan_ref: str, approval_receipt_ref: str,
                 approver_authority_ref: str, authorization_ref: str) -> None:
        self._planning = planning
        self._receipt_authenticator = receipt_authenticator
        self._service_binding = service_binding
        self._onboarding_binding = onboarding_binding
        self._source_plan_ref = source_plan_ref
        self._approval_receipt_ref = approval_receipt_ref
        self._approver_authority_ref = approver_authority_ref
        self._authorization_ref = authorization_ref

    def verify(self, plan: M4ExecutionPlan,
               authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            expected = promote_web_secret_service_m4_binding(
                self._planning, self._receipt_authenticator, self._service_binding,
                onboarding_binding=self._onboarding_binding,
                source_plan_ref=self._source_plan_ref,
                approval_receipt_ref=self._approval_receipt_ref,
                approver_authority_ref=self._approver_authority_ref,
                authorization_ref=self._authorization_ref, now_epoch=now_epoch,
            )
            if expected.plan != plan or expected.authorization != authorization:
                raise WebSecretServiceM4AuthorizationError(_UNAVAILABLE)
        except WebSecretServiceM4AuthorizationError:
            raise
        except Exception as exc:
            raise WebSecretServiceM4AuthorizationError(_UNAVAILABLE) from exc


def _validated_chain(
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    service: WebSecretServiceBinding,
    *, onboarding_binding: WebSecretOnboardingBinding, source_plan_ref: str,
    approval_receipt_ref: str, approver_authority_ref: str, now_epoch: int,
) -> _PlanningChain:
    try:
        plan = planning.get_plan(source_plan_ref)
        summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
        confirmation = planning.get_confirmation(plan.confirmation_ref)
        receipt = planning.get_approval_receipt(approval_receipt_ref)
        decision = planning.get_policy_decision(receipt.decision_ref)
        claim = planning.get_approval_claim(receipt.receipt_ref)
    except Exception as exc:
        raise WebSecretServiceM4AuthorizationError(_UNAVAILABLE) from exc
    chain = _PlanningChain(summary, confirmation, plan, decision, receipt, claim)
    _validate_web_service_chain(chain, service, onboarding_binding, now_epoch=now_epoch)
    _validate_approval_chain(
        chain, receipt_authenticator,
        approver_authority_ref=approver_authority_ref, now_epoch=now_epoch,
    )
    return chain


def _validate_web_service_chain(
    chain: _PlanningChain, service: WebSecretServiceBinding,
    onboarding: WebSecretOnboardingBinding, *, now_epoch: int,
) -> None:
    _validate_web_service_summary_confirmation_plan(
        chain.summary, chain.confirmation, chain.plan, service, onboarding,
        now_epoch=now_epoch,
    )


def validate_web_secret_service_lab_auto_source(
    summary: FinalIntentSummary, confirmation: ConfirmationRecord,
    plan: PreparedPlan, service: WebSecretServiceBinding,
    onboarding: WebSecretOnboardingBinding, *, now_epoch: int,
) -> None:
    """Validate the exact BP007 C/P/E source without an M3 receipt."""

    _validate_web_service_summary_confirmation_plan(
        summary, confirmation, plan, service, onboarding, now_epoch=now_epoch,
    )


def _validate_web_service_summary_confirmation_plan(
    summary: FinalIntentSummary, confirmation: ConfirmationRecord,
    plan: PreparedPlan, service: WebSecretServiceBinding,
    onboarding: WebSecretOnboardingBinding, *, now_epoch: int,
) -> None:
    changes = {item.object_class: item for item in summary.object_changes}
    required = {
        ObjectClass.FOLDER_BINDING, ObjectClass.TEMPLATE_BINDING,
        ObjectClass.WEB_SECRET_METADATA, ObjectClass.WEB_SECRET_SERVICE_BINDING,
    }
    if len(changes) != len(summary.object_changes) or set(changes) != required:
        raise WebSecretServiceM4AuthorizationError(_UNAVAILABLE)
    folder = changes[ObjectClass.FOLDER_BINDING]
    template = changes[ObjectClass.TEMPLATE_BINDING]
    secret = changes[ObjectClass.WEB_SECRET_METADATA]
    status = changes[ObjectClass.WEB_SECRET_SERVICE_BINDING]
    expected_noops = (
        (folder, onboarding.folder_object_ref, {"exists": True, "folder_ref": onboarding.folder_ref}),
        (template, onboarding.template_object_ref, {"exists": True, "template_ref": onboarding.template_ref, "compatibility": "compatible"}),
        (secret, onboarding.secret_object_ref, {"exists": True, "inherit_permission": True, "session_recording": True}),
    )
    current = {"exists": True, "http_service_enabled": False}
    expected = {"exists": True, "http_service_enabled": True}
    cross_bound = (
        service.object_ref == onboarding.service_object_ref
        and service.folder_path == onboarding.folder_path
        and service.secret_name == onboarding.secret_name
        and service.secret_id == onboarding.existing_secret_id
        and onboarding.template_name == "Web Account"
        and onboarding.session_recording is True
    )
    if (
        canonical_digest(summary.canonical_content()) != summary.summary_digest
        or canonical_digest(confirmation.canonical_content()) != confirmation.record_digest
        or canonical_digest(plan.canonical_content()) != plan.plan_digest
        or not cross_bound
        or summary.scheme_id is not SchemeId.SECRET_ONBOARDING
        or summary.blueprint_ref != "FPA-BP-007"
        or summary.outcome_code != "onboard_web_account"
        or summary.action_family_ref != _ACTION_FAMILY
        or summary.action_family_version != _ACTION_FAMILY_VERSION
        or summary.material_reference_metadata is not None
        or len(plan.lines) != 1
        or any(now_epoch < item.observed_at or now_epoch >= item.fresh_until for item in summary.object_changes)
        or now_epoch < summary.created_at or now_epoch >= summary.expires_at
        or now_epoch < confirmation.confirmed_at or now_epoch >= confirmation.expires_at
        or now_epoch < plan.created_at or now_epoch >= plan.expires_at
        or plan.requester_digest != summary.requester_digest
        or confirmation.requester_digest != summary.requester_digest
        or plan.summary_digest != summary.summary_digest
        or plan.summary_ref != summary.summary_ref or plan.summary_revision != summary.revision
        or plan.confirmation_ref != confirmation.confirmation_ref
        or confirmation.summary_ref != summary.summary_ref
        or confirmation.summary_revision != summary.revision
        or confirmation.summary_digest != summary.summary_digest
        or confirmation.record_digest != plan.confirmation_digest
        or confirmation.interaction_type != "authenticated_human_confirmation"
        or plan.environment_ref != summary.environment_ref or plan.scope_ref != summary.scope_ref
        or plan.scheme_id is not SchemeId.SECRET_ONBOARDING
        or any(
            item.change_kind is not ChangeKind.NO_OP
            or item.object_ref != ref
            or not _same_fields(dict(item.current_fields), fields)
            or not _same_fields(dict(item.expected_fields), fields)
            or item.proposed_fields
            for item, ref, fields in expected_noops
        )
        or status.object_ref != onboarding.service_object_ref
        or status.change_kind is not ChangeKind.UPDATE
        or not _same_fields(dict(status.current_fields), current)
        or not _same_fields(dict(status.expected_fields), expected)
        or not _same_fields(dict(status.proposed_fields), {"http_service_enabled": True})
        or any(
            item.projection_contract_ref != secret_onboarding_projection_contract(item.object_class).contract_id
            or item.projection_contract_version != secret_onboarding_projection_contract(item.object_class).version
            or item.projection_source_ref != secret_onboarding_projection_contract(item.object_class).source_ref
            for item in changes.values()
        )
    ):
        raise WebSecretServiceM4AuthorizationError(_UNAVAILABLE)
    line = plan.lines[0]
    if (
        line.action_family_ref != _ACTION_FAMILY
        or line.action_family_version != _ACTION_FAMILY_VERSION
        or line.target_ref != status.object_ref
        or line.target_class is not ObjectClass.WEB_SECRET_SERVICE_BINDING
        or line.change_kind is not ChangeKind.UPDATE or line.depends_on
        or line.expected_current_digest != status.current_projection_digest
        or line.expected_state_digest != status.expected_projection_digest
        or line.projection_contract_ref != secret_onboarding_projection_contract(ObjectClass.WEB_SECRET_SERVICE_BINDING).contract_id
    ):
        raise WebSecretServiceM4AuthorizationError(_UNAVAILABLE)


def _same_fields(actual: Mapping[str, object], expected: Mapping[str, object]) -> bool:
    return set(actual) == set(expected) and all(
        type(actual[key]) is type(value) and actual[key] == value
        for key, value in expected.items()
    )


__all__ = [
    "PlanningChainWebSecretServiceM4AuthorizationVerifier",
    "WebSecretServiceM4AuthorizationError",
    "promote_web_secret_service_m4_binding",
    "validate_web_secret_service_lab_auto_source",
]
