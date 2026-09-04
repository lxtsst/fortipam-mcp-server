"""Repository-only V4 M2 Scheme compiler and comparison state machine.

This module has no product client, MCP registration, credential loader,
approval service, write adapter, or execution method.  It compiles two typed
Scheme profiles into confirmed, explicitly non-dispatchable planning records.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Mapping, Protocol, Sequence, cast

from .canonical import CanonicalValue, canonical_digest
from .models import (
    AuthenticatedRequester,
    AuthoritativeProjection,
    ChangeKind,
    ConfirmationRecord,
    DesiredObject,
    FieldKind,
    FieldRule,
    FinalIntentSummary,
    MaterialReferenceMetadata,
    ObjectChange,
    ObjectClass,
    PlanLine,
    PlanState,
    PlanningContractError,
    PostWriteEvaluation,
    PostWriteStatus,
    PreparedPlan,
    PreWriteEvaluation,
    PreWriteStatus,
    ProjectionContract,
    SchemeDraft,
    SchemeId,
    SummaryState,
    VerifiedConfirmationInteraction,
    VerifiedReferenceDecision,
    require_ref,
)


class PlanningDenied(PlanningContractError):
    """Raised when a safe M2 state transition is not available."""


class ReferenceIssuer(Protocol):
    """Trusted server-side opaque reference source required by M2."""

    def issue(self, purpose: str) -> str: ...


class ReferenceAuthorizer(Protocol):
    """Trusted boundary that resolves caller text to scoped C2 references."""

    authority_ref: str

    def authorize(
        self,
        reference: str,
        *,
        reference_kind: str,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
        now_epoch: int,
    ) -> VerifiedReferenceDecision: ...


_M2_SCHEMES = {SchemeId.ACCESS_DOMAIN.value, SchemeId.SECRET_ONBOARDING.value}
_M2_PROFILE_BLUEPRINT = {
    SchemeId.ACCESS_DOMAIN.value: "FPA-BP-004",
    SchemeId.SECRET_ONBOARDING.value: "FPA-BP-005",
}
_M2_PROFILE_OUTCOME = {
    SchemeId.ACCESS_DOMAIN.value: "establish_access_domain",
    SchemeId.SECRET_ONBOARDING.value: "onboard_privileged_resource",
}
_ACCESS_CLASSES = {
    ObjectClass.PUBLIC_FOLDER,
    ObjectClass.ACCESS_GRANT,
    ObjectClass.CLASSIFICATION_BINDING,
    ObjectClass.FOLDER_POLICY_BINDING,
}
_SECRET_CLASSES = {
    ObjectClass.FOLDER_BINDING,
    ObjectClass.TARGET,
    ObjectClass.TEMPLATE_BINDING,
    ObjectClass.SECRET_METADATA,
    ObjectClass.LAUNCHER_BINDING,
    ObjectClass.POLICY_BINDING,
}
_REQUIRED_SECRET_CLASSES = {
    ObjectClass.FOLDER_BINDING,
    ObjectClass.TARGET,
    ObjectClass.TEMPLATE_BINDING,
    ObjectClass.SECRET_METADATA,
}
_UNCHANGED_BOUNDARY = (
    "c3_material_excluded",
    "device_state_unchanged_by_m2",
    "mcp_tool_surface_unchanged",
    "v3_runtime_unchanged",
)
_DEPENDENCY_ORDER = {
    ObjectClass.PUBLIC_FOLDER: 0,
    ObjectClass.CLASSIFICATION_BINDING: 1,
    ObjectClass.FOLDER_POLICY_BINDING: 1,
    ObjectClass.ACCESS_GRANT: 2,
    ObjectClass.FOLDER_BINDING: 0,
    ObjectClass.TARGET: 1,
    ObjectClass.TEMPLATE_BINDING: 1,
    ObjectClass.SECRET_METADATA: 2,
    ObjectClass.LAUNCHER_BINDING: 3,
    ObjectClass.POLICY_BINDING: 3,
}


def _rules(*rules: FieldRule) -> tuple[FieldRule, ...]:
    return (FieldRule("exists", FieldKind.BOOLEAN), *rules)


_FIELD_RULES: dict[ObjectClass, tuple[FieldRule, ...]] = {
    ObjectClass.PUBLIC_FOLDER: _rules(
        FieldRule("owner_ref", FieldKind.REFERENCE),
        FieldRule("enabled", FieldKind.BOOLEAN),
    ),
    ObjectClass.ACCESS_GRANT: _rules(
        FieldRule("subject_ref", FieldKind.REFERENCE),
        FieldRule("subject_class", FieldKind.ENUM, ("user", "group", "role")),
        FieldRule("permission", FieldKind.ENUM, ("use", "manage")),
    ),
    ObjectClass.CLASSIFICATION_BINDING: _rules(
        FieldRule("classification_ref", FieldKind.REFERENCE),
    ),
    ObjectClass.FOLDER_POLICY_BINDING: _rules(
        FieldRule("policy_profile_ref", FieldKind.REFERENCE),
    ),
    ObjectClass.FOLDER_BINDING: _rules(
        FieldRule("folder_ref", FieldKind.REFERENCE),
    ),
    ObjectClass.TARGET: _rules(
        FieldRule(
            "protocol",
            FieldKind.ENUM,
            ("database", "https", "rdp", "sftp", "ssh", "supported_other"),
        ),
        FieldRule("connectivity_profile_ref", FieldKind.REFERENCE),
    ),
    ObjectClass.TEMPLATE_BINDING: _rules(
        FieldRule("template_ref", FieldKind.REFERENCE),
        FieldRule("compatibility", FieldKind.ENUM, ("compatible", "unknown")),
    ),
    ObjectClass.SECRET_METADATA: _rules(
        FieldRule(
            "account_type",
            FieldKind.ENUM,
            ("application", "database", "directory", "key_based", "local"),
        ),
        FieldRule("enabled", FieldKind.BOOLEAN),
        FieldRule(
            "lifecycle_class",
            FieldKind.ENUM,
            ("managed", "manual", "rotate_and_verify"),
        ),
    ),
    ObjectClass.LAUNCHER_BINDING: _rules(
        FieldRule("launcher_profile_ref", FieldKind.REFERENCE),
    ),
    ObjectClass.POLICY_BINDING: _rules(
        FieldRule("policy_profile_ref", FieldKind.REFERENCE),
    ),
}


class M2RegistryView:
    """Minimized registry view that proves M2 remains fake-only."""

    def __init__(self, registry: Mapping[str, object]) -> None:
        if registry.get("registry_kind") != "fortipam_v4_administrative_registry":
            raise PlanningDenied("The V4 administrative registry is unavailable.")
        schema_version = registry.get("schema_version")
        if type(schema_version) is not str:
            raise PlanningDenied("The V4 registry schema version is invalid.")
        self.schema_version = schema_version
        self._schemes = _index_records(registry.get("schemes"), "scheme")
        self._blueprints = _index_records(registry.get("blueprints"), "blueprint")
        self._actions = _index_records(registry.get("actions"), "action")
        for scheme_id in _M2_SCHEMES:
            scheme = self._schemes.get(scheme_id)
            if scheme is None:
                raise PlanningDenied("An M2 Scheme is absent from the registry.")
            evidence = scheme.get("implementation_evidence")
            if (
                scheme.get("status") != "planned"
                or scheme.get("maturity") != "contract_tested"
                or scheme.get("lifecycle") != "contract_tested"
                or not isinstance(evidence, Mapping)
                or evidence.get("evidence_status") != "contract_tested"
                or evidence.get("evidence_kind") != "fake_only_contract"
                or evidence.get("profile_blueprint_refs")
                != [_M2_PROFILE_BLUEPRINT[scheme_id]]
            ):
                raise PlanningDenied("The M2 Scheme is not contract-tested.")
            for capability in ("dispatchable", "runtime_packaged", "mcp_exposed", "device_access"):
                if evidence.get(capability) is not False:
                    raise PlanningDenied("M2 implementation evidence claims runtime authority.")

    def resolve(self, draft: SchemeDraft) -> tuple[str, str, str]:
        scheme = self._schemes.get(draft.scheme_id.value)
        if scheme is None or scheme.get("version") != draft.scheme_version:
            raise PlanningDenied("Scheme version is not registered.")
        if draft.registry_schema_version != self.schema_version:
            raise PlanningDenied("Scheme uses a different registry schema version.")
        if (
            draft.blueprint_ref != _M2_PROFILE_BLUEPRINT[draft.scheme_id.value]
            or draft.outcome_code != _M2_PROFILE_OUTCOME[draft.scheme_id.value]
        ):
            raise PlanningDenied("Scheme is outside the exact fake-only M2 profile.")
        blueprint_refs = _string_tuple(scheme.get("blueprint_refs"))
        if draft.blueprint_ref not in blueprint_refs:
            raise PlanningDenied("Blueprint is not bound to the selected Scheme.")
        blueprint = self._blueprints.get(draft.blueprint_ref)
        if blueprint is None:
            raise PlanningDenied("Blueprint is unavailable.")
        action_refs = _string_tuple(blueprint.get("action_refs"))
        if len(action_refs) != 1:
            raise PlanningDenied("Blueprint does not bind one action-family placeholder.")
        action_ref = action_refs[0]
        action = self._actions.get(action_ref)
        if (
            action is None
            or action.get("record_kind") != "action_family_placeholder"
            or action.get("atomic_contract") is not False
            or action.get("executable") is not False
            or action.get("adapter") != "none"
            or action.get("status") != "design_only"
            or action.get("maturity") != "catalogued"
            or action.get("lifecycle") != "catalogued"
        ):
            raise PlanningDenied("Action family is not a disabled placeholder.")
        version = action.get("version")
        risk_tier = action.get("risk_tier")
        if type(version) is not str or type(risk_tier) is not str:
            raise PlanningDenied("Action-family metadata is invalid.")
        return action_ref, version, risk_tier


class M2PlanningEngine:
    """In-memory M2 planner with no execution transition or product adapter."""

    def __init__(
        self,
        registry: Mapping[str, object],
        issuer: ReferenceIssuer,
        reference_authorizer: ReferenceAuthorizer,
    ) -> None:
        self._registry = M2RegistryView(registry)
        self._issuer = issuer
        self._reference_authorizer = reference_authorizer
        require_ref(reference_authorizer.authority_ref, "reference authority_ref")
        self._summaries: dict[str, FinalIntentSummary] = {}
        self._confirmations: dict[str, ConfirmationRecord] = {}
        self._plans: dict[str, PreparedPlan] = {}
        self._issued_refs: set[str] = set()
        self._used_nonce_digests: set[str] = set()
        self._used_confirmation_refs: set[str] = set()
        self._prewrite_matches: dict[str, tuple[int, str]] = {}
        self._postwrite_evaluated_at: dict[str, int] = {}

    @staticmethod
    def projection_contract(scheme_id: SchemeId, object_class: ObjectClass) -> ProjectionContract:
        allowed = _ACCESS_CLASSES if scheme_id is SchemeId.ACCESS_DOMAIN else _SECRET_CLASSES
        if object_class not in allowed:
            raise PlanningDenied("Object class is not allowed for the Scheme.")
        contract_id = (
            "access-domain-state-v1"
            if scheme_id is SchemeId.ACCESS_DOMAIN
            else "secret-onboarding-state-v1"
        )
        return ProjectionContract(
            contract_id=contract_id,
            version="1.0.0",
            source_ref="m2-fake-projection-source",
            object_class=object_class,
            field_rules=_FIELD_RULES[object_class],
            max_age_seconds=300,
        )

    def compile_summary(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        projections: Sequence[AuthoritativeProjection],
        *,
        now_epoch: int,
        prior_summary_ref: str | None = None,
    ) -> FinalIntentSummary:
        """Compile a versioned human-readable comparison without side effects."""

        action_ref, action_version, risk_tier = self._registry.resolve(draft)
        self._validate_draft(draft, risk_tier)
        projection_by_ref = {item.object_ref: item for item in projections}
        if len(projection_by_ref) != len(projections):
            raise PlanningDenied("Projection object references must be unique.")
        expected_refs = {item.object_ref for item in draft.desired_objects}
        if set(projection_by_ref) != expected_refs:
            raise PlanningDenied("One exact current projection is required per desired object.")
        for desired in draft.desired_objects:
            _validate_projection(
                projection_by_ref[desired.object_ref],
                self.projection_contract(draft.scheme_id, desired.object_class),
                now_epoch,
            )
        reference_expires_at, reference_digest = self._validate_references(
            draft,
            projections,
            requester,
            now_epoch,
        )

        changes: list[ObjectChange] = []
        for desired in sorted(
            draft.desired_objects,
            key=lambda item: (_DEPENDENCY_ORDER[item.object_class], item.object_ref),
        ):
            projection = projection_by_ref[desired.object_ref]
            contract = self.projection_contract(draft.scheme_id, desired.object_class)
            _validate_projection(projection, contract, now_epoch)
            desired_values = dict(desired.desired_fields)
            contract.validate_fields(
                {"exists": desired.desired_exists, **desired_values}, complete=True
            )
            current_values = projection.values
            expected_values: dict[str, bool | str] = {
                "exists": desired.desired_exists,
                **desired_values,
            }
            if current_values.get("exists") is False and desired.desired_exists:
                kind = ChangeKind.CREATE
                proposed_values = expected_values
            elif current_values.get("exists") is True and not desired.desired_exists:
                kind = ChangeKind.REVOKE
                proposed_values = {"exists": False}
            else:
                proposed_values = {
                    key: value
                    for key, value in expected_values.items()
                    if current_values.get(key) != value
                }
                kind = ChangeKind.UPDATE if proposed_values else ChangeKind.NO_OP
            expected_digest = _expected_projection_digest(
                contract, desired.object_ref, expected_values
            )
            changes.append(
                ObjectChange(
                    object_ref=desired.object_ref,
                    object_class=desired.object_class,
                    change_kind=kind,
                    current_fields=tuple(sorted(current_values.items())),
                    proposed_fields=tuple(sorted(proposed_values.items())),
                    expected_fields=tuple(sorted(expected_values.items())),
                    current_projection_digest=projection.state_digest,
                    expected_projection_digest=expected_digest,
                    projection_contract_ref=contract.contract_id,
                    projection_contract_version=contract.version,
                    projection_source_ref=contract.source_ref,
                    observed_at=projection.observed_at,
                    fresh_until=projection.fresh_until,
                )
            )

        current_digest = canonical_digest(
            [change.current_projection_digest for change in changes]
        )
        proposed_digest = canonical_digest([change.as_dict() for change in changes])
        expected_digest = canonical_digest(
            [change.expected_projection_digest for change in changes]
        )

        prior: FinalIntentSummary | None = None
        if prior_summary_ref is not None:
            prior = self._active_summary(prior_summary_ref, now_epoch)
            if now_epoch < prior.created_at:
                raise PlanningDenied("Summary revision time cannot move backwards.")
            if (
                prior.requester_digest != requester.digest
                or prior.audience_ref != draft.audience_ref
                or prior.environment_ref != draft.environment_ref
                or prior.scope_ref != draft.scope_ref
            ):
                raise PlanningDenied("Prior summary revision binding is invalid.")
            summary_ref = prior.summary_ref
            revision = prior.revision + 1
            self._invalidate_summary(prior.summary_ref)
        else:
            summary_ref = self._issue("summary")
            revision = 1

        expires_at = min(
            now_epoch + draft.summary_ttl_seconds,
            reference_expires_at,
        )

        content = _summary_content(
            summary_ref=summary_ref,
            revision=revision,
            requester=requester,
            draft=draft,
            action_ref=action_ref,
            action_version=action_version,
            changes=tuple(changes),
            current_digest=current_digest,
            proposed_digest=proposed_digest,
            expected_digest=expected_digest,
            now_epoch=now_epoch,
            expires_at=expires_at,
            reference_authority_ref=self._reference_authorizer.authority_ref,
            reference_authorization_digest=reference_digest,
            reference_authorization_expires_at=reference_expires_at,
        )
        summary = FinalIntentSummary(
            summary_ref=summary_ref,
            revision=revision,
            state=SummaryState.AWAITING_CONFIRMATION,
            requester_digest=requester.digest,
            requester_class=requester.principal_class,
            audience_ref=draft.audience_ref,
            scheme_id=draft.scheme_id,
            scheme_version=draft.scheme_version,
            registry_schema_version=draft.registry_schema_version,
            blueprint_ref=draft.blueprint_ref,
            action_family_ref=action_ref,
            action_family_version=action_version,
            environment_ref=draft.environment_ref,
            scope_ref=draft.scope_ref,
            owner_ref=draft.owner_ref,
            outcome_code=draft.outcome_code,
            object_changes=tuple(changes),
            unchanged_boundary=_UNCHANGED_BOUNDARY,
            facts=draft.evidence_refs,
            assumptions=draft.assumption_codes,
            excluded_scope=draft.excluded_scope_codes,
            verification_codes=draft.verification_codes,
            stop_codes=draft.stop_codes,
            evidence_policy=draft.evidence_policy,
            maintenance_class=draft.maintenance_class,
            reversibility_class=draft.reversibility_class,
            unresolved_gaps=draft.unresolved_gap_codes,
            risk_class=draft.risk_class,
            external_effects=draft.external_effects,
            approval_class=draft.approval_class,
            separation_required=draft.separation_required,
            reconciliation_strategy=draft.reconciliation_strategy,
            material_reference_metadata=draft.material_reference_metadata,
            reference_authority_ref=self._reference_authorizer.authority_ref,
            reference_authorization_digest=reference_digest,
            reference_authorization_expires_at=reference_expires_at,
            created_at=now_epoch,
            expires_at=expires_at,
            current_state_digest=current_digest,
            proposed_changes_digest=proposed_digest,
            expected_state_digest=expected_digest,
            summary_digest=canonical_digest(content),
        )
        self._summaries[summary.summary_ref] = summary
        return summary

    def confirm_intent(
        self,
        summary_ref: str,
        requester: AuthenticatedRequester,
        interaction: VerifiedConfirmationInteraction,
        *,
        now_epoch: int,
    ) -> ConfirmationRecord:
        """Consume a verified human interaction bound to one exact summary."""

        summary = self._active_summary(summary_ref, now_epoch)
        if now_epoch < summary.created_at:
            raise PlanningDenied("Confirmation time cannot precede the summary.")
        if summary.state is not SummaryState.AWAITING_CONFIRMATION:
            raise PlanningDenied("Final Intent Summary already consumed a decision.")
        if summary.unresolved_gaps:
            raise PlanningDenied("Unresolved gaps prevent intent confirmation.")
        if any(change.fresh_until <= now_epoch for change in summary.object_changes):
            self._invalidate_summary(summary_ref)
            raise PlanningDenied("Current projection expired before confirmation.")
        try:
            reference_expires_at, _ = self._reauthorize_summary(summary, now_epoch)
        except PlanningContractError:
            self._invalidate_summary(summary_ref)
            raise
        if (
            requester.digest != summary.requester_digest
            or interaction.requester_digest != requester.digest
            or interaction.audience_ref != summary.audience_ref
            or interaction.summary_ref != summary.summary_ref
            or interaction.summary_revision != summary.revision
            or interaction.summary_digest != summary.summary_digest
            or interaction.confirmed_at < summary.created_at
            or interaction.confirmed_at > now_epoch
            or interaction.expires_at <= now_epoch
            or interaction.expires_at > summary.expires_at
            or interaction.expires_at > reference_expires_at
        ):
            raise PlanningDenied("Confirmation interaction is not bound to the active summary.")
        if interaction.nonce_digest in self._used_nonce_digests:
            raise PlanningDenied("Confirmation interaction was replayed.")
        if interaction.decision != "affirm":
            self._used_nonce_digests.add(interaction.nonce_digest)
            self._invalidate_summary(summary_ref)
            raise PlanningDenied("The requester denied the Final Intent Summary.")
        confirmation_ref = self._issue("confirmation")
        record_content: dict[str, CanonicalValue] = {
            "audience_ref": summary.audience_ref,
            "confirmation_ref": confirmation_ref,
            "confirmed_at": interaction.confirmed_at,
            "expires_at": interaction.expires_at,
            "interaction_ref_digest": canonical_digest(interaction.interaction_ref),
            "interaction_type": interaction.interaction_type,
            "nonce_digest": interaction.nonce_digest,
            "requester_digest": requester.digest,
            "state": "confirmed",
            "summary_digest": summary.summary_digest,
            "summary_ref": summary.summary_ref,
            "summary_revision": summary.revision,
        }
        record = ConfirmationRecord(
            confirmation_ref=confirmation_ref,
            requester_digest=requester.digest,
            audience_ref=summary.audience_ref,
            summary_ref=summary.summary_ref,
            summary_revision=summary.revision,
            summary_digest=summary.summary_digest,
            interaction_ref_digest=canonical_digest(interaction.interaction_ref),
            interaction_type=interaction.interaction_type,
            nonce_digest=interaction.nonce_digest,
            confirmed_at=interaction.confirmed_at,
            expires_at=interaction.expires_at,
            state="confirmed",
            record_digest=canonical_digest(record_content),
        )
        self._used_nonce_digests.add(interaction.nonce_digest)
        self._confirmations[confirmation_ref] = record
        self._summaries[summary_ref] = replace(summary, state=SummaryState.CONFIRMED)
        return record

    def prepare_plan(
        self,
        summary_ref: str,
        confirmation_ref: str,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> PreparedPlan:
        """Create an immutable plan model that is structurally non-executable."""

        summary = self._active_summary(summary_ref, now_epoch)
        confirmation = self._confirmations.get(confirmation_ref)
        if summary.state is not SummaryState.CONFIRMED or confirmation is None:
            raise PlanningDenied("Exact intent confirmation is required.")
        if any(change.fresh_until <= now_epoch for change in summary.object_changes):
            self._invalidate_summary(summary_ref)
            raise PlanningDenied("Current projection expired before plan preparation.")
        if now_epoch < summary.created_at or now_epoch < confirmation.confirmed_at:
            raise PlanningDenied("Plan preparation time cannot move backwards.")
        try:
            reference_expires_at, _ = self._reauthorize_summary(summary, now_epoch)
        except PlanningContractError:
            self._invalidate_summary(summary_ref)
            raise
        if confirmation_ref in self._used_confirmation_refs:
            raise PlanningDenied("Intent confirmation already prepared a plan.")
        if (
            confirmation.requester_digest != requester.digest
            or requester.digest != summary.requester_digest
            or confirmation.summary_ref != summary.summary_ref
            or confirmation.summary_revision != summary.revision
            or confirmation.summary_digest != summary.summary_digest
            or confirmation.expires_at <= now_epoch
        ):
            raise PlanningDenied("Confirmation does not bind the requested plan.")
        if summary.material_reference_metadata is not None and (
            summary.material_reference_metadata.lifecycle != "available"
        ):
            raise PlanningDenied("Material availability metadata is not ready.")
        mutable_changes = [
            change for change in summary.object_changes if change.change_kind is not ChangeKind.NO_OP
        ]
        if not mutable_changes:
            raise PlanningDenied("A no-op summary cannot produce a prepared plan.")

        action_version = summary.action_family_version
        line_refs: dict[str, str] = {}
        for change in mutable_changes:
            line_refs[change.object_ref] = self._issue("line")
        lines: list[PlanLine] = []
        for change in mutable_changes:
            dependencies = tuple(
                line_refs[candidate.object_ref]
                for candidate in mutable_changes
                if _depends_on(change.object_class, candidate.object_class)
            )
            lines.append(
                PlanLine(
                    line_ref=line_refs[change.object_ref],
                    action_family_ref=summary.action_family_ref,
                    action_family_version=action_version,
                    target_ref=change.object_ref,
                    target_class=change.object_class,
                    change_kind=change.change_kind,
                    expected_current_digest=change.current_projection_digest,
                    expected_state_digest=change.expected_projection_digest,
                    projection_contract_ref=change.projection_contract_ref,
                    depends_on=dependencies,
                )
            )
        plan_ref = self._issue("plan")
        expires_at = min(
            summary.expires_at,
            confirmation.expires_at,
            reference_expires_at,
            *(change.fresh_until for change in summary.object_changes),
        )
        plan_content = _plan_content(
            plan_ref=plan_ref,
            summary=summary,
            confirmation=confirmation,
            requester=requester,
            lines=tuple(lines),
            now_epoch=now_epoch,
            expires_at=expires_at,
        )
        plan = PreparedPlan(
            plan_ref=plan_ref,
            revision=1,
            state=PlanState.PREPARED_NON_EXECUTABLE,
            summary_ref=summary.summary_ref,
            summary_revision=summary.revision,
            summary_digest=summary.summary_digest,
            confirmation_ref=confirmation.confirmation_ref,
            confirmation_digest=confirmation.record_digest,
            requester_digest=requester.digest,
            environment_ref=summary.environment_ref,
            scope_ref=summary.scope_ref,
            scheme_id=summary.scheme_id,
            scheme_version=summary.scheme_version,
            registry_schema_version=summary.registry_schema_version,
            created_at=now_epoch,
            expires_at=expires_at,
            lines=tuple(lines),
            dispatchable=False,
            adapter_registry_bound=False,
            runtime_packaged=False,
            mcp_exposed=False,
            plan_digest=canonical_digest(plan_content),
        )
        self._used_confirmation_refs.add(confirmation_ref)
        self._plans[plan_ref] = plan
        return plan

    def evaluate_pre_write(
        self,
        plan_ref: str,
        projections: Sequence[AuthoritativeProjection],
        *,
        now_epoch: int,
    ) -> PreWriteEvaluation:
        """Compare a hypothetical pre-write reread; never dispatch a write."""

        plan = self._active_plan(plan_ref, now_epoch)
        summary = self._active_summary(plan.summary_ref, now_epoch)
        prior_match = self._prewrite_matches.get(plan_ref)
        if prior_match is not None and now_epoch < prior_match[0]:
            raise PlanningDenied("Pre-write evaluation time cannot move backwards.")
        try:
            self._reauthorize_summary(summary, now_epoch)
            self._validate_projection_references(summary, projections, now_epoch)
            projection_by_ref = _projection_map(projections, summary.object_changes)
            observed = _current_aggregate(
                summary.scheme_id, summary.object_changes, projection_by_ref, now_epoch
            )
        except PlanningContractError:
            self._invalidate_summary(plan.summary_ref)
            return PreWriteEvaluation(
                plan_ref=plan_ref,
                status=PreWriteStatus.UNKNOWN,
                reason_codes=("current_state_unavailable_or_unsafe",),
                evaluated_at=now_epoch,
                observed_state_digest=None,
            )
        if observed != summary.current_state_digest:
            self._invalidate_summary(plan.summary_ref)
            return PreWriteEvaluation(
                plan_ref=plan_ref,
                status=PreWriteStatus.INVALIDATED,
                reason_codes=("current_state_drift",),
                evaluated_at=now_epoch,
                observed_state_digest=observed,
            )
        self._prewrite_matches[plan_ref] = (now_epoch, observed)
        return PreWriteEvaluation(
            plan_ref=plan_ref,
            status=PreWriteStatus.MATCH,
            reason_codes=(),
            evaluated_at=now_epoch,
            observed_state_digest=observed,
        )

    def evaluate_post_write(
        self,
        plan_ref: str,
        projections: Sequence[AuthoritativeProjection],
        *,
        now_epoch: int,
    ) -> PostWriteEvaluation:
        """Model post-write readback comparison without asserting a write occurred."""

        plan = self._active_plan(plan_ref, now_epoch)
        summary = self._active_summary(plan.summary_ref, now_epoch)
        prior_postwrite_at = self._postwrite_evaluated_at.get(plan_ref)
        if prior_postwrite_at is not None and now_epoch < prior_postwrite_at:
            raise PlanningDenied("Post-write evaluation time cannot move backwards.")
        prewrite_match = self._prewrite_matches.get(plan_ref)
        if prewrite_match is None:
            result = PostWriteEvaluation(
                plan_ref=plan_ref,
                status=PostWriteStatus.COMPARISON_UNKNOWN,
                reason_codes=("prewrite_match_not_established",),
                evaluated_at=now_epoch,
                actual_state_digest=None,
                expected_state_digest=summary.expected_state_digest,
            )
            self._postwrite_evaluated_at[plan_ref] = now_epoch
            return result
        if now_epoch < prewrite_match[0]:
            raise PlanningDenied("Post-write evaluation cannot precede the pre-write match.")
        try:
            self._reauthorize_summary(summary, now_epoch)
            self._validate_projection_references(summary, projections, now_epoch)
            projection_by_ref = _projection_map(projections, summary.object_changes)
            actual_digests: list[str] = []
            for change in summary.object_changes:
                projection = projection_by_ref[change.object_ref]
                contract = self.projection_contract(summary.scheme_id, change.object_class)
                _validate_projection(projection, contract, now_epoch)
                actual_digests.append(
                    _expected_projection_digest(
                        contract, projection.object_ref, projection.values
                    )
                )
            actual = canonical_digest(actual_digests)
        except PlanningContractError:
            result = PostWriteEvaluation(
                plan_ref=plan_ref,
                status=PostWriteStatus.COMPARISON_UNKNOWN,
                reason_codes=("post_write_state_unavailable_or_unsafe",),
                evaluated_at=now_epoch,
                actual_state_digest=None,
                expected_state_digest=summary.expected_state_digest,
            )
            self._postwrite_evaluated_at[plan_ref] = now_epoch
            return result
        status = (
            PostWriteStatus.EXPECTED_STATE_MATCHES
            if actual == summary.expected_state_digest
            else PostWriteStatus.EXPECTED_STATE_MISMATCH
        )
        reasons = (
            ()
            if status is PostWriteStatus.EXPECTED_STATE_MATCHES
            else ("actual_expected_mismatch",)
        )
        result = PostWriteEvaluation(
            plan_ref=plan_ref,
            status=status,
            reason_codes=reasons,
            evaluated_at=now_epoch,
            actual_state_digest=actual,
            expected_state_digest=summary.expected_state_digest,
        )
        self._postwrite_evaluated_at[plan_ref] = now_epoch
        return result

    def _validate_draft(self, draft: SchemeDraft, registered_risk: str) -> None:
        if draft.risk_class != registered_risk:
            raise PlanningDenied("Scheme risk does not match its action-family placeholder.")
        classes = [item.object_class for item in draft.desired_objects]
        if draft.scheme_id is SchemeId.ACCESS_DOMAIN:
            if set(classes) - _ACCESS_CLASSES or classes.count(ObjectClass.PUBLIC_FOLDER) != 1:
                raise PlanningDenied("AccessDomainScheme object shape is invalid.")
            if draft.material_reference_metadata is not None:
                raise PlanningDenied("AccessDomainScheme cannot carry material metadata.")
            folder = next(
                item
                for item in draft.desired_objects
                if item.object_class is ObjectClass.PUBLIC_FOLDER
            )
            if not folder.desired_exists:
                raise PlanningDenied("AccessDomainScheme needs an existing expected folder anchor.")
            grant_relations = [
                (
                    dict(item.desired_fields).get("subject_class"),
                    dict(item.desired_fields).get("subject_ref"),
                )
                for item in draft.desired_objects
                if item.object_class is ObjectClass.ACCESS_GRANT and item.desired_exists
            ]
            if len(grant_relations) != len(set(grant_relations)):
                raise PlanningDenied("AccessDomainScheme ACL relations are duplicated.")
            if (
                len(classes) > 19
                or classes.count(ObjectClass.ACCESS_GRANT) > 16
                or classes.count(ObjectClass.CLASSIFICATION_BINDING) > 1
                or classes.count(ObjectClass.FOLDER_POLICY_BINDING) > 1
            ):
                raise PlanningDenied("AccessDomainScheme cardinality is invalid.")
        else:
            if set(classes) - _SECRET_CLASSES or not _REQUIRED_SECRET_CLASSES.issubset(classes):
                raise PlanningDenied("SecretOnboardingScheme object shape is invalid.")
            if any(classes.count(item) != 1 for item in _REQUIRED_SECRET_CLASSES):
                raise PlanningDenied("SecretOnboardingScheme needs one required relation of each class.")
            required = [
                item
                for item in draft.desired_objects
                if item.object_class in _REQUIRED_SECRET_CLASSES
            ]
            if any(not item.desired_exists for item in required):
                raise PlanningDenied("SecretOnboardingScheme required relations must exist.")
            template = next(
                item
                for item in required
                if item.object_class is ObjectClass.TEMPLATE_BINDING
            )
            if dict(template.desired_fields).get("compatibility") != "compatible":
                raise PlanningDenied("SecretOnboardingScheme template compatibility is unresolved.")
            if any(classes.count(item) > 1 for item in _SECRET_CLASSES - _REQUIRED_SECRET_CLASSES):
                raise PlanningDenied("SecretOnboardingScheme optional relation is duplicated.")
            if draft.material_reference_metadata is None:
                raise PlanningDenied("SecretOnboardingScheme needs safe material metadata.")
        if registered_risk == "high" and (
            draft.approval_class != "independent_approval" or not draft.separation_required
        ):
            raise PlanningDenied("High-risk intent needs independent approval separation.")
        for desired in draft.desired_objects:
            contract = self.projection_contract(draft.scheme_id, desired.object_class)
            contract.validate_fields(
                {"exists": desired.desired_exists, **dict(desired.desired_fields)},
                complete=True,
            )

    def _validate_references(
        self,
        draft: SchemeDraft,
        projections: Sequence[AuthoritativeProjection],
        requester: AuthenticatedRequester,
        now_epoch: int,
    ) -> tuple[int, str]:
        references: list[tuple[str, str]] = [
            (draft.environment_ref, "environment"),
            (draft.scope_ref, "scope"),
            (draft.owner_ref, "owner"),
            (draft.audience_ref, "audience"),
            *((reference, "evidence") for reference in draft.evidence_refs),
        ]
        for desired in draft.desired_objects:
            references.append(
                (desired.object_ref, f"object_{_object_kind_code(desired.object_class)}")
            )
            contract = self.projection_contract(draft.scheme_id, desired.object_class)
            for field, value in desired.desired_fields:
                rule = contract.rules[field]
                if rule.kind is FieldKind.REFERENCE:
                    if type(value) is not str:
                        raise PlanningDenied("Reference field value is invalid.")
                    references.append((value, f"field_{field}"))
        projection_by_ref = {item.object_ref: item for item in projections}
        for desired in draft.desired_objects:
            projection = projection_by_ref[desired.object_ref]
            references.extend(
                self._projection_references(
                    projection,
                    desired.object_class,
                )
            )
        return self._authorize_references(
            references,
            requester_digest=requester.digest,
            environment_ref=draft.environment_ref,
            scope_ref=draft.scope_ref,
            now_epoch=now_epoch,
        )

    def _authorize_references(
        self,
        references: Sequence[tuple[str, str]],
        *,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
        now_epoch: int,
    ) -> tuple[int, str]:
        decisions: list[VerifiedReferenceDecision] = []
        for reference, reference_kind in sorted(set(references)):
            decision = self._reference_authorizer.authorize(
                reference,
                reference_kind=reference_kind,
                requester_digest=requester_digest,
                environment_ref=environment_ref,
                scope_ref=scope_ref,
                now_epoch=now_epoch,
            )
            if (
                decision.authority_ref != self._reference_authorizer.authority_ref
                or decision.reference_digest != canonical_digest(reference)
                or decision.reference_kind != reference_kind
                or decision.requester_digest != requester_digest
                or decision.environment_digest != canonical_digest(environment_ref)
                or decision.scope_digest != canonical_digest(scope_ref)
                or not decision.authorized
                or decision.checked_at > now_epoch
                or decision.expires_at <= now_epoch
            ):
                raise PlanningDenied(
                    f"Reference is not authorized for the exact {reference_kind} boundary."
                )
            decisions.append(decision)
        if not decisions:
            raise PlanningDenied("Reference authorization set cannot be empty.")
        return (
            min(decision.expires_at for decision in decisions),
            canonical_digest([decision.as_dict() for decision in decisions]),
        )

    def _reauthorize_summary(
        self,
        summary: FinalIntentSummary,
        now_epoch: int,
    ) -> tuple[int, str]:
        references: list[tuple[str, str]] = [
            (summary.environment_ref, "environment"),
            (summary.scope_ref, "scope"),
            (summary.owner_ref, "owner"),
            (summary.audience_ref, "audience"),
            *((reference, "evidence") for reference in summary.facts),
        ]
        for change in summary.object_changes:
            references.append(
                (change.object_ref, f"object_{_object_kind_code(change.object_class)}")
            )
            references.append((change.projection_source_ref, "projection_source"))
            contract = self.projection_contract(summary.scheme_id, change.object_class)
            for fields in (
                change.current_fields,
                change.proposed_fields,
                change.expected_fields,
            ):
                for field, value in fields:
                    rule = contract.rules.get(field)
                    if rule is not None and rule.kind is FieldKind.REFERENCE:
                        if type(value) is not str:
                            raise PlanningDenied("Summary reference field value is invalid.")
                        references.append((value, f"field_{field}"))
        return self._authorize_references(
            references,
            requester_digest=summary.requester_digest,
            environment_ref=summary.environment_ref,
            scope_ref=summary.scope_ref,
            now_epoch=now_epoch,
        )

    def _validate_projection_references(
        self,
        summary: FinalIntentSummary,
        projections: Sequence[AuthoritativeProjection],
        now_epoch: int,
    ) -> tuple[int, str]:
        changes = {change.object_ref: change for change in summary.object_changes}
        references: list[tuple[str, str]] = []
        for projection in projections:
            change = changes.get(projection.object_ref)
            if change is None:
                raise PlanningDenied("Projection reference is outside the confirmed summary.")
            references.extend(self._projection_references(projection, change.object_class))
        return self._authorize_references(
            references,
            requester_digest=summary.requester_digest,
            environment_ref=summary.environment_ref,
            scope_ref=summary.scope_ref,
            now_epoch=now_epoch,
        )

    def _projection_references(
        self,
        projection: AuthoritativeProjection,
        object_class: ObjectClass,
    ) -> list[tuple[str, str]]:
        contract = self.projection_contract(
            SchemeId.ACCESS_DOMAIN
            if object_class in _ACCESS_CLASSES
            else SchemeId.SECRET_ONBOARDING,
            object_class,
        )
        references = [
            (projection.object_ref, f"object_{_object_kind_code(object_class)}"),
            (contract.source_ref, "projection_source"),
        ]
        for field, value in projection.fields:
            rule = contract.rules.get(field)
            if rule is not None and rule.kind is FieldKind.REFERENCE:
                if type(value) is not str:
                    raise PlanningDenied("Projection reference field value is invalid.")
                references.append((value, f"field_{field}"))
        return references

    def _issue(self, purpose: str) -> str:
        reference = require_ref(self._issuer.issue(purpose), f"issued {purpose}_ref")
        if reference in self._issued_refs:
            raise PlanningDenied("Reference issuer returned a duplicate reference.")
        self._issued_refs.add(reference)
        return reference

    def _active_summary(self, summary_ref: str, now_epoch: int) -> FinalIntentSummary:
        summary = self._summaries.get(summary_ref)
        if summary is None or summary.state is SummaryState.INVALIDATED:
            raise PlanningDenied("Final Intent Summary is unavailable.")
        if now_epoch < summary.created_at:
            raise PlanningDenied("Final Intent Summary time cannot move backwards.")
        if summary.expires_at <= now_epoch:
            self._invalidate_summary(summary_ref)
            raise PlanningDenied("Final Intent Summary expired.")
        return summary

    def _active_plan(self, plan_ref: str, now_epoch: int) -> PreparedPlan:
        plan = self._plans.get(plan_ref)
        if plan is None or plan.state is PlanState.INVALIDATED:
            raise PlanningDenied("Prepared plan is unavailable.")
        if now_epoch < plan.created_at:
            raise PlanningDenied("Prepared plan time cannot move backwards.")
        if plan.expires_at <= now_epoch:
            self._invalidate_summary(plan.summary_ref)
            raise PlanningDenied("Prepared plan expired.")
        return plan

    def _invalidate_summary(self, summary_ref: str) -> None:
        summary = self._summaries.get(summary_ref)
        if summary is not None:
            self._summaries[summary_ref] = replace(summary, state=SummaryState.INVALIDATED)
        for confirmation_ref, record in tuple(self._confirmations.items()):
            if record.summary_ref == summary_ref:
                del self._confirmations[confirmation_ref]
        for plan_ref, plan in tuple(self._plans.items()):
            if plan.summary_ref == summary_ref:
                self._invalidate_plan(plan_ref)

    def _invalidate_plan(self, plan_ref: str) -> None:
        plan = self._plans.get(plan_ref)
        if plan is not None:
            self._plans[plan_ref] = replace(plan, state=PlanState.INVALIDATED)
        self._prewrite_matches.pop(plan_ref, None)
        self._postwrite_evaluated_at.pop(plan_ref, None)


def _index_records(value: object, kind: str) -> dict[str, Mapping[str, object]]:
    if not isinstance(value, list):
        raise PlanningDenied(f"Registry {kind} collection is invalid.")
    result: dict[str, Mapping[str, object]] = {}
    for item in value:
        if not isinstance(item, Mapping) or type(item.get("id")) is not str:
            raise PlanningDenied(f"Registry {kind} record is invalid.")
        identifier = cast(str, item["id"])
        if identifier in result:
            raise PlanningDenied(f"Registry {kind} identifiers are duplicated.")
        result[identifier] = cast(Mapping[str, object], item)
    return result


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(type(item) is not str for item in value):
        raise PlanningDenied("Registry reference list is invalid.")
    return tuple(cast(list[str], value))


def _validate_projection(
    projection: AuthoritativeProjection,
    expected_contract: ProjectionContract,
    now_epoch: int,
) -> None:
    if projection.contract != expected_contract:
        raise PlanningDenied("Projection contract differs from the fixed M2 contract.")
    if (
        not projection.authoritative
        or not projection.complete
        or projection.contradictory
        or projection.c3_included
        or projection.raw_response_included
        or projection.observed_at > now_epoch
        or projection.fresh_until <= now_epoch
    ):
        raise PlanningDenied("Projection is unavailable, unsafe, or stale.")


def _expected_projection_digest(
    contract: ProjectionContract,
    object_ref: str,
    values: Mapping[str, object],
) -> str:
    validated = contract.validate_fields(values, complete=True)
    return canonical_digest(
        {
            "contract": contract.as_dict(),
            "fields": dict(validated),
            "object_ref": object_ref,
        }
    )


def _summary_content(
    *,
    summary_ref: str,
    revision: int,
    requester: AuthenticatedRequester,
    draft: SchemeDraft,
    action_ref: str,
    action_version: str,
    changes: tuple[ObjectChange, ...],
    current_digest: str,
    proposed_digest: str,
    expected_digest: str,
    now_epoch: int,
    expires_at: int,
    reference_authority_ref: str,
    reference_authorization_digest: str,
    reference_authorization_expires_at: int,
) -> dict[str, CanonicalValue]:
    return {
        "action_family_ref": action_ref,
        "action_family_version": action_version,
        "approval_class": draft.approval_class,
        "assumptions": list(draft.assumption_codes),
        "audience_ref": draft.audience_ref,
        "blueprint_ref": draft.blueprint_ref,
        "created_at": now_epoch,
        "current_state_digest": current_digest,
        "environment_ref": draft.environment_ref,
        "expected_state_digest": expected_digest,
        "expires_at": expires_at,
        "excluded_scope": list(draft.excluded_scope_codes),
        "external_effects": list(draft.external_effects),
        "facts": list(draft.evidence_refs),
        "evidence_policy": draft.evidence_policy,
        "material_reference_metadata": (
            draft.material_reference_metadata.as_dict()
            if draft.material_reference_metadata is not None
            else None
        ),
        "object_changes": [change.as_dict() for change in changes],
        "outcome_code": draft.outcome_code,
        "owner_ref": draft.owner_ref,
        "proposed_changes_digest": proposed_digest,
        "reconciliation_strategy": draft.reconciliation_strategy,
        "reference_authority_ref": reference_authority_ref,
        "reference_authorization_digest": reference_authorization_digest,
        "reference_authorization_expires_at": reference_authorization_expires_at,
        "registry_schema_version": draft.registry_schema_version,
        "requester_class": requester.principal_class,
        "requester_digest": requester.digest,
        "revision": revision,
        "reversibility_class": draft.reversibility_class,
        "risk_class": draft.risk_class,
        "scheme_id": draft.scheme_id.value,
        "scheme_version": draft.scheme_version,
        "scope_ref": draft.scope_ref,
        "separation_required": draft.separation_required,
        "summary_ref": summary_ref,
        "stop_codes": list(draft.stop_codes),
        "unchanged_boundary": list(_UNCHANGED_BOUNDARY),
        "unresolved_gaps": list(draft.unresolved_gap_codes),
        "verification_codes": list(draft.verification_codes),
        "maintenance_class": draft.maintenance_class,
    }


def _plan_content(
    *,
    plan_ref: str,
    summary: FinalIntentSummary,
    confirmation: ConfirmationRecord,
    requester: AuthenticatedRequester,
    lines: tuple[PlanLine, ...],
    now_epoch: int,
    expires_at: int,
) -> dict[str, CanonicalValue]:
    return {
        "adapter_registry_bound": False,
        "confirmation_digest": confirmation.record_digest,
        "confirmation_ref": confirmation.confirmation_ref,
        "created_at": now_epoch,
        "dispatchable": False,
        "environment_ref": summary.environment_ref,
        "expires_at": expires_at,
        "lines": [line.as_dict() for line in lines],
        "mcp_exposed": False,
        "plan_ref": plan_ref,
        "registry_schema_version": summary.registry_schema_version,
        "requester_digest": requester.digest,
        "revision": 1,
        "runtime_packaged": False,
        "scheme_id": summary.scheme_id.value,
        "scheme_version": summary.scheme_version,
        "scope_ref": summary.scope_ref,
        "summary_digest": summary.summary_digest,
        "summary_ref": summary.summary_ref,
        "summary_revision": summary.revision,
    }


def _depends_on(current: ObjectClass, candidate: ObjectClass) -> bool:
    current_order = _DEPENDENCY_ORDER[current]
    candidate_order = _DEPENDENCY_ORDER[candidate]
    if candidate_order >= current_order:
        return False
    if current in _ACCESS_CLASSES and candidate not in _ACCESS_CLASSES:
        return False
    if current in _SECRET_CLASSES and candidate not in _SECRET_CLASSES:
        return False
    if current is ObjectClass.SECRET_METADATA:
        return candidate in {
            ObjectClass.FOLDER_BINDING,
            ObjectClass.TARGET,
            ObjectClass.TEMPLATE_BINDING,
        }
    if current in {ObjectClass.LAUNCHER_BINDING, ObjectClass.POLICY_BINDING}:
        return candidate is ObjectClass.SECRET_METADATA
    if current in {
        ObjectClass.ACCESS_GRANT,
        ObjectClass.CLASSIFICATION_BINDING,
        ObjectClass.FOLDER_POLICY_BINDING,
    }:
        return candidate is ObjectClass.PUBLIC_FOLDER
    return False


def _object_kind_code(object_class: ObjectClass) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", object_class.value).lower()


def _projection_map(
    projections: Sequence[AuthoritativeProjection],
    changes: Sequence[ObjectChange],
) -> dict[str, AuthoritativeProjection]:
    result = {item.object_ref: item for item in projections}
    expected = {change.object_ref for change in changes}
    if len(result) != len(projections) or set(result) != expected:
        raise PlanningDenied("Projection set does not match the confirmed object set.")
    return result


def _current_aggregate(
    scheme_id: SchemeId,
    changes: Sequence[ObjectChange],
    projections: Mapping[str, AuthoritativeProjection],
    now_epoch: int,
) -> str:
    digests: list[str] = []
    for change in changes:
        projection = projections[change.object_ref]
        contract = M2PlanningEngine.projection_contract(scheme_id, change.object_class)
        _validate_projection(projection, contract, now_epoch)
        digests.append(projection.state_digest)
    return canonical_digest(digests)
