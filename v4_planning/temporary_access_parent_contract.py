"""Repository-only parent assessment for the BP015 temporary-access plan.

This module validates only the catalog relationship and one already-validated
IdentityLifecycleScheme draft.  It deliberately creates neither a C/P/E plan
nor a product-state claim: no provider, runtime, confirmation, transport, or
executor participates in the assessment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .models import ObjectClass, PlanningContractError, SchemeDraft, SchemeId, require_ref


TEMPORARY_ACCESS_PARENT_CONTRACT = "fortipam-bp015-parent-assessment-v1"
BP015_REF = "FPA-BP-015"
ACTION_FAMILY_REF = "sponsored-and-temporary-access-plan"
SCHEME_REFS = (
    "IdentityLifecycleScheme",
    "ApprovalAndObserveScheme",
    "AccessReviewScheme",
)
COVERED_REQUIREMENTS = (
    "sponsor",
    "scope",
    "end_date",
    "group",
    "review_cadence",
    "revocation_owner",
)
REVIEW_CADENCE_CODES = frozenset({"weekly", "monthly", "quarterly"})
NEGATIVE_TESTS = frozenset({"denied_after_expiry", "explicit_revoke"})
UNPROVEN_LAYERS = (
    "identity",
    "group_membership",
    "entitlement",
    "schedule",
    "approval_and_sponsor_visibility",
    "audit_and_access_review",
    "current_state",
)


class TemporaryAccessParentContractError(ValueError):
    """Raised when a BP015 parent assessment is outside its closed contract."""


@dataclass(frozen=True, slots=True)
class TemporaryAccessParentAssessment:
    """A bound BP015 requirements assessment without product-state authority."""

    sponsor_ref: str
    group_ref: str
    entitlement_boundary_ref: str
    scope_ref: str
    end_date_ref: str
    revocation_owner_ref: str
    evidence_owner_ref: str
    review_cadence_code: str
    negative_test: str

    def __post_init__(self) -> None:
        for field, value in (
            ("sponsor_ref", self.sponsor_ref),
            ("group_ref", self.group_ref),
            ("entitlement_boundary_ref", self.entitlement_boundary_ref),
            ("scope_ref", self.scope_ref),
            ("end_date_ref", self.end_date_ref),
            ("revocation_owner_ref", self.revocation_owner_ref),
            ("evidence_owner_ref", self.evidence_owner_ref),
        ):
            _require_opaque_ref(value, field)
        if self.review_cadence_code not in REVIEW_CADENCE_CODES:
            raise TemporaryAccessParentContractError("Review cadence is not supported.")
        if self.negative_test not in NEGATIVE_TESTS:
            raise TemporaryAccessParentContractError("Negative test is not supported.")

    @property
    def contract(self) -> str:
        return TEMPORARY_ACCESS_PARENT_CONTRACT

    @property
    def blueprint_ref(self) -> str:
        return BP015_REF

    @property
    def action_family_ref(self) -> str:
        return ACTION_FAMILY_REF

    @property
    def scheme_refs(self) -> tuple[str, ...]:
        return SCHEME_REFS

    @property
    def covered_requirements(self) -> tuple[str, ...]:
        return COVERED_REQUIREMENTS

    @property
    def approval_control_required(self) -> bool:
        return True

    @property
    def sponsor_visibility_required(self) -> bool:
        return True

    @property
    def audit_evidence_required(self) -> bool:
        return True

    @property
    def approval_evidence_state(self) -> str:
        return "unproven"

    @property
    def identity_contract_state(self) -> str:
        return "fake_only"

    @property
    def current_state_evidence(self) -> str:
        return "unavailable"

    @property
    def outcome(self) -> str:
        return "plan_only"

    @property
    def evidence_state(self) -> str:
        return "evidence_gap"

    @property
    def reconciliation_strategy(self) -> str:
        return "reconcile_or_manual"

    @property
    def execution_ready(self) -> bool:
        return False

    @property
    def device_access(self) -> bool:
        return False

    @property
    def dispatchable(self) -> bool:
        return False

    @property
    def unproven_layers(self) -> tuple[str, ...]:
        return UNPROVEN_LAYERS

    def as_dict(self) -> dict[str, object]:
        """Render only opaque bindings and fixed non-executable conclusions."""

        return {
            "action_family_ref": self.action_family_ref,
            "approval_control_required": self.approval_control_required,
            "approval_evidence_state": self.approval_evidence_state,
            "audit_evidence_required": self.audit_evidence_required,
            "blueprint_ref": self.blueprint_ref,
            "bound_requirement_refs": {
                "end_date": self.end_date_ref,
                "entitlement_boundary": self.entitlement_boundary_ref,
                "evidence_owner": self.evidence_owner_ref,
                "group": self.group_ref,
                "revocation_owner": self.revocation_owner_ref,
                "scope": self.scope_ref,
                "sponsor": self.sponsor_ref,
            },
            "contract": self.contract,
            "covered_requirements": list(self.covered_requirements),
            "current_state_evidence": self.current_state_evidence,
            "device_access": self.device_access,
            "dispatchable": self.dispatchable,
            "evidence_state": self.evidence_state,
            "execution_ready": self.execution_ready,
            "identity_contract_state": self.identity_contract_state,
            "negative_test": self.negative_test,
            "outcome": self.outcome,
            "reconciliation_strategy": self.reconciliation_strategy,
            "review_cadence_code": self.review_cadence_code,
            "scheme_refs": list(self.scheme_refs),
            "sponsor_visibility_required": self.sponsor_visibility_required,
            "unproven_layers": list(self.unproven_layers),
        }


def assess_temporary_access_parent(
    registry: Mapping[str, object],
    identity_draft: SchemeDraft,
    *,
    entitlement_boundary_ref: str,
    scope_ref: str,
    end_date_ref: str,
    revocation_owner_ref: str,
    evidence_owner_ref: str,
    review_cadence_code: str,
    negative_test: str,
    approval_control_required: bool,
    sponsor_visibility_required: bool,
    audit_evidence_required: bool,
) -> TemporaryAccessParentAssessment:
    """Assess one fully bounded BP015 request without reading or changing a product."""

    for field, value in (
        ("entitlement_boundary_ref", entitlement_boundary_ref),
        ("scope_ref", scope_ref),
        ("end_date_ref", end_date_ref),
        ("revocation_owner_ref", revocation_owner_ref),
        ("evidence_owner_ref", evidence_owner_ref),
    ):
        _require_opaque_ref(value, field)
    registry_schema_version = _validate_registry_relationship(registry)
    sponsor_ref, group_ref = _validate_identity_draft(
        identity_draft, scope_ref, registry_schema_version
    )
    if review_cadence_code not in REVIEW_CADENCE_CODES:
        raise TemporaryAccessParentContractError("Review cadence is not supported.")
    if negative_test not in NEGATIVE_TESTS:
        raise TemporaryAccessParentContractError("Negative test is not supported.")
    if (
        approval_control_required is not True
        or sponsor_visibility_required is not True
        or audit_evidence_required is not True
    ):
        raise TemporaryAccessParentContractError(
            "Approval, sponsor visibility, and audit evidence are required."
        )
    return TemporaryAccessParentAssessment(
        sponsor_ref=sponsor_ref,
        group_ref=group_ref,
        entitlement_boundary_ref=entitlement_boundary_ref,
        scope_ref=scope_ref,
        end_date_ref=end_date_ref,
        revocation_owner_ref=revocation_owner_ref,
        evidence_owner_ref=evidence_owner_ref,
        review_cadence_code=review_cadence_code,
        negative_test=negative_test,
    )


def _validate_registry_relationship(registry: Mapping[str, object]) -> str:
    registry_schema_version = registry.get("schema_version")
    if not isinstance(registry_schema_version, str):
        raise TemporaryAccessParentContractError("BP015 registry schema is unavailable.")
    blueprint = _find_registry_record(registry, "blueprints", BP015_REF)
    action = _find_registry_record(registry, "actions", ACTION_FAMILY_REF)
    schemes = {
        scheme_ref: _find_registry_record(registry, "schemes", scheme_ref)
        for scheme_ref in SCHEME_REFS
    }
    identity_evidence = schemes["IdentityLifecycleScheme"].get(
        "implementation_evidence"
    )
    if (
        blueprint.get("action_refs") != [ACTION_FAMILY_REF]
        or blueprint.get("scheme_refs") != list(SCHEME_REFS)
        or action.get("blueprint_refs") != [BP015_REF]
        or action.get("scheme_refs") != list(SCHEME_REFS)
        or action.get("record_kind") != "action_family_placeholder"
        or action.get("atomic_contract") is not False
        or action.get("executable") is not False
        or action.get("adapter") != "none"
        or action.get("status") != "design_only"
        or action.get("maturity") != "catalogued"
        or action.get("lifecycle") != "catalogued"
        or action.get("risk_tier") != "medium"
        or schemes["IdentityLifecycleScheme"].get("version") != "1.0.0"
        or schemes["IdentityLifecycleScheme"].get("status") != "planned"
        or schemes["IdentityLifecycleScheme"].get("maturity") != "contract_tested"
        or schemes["IdentityLifecycleScheme"].get("lifecycle") != "contract_tested"
        or not isinstance(identity_evidence, Mapping)
        or identity_evidence.get("evidence_status") != "contract_tested"
        or identity_evidence.get("evidence_kind") != "fake_only_contract"
        or identity_evidence.get("profile_blueprint_refs") != [BP015_REF]
        or identity_evidence.get("device_access") is not False
        or identity_evidence.get("dispatchable") is not False
        or identity_evidence.get("executor_runtime_packaged") is not False
        or identity_evidence.get("executor_mcp_exposed") is not False
        or identity_evidence.get("planner_runtime_packaged") is not True
        or identity_evidence.get("planner_mcp_exposed") is not False
        or "projection_profile" in identity_evidence
    ):
        raise TemporaryAccessParentContractError(
            "BP015 registry relationship is not exact."
        )
    return registry_schema_version


def _find_registry_record(
    registry: Mapping[str, object], collection: str, record_id: str
) -> Mapping[str, object]:
    entries = registry.get(collection)
    if not isinstance(entries, list):
        raise TemporaryAccessParentContractError("BP015 registry relationship is unavailable.")
    matches = [item for item in entries if isinstance(item, Mapping) and item.get("id") == record_id]
    if len(matches) != 1:
        raise TemporaryAccessParentContractError("BP015 registry record is unavailable.")
    return matches[0]


def _validate_identity_draft(
    draft: SchemeDraft, scope_ref: str, registry_schema_version: str
) -> tuple[str, str]:
    if (
        draft.scheme_id is not SchemeId.IDENTITY_LIFECYCLE
        or draft.scheme_version != "1.0.0"
        or draft.registry_schema_version != registry_schema_version
        or draft.blueprint_ref != BP015_REF
        or draft.outcome_code != "manage_sponsored_group_membership"
        or draft.scope_ref != scope_ref
        or draft.risk_class != "medium"
        or draft.material_reference_metadata is not None
        or len(draft.desired_objects) != 2
    ):
        raise TemporaryAccessParentContractError("Identity lifecycle draft is not BP015 exact.")
    group = next(
        (item for item in draft.desired_objects if item.object_class is ObjectClass.SPONSORED_GROUP),
        None,
    )
    member = next(
        (item for item in draft.desired_objects if item.object_class is ObjectClass.SPONSORED_GROUP_MEMBER),
        None,
    )
    if group is None or member is None or not group.desired_exists or not member.desired_exists:
        raise TemporaryAccessParentContractError("Identity lifecycle object shape is invalid.")
    group_fields = dict(group.desired_fields)
    member_fields = dict(member.desired_fields)
    maximum_members = group_fields.get("maximum_members")
    if (
        set(group_fields) != {
            "sponsor_admin_ref",
            "maximum_members",
            "sponsor_admin_scope_enforced",
        }
        or set(member_fields)
        != {"sponsored_group_ref", "member_ref", "schedule_ref", "membership_status"}
        or group_fields.get("sponsor_admin_scope_enforced") is not True
        or not isinstance(maximum_members, int)
        or isinstance(maximum_members, bool)
        or maximum_members <= 0
        or maximum_members > 2_147_483_647
        or member_fields.get("sponsored_group_ref") != group.object_ref
        or member_fields.get("membership_status") not in {"active", "disabled"}
    ):
        raise TemporaryAccessParentContractError("Identity lifecycle fixed profile is invalid.")
    sponsor_ref = group_fields.get("sponsor_admin_ref")
    member_ref = member_fields.get("member_ref")
    schedule_ref = member_fields.get("schedule_ref")
    if not isinstance(sponsor_ref, str) or not isinstance(member_ref, str) or not isinstance(schedule_ref, str):
        raise TemporaryAccessParentContractError("Identity lifecycle references are invalid.")
    for field, value in (
        ("sponsor_admin_ref", sponsor_ref),
        ("group_ref", group.object_ref),
        ("member_ref", member_ref),
        ("schedule_ref", schedule_ref),
    ):
        _require_opaque_ref(value, field)
    return sponsor_ref, group.object_ref


def _require_opaque_ref(value: str, field: str) -> None:
    try:
        require_ref(value, field)
    except PlanningContractError as exc:
        raise TemporaryAccessParentContractError(
            f"{field} must be an opaque bounded reference."
        ) from exc


__all__ = [
    "ACTION_FAMILY_REF",
    "BP015_REF",
    "COVERED_REQUIREMENTS",
    "NEGATIVE_TESTS",
    "REVIEW_CADENCE_CODES",
    "SCHEME_REFS",
    "TEMPORARY_ACCESS_PARENT_CONTRACT",
    "TemporaryAccessParentAssessment",
    "TemporaryAccessParentContractError",
    "assess_temporary_access_parent",
]
