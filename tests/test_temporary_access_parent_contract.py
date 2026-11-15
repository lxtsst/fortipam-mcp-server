from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from scripts.v4_registry import load_registry
from v4_planning import DesiredObject, ObjectClass, SchemeDraft, SchemeId
from v4_planning.temporary_access_parent_contract import (
    ACTION_FAMILY_REF,
    BP015_REF,
    COVERED_REQUIREMENTS,
    SCHEME_REFS,
    TEMPORARY_ACCESS_PARENT_CONTRACT,
    TemporaryAccessParentAssessment,
    TemporaryAccessParentContractError,
    assess_temporary_access_parent,
)


def _desired(
    object_ref: str, object_class: ObjectClass, fields: dict[str, bool | str | int]
) -> DesiredObject:
    return DesiredObject(
        object_ref=object_ref,
        object_class=object_class,
        desired_exists=True,
        desired_fields=tuple(sorted(fields.items())),
    )


def _identity_draft() -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.IDENTITY_LIFECYCLE,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref=BP015_REF,
        environment_ref="temporary-environment-ref01",
        scope_ref="temporary-scope-reference01",
        owner_ref="temporary-owner-reference01",
        audience_ref="temporary-audience-ref001",
        outcome_code="manage_sponsored_group_membership",
        desired_objects=(
            _desired(
                "sponsored-group-object-ref01",
                ObjectClass.SPONSORED_GROUP,
                {
                    "maximum_members": 1,
                    "sponsor_admin_ref": "sponsor-admin-reference01",
                    "sponsor_admin_scope_enforced": True,
                },
            ),
            _desired(
                "sponsored-member-object-ref01",
                ObjectClass.SPONSORED_GROUP_MEMBER,
                {
                    "member_ref": "sponsored-member-reference01",
                    "membership_status": "active",
                    "schedule_ref": "sponsored-schedule-ref01",
                    "sponsored_group_ref": "sponsored-group-object-ref01",
                },
            ),
        ),
        approval_class="owner_approval",
        separation_required=False,
        risk_class="medium",
        external_effects=("sponsored_access_metadata_change",),
        assumption_codes=("sponsor_relationship_prevalidated",),
        excluded_scope_codes=("credential_material", "runtime_execution"),
        verification_codes=("sponsored_membership_relation_readback",),
        stop_codes=("current_state_drift", "projection_unavailable"),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="none",
        reversibility_class="manual_reconciliation_only",
        evidence_refs=("temporary-evidence-reference01",),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
    )


def _assess(**overrides: object) -> TemporaryAccessParentAssessment:
    values: dict[str, object] = {
        "entitlement_boundary_ref": "temporary-entitlement-ref01",
        "scope_ref": "temporary-scope-reference01",
        "end_date_ref": "temporary-end-date-reference01",
        "revocation_owner_ref": "temporary-revocation-owner01",
        "evidence_owner_ref": "temporary-evidence-owner-ref01",
        "review_cadence_code": "monthly",
        "negative_test": "denied_after_expiry",
        "approval_control_required": True,
        "sponsor_visibility_required": True,
        "audit_evidence_required": True,
    }
    values.update(overrides)
    return assess_temporary_access_parent(
        load_registry(), _identity_draft(), **values  # type: ignore[arg-type]
    )


def test_parent_assessment_is_bound_and_non_executable() -> None:
    assessment = _assess()
    result = assessment.as_dict()

    assert result["contract"] == TEMPORARY_ACCESS_PARENT_CONTRACT
    assert result["blueprint_ref"] == BP015_REF
    assert result["action_family_ref"] == ACTION_FAMILY_REF
    assert result["scheme_refs"] == list(SCHEME_REFS)
    assert result["covered_requirements"] == list(COVERED_REQUIREMENTS)
    assert result["bound_requirement_refs"] == {
        "end_date": "temporary-end-date-reference01",
        "entitlement_boundary": "temporary-entitlement-ref01",
        "evidence_owner": "temporary-evidence-owner-ref01",
        "group": "sponsored-group-object-ref01",
        "revocation_owner": "temporary-revocation-owner01",
        "scope": "temporary-scope-reference01",
        "sponsor": "sponsor-admin-reference01",
    }
    assert result["approval_control_required"] is True
    assert result["sponsor_visibility_required"] is True
    assert result["audit_evidence_required"] is True
    assert result["approval_evidence_state"] == "unproven"
    assert result["identity_contract_state"] == "fake_only"
    assert result["current_state_evidence"] == "unavailable"
    assert result["outcome"] == "plan_only"
    assert result["evidence_state"] == "evidence_gap"
    assert result["execution_ready"] is False
    assert result["device_access"] is False
    assert result["dispatchable"] is False
    assert result["reconciliation_strategy"] == "reconcile_or_manual"
    assert result["unproven_layers"] == [
        "identity",
        "group_membership",
        "entitlement",
        "schedule",
        "approval_and_sponsor_visibility",
        "audit_and_access_review",
        "current_state",
    ]
    assert not {
        "PreparedPlan",
        "FinalIntentSummary",
        "confirmation",
        "mcp",
        "http",
        "runtime",
        "provider",
    } & set(result)


@pytest.mark.parametrize("field", [
    "entitlement_boundary_ref",
    "scope_ref",
    "end_date_ref",
    "revocation_owner_ref",
    "evidence_owner_ref",
])
def test_parent_assessment_rejects_non_opaque_bindings(field: str) -> None:
    with pytest.raises(TemporaryAccessParentContractError, match="opaque bounded"):
        _assess(**{field: "bad"})


@pytest.mark.parametrize("field", [
    "approval_control_required",
    "sponsor_visibility_required",
    "audit_evidence_required",
])
def test_parent_assessment_requires_all_control_evidence(field: str) -> None:
    with pytest.raises(TemporaryAccessParentContractError, match="required"):
        _assess(**{field: False})


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("review_cadence_code", "daily", "Review cadence"),
        ("negative_test", "allow_after_expiry", "Negative test"),
    ],
)
def test_parent_assessment_rejects_unclosed_review_terms(
    field: str, value: str, message: str
) -> None:
    with pytest.raises(TemporaryAccessParentContractError, match=message):
        _assess(**{field: value})


def test_parent_assessment_rejects_identity_draft_outside_fixed_profile() -> None:
    draft = _identity_draft()
    group, member = draft.desired_objects
    invalid = replace(
        draft,
        desired_objects=(
            group,
            replace(
                member,
                desired_fields=tuple(
                    sorted({**dict(member.desired_fields), "membership_status": "pending"}.items())
                ),
            ),
        ),
    )
    with pytest.raises(TemporaryAccessParentContractError, match="fixed profile"):
        assess_temporary_access_parent(
            load_registry(),
            invalid,
            entitlement_boundary_ref="temporary-entitlement-ref01",
            scope_ref="temporary-scope-reference01",
            end_date_ref="temporary-end-date-reference01",
            revocation_owner_ref="temporary-revocation-owner01",
            evidence_owner_ref="temporary-evidence-owner-ref01",
            review_cadence_code="monthly",
            negative_test="explicit_revoke",
            approval_control_required=True,
            sponsor_visibility_required=True,
            audit_evidence_required=True,
        )


def test_parent_assessment_rejects_identity_member_count_outside_m2_bound() -> None:
    draft = _identity_draft()
    group, member = draft.desired_objects
    invalid = replace(
        draft,
        desired_objects=(
            replace(
                group,
                desired_fields=tuple(
                    sorted({**dict(group.desired_fields), "maximum_members": 2_147_483_648}.items())
                ),
            ),
            member,
        ),
    )
    with pytest.raises(TemporaryAccessParentContractError, match="fixed profile"):
        assess_temporary_access_parent(
            load_registry(),
            invalid,
            entitlement_boundary_ref="temporary-entitlement-ref01",
            scope_ref="temporary-scope-reference01",
            end_date_ref="temporary-end-date-reference01",
            revocation_owner_ref="temporary-revocation-owner01",
            evidence_owner_ref="temporary-evidence-owner-ref01",
            review_cadence_code="monthly",
            negative_test="explicit_revoke",
            approval_control_required=True,
            sponsor_visibility_required=True,
            audit_evidence_required=True,
        )


def test_parent_assessment_rejects_registry_relationship_drift() -> None:
    registry: dict[str, Any] = load_registry()
    copied = {
        **registry,
        "blueprints": [dict(item) for item in registry["blueprints"]],
        "actions": [dict(item) for item in registry["actions"]],
    }
    blueprint = next(item for item in copied["blueprints"] if item["id"] == BP015_REF)
    blueprint["scheme_refs"] = ["IdentityLifecycleScheme"]
    with pytest.raises(TemporaryAccessParentContractError, match="not exact"):
        assess_temporary_access_parent(
            copied,
            _identity_draft(),
            entitlement_boundary_ref="temporary-entitlement-ref01",
            scope_ref="temporary-scope-reference01",
            end_date_ref="temporary-end-date-reference01",
            revocation_owner_ref="temporary-revocation-owner01",
            evidence_owner_ref="temporary-evidence-owner-ref01",
            review_cadence_code="monthly",
            negative_test="explicit_revoke",
            approval_control_required=True,
            sponsor_visibility_required=True,
            audit_evidence_required=True,
        )


def test_parent_assessment_rejects_executable_action_metadata() -> None:
    registry: dict[str, Any] = load_registry()
    copied = {
        **registry,
        "blueprints": [dict(item) for item in registry["blueprints"]],
        "actions": [dict(item) for item in registry["actions"]],
    }
    action = next(
        item for item in copied["actions"] if item["id"] == ACTION_FAMILY_REF
    )
    action["atomic_contract"] = True
    with pytest.raises(TemporaryAccessParentContractError, match="not exact"):
        assess_temporary_access_parent(
            copied,
            _identity_draft(),
            entitlement_boundary_ref="temporary-entitlement-ref01",
            scope_ref="temporary-scope-reference01",
            end_date_ref="temporary-end-date-reference01",
            revocation_owner_ref="temporary-revocation-owner01",
            evidence_owner_ref="temporary-evidence-owner-ref01",
            review_cadence_code="monthly",
            negative_test="explicit_revoke",
            approval_control_required=True,
            sponsor_visibility_required=True,
            audit_evidence_required=True,
        )


def test_parent_assessment_rejects_identity_evidence_drift() -> None:
    registry: dict[str, Any] = load_registry()
    copied = {
        **registry,
        "blueprints": [dict(item) for item in registry["blueprints"]],
        "actions": [dict(item) for item in registry["actions"]],
        "schemes": [dict(item) for item in registry["schemes"]],
    }
    identity = next(
        item for item in copied["schemes"] if item["id"] == "IdentityLifecycleScheme"
    )
    identity["implementation_evidence"] = {
        **identity["implementation_evidence"],
        "device_access": True,
    }
    with pytest.raises(TemporaryAccessParentContractError, match="not exact"):
        assess_temporary_access_parent(
            copied,
            _identity_draft(),
            entitlement_boundary_ref="temporary-entitlement-ref01",
            scope_ref="temporary-scope-reference01",
            end_date_ref="temporary-end-date-reference01",
            revocation_owner_ref="temporary-revocation-owner01",
            evidence_owner_ref="temporary-evidence-owner-ref01",
            review_cadence_code="monthly",
            negative_test="explicit_revoke",
            approval_control_required=True,
            sponsor_visibility_required=True,
            audit_evidence_required=True,
        )


@pytest.mark.parametrize(
    "mode",
    [
        "risk_class",
        "scheme_version",
        "registry_schema_version",
    ],
)
def test_parent_assessment_rejects_draft_version_or_risk_drift(
    mode: str,
) -> None:
    draft = _identity_draft()
    if mode == "risk_class":
        draft = replace(draft, risk_class="high")
    elif mode == "scheme_version":
        draft = replace(draft, scheme_version="1.0.1")
    else:
        draft = replace(draft, registry_schema_version="1.0.0")
    with pytest.raises(TemporaryAccessParentContractError, match="not BP015 exact"):
        assess_temporary_access_parent(
            load_registry(),
            draft,
            entitlement_boundary_ref="temporary-entitlement-ref01",
            scope_ref="temporary-scope-reference01",
            end_date_ref="temporary-end-date-reference01",
            revocation_owner_ref="temporary-revocation-owner01",
            evidence_owner_ref="temporary-evidence-owner-ref01",
            review_cadence_code="monthly",
            negative_test="explicit_revoke",
            approval_control_required=True,
            sponsor_visibility_required=True,
            audit_evidence_required=True,
        )
