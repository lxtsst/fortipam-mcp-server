"""Source-bounded sponsored and temporary-access planning requirements."""

from __future__ import annotations


V4_TEMPORARY_ACCESS_PLAN_TOOL = "get_v4_temporary_access_plan_requirements"
V4_TEMPORARY_ACCESS_PLAN_CONTRACT = "fortipam_v4_temporary_access_plan_v1"

_REQUIRED_INFORMATION = (
    "sponsor",
    "scope",
    "end_date",
    "group",
    "review_cadence",
    "revocation_owner",
)

_CONTROL_LAYERS = (
    "identity",
    "group_membership",
    "entitlement",
    "schedule",
    "approval_and_sponsor_visibility",
    "audit_and_access_review",
)

_ACCEPTANCE_REQUIREMENTS = (
    "sponsor_visibility",
    "expiry_or_explicit_revoke_negative_test",
    "minimized_audit_evidence",
    "partial_result_reconciliation",
)

_BLOCKED_OPERATIONS = (
    "fortipam_or_external_identity_state_read",
    "identity_group_role_schedule_or_approval_change",
    "temporary_access_grant_extension_disable_or_revoke",
    "session_launch_or_termination",
    "configuration_write",
    "execution_authorization",
)


def temporary_access_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable BP015 requirements for FortiPAM 7.0."""

    return {
        "contract": V4_TEMPORARY_ACCESS_PLAN_CONTRACT,
        "action_family": "sponsored-and-temporary-access-plan",
        "blueprint_ref": "FPA-BP-015",
        "skill_sku": "FPA-SK-015",
        "source_version": "1.9.1",
        "target_version": "7.0.0",
        "target_version_validation_required": True,
        "planning_status": "requirements_only",
        "source_contract_status": "requirements_only_no_product_write_contract",
        "required_information": list(_REQUIRED_INFORMATION),
        "control_layers": list(_CONTROL_LAYERS),
        "project_acceptance_requirements": list(_ACCEPTANCE_REQUIREMENTS),
        "blocked_operations": list(_BLOCKED_OPERATIONS),
        "candidate_api_contract_available": False,
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "external_identity_service_contacted": False,
        "protected_material_loaded": False,
        "access_effect_applied": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


__all__ = [
    "V4_TEMPORARY_ACCESS_PLAN_CONTRACT",
    "V4_TEMPORARY_ACCESS_PLAN_TOOL",
    "temporary_access_plan_requirements",
]
