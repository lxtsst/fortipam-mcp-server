"""Pure contracts for a dedicated least-privilege FortiPAM API identity."""

from __future__ import annotations

from typing import Mapping


ACCESS_CATEGORY_FIELDS = frozenset(
    {
        "authgrp",
        "ftviewgrp",
        "fwgrp",
        "loggrp",
        "netgrp",
        "secfabgrp",
        "secretgrp",
        "sysgrp",
        "utmgrp",
        "vpngrp",
        "wanoptgrp",
    }
)

CUSTOM_PERMISSION_FIELDS: Mapping[str, frozenset[str]] = {
    "loggrp": frozenset({"config", "data-access", "report-access"}),
    "secretgrp": frozenset(
        {
            "approval-prof",
            "classification-tag",
            "client-software",
            "create-personal-folder",
            "create-root-folder",
            "dependency-updater",
            "event-filter-profile",
            "folder-table",
            "launcher",
            "modify-personal-folder",
            "playback-video",
            "pwd-changer",
            "pwd-charset",
            "pwd-policy",
            "request",
            "secret-discovery",
            "secret-job",
            "secret-policy",
            "secret-script",
            "secret-table",
            "ssh-challenge",
            "target",
            "template",
            "view-clear-information",
            "view-secret-log",
            "view-secret-recording",
            "winappfilter-profile",
        }
    ),
    "sysgrp": frozenset({"accprofile", "admin", "cfg", "mnt", "mnt-mode", "upd"}),
}

# This is a lab hypothesis for FortiPAM 1.9.1, not a vendor route-to-role contract.
# Each mapping must be proven by the dedicated identity acceptance before cutover.
ROUTE_PERMISSION_HYPOTHESIS: Mapping[str, tuple[str, str]] = {
    "system_status": ("sysgrp", "mnt"),
    "system_global": ("sysgrp", "cfg"),
    "approval_profile": ("secretgrp", "approval-prof"),
    "fortianalyzer_delivery": ("loggrp", "config"),
    "license_support": ("sysgrp", "upd"),
    "ha_configuration": ("sysgrp", "cfg"),
    "recording_storage": ("loggrp", "data-access"),
}
V16_ROUTE_PERMISSION_HYPOTHESIS: Mapping[str, tuple[str, str]] = {
    **ROUTE_PERMISSION_HYPOTHESIS,
    "password_changer_configuration": ("secretgrp", "pwd-changer"),
}
V17_ROUTE_PERMISSION_HYPOTHESIS: Mapping[str, tuple[str, str]] = {
    **V16_ROUTE_PERMISSION_HYPOTHESIS,
    "ems_connection": ("secfabgrp", "read"),
}

REQUIRED_CUSTOM_PERMISSIONS: Mapping[str, frozenset[str]] = {
    "loggrp": frozenset({"config", "data-access"}),
    "secretgrp": frozenset({"approval-prof"}),
    "sysgrp": frozenset({"cfg", "mnt", "upd"}),
}
V16_REQUIRED_CUSTOM_PERMISSIONS: Mapping[str, frozenset[str]] = {
    **REQUIRED_CUSTOM_PERMISSIONS,
    "secretgrp": frozenset({"approval-prof", "pwd-changer"}),
}

SAFE_PROFILE_CONTROLS: Mapping[str, str] = {
    "admintimeout-override": "disable",
    "cli": "disable",
    "file-launcher-perm": "disable",
    "glass-breaking": "disable",
    "scope": "vdom",
    "secret-proxy-mode": "force-proxy",
    "system-diagnostics": "disable",
}

_LEVELS = {
    "none": "none",
    "read": "read_only",
    "read-only": "read_only",
    "read_only": "read_only",
    "read-write": "read_write",
    "read_write": "read_write",
    "rw": "read_write",
    "custom": "custom",
}


def desired_access_profile() -> dict[str, object]:
    """Return the frozen V1.5 permission body."""

    return _desired_access_profile(REQUIRED_CUSTOM_PERMISSIONS)


def desired_access_profile_v16() -> dict[str, object]:
    """Return the V1.6 candidate body without changing the V1.5 baseline."""

    return _desired_access_profile(V16_REQUIRED_CUSTOM_PERMISSIONS)


def desired_access_profile_v17() -> dict[str, object]:
    """Return the V1.7 candidate with one unavoidable broad read category."""

    profile = _desired_access_profile(V16_REQUIRED_CUSTOM_PERMISSIONS)
    profile["secfabgrp"] = "read"
    return profile


def _desired_access_profile(
    required_permissions: Mapping[str, frozenset[str]],
) -> dict[str, object]:
    """Build one exact custom-subpermission profile."""

    profile: dict[str, object] = {
        category: (
            "custom" if category in required_permissions else "none"
        )
        for category in ACCESS_CATEGORY_FIELDS
    }
    profile.update(SAFE_PROFILE_CONTROLS)
    for category, fields in CUSTOM_PERMISSION_FIELDS.items():
        required = required_permissions[category]
        profile[f"{category}-permission"] = {
            field: "read" if field in required else "none"
            for field in fields
        }
    return profile


def evaluate_access_profile(profile: object) -> dict[str, object]:
    """Evaluate the frozen V1.5 permission shape."""

    return _evaluate_access_profile(
        profile,
        REQUIRED_CUSTOM_PERMISSIONS,
        "fortipam_1_9_1_custom_subpermission_candidate",
    )


def evaluate_access_profile_v16(profile: object) -> dict[str, object]:
    """Evaluate the separate V1.6 candidate permission shape."""

    return _evaluate_access_profile(
        profile,
        V16_REQUIRED_CUSTOM_PERMISSIONS,
        "fortipam_1_9_1_v16_custom_subpermission_candidate",
    )


def evaluate_access_profile_v17(profile: object) -> dict[str, object]:
    """Evaluate the exact V1.7 candidate and its explicit residual risk."""

    return _evaluate_access_profile(
        profile,
        V16_REQUIRED_CUSTOM_PERMISSIONS,
        "fortipam_1_9_1_v17_sec_fabric_read_candidate",
        expected_profile=desired_access_profile_v17(),
        allowed_broad_read_categories=frozenset({"secfabgrp"}),
    )


def _evaluate_access_profile(
    profile: object,
    required_permissions: Mapping[str, frozenset[str]],
    profile_model: str,
    *,
    expected_profile: Mapping[str, object] | None = None,
    allowed_broad_read_categories: frozenset[str] = frozenset(),
) -> dict[str, object]:
    """Evaluate only permission shape; route authorization remains separate."""

    if not isinstance(profile, Mapping):
        return _invalid_profile_result(
            "PROFILE_DEFINITION_NOT_AN_OBJECT",
            required_permissions,
            profile_model,
        )

    expected = expected_profile or _desired_access_profile(required_permissions)
    level_counts = {"read_write": 0, "read_only": 0, "custom": 0, "none": 0}
    top_level_mismatch_count = 0
    broad_top_level_access_count = 0
    for category in ACCESS_CATEGORY_FIELDS:
        actual = _normalized_level(profile.get(category))
        if actual is not None:
            level_counts[actual] += 1
        if profile.get(category) != expected[category]:
            top_level_mismatch_count += 1
        if actual in {"read_only", "read_write"}:
            broad_top_level_access_count += 1

    required_permission_mismatch_count = 0
    unexpected_subpermission_access_count = 0
    for category, fields in CUSTOM_PERMISSION_FIELDS.items():
        actual_permissions = profile.get(f"{category}-permission")
        if not isinstance(actual_permissions, Mapping):
            required_permission_mismatch_count += len(fields)
            continue
        required = required_permissions[category]
        for field in fields:
            actual_value = actual_permissions.get(field)
            expected_value = "read" if field in required else "none"
            if actual_value != expected_value:
                if field in required:
                    required_permission_mismatch_count += 1
                elif _normalized_level(actual_value) in {
                    "read_only",
                    "read_write",
                    "custom",
                }:
                    unexpected_subpermission_access_count += 1
        for field, value in actual_permissions.items():
            if (
                field not in fields
                and _normalized_level(value)
                in {"read_only", "read_write", "custom"}
            ):
                unexpected_subpermission_access_count += 1

    safety_control_mismatch_count = sum(
        profile.get(field) != expected_value
        for field, expected_value in SAFE_PROFILE_CONTROLS.items()
    )
    reason_codes: list[str] = []
    if level_counts["read_write"]:
        reason_codes.append("WRITE_CAPABLE_PERMISSION_CATEGORIES_PRESENT")
    unexpected_broad_read_count = sum(
        _normalized_level(profile.get(category)) in {"read_only", "read_write"}
        and category not in allowed_broad_read_categories
        for category in ACCESS_CATEGORY_FIELDS
    )
    if unexpected_broad_read_count:
        reason_codes.append("BROAD_READ_PERMISSION_CATEGORIES_PRESENT")
    if top_level_mismatch_count:
        reason_codes.append("TOP_LEVEL_PERMISSION_SHAPE_MISMATCH")
    if required_permission_mismatch_count:
        reason_codes.append("REQUIRED_CUSTOM_SUBPERMISSIONS_NOT_EXACT")
    if unexpected_subpermission_access_count:
        reason_codes.append("UNEXPECTED_CUSTOM_SUBPERMISSION_ACCESS_PRESENT")
    if safety_control_mismatch_count:
        reason_codes.append("SAFETY_CONTROL_SHAPE_MISMATCH")

    profile_shape_confirmed = not reason_codes
    return {
        "profile_model": profile_model,
        "permission_category_counts": level_counts,
        "custom_permission_category_count": len(required_permissions),
        "required_custom_subpermission_count": sum(
            len(fields) for fields in required_permissions.values()
        ),
        "top_level_permission_mismatch_count": top_level_mismatch_count,
        "broad_top_level_access_count": broad_top_level_access_count,
        "accepted_broad_read_category_count": sum(
            _normalized_level(profile.get(category)) == "read_only"
            for category in allowed_broad_read_categories
        ),
        "broad_read_residual_risk_present": bool(allowed_broad_read_categories),
        "required_custom_subpermission_mismatch_count": (
            required_permission_mismatch_count
        ),
        "unexpected_custom_subpermission_access_count": (
            unexpected_subpermission_access_count
        ),
        "safety_control_mismatch_count": safety_control_mismatch_count,
        "candidate_profile_shape_confirmed": profile_shape_confirmed,
        "route_authorization_mapping_verified": False,
        "reason_codes": reason_codes,
        "permission_category_names_returned": False,
        "permission_field_names_returned": False,
        "profile_name_returned": False,
        "raw_response_returned": False,
    }


def evaluate_live_authorization(
    required_status_codes: tuple[int, ...],
    denied_status_codes: tuple[int, ...],
) -> dict[str, object]:
    """Evaluate the bounded positive and negative authorization matrix."""

    return _evaluate_live_authorization(
        required_status_codes,
        denied_status_codes,
        expected_required=len(ROUTE_PERMISSION_HYPOTHESIS),
        expected_denials=5,
    )


def evaluate_live_authorization_v16(
    required_status_codes: tuple[int, ...],
    denied_status_codes: tuple[int, ...],
) -> dict[str, object]:
    """Evaluate the eight positives and expanded V1.6 denial matrix."""

    return _evaluate_live_authorization(
        required_status_codes,
        denied_status_codes,
        expected_required=len(V16_ROUTE_PERMISSION_HYPOTHESIS),
        expected_denials=11,
    )


def evaluate_live_authorization_v17(
    required_status_codes: tuple[int, ...],
    denied_status_codes: tuple[int, ...],
) -> dict[str, object]:
    """Evaluate nine positives and the fixed V1.7 denial matrix."""

    return _evaluate_live_authorization(
        required_status_codes,
        denied_status_codes,
        expected_required=len(V17_ROUTE_PERMISSION_HYPOTHESIS),
        expected_denials=11,
    )


def _evaluate_live_authorization(
    required_status_codes: tuple[int, ...],
    denied_status_codes: tuple[int, ...],
    *,
    expected_required: int,
    expected_denials: int,
) -> dict[str, object]:
    required_success_count = sum(
        200 <= status_code < 300 for status_code in required_status_codes
    )
    required_failure_count = len(required_status_codes) - required_success_count
    denied_success_count = sum(status_code == 403 for status_code in denied_status_codes)
    denial_failure_count = len(denied_status_codes) - denied_success_count
    accepted = (
        len(required_status_codes) == expected_required
        and required_failure_count == 0
        and len(denied_status_codes) == expected_denials
        and denial_failure_count == 0
    )
    reason_codes: list[str] = []
    if len(required_status_codes) != expected_required:
        reason_codes.append("REQUIRED_ROUTE_COUNT_MISMATCH")
    if required_failure_count:
        reason_codes.append("REQUIRED_ROUTE_AUTHORIZATION_FAILED")
    if len(denied_status_codes) != expected_denials:
        reason_codes.append("NEGATIVE_ROUTE_COUNT_MISMATCH")
    if denial_failure_count:
        reason_codes.append("UNRELATED_ROUTE_NOT_DENIED")
    return {
        "required_route_count": len(required_status_codes),
        "required_route_success_count": required_success_count,
        "required_route_failure_count": required_failure_count,
        "negative_route_count": len(denied_status_codes),
        "negative_route_denial_count": denied_success_count,
        "negative_route_failure_count": denial_failure_count,
        "candidate_operationally_accepted": accepted,
        "route_authorization_mapping_verified_in_lab": accepted,
        "vendor_route_authorization_contract_claimed": False,
        "reason_codes": reason_codes,
        "route_names_returned": False,
        "response_bodies_returned": False,
        "identity_values_returned": False,
    }


def _invalid_profile_result(
    reason_code: str,
    required_permissions: Mapping[str, frozenset[str]],
    profile_model: str,
) -> dict[str, object]:
    return {
        "profile_model": profile_model,
        "permission_category_counts": {
            "read_write": 0,
            "read_only": 0,
            "custom": 0,
            "none": 0,
        },
        "custom_permission_category_count": len(required_permissions),
        "required_custom_subpermission_count": sum(
            len(fields) for fields in required_permissions.values()
        ),
        "top_level_permission_mismatch_count": len(ACCESS_CATEGORY_FIELDS),
        "broad_top_level_access_count": 0,
        "accepted_broad_read_category_count": 0,
        "broad_read_residual_risk_present": False,
        "required_custom_subpermission_mismatch_count": sum(
            len(fields) for fields in required_permissions.values()
        ),
        "unexpected_custom_subpermission_access_count": 0,
        "safety_control_mismatch_count": len(SAFE_PROFILE_CONTROLS),
        "candidate_profile_shape_confirmed": False,
        "route_authorization_mapping_verified": False,
        "reason_codes": [reason_code],
        "permission_category_names_returned": False,
        "permission_field_names_returned": False,
        "profile_name_returned": False,
        "raw_response_returned": False,
    }


def _normalized_level(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return _LEVELS.get(value.strip().lower())
