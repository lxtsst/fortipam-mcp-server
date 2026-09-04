"""Non-disclosing analysis for the dedicated FortiPAM API identity."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .least_privilege import (
    evaluate_access_profile,
    evaluate_access_profile_v16,
    evaluate_access_profile_v17,
)

API_USER_AUDIT_PATH = "/api/v2/cmdb/system/api-user"
ACCESS_PROFILE_AUDIT_PATH = "/api/v2/cmdb/system/accprofile"
PERMISSION_AUDIT_PATHS = frozenset(
    {API_USER_AUDIT_PATH, ACCESS_PROFILE_AUDIT_PATH}
)

_UNRESTRICTED_PROFILE_NAMES = {"super_admin", "super-admin"}
_UNRESTRICTED_TRUSTHOST_MARKERS = (
    "0.0.0.0/0",
    "0.0.0.0 0.0.0.0",
    "::/0",
)


class PermissionAuditError(ValueError):
    """Raised when a permission-audit response cannot be analyzed safely."""


def summarize_permission_audit(
    api_user_payload: object,
    access_profile_payload: object,
    *,
    expected_api_username: str | None = None,
    profile_version: str = "v15",
) -> dict[str, object]:
    """Return derived permission posture without identity or profile values."""

    api_users = _result_list(api_user_payload, "API-user")
    profiles = _result_list(access_profile_payload, "access-profile")

    if expected_api_username:
        selected_users = [
            user
            for user in api_users
            if isinstance(user, Mapping)
            and user.get("name") == expected_api_username
        ]
        selected_user = selected_users[0] if len(selected_users) == 1 else None
    else:
        selected_users = api_users
        selected_user = api_users[0] if len(api_users) == 1 else None
    profile_name = (
        selected_user.get("accprofile")
        if isinstance(selected_user, Mapping)
        else None
    )
    matched_profile = next(
        (
            profile
            for profile in profiles
            if isinstance(profile, Mapping) and profile.get("name") == profile_name
        ),
        None,
    )

    if profile_version == "v15":
        profile_posture = evaluate_access_profile(matched_profile)
    elif profile_version == "v16":
        profile_posture = evaluate_access_profile_v16(matched_profile)
    elif profile_version == "v17":
        profile_posture = evaluate_access_profile_v17(matched_profile)
    else:
        raise PermissionAuditError("Permission profile version is invalid.")

    selected_profile_is_builtin_unrestricted = (
        isinstance(profile_name, str)
        and profile_name.strip().lower() in _UNRESTRICTED_PROFILE_NAMES
    )
    trusthost_restriction_present = _trusthost_is_restricted(
        selected_user.get("trusthost")
        if isinstance(selected_user, Mapping)
        else None
    )

    reason_codes: list[str] = []
    if expected_api_username and len(selected_users) != 1:
        reason_codes.append("EXPECTED_API_USER_NOT_RESOLVED")
    elif not expected_api_username and len(api_users) != 1:
        reason_codes.append("API_USER_VISIBILITY_NOT_SINGLETON")
    if matched_profile is None:
        reason_codes.append("ACCESS_PROFILE_NOT_RESOLVED")
    if selected_profile_is_builtin_unrestricted:
        reason_codes.append("BUILTIN_UNRESTRICTED_PROFILE")
    profile_reason_codes = profile_posture.get("reason_codes")
    if isinstance(profile_reason_codes, list):
        for code in profile_reason_codes:
            if isinstance(code, str) and code not in reason_codes:
                reason_codes.append(code)
    if not trusthost_restriction_present:
        reason_codes.append("TRUSTHOST_RESTRICTION_NOT_CONFIRMED")
    configuration_gate_passed = not reason_codes
    result: dict[str, object] = {
        "audit_kind": "derived_api_identity_permission_posture",
        "api_user_visible_object_count": len(api_users),
        "single_visible_api_user": len(api_users) == 1,
        "selected_api_user_resolved": selected_user is not None,
        "selection_used_expected_identity": bool(expected_api_username),
        "access_profile_visible_object_count": len(profiles),
        "selected_profile_definition_matched": matched_profile is not None,
        "selected_profile_is_builtin_unrestricted": (
            selected_profile_is_builtin_unrestricted
        ),
        "trusthost_restriction_present": trusthost_restriction_present,
        "identity_configuration_gate_passed": configuration_gate_passed,
        "api_identity_gate_passed": configuration_gate_passed,
        "least_privilege_confirmed": False,
        "live_route_authorization_acceptance_required": True,
        "reason_codes": reason_codes,
        "identity_values_returned": False,
        "profile_name_returned": False,
        "permission_category_names_returned": False,
        "credential_values_returned": False,
        "raw_response_returned": False,
    }
    for key, value in profile_posture.items():
        if key != "reason_codes":
            result[key] = value
    return result


def _result_list(payload: object, label: str) -> list[Any]:
    if not isinstance(payload, Mapping):
        raise PermissionAuditError(f"{label} response must be an object.")
    results = payload.get("results")
    if not isinstance(results, list):
        raise PermissionAuditError(f"{label} response must contain a result list.")
    return results


def _trusthost_is_restricted(value: object) -> bool:
    if not value:
        return False
    serialized = json.dumps(value, sort_keys=True).lower()
    return not any(marker in serialized for marker in _UNRESTRICTED_TRUSTHOST_MARKERS)
