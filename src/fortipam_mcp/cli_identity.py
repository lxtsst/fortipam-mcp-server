"""Pure, non-disclosing evaluation for the dedicated V2 CLI identity."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import ipaddress

from .least_privilege import ACCESS_CATEGORY_FIELDS, CUSTOM_PERMISSION_FIELDS


@dataclass(frozen=True, slots=True)
class CliIdentityExpectation:
    """Trusted local expectations which never cross an MCP result."""

    username: str
    profile_name: str
    trusted_source: str
    public_key: str


def evaluate_cli_identity(
    admin_payload: object,
    profile_payload: object,
    expectation: CliIdentityExpectation,
) -> dict[str, object]:
    """Return only exact gate facts for one dedicated CLI identity."""

    admins = _named_results(admin_payload, expectation.username)
    profiles = _named_results(profile_payload, expectation.profile_name)
    admin = admins[0] if len(admins) == 1 else None
    profile = profiles[0] if len(profiles) == 1 else None
    sys_permissions = profile.get("sysgrp-permission") if profile else None

    gates = {
        "admin_exists_exactly_once": admin is not None,
        "profile_exists_exactly_once": profile is not None,
        "admin_enabled": bool(admin and admin.get("status") == "enable"),
        "admin_profile_exact": bool(
            admin and admin.get("accprofile") == expectation.profile_name
        ),
        "admin_root_vdom_exact": bool(admin and _root_vdom_exact(admin.get("vdom"))),
        "admin_source_exact": bool(
            admin
            and _trusted_source_equal(
                admin.get("trusthost1"), expectation.trusted_source
            )
        ),
        "admin_public_key_exact": bool(
            admin
            and _normalized_public_key(admin.get("ssh-public-key1"))
            == _normalized_public_key(expectation.public_key)
            and _normalized_public_key(expectation.public_key)
        ),
        "profile_cli_enabled": bool(profile and profile.get("cli") == "enable"),
        "profile_system_diagnostics_enabled": bool(
            profile and profile.get("system-diagnostics") == "enable"
        ),
        "profile_break_glass_disabled": bool(
            profile
            and profile.get("glass-breaking") == "disable"
            and profile.get("file-launcher-perm") == "disable"
        ),
        "profile_vdom_scope_exact": bool(
            profile and profile.get("scope") == "vdom"
        ),
        "profile_timeout_override_disabled": bool(
            profile and profile.get("admintimeout-override") == "disable"
        ),
        "profile_secret_proxy_forced": bool(
            profile and profile.get("secret-proxy-mode") == "force-proxy"
        ),
        "profile_sensitive_categories_none": bool(
            profile
            and all(
                profile.get(category) == "none"
                for category in ACCESS_CATEGORY_FIELDS
                if category != "sysgrp"
            )
        ),
        "profile_unknown_access_absent": bool(
            profile and _unknown_access_absent(profile)
        ),
        "profile_system_permissions_exact": bool(
            profile
            and profile.get("sysgrp") == "custom"
            and _system_permissions_exact(sys_permissions)
        ),
    }
    failed = sorted(key for key, passed in gates.items() if not passed)
    return {
        "contract": "fortipam_cli_identity_audit_v2",
        **gates,
        "required_admin_write_residual_present": bool(
            isinstance(sys_permissions, Mapping)
            and sys_permissions.get("admin") == "read-write"
        ),
        "device_role_read_only": False,
        "failed_gate_count": len(failed),
        "failed_gate_codes": failed,
        "identity_operationally_accepted": not failed,
        "identity_values_returned": False,
        "profile_values_returned": False,
        "network_values_returned": False,
        "public_key_values_returned": False,
        "credential_values_returned": False,
        "response_bodies_returned": False,
    }


def _named_results(payload: object, expected_name: str) -> list[Mapping[str, object]]:
    if not isinstance(payload, Mapping):
        return []
    results = payload.get("results")
    if isinstance(results, Mapping):
        results = [results]
    if not isinstance(results, list):
        return []
    return [
        item
        for item in results
        if isinstance(item, Mapping) and item.get("name") == expected_name
    ]


def _root_vdom_exact(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 1
        and isinstance(value[0], Mapping)
        and value[0].get("name") == "root"
    )


def _trusted_source_equal(actual: object, expected: str) -> bool:
    if not isinstance(actual, str):
        return False
    try:
        expected_network = ipaddress.ip_network(expected, strict=False)
        parts = actual.strip().split()
        actual_text = f"{parts[0]}/{parts[1]}" if len(parts) == 2 else actual.strip()
        actual_network = ipaddress.ip_network(actual_text, strict=False)
    except (ValueError, IndexError):
        return False
    return actual_network == expected_network


def _normalized_public_key(value: object) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip()
    boundary_quotes = (
        normalized[:1] in {"'", '"'},
        normalized[-1:] in {"'", '"'},
    )
    if any(boundary_quotes):
        if (
            len(normalized) < 2
            or not all(boundary_quotes)
            or normalized[0] != normalized[-1]
        ):
            return ""
        normalized = normalized[1:-1].strip()
    if not normalized or "'" in normalized or '"' in normalized:
        return ""
    parts = normalized.split()
    if len(parts) < 2 or not parts[0].startswith("ssh-"):
        return ""
    return " ".join(parts[:2])


def _system_permissions_exact(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    known_fields = CUSTOM_PERMISSION_FIELDS["sysgrp"]
    for field in known_fields:
        if field == "admin":
            expected = "read-write"
        else:
            expected = "read" if field == "cfg" else "none"
        if value.get(field) != expected:
            return False
    return all(
        key in known_fields or permission == "none"
        for key, permission in value.items()
    )


def _unknown_access_absent(profile: Mapping[str, object]) -> bool:
    known_permission_maps = {
        f"{category}-permission" for category in CUSTOM_PERMISSION_FIELDS
    }
    for key, value in profile.items():
        if key.endswith("grp") and key not in ACCESS_CATEGORY_FIELDS:
            if value != "none":
                return False
        if key.endswith("-permission") and key not in known_permission_maps:
            if not isinstance(value, Mapping):
                return False
            if any(permission != "none" for permission in value.values()):
                return False
    return True
