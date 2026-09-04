from __future__ import annotations

import pytest

from scripts.audit_api_user_permissions import (
    RUNTIME_PROFILE_VERSION_VARIABLE,
    _runtime_profile_version,
)
from fortipam_mcp.config import ConfigurationError

from fortipam_mcp.least_privilege import (
    desired_access_profile,
    desired_access_profile_v16,
    desired_access_profile_v17,
)
from fortipam_mcp.permission_audit import (
    ACCESS_PROFILE_AUDIT_PATH,
    API_USER_AUDIT_PATH,
    PERMISSION_AUDIT_PATHS,
    PermissionAuditError,
    summarize_permission_audit,
)


def test_permission_audit_reports_overprivilege_without_values() -> None:
    api_users = {
        "results": [
            {
                "name": "private-api-user",
                "accprofile": "private-custom-profile",
                "api-key": "must-not-escape",
                "trusthost": [{"ipv4-trusthost": "192.0.2.0/24"}],
            }
        ]
    }
    profiles = {
        "results": [
            {
                "name": "private-custom-profile",
                "sysgrp": "read-write",
                "secretgrp": "read",
                "loggrp": "none",
            }
        ]
    }

    result = summarize_permission_audit(api_users, profiles)

    assert result["least_privilege_confirmed"] is False
    assert result["api_identity_gate_passed"] is False
    assert result["permission_category_counts"] == {
        "read_write": 1,
        "read_only": 1,
        "custom": 0,
        "none": 1,
    }
    assert result["trusthost_restriction_present"] is True
    assert "WRITE_CAPABLE_PERMISSION_CATEGORIES_PRESENT" in result["reason_codes"]
    rendered = str(result)
    assert "private-api-user" not in rendered
    assert "private-custom-profile" not in rendered
    assert "must-not-escape" not in rendered
    assert "192.0.2.0" not in rendered


def test_permission_audit_rejects_unrestricted_identity() -> None:
    api_users = {
        "results": [
            {
                "name": "hidden",
                "accprofile": "super_admin",
                "trusthost": [{"ipv4-trusthost": "0.0.0.0/0"}],
            }
        ]
    }
    profiles = {"results": [{"name": "super_admin", "sysgrp": "read-write"}]}

    result = summarize_permission_audit(api_users, profiles)

    assert result["selected_profile_is_builtin_unrestricted"] is True
    assert result["trusthost_restriction_present"] is False
    assert "BUILTIN_UNRESTRICTED_PROFILE" in result["reason_codes"]
    assert "TRUSTHOST_RESTRICTION_NOT_CONFIRMED" in result["reason_codes"]


def test_permission_audit_accepts_one_restricted_custom_profile_shape() -> None:
    api_users = {
        "results": [
            {
                "name": "hidden",
                "accprofile": "hidden-profile",
                "trusthost": [{"ipv4-trusthost": "198.51.100.0/24"}],
            }
        ]
    }
    profiles = {
        "results": [
            {
                "name": "hidden-profile",
                **desired_access_profile(),
            }
        ]
    }

    result = summarize_permission_audit(api_users, profiles)

    assert result["candidate_profile_shape_confirmed"] is True
    assert result["least_privilege_confirmed"] is False
    assert result["api_identity_gate_passed"] is True
    assert result["live_route_authorization_acceptance_required"] is True
    assert result["reason_codes"] == []


def test_permission_audit_selects_expected_user_from_multiple_visible_users() -> None:
    api_users = {
        "results": [
            {
                "name": "unrelated",
                "accprofile": "broad-profile",
                "trusthost": [{"ipv4-trusthost": "0.0.0.0/0"}],
            },
            {
                "name": "dedicated",
                "accprofile": "dedicated-profile",
                "trusthost": [{"ipv4-trusthost": "198.51.100.4/32"}],
            },
        ]
    }
    profiles = {
        "results": [
            {"name": "broad-profile", "sysgrp": "read-write"},
            {"name": "dedicated-profile", **desired_access_profile()},
        ]
    }

    result = summarize_permission_audit(
        api_users,
        profiles,
        expected_api_username="dedicated",
    )

    assert result["single_visible_api_user"] is False
    assert result["selected_api_user_resolved"] is True
    assert result["selection_used_expected_identity"] is True
    assert result["identity_configuration_gate_passed"] is True
    assert "dedicated" not in str(result)


def test_permission_audit_rejects_broad_category_read_profile() -> None:
    api_users = {
        "results": [
            {
                "name": "hidden",
                "accprofile": "hidden-profile",
                "trusthost": [{"ipv4-trusthost": "198.51.100.4/32"}],
            }
        ]
    }
    profiles = {
        "results": [
            {
                "name": "hidden-profile",
                "sysgrp": "read",
                "secretgrp": "read",
                "loggrp": "read",
            }
        ]
    }

    result = summarize_permission_audit(api_users, profiles)

    assert result["identity_configuration_gate_passed"] is False
    assert "BROAD_READ_PERMISSION_CATEGORIES_PRESENT" in result["reason_codes"]


def test_permission_audit_requires_result_lists() -> None:
    with pytest.raises(PermissionAuditError):
        summarize_permission_audit({}, {"results": []})


def test_permission_audit_accepts_the_separate_v16_profile_shape() -> None:
    api_users = {
        "results": [
            {
                "name": "v16-hidden",
                "accprofile": "v16-hidden-profile",
                "trusthost": [{"ipv4-trusthost": "198.51.100.4/32"}],
            }
        ]
    }
    profiles = {
        "results": [
            {
                "name": "v16-hidden-profile",
                **desired_access_profile_v16(),
            }
        ]
    }

    result = summarize_permission_audit(
        api_users,
        profiles,
        expected_api_username="v16-hidden",
        profile_version="v16",
    )

    assert result["candidate_profile_shape_confirmed"] is True
    assert result["required_custom_subpermission_count"] == 7
    assert result["identity_configuration_gate_passed"] is True
    assert "v16-hidden" not in str(result)


def test_permission_audit_rejects_unknown_profile_version() -> None:
    with pytest.raises(PermissionAuditError, match="profile version"):
        summarize_permission_audit(
            {"results": []},
            {"results": []},
            profile_version="future",
        )


def test_permission_audit_accepts_v17_with_explicit_broad_read_residual_risk() -> None:
    api_users = {
        "results": [
            {
                "name": "v17-hidden",
                "accprofile": "v17-hidden-profile",
                "trusthost": [{"ipv4-trusthost": "198.51.100.4/32"}],
            }
        ]
    }
    profiles = {
        "results": [
            {"name": "v17-hidden-profile", **desired_access_profile_v17()}
        ]
    }

    result = summarize_permission_audit(
        api_users,
        profiles,
        expected_api_username="v17-hidden",
        profile_version="v17",
    )

    assert result["candidate_profile_shape_confirmed"] is True
    assert result["identity_configuration_gate_passed"] is True
    assert result["accepted_broad_read_category_count"] == 1
    assert result["broad_read_residual_risk_present"] is True
    assert "v17-hidden" not in str(result)


def test_runtime_permission_audit_profile_version_is_explicit() -> None:
    assert _runtime_profile_version({}) == "v15"
    assert _runtime_profile_version(
        {RUNTIME_PROFILE_VERSION_VARIABLE: "v16"}
    ) == "v16"
    assert _runtime_profile_version(
        {RUNTIME_PROFILE_VERSION_VARIABLE: "v17"}
    ) == "v17"
    with pytest.raises(ConfigurationError, match="profile version"):
        _runtime_profile_version(
            {RUNTIME_PROFILE_VERSION_VARIABLE: "future"}
        )


def test_permission_audit_paths_are_fixed() -> None:
    assert PERMISSION_AUDIT_PATHS == {
        API_USER_AUDIT_PATH,
        ACCESS_PROFILE_AUDIT_PATH,
    }
