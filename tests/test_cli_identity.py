from __future__ import annotations

from copy import deepcopy

import pytest

from fortipam_mcp.cli_identity import (
    CliIdentityExpectation,
    evaluate_cli_identity,
)
from fortipam_mcp.least_privilege import ACCESS_CATEGORY_FIELDS, CUSTOM_PERMISSION_FIELDS


EXPECTATION = CliIdentityExpectation(
    username="dedicated-cli",
    profile_name="dedicated-cli-role",
    trusted_source="192.0.2.10/32",
    public_key="ssh-rsa AAAATEST local-comment",
)


def _payloads() -> tuple[dict[str, object], dict[str, object]]:
    permissions = {
        field: (
            "read-write"
            if field == "admin"
            else "read" if field == "cfg" else "none"
        )
        for field in CUSTOM_PERMISSION_FIELDS["sysgrp"]
    }
    profile: dict[str, object] = {
        "name": EXPECTATION.profile_name,
        "cli": "enable",
        "system-diagnostics": "enable",
        "glass-breaking": "disable",
        "file-launcher-perm": "disable",
        "scope": "vdom",
        "admintimeout-override": "disable",
        "secret-proxy-mode": "force-proxy",
        "sysgrp": "custom",
        "sysgrp-permission": permissions,
    }
    profile.update(
        {
            category: "none"
            for category in ACCESS_CATEGORY_FIELDS
            if category != "sysgrp"
        }
    )
    admin = {
        "name": EXPECTATION.username,
        "status": "enable",
        "accprofile": EXPECTATION.profile_name,
        "vdom": [{"name": "root"}],
        "trusthost1": "192.0.2.10 255.255.255.255",
        "ssh-public-key1": "ssh-rsa AAAATEST different-comment",
    }
    return {"results": [admin]}, {"results": [profile]}


def test_cli_identity_accepts_only_exact_non_disclosing_shape() -> None:
    admin_payload, profile_payload = _payloads()
    result = evaluate_cli_identity(admin_payload, profile_payload, EXPECTATION)
    assert result["identity_operationally_accepted"] is True
    assert result["failed_gate_count"] == 0
    assert result["required_admin_write_residual_present"] is True
    assert result["device_role_read_only"] is False
    assert result["identity_values_returned"] is False
    assert EXPECTATION.username not in str(result)
    assert "192.0.2.10" not in str(result)
    assert "AAAATEST" not in str(result)


def test_cli_identity_accepts_exact_member_get_payload_shape() -> None:
    admin_payload, profile_payload = _payloads()
    admin_payload["results"] = admin_payload["results"][0]
    profile_payload["results"] = profile_payload["results"][0]
    result = evaluate_cli_identity(admin_payload, profile_payload, EXPECTATION)
    assert result["identity_operationally_accepted"] is True
    assert result["failed_gate_count"] == 0


def test_cli_identity_accepts_one_fortipam_api_quote_wrapper() -> None:
    admin_payload, profile_payload = _payloads()
    admin_payload["results"][0]["ssh-public-key1"] = (
        "'ssh-rsa AAAATEST device-comment'"
    )
    result = evaluate_cli_identity(admin_payload, profile_payload, EXPECTATION)
    assert result["admin_public_key_exact"] is True
    assert result["identity_operationally_accepted"] is True


@pytest.mark.parametrize(
    "public_key",
    (
        "'ssh-rsa AAAATEST device-comment\"",
        "\"'ssh-rsa AAAATEST device-comment'\"",
        "ssh-rsa AAAATEST device-comment'",
        "'ssh-rsa AAAATEST device-comment",
    ),
)
def test_cli_identity_rejects_mismatched_or_nested_quote_wrappers(
    public_key: str,
) -> None:
    admin_payload, profile_payload = _payloads()
    admin_payload["results"][0]["ssh-public-key1"] = public_key
    result = evaluate_cli_identity(admin_payload, profile_payload, EXPECTATION)
    assert result["admin_public_key_exact"] is False
    assert result["identity_operationally_accepted"] is False


def test_cli_identity_rejects_duplicate_or_broadened_objects() -> None:
    admin_payload, profile_payload = _payloads()
    duplicate_admin = deepcopy(admin_payload["results"][0])
    admin_payload["results"].append(duplicate_admin)
    profile = profile_payload["results"][0]
    profile["secretgrp"] = "read"
    profile["system-diagnostics"] = "disable"
    result = evaluate_cli_identity(admin_payload, profile_payload, EXPECTATION)
    assert result["identity_operationally_accepted"] is False
    assert result["admin_exists_exactly_once"] is False
    assert result["profile_sensitive_categories_none"] is False
    assert result["profile_system_diagnostics_enabled"] is False


def test_cli_identity_rejects_wrong_key_source_vdom_or_permission() -> None:
    admin_payload, profile_payload = _payloads()
    admin = admin_payload["results"][0]
    admin["ssh-public-key1"] = "ssh-rsa OTHER"
    admin["trusthost1"] = "192.0.2.0 255.255.255.0"
    admin["vdom"] = [{"name": "other"}]
    profile = profile_payload["results"][0]
    profile["sysgrp-permission"]["admin"] = "none"
    result = evaluate_cli_identity(admin_payload, profile_payload, EXPECTATION)
    assert result["identity_operationally_accepted"] is False
    assert result["admin_public_key_exact"] is False
    assert result["admin_source_exact"] is False
    assert result["admin_root_vdom_exact"] is False
    assert result["profile_system_permissions_exact"] is False


def test_cli_identity_rejects_unknown_access_categories_or_permission_maps() -> None:
    admin_payload, profile_payload = _payloads()
    profile = profile_payload["results"][0]
    profile["futuregrp"] = "read"
    profile["futuregrp-permission"] = {"new-object": "read"}
    result = evaluate_cli_identity(admin_payload, profile_payload, EXPECTATION)
    assert result["identity_operationally_accepted"] is False
    assert result["profile_unknown_access_absent"] is False


def test_cli_identity_rejects_broadened_scope_or_safety_controls() -> None:
    admin_payload, profile_payload = _payloads()
    profile = profile_payload["results"][0]
    profile["scope"] = "global"
    profile["admintimeout-override"] = "enable"
    profile["secret-proxy-mode"] = "direct"
    result = evaluate_cli_identity(admin_payload, profile_payload, EXPECTATION)
    assert result["profile_vdom_scope_exact"] is False
    assert result["profile_timeout_override_disabled"] is False
    assert result["profile_secret_proxy_forced"] is False
    assert result["identity_operationally_accepted"] is False
