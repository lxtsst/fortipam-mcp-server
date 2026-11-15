from __future__ import annotations

from ipaddress import IPv4Address
import pytest

from scripts.v4_role_update_mcp_oauth_acceptance import (
    RoleUpdateMcpOAuthAcceptanceError,
    _contains_role_update_acceptance_error,
    _is_private_ip_lab_url,
    _validate_preview,
)


PRIVATE_LAB_IPV4 = str(IPv4Address(0x0A00020C))


def _preview() -> dict[str, object]:
    return {
        "contract": "fortipam_v4_role_diagnostics_enable_workflow_v1",
        "preview_ref": "role-update-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_role_name": "mcp-v4-role-01",
            "role_exists": True,
            "guide_example_permissions_match": True,
            "system_diagnostics_disabled": True,
            "role_assigned_to_any_local_user": False,
            "write_transport": "ssh_cli_fallback",
            "write_transport": "ssh_cli_fallback",
        },
        "Proposed Changes": {
            "operation": "enable_role_system_diagnostics_via_cli_fallback",
            "role_name": "mcp-v4-role-01",
            "configuration_profile": "pam_standard_user_diagnostics_enable_v1",
            "system_diagnostics": "enable",
            "role_assignment_changes": False,
            "folder_target_secret_or_credential_changes": False,
            "rest_write_attempted": False,
            "rest_write_attempted": False,
        },
        "Expected State": {
            "role_name_matches": True,
            "role_exists": True,
            "guide_example_permissions_preserved": True,
            "system_diagnostics_enabled": True,
            "role_assigned_to_any_local_user": False,
            "role_assignment_changes": False,
            "folder_target_secret_or_credential_changes": False,
            "readback_transport": "ssh_cli_fallback",
        },
    }


def test_preview_accepts_only_the_fixed_role_diagnostics_transition() -> None:
    _validate_preview(_preview(), "mcp-v4-role-01", False)

    invalid = _preview()
    proposed = invalid["Proposed Changes"]
    assert isinstance(proposed, dict)
    proposed["system_diagnostics"] = "disable"
    with pytest.raises(RoleUpdateMcpOAuthAcceptanceError):
        _validate_preview(invalid, "mcp-v4-role-01", False)


def test_callback_error_recognition_is_specific_to_role_update() -> None:
    nested = ExceptionGroup(
        "nested",
        [ExceptionGroup("callback", [RoleUpdateMcpOAuthAcceptanceError("failed")])],
    )

    assert _contains_role_update_acceptance_error(nested) is True
    assert _contains_role_update_acceptance_error(
        ExceptionGroup("other", [RuntimeError("failed")])
    ) is False


def test_private_http_lab_exception_remains_strictly_bounded() -> None:
    assert _is_private_ip_lab_url(f"http://{PRIVATE_LAB_IPV4}/fpamcp") is True
    assert _is_private_ip_lab_url(f"http://{PRIVATE_LAB_IPV4}") is False
    assert (
        _is_private_ip_lab_url(f"http://{PRIVATE_LAB_IPV4}:8080/fpamcp")
        is False
    )
