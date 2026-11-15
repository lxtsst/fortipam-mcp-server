from __future__ import annotations

import stat

import pytest

from scripts.v4_secret_gateway_mcp_oauth_acceptance import (
    SecretGatewayMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "secret-gateway-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "secret-gateway-preview-opaque"
    with pytest.raises(SecretGatewayMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_requires_fixed_disabled_gateway_contract() -> None:
    name = "mcp-v4-secret-gateway-b46"
    projection = {
        "contract": "fortipam_v4_secret_gateway_create_cli_fallback_workflow_v1",
        "preview_ref": "secret-gateway-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_gateway_name": name,
            "gateway_name_exists": False,
            "write_transport": "ssh_cli_fallback",
        },
        "Proposed Changes": {
            "operation": "create_secret_gateway_via_cli_fallback",
            "gateway_name": name,
            "configuration_profile": "disabled-forward-documentation-ipv4-v1",
            "gateway_status": "disable",
            "gateway_type": "forward",
            "gateway_address_class": "documentation_ipv4",
            "gateway_port": 443,
            "url_map": "tcp",
            "ssl_maximum_version": "tls-1.3",
            "target_or_secret_association_changes": False,
            "gateway_chain_changes": False,
            "reverse_service_changes": False,
            "traffic_forwarding_enabled": False,
            "rest_write_attempted": False,
        },
        "Expected State": {
            "gateway_name_matches": True,
            "gateway_name_exists": True,
            "status_disabled": True,
            "forward_type_enabled": True,
            "documentation_address_matches": True,
            "port_443_enabled": True,
            "tcp_url_map_enabled": True,
            "tls_1_3_maximum_enabled": True,
            "description_matches": True,
            "target_or_secret_association_changes": False,
            "gateway_chain_changes": False,
            "reverse_service_changes": False,
            "traffic_forwarding_enabled": False,
            "readback_transport": "ssh_cli",
        },
    }

    _validate_preview(projection, name, False)
    projection["Proposed Changes"]["traffic_forwarding_enabled"] = True
    with pytest.raises(SecretGatewayMcpOAuthAcceptanceError):
        _validate_preview(projection, name, False)


def test_execution_requires_categorical_disabled_readback() -> None:
    result = {
        "contract": "fortipam_v4_secret_gateway_create_cli_fallback_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "separate_secret_gateway_delete_action_required",
        "gateway_name_returned": False,
        "target_or_secret_association_changes": False,
        "gateway_chain_changes": False,
        "reverse_service_changes": False,
        "traffic_forwarding_enabled": False,
        "raw_cli_returned": False,
    }

    _validate_execution(result, False)
    result["traffic_forwarding_enabled"] = True
    with pytest.raises(SecretGatewayMcpOAuthAcceptanceError):
        _validate_execution(result, False)
