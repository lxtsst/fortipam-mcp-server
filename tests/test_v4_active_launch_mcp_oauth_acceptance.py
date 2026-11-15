from __future__ import annotations

from ipaddress import IPv4Address
import pytest
from urllib.parse import urlsplit

from scripts.v4_address_mcp_oauth_surface_acceptance import _accepted_scheme
from scripts.v4_active_launch_mcp_oauth_acceptance import (
    ActiveLaunchMcpOAuthAcceptanceError,
    _contains_acceptance_error,
    _validate_observation,
)


PRIVATE_LAB_IPV4 = str(IPv4Address(0x0A00020C))


def test_private_ip_http_acceptance_requires_the_explicit_lab_flag() -> None:
    private_ip = urlsplit(f"http://{PRIVATE_LAB_IPV4}/fpamcp")

    assert _accepted_scheme(urlsplit("https://mcp.example.com/fpamcp"), False) is True
    assert _accepted_scheme(private_ip, False) is False
    assert _accepted_scheme(private_ip, True) is True
    assert _accepted_scheme(urlsplit("http://mcp.example.com/fpamcp"), True) is False
    assert (
        _accepted_scheme(
            urlsplit(f"http://{PRIVATE_LAB_IPV4}:8080/fpamcp"), True
        )
        is False
    )


def test_verified_observation_accepts_opaque_references_only() -> None:
    projection = {
        "contract": "fortipam_v4_active_launch_observation_cli_v1",
        "observation": "verified",
        "active_launch_count": 1,
        "active_launch_refs": [
            {
                "launch_ref": "active-launch-ref-opaque",
                "expires_at": 123,
                "token_or_session_data_returned": False,
            }
        ],
        "raw_cli_returned": False,
        "wad_token_returned": False,
        "identity_target_secret_or_session_data_returned": False,
        "device_write_executed": False,
    }

    _validate_observation(projection, False)

    projection["active_launch_refs"][0]["token_or_session_data_returned"] = True
    with pytest.raises(ActiveLaunchMcpOAuthAcceptanceError):
        _validate_observation(projection, False)


def test_unrecognized_observation_is_not_relabelled_as_zero() -> None:
    projection = {
        "contract": "fortipam_v4_active_launch_observation_cli_v1",
        "observation": "unavailable_or_unrecognized",
        "active_launch_count": None,
        "active_launch_refs": [],
        "raw_cli_returned": False,
        "wad_token_returned": False,
        "identity_target_secret_or_session_data_returned": False,
        "device_write_executed": False,
    }

    _validate_observation(projection, False)

    projection["active_launch_count"] = 0
    with pytest.raises(ActiveLaunchMcpOAuthAcceptanceError):
        _validate_observation(projection, False)


def test_nested_acceptance_error_is_detected() -> None:
    error = ExceptionGroup(
        "outer",
        [ExceptionGroup("inner", [ActiveLaunchMcpOAuthAcceptanceError("failed")])],
    )

    assert _contains_acceptance_error(error) is True
