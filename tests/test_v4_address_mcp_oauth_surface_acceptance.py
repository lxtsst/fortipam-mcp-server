from __future__ import annotations

import asyncio
import ipaddress
import json
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit

import pytest

from scripts.v4_address_mcp_oauth_surface_acceptance import (
    AddressMcpOAuthSurfaceAcceptanceError,
    LOGIN_PASSWORD,
    LOGIN_USERNAME,
    PLAN_ONLY_SCOPE,
    REDIRECT_URI,
    _StaticHostNetworkBackend,
    _accepted_scheme,
    _authorization_error_category,
    _contained_acceptance_error_message,
    _connection_origin,
    _connection_url,
    _registration_failure_reason,
    _validated_scope,
    _write_preview_state,
    run_address_mcp_oauth_surface_acceptance,
)


def _private_lab_host() -> str:
    return str(ipaddress.IPv4Address(0x0A000001))


def test_nested_acceptance_error_message_is_bounded() -> None:
    nested = ExceptionGroup(
        "transport task group",
        [
            ExceptionGroup(
                "session task group",
                [
                    AddressMcpOAuthSurfaceAcceptanceError(
                        "MCP server version differs from the candidate release."
                    )
                ],
            )
        ],
    )

    assert _contained_acceptance_error_message(nested) == (
        "MCP server version differs from the candidate release."
    )


@pytest.mark.parametrize(
    ("status_code", "payload", "expected"),
    [
        (400, {"error": "invalid_client_metadata", "error_description": "secret"}, "http_400:invalid_client_metadata"),
        (401, {"error": "access_denied", "detail": "secret"}, "http_401:access_denied"),
        (503, {"error": "unexpected", "error_description": "secret"}, "http_503:unclassified"),
        (502, "not-json", "http_502:unclassified"),
    ],
)
def test_registration_failure_reason_is_bounded(
    status_code: int, payload: object, expected: str
) -> None:
    assert _registration_failure_reason(status_code, payload) == expected


def test_authorization_error_callback_returns_only_known_category() -> None:
    assert _authorization_error_category(
        f"{REDIRECT_URI}?error=invalid_scope&error_description=secret"
    ) == "invalid_scope"
    assert _authorization_error_category(
        f"{REDIRECT_URI}?error=unexpected&error_description=secret"
    ) is None
    assert _authorization_error_category(
        "https://attacker.example/callback?error=invalid_scope"
    ) is None


def test_preview_reference_is_persisted_once_in_owner_only_state(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    state_file = state_dir / "preview.json"

    _write_preview_state(
        state_file,
        preview_ref="opaque-preview-reference",
        name="mcp-v4-address-203-0-113-0-24",
        cidr="203.0.113.0/24",
    )

    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    assert json.loads(state_file.read_text()) == {
        "preview_ref": "opaque-preview-reference",
        "name": "mcp-v4-address-203-0-113-0-24",
        "cidr": "203.0.113.0/24",
    }
    with pytest.raises(AddressMcpOAuthSurfaceAcceptanceError, match="already exists"):
        _write_preview_state(
            state_file,
            preview_ref="different-preview-reference",
            name="mcp-v4-address-203-0-113-0-24",
            cidr="203.0.113.0/24",
        )


def test_oauth_scope_accepts_only_fixed_operate_or_plan_profiles() -> None:
    assert _validated_scope(PLAN_ONLY_SCOPE) == "fortipam:read fortipam:plan"
    with pytest.raises(
        AddressMcpOAuthSurfaceAcceptanceError,
        match="scope is invalid",
    ):
        _validated_scope("fortipam:read fortipam:admin")


def test_explicit_login_file_overrides_stale_acceptance_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login_file = tmp_path / "login.env"
    login_file.write_text(
        f"{LOGIN_USERNAME}=current-operator\n"
        f"{LOGIN_PASSWORD}=current-password-value\n",
        encoding="utf-8",
    )
    login_file.chmod(0o600)
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    monkeypatch.setenv(LOGIN_USERNAME, "stale-operator")
    monkeypatch.setenv(LOGIN_PASSWORD, "stale-password-value")

    with pytest.raises(AddressMcpOAuthSurfaceAcceptanceError, match="URL is invalid"):
        asyncio.run(
            run_address_mcp_oauth_surface_acceptance(
                "not-a-valid-url",
                login_file,
                state_directory / "client.json",
            )
        )

    assert os.environ[LOGIN_USERNAME] == "current-operator"
    assert os.environ[LOGIN_PASSWORD] == "current-password-value"


def test_private_lab_connection_override_preserves_the_logical_origin() -> None:
    parsed = urlsplit("http://mcp.example.test/fpamcp")
    connect_host = _private_lab_host()
    assert _accepted_scheme(parsed, True, connect_host) is True
    origin = "http://mcp.example.test"
    connection_origin = _connection_origin(
        parsed,
        allow_insecure_private_ip_lab=True,
        lab_connect_host=connect_host,
    )
    assert connection_origin == f"http://{connect_host}"
    assert _connection_url(
        "http://mcp.example.test/fpamcp/oauth/token?state=opaque",
        origin,
        connection_origin,
    ) == f"http://{connect_host}/fpamcp/oauth/token?state=opaque"
    assert _accepted_scheme(parsed, False, connect_host) is False
    with pytest.raises(AddressMcpOAuthSurfaceAcceptanceError, match="invalid"):
        _connection_origin(
            parsed,
            allow_insecure_private_ip_lab=True,
            lab_connect_host="203.0.113.10",
        )


def test_https_private_connection_override_preserves_tls_logical_host() -> None:
    parsed = urlsplit("https://fpamcp.example.test/fpamcp-v4")
    connect_host = _private_lab_host()
    assert _connection_origin(
        parsed,
        allow_insecure_private_ip_lab=False,
        lab_connect_host=connect_host,
    ) == "https://fpamcp.example.test"

    class FakeBackend:
        def __init__(self) -> None:
            self.hosts: list[str] = []
            self.ports: list[int] = []

        async def connect_tcp(self, host: str, port: int, *args: object, **kwargs: object) -> str:
            self.hosts.append(host)
            self.ports.append(port)
            return "stream"

        async def connect_unix_socket(self, *args: object, **kwargs: object) -> str:
            return "unix-stream"

        async def sleep(self, seconds: float) -> None:
            return None

    delegate = FakeBackend()
    backend = _StaticHostNetworkBackend(
        delegate,
        "fpamcp.example.test",
        connect_host,
    )
    assert asyncio.run(backend.connect_tcp("fpamcp.example.test", 443)) == "stream"
    assert asyncio.run(backend.connect_tcp("unrelated.example.test", 443)) == "stream"
    assert delegate.hosts == [connect_host, "unrelated.example.test"]
    assert delegate.ports == [443, 443]

    tunnel_backend = _StaticHostNetworkBackend(
        delegate,
        "fpamcp.example.test",
        "127.0.0.1",
        18443,
    )
    assert asyncio.run(tunnel_backend.connect_tcp("fpamcp.example.test", 443)) == "stream"
    assert asyncio.run(tunnel_backend.connect_tcp("unrelated.example.test", 443)) == "stream"
    assert delegate.hosts[-2:] == ["127.0.0.1", "unrelated.example.test"]
    assert delegate.ports[-2:] == [18443, 443]


def test_https_loopback_tunnel_requires_explicit_opt_in() -> None:
    parsed = urlsplit("https://fpamcp.example.test/fpamcp-v4")

    with pytest.raises(AddressMcpOAuthSurfaceAcceptanceError, match="invalid"):
        _connection_origin(
            parsed,
            allow_insecure_private_ip_lab=False,
            lab_connect_host="127.0.0.1",
        )

    assert _connection_origin(
        parsed,
        allow_insecure_private_ip_lab=False,
        lab_connect_host="127.0.0.1",
        allow_loopback_tunnel=True,
    ) == "https://fpamcp.example.test"


def test_private_http_loopback_tunnel_requires_all_lab_opt_ins() -> None:
    parsed = urlsplit(f"http://{_private_lab_host()}/fpamcp")

    with pytest.raises(AddressMcpOAuthSurfaceAcceptanceError, match="invalid"):
        _connection_origin(
            parsed,
            allow_insecure_private_ip_lab=True,
            lab_connect_host="127.0.0.1",
            allow_loopback_tunnel=True,
        )

    assert _connection_origin(
        parsed,
        allow_insecure_private_ip_lab=True,
        lab_connect_host="127.0.0.1",
        lab_connect_port=18080,
        allow_loopback_tunnel=True,
    ) == "http://127.0.0.1:18080"


@pytest.mark.parametrize("timeout", (False, 29, 301, float("inf")))
def test_invalid_mcp_read_deadline_is_rejected_before_loading_credentials(tmp_path: Path, timeout) -> None:
    with pytest.raises(AddressMcpOAuthSurfaceAcceptanceError, match="MCP read timeout"):
        asyncio.run(run_address_mcp_oauth_surface_acceptance(
            "https://pam.example.test/mcp", tmp_path / "absent.env", tmp_path / "client.json",
            mcp_read_timeout_seconds=timeout,
        ))
