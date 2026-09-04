from __future__ import annotations

import os
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import server as server_module
from fortipam_mcp.config import HA_CONFIGURATION_PATH
from fortipam_mcp.http_server import (
    HTTP_ENV_FILE_VARIABLE,
    HttpConfigurationError,
    HttpServerSettings,
    create_http_app,
    load_http_runtime_environment,
)
from fortipam_mcp.http_smoke import run_smoke
from fortipam_mcp.local_oauth import hash_local_password, verify_local_password
from fortipam_mcp.mcp_smoke import EXPECTED_TOOLS, LAB_EXPECTED_TOOLS
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV, RuntimeProfile

PREFIX = "FORTIPAM_MCP_HTTP_"
TEST_TOKEN = "test-only-bearer-token-0123456789abcdef"


def _bearer_environment(**overrides: str) -> dict[str, str]:
    environment = {
        f"{PREFIX}AUTH_MODE": "bearer",
        f"{PREFIX}BEARER_TOKEN": TEST_TOKEN,
    }
    environment.update(overrides)
    return environment


def _initialize_payload() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1"},
        },
    }


def _local_oauth_environment(tmp_path: Path) -> dict[str, str]:
    state_dir = tmp_path / "oauth-state"
    state_dir.mkdir(mode=0o700)
    return {
        f"{PREFIX}AUTH_MODE": "local_oauth",
        f"{PREFIX}PATH": "/fpamcp",
        f"{PREFIX}PUBLIC_URL": "https://mcp.example.com/fpamcp",
        f"{PREFIX}ALLOWED_HOSTS": "mcp.example.com",
        f"{PREFIX}LOCAL_OAUTH_DB": str(state_dir / "oauth.sqlite3"),
        f"{PREFIX}LOCAL_OAUTH_USERNAME": "operator",
        f"{PREFIX}LOCAL_OAUTH_PASSWORD_HASH": hash_local_password(
            "correct-horse-battery-staple",
            salt=b"0123456789abcdef",
        ),
    }


def _register_public_client(
    client: TestClient, scope: str = "fortipam:read"
) -> str:
    response = client.post(
        "/fpamcp/oauth/register",
        json={
            "client_name": "FortiPAM MCP test client",
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": scope,
        },
    )
    assert response.status_code == 201
    assert response.json().get("client_secret") is None
    return str(response.json()["client_id"])


def _authorize_and_login(
    client: TestClient,
    client_id: str,
    scope: str = "fortipam:read",
) -> tuple[str, str]:
    verifier = "test-code-verifier-with-more-than-forty-three-characters"
    import base64
    import hashlib

    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    authorization = client.get(
        "/fpamcp/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://client.example/callback",
            "scope": scope,
            "state": "state-123",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": "https://mcp.example.com/fpamcp",
        },
        follow_redirects=False,
    )
    assert authorization.status_code == 302
    login_path = authorization.headers["location"]
    assert login_path.startswith("https://mcp.example.com/fpamcp/oauth/login?")

    login_page = client.get(login_path)
    assert login_page.status_code == 200
    request_id = re.search(r'name="request_id" value="([^"]+)"', login_page.text)
    csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
    assert request_id is not None
    assert csrf_token is not None
    approved = client.post(
        "/fpamcp/oauth/login",
        data={
            "request_id": request_id.group(1),
            "csrf_token": csrf_token.group(1),
            "username": "operator",
            "password": "correct-horse-battery-staple",
            "action": "allow",
        },
        headers={"origin": "https://mcp.example.com"},
        follow_redirects=False,
    )
    assert approved.status_code == 302
    callback = urlsplit(approved.headers["location"])
    callback_query = parse_qs(callback.query)
    assert callback.scheme == "https"
    assert callback.netloc == "client.example"
    assert callback_query["state"] == ["state-123"]
    assert callback_query["iss"] == ["https://mcp.example.com/fpamcp/oauth"]
    return callback_query["code"][0], verifier


def _request_headers(token: str = TEST_TOKEN) -> dict[str, str]:
    return {
        "accept": "application/json, text/event-stream",
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "host": "127.0.0.1:8000",
        "mcp-protocol-version": "2025-11-25",
    }


def _diagnostic_environment(tmp_path: Path) -> dict[str, str]:
    environment = _local_oauth_environment(tmp_path)
    diagnostic_dir = tmp_path / "diagnostic-state"
    diagnostic_dir.mkdir(mode=0o700)
    key_file = diagnostic_dir / "hmac.key"
    key_file.write_text("6b" * 32, encoding="ascii")
    key_file.chmod(0o600)
    environment.update(
        {
            "FORTIPAM_MCP_DIAGNOSTIC_DB": str(
                diagnostic_dir / "diagnostic.sqlite3"
            ),
            "FORTIPAM_MCP_DIAGNOSTIC_HMAC_KEY_FILE": str(key_file),
        }
    )
    return environment


class _FixedDeviceTools:
    async def get_ha_configuration_posture_summary(self) -> dict[str, object]:
        return {
            "scenario": "ha_sync",
            "operation": "GET",
            "path": HA_CONFIGURATION_PATH,
            "sensitivity": "ha_configuration_posture",
            "status_code": 200,
            "content_type": "application/json",
            "response_body_returned": False,
            "posture": {
                "contract": "fortipam_ha_configuration_posture_v1",
                "ha_enabled": False,
                "topology_mode": "standalone",
                "heartbeat_authentication_enabled": True,
                "heartbeat_encryption_enabled": True,
                "heartbeat_interface_configured": True,
                "monitored_interface_configured": False,
                "dedicated_management_enabled": False,
                "management_interface_entry_count": 0,
                "unicast_heartbeat_enabled": False,
                "unicast_peer_entry_count": 0,
                "session_pickup_enabled": False,
                "connectionless_session_pickup_enabled": False,
                "override_enabled": False,
                "synchronization_state": "not_observed",
                "response_body_returned": False,
                "serial_values_returned": False,
                "network_values_returned": False,
                "interface_values_returned": False,
                "group_values_returned": False,
                "credential_values_returned": False,
                "priority_values_returned": False,
                "checksum_values_returned": False,
            },
        }


class _FixedCliTools:
    async def get_ha_configuration_summary(self) -> dict[str, object]:
        return {
            "workflow_id": "ha_configuration",
            "execution_status": "completed",
            "evidence": {
                "evidence_status": "complete",
                "ha_mode": "standalone",
                "session_pickup": "disabled",
                "override_state": "disabled",
                "configuration_security": "enabled",
                "identity_values_returned": False,
                "network_values_returned": False,
                "group_name_returned": False,
                "password_values_returned": False,
                "priority_values_returned": False,
                "exact_checksum_returned": False,
                "raw_cli_returned": False,
            },
            "raw_cli_returned": False,
            "credential_values_returned": False,
        }


def test_bearer_is_the_secure_default_and_requires_a_strong_token() -> None:
    with pytest.raises(HttpConfigurationError, match="at least 32"):
        HttpServerSettings.from_environment({})
    with pytest.raises(HttpConfigurationError, match="at least 32"):
        HttpServerSettings.from_environment(
            {f"{PREFIX}AUTH_MODE": "bearer", f"{PREFIX}BEARER_TOKEN": "short"}
        )


def test_unauthenticated_mode_is_loopback_only() -> None:
    settings = HttpServerSettings.from_environment(
        {f"{PREFIX}AUTH_MODE": "none"}
    )
    assert settings.host == "127.0.0.1"

    with pytest.raises(HttpConfigurationError, match="allowed hosts"):
        HttpServerSettings.from_environment(
            {
                f"{PREFIX}AUTH_MODE": "none",
                f"{PREFIX}HOST": "0.0.0.0",
            }
        )
    with pytest.raises(HttpConfigurationError, match="restricted to loopback"):
        HttpServerSettings.from_environment(
            {
                f"{PREFIX}AUTH_MODE": "none",
                f"{PREFIX}HOST": "0.0.0.0",
                f"{PREFIX}ALLOWED_HOSTS": "mcp.example.com",
            }
        )


def test_oauth_requires_audience_bound_https_configuration() -> None:
    environment = {
        f"{PREFIX}AUTH_MODE": "oauth",
        f"{PREFIX}PATH": "/fpamcp",
        f"{PREFIX}PUBLIC_URL": "https://mcp.example.com/fpamcp",
        f"{PREFIX}OAUTH_ISSUER": "https://id.example.com",
        f"{PREFIX}OAUTH_JWKS_URL": "https://id.example.com/.well-known/jwks.json",
        f"{PREFIX}OAUTH_AUDIENCE": "https://mcp.example.com/fpamcp",
    }
    settings = HttpServerSettings.from_environment(environment)

    assert settings.oauth_audience == settings.public_url
    assert settings.oauth_required_scopes == ("fortipam:read",)

    environment[f"{PREFIX}OAUTH_AUDIENCE"] = "https://other.example.com/fpamcp"
    with pytest.raises(HttpConfigurationError, match="exactly match"):
        HttpServerSettings.from_environment(environment)


def test_local_oauth_requires_owner_only_state_and_a_password_hash(tmp_path: Path) -> None:
    environment = _local_oauth_environment(tmp_path)
    settings = HttpServerSettings.from_environment(environment)

    assert settings.local_oauth is not None
    assert settings.local_oauth.issuer == "https://mcp.example.com/fpamcp/oauth"
    assert verify_local_password(
        "correct-horse-battery-staple",
        settings.local_oauth.password_hash,
    )
    assert not verify_local_password("wrong-password", settings.local_oauth.password_hash)

    unsafe_dir = tmp_path / "unsafe-state"
    unsafe_dir.mkdir(mode=0o755)
    environment[f"{PREFIX}LOCAL_OAUTH_DB"] = str(unsafe_dir / "oauth.sqlite3")
    unsafe = HttpServerSettings.from_environment(environment)
    with pytest.raises(ValueError, match="owner-only"):
        create_http_app(unsafe)


def test_embedded_oauth_discovery_login_rotation_and_revocation(tmp_path: Path) -> None:
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path))

    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        protected = client.get("/.well-known/oauth-protected-resource/fpamcp")
        authorization_server = client.get(
            "/.well-known/oauth-authorization-server/fpamcp/oauth"
        )
        rejected_host = client.get(
            "/.well-known/oauth-authorization-server/fpamcp/oauth",
            headers={"host": "untrusted.example"},
        )
        unauthorized = client.post(
            "/fpamcp",
            headers={
                "accept": "application/json, text/event-stream",
                "content-type": "application/json",
                "mcp-protocol-version": "2025-11-25",
            },
            json=_initialize_payload(),
        )

        assert protected.status_code == 200
        assert protected.json()["resource"] == "https://mcp.example.com/fpamcp"
        assert protected.json()["authorization_servers"] == [
            "https://mcp.example.com/fpamcp/oauth"
        ]
        assert authorization_server.status_code == 200
        assert rejected_host.status_code == 421
        metadata = authorization_server.json()
        assert metadata["authorization_endpoint"].endswith("/fpamcp/oauth/authorize")
        assert metadata["token_endpoint"].endswith("/fpamcp/oauth/token")
        assert metadata["registration_endpoint"].endswith("/fpamcp/oauth/register")
        assert "none" in metadata["token_endpoint_auth_methods_supported"]
        assert unauthorized.status_code == 401
        assert "resource_metadata=" in unauthorized.headers["www-authenticate"]

        client_id = _register_public_client(client)
        code, verifier = _authorize_and_login(client, client_id)
        token_response = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert token_response.status_code == 200
        access_token = token_response.json()["access_token"]
        refresh_token = token_response.json()["refresh_token"]

        replay = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"

        accepted = client.post(
            "/fpamcp",
            headers={
                "accept": "application/json, text/event-stream",
                "authorization": f"Bearer {access_token}",
                "content-type": "application/json",
                "mcp-protocol-version": "2025-11-25",
            },
            json=_initialize_payload(),
        )
        assert accepted.status_code == 200

        refreshed = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
                "scope": "fortipam:read",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert refreshed.status_code == 200
        rotated_access = refreshed.json()["access_token"]
        assert rotated_access != access_token

        old_access = client.post(
            "/fpamcp",
            headers={
                "accept": "application/json, text/event-stream",
                "authorization": f"Bearer {access_token}",
                "content-type": "application/json",
                "mcp-protocol-version": "2025-11-25",
            },
            json=_initialize_payload(),
        )
        assert old_access.status_code == 401

        revoked = client.post(
            "/fpamcp/oauth/revoke",
            data={"client_id": client_id, "client_secret": "", "token": rotated_access},
        )
        assert revoked.status_code == 200
        revoked_access = client.post(
            "/fpamcp",
            headers={
                "accept": "application/json, text/event-stream",
                "authorization": f"Bearer {rotated_access}",
                "content-type": "application/json",
                "mcp-protocol-version": "2025-11-25",
            },
            json=_initialize_payload(),
        )
        assert revoked_access.status_code == 401

    database_bytes = settings.local_oauth.database_path.read_bytes()  # type: ignore[union-attr]
    assert access_token.encode("ascii") not in database_bytes
    assert refresh_token.encode("ascii") not in database_bytes
    assert code.encode("ascii") not in database_bytes
    assert b"correct-horse-battery-staple" not in database_bytes


def test_http_oauth_diagnostic_scope_executes_only_fixed_local_state_workflows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        server_module.FortiPamMcpServer,
        "_require_device_tools",
        lambda self: _FixedDeviceTools(),
    )
    monkeypatch.setattr(
        server_module.FortiPamMcpServer,
        "_require_cli_tools",
        lambda self: _FixedCliTools(),
    )
    settings = HttpServerSettings.from_environment(
        _diagnostic_environment(tmp_path)
    )
    scope = "fortipam:read fortipam:diagnostic"

    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token_response = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert token_response.status_code == 200
        assert set(token_response.json()["scope"].split()) == {
            "fortipam:read",
            "fortipam:diagnostic",
        }
        headers = _request_headers(token_response.json()["access_token"])
        headers["host"] = "mcp.example.com"

        def call(tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
            response = client.post(
                "/fpamcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": tool_name,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": arguments},
                },
            )
            assert response.status_code == 200
            payload = response.json()["result"]
            assert payload.get("isError", False) is False
            return payload["structuredContent"]

        assert call("create_ha_diagnostic_baseline", {"baseline_id": "known-ha"}) == {
            "status": "created"
        }
        assert call("compare_ha_diagnostic_baseline", {"baseline_id": "known-ha"}) == {
            "status": "unchanged"
        }
        assert call("correlate_ha_api_cli_posture", {}) == {
            "status": "operationally_consistent"
        }

        read_client_id = _register_public_client(client)
        read_code, read_verifier = _authorize_and_login(client, read_client_id)
        read_token_response = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": read_client_id,
                "code": read_code,
                "code_verifier": read_verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert read_token_response.status_code == 200
        read_headers = _request_headers(
            read_token_response.json()["access_token"]
        )
        read_headers["host"] = "mcp.example.com"
        denied = client.post(
            "/fpamcp",
            headers=read_headers,
            json={
                "jsonrpc": "2.0",
                "id": "scope-denied",
                "method": "tools/call",
                "params": {
                    "name": "create_ha_diagnostic_baseline",
                    "arguments": {"baseline_id": "other-ha"},
                },
            },
        )
        assert denied.status_code == 200
        assert denied.json()["result"]["isError"] is True
        assert "other-ha" not in denied.text

    state_bytes = (
        tmp_path / "diagnostic-state" / "diagnostic.sqlite3"
    ).read_bytes()
    assert b"known-ha" not in state_bytes


def test_embedded_oauth_rejects_redirect_resource_and_cross_origin_login(
    tmp_path: Path,
) -> None:
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path))
    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        invalid_redirect = client.post(
            "/fpamcp/oauth/register",
            json={
                "client_name": "Unsafe client",
                "redirect_uris": ["http://remote.example/callback"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "scope": "fortipam:read",
            },
        )
        assert invalid_redirect.status_code == 400
        assert invalid_redirect.json()["error"] == "invalid_redirect_uri"

        client_id = _register_public_client(client)
        common_params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://client.example/callback",
            "scope": "fortipam:read",
            "state": "negative-state",
            "code_challenge": "A" * 43,
            "code_challenge_method": "S256",
        }
        wrong_resource = client.get(
            "/fpamcp/oauth/authorize",
            params={**common_params, "resource": "https://other.example/mcp"},
            follow_redirects=False,
        )
        assert wrong_resource.status_code == 302
        assert parse_qs(urlsplit(wrong_resource.headers["location"]).query)["error"] == [
            "invalid_target"
        ]

        authorization = client.get(
            "/fpamcp/oauth/authorize",
            params={
                **common_params,
                "resource": "https://mcp.example.com/fpamcp",
            },
            follow_redirects=False,
        )
        login_page = client.get(authorization.headers["location"])
        request_id = re.search(r'name="request_id" value="([^"]+)"', login_page.text)
        csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
        assert request_id is not None
        assert csrf_token is not None
        cross_origin = client.post(
            "/fpamcp/oauth/login",
            data={
                "request_id": request_id.group(1),
                "csrf_token": csrf_token.group(1),
                "username": "operator",
                "password": "correct-horse-battery-staple",
                "action": "allow",
            },
            headers={"origin": "https://attacker.example"},
            follow_redirects=False,
        )
        assert cross_origin.status_code == 400
        assert "rejected" in cross_origin.text


def test_embedded_oauth_access_survives_application_restart(tmp_path: Path) -> None:
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path))
    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        client_id = _register_public_client(client)
        code, verifier = _authorize_and_login(client, client_id)
        tokens = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert tokens.status_code == 200
        access_token = tokens.json()["access_token"]

    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as restarted:
        accepted = restarted.post(
            "/fpamcp",
            headers={
                "accept": "application/json, text/event-stream",
                "authorization": f"Bearer {access_token}",
                "content-type": "application/json",
                "mcp-protocol-version": "2025-11-25",
            },
            json=_initialize_payload(),
        )
        assert accepted.status_code == 200
        assert accepted.json()["result"]["serverInfo"]["version"] == "3.1.3"


def test_http_environment_file_is_owner_only_and_prefix_filtered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / "http.env"
    env_file.write_text(
        f"{PREFIX}AUTH_MODE=bearer\n"
        f"{PREFIX}BEARER_TOKEN={TEST_TOKEN}\n"
        f"{RUNTIME_PROFILE_ENV}=lab-simulated\n"
        "FORTIPAM_MCP_DIAGNOSTIC_DB=/protected/diagnostic.sqlite3\n"
        "UNRELATED_SECRET=must-not-load\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    monkeypatch.setenv(HTTP_ENV_FILE_VARIABLE, str(env_file))
    monkeypatch.delenv(f"{PREFIX}AUTH_MODE", raising=False)
    monkeypatch.delenv(f"{PREFIX}BEARER_TOKEN", raising=False)
    monkeypatch.delenv(RUNTIME_PROFILE_ENV, raising=False)
    monkeypatch.delenv("UNRELATED_SECRET", raising=False)
    monkeypatch.delenv("FORTIPAM_MCP_DIAGNOSTIC_DB", raising=False)

    assert load_http_runtime_environment() is True
    assert os.environ[f"{PREFIX}AUTH_MODE"] == "bearer"
    assert os.environ[f"{PREFIX}BEARER_TOKEN"] == TEST_TOKEN
    assert os.environ[RUNTIME_PROFILE_ENV] == "lab-simulated"
    assert os.environ["FORTIPAM_MCP_DIAGNOSTIC_DB"] == "/protected/diagnostic.sqlite3"
    assert "UNRELATED_SECRET" not in os.environ
    os.environ.pop(RUNTIME_PROFILE_ENV, None)


def test_streamable_http_requires_bearer_and_lists_frozen_tool_surface() -> None:
    settings = HttpServerSettings.from_environment(_bearer_environment())
    assert settings.runtime_profile is RuntimeProfile.READONLY

    with TestClient(create_http_app(settings)) as client:
        unauthorized = client.post(
            settings.path,
            headers={
                key: value
                for key, value in _request_headers().items()
                if key != "authorization"
            },
            json=_initialize_payload(),
        )
        initialized = client.post(
            settings.path,
            headers=_request_headers(),
            json=_initialize_payload(),
        )
        tools = client.post(
            settings.path,
            headers=_request_headers(),
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        rejected_host = client.post(
            settings.path,
            headers={**_request_headers(), "host": "untrusted.example"},
            json=_initialize_payload(),
        )

    assert unauthorized.status_code == 401
    assert unauthorized.headers["cache-control"] == "no-store"
    assert initialized.status_code == 200
    assert initialized.json()["result"]["serverInfo"]["version"] == "3.1.3"
    assert tools.status_code == 200
    assert {tool["name"] for tool in tools.json()["result"]["tools"]} == set(
        EXPECTED_TOOLS
    )
    assert rejected_host.status_code == 421


def test_streamable_http_lab_profile_is_explicit_and_offline(monkeypatch) -> None:
    def _unexpected_environment_load() -> None:
        raise AssertionError("Listing HTTP LAB tools must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    settings = HttpServerSettings.from_environment(
        _bearer_environment(**{RUNTIME_PROFILE_ENV: "lab-simulated"})
    )
    assert settings.runtime_profile is RuntimeProfile.LAB_SIMULATED

    with TestClient(create_http_app(settings)) as client:
        initialized = client.post(
            settings.path,
            headers=_request_headers(),
            json=_initialize_payload(),
        )
        tools = client.post(
            settings.path,
            headers=_request_headers(),
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )

    assert initialized.status_code == 200
    assert tools.status_code == 200
    assert {tool["name"] for tool in tools.json()["result"]["tools"]} == set(
        LAB_EXPECTED_TOOLS
    )
    assert len(tools.json()["result"]["tools"]) == 34


def test_packaged_streamable_http_smoke_is_offline() -> None:
    result = run_smoke()

    assert result["transport"] == "streamable_http"
    assert result["tool_count"] == len(EXPECTED_TOOLS)
    assert result["missing_credential_rejected"] is True
    assert result["live_fortipam_contacted"] is False
