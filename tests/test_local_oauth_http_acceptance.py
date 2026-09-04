from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from fortipam_mcp.env import EnvironmentFileError
from scripts.local_oauth_http_acceptance import (
    CLIENT_STATE_KEY,
    LOGIN_PASSWORD,
    LOGIN_USERNAME,
    LocalOAuthAcceptanceError,
    _initialize_payload,
    _locked_client_state,
    _read_client_id,
    _requested_scopes,
    _revocation_is_proven,
    _write_client_id,
    run_local_oauth_acceptance,
)


def test_local_oauth_acceptance_requires_https_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login_file = tmp_path / "login.env"
    login_file.write_text(
        f"{LOGIN_USERNAME}=operator\n{LOGIN_PASSWORD}=test-password-value\n",
        encoding="utf-8",
    )
    login_file.chmod(0o600)
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    client_state_file = state_directory / "client.env"
    monkeypatch.delenv(LOGIN_USERNAME, raising=False)
    monkeypatch.delenv(LOGIN_PASSWORD, raising=False)

    with pytest.raises(LocalOAuthAcceptanceError, match="URL is invalid"):
        asyncio.run(
            run_local_oauth_acceptance(
                "http://mcp.example.com/fpamcp",
                login_file,
                client_state_file,
            )
        )


def test_local_oauth_acceptance_rejects_unprotected_login_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login_file = tmp_path / "login.env"
    login_file.write_text(
        f"{LOGIN_USERNAME}=operator\n{LOGIN_PASSWORD}=test-password-value\n",
        encoding="utf-8",
    )
    login_file.chmod(0o644)
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    client_state_file = state_directory / "client.env"
    monkeypatch.delenv(LOGIN_USERNAME, raising=False)
    monkeypatch.delenv(LOGIN_PASSWORD, raising=False)

    with pytest.raises(EnvironmentFileError):
        asyncio.run(
            run_local_oauth_acceptance(
                "https://mcp.example.com/fpamcp",
                login_file,
                client_state_file,
            )
        )


def test_client_state_is_owner_only_and_reusable(tmp_path: Path) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    client_state_file = state_directory / "client.env"
    client_id = "acceptance-client-0123456789"

    with _locked_client_state(client_state_file):
        assert _read_client_id(client_state_file) is None
        _write_client_id(client_state_file, client_id)

    with _locked_client_state(client_state_file):
        assert _read_client_id(client_state_file) == client_id
    assert client_state_file.stat().st_mode & 0o777 == 0o600
    assert client_state_file.read_text(encoding="utf-8") == (
        f"{CLIENT_STATE_KEY}={client_id}\n"
    )


def test_client_state_rejects_group_readable_file(tmp_path: Path) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    client_state_file = state_directory / "client.env"
    client_state_file.write_text(
        f"{CLIENT_STATE_KEY}=acceptance-client-0123456789\n",
        encoding="utf-8",
    )
    client_state_file.chmod(0o640)

    with pytest.raises(LocalOAuthAcceptanceError, match="owner-only"):
        _read_client_id(client_state_file)


def test_revocation_probe_is_a_fixed_initialize_request() -> None:
    assert _initialize_payload() == {
        "jsonrpc": "2.0",
        "id": "revocation-proof",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "fortipam-mcp-revocation-proof",
                "version": "1",
            },
        },
    }


def test_revocation_requires_same_token_rejection() -> None:
    assert _revocation_is_proven(200, 401) is True
    assert _revocation_is_proven(200, 200) is False
    assert _revocation_is_proven(400, 401) is False


def test_acceptance_scope_selection_is_explicit_and_stable() -> None:
    assert _requested_scopes(False, False) == ("fortipam:read",)
    assert _requested_scopes(True, False) == (
        "fortipam:read",
        "fortipam:diagnostic",
    )
    assert _requested_scopes(False, True) == (
        "fortipam:read",
        "fortipam:operate",
    )
    assert _requested_scopes(True, True) == (
        "fortipam:read",
        "fortipam:diagnostic",
        "fortipam:operate",
    )
