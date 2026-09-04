#!/usr/bin/env python3
"""Run full embedded-OAuth and MCP acceptance without secret disclosure."""

from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Iterator
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx2

from fortipam_mcp.env import EnvironmentFileError, load_prefixed_environment_file
from scripts.external_http_acceptance import (
    run_external_http_acceptance_with_token,
)


LOGIN_PREFIX = "FORTIPAM_MCP_LOCAL_OAUTH_"
LOGIN_USERNAME = f"{LOGIN_PREFIX}USERNAME"
LOGIN_PASSWORD = f"{LOGIN_PREFIX}PASSWORD"
CLIENT_STATE_KEY = f"{LOGIN_PREFIX}CLIENT_ID"
REDIRECT_URI = "https://client.example/callback"
READ_SCOPE = "fortipam:read"
DIAGNOSTIC_SCOPE = "fortipam:diagnostic"
OPERATION_SCOPE = "fortipam:operate"
MCP_PROTOCOL_VERSION = "2025-11-25"
_HIDDEN_INPUT = re.compile(
    r'<input[^>]+name="(?P<name>request_id|csrf_token)"[^>]+'
    r'value="(?P<value>[^"]+)"'
)


class LocalOAuthAcceptanceError(RuntimeError):
    """A non-disclosing embedded-OAuth acceptance failure."""


async def run_local_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    ca_file: Path | None = None,
    include_diagnostics: bool = False,
    include_operation_scope: bool = False,
) -> dict[str, object]:
    """Acquire, use, and revoke one OAuth token through the real HTTPS ingress.

    A single dynamic client registration is persisted in an owner-only state
    file and reused. This prevents repeated release acceptance from exhausting
    the OAuth provider's bounded client-registration capacity.
    """

    load_prefixed_environment_file(login_file, LOGIN_PREFIX)
    username = os.environ.get(LOGIN_USERNAME)
    password = os.environ.get(LOGIN_PASSWORD)
    if not username or not password:
        raise LocalOAuthAcceptanceError(
            "The owner-only local OAuth acceptance identity is unavailable."
        )

    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise LocalOAuthAcceptanceError("The OAuth acceptance URL is invalid.")
    mcp_path = parsed.path.rstrip("/")
    if not mcp_path:
        raise LocalOAuthAcceptanceError("The OAuth acceptance path is invalid.")
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    issuer = f"{origin}{mcp_path}/oauth"
    protected_metadata = (
        f"{origin}/.well-known/oauth-protected-resource{mcp_path}"
    )
    authorization_metadata = (
        f"{origin}/.well-known/oauth-authorization-server{mcp_path}/oauth"
    )
    registration_endpoint = f"{issuer}/register"
    authorization_endpoint = f"{issuer}/authorize"
    login_endpoint = f"{issuer}/login"
    token_endpoint = f"{issuer}/token"
    revocation_endpoint = f"{issuer}/revoke"
    verify: str | bool = str(ca_file) if ca_file is not None else True
    scope = " ".join(
        _requested_scopes(include_diagnostics, include_operation_scope)
    )

    access_token: str | None = None
    client_registered_this_run = False
    client_reused = False
    revocation_confirmed = False
    async with httpx2.AsyncClient(
        timeout=30.0,
        follow_redirects=False,
        trust_env=False,
        verify=verify,
        headers={"User-Agent": "fortipam-mcp-local-oauth-acceptance/1"},
    ) as client:
        protected = await client.get(protected_metadata)
        metadata = await client.get(authorization_metadata)
        if protected.status_code != 200 or metadata.status_code != 200:
            raise LocalOAuthAcceptanceError("OAuth metadata acceptance failed.")

        with _locked_client_state(client_state_file):
            client_id = _read_client_id(client_state_file)
            if client_id is None:
                registration = await client.post(
                    registration_endpoint,
                    json={
                        "client_name": "FortiPAM MCP release acceptance",
                        "redirect_uris": [REDIRECT_URI],
                        "token_endpoint_auth_method": "none",
                        "grant_types": ["authorization_code"],
                        "response_types": ["code"],
                        "scope": scope,
                    },
                )
                if registration.status_code != 201:
                    raise LocalOAuthAcceptanceError(
                        "OAuth client registration failed."
                    )
                client_id_value = registration.json().get("client_id")
                if not isinstance(client_id_value, str):
                    raise LocalOAuthAcceptanceError(
                        "OAuth client registration was invalid."
                    )
                _validate_client_id(client_id_value)
                client_id = client_id_value
                _write_client_id(client_state_file, client_id)
                client_registered_this_run = True
            else:
                client_reused = True

        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")
        state = secrets.token_urlsafe(32)
        authorization_query = urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "scope": scope,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": url,
            }
        )
        authorization = await client.get(
            f"{authorization_endpoint}?{authorization_query}"
        )
        if authorization.status_code != 302:
            raise LocalOAuthAcceptanceError("OAuth authorization request failed.")
        login_url = authorization.headers.get("location", "")
        login_parsed = urlsplit(login_url)
        if (
            urlunsplit((login_parsed.scheme, login_parsed.netloc, "", "", ""))
            != origin
            or login_parsed.path != urlsplit(login_endpoint).path
        ):
            raise LocalOAuthAcceptanceError("OAuth login redirect was invalid.")

        login_page = await client.get(login_url)
        if login_page.status_code != 200:
            raise LocalOAuthAcceptanceError("OAuth login page was unavailable.")
        hidden = {
            match.group("name"): match.group("value")
            for match in _HIDDEN_INPUT.finditer(login_page.text)
        }
        if set(hidden) != {"request_id", "csrf_token"}:
            raise LocalOAuthAcceptanceError("OAuth login form was invalid.")
        approved = await client.post(
            login_endpoint,
            data={
                **hidden,
                "username": username,
                "password": password,
                "action": "allow",
            },
            headers={"Origin": origin},
        )
        if approved.status_code != 302:
            raise LocalOAuthAcceptanceError("OAuth local login failed.")
        callback = urlsplit(approved.headers.get("location", ""))
        callback_query = parse_qs(callback.query)
        if (
            urlunsplit((callback.scheme, callback.netloc, callback.path, "", ""))
            != REDIRECT_URI
            or callback_query.get("state") != [state]
            or callback_query.get("iss") != [issuer]
            or len(callback_query.get("code", [])) != 1
        ):
            raise LocalOAuthAcceptanceError("OAuth callback validation failed.")
        code = callback_query["code"][0]

        token_response = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
                "resource": url,
            },
        )
        if token_response.status_code != 200:
            raise LocalOAuthAcceptanceError("OAuth token exchange failed.")
        access_token_value = token_response.json().get("access_token")
        if not isinstance(access_token_value, str) or not access_token_value:
            raise LocalOAuthAcceptanceError("OAuth token response was invalid.")
        access_token = access_token_value

        try:
            mcp_result = await run_external_http_acceptance_with_token(
                url,
                access_token,
                expected_path=mcp_path,
                ca_file=ca_file,
                include_diagnostics=include_diagnostics,
            )
        finally:
            revoked = await client.post(
                revocation_endpoint,
                data={
                    "client_id": client_id,
                    "client_secret": "",
                    "token": access_token,
                },
            )
            rejected = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                },
                json=_initialize_payload(),
            )
            revocation_confirmed = _revocation_is_proven(
                revoked.status_code,
                rejected.status_code,
            )
        if not revocation_confirmed:
            raise LocalOAuthAcceptanceError(
                "OAuth token revocation was not proven by a rejected MCP request."
            )

    return {
        **mcp_result,
        "authentication": "oauth_authorization_code_pkce_s256",
        "oauth_metadata_accepted": True,
        "dynamic_client_registration_performed": client_registered_this_run,
        "acceptance_client_reused": client_reused,
        "persistent_acceptance_client_state": True,
        "client_id_values_returned": False,
        "local_login_accepted": True,
        "token_exchange_accepted": access_token is not None,
        "token_revocation_accepted": revocation_confirmed,
        "revoked_access_rejected": revocation_confirmed,
        "environment_proxy_used": False,
        "redirects_followed": False,
        "login_values_returned": False,
        "oauth_token_values_returned": False,
        "diagnostic_scope_requested": include_diagnostics,
        "operation_scope_requested": include_operation_scope,
    }


def _requested_scopes(
    include_diagnostics: bool,
    include_operation_scope: bool,
) -> tuple[str, ...]:
    """Return the explicit acceptance scope set in stable order."""

    scopes = [READ_SCOPE]
    if include_diagnostics:
        scopes.append(DIAGNOSTIC_SCOPE)
    if include_operation_scope:
        scopes.append(OPERATION_SCOPE)
    return tuple(scopes)


def _initialize_payload() -> dict[str, object]:
    """Return a fixed no-device MCP request used only after token revocation."""

    return {
        "jsonrpc": "2.0",
        "id": "revocation-proof",
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "fortipam-mcp-revocation-proof",
                "version": "1",
            },
        },
    }


def _revocation_is_proven(revoke_status: int, rejected_status: int) -> bool:
    """Require both revoke acceptance and denial of the same access token."""

    return revoke_status == 200 and rejected_status == 401


@contextmanager
def _locked_client_state(path: Path) -> Iterator[None]:
    """Serialize one-time registration without exposing or rotating client IDs."""

    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise LocalOAuthAcceptanceError(
            "The OAuth acceptance client-state directory is invalid."
        )
    if stat.S_IMODE(parent.stat().st_mode) & 0o077:
        raise LocalOAuthAcceptanceError(
            "The OAuth acceptance client-state directory must be owner-only."
        )
    lock_path = path.with_name(f".{path.name}.lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _read_client_id(path: Path) -> str | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise LocalOAuthAcceptanceError(
            "The OAuth acceptance client-state file is invalid."
        )
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise LocalOAuthAcceptanceError(
            "The OAuth acceptance client-state file must be owner-only."
        )
    assignments = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    prefix = f"{CLIENT_STATE_KEY}="
    if len(assignments) != 1 or not assignments[0].startswith(prefix):
        raise LocalOAuthAcceptanceError(
            "The OAuth acceptance client-state file is invalid."
        )
    client_id = assignments[0][len(prefix) :]
    _validate_client_id(client_id)
    return client_id


def _write_client_id(path: Path, client_id: str) -> None:
    _validate_client_id(client_id)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        payload = f"{CLIENT_STATE_KEY}={client_id}\n".encode("utf-8")
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    path.chmod(0o600)


def _validate_client_id(client_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9._~-]{16,256}", client_id):
        raise LocalOAuthAcceptanceError(
            "The OAuth acceptance client registration was invalid."
        )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Run embedded OAuth and MCP acceptance through HTTPS."
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument(
        "--include-diagnostics",
        action="store_true",
        help=(
            "Request the separate diagnostic scope and exercise immutable local "
            "baseline and correlation workflows."
        ),
    )
    parser.add_argument(
        "--include-operation-scope",
        action="store_true",
        help=(
            "Request the explicit V3 operate scope while confirming that the "
            "default-deny candidate exposes no device action tool."
        ),
    )
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(
            run_local_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                args.ca_file,
                args.include_diagnostics,
                args.include_operation_scope,
            )
        )
    except (EnvironmentFileError, LocalOAuthAcceptanceError, ValueError) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
