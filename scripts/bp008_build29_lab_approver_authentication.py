#!/usr/bin/env python3
"""Authenticate one separate lab account through the existing OAuth SDK.

This private ASGI harness creates no listener and grants no main-server scope.
It does not issue delegation, approval receipts, or execution qualification.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import cast
from urllib.parse import parse_qs, urlsplit, urlunsplit

import httpx
from starlette.applications import Starlette

from fortipam_mcp.local_oauth import LocalOAuthProvider, local_oauth_settings_from_environment
from fortipam_mcp.secret_approval_build29_projection_source import _reject_constant, _unique_members
from fortipam_mcp.secret_approval_build29_runtime_provider import _read_private_buffer
from fortipam_mcp.secret_create_central_lab_provider import _ascii_identifier, _dotenv_value_range
from fortipam_mcp.secret_metadata_http_transport import _zeroize_mutable
from fortipam_mcp.v4_plan_runtime import (
    V4_APPROVAL_SCOPE, V4PlanningPrincipal, _human_identity_binding,
    approver_from_access_token, planning_authorization_settings_from_environment,
)
from v4_planning import AuthenticatedRequester


HTTP_PREFIX = "FORTIPAM_MCP_HTTP_"
LOGIN_PREFIX = "FORTIPAM_MCP_LOCAL_OAUTH_"
LOGIN_KEYS = frozenset(LOGIN_PREFIX + suffix for suffix in ("USERNAME", "PASSWORD", "PASSWORD_HASH"))
_MAIN_REQUIRED = frozenset({
    HTTP_PREFIX + "PUBLIC_URL", HTTP_PREFIX + "LOCAL_OAUTH_DB", HTTP_PREFIX + "LOCAL_OAUTH_USERNAME",
    HTTP_PREFIX + "LOCAL_OAUTH_PASSWORD_HASH", "FORTIPAM_MCP_V4_PLAN_PRINCIPAL_HMAC_KEY_FILE",
})
_MAIN_KEYS = _MAIN_REQUIRED | {HTTP_PREFIX + "LOCAL_OAUTH_ISSUER", HTTP_PREFIX + "INSECURE_PRIVATE_IP_LAB"}
_REDIRECT = "https://bp008-lab-client.example.test/callback"
_HIDDEN = re.compile(r'<input[^>]+name="(?P<name>request_id|csrf_token)"[^>]+value="(?P<value>[^"]+)"')
_UNAVAILABLE = "Protected BP008 lab approver authentication failed."


class LabApproverAuthenticationError(RuntimeError):
    """Non-disclosing failure for the fixed private authentication harness."""


async def authenticate_bp008_build29_lab_approver(
    main_env_file: Path, requester_principal_file: Path, approver_login_file: Path, approver_output_file: Path,
) -> dict[str, object]:
    """Authenticate, separate, revoke, then exclusively save private metadata.

    The requester file is the protected ``asdict(V4PlanningPrincipal)`` output
    from the already authenticated main client; this does not authenticate it
    again. The login file has exactly the three declared LOGIN_KEYS.
    """
    buffers: list[bytearray] = []
    directory: int | None = None
    main: dict[str, bytearray] = {}
    login: dict[str, bytearray] = {}
    try:
        if len({main_env_file, requester_principal_file, approver_login_file, approver_output_file}) != 4:
            raise ValueError
        for path in (main_env_file, requester_principal_file, approver_login_file):
            buffers.append(_read_private_buffer(path, 16384))
        main = _selected_env(buffers[0], _MAIN_KEYS, _MAIN_REQUIRED, exact=False)
        login = _selected_env(buffers[2], LOGIN_KEYS, LOGIN_KEYS, exact=True)
        buffers.extend(main.values())
        buffers.extend(login.values())
        environment = {name: value.decode("utf-8") for name, value in main.items()}
        insecure = environment.get(HTTP_PREFIX + "INSECURE_PRIVATE_IP_LAB", "false")
        if insecure not in {"true", "false"}:
            raise ValueError
        settings = local_oauth_settings_from_environment(
            environment, prefix=HTTP_PREFIX, public_url=environment[HTTP_PREFIX + "PUBLIC_URL"],
            allow_insecure_private_ip_lab=insecure == "true",
        )
        identity = planning_authorization_settings_from_environment(
            environment, expected_resource=settings.resource, allow_insecure_private_ip_lab=insecure == "true",
        )
        requester = _requester(buffers[1])
        expected = _human_identity_binding(
            identity, issuer=settings.issuer, subject=settings.username, resource=settings.resource,
        )
        if (requester.requester.subject_ref, requester.requester.identity_authority_ref,
                requester.requester.subject_namespace) != expected:
            raise ValueError
        username = login[LOGIN_PREFIX + "USERNAME"].decode("utf-8")
        if username == settings.username or not 1 <= len(username) <= 64 or any(char.isspace() for char in username):
            raise ValueError
        # Reject aliasing and an existing output before provider bootstrap.
        if approver_output_file in {settings.database_path, Path(environment["FORTIPAM_MCP_V4_PLAN_PRINCIPAL_HMAC_KEY_FILE"])}:
            raise ValueError
        directory = _output_directory(approver_output_file)
        try:
            os.stat(approver_output_file.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError
        provider = LocalOAuthProvider(replace(
            settings, username=username, password_hash=login[LOGIN_PREFIX + "PASSWORD_HASH"].decode("utf-8"),
            scope=V4_APPROVAL_SCOPE, available_scopes=(V4_APPROVAL_SCOPE,), default_scopes=(V4_APPROVAL_SCOPE,),
        ))
        metadata = await _sdk_authenticate(provider, username, login[LOGIN_PREFIX + "PASSWORD"], identity, requester)
        _write_metadata(directory, approver_output_file.name, metadata)
        return {"sdk_authenticated": True, "comparable_namespace": True, "separate_subject": True, "token_revoked": True}
    except Exception:
        raise LabApproverAuthenticationError(_UNAVAILABLE) from None
    finally:
        for raw in buffers:
            _zeroize_mutable(raw)
        # Also cover failures while selecting the second input.
        for raw in (*main.values(), *login.values()):
            _zeroize_mutable(raw)
        if directory is not None:
            os.close(directory)


def _selected_env(
    raw: bytearray, selected: frozenset[str], required: frozenset[str], *, exact: bool,
) -> dict[str, bytearray]:
    values: dict[str, bytearray] = {}
    seen: set[str] = set()
    try:
        if 0 in raw or 13 in raw:
            raise ValueError
        start = 0
        while start < len(raw):
            end = raw.find(b"\n", start)
            if end < 0:
                end = len(raw)
            if end > start and raw[start] != 35:
                equals = raw.find(b"=", start, end)
                name_bytes = bytes(raw[start:equals]) if equals > start else b""
                if not _ascii_identifier(name_bytes):
                    raise ValueError
                name = name_bytes.decode("ascii")
                if name in seen or (exact and name not in selected):
                    raise ValueError
                seen.add(name)
                if name in selected:
                    first, last = _dotenv_value_range(raw, equals + 1, end)
                    values[name] = bytearray(raw[first:last])
                    if not values[name]:
                        raise ValueError
            start = end + 1
        if not required <= values.keys():
            raise ValueError
        return values
    except Exception:
        for value in values.values():
            _zeroize_mutable(value)
        raise ValueError from None


def _requester(raw: bytearray) -> V4PlanningPrincipal:
    value = json.loads(raw, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
    if type(value) is not dict or set(value) != {"requester", "transport_namespace_digest"}:
        raise ValueError
    member = value["requester"]
    if (type(member) is not dict or set(member) != {"subject_ref", "principal_class", "identity_authority_ref", "subject_namespace"}
            or any(type(item) is not str for item in member.values()) or member["principal_class"] != "operator"):
        raise ValueError
    return V4PlanningPrincipal(AuthenticatedRequester(**member), value["transport_namespace_digest"])


async def _sdk_authenticate(
    provider: LocalOAuthProvider, username: str, password: bytearray,
    identity: object, requester: V4PlanningPrincipal,
) -> dict[str, str]:
    from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings

    if not isinstance(identity, V4PlanningAuthorizationSettings):
        raise ValueError
    issuer = provider.settings.issuer
    parsed = urlsplit(issuer)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    transport = httpx.ASGITransport(app=Starlette(routes=provider.authorization_routes()))
    token = bytearray()
    client_id = ""
    async with httpx.AsyncClient(transport=transport, base_url=origin, follow_redirects=False, trust_env=False) as client:
        try:
            registered = await client.post(issuer + "/register", json={
                "client_name": "BP008 fixed private lab approver", "redirect_uris": [_REDIRECT],
                "token_endpoint_auth_method": "none", "grant_types": ["authorization_code"],
                "response_types": ["code"], "scope": V4_APPROVAL_SCOPE,
            })
            if registered.status_code != 201:
                raise ValueError
            client_id = registered.json().get("client_id")
            if type(client_id) is not str or not client_id:
                raise ValueError
            verifier = secrets.token_urlsafe(64)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
            state = secrets.token_urlsafe(32)
            authorized = await client.get(issuer + "/authorize", params={
                "response_type": "code", "client_id": client_id, "redirect_uri": _REDIRECT,
                "scope": V4_APPROVAL_SCOPE, "state": state, "code_challenge": challenge,
                "code_challenge_method": "S256", "resource": provider.settings.resource,
            })
            login_url = authorized.headers.get("location", "")
            location = urlsplit(login_url)
            if authorized.status_code != 302 or (location.scheme, location.netloc, location.path) != (parsed.scheme, parsed.netloc, provider.login_path):
                raise ValueError
            page = await client.get(login_url)
            hidden = {match.group("name"): match.group("value") for match in _HIDDEN.finditer(page.text)}
            if page.status_code != 200 or set(hidden) != {"request_id", "csrf_token"}:
                raise ValueError
            consent = await client.post(issuer + "/login", data={
                **hidden, "username": username, "password": password.decode("utf-8"), "action": "allow",
            }, headers={"Origin": origin})
            callback = urlsplit(consent.headers.get("location", ""))
            query = parse_qs(callback.query)
            if (consent.status_code != 302 or urlunsplit((callback.scheme, callback.netloc, callback.path, "", "")) != _REDIRECT
                    or query.get("state") != [state] or query.get("iss") != [issuer] or len(query.get("code", [])) != 1):
                raise ValueError
            exchanged = await client.post(issuer + "/token", data={
                "grant_type": "authorization_code", "client_id": client_id, "code": query["code"][0],
                "code_verifier": verifier, "redirect_uri": _REDIRECT, "resource": provider.settings.resource,
            })
            payload = exchanged.json()
            raw_token = payload.get("access_token")
            if type(raw_token) is str and raw_token:
                token.extend(raw_token.encode("utf-8"))
            if exchanged.status_code != 200 or not token or payload.get("scope") != V4_APPROVAL_SCOPE:
                raise ValueError
            loaded = await provider.load_access_token(token.decode("utf-8"))
            approver = approver_from_access_token(loaded, identity)
            current = requester.requester
            if (approver.identity_authority_ref != current.identity_authority_ref or approver.subject_namespace != current.subject_namespace
                    or approver.subject_ref == current.subject_ref or approver.identity_digest == current.identity_digest):
                raise ValueError
            return {"identity_authority_ref": cast(str, approver.identity_authority_ref),
                    "subject_namespace": cast(str, approver.subject_namespace), "subject_ref": approver.subject_ref}
        finally:
            try:
                if token:
                    revoked = await client.post(issuer + "/revoke", data={
                        "client_id": client_id, "client_secret": "", "token": token.decode("utf-8"),
                    })
                    remaining = await provider.load_access_token(token.decode("utf-8"))
                    if revoked.status_code != 200 or remaining is not None:
                        raise ValueError
            except Exception:
                # Cleanup through the same provider's public revocation method;
                # a failed SDK revocation still denies metadata/proof success.
                remaining = await provider.load_access_token(token.decode("utf-8"))
                if remaining is not None:
                    await provider.revoke_token(remaining)
                raise ValueError from None
            finally:
                _zeroize_mutable(token)


def _output_directory(path: Path) -> int:
    directory: int | None = None
    try:
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        current = os.fstat(directory)
        if current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o700:
            raise ValueError
        return directory
    except Exception:
        if directory is not None:
            os.close(directory)
        raise ValueError from None


def _write_metadata(directory: int, name: str, metadata: dict[str, str]) -> None:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    raw = bytearray(json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("ascii"))
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, memoryview(raw)[offset:])
            if count <= 0:
                raise ValueError
            offset += count
        os.fsync(descriptor)
    except Exception:
        os.unlink(name, dir_fd=directory)
        raise
    finally:
        os.close(descriptor)
        _zeroize_mutable(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("main-env-file", "requester-principal-file", "approver-login-file", "approver-output-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    arguments = parser.parse_args()
    try:
        proof = asyncio.run(authenticate_bp008_build29_lab_approver(
            arguments.main_env_file, arguments.requester_principal_file,
            arguments.approver_login_file, arguments.approver_output_file,
        ))
    except LabApproverAuthenticationError:
        print(_UNAVAILABLE)
        return 1
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
