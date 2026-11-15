#!/usr/bin/env python3
"""Verify the V4 Address MCP surface through local OAuth over HTTPS.

Without preview arguments this stops after MCP initialization and ``tools/list``.
With a complete preview tuple it calls only the non-mutating Address preview
Tool and stores its opaque reference in an owner-only state file.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from collections.abc import Awaitable, Callable
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fortipam_mcp import __version__
from fortipam_mcp.env import EnvironmentFileError, load_prefixed_environment_file
from scripts.local_oauth_http_acceptance import (
    CLIENT_STATE_KEY,
    LOGIN_PASSWORD,
    LOGIN_PREFIX,
    LOGIN_USERNAME,
    REDIRECT_URI,
    _HIDDEN_INPUT,
    _locked_client_state,
    _read_client_id,
    _validate_client_id,
    _write_client_id,
)


ADDRESS_TOOLS = frozenset(
    {
        "preview_v4_ipv4_address_create",
        "confirm_v4_ipv4_address_create",
        "execute_confirmed_v4_ipv4_address_create",
    }
)
_SCOPE = "fortipam:read fortipam:plan fortipam:operate"
PLAN_ONLY_SCOPE = "fortipam:read fortipam:plan"
_ALLOWED_SCOPES = frozenset({_SCOPE, PLAN_ONLY_SCOPE})
_REGISTRATION_ERROR_CODES = frozenset(
    {
        "access_denied",
        "invalid_client_metadata",
        "invalid_client",
        "invalid_redirect_uri",
        "invalid_request",
        "invalid_scope",
        "invalid_software_statement",
        "server_error",
    }
)


class AddressMcpOAuthSurfaceAcceptanceError(RuntimeError):
    """Raised when the narrow HTTPS OAuth/MCP surface contract fails."""


def _registration_failure_reason(status_code: int, payload: object) -> str:
    """Return a bounded OAuth registration failure category without response data."""

    category = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(category, str) and category in _REGISTRATION_ERROR_CODES:
        return f"http_{status_code}:{category}"
    return f"http_{status_code}:unclassified"


def _authorization_error_category(location: str) -> str | None:
    """Recognize only a bounded OAuth error callback without returning its data."""

    parsed = urlsplit(location)
    if urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")) != REDIRECT_URI:
        return None
    values = parse_qs(parsed.query)
    category = values.get("error")
    if (
        not isinstance(category, list)
        or len(category) != 1
        or category[0] not in _REGISTRATION_ERROR_CODES
    ):
        return None
    return category[0]


def _contained_acceptance_error_message(
    error: BaseExceptionGroup,
) -> str | None:
    """Return a bounded nested acceptance failure without a task-group trace."""

    for nested in error.exceptions:
        if isinstance(nested, AddressMcpOAuthSurfaceAcceptanceError):
            return str(nested)
        if isinstance(nested, BaseExceptionGroup):
            message = _contained_acceptance_error_message(nested)
            if message is not None:
                return message
    return None


async def run_address_mcp_oauth_surface_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_name: str | None = None,
    preview_cidr: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    tool_session_callback: Callable[[ClientSession], Awaitable[None]] | None = None,
    required_tools: frozenset[str] | None = None,
    requested_scope: str = _SCOPE,
    allow_insecure_private_ip_lab: bool = False,
    lab_connect_host: str | None = None,
    lab_connect_port: int | None = None,
    allow_loopback_tunnel: bool = False,
    mcp_read_timeout_seconds: int = 30,
) -> dict[str, object]:
    """Acquire one token, list only the Address Tool surface, then revoke it."""

    if type(mcp_read_timeout_seconds) is not int or not 30 <= mcp_read_timeout_seconds <= 300:
        raise AddressMcpOAuthSurfaceAcceptanceError("MCP read timeout must be 30 to 300 seconds.")
    expected_tools = ADDRESS_TOOLS if required_tools is None else required_tools
    if not expected_tools or any(not isinstance(tool, str) or not tool for tool in expected_tools):
        raise AddressMcpOAuthSurfaceAcceptanceError("Required MCP Tools are invalid.")
    scope = _validated_scope(requested_scope)

    # The caller-selected owner-only file must beat stale exported values from
    # an earlier acceptance run or interactive shell.
    load_prefixed_environment_file(
        login_file, LOGIN_PREFIX, overwrite=True,
        required_keys=(LOGIN_USERNAME, LOGIN_PASSWORD),
    )
    username = os.environ.get(LOGIN_USERNAME)
    password = os.environ.get(LOGIN_PASSWORD)
    if not username or not password:
        raise AddressMcpOAuthSurfaceAcceptanceError("OAuth login identity is unavailable.")

    parsed = urlsplit(url)
    if (
        not _accepted_scheme(
            parsed,
            allow_insecure_private_ip_lab,
            lab_connect_host,
        )
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.path.rstrip("/")
    ):
        raise AddressMcpOAuthSurfaceAcceptanceError("Acceptance URL is invalid.")
    path = parsed.path.rstrip("/")
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    connection_origin = _connection_origin(
        parsed,
        allow_insecure_private_ip_lab=allow_insecure_private_ip_lab,
        lab_connect_host=lab_connect_host,
        lab_connect_port=lab_connect_port,
        allow_loopback_tunnel=allow_loopback_tunnel,
    )
    connection_headers = {"Host": parsed.netloc} if connection_origin != origin else {}
    issuer = f"{origin}{path}/oauth"
    protected_metadata = f"{origin}/.well-known/oauth-protected-resource{path}"
    authorization_metadata = f"{origin}/.well-known/oauth-authorization-server{path}/oauth"
    verify: str | bool = str(ca_file) if ca_file is not None else True
    connection_transport = _connection_transport(
        parsed,
        lab_connect_host,
        verify,
        lab_connect_port=lab_connect_port,
        allow_loopback_tunnel=allow_loopback_tunnel,
    )
    access_token: str | None = None
    client_registered_this_run = False
    client_reused = False
    preview_verified = False
    execution_verified = False
    if execute_preview_state_file is not None and any(
        value is not None for value in (preview_name, preview_cidr, preview_state_file)
    ):
        raise AddressMcpOAuthSurfaceAcceptanceError(
            "Address preview and execution inputs cannot be combined."
        )

    async with httpx2.AsyncClient(
        timeout=30.0,
        follow_redirects=False,
        trust_env=False,
        verify=verify,
        headers={
            "User-Agent": "fortipam-mcp-v4-address-surface-acceptance/1",
            **connection_headers,
        },
        transport=connection_transport,
    ) as client:
        if (
            (await client.get(_connection_url(protected_metadata, origin, connection_origin))).status_code != 200
            or (await client.get(_connection_url(authorization_metadata, origin, connection_origin))).status_code != 200
        ):
            raise AddressMcpOAuthSurfaceAcceptanceError("OAuth metadata is unavailable.")

        with _locked_client_state(client_state_file):
            client_id = _read_client_id(client_state_file)
            if client_id is None:
                registered = await client.post(
                    _connection_url(f"{issuer}/register", origin, connection_origin),
                    json={
                        "client_name": "FortiPAM MCP V4 Address surface acceptance",
                        "redirect_uris": [REDIRECT_URI],
                        "token_endpoint_auth_method": "none",
                        "grant_types": ["authorization_code"],
                        "response_types": ["code"],
                        "scope": scope,
                    },
                )
                if registered.status_code != 201:
                    try:
                        payload = registered.json()
                    except (ValueError, TypeError):
                        payload = None
                    reason = _registration_failure_reason(registered.status_code, payload)
                    raise AddressMcpOAuthSurfaceAcceptanceError(
                        f"OAuth client registration failed ({reason})."
                    )
                candidate = registered.json().get("client_id")
                if not isinstance(candidate, str):
                    raise AddressMcpOAuthSurfaceAcceptanceError("OAuth client registration was invalid.")
                _validate_client_id(candidate)
                _write_client_id(client_state_file, candidate)
                client_id = candidate
                client_registered_this_run = True
            else:
                client_reused = True

        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")
        state = secrets.token_urlsafe(32)
        authorization = await client.get(
            _connection_url(f"{issuer}/authorize?"
            + urlencode(
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
            ), origin, connection_origin)
        )
        if authorization.status_code != 302:
            raise AddressMcpOAuthSurfaceAcceptanceError(
                f"OAuth authorization failed (http_{authorization.status_code})."
            )
        login_url = authorization.headers.get("location", "")
        login = urlsplit(login_url)
        if (
            urlunsplit((login.scheme, login.netloc, "", "", "")) != origin
            or login.path != f"{path}/oauth/login"
        ):
            category = _authorization_error_category(login_url)
            if category is not None:
                raise AddressMcpOAuthSurfaceAcceptanceError(
                    f"OAuth authorization rejected ({category})."
                )
            raise AddressMcpOAuthSurfaceAcceptanceError("OAuth login redirect was invalid.")
        login_page = await client.get(_connection_url(login_url, origin, connection_origin))
        hidden = {
            match.group("name"): match.group("value")
            for match in _HIDDEN_INPUT.finditer(login_page.text)
        }
        if login_page.status_code != 200 or set(hidden) != {"request_id", "csrf_token"}:
            raise AddressMcpOAuthSurfaceAcceptanceError("OAuth login form was invalid.")
        approved = await client.post(
            _connection_url(f"{issuer}/login", origin, connection_origin),
            data={**hidden, "username": username, "password": password, "action": "allow"},
            headers={"Origin": origin},
        )
        callback = urlsplit(approved.headers.get("location", ""))
        query = parse_qs(callback.query)
        if approved.status_code != 302:
            raise AddressMcpOAuthSurfaceAcceptanceError(
                f"OAuth local login response was rejected (http_{approved.status_code})."
            )
        if (
            urlunsplit((callback.scheme, callback.netloc, callback.path, "", ""))
            != REDIRECT_URI
            or query.get("state") != [state]
            or query.get("iss") != [issuer]
            or len(query.get("code", [])) != 1
        ):
            raise AddressMcpOAuthSurfaceAcceptanceError(
                "OAuth local login callback was invalid."
            )
        token_response = await client.post(
            _connection_url(f"{issuer}/token", origin, connection_origin),
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": query["code"][0],
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
                "resource": url,
            },
        )
        access_token = token_response.json().get("access_token") if token_response.status_code == 200 else None
        if not isinstance(access_token, str) or not access_token:
            raise AddressMcpOAuthSurfaceAcceptanceError("OAuth token exchange failed.")

        try:
            async with httpx2.AsyncClient(
                headers={"Authorization": f"Bearer {access_token}", **connection_headers},
                # Bound long fixed read preflights without changing OAuth,
                # connection/write timeouts or introducing dispatch retries.
                timeout=httpx2.Timeout(30.0, read=float(mcp_read_timeout_seconds)),
                follow_redirects=False,
                trust_env=False,
                verify=verify,
                transport=_connection_transport(
                    parsed,
                    lab_connect_host,
                    verify,
                    lab_connect_port=lab_connect_port,
                    allow_loopback_tunnel=allow_loopback_tunnel,
                ),
            ) as mcp_client:
                async with streamable_http_client(
                    _connection_url(url, origin, connection_origin),
                    http_client=mcp_client,
                    terminate_on_close=False,
                ) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        initialized = await session.initialize()
                        if initialized.server_info.version != __version__:
                            raise AddressMcpOAuthSurfaceAcceptanceError(
                                "MCP server version differs from the candidate release."
                            )
                        names = {tool.name for tool in (await session.list_tools()).tools}
                        if not expected_tools <= names:
                            raise AddressMcpOAuthSurfaceAcceptanceError(
                                "Address MCP Tool surface is incomplete."
                            )
                        if tool_session_callback is not None:
                            await tool_session_callback(session)
                        if any(
                            value is not None
                            for value in (preview_name, preview_cidr, preview_state_file)
                        ):
                            if not isinstance(preview_name, str) or not isinstance(
                                preview_cidr, str
                            ) or preview_state_file is None:
                                raise AddressMcpOAuthSurfaceAcceptanceError(
                                    "Address preview inputs are incomplete."
                                )
                            preview = await session.call_tool(
                                "preview_v4_ipv4_address_create",
                                {"name": preview_name, "cidr": preview_cidr},
                            )
                            projection = preview.structured_content
                            if preview.is_error or not isinstance(projection, dict):
                                raise AddressMcpOAuthSurfaceAcceptanceError(
                                    "Address MCP preview failed."
                                )
                            current = projection.get("Current State")
                            proposed = projection.get("Proposed Changes")
                            expected = projection.get("Expected State")
                            preview_ref = projection.get("preview_ref")
                            if (
                                not isinstance(current, dict)
                                or not isinstance(proposed, dict)
                                or not isinstance(expected, dict)
                                or not isinstance(preview_ref, str)
                                or projection.get("contract")
                                != "fortipam_v4_address_create_api_workflow_v1"
                                or projection.get("device_write_executed") is not False
                                or current.get("address_exists") is not False
                                or current.get("requested_address_name") != preview_name
                                or current.get("requested_ipv4_cidr") != preview_cidr
                                or proposed.get("address_name") != preview_name
                                or proposed.get("ipv4_cidr") != preview_cidr
                                or expected.get("address_exists") is not True
                                or expected.get("address_name_matches") is not True
                                or expected.get("address_type_matches") is not True
                                or expected.get("ipv4_cidr_matches") is not True
                            ):
                                raise AddressMcpOAuthSurfaceAcceptanceError(
                                    "Address MCP preview projection was invalid."
                                )
                            _write_preview_state(
                                preview_state_file,
                                preview_ref=preview_ref,
                                name=preview_name,
                                cidr=preview_cidr,
                            )
                            preview_verified = True
                        if execute_preview_state_file is not None:
                            preview_ref = _read_preview_ref(execute_preview_state_file)
                            confirmation = await session.call_tool(
                                "confirm_v4_ipv4_address_create",
                                {"preview_ref": preview_ref},
                            )
                            confirmed = confirmation.structured_content
                            authorization_ref = (
                                confirmed.get("authorization_ref")
                                if isinstance(confirmed, dict)
                                else None
                            )
                            if (
                                confirmation.is_error
                                or not isinstance(authorization_ref, str)
                                or not authorization_ref.startswith("address-authorized-")
                                or confirmed.get("contract")
                                != "fortipam_v4_address_create_api_workflow_v1"
                                or confirmed.get("confirmation") != "recorded"
                                or confirmed.get("execution") != "authorized_once"
                                or confirmed.get("device_write_executed") is not False
                            ):
                                raise AddressMcpOAuthSurfaceAcceptanceError(
                                    "Address MCP confirmation failed."
                                )
                            execution = await session.call_tool(
                                "execute_confirmed_v4_ipv4_address_create",
                                {"authorization_ref": authorization_ref},
                            )
                            result = execution.structured_content
                            if (
                                execution.is_error
                                or not isinstance(result, dict)
                                or result.get("contract")
                                != "fortipam_v4_address_create_api_execution_v1"
                                or result.get("outcome") != "succeeded"
                                or result.get("verification") != "verified"
                                or result.get("idempotent_replay") is not False
                                or result.get("address_name_returned") is not False
                                or result.get("cidr_returned") is not False
                                or result.get("raw_api_response_returned") is not False
                            ):
                                raise AddressMcpOAuthSurfaceAcceptanceError(
                                    "Address MCP execution readback failed."
                                )
                            execute_preview_state_file.unlink()
                            execution_verified = True
        finally:
            revoked = await client.post(
                _connection_url(f"{issuer}/revoke", origin, connection_origin),
                data={"client_id": client_id, "client_secret": "", "token": access_token},
            )
            if revoked.status_code != 200:
                raise AddressMcpOAuthSurfaceAcceptanceError("OAuth token revocation failed.")

    return {
        "contract": "fortipam_v4_address_mcp_oauth_surface_acceptance_v1",
        "oauth_metadata_verified": True,
        "client_registered_this_run": client_registered_this_run,
        "client_reused": client_reused,
        "mcp_initialized": True,
        "address_tool_surface_complete": True,
        "address_preview_verified": preview_verified,
        "address_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": True,
        "credential_values_returned": False,
        "token_returned": False,
        "client_id_returned": False,
    }


def _validated_scope(value: str) -> str:
    if type(value) is not str or value not in _ALLOWED_SCOPES:
        raise AddressMcpOAuthSurfaceAcceptanceError(
            "Requested OAuth scope is invalid."
        )
    return value


def _accepted_scheme(
    parsed: object,
    allow_insecure_private_ip_lab: bool,
    lab_connect_host: str | None = None,
) -> bool:
    """Permit HTTP only for an explicit private-IP laboratory connection."""

    scheme = getattr(parsed, "scheme", None)
    hostname = getattr(parsed, "hostname", None)
    port = getattr(parsed, "port", None)
    if scheme == "https":
        return True
    if not allow_insecure_private_ip_lab or scheme != "http" or not hostname or port:
        return False
    return _is_private_lab_host(hostname) or (
        isinstance(lab_connect_host, str)
        and _is_private_lab_host(lab_connect_host)
    )


def _connection_origin(
    parsed: object,
    *,
    allow_insecure_private_ip_lab: bool,
    lab_connect_host: str | None,
    lab_connect_port: int | None = None,
    allow_loopback_tunnel: bool = False,
) -> str:
    """Select an opt-in private connection origin without changing resource ID."""

    scheme = getattr(parsed, "scheme", None)
    hostname = getattr(parsed, "hostname", None)
    netloc = getattr(parsed, "netloc", None)
    if not isinstance(scheme, str) or not isinstance(netloc, str):
        raise AddressMcpOAuthSurfaceAcceptanceError("Acceptance URL is invalid.")
    if lab_connect_host is None:
        if lab_connect_port is not None:
            raise AddressMcpOAuthSurfaceAcceptanceError("Acceptance URL is invalid.")
        return urlunsplit((scheme, netloc, "", "", ""))
    if (
        allow_insecure_private_ip_lab
        and allow_loopback_tunnel
        and scheme == "http"
        and isinstance(hostname, str)
        and _is_private_lab_host(hostname)
        and lab_connect_host == "127.0.0.1"
        and type(lab_connect_port) is int
        and 1 <= lab_connect_port <= 65_535
    ):
        return f"http://127.0.0.1:{lab_connect_port}"
    if lab_connect_port is not None and scheme != "https":
        raise AddressMcpOAuthSurfaceAcceptanceError("Acceptance URL is invalid.")
    if (
        scheme == "https"
        and isinstance(hostname, str)
        and not _is_private_lab_host(hostname)
        and _accepted_connect_host(lab_connect_host, allow_loopback_tunnel)
    ):
        return urlunsplit((scheme, netloc, "", "", ""))
    if (
        not allow_insecure_private_ip_lab
        or scheme != "http"
        or not isinstance(hostname, str)
        or _is_private_lab_host(hostname)
        or not _is_private_lab_host(lab_connect_host)
    ):
        raise AddressMcpOAuthSurfaceAcceptanceError("Acceptance URL is invalid.")
    return f"http://{lab_connect_host}"


class _StaticHostNetworkBackend:
    """Connect one validated HTTPS origin to its fixed laboratory IPv4 address.

    The request origin remains the logical hostname, so httpcore supplies that
    hostname for both TLS SNI and certificate verification.  Only TCP dialing
    is pinned to the supplied private address.
    """

    def __init__(
        self,
        delegate: Any,
        logical_host: str,
        connect_host: str,
        connect_port: int | None = None,
    ) -> None:
        self._delegate = delegate
        self._logical_host = logical_host.lower()
        self._connect_host = connect_host
        self._connect_port = connect_port

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> Any:
        return await self._delegate.connect_tcp(
            self._connect_host if host.lower() == self._logical_host else host,
            self._connect_port
            if host.lower() == self._logical_host and self._connect_port is not None
            else port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> Any:
        return await self._delegate.connect_unix_socket(
            path,
            timeout=timeout,
            socket_options=socket_options,
        )

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


def _connection_transport(
    parsed: object,
    lab_connect_host: str | None,
    verify: str | bool,
    *,
    lab_connect_port: int | None = None,
    allow_loopback_tunnel: bool = False,
) -> httpx2.AsyncBaseTransport | None:
    """Build strict-TLS transport for an opt-in logical-host lab connection."""

    if lab_connect_host is None:
        if lab_connect_port is not None:
            raise AddressMcpOAuthSurfaceAcceptanceError("Acceptance URL is invalid.")
        return None
    scheme = getattr(parsed, "scheme", None)
    hostname = getattr(parsed, "hostname", None)
    if scheme != "https":
        return None
    if (
        not isinstance(hostname, str)
        or _is_private_lab_host(hostname)
        or not _accepted_connect_host(lab_connect_host, allow_loopback_tunnel)
    ):
        raise AddressMcpOAuthSurfaceAcceptanceError("Acceptance URL is invalid.")
    if lab_connect_port is not None and (
        not allow_loopback_tunnel
        or lab_connect_host != "127.0.0.1"
        or type(lab_connect_port) is not int
        or not 1 <= lab_connect_port <= 65_535
    ):
        raise AddressMcpOAuthSurfaceAcceptanceError("Acceptance URL is invalid.")
    transport = httpx2.AsyncHTTPTransport(verify=verify, trust_env=False)
    pool = getattr(transport, "_pool", None)
    backend = getattr(pool, "_network_backend", None)
    if pool is None or backend is None:
        raise AddressMcpOAuthSurfaceAcceptanceError(
            "HTTPS laboratory connection override is unavailable."
        )
    setattr(
        pool,
        "_network_backend",
        _StaticHostNetworkBackend(
            backend,
            hostname,
            lab_connect_host,
            lab_connect_port,
        ),
    )
    return transport


def _connection_url(raw: str, origin: str, connection_origin: str) -> str:
    """Map a validated logical-origin URL to its optional private connection."""

    parsed = urlsplit(raw)
    raw_origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    if raw_origin != origin:
        raise AddressMcpOAuthSurfaceAcceptanceError("OAuth redirect was invalid.")
    connected = urlsplit(connection_origin)
    return urlunsplit(
        (connected.scheme, connected.netloc, parsed.path, parsed.query, parsed.fragment)
    )


def _is_private_lab_host(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and address in ipaddress.ip_network((0x0A000000, 8))


def _accepted_connect_host(value: str, allow_loopback_tunnel: bool) -> bool:
    """Accept a private lab host or an explicit local SSH-tunnel endpoint."""

    return _is_private_lab_host(value) or (
        allow_loopback_tunnel and value == "127.0.0.1"
    )


def _write_preview_state(path: Path, *, preview_ref: str, name: str, cidr: str) -> None:
    """Persist one opaque preview reference without any OAuth credential."""

    if path.parent.is_symlink() or not path.parent.is_dir():
        raise AddressMcpOAuthSurfaceAcceptanceError("Preview state directory is invalid.")
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise AddressMcpOAuthSurfaceAcceptanceError("Preview state directory must be owner-only.")
    if path.exists() or path.is_symlink():
        raise AddressMcpOAuthSurfaceAcceptanceError("Preview state file already exists.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(
            descriptor,
            json.dumps(
                {"preview_ref": preview_ref, "name": name, "cidr": cidr},
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    """Read one owner-only opaque preview reference for confirmed execution."""

    if path.is_symlink() or not path.is_file():
        raise AddressMcpOAuthSurfaceAcceptanceError("Preview state file is invalid.")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise AddressMcpOAuthSurfaceAcceptanceError("Preview state file must be owner-only.")
    try:
        projection = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AddressMcpOAuthSurfaceAcceptanceError("Preview state file is invalid.") from exc
    preview_ref = projection.get("preview_ref") if isinstance(projection, dict) else None
    if not isinstance(preview_ref, str) or not preview_ref.startswith("address-preview-"):
        raise AddressMcpOAuthSurfaceAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-name")
    parser.add_argument("--preview-cidr")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument(
        "--allow-insecure-private-ip-lab",
        action="store_true",
        help="Allow HTTP only for the explicit private-IP laboratory exception.",
    )
    parser.add_argument("--lab-connect-host")
    parser.add_argument(
        "--allow-loopback-tunnel",
        action="store_true",
        help="Allow an explicit strict-TLS SSH tunnel at 127.0.0.1 only.",
    )
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_address_mcp_oauth_surface_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_name=args.preview_name,
                preview_cidr=args.preview_cidr,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
                allow_insecure_private_ip_lab=(
                    args.allow_insecure_private_ip_lab
                ),
                lab_connect_host=args.lab_connect_host,
                allow_loopback_tunnel=args.allow_loopback_tunnel,
            )
        )
    except (AddressMcpOAuthSurfaceAcceptanceError, EnvironmentFileError, ValueError) as exc:
        raise SystemExit(str(exc)) from None
    except BaseExceptionGroup as exc:
        message = _contained_acceptance_error_message(exc)
        if message is not None:
            raise SystemExit(message) from None
        raise
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
