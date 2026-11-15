#!/usr/bin/env python3
"""Exercise the V4 synthetic plan-only flow through real HTTPS MCP ingress.

This command intentionally never calls the inherited 28 device-read tools.
It is a release-acceptance capability only: using it against a deployed
candidate is a separate, operator-approved lab acceptance step.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import AsyncExitStack
import hashlib
import json
import os
from pathlib import Path
import secrets
import re
import stat
import time
from types import TracebackType
from typing import Any, Awaitable, Callable
from urllib.parse import SplitResult, parse_qs, urlencode, urlsplit, urlunsplit

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from fortipam_mcp.env import EnvironmentFileError, load_prefixed_environment_file
from fortipam_mcp.mcp_smoke import EXPECTED_TOOLS, V4_EXPECTED_TOOLS, V4_PLAN_TOOLS
from scripts.local_oauth_http_acceptance import (
    LOGIN_PASSWORD,
    LOGIN_PREFIX,
    LOGIN_USERNAME,
    LocalOAuthAcceptanceError,
    REDIRECT_URI,
    _initialize_payload,
    _locked_client_state,
    _read_client_id,
    _revocation_is_proven,
    _validate_client_id,
    _write_client_id,
)


MCP_PROTOCOL_VERSION = "2025-11-25"
PLANNING_SCOPE = "fortipam:plan"
READ_SCOPE = "fortipam:read"
_CSRF_INPUT = re.compile(r'name="csrf_token" value="([^"]+)"')
_RESTART_READY_PREFIX = "v4-restart-ready "
_RESTART_CONTINUE_PREFIX = "v4-restart-continue "
_RESTART_POLL_SECONDS = 0.25
_MIN_RESTART_TIMEOUT_SECONDS = 5
_MAX_RESTART_TIMEOUT_SECONDS = 1800
_RESTART_READINESS_TIMEOUT_SECONDS = 30
_RESTART_READINESS_POLL_SECONDS = 1.0


class V4HttpsOAuthAcceptanceError(RuntimeError):
    """Raised without retaining local login values, tokens, or client IDs."""


_MarkerFingerprint = tuple[int, int]


class RestartMarkerConfig:
    """Exact owner-only filesystem handshake for an operator-arranged restart."""

    def __init__(self, ready_path: Path, continue_path: Path, timeout_seconds: int) -> None:
        self.ready_path = ready_path
        self.continue_path = continue_path
        self.timeout_seconds = timeout_seconds


async def run_v4_https_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    ca_file: Path | None = None,
    *,
    restart_url: str | None = None,
    restart_ready_file: Path | None = None,
    restart_continue_file: Path | None = None,
    restart_timeout_seconds: int = 300,
) -> dict[str, object]:
    """Run OAuth, MCP plan-only, browser-confirmation, and revocation checks.

    ``restart_url`` is optional and must point to the same persisted synthetic
    host after an operator-arranged process restart.  The script never starts,
    stops, or restarts a service itself.
    """

    # Treat the explicit owner-only login file as the single credential source
    # for this run instead of inheriting possibly stale process values.
    load_prefixed_environment_file(
        login_file, LOGIN_PREFIX, overwrite=True,
        required_keys=(LOGIN_USERNAME, LOGIN_PASSWORD),
    )
    username = _required_login_value(LOGIN_USERNAME)
    password = _required_login_value(LOGIN_PASSWORD)
    parsed = _validate_https_mcp_url(url)
    restart_config = _restart_marker_config(
        restart_url,
        restart_ready_file,
        restart_continue_file,
        restart_timeout_seconds,
    )
    if restart_url is not None:
        restart = _validate_https_mcp_url(restart_url)
        if restart.path != parsed.path or restart.netloc != parsed.netloc:
            raise V4HttpsOAuthAcceptanceError(
                "The optional restart URL must use the same HTTPS MCP ingress."
            )
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    issuer = f"{origin}{parsed.path}/oauth"
    verify: str | bool = str(ca_file) if ca_file is not None else True
    access_token: str | None = None
    client_id: str | None = None
    client_registered_this_run = False
    client_reused = False

    async with httpx2.AsyncClient(
        timeout=30.0,
        follow_redirects=False,
        trust_env=False,
        verify=verify,
        headers={"User-Agent": "fortipam-mcp-v4-https-oauth-acceptance/1"},
    ) as browser_client:
        access_token, client_registered_this_run, client_reused, client_id = await _oauth_token(
            browser_client,
            url=url,
            origin=origin,
            issuer=issuer,
            username=username,
            password=password,
            client_state_file=client_state_file,
        )
        try:
            status, preview = await _status_and_preview(url, access_token, verify)
            confirmation_url = _confirmation_url(preview, origin)
            await _affirm_browser_confirmation(
                browser_client,
                confirmation_url,
                origin=origin,
                username=username,
                password=password,
            )
            confirmation, plan = await _confirm_and_prepare(
                url,
                access_token,
                verify,
                preview,
            )
            restarted = False
            restart_readiness_class = "not_requested"
            if restart_url is not None and restart_config is not None:
                restarted, restart_readiness_class = await _synchronized_restart_retry(
                    restart_url,
                    access_token,
                    verify,
                    preview,
                    confirmation,
                    plan,
                    restart_config,
                )
        finally:
            revocation_confirmed = await _revoke_and_prove_401(
                browser_client,
                url,
                issuer,
                access_token,
                client_id,
            )

    if not revocation_confirmed:
        raise V4HttpsOAuthAcceptanceError(
            "OAuth token revocation was not proven by a rejected MCP request."
        )
    return {
        "transport": "MCP Streamable HTTP over HTTPS",
        "authentication": "oauth_authorization_code_pkce_s256",
        "requested_scopes": [READ_SCOPE, PLANNING_SCOPE],
        "tool_count": len(V4_EXPECTED_TOOLS),
        "read_tool_count": len(EXPECTED_TOOLS),
        "planning_tool_count": len(V4_PLAN_TOOLS),
        "device_tool_calls": 0,
        "device_contacted": False,
        "synthetic_host_required": True,
        "no_device_status_accepted": bool(status),
        "browser_confirmation_get_reauth_affirm_accepted": True,
        "exact_origin_and_csrf_used": True,
        "confirmation_consumed": True,
        "prepared_plan_non_executable": True,
        "restart_recovery_retry_checked": restarted,
        "restart_readiness_class": restart_readiness_class,
        "token_revocation_accepted": True,
        "revoked_access_rejected": True,
        "dynamic_client_registration_performed": client_registered_this_run,
        "acceptance_client_reused": client_reused,
        "client_id_values_returned": False,
        "login_values_returned": False,
        "oauth_token_values_returned": False,
        "raw_device_response_bodies_returned": False,
    }


def _required_login_value(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise V4HttpsOAuthAcceptanceError("The local OAuth acceptance identity is unavailable.")
    return value


def _restart_marker_config(
    restart_url: str | None,
    ready_path: Path | None,
    continue_path: Path | None,
    timeout_seconds: int,
) -> RestartMarkerConfig | None:
    requested = (restart_url, ready_path, continue_path)
    if all(value is None for value in requested):
        return None
    if any(value is None for value in requested):
        raise V4HttpsOAuthAcceptanceError(
            "Restart recovery requires URL, ready marker, and continue marker together."
        )
    if type(timeout_seconds) is not int or not (
        _MIN_RESTART_TIMEOUT_SECONDS <= timeout_seconds <= _MAX_RESTART_TIMEOUT_SECONDS
    ):
        raise V4HttpsOAuthAcceptanceError("Restart marker timeout is outside the safe bound.")
    assert ready_path is not None and continue_path is not None
    config = RestartMarkerConfig(ready_path, continue_path, timeout_seconds)
    _validate_marker_paths(config)
    return config


def _validate_marker_paths(config: RestartMarkerConfig) -> None:
    if config.ready_path == config.continue_path:
        raise V4HttpsOAuthAcceptanceError("Restart marker paths must be distinct.")
    for path in (config.ready_path, config.continue_path):
        if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
            raise V4HttpsOAuthAcceptanceError("Restart marker paths must be exact absolute paths.")
        _assert_owner_only_marker_parent(path.parent)
        if path.exists() or path.is_symlink():
            _assert_owner_only_marker(path)
            raise V4HttpsOAuthAcceptanceError("Restart marker is stale and must be absent.")


def _assert_owner_only_marker_parent(path: Path) -> None:
    if not path.is_absolute():
        raise V4HttpsOAuthAcceptanceError("Restart marker parent is unsafe.")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise V4HttpsOAuthAcceptanceError("Restart marker parent is unavailable.") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise V4HttpsOAuthAcceptanceError("Restart marker parent is unsafe.")
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise V4HttpsOAuthAcceptanceError("Restart marker parent must be owner-only.")


def _assert_owner_only_marker(path: Path) -> _MarkerFingerprint:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise V4HttpsOAuthAcceptanceError("Restart marker is unavailable.") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise V4HttpsOAuthAcceptanceError("Restart marker is unsafe.")
    return (metadata.st_dev, metadata.st_ino)


def _create_ready_marker(path: Path) -> tuple[str, _MarkerFingerprint]:
    nonce = secrets.token_urlsafe(24)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, f"{_RESTART_READY_PREFIX}{nonce}\n".encode("ascii"))
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise V4HttpsOAuthAcceptanceError("Restart ready marker could not be created.") from exc
    return nonce, _assert_owner_only_marker(path)


async def _wait_for_continue_marker(
    path: Path,
    *,
    nonce: str,
    timeout_seconds: int,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> _MarkerFingerprint:
    deadline = monotonic() + timeout_seconds
    while monotonic() < deadline:
        if path.exists() or path.is_symlink():
            fingerprint = _assert_owner_only_marker(path)
            try:
                content = path.read_text(encoding="ascii")
            except OSError as exc:
                raise V4HttpsOAuthAcceptanceError("Restart continue marker is unavailable.") from exc
            if content != f"{_RESTART_CONTINUE_PREFIX}{nonce}\n":
                raise V4HttpsOAuthAcceptanceError("Restart continue marker is stale.")
            return fingerprint
        await sleep(min(_RESTART_POLL_SECONDS, max(0.01, deadline - monotonic())))
    raise V4HttpsOAuthAcceptanceError("Timed out waiting for the restart continue marker.")


def _cleanup_marker(path: Path, fingerprint: _MarkerFingerprint | None) -> None:
    if fingerprint is None:
        return
    try:
        current = _assert_owner_only_marker(path)
    except V4HttpsOAuthAcceptanceError:
        return
    if current != fingerprint:
        return
    try:
        path.unlink()
    except OSError:
        return


def _validate_https_mcp_url(url: str) -> SplitResult:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or not parsed.path
        or parsed.path.endswith("/")
        or parsed.query
        or parsed.fragment
    ):
        raise V4HttpsOAuthAcceptanceError("The V4 OAuth acceptance URL is invalid.")
    return parsed


async def _oauth_token(
    client: httpx2.AsyncClient,
    *,
    url: str,
    origin: str,
    issuer: str,
    username: str,
    password: str,
    client_state_file: Path,
    include_operation_scope: bool = False,
    require_existing_client: bool = False,
) -> tuple[str, bool, bool, str]:
    if type(include_operation_scope) is not bool or type(require_existing_client) is not bool:
        raise V4HttpsOAuthAcceptanceError("OAuth acceptance scope is invalid.")
    parsed = urlsplit(url)
    protected = f"{origin}/.well-known/oauth-protected-resource{parsed.path}"
    metadata = f"{origin}/.well-known/oauth-authorization-server{parsed.path}/oauth"
    if (await client.get(protected)).status_code != 200 or (await client.get(metadata)).status_code != 200:
        raise V4HttpsOAuthAcceptanceError("OAuth metadata acceptance failed.")
    registration_endpoint = f"{issuer}/register"
    authorization_endpoint = f"{issuer}/authorize"
    login_endpoint = f"{issuer}/login"
    token_endpoint = f"{issuer}/token"
    scope = f"{READ_SCOPE} {PLANNING_SCOPE}"
    if include_operation_scope:
        scope += " fortipam:operate"
    registered = False
    reused = False
    with _locked_client_state(client_state_file):
        client_id = _read_client_id(client_state_file)
        if client_id is None and require_existing_client:
            raise V4HttpsOAuthAcceptanceError("An existing OAuth client is required.")
        if client_id is None:
            registration = await client.post(
                registration_endpoint,
                json={
                    "client_name": "FortiPAM MCP V4 release acceptance",
                    "redirect_uris": [REDIRECT_URI],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                    "scope": scope,
                },
            )
            client_id = registration.json().get("client_id") if registration.status_code == 201 else None
            if not isinstance(client_id, str):
                raise V4HttpsOAuthAcceptanceError("OAuth client registration failed.")
            _validate_client_id(client_id)
            _write_client_id(client_state_file, client_id)
            registered = True
        else:
            reused = True
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    state = secrets.token_urlsafe(32)
    query = urlencode(
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
    authorization = await client.get(f"{authorization_endpoint}?{query}")
    if authorization.status_code != 302:
        raise V4HttpsOAuthAcceptanceError("OAuth authorization request failed.")
    login_url = authorization.headers.get("location", "")
    login_parts = urlsplit(login_url)
    if (
        urlunsplit((login_parts.scheme, login_parts.netloc, "", "", "")) != origin
        or login_parts.path != urlsplit(login_endpoint).path
    ):
        raise V4HttpsOAuthAcceptanceError("OAuth login redirect was invalid.")
    login_page = await client.get(login_url)
    hidden = _hidden_inputs(login_page.text, {"request_id", "csrf_token"})
    approved = await client.post(
        login_endpoint,
        data={**hidden, "username": username, "password": password, "action": "allow"},
        headers={"Origin": origin},
    )
    callback = urlsplit(approved.headers.get("location", ""))
    callback_query = parse_qs(callback.query)
    if (
        approved.status_code != 302
        or urlunsplit((callback.scheme, callback.netloc, callback.path, "", "")) != REDIRECT_URI
        or callback_query.get("state") != [state]
        or callback_query.get("iss") != [issuer]
        or len(callback_query.get("code", [])) != 1
    ):
        raise V4HttpsOAuthAcceptanceError("OAuth local login failed.")
    token_response = await client.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": callback_query["code"][0],
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
            "resource": url,
        },
    )
    token = token_response.json().get("access_token") if token_response.status_code == 200 else None
    if not isinstance(token, str) or not token:
        raise V4HttpsOAuthAcceptanceError("OAuth token exchange failed.")
    return token, registered, reused, client_id


async def _status_and_preview(
    url: str,
    token: str,
    verify: str | bool,
) -> tuple[dict[str, object], dict[str, object]]:
    async with _mcp_session(url, token, verify) as session:
        await session.initialize()
        listed = await session.list_tools()
        names = {tool.name for tool in listed.tools}
        if names != set(V4_EXPECTED_TOOLS) or len(names) != len(V4_EXPECTED_TOOLS):
            raise V4HttpsOAuthAcceptanceError("V4 ingress tool surface is not exactly 32 tools.")
        status = _structured(await session.call_tool("get_v4_plan_status", {}))
        _validate_status(status)
        refs = status.get("synthetic_scheme_draft_refs")
        if not isinstance(refs, list) or len(refs) != 1 or not isinstance(refs[0], str):
            raise V4HttpsOAuthAcceptanceError("Synthetic V4 Scheme reference is unavailable.")
        preview = _structured(
            await session.call_tool(
                "preview_v4_administrative_intent",
                {"scheme_draft_ref": refs[0]},
            )
        )
        _validate_preview(preview)
        return status, preview


class _McpSessionContext:
    def __init__(self, url: str, token: str, verify: str | bool, timeout_seconds: float = 30.0) -> None:
        # The associated User lifecycle waits for six independent 60-second
        # child windows plus preparation/readback. This is only a client wait;
        # server-side authorization expiry and one-shot dispatch stay unchanged.
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 480:
            raise V4HttpsOAuthAcceptanceError("MCP timeout is invalid.")
        self._timeout = timeout_seconds
        self._url = url
        self._token = token
        self._verify = verify
        self._exit_stack = AsyncExitStack()

    async def __aenter__(self) -> ClientSession:
        async with AsyncExitStack() as stack:
            http = httpx2.AsyncClient(
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
                verify=self._verify,
            )
            stack.push_async_callback(http.aclose)
            stream = streamable_http_client(
                self._url,
                http_client=http,
                terminate_on_close=False,
            )
            read_stream, write_stream = await stack.enter_async_context(stream)
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            self._exit_stack = stack.pop_all()
            return session

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self._exit_stack.__aexit__(exc_type, exc_value, traceback)


def _mcp_session(url: str, token: str, verify: str | bool, *,
                 timeout_seconds: float = 30.0) -> _McpSessionContext:
    return _McpSessionContext(url, token, verify, timeout_seconds)


def _structured(result: Any) -> dict[str, object]:
    if getattr(result, "is_error", True) or not isinstance(
        getattr(result, "structured_content", None), dict
    ):
        raise V4HttpsOAuthAcceptanceError("V4 MCP plan-only Tool call failed.")
    return dict(result.structured_content)


def _validate_status(status: dict[str, object]) -> None:
    if (
        status.get("runtime_profile") != "v4-plan-only"
        or status.get("device_access") is not False
        or status.get("product_write_enabled") is not False
        or status.get("dispatchable") is not False
        or status.get("host_services_bound") is not True
        or status.get("confirmation_transport_bound") is not True
    ):
        raise V4HttpsOAuthAcceptanceError("V4 no-device status contract is invalid.")


def _validate_preview(preview: dict[str, object]) -> None:
    if (
        preview.get("state") != "awaiting_confirmation"
        or preview.get("confirmation_state") != "awaiting_human_reauthentication"
        or not isinstance(preview.get("summary_ref"), str)
        or type(preview.get("revision")) is not int
        or not isinstance(preview.get("confirmation_url"), str)
    ):
        raise V4HttpsOAuthAcceptanceError("V4 intent preview contract is invalid.")


def _confirmation_url(preview: dict[str, object], origin: str) -> str:
    raw = preview["confirmation_url"]
    assert isinstance(raw, str)
    parsed = urlsplit(raw)
    if (
        urlunsplit((parsed.scheme, parsed.netloc, "", "", "")) != origin
        or not parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise V4HttpsOAuthAcceptanceError("V4 confirmation URL is invalid.")
    return raw


async def _affirm_browser_confirmation(
    client: httpx2.AsyncClient,
    confirmation_url: str,
    *,
    origin: str,
    username: str,
    password: str,
) -> None:
    page = await client.get(confirmation_url)
    if page.status_code != 200 or "Current / Proposed / Expected" in page.text:
        raise V4HttpsOAuthAcceptanceError("V4 confirmation reauthentication page is invalid.")
    csrf = _csrf(page.text)
    review = await client.post(
        confirmation_url,
        data={"csrf_token": csrf, "username": username, "password": password, "action": "review"},
        headers={"Origin": origin},
    )
    if review.status_code != 200 or "Current / Proposed / Expected" not in review.text:
        raise V4HttpsOAuthAcceptanceError("V4 confirmation reauthentication failed.")
    decision = await client.post(
        confirmation_url,
        data={"csrf_token": _csrf(review.text), "action": "affirm"},
        headers={"Origin": origin},
    )
    if decision.status_code != 200:
        raise V4HttpsOAuthAcceptanceError("V4 confirmation affirm failed.")


async def _confirm_and_prepare(
    url: str,
    token: str,
    verify: str | bool,
    preview: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    summary_ref = str(preview["summary_ref"])
    revision = _revision(preview)
    async with _mcp_session(url, token, verify) as session:
        await session.initialize()
        confirmation = _structured(
            await session.call_tool(
                "confirm_v4_administrative_intent",
                {"summary_ref": summary_ref, "summary_revision": revision},
            )
        )
        confirmation_ref = confirmation.get("confirmation_ref")
        if not isinstance(confirmation_ref, str):
            raise V4HttpsOAuthAcceptanceError("V4 confirmation consumption failed.")
        plan = _structured(
            await session.call_tool(
                "prepare_v4_non_executable_plan",
                {"summary_ref": summary_ref, "confirmation_ref": confirmation_ref},
            )
        )
        _validate_plan(plan)
        retry_confirmation = _structured(
            await session.call_tool(
                "confirm_v4_administrative_intent",
                {"summary_ref": summary_ref, "summary_revision": revision},
            )
        )
        retry_plan = _structured(
            await session.call_tool(
                "prepare_v4_non_executable_plan",
                {"summary_ref": summary_ref, "confirmation_ref": confirmation_ref},
            )
        )
        if retry_confirmation != confirmation or retry_plan != plan:
            raise V4HttpsOAuthAcceptanceError("V4 exact retry did not return immutable records.")
        return confirmation, plan


def _validate_plan(plan: dict[str, object]) -> None:
    if (
        plan.get("dispatchable") is not False
        or plan.get("adapter_registry_bound") is not False
        or plan.get("executor_runtime_packaged") is not False
        or plan.get("executor_mcp_exposed") is not False
        or plan.get("planner_mcp_exposed") is not True
        or not isinstance(plan.get("plan_ref"), str)
    ):
        raise V4HttpsOAuthAcceptanceError("V4 prepared plan widened an execution boundary.")


async def _verify_restart_retry(
    url: str,
    token: str,
    verify: str | bool,
    preview: dict[str, object],
    confirmation: dict[str, object],
    plan: dict[str, object],
) -> bool:
    summary_ref = str(preview["summary_ref"])
    revision = _revision(preview)
    confirmation_ref = str(confirmation["confirmation_ref"])
    async with _mcp_session(url, token, verify) as session:
        await session.initialize()
        retry_confirmation = _structured(
            await session.call_tool(
                "confirm_v4_administrative_intent",
                {"summary_ref": summary_ref, "summary_revision": revision},
            )
        )
        retry_plan = _structured(
            await session.call_tool(
                "prepare_v4_non_executable_plan",
                {"summary_ref": summary_ref, "confirmation_ref": confirmation_ref},
            )
        )
    return retry_confirmation == confirmation and retry_plan == plan


async def _synchronized_restart_retry(
    url: str,
    token: str,
    verify: str | bool,
    preview: dict[str, object],
    confirmation: dict[str, object],
    plan: dict[str, object],
    markers: RestartMarkerConfig,
    *,
    wait_for_continue: Callable[..., Awaitable[_MarkerFingerprint]] = _wait_for_continue_marker,
) -> tuple[bool, str]:
    """Wait for an operator's post-restart marker before retrying one chain."""

    _validate_marker_paths(markers)
    ready_fingerprint: _MarkerFingerprint | None = None
    continue_fingerprint: _MarkerFingerprint | None = None
    try:
        nonce, ready_fingerprint = _create_ready_marker(markers.ready_path)
        continue_fingerprint = await wait_for_continue(
            markers.continue_path,
            nonce=nonce,
            timeout_seconds=markers.timeout_seconds,
        )
        readiness_class = await _await_authorized_restart_readiness(
            url,
            token,
            verify,
        )
        retry_matches = await _verify_restart_retry(
            url,
            token,
            verify,
            preview,
            confirmation,
            plan,
        )
        if not retry_matches:
            raise V4HttpsOAuthAcceptanceError(
                "Restart retry returned a different confirmation or prepared plan."
            )
        return retry_matches, readiness_class
    finally:
        _cleanup_marker(markers.ready_path, ready_fingerprint)
        _cleanup_marker(markers.continue_path, continue_fingerprint)


async def _await_authorized_restart_readiness(
    url: str,
    token: str,
    verify: str | bool,
) -> str:
    """Wait only for a bounded startup/transport recovery window.

    This is deliberately a same-token MCP ``initialize`` request.  It does
    not inspect or retain response bodies, and does not call a Tool.  A token
    denial or other non-startup response fails immediately rather than being
    confused with service recovery.
    """

    async with httpx2.AsyncClient(
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
        verify=verify,
    ) as client:
        async def probe() -> int:
            response = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                },
                json=_initialize_payload(),
            )
            return response.status_code

        return await _poll_restart_readiness(probe)


def _restart_readiness_status_class(status_code: int) -> str:
    if 200 <= status_code < 300:
        return "ready"
    if status_code in {401, 403}:
        return "authorization_denied"
    if 500 <= status_code < 600:
        return "startup_unavailable"
    return "non_retryable_http"


async def _poll_restart_readiness(
    probe: Callable[[], Awaitable[int]],
    *,
    timeout_seconds: int = _RESTART_READINESS_TIMEOUT_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> str:
    """Poll only retryable startup/transport failures before immutable retry."""

    deadline = monotonic() + timeout_seconds
    had_retryable_failure = False
    while True:
        try:
            outcome = _restart_readiness_status_class(await probe())
        except httpx2.TransportError:
            outcome = "transport_unavailable"
        if outcome == "ready":
            return (
                "authorized_initialize_ready_after_retry"
                if had_retryable_failure
                else "authorized_initialize_ready"
            )
        if outcome == "authorization_denied":
            raise V4HttpsOAuthAcceptanceError(
                "Restart readiness authorization was rejected."
            )
        if outcome == "non_retryable_http":
            raise V4HttpsOAuthAcceptanceError(
                "Restart readiness received a non-retryable HTTP response."
            )
        if monotonic() >= deadline:
            raise V4HttpsOAuthAcceptanceError(
                "Timed out waiting for authorized restart readiness."
            )
        had_retryable_failure = True
        await sleep(
            min(
                _RESTART_READINESS_POLL_SECONDS,
                max(0.01, deadline - monotonic()),
            )
        )


async def _revoke_and_prove_401(
    client: httpx2.AsyncClient,
    url: str,
    issuer: str,
    token: str | None,
    client_id: str | None,
) -> bool:
    if not token or not client_id:
        return False
    # The client ID stays only in the owner-only state file and is intentionally
    # not returned, logged, or included in an exception.
    revoke = await client.post(
        f"{issuer}/revoke",
        data={"client_id": client_id, "client_secret": "", "token": token},
    )
    rejected = await client.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        },
        json=_initialize_payload(),
    )
    return _revocation_is_proven(revoke.status_code, rejected.status_code)


def _hidden_inputs(text: str, required: set[str]) -> dict[str, str]:
    pairs = re.findall(r'name="([^\"]+)" value="([^\"]+)"', text)
    required_pairs = [(name, value) for name, value in pairs if name in required]
    matches = dict(required_pairs)
    if set(matches) != required or len(matches) != len(required_pairs):
        raise V4HttpsOAuthAcceptanceError("OAuth form was invalid.")
    return matches


def _csrf(text: str) -> str:
    match = _CSRF_INPUT.search(text)
    if match is None:
        raise V4HttpsOAuthAcceptanceError("V4 confirmation CSRF field is unavailable.")
    return match.group(1)


def _revision(preview: dict[str, object]) -> int:
    value = preview.get("revision")
    if type(value) is not int or value < 1:
        raise V4HttpsOAuthAcceptanceError("V4 intent preview revision is invalid.")
    return value


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Run V4 HTTPS/local-OAuth plan-only ingress acceptance."
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument(
        "--restart-url",
        help="Same ingress after an operator-arranged restart; requires both marker paths.",
    )
    parser.add_argument(
        "--restart-ready-file",
        type=Path,
        help="Absent owner-only absolute marker created before the operator restart.",
    )
    parser.add_argument(
        "--restart-continue-file",
        type=Path,
        help=(
            "Absent owner-only absolute marker the operator creates after restart; "
            "copy the nonce from the ready marker using the documented prefix."
        ),
    )
    parser.add_argument(
        "--restart-timeout-seconds",
        type=int,
        default=300,
        help="Bounded operator synchronization wait (5-1800 seconds).",
    )
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(
            run_v4_https_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                args.ca_file,
                restart_url=args.restart_url,
                restart_ready_file=args.restart_ready_file,
                restart_continue_file=args.restart_continue_file,
                restart_timeout_seconds=args.restart_timeout_seconds,
            )
        )
    except (EnvironmentFileError, LocalOAuthAcceptanceError, V4HttpsOAuthAcceptanceError, ValueError) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
