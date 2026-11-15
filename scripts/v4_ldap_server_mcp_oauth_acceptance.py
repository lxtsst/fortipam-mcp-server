#!/usr/bin/env python3
"""Accept one privately bound LDAP creation through HTTPS OAuth/MCP.

Connections occur only when this client is explicitly invoked. The disposable
LDAP object remains for separate owner-gated recovery. Retain every dispatch
marker: an uncertain or consumed request must never be submitted again.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any
from urllib.parse import urlunsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    while str(root) in sys.path:
        sys.path.remove(str(root))
    sys.path.insert(0, str(root))

import httpx2
from fortipam_mcp.env import load_prefixed_environment_file
from scripts import v4_https_oauth_acceptance as oauth
from scripts.local_oauth_http_acceptance import LOGIN_PASSWORD, LOGIN_PREFIX, LOGIN_USERNAME

CONTRACT = "fortipam-700-build29-ldap-create-private-v1"
PREVIEW_TOOL = "preview_v4_ldap_server_create_700"
AUTHORIZE_TOOL = "authorize_v4_ldap_server_create_700"
EXECUTE_TOOL = "execute_v4_ldap_server_create_700"
TOOLS = frozenset({PREVIEW_TOOL, AUTHORIZE_TOOL, EXECUTE_TOOL})
DISPATCH_CONTRACT = "fortipam_v4_ldap_server_dispatch_v1"


class LdapServerMcpOAuthAcceptanceError(RuntimeError):
    """Categorical failure without credentials, raw results or private refs."""


def _require(condition: bool) -> None:
    if not condition:
        raise LdapServerMcpOAuthAcceptanceError("LDAP acceptance contract rejected.")


def _exact(value: Any, expected: dict[str, object]) -> None:
    _require(type(value) is dict and set(value) == set(expected))
    for key, item in expected.items():
        if isinstance(item, dict):
            _exact(value[key], item)
        else:
            _require(type(value[key]) is type(item) and value[key] == item)


def _body(reply: Any) -> dict[str, Any]:
    _require(getattr(reply, "is_error", True) is False)
    body = getattr(reply, "structured_content", None)
    _require(type(body) is dict)
    assert isinstance(body, dict)
    return body


def _reference(value: Any, prefix: str) -> None:
    _require(type(value) is str and re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}", value) is not None)


def _fresh(expires: Any) -> None:
    now = time.time()
    _require(type(expires) is int and now < expires <= now + 60)


def _validate_preview(body: dict[str, Any]) -> None:
    _reference(body.get("preview_ref"), "ldap-preview-")
    _fresh(body.get("expires_at"))
    _exact(body, {
        "contract": CONTRACT, "policy_mode": "lab_auto",
        "preview_ref": body["preview_ref"], "expires_at": body["expires_at"],
        "Current State": {"bound_entry_absent": True, "schema_defaults_qualified": True, "pinned_ca_verified": True},
        "Proposed Changes": {"operation": "create_ldap_server", "scope": "privately_bound_lab_fixture",
            "secure": "ldaps", "port": 636, "server_identity_check": True},
        "Expected State": {"exact_owned_entry_verified": True, "existing_entries_preserved": True},
        "device_write_executed": False,
    })


def _validate_authorization(body: dict[str, Any], preview: dict[str, Any]) -> None:
    _reference(body.get("authorization_ref"), "ldap-auth-")
    _fresh(body.get("expires_at"))
    _exact(body, {"contract": CONTRACT, "policy_mode": "lab_auto",
                  "authorization_ref": body["authorization_ref"], "expires_at": preview["expires_at"]})


def _validate_execution(body: dict[str, Any]) -> None:
    _exact(body, {"contract": CONTRACT, "outcome": "succeeded", "verification": "verified",
                  "compensation": "not_requested", "idempotent_replay": False})


def _protected_parent(path: Path) -> None:
    _require(path.is_absolute() and not any(part.is_symlink() for part in (path, *path.parents)))
    metadata = path.parent.stat()
    _require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077)


def _new_dispatch_path(path: Path) -> None:
    _protected_parent(path)
    _require(not path.exists())


def _reserve_dispatch(path: Path) -> None:
    _new_dispatch_path(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(parent)
        _require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077)
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({"contract": DISPATCH_CONTRACT, "dispatch_reserved": True, "retry_allowed": False}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        # A partial marker is retained if writing or either fsync fails.
        os.close(parent)


async def run_ldap_server_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, dispatch_state_file: Path,
    *, ca_file: Path | None = None,
) -> dict[str, object]:
    attempted, revoked = False, False
    phase = "preflight"
    try:
        _new_dispatch_path(dispatch_state_file)
        for path in (login_file, client_state_file):
            _protected_parent(path)
            if path.exists():
                metadata = path.stat()
                _require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077)
        _require(len({path.resolve() for path in (login_file, client_state_file, dispatch_state_file)}) == 3)
        parsed = oauth._validate_https_mcp_url(url)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        issuer = f"{origin}{parsed.path}/oauth"
        load_prefixed_environment_file(login_file, LOGIN_PREFIX, overwrite=True,
            required_keys=(LOGIN_USERNAME, LOGIN_PASSWORD))
        verify: str | bool = str(ca_file) if ca_file is not None else True
        async with httpx2.AsyncClient(timeout=30.0, follow_redirects=False, trust_env=False, verify=verify) as client:
            phase = "oauth"
            token, _, _, client_id = await oauth._oauth_token(client, url=url, origin=origin, issuer=issuer,
                username=oauth._required_login_value(LOGIN_USERNAME), password=oauth._required_login_value(LOGIN_PASSWORD),
                client_state_file=client_state_file, include_operation_scope=True)
            try:
                phase = "preview"
                async with oauth._mcp_session(url, token, verify) as session:
                    await session.initialize()
                    listed = (await session.list_tools()).tools
                    _require(TOOLS <= {tool.name for tool in listed})
                    preview = _body(await session.call_tool(PREVIEW_TOOL, {}))
                    _validate_preview(preview)
                    phase = "authorization"
                    authorization = _body(await session.call_tool(AUTHORIZE_TOOL, {"preview_ref": preview["preview_ref"]}))
                    _validate_authorization(authorization, preview)
                    _reserve_dispatch(dispatch_state_file)
                    attempted = True
                    phase = "execution"
                    _fresh(authorization["expires_at"])
                    result = _body(await session.call_tool(EXECUTE_TOOL, {"authorization_ref": authorization["authorization_ref"]}))
                    _validate_execution(result)
            finally:
                revoked = await oauth._revoke_and_prove_401(client, url, issuer, token, client_id)
                _require(revoked)
    except (Exception, BaseExceptionGroup):
        attempted = attempted or dispatch_state_file.exists()
        raise LdapServerMcpOAuthAcceptanceError(
            f"LDAP acceptance failed: phase={phase}; dispatch_reserved={str(attempted).lower()}; "
            f"reconciliation_required={str(attempted).lower()}; token_revoked_and_401_verified={str(revoked).lower()}; retry_allowed=false."
        ) from None
    return {"contract": "fortipam_v4_ldap_server_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": True, "mcp_initialized": True, "ldap_create_preview_verified": True,
        "authorization_verified": True, "dispatch_attempted_once": True, "ldap_created": True,
        "fixed_readback_verified": True, "ldap_cleanup_completed": False, "owner_recovery_required": True,
        "token_revoked": True, "revoked_access_rejected": True, "reconciliation_required": False,
        "credential_values_returned": False, "raw_response_returned": False,
        "references_returned": False, "retry_allowed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    for name in ("login-file", "client-state-file", "dispatch-state-file"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(run_ldap_server_mcp_oauth_acceptance(**vars(args)))
    except LdapServerMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
