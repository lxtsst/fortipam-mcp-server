#!/usr/bin/env python3
"""Accept one owner-bound LDAP update or restore through HTTPS OAuth/MCP.

The phase selects a fixed registered workflow, never an object or field value.
Keep each durable dispatch marker even on failure: consumed or uncertain calls
must not be retried. Native source qualification is not this MCP acceptance.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any
from urllib.parse import urlunsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    while str(root) in sys.path:
        sys.path.remove(str(root))
    sys.path.insert(0, str(root))

import httpx2
from fortipam_mcp.env import load_prefixed_environment_file
from fortipam_mcp.ldap_server_update_contract import CONTRACT as CONTRACT, UPDATED_GROUP_FILTER
from scripts import v4_https_oauth_acceptance as oauth
from scripts import v4_ldap_server_mcp_oauth_acceptance as create_client
from scripts.local_oauth_http_acceptance import (
    LOGIN_PASSWORD as LOGIN_PASSWORD,
    LOGIN_PREFIX,
    LOGIN_USERNAME as LOGIN_USERNAME,
)

PHASES = frozenset({"update", "restore"})
DISPATCH_CONTRACT = "fortipam_v4_ldap_server_update_dispatch_v1"
ACCEPTANCE_CONTRACT = "fortipam_v4_ldap_server_update_mcp_oauth_acceptance_v1"


class LdapServerUpdateMcpOAuthAcceptanceError(RuntimeError):
    """Categorical refusal without private references, responses or credentials."""


def _require(condition: bool) -> None:
    if not condition:
        raise LdapServerUpdateMcpOAuthAcceptanceError("LDAP phase acceptance contract rejected.")


def _tools(phase: str) -> tuple[str, str, str]:
    _require(type(phase) is str and phase in PHASES)
    return (f"preview_v4_ldap_server_{phase}_700", f"authorize_v4_ldap_server_{phase}_700",
            f"execute_v4_ldap_server_{phase}_700")


def _validate_preview(body: dict[str, Any], phase: str) -> None:
    _tools(phase)
    try:
        create_client._reference(body.get("preview_ref"), "ldap-change-preview-")
        create_client._fresh(body.get("expires_at"))
        create_client._exact(body, {
            "contract": CONTRACT, "phase": phase, "policy_mode": "lab_auto",
            "preview_ref": body["preview_ref"], "expires_at": body["expires_at"],
            "Current State": {"original_creation_ownership_verified": True,
                "zero_references_verified": True, "complete_bound_state_verified": True},
            "Proposed Changes": {"operation": phase + "_ldap_server", "field": "group-filter",
                "value": "" if phase == "restore" else UPDATED_GROUP_FILTER,
                "same_object_native_password_token_preserved": True},
            "Expected State": {"complete_bound_state_verified": True,
                "original_state_restored": phase == "restore", "stored_credential_path_verified": True},
            "device_write_executed": False,
        })
    except create_client.LdapServerMcpOAuthAcceptanceError:
        raise LdapServerUpdateMcpOAuthAcceptanceError("LDAP phase acceptance contract rejected.") from None


def _validate_authorization(body: dict[str, Any], preview: dict[str, Any], phase: str) -> None:
    _tools(phase)
    try:
        create_client._reference(body.get("authorization_ref"), "ldap-change-auth-")
        create_client._fresh(body.get("expires_at"))
        create_client._exact(body, {"contract": CONTRACT, "phase": phase, "policy_mode": "lab_auto",
            "authorization_ref": body["authorization_ref"], "expires_at": preview["expires_at"]})
    except create_client.LdapServerMcpOAuthAcceptanceError:
        raise LdapServerUpdateMcpOAuthAcceptanceError("LDAP phase acceptance contract rejected.") from None


def _validate_execution(body: dict[str, Any], phase: str) -> None:
    _tools(phase)
    try:
        create_client._exact(body, {"contract": CONTRACT, "phase": phase,
            "outcome": "succeeded", "verification": "verified",
            "compensation": "not_requested", "idempotent_replay": False})
    except create_client.LdapServerMcpOAuthAcceptanceError:
        raise LdapServerUpdateMcpOAuthAcceptanceError("LDAP phase acceptance contract rejected.") from None


def _clear_login_environment() -> None:
    for name in (LOGIN_USERNAME, LOGIN_PASSWORD):
        os.environ.pop(name, None)


def _reserve_dispatch(path: Path, phase: str) -> None:
    _tools(phase)
    create_client._new_dispatch_path(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(parent)
        _require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077)
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({"contract": DISPATCH_CONTRACT, "phase": phase,
                "dispatch_reserved": True, "retry_allowed": False}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        # Preserve even a partial marker if writing or either fsync fails.
        os.close(parent)


async def run_ldap_server_update_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, dispatch_state_file: Path,
    *, phase: str, ca_file: Path | None = None,
) -> dict[str, object]:
    attempted, revoked = False, False
    stage = "preflight"
    try:
        preview_tool, authorize_tool, execute_tool = _tools(phase)
        create_client._new_dispatch_path(dispatch_state_file)
        for path in (login_file, client_state_file):
            create_client._protected_parent(path)
            if path.exists():
                metadata = path.stat()
                _require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
                    and not metadata.st_mode & 0o077)
        _require(len({path.resolve() for path in (login_file, client_state_file, dispatch_state_file)}) == 3)
        parsed = oauth._validate_https_mcp_url(url)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        issuer = f"{origin}{parsed.path}/oauth"
        load_prefixed_environment_file(login_file, LOGIN_PREFIX, overwrite=True,
            required_keys=(LOGIN_USERNAME, LOGIN_PASSWORD))
        verify: str | bool = str(ca_file) if ca_file is not None else True
        async with httpx2.AsyncClient(timeout=30.0, follow_redirects=False, trust_env=False, verify=verify) as client:
            stage = "oauth"
            try:
                token, _, _, client_id = await oauth._oauth_token(client, url=url, origin=origin, issuer=issuer,
                    username=oauth._required_login_value(LOGIN_USERNAME),
                    password=oauth._required_login_value(LOGIN_PASSWORD),
                    client_state_file=client_state_file, include_operation_scope=True)
            finally:
                _clear_login_environment()
            try:
                stage = "preview"
                async with oauth._mcp_session(url, token, verify) as session:
                    await session.initialize()
                    names = {tool.name for tool in (await session.list_tools()).tools}
                    _require(set(_tools(phase)) <= names)
                    other_phase = "restore" if phase == "update" else "update"
                    _require(not set(_tools(other_phase)) & names)
                    preview = create_client._body(await session.call_tool(preview_tool, {}))
                    _validate_preview(preview, phase)
                    stage = "authorization"
                    authorization = create_client._body(await session.call_tool(
                        authorize_tool, {"preview_ref": preview["preview_ref"]}))
                    _validate_authorization(authorization, preview, phase)
                    _reserve_dispatch(dispatch_state_file, phase)
                    attempted = True
                    stage = "execution"
                    create_client._fresh(authorization["expires_at"])
                    result = create_client._body(await session.call_tool(
                        execute_tool, {"authorization_ref": authorization["authorization_ref"]}))
                    _validate_execution(result, phase)
            finally:
                revoked = await oauth._revoke_and_prove_401(client, url, issuer, token, client_id)
                _require(revoked)
    except (Exception, BaseExceptionGroup, asyncio.CancelledError):
        attempted = attempted or dispatch_state_file.exists()
        raise LdapServerUpdateMcpOAuthAcceptanceError(
            f"LDAP phase acceptance failed: stage={stage}; dispatch_reserved={str(attempted).lower()}; "
            f"reconciliation_required={str(attempted).lower()}; "
            f"token_revoked_and_401_verified={str(revoked).lower()}; retry_allowed=false."
        ) from None
    finally:
        _clear_login_environment()
    return {"contract": ACCEPTANCE_CONTRACT, "phase": phase,
        "oauth_metadata_verified": True, "mcp_initialized": True, "phase_preview_verified": True,
        "authorization_verified": True, "dispatch_attempted_once": True,
        "ldap_updated": phase == "update", "original_state_restored": phase == "restore",
        "fixed_readback_verified": True, "stored_credential_path_verified": True,
        "native_password_token_preserved": True, "owner_restore_required": phase == "update",
        "token_revoked": True, "revoked_access_rejected": True, "reconciliation_required": False,
        "credential_values_returned": False, "raw_response_returned": False,
        "references_returned": False, "retry_allowed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--phase", choices=sorted(PHASES), required=True)
    for name in ("login-file", "client-state-file", "dispatch-state-file"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(run_ldap_server_update_mcp_oauth_acceptance(**vars(args)))
    except LdapServerUpdateMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
