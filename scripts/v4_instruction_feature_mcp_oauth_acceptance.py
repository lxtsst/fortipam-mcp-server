#!/usr/bin/env python3
"""Accept one owner-bound shared Instruction feature enable or restore through HTTPS OAuth/MCP.

The phase selects a fixed registered workflow, never an object or field value.
Keep each durable dispatch marker even on failure: consumed or uncertain calls
must not be retried. Native source qualification is not this MCP acceptance.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
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
from fortipam_mcp.instruction_feature_http_transport import CONTRACT as CONTRACT
from scripts import v4_https_oauth_acceptance as oauth
from scripts import v4_ldap_server_mcp_oauth_acceptance as create_client
from scripts.local_oauth_http_acceptance import (
    LOGIN_PASSWORD as LOGIN_PASSWORD,
    LOGIN_PREFIX,
    LOGIN_USERNAME as LOGIN_USERNAME,
)

PHASES = frozenset({"enable", "restore"})
DISPATCH_CONTRACT = "fortipam_v4_instruction_feature_dispatch_v1"
ACCEPTANCE_CONTRACT = "fortipam_v4_instruction_feature_mcp_oauth_acceptance_v1"
CLEANUP_CONTRACT = "fortipam_v4_instruction_feature_private_cleanup_v1"


class InstructionFeatureMcpOAuthAcceptanceError(RuntimeError):
    """Categorical refusal without private references, responses or credentials."""


def _require(condition: bool) -> None:
    if not condition:
        raise InstructionFeatureMcpOAuthAcceptanceError("Instruction feature phase acceptance contract rejected.")


def _tools(phase: str, reconciled_restore: bool = False) -> tuple[str, str, str]:
    _require(type(phase) is str and phase in PHASES)
    _require(type(reconciled_restore) is bool and (not reconciled_restore or phase == "restore"))
    preview = "preview_v4_instruction_feature_reconciled_restore_700" if reconciled_restore else f"preview_v4_instruction_feature_{phase}_700"
    return (preview, f"authorize_v4_instruction_feature_{phase}_700",
            f"execute_v4_instruction_feature_{phase}_700")


def _require_local_schema(schema: object) -> None:
    # These fixed tools need no references. Reject URI/base keywords at every
    # depth before the SDK can compile a resolver or make an external request.
    if type(schema) is dict:
        _require(not {"$ref", "$dynamicRef", "$recursiveRef", "$id", "id",
                      "$schema", "$anchor", "$dynamicAnchor"} & schema.keys())
        for value in schema.values():
            _require_local_schema(value)
    elif type(schema) is list:
        for value in schema:
            _require_local_schema(value)


def _validate_preview(body: dict[str, Any], phase: str) -> None:
    _tools(phase)
    restoring = phase == "restore"
    try:
        create_client._reference(body.get("preview_ref"), "instruction-feature-preview-")
        create_client._fresh(body.get("expires_at"))
        create_client._exact(body, {
            "contract": CONTRACT, "phase": phase, "policy_mode": "lab_auto",
            "preview_ref": body["preview_ref"], "expires_at": body["expires_at"],
            "Current State": {"instruction_enabled": restoring, "complete_setting_verified": True,
                "original_enable_ack_and_readback_verified": restoring},
            "Proposed Changes": {"operation": phase + "_instruction_feature",
                "shared_setting_change": True, "other_setting_fields_preserved": True},
            "Expected State": {"instruction_enabled": not restoring, "complete_setting_verified": True,
                "original_disabled_state_restored": restoring},
            "device_write_executed": False,
        })
    except create_client.LdapServerMcpOAuthAcceptanceError:
        raise InstructionFeatureMcpOAuthAcceptanceError("Instruction feature phase acceptance contract rejected.") from None


def _validate_authorization(body: dict[str, Any], preview: dict[str, Any], phase: str) -> None:
    _tools(phase)
    try:
        create_client._reference(body.get("authorization_ref"), "instruction-feature-auth-")
        create_client._fresh(body.get("expires_at"))
        _require(preview.get("contract") == CONTRACT)
        create_client._exact(body, {"contract": CONTRACT, "phase": phase, "policy_mode": "lab_auto",
            "authorization_ref": body["authorization_ref"], "expires_at": preview["expires_at"]})
    except create_client.LdapServerMcpOAuthAcceptanceError:
        raise InstructionFeatureMcpOAuthAcceptanceError("Instruction feature phase acceptance contract rejected.") from None


def _validate_execution(body: dict[str, Any], phase: str) -> None:
    _tools(phase)
    try:
        create_client._exact(body, {"contract": CONTRACT, "phase": phase,
            "outcome": "succeeded", "verification": "verified",
            "compensation": "not_requested", "idempotent_replay": False})
    except create_client.LdapServerMcpOAuthAcceptanceError:
        raise InstructionFeatureMcpOAuthAcceptanceError("Instruction feature phase acceptance contract rejected.") from None


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


async def run_instruction_feature_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, dispatch_state_file: Path,
    *, phase: str, cleanup_state_file: Path, ca_file: Path | None = None,
    reconciled_restore: bool = False,
) -> dict[str, object]:
    attempted, revoked = False, False
    stage = "preflight"
    try:
        preview_tool, authorize_tool, execute_tool = _tools(phase, reconciled_restore)
        create_client._new_dispatch_path(dispatch_state_file)
        create_client._new_dispatch_path(cleanup_state_file)
        for path in (login_file, client_state_file):
            create_client._protected_parent(path)
            if path.exists():
                metadata = path.stat()
                _require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
                    and not metadata.st_mode & 0o077)
        _require(len({path.resolve() for path in (login_file, client_state_file, dispatch_state_file,
            cleanup_state_file)}) == 4)
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
                stage = "cleanup_custody"
                # This local OAuth token remains owner-only for cleanup after a
                # verified device write. It never enters MCP arguments/results.
                _require(type(token) is str and 0 < len(token) <= 4096
                    and type(client_id) is str and 0 < len(client_id) <= 1024)
                metadata = client_state_file.stat()
                _require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
                    and not metadata.st_mode & 0o077 and metadata.st_size <= 4096)
                binding = hashlib.sha256(client_state_file.read_bytes()).hexdigest()
                parent = os.open(cleanup_state_file.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    metadata = os.fstat(parent)
                    _require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid()
                        and not metadata.st_mode & 0o077)
                    descriptor = os.open(cleanup_state_file.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=parent)
                    with os.fdopen(descriptor, "w") as output:
                        os.fchmod(output.fileno(), 0o600)
                        json.dump({"contract": CLEANUP_CONTRACT, "url": url, "token": token,
                            "client_id": client_id, "client_state_digest": binding}, output)
                        output.flush()
                        os.fsync(output.fileno())
                    os.fsync(parent)
                finally:
                    os.close(parent)
                stage = "mcp_connect"
                async with oauth._mcp_session(url, token, verify) as session:
                    stage = "mcp_initialize"
                    await session.initialize()
                    stage = "tool_listing"
                    listing = await session.list_tools()
                    stage = "tool_schema"
                    names = {tool.name for tool in listing.tools}
                    _require(set(_tools(phase, reconciled_restore)) <= names)
                    other_phase = "restore" if phase == "enable" else "enable"
                    _require(not set(_tools(other_phase)) & names)
                    for name in _tools(phase, reconciled_restore):
                        matches = [tool for tool in listing.tools if tool.name == name]
                        _require(len(matches) == 1)
                        _require_local_schema(matches[0].input_schema)
                        _require_local_schema(matches[0].output_schema)
                    stage = "preview_call"
                    preview_reply = await session.call_tool(preview_tool, {})
                    stage = "preview_tool_error"
                    _require(getattr(preview_reply, "is_error", True) is False)
                    stage = "preview_body"
                    preview = create_client._body(preview_reply)
                    stage = "preview_contract"
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
        try:
            attempted = attempted or dispatch_state_file.exists()
        except Exception:
            # An unreadable marker cannot prove that dispatch is unconsumed.
            attempted = True
        raise InstructionFeatureMcpOAuthAcceptanceError(
            f"Instruction feature phase acceptance failed: stage={stage}; dispatch_reserved={str(attempted).lower()}; "
            f"reconciliation_required={str(attempted).lower()}; "
            f"token_revoked_and_401_verified={str(revoked).lower()}; retry_allowed=false."
        ) from None
    finally:
        _clear_login_environment()
    proof = {"contract": ACCEPTANCE_CONTRACT, "phase": phase,
        "oauth_metadata_verified": True, "mcp_initialized": True, "phase_preview_verified": True,
        "authorization_verified": True, "dispatch_attempted_once": True,
        "feature_enabled": phase == "enable", "original_disabled_state_restored": phase == "restore",
        "fixed_readback_verified": True, "owner_cleanup_required": phase == "enable",
        "token_revoked": True, "revoked_access_rejected": True, "reconciliation_required": False,
        "credential_values_returned": False, "raw_response_returned": False,
        "references_returned": False, "retry_allowed": False}
    if reconciled_restore:
        proof.update(reconciled_restore=True, new_plan_issued=True)
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--phase", choices=sorted(PHASES), required=True)
    parser.add_argument("--reconciled-restore", action="store_true")
    for name in ("login-file", "client-state-file", "dispatch-state-file", "cleanup-state-file"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(run_instruction_feature_mcp_oauth_acceptance(**vars(args)))
    except InstructionFeatureMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
