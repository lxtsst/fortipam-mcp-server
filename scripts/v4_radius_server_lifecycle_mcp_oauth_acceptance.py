#!/usr/bin/env python3
"""Accept one fixed private RADIUS lifecycle through HTTPS OAuth/MCP.

Connections occur only when this client is explicitly invoked. The default
qualification includes original-ACK recovery and final dual absence. The explicit
persistent profile retains complete verified success; separate removal uses its
own preview and grant. Retain every dispatch marker: never repeat a consumed or
uncertain request.
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
from typing import Any, cast
from urllib.parse import urlunsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    while str(root) in sys.path:
        sys.path.remove(str(root))
    sys.path.insert(0, str(root))

import httpx2
from fortipam_mcp.ldap_server_runtime import _read
from fortipam_mcp.secret_metadata_http_transport import _zeroize_mutable
from scripts import v4_https_oauth_acceptance as oauth

CONTRACT = "fortipam-v4-radius-primary-lifecycle-candidate-v1"
PERSISTENT_CONTRACT = "fortipam-v4-radius-primary-configure-candidate-v1"
PREVIEW_TOOL = "preview_v4_radius_primary_lifecycle_700"
AUTHORIZE_TOOL = "authorize_v4_radius_primary_lifecycle_700"
EXECUTE_TOOL = "execute_v4_radius_primary_lifecycle_700"
TOOLS = frozenset({PREVIEW_TOOL, AUTHORIZE_TOOL, EXECUTE_TOOL})
CONFIGURE_TOOLS = tuple(f"{verb}_v4_radius_primary_configure_700" for verb in ("preview", "authorize", "execute"))
REMOVE_TOOLS = frozenset(f"{verb}_v4_radius_primary_remove_700" for verb in ("preview", "authorize", "execute"))
REMOVAL_CONTRACT = "fortipam-radius-owned-recovery-private-v1"
DISPATCH_CONTRACT = "fortipam_v4_radius_lifecycle_dispatch_v1"


class RadiusLifecycleMcpOAuthAcceptanceError(RuntimeError):
    """Categorical failure without credentials, raw results or private refs."""


def _require(condition: bool) -> None:
    if not condition:
        raise RadiusLifecycleMcpOAuthAcceptanceError("RADIUS lifecycle acceptance contract rejected.")


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


def _validate_preview(body: dict[str, Any], *, persistent_primary: bool = False) -> None:
    _reference(body.get("preview_ref"), "radius-lifecycle-preview-")
    _fresh(body.get("expires_at"))
    expected = {"original_m4_success_required": True, "exact_reject_only_response_required": True,
        "full_created_state_preserved": True, "all_candidate_gates_closed": True}
    if persistent_primary:
        expected.update(owned_entry_retained=True, independent_original_ack_removal_available=True)
    else:
        expected["final_dual_absence_required"] = True
    _exact(body, {
        "contract": PERSISTENT_CONTRACT if persistent_primary else CONTRACT, "policy_mode": "lab_auto",
        "preview_ref": body["preview_ref"], "expires_at": body["expires_at"],
        "Current State": {"bound_entry_absent": True, "schema_defaults_qualified": True,
            "dual_absence_verified": True, "child_dispatches_unconsumed": True},
        "Proposed Changes": {"operation": "configure_radius_primary" if persistent_primary
                else "qualify_disposable_radius_primary", "primary_only": True,
            "user_group_associations": False,
            "fixed_sequence": ["create", "owned_native_connect"] if persistent_primary
                else ["create", "owned_native_connect", "original_ack_remove"],
            "material_acquisitions_maximum": 1},
        "Expected State": expected,
        "device_write_executed": False,
    })


def _validate_authorization(body: dict[str, Any], preview: dict[str, Any], *, persistent_primary: bool = False) -> None:
    _reference(body.get("authorization_ref"), "radius-lifecycle-auth-")
    _fresh(body.get("expires_at"))
    _exact(body, {"contract": PERSISTENT_CONTRACT if persistent_primary else CONTRACT, "policy_mode": "lab_auto",
                  "authorization_ref": body["authorization_ref"], "expires_at": preview["expires_at"]})


def _validate_execution(body: dict[str, Any], *, persistent_primary: bool = False) -> None:
    expected: dict[str, object] = {"contract": PERSISTENT_CONTRACT if persistent_primary else CONTRACT,
        "outcome": "succeeded", "verification": "verified",
                  "idempotent_replay": False, "create_verified": True, "native_m4_verified": True,
        "exact_reject_only_response_verified": True, "original_ack_removal_verified": not persistent_primary,
        "private_reject_only_connectivity_verified": True, "user_authentication_verified": False,
        "all_candidate_gates_closed": True, "failure_stage": None}
    if persistent_primary:
        expected["owned_entry_retained"] = True
    _exact(body, expected)


def _validate_removal_preview(body: dict[str, Any]) -> None:
    _reference(body.get("preview_ref"), "radius-recovery-preview-")
    _fresh(body.get("expires_at"))
    _exact(body, {"contract": REMOVAL_CONTRACT, "policy_mode": "lab_auto",
        "preview_ref": body["preview_ref"], "expires_at": body["expires_at"],
        "Current State": {"original_creation_ack_verified": True, "full_state_unchanged": True,
            "zero_references": True},
        "Proposed Changes": {"operation": "remove_original_owned_radius_row", "material_access": False},
        "Expected State": {"exact_detail_absent": True, "complete_collection_absent": True},
        "device_write_executed": False})


def _validate_removal_authorization(body: dict[str, Any], preview: dict[str, Any]) -> None:
    _reference(body.get("authorization_ref"), "radius-recovery-auth-")
    _fresh(body.get("expires_at"))
    _exact(body, {"contract": REMOVAL_CONTRACT, "policy_mode": "lab_auto",
        "authorization_ref": body["authorization_ref"], "expires_at": preview["expires_at"]})


def _validate_removal_execution(body: dict[str, Any]) -> None:
    _exact(body, {"contract": REMOVAL_CONTRACT, "outcome": "succeeded", "verification": "verified",
        "compensation": "not_requested", "idempotent_replay": False})


def _protected_parent(path: Path) -> None:
    _require(path.is_absolute() and not any(part.is_symlink() for part in (path, *path.parents)))
    metadata = path.parent.stat()
    _require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077)


def _login(path: Path) -> dict[str, str]:
    """Use the existing owner-only JSON account source without copying credentials."""
    raw = _read(path, 4096)
    try:
        value = json.loads(raw)
        _require(type(value) is dict and set(value) == {"username", "password"})
        _require(all(type(value[k]) is str and 0 < len(value[k]) <= 4096 for k in value))
        return cast(dict[str, str], value)
    finally:
        _zeroize_mutable(raw)


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


async def run_radius_server_lifecycle_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, dispatch_state_file: Path,
    *, ca_file: Path | None = None, persistent_primary: bool = False, remove_owned_primary: bool = False,
) -> dict[str, object]:
    attempted, revoked = False, False
    login: dict[str, str] = {}
    phase = "preflight"
    try:
        _require(type(persistent_primary) is bool and type(remove_owned_primary) is bool
            and not (persistent_primary and remove_owned_primary))
        preview_tool, authorize_tool, execute_tool = CONFIGURE_TOOLS if persistent_primary else (
            PREVIEW_TOOL, AUTHORIZE_TOOL, EXECUTE_TOOL)
        if remove_owned_primary:
            preview_tool, authorize_tool, execute_tool = tuple(
                f"{verb}_v4_radius_primary_remove_700" for verb in ("preview", "authorize", "execute"))
        _new_dispatch_path(dispatch_state_file)
        for path in (login_file, client_state_file):
            _protected_parent(path)
            if path.exists():
                metadata = path.stat()
                _require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077)
        _require(len({path.resolve() for path in (login_file, client_state_file, dispatch_state_file)}) == 3)
        _require(client_state_file.is_file())
        parsed = oauth._validate_https_mcp_url(url)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        issuer = f"{origin}{parsed.path}/oauth"
        login = _login(login_file)
        verify: str | bool = str(ca_file) if ca_file is not None else True
        async with httpx2.AsyncClient(timeout=30.0, follow_redirects=False, trust_env=False, verify=verify) as client:
            phase = "oauth"
            token, registered, reused, client_id = await oauth._oauth_token(client, url=url, origin=origin, issuer=issuer,
                username=login["username"], password=login["password"],
                client_state_file=client_state_file, include_operation_scope=True, require_existing_client=True)
            login.clear()
            try:
                _require(registered is False and reused is True)
                phase = "preview"
                async with oauth._mcp_session(url, token, verify, timeout_seconds=300.0) as session:
                    await session.initialize()
                    listed = (await session.list_tools()).tools
                    required = set(CONFIGURE_TOOLS) | REMOVE_TOOLS if persistent_primary else (
                        REMOVE_TOOLS if remove_owned_primary else TOOLS)
                    _require(required <= {tool.name for tool in listed})
                    preview = _body(await session.call_tool(preview_tool, {}))
                    if remove_owned_primary:
                        _validate_removal_preview(preview)
                    else:
                        _validate_preview(preview, persistent_primary=persistent_primary)
                    phase = "authorization"
                    authorization = _body(await session.call_tool(authorize_tool, {"preview_ref": preview["preview_ref"]}))
                    if remove_owned_primary:
                        _validate_removal_authorization(authorization, preview)
                    else:
                        _validate_authorization(authorization, preview, persistent_primary=persistent_primary)
                    _reserve_dispatch(dispatch_state_file)
                    attempted = True
                    phase = "execution"
                    _fresh(authorization["expires_at"])
                    result = _body(await session.call_tool(execute_tool, {"authorization_ref": authorization["authorization_ref"]}))
                    if remove_owned_primary:
                        _validate_removal_execution(result)
                    else:
                        _validate_execution(result, persistent_primary=persistent_primary)
            finally:
                revoked = await oauth._revoke_and_prove_401(client, url, issuer, token, client_id)
                _require(revoked)
    except (Exception, BaseExceptionGroup):
        attempted = attempted or dispatch_state_file.exists()
        raise RadiusLifecycleMcpOAuthAcceptanceError(
            f"RADIUS lifecycle acceptance failed: phase={phase}; dispatch_reserved={str(attempted).lower()}; "
            f"reconciliation_required={str(attempted).lower()}; token_revoked_and_401_verified={str(revoked).lower()}; retry_allowed=false."
        ) from None
    finally:
        login.clear()
    if remove_owned_primary:
        return {"contract": "fortipam_v4_radius_remove_mcp_oauth_acceptance_v1",
            "oauth_metadata_verified": True, "existing_client_reused": True,
            "dynamic_client_registration_performed": False, "mcp_initialized": True,
            "original_ack_cpe_verified": True, "independent_authorization_verified": True,
            "dispatch_attempted_once": True, "original_ack_removal_verified": True,
            "final_dual_absence_verified": True, "material_acquisitions": 0,
            "token_revoked": True, "revoked_access_rejected": True,
            "reconciliation_required": False, "credential_values_returned": False,
            "raw_response_returned": False, "references_returned": False, "retry_allowed": False}
    proof: dict[str, object] = {"contract": "fortipam_v4_radius_configure_mcp_oauth_acceptance_v1" if persistent_primary
            else "fortipam_v4_radius_lifecycle_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": True, "existing_client_reused": True,
        "dynamic_client_registration_performed": False, "mcp_initialized": True,
        "parent_cpe_verified": True, "authorization_verified": True, "dispatch_attempted_once": True,
        "radius_created_and_full_readback_verified": True, "original_native_m4_verified": True,
        "private_reject_only_connectivity_verified": True, "original_ack_removal_verified": not persistent_primary,
        "final_dual_absence_verified": not persistent_primary, "all_candidate_gates_closed": True,
        "user_authentication_verified": False, "token_revoked": True, "revoked_access_rejected": True,
        "reconciliation_required": False, "credential_values_returned": False,
        "raw_response_returned": False, "references_returned": False, "retry_allowed": False}
    if persistent_primary:
        proof["owned_entry_retained"] = True
    return proof



def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    for name in ("login-file", "client-state-file", "dispatch-state-file"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--persistent-primary", action="store_true",
        help="Use the separately pinned configure profile and retain the fully verified primary on success.")
    modes.add_argument("--remove-owned-primary", action="store_true",
        help="Use independent original-ACK removal after normally recomposing the same pinned persistent profile.")
    args = parser.parse_args()
    try:
        result = asyncio.run(run_radius_server_lifecycle_mcp_oauth_acceptance(**vars(args)))
    except RadiusLifecycleMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
