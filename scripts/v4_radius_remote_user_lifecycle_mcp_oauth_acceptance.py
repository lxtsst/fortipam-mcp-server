#!/usr/bin/env python3
"""Accept one fresh pair/disabled-User lifecycle through HTTPS OAuth/MCP.

Reuse the existing protected login/client, validate exact signed-summary semantics,
reserve one terminal dispatch and revoke/prove401 on every acquired-token path.
Server reports do not establish independent backend, login or failover acceptance.
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

if __package__ in {None, ""}:
    root = Path(__file__).resolve().parents[1]
    if str(root) in sys.path: sys.path.remove(str(root))
    sys.path.insert(0, str(root))

import httpx2
from v4_planning import canonical_digest
from scripts import v4_https_oauth_acceptance as oauth
from scripts.v4_radius_server_pair_lifecycle_mcp_oauth_acceptance import _protected_parent, _login, _new_dispatch_path

CONTRACT = "fortipam-v4-radius-pair-disabled-user-lifecycle-private-v1"
PREVIEW_TOOL = "preview_v4_radius_user_lifecycle_700"
AUTHORIZE_TOOL = "authorize_v4_radius_user_lifecycle_700"
EXECUTE_TOOL = "execute_v4_radius_user_lifecycle_700"
TOOLS = frozenset({PREVIEW_TOOL, AUTHORIZE_TOOL, EXECUTE_TOOL})
DISPATCH_CONTRACT = "fortipam_v4_radius_user_lifecycle_dispatch_v1"
# Six fresh child windows, handoff qualification and bounded cleanup headroom.
MCP_TIMEOUT_SECONDS = 480.0


class RadiusUserLifecycleAcceptanceError(RuntimeError):
    """Categorical failure with no private sources, credentials or refs."""


def _require(condition: bool) -> None:
    if not condition: raise RadiusUserLifecycleAcceptanceError("RADIUS User lifecycle contract rejected.")


def _exact(value: Any, expected: dict[str, object]) -> None:
    _require(type(value) is dict and set(value) == set(expected))
    for name, item in expected.items():
        if isinstance(item, dict): _exact(value[name], item)
        else: _require(type(value[name]) is type(item) and value[name] == item)


def _reference(value: Any, prefix: str) -> None:
    _require(type(value) is str and re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}", value) is not None)


def _fresh(value: Any) -> None:
    now = time.time()
    _require(type(value) is int and now < value <= now + 60)


def _body(reply: Any) -> dict[str, Any]:
    _require(getattr(reply, "is_error", True) is False)
    body = getattr(reply, "structured_content", None)
    _require(type(body) is dict)
    assert isinstance(body, dict)
    return body


def _validate_preview(body: dict[str, Any]) -> None:
    _reference(body.get("preview_ref"), "radius-user-lifecycle-preview-")
    _reference(body.get("summary_digest"), "")
    _reference(body.get("requester_digest"), "")
    _fresh(body.get("expires_at"))
    current = body.get("Current State")
    _require(type(current) is dict)
    assert isinstance(current, dict)
    _reference(current.get("pair_create_summary_digest"), "")
    _exact(body, {"contract": CONTRACT, "policy_mode": "lab_auto", "summary_revision": 1,
        "preview_ref": body["preview_ref"], "expires_at": body["expires_at"], "summary_digest": body["summary_digest"],
        "requester_digest": body["requester_digest"],
        "Current State": {"pair_create_summary_digest": current["pair_create_summary_digest"],
            "fresh_unclaimed_user_journal": True, "dependent_user_preflight": "after_owned_pair_before_user_dispatch"},
        "Proposed Changes": {"scope": "one_fresh_pair_and_one_disabled_remote_user", "child_m4_actions": 6,
            "user_status": "disable", "user_profile": "Standard", "user_wildcard": False,
            "group_association": False, "login_or_credential_probe": False},
        "Expected State": {"original_child_m4_required": True, "user_removed_before_pair": True,
            "both_final_dual_absence_required": True, "all_candidate_gates_closed": True,
            "user_authentication_qualified": False, "automatic_failover_qualified": False},
        "authorization_and_approval": {"mode": "standing_owner_lab_authority", "parent_grants_no_child_dispatch": True},
        "risk_and_effects": {"class": "C3", "effect": "one_bounded_pair_and_disabled_user_lifecycle"},
        "unresolved_gaps": ["user_enable", "user_authentication", "automatic_failover", "group_mapping", "version_1_9_1"],
        "compensation_and_stop": {"order": ["original_owned_user", "original_owned_pair"],
            "missing_ack_or_uncertain_delete": "retain_claims_read_only_reconcile_no_replay"},
        "device_write_executed": False})
    _require(canonical_digest({k:v for k,v in body.items() if k != "summary_digest"}) == body["summary_digest"])


def _validate_authorization(body: dict[str, Any], preview: dict[str, Any]) -> None:
    _reference(body.get("authorization_ref"), "radius-user-lifecycle-auth-")
    _fresh(body.get("expires_at"))
    _exact(body, {"contract": CONTRACT, "policy_mode": "lab_auto", "authorization_ref": body["authorization_ref"],
        "expires_at": preview["expires_at"]})


def _validate_execution(body: dict[str, Any]) -> None:
    _exact(body, {"contract": CONTRACT, "outcome": "succeeded", "verification": "verified", "idempotent_replay": False,
        "pair_configure_verified": True, "user_create_verified": True, "user_remove_verified": True,
        "user_absence_verified": True, "pair_remove_verified": True, "pair_absence_verified": True,
        "all_candidate_gates_closed": True, "user_authentication_qualified": False,
        "automatic_failover_qualified": False, "failure_stage": None})


def _reserve_dispatch(path: Path) -> None:
    _new_dispatch_path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077)
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({"contract": DISPATCH_CONTRACT, "dispatch_reserved": True, "retry_allowed": False}, stream)
            stream.flush(); os.fsync(stream.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)


async def run_radius_remote_user_lifecycle_mcp_oauth_acceptance(url: str, login_file: Path,
        client_state_file: Path, dispatch_state_file: Path, *, ca_file: Path | None = None) -> dict[str, object]:
    attempted = revoked = False
    phase = "preflight"
    login: dict[str, str] = {}
    try:
        _new_dispatch_path(dispatch_state_file)
        for path in (login_file, client_state_file):
            _protected_parent(path)
            info = path.stat()
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077)
        _require(len({p.resolve() for p in (login_file, client_state_file, dispatch_state_file)}) == 3)
        parsed = oauth._validate_https_mcp_url(url)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        issuer = f"{origin}{parsed.path}/oauth"
        login = _login(login_file)
        verify: str | bool = str(ca_file) if ca_file is not None else True
        async with httpx2.AsyncClient(timeout=30.0, follow_redirects=False, trust_env=False, verify=verify) as client:
            phase = "oauth"
            token, registered, reused, client_id = await oauth._oauth_token(client, url=url, origin=origin, issuer=issuer,
                username=login["username"], password=login["password"], client_state_file=client_state_file,
                include_operation_scope=True, require_existing_client=True)
            login.clear()
            try:
                _require(registered is False and reused is True)
                phase = "preview"
                async with oauth._mcp_session(url, token, verify, timeout_seconds=MCP_TIMEOUT_SECONDS) as session:
                    await session.initialize()
                    _require(TOOLS <= {tool.name for tool in (await session.list_tools()).tools})
                    preview = _body(await session.call_tool(PREVIEW_TOOL, {})); _validate_preview(preview)
                    phase = "authorization"
                    authorization = _body(await session.call_tool(AUTHORIZE_TOOL, {"preview_ref": preview["preview_ref"]}))
                    _validate_authorization(authorization, preview)
                    _reserve_dispatch(dispatch_state_file); attempted = True
                    phase = "execution"
                    _fresh(authorization["expires_at"])
                    result = _body(await session.call_tool(EXECUTE_TOOL, {"authorization_ref": authorization["authorization_ref"]}))
                    _validate_execution(result)
            finally:
                revoked = await oauth._revoke_and_prove_401(client, url, issuer, token, client_id)
                _require(revoked)
    except (Exception, BaseExceptionGroup, asyncio.CancelledError):
        attempted = attempted or dispatch_state_file.exists()
        raise RadiusUserLifecycleAcceptanceError(f"RADIUS User lifecycle acceptance failed: phase={phase}; "
            f"dispatch_reserved={str(attempted).lower()}; reconciliation_required={str(attempted).lower()}; "
            f"token_revoked_and_401_verified={str(revoked).lower()}; retry_allowed=false.") from None
    finally:
        login.clear()
    return {"contract": "fortipam_v4_radius_user_lifecycle_mcp_oauth_acceptance_v1", "oauth_metadata_verified": True,
        "existing_client_reused": True, "dynamic_client_registration_performed": False,
        "mcp_initialized": True, "parent_cpe_and_summary_verified": True, "authorization_verified": True,
        "dispatch_attempted_once": True, "pair_configure_reported_verified": True,
        "disabled_standard_user_create_reported_verified": True, "ordered_original_ack_recovery_reported_verified": True,
        "both_dual_absence_reported_verified": True, "all_candidate_gates_reported_closed": True,
        "user_authentication_qualified": False, "automatic_failover_qualified": False,
        "token_revoked": True, "revoked_access_rejected": True, "reconciliation_required": False,
        "credential_values_returned": False, "raw_response_returned": False, "references_returned": False,
        "retry_allowed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    for name in ("login-file", "client-state-file", "dispatch-state-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try: result = asyncio.run(run_radius_remote_user_lifecycle_mcp_oauth_acceptance(**vars(args)))
    except RadiusUserLifecycleAcceptanceError as error: raise SystemExit(str(error)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__": main()
