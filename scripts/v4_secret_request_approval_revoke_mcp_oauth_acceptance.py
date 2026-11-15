#!/usr/bin/env python3
"""Accept the privately bound BP008 withdrawal once through HTTPS OAuth/MCP.

The operator supplies an already configured candidate and protected OAuth login.
This client never creates Requests, approves access, or changes access windows.
Keep the dispatch marker after every outcome; uncertainty never permits replay.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
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
from scripts import v4_https_oauth_acceptance as oauth

CONTRACT = "fortipam_v4_secret_request_approval_revoke_700_candidate_v1"
OPERATION = "withdraw_secret_request_approval"
PREVIEW_TOOL = "preview_v4_secret_request_approval_revoke_700"
AUTHORIZE_TOOL = "authorize_v4_secret_request_approval_revoke_700"
EXECUTE_TOOL = "execute_v4_secret_request_approval_revoke_700"
TOOLS = frozenset({PREVIEW_TOOL, AUTHORIZE_TOOL, EXECUTE_TOOL})


class SecretRequestApprovalRevokeMcpOAuthAcceptanceError(RuntimeError):
    """Categorical failure without source values, references or credentials."""


def _require(condition: bool) -> None:
    if not condition:
        raise SecretRequestApprovalRevokeMcpOAuthAcceptanceError("Withdrawal acceptance contract rejected.")


def _exact(value: Any, expected: dict[str, object]) -> None:
    # JSON equality alone would accept 1 in place of True.
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


def _reference(value: Any, kind: str) -> None:
    prefix = f"secret-request-approval-revoke-{OPERATION}-{kind}-"
    _require(type(value) is str and re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9_-]{32}", value) is not None)


def _fresh(expires: Any) -> None:
    _require(type(expires) in (int, float) and math.isfinite(expires) and time.time() < expires <= time.time() + 120)


def _validate_preview(body: dict[str, Any]) -> None:
    _reference(body.get("preview_ref"), "preview")
    _fresh(body.get("expires_at"))
    _exact(body, {
        "contract": CONTRACT, "preview_ref": body["preview_ref"], "expires_at": body["expires_at"],
        "Current State": {"exact_active_original_grant_verified": True, "original_reviewer_verified": True, "credential_values_returned": False},
        "Proposed Changes": {"operation": OPERATION, "own_grant_withdrawal_only": True, "request_and_parent_metadata_preserved": True},
        "Expected State": {"request_pending": True, "request_and_parent_metadata_preserved": True, "backend_launch_denial_requires_independent_evidence": True},
        "device_write_executed": False,
    })


def _validate_authorization(body: dict[str, Any], preview: dict[str, Any]) -> None:
    _reference(body.get("authorization_ref"), "authorized")
    _fresh(body.get("expires_at"))
    _exact(body, {"contract": CONTRACT, "preview_ref": preview["preview_ref"],
        "authorization_ref": body["authorization_ref"], "expires_at": preview["expires_at"],
        "confirmation": "recorded", "execution": "authorized_once", "device_write_executed": False})


def _validate_execution(body: dict[str, Any]) -> None:
    _exact(body, {"contract": CONTRACT, "operation": OPERATION, "outcome": "succeeded",
        "verification": "verified", "idempotent_replay": False, "device_write_may_have_occurred": True,
        "credential_values_returned": False, "raw_api_response_returned": False,
        "backend_launch_denial_requires_independent_evidence": True})


def _protected_parent(path: Path) -> None:
    _require(path.is_absolute() and not any(part.is_symlink() for part in (path, *path.parents)))
    metadata = path.parent.stat()
    _require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077)


def _new_dispatch_path(path: Path) -> None:
    _protected_parent(path)
    _require(not path.exists())


def _reserve_dispatch(path: Path) -> None:
    _new_dispatch_path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            json.dump({"contract": "fortipam_v4_approval_withdrawal_dispatch_v1", "dispatch_reserved": True, "retry_allowed": False}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except BaseException:
        # Even a partially written reservation remains a permanent stop marker.
        raise


async def run_secret_request_approval_revoke_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, dispatch_state_file: Path,
    *, ca_file: Path | None = None,
) -> dict[str, object]:
    attempted = False
    cleanup = False
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
        oauth.load_prefixed_environment_file(login_file, oauth.LOGIN_PREFIX, overwrite=True,
            required_keys=(oauth.LOGIN_USERNAME, oauth.LOGIN_PASSWORD))
        verify: str | bool = str(ca_file) if ca_file is not None else True
        async with httpx2.AsyncClient(timeout=30.0, follow_redirects=False, trust_env=False, verify=verify) as client:
            phase = "oauth"
            token, _, _, client_id = await oauth._oauth_token(client, url=url, origin=origin, issuer=issuer,
                username=oauth._required_login_value(oauth.LOGIN_USERNAME), password=oauth._required_login_value(oauth.LOGIN_PASSWORD),
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
                    _validate_execution(_body(await session.call_tool(EXECUTE_TOOL, {"authorization_ref": authorization["authorization_ref"]})))
            finally:
                cleanup = await oauth._revoke_and_prove_401(client, url, issuer, token, client_id)
                _require(cleanup)
    except (Exception, BaseExceptionGroup):
        attempted = attempted or dispatch_state_file.exists()
        raise SecretRequestApprovalRevokeMcpOAuthAcceptanceError(
            f"Withdrawal acceptance failed: phase={phase}; dispatch_reserved={str(attempted).lower()}; "
            f"reconciliation_required={str(attempted).lower()}; token_revoked_and_401_verified={str(cleanup).lower()}; retry_allowed=false."
        ) from None
    return {"contract": "fortipam_v4_secret_request_approval_revoke_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": True, "mcp_initialized": True, "withdrawal_preview_verified": True,
        "authorization_verified": True, "dispatch_attempted_once": True, "withdrawal_readback_verified": True,
        "backend_launch_denial_verified": False, "backend_launch_denial_requires_independent_evidence": True,
        "token_revoked": True, "revoked_access_rejected": True, "reconciliation_required": False,
        "credential_values_returned": False, "raw_response_returned": False, "references_returned": False, "retry_allowed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    for name in ("login-file", "client-state-file", "dispatch-state-file"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(run_secret_request_approval_revoke_mcp_oauth_acceptance(**vars(args)))
    except SecretRequestApprovalRevokeMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
