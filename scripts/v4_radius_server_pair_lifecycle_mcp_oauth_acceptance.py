#!/usr/bin/env python3
"""Accept one fixed paired RADIUS lifecycle or configure/removal via HTTPS OAuth/MCP.

Reuse the existing OAuth client; validate exact fresh C/P/E and summary digest;
fsync a terminal dispatch marker before one execution; revoke and prove401.
Retain partial/uncertain markers. This client grants no material or retry authority
and never promotes observation success to connectivity or retained-pair acceptance.
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
from v4_planning import canonical_digest

CONTRACT = "fortipam-v4-radius-pair-lifecycle-candidate-v1"
PERSISTENT_CONTRACT = "fortipam-v4-radius-pair-configure-candidate-v1"
REMOVAL_CONTRACT = "fortipam-radius-pair-owned-recovery-private-v1"
PREVIEW_TOOL = "preview_v4_radius_pair_lifecycle_700"
AUTHORIZE_TOOL = "authorize_v4_radius_pair_lifecycle_700"
EXECUTE_TOOL = "execute_v4_radius_pair_lifecycle_700"
TOOLS = frozenset({PREVIEW_TOOL, AUTHORIZE_TOOL, EXECUTE_TOOL})
CONFIGURE_TOOLS = tuple(f"{verb}_v4_radius_pair_configure_700" for verb in ("preview", "authorize", "execute"))
REMOVE_TOOLS = tuple(f"{verb}_v4_radius_pair_remove_700" for verb in ("preview", "authorize", "execute"))
DISPATCH_CONTRACT = "fortipam_v4_radius_pair_lifecycle_dispatch_v1"


class RadiusPairLifecycleMcpOAuthAcceptanceError(RuntimeError):
    """Categorical failure without credentials, raw results or private refs."""


def _require(condition: bool) -> None:
    if not condition:
        raise RadiusPairLifecycleMcpOAuthAcceptanceError("Paired RADIUS lifecycle acceptance contract rejected.")


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


def _validate_preview(body: dict[str, Any], *, persistent_pair: bool = False) -> None:
    _reference(body.get("preview_ref"), "radius-pair-lifecycle-preview-")
    _reference(body.get("summary_digest"), "")
    _fresh(body.get("expires_at"))
    expected = {"original_child_m4_success_required": True, "both_ordinal_observations_recorded": True,
        "full_created_state_preserved": True, "all_candidate_gates_closed": True, "connectivity_qualified": False}
    if persistent_pair:
        expected.update(exact_reject_only_response_required=True, owned_entry_retained=True,
            independent_original_ack_removal_available=True)
    else:
        expected["final_dual_absence_required"] = True
    _exact(body, {
        "contract": PERSISTENT_CONTRACT if persistent_pair else CONTRACT, "policy_mode": "lab_auto", "summary_revision": 1,
        "preview_ref": body["preview_ref"], "expires_at": body["expires_at"], "summary_digest": body["summary_digest"],
        "Current State": {"bound_entry_absent": True, "schema_defaults_qualified": True,
            "dual_absence_verified": True, "child_dispatches_unconsumed": True},
        "Proposed Changes": {"operation": "configure_radius_pair" if persistent_pair else "qualify_disposable_radius_pair",
            "fixed_sequence": ["create", "observe_primary", "observe_secondary"] if persistent_pair
                else ["create", "observe_primary", "observe_secondary", "original_ack_remove"],
            "material_endpoint_acquisitions_maximum": 2, "material_pair_leases_maximum": 1, "user_group_associations": False},
        "Expected State": expected,
        "authorization_and_approval": {"mode": "standing_owner_lab_authority", "child_authorizations_independent": True},
        "unresolved_gaps": ["protocol_and_material_application", "automatic_failover", "user_login"],
        "compensation_and_stop": {"failure": "stop_remaining_observations_and_attempt_qualified_original_ack_recovery",
            "uncertain_result": "retain_consumed_claims_without_replay"}, "device_write_executed": False,
    })
    _require(canonical_digest({k: v for k, v in body.items() if k != "summary_digest"}) == body["summary_digest"])


def _validate_authorization(body: dict[str, Any], preview: dict[str, Any], *, persistent_pair: bool = False) -> None:
    _reference(body.get("authorization_ref"), "radius-pair-lifecycle-auth-")
    _fresh(body.get("expires_at"))
    _exact(body, {"contract": PERSISTENT_CONTRACT if persistent_pair else CONTRACT, "policy_mode": "lab_auto",
        "authorization_ref": body["authorization_ref"], "expires_at": preview["expires_at"]})


def _validate_execution(body: dict[str, Any], *, persistent_pair: bool = False) -> None:
    expected: dict[str, object] = {"contract": PERSISTENT_CONTRACT if persistent_pair else CONTRACT,
        "outcome": "succeeded", "verification": "verified", "idempotent_replay": False,
        "execution_scope": "persistent_pair_configure" if persistent_pair else "disposable_pair_lifecycle", "create_verified": True,
        "ordinal_observations_verified": {"primary": True, "secondary": True}, "original_ack_removal_verified": not persistent_pair,
        "connectivity_qualified": False, "user_authentication_verified": False, "all_candidate_gates_closed": True,
        "failure_stage": None}
    if persistent_pair:
        expected.update(owned_entry_retained=True, exact_reject_only_responses_verified=True)
    _exact(body, expected)


def _validate_removal_preview(body: dict[str, Any]) -> None:
    _reference(body.get("preview_ref"), "radius-pair-recovery-preview-")
    _reference(body.get("summary_digest"), "")
    _reference(body.get("requester_digest"), "")
    _fresh(body.get("expires_at"))
    current = body.get("Current State")
    _require(type(current) is dict)
    assert isinstance(current, dict)
    observed = current.get("observed_at")
    _require(type(observed) is int and 0 <= time.time() - observed < 60 and observed < body["expires_at"])
    _exact(body, {"contract": REMOVAL_CONTRACT, "policy_mode": "lab_auto", "summary_revision": 1,
        "preview_ref": body["preview_ref"], "expires_at": body["expires_at"], "summary_digest": body["summary_digest"],
        "requester_digest": body["requester_digest"], "environment": "privately_bound_disposable_lab",
        "unchanged_boundary": ["other_identity_servers", "users_groups_and_roles"],
        "Current State": {"original_creation_ack_verified": True, "full_state_unchanged": True,
            "zero_references": True, "observed_at": observed},
        "Proposed Changes": {"operation": "remove_original_owned_radius_pair_row", "material_access": False},
        "Expected State": {"exact_detail_absent": True, "complete_collection_absent": True},
        "dependencies": ["original_pair_creation_ack", "fresh_complete_unchanged_state", "independent_recovery_ledger"],
        "risk_and_effects": {"effect": "remove_one_unassociated_owned_lab_row"},
        "authorization_and_approval": {"mode": "standing_owner_lab_authority", "independent_human_approval": False},
        "facts": {"source": "original_pair_ack_and_fresh_full_cmdb_state", "freshness_seconds": 60},
        "assumptions": ["owner_authorized_disposable_lab_scope"], "unresolved_gaps": [],
        "verification": ["original_delete_ack", "dual_absence"],
        "compensation_and_stop": {"uncertain_result": "retain_claims_and_reconcile_without_replay"},
        "device_write_executed": False})
    _require(canonical_digest({k: v for k, v in body.items() if k != "summary_digest"}) == body["summary_digest"])


def _validate_removal_authorization(body: dict[str, Any], preview: dict[str, Any]) -> None:
    _reference(body.get("authorization_ref"), "radius-pair-recovery-auth-")
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


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        _require(name not in value)
        value[name] = item
    return value


def _login(path: Path) -> dict[str, str]:
    """Use the existing owner-only JSON account source without copying credentials."""
    raw = _read(path, 4096)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
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


async def run_radius_server_pair_lifecycle_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, dispatch_state_file: Path,
    *, ca_file: Path | None = None, persistent_pair: bool = False, remove_owned_pair: bool = False,
) -> dict[str, object]:
    attempted, revoked = False, False
    login: dict[str, str] = {}
    phase = "preflight"
    try:
        _require(type(persistent_pair) is bool and type(remove_owned_pair) is bool and not (persistent_pair and remove_owned_pair))
        preview_tool, authorize_tool, execute_tool = (REMOVE_TOOLS if remove_owned_pair else
            CONFIGURE_TOOLS if persistent_pair else (PREVIEW_TOOL, AUTHORIZE_TOOL, EXECUTE_TOOL))
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
                    required = set(CONFIGURE_TOOLS) | set(REMOVE_TOOLS) if persistent_pair else set(REMOVE_TOOLS) if remove_owned_pair else TOOLS
                    _require(required <= {tool.name for tool in listed})
                    preview = _body(await session.call_tool(preview_tool, {}))
                    if remove_owned_pair:
                        _validate_removal_preview(preview)
                    else:
                        _validate_preview(preview, persistent_pair=persistent_pair)
                    phase = "authorization"
                    authorization = _body(await session.call_tool(authorize_tool, {"preview_ref": preview["preview_ref"]}))
                    if remove_owned_pair:
                        _validate_removal_authorization(authorization, preview)
                    else:
                        _validate_authorization(authorization, preview, persistent_pair=persistent_pair)
                    _reserve_dispatch(dispatch_state_file)
                    attempted = True
                    phase = "execution"
                    _fresh(authorization["expires_at"])
                    result = _body(await session.call_tool(execute_tool, {"authorization_ref": authorization["authorization_ref"]}))
                    if remove_owned_pair:
                        _validate_removal_execution(result)
                    else:
                        _validate_execution(result, persistent_pair=persistent_pair)
            finally:
                revoked = await oauth._revoke_and_prove_401(client, url, issuer, token, client_id)
                _require(revoked)
    except (Exception, BaseExceptionGroup, asyncio.CancelledError):
        attempted = attempted or dispatch_state_file.exists()
        raise RadiusPairLifecycleMcpOAuthAcceptanceError(
            f"Paired RADIUS lifecycle acceptance failed: phase={phase}; dispatch_reserved={str(attempted).lower()}; "
            f"reconciliation_required={str(attempted).lower()}; token_revoked_and_401_verified={str(revoked).lower()}; retry_allowed=false."
        ) from None
    finally:
        login.clear()
    if remove_owned_pair:
        return {"contract": "fortipam_v4_radius_pair_remove_mcp_oauth_acceptance_v1",
            "oauth_metadata_verified": True, "existing_client_reused": True, "dynamic_client_registration_performed": False,
            "mcp_initialized": True, "original_ack_cpe_and_summary_verified": True, "independent_authorization_verified": True,
            "dispatch_attempted_once": True, "original_ack_removal_reported_verified": True,
            "final_dual_absence_reported_verified": True, "token_revoked": True, "revoked_access_rejected": True,
            "reconciliation_required": False, "credential_values_returned": False, "raw_response_returned": False,
            "references_returned": False, "retry_allowed": False}
    proof: dict[str, object] = {"contract": "fortipam_v4_radius_pair_configure_mcp_oauth_acceptance_v1" if persistent_pair
            else "fortipam_v4_radius_pair_lifecycle_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": True, "existing_client_reused": True, "dynamic_client_registration_performed": False,
        "mcp_initialized": True, "parent_cpe_and_summary_verified": True, "authorization_verified": True,
        "dispatch_attempted_once": True, "radius_pair_created_and_full_readback_reported": True,
        "both_ordinal_observations_reported_verified": True, "original_ack_removal_reported_verified": not persistent_pair,
        "final_dual_absence_reported_verified": not persistent_pair, "all_candidate_gates_reported_closed": True,
        "connectivity_qualified": False, "retained_pair_qualified": False, "user_authentication_verified": False,
        "token_revoked": True, "revoked_access_rejected": True, "reconciliation_required": False,
        "credential_values_returned": False, "raw_response_returned": False, "references_returned": False,
        "retry_allowed": False}
    if persistent_pair:
        proof.update(owned_entry_retained_reported=True, exact_reject_only_responses_reported_verified=True)
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    for name in ("login-file", "client-state-file", "dispatch-state-file"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--persistent-pair", action="store_true")
    mode.add_argument("--remove-owned-pair", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(run_radius_server_pair_lifecycle_mcp_oauth_acceptance(**vars(args)))
    except RadiusPairLifecycleMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
