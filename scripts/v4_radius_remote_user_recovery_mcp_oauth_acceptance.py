#!/usr/bin/env python3
"""Original User/pair recovery or read-only reconciliation through HTTPS OAuth/MCP.

Reuse protected existing login/client inputs. Every mutating run retains one
terminal marker before its first execute; uncertain outcomes cannot resume it.
Reports are server evidence, not independent backend or authentication acceptance.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
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
from scripts.v4_radius_remote_user_lifecycle_mcp_oauth_acceptance import _body, _exact, _fresh, _reference
from scripts.v4_radius_server_pair_lifecycle_mcp_oauth_acceptance import _protected_parent, _login, _new_dispatch_path

USER_CONTRACT = "fortipam-radius-remote-user-original-recovery-private-v1"
PAIR_CONTRACT = "fortipam-radius-pair-owned-recovery-private-v1"
INSPECT = "inspect_v4_radius_user_cleanup_700"
USER_PREVIEW = "preview_v4_radius_user_recovery_700"
USER_AUTHORIZE = "authorize_v4_radius_user_recovery_700"
USER_EXECUTE = "execute_v4_radius_user_recovery_700"
USER_RECONCILE = "reconcile_v4_radius_user_recovery_700"
PAIR_PREVIEW = "preview_v4_radius_associated_pair_recovery_700"
PAIR_AUTHORIZE = "authorize_v4_radius_associated_pair_recovery_700"
PAIR_EXECUTE = "execute_v4_radius_associated_pair_recovery_700"
PAIR_RECONCILE = "reconcile_v4_radius_associated_pair_recovery_700"
MODES = ("recover-user-pair", "recover-pair", "inspect-user", "reconcile-user", "reconcile-pair")
MUTATING = frozenset(MODES[:2])
MODE_TOOLS = {
    "recover-user-pair": frozenset({USER_PREVIEW, USER_AUTHORIZE, USER_EXECUTE, USER_RECONCILE,
        INSPECT, PAIR_PREVIEW, PAIR_AUTHORIZE, PAIR_EXECUTE, PAIR_RECONCILE}),
    "recover-pair": frozenset({INSPECT, PAIR_PREVIEW, PAIR_AUTHORIZE, PAIR_EXECUTE, PAIR_RECONCILE}),
    "inspect-user": frozenset({INSPECT}), "reconcile-user": frozenset({USER_RECONCILE}),
    "reconcile-pair": frozenset({PAIR_RECONCILE}),
}
DISPATCH_CONTRACT = "fortipam_v4_radius_user_recovery_dispatch_v1"
MCP_TIMEOUT_SECONDS = 180.0


class RadiusUserRecoveryAcceptanceError(RuntimeError):
    """Value-free contract or acceptance failure."""


def _require(condition: bool) -> None:
    if not condition: raise RadiusUserRecoveryAcceptanceError("RADIUS User recovery contract rejected.")


def _validate_preview(body: dict[str, Any], *, pair: bool, preparation: bool = False) -> None:
    prefix = "radius-pair-recovery-" if pair else "radius-user-"
    _reference(body.get("preview_ref"), prefix + "preview-")
    _reference(body.get("requester_digest"), ""); _reference(body.get("summary_digest"), "")
    _fresh(body.get("expires_at"))
    current = body.get("Current State")
    _require(type(current) is dict and type(current.get("observed_at")) is int)
    assert isinstance(current, dict)
    observed = current["observed_at"]
    _require(observed <= time.time() < body["expires_at"] and body["expires_at"] == observed + 60)
    expected: dict[str, Any] = {"contract": PAIR_CONTRACT if pair else USER_CONTRACT,
        "policy_mode": "lab_auto", "summary_revision": 1, "preview_ref": body["preview_ref"],
        "expires_at": body["expires_at"], "requester_digest": body["requester_digest"],
        "environment": "privately_bound_disposable_lab", "summary_digest": body["summary_digest"],
        "assumptions": ["owner_authorized_disposable_lab_scope"], "device_write_executed": False}
    if pair:
        expected.update({"unchanged_boundary": ["other_identity_servers", "users_groups_and_roles"],
            "Current State": {"original_creation_ack_verified": True, "full_state_unchanged": True,
                "zero_references": True, "observed_at": observed, "associated_user_dual_absence_verified": True},
            "Proposed Changes": {"operation": "remove_original_owned_radius_pair_row", "material_access": False},
            "Expected State": {"exact_detail_absent": True, "complete_collection_absent": True},
            "dependencies": ["original_pair_creation_ack", "fresh_complete_unchanged_state", "independent_recovery_ledger",
                "fresh_original_user_dual_absence_before_final_dispatch"],
            "risk_and_effects": {"effect": "remove_original_pair_after_owned_user_absence"},
            "authorization_and_approval": {"mode": "standing_owner_lab_authority", "independent_human_approval": False},
            "facts": {"source": "original_pair_ack_and_fresh_full_cmdb_state", "freshness_seconds": 60},
            "unresolved_gaps": [], "verification": ["original_delete_ack", "dual_absence"],
            "compensation_and_stop": {"uncertain_result": "retain_claims_and_reconcile_without_replay"}})
        if preparation:
            expected["Current State"]["user_preparation_only_zero_claim"] = True
            expected["dependencies"].append("original_preparation_proof_without_declaration_repair")
            expected["risk_and_effects"]["effect"] = "remove_original_pair_after_unattempted_user_absence"
    else:
        expected.update({"Current State": {"fresh_source_and_ownership_verified": True, "observed_at": observed,
                "bound_user_absent": False, "original_user_ack_and_context_required": True},
            "Proposed Changes": {"operation": "remove_original_owned_remote_user", "scope": "one_privately_bound_remote_user",
                "material_access": False, "status": "disable", "profile": "Standard", "wildcard": False, "group_association": False},
            "Expected State": {"original_ack_and_full_state_required": True, "owned_user_retained": False,
                "dual_absence_required": True, "user_authentication_qualified": False, "automatic_failover_qualified": False},
            "facts": {"source": "fixed_build29_cmdb_projection", "freshness_seconds": 60},
            "authorization_and_approval": {"mode": "standing_owner_lab_authority", "active_m4_required": True,
                "independent_human_approval": False},
            "risk_and_effects": {"class": "C3", "effect": "remove_one_original_owned_identity_row"},
            "dependencies": ["original_user_ack_and_signed_context", "original_create_m4_store"],
            "unresolved_gaps": ["user_enable", "user_authentication", "automatic_failover", "group_mapping", "version_1_9_1"],
            "compensation_and_stop": {"recovery": "separate_original_ack_and_context_m4",
                "uncertain_result": "retain_claims_and_reconcile_without_replay"}})
    _exact(body, expected)
    _require(canonical_digest({k:v for k,v in body.items() if k != "summary_digest"}) == body["summary_digest"])


def _validate_authorization(body: dict[str, Any], preview: dict[str, Any], *, pair: bool) -> None:
    _reference(body.get("authorization_ref"), "radius-pair-recovery-auth-" if pair else "radius-user-auth-")
    _fresh(body.get("expires_at"))
    _exact(body, {"contract": PAIR_CONTRACT if pair else USER_CONTRACT, "policy_mode": "lab_auto",
        "authorization_ref": body["authorization_ref"], "expires_at": preview["expires_at"]})


def _validate_execution(body: dict[str, Any], *, pair: bool) -> None:
    _exact(body, {"contract": PAIR_CONTRACT if pair else USER_CONTRACT, "outcome": "succeeded",
        "verification": "verified", "compensation": "not_requested", "idempotent_replay": False})


def _validate_inspection(body: dict[str, Any], *, require_absent: bool = False) -> bool:
    mode, observation = body.get("evidence_mode"), body.get("observation")
    _require(mode in {"preparation_only_zero_claim", "unattempted", "consumed_create", "consumed_delete", "terminal_no_http_claim"})
    _require(observation in {"absent_observed", "present_observed"})
    absent = observation == "absent_observed"
    _require(absent or mode == "consumed_create")
    _exact(body, {"contract": "fortipam-radius-user-cleanup-observation-private-v1", "evidence_mode": mode,
        "observation": observation, "user_absence_verified": absent, "mutation_executed": False,
        "prior_m4_outcome_unchanged": True, "dispatch_retry_allowed": False, "user_ownership_or_delete_authority_granted": False})
    _require(not require_absent or absent)
    return mode == "preparation_only_zero_claim"


def _validate_reconciliation(body: dict[str, Any], *, pair: bool) -> None:
    expected: dict[str, Any] = {"contract": "fortipam-radius-associated-pair-delete-reconciliation-private-v1" if pair
        else "fortipam-radius-user-delete-reconciliation-private-v1", "user_absence_verified": True,
        "mutation_executed": False, "prior_m4_outcome_unchanged": True, "dispatch_retry_allowed": False}
    if pair: expected["pair_absence_verified"] = True
    else: expected["pair_cleanup_performed"] = False
    _exact(body, expected)


def _reserve_dispatch(path: Path, mode: str) -> None:
    _new_dispatch_path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077)
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({"contract": DISPATCH_CONTRACT, "mode": mode, "dispatch_reserved": True, "retry_allowed": False}, stream)
            stream.flush(); os.fsync(stream.fileno())
        os.fsync(directory)
    finally: os.close(directory)


async def run_radius_remote_user_recovery_mcp_oauth_acceptance(url: str, login_file: Path,
        client_state_file: Path, *, mode: str, dispatch_state_file: Path | None = None,
        ca_file: Path | None = None) -> dict[str, object]:
    reserved = revoked = user_removed = pair_removed = observed = reconciled = False
    phase = "preflight"
    login: dict[str, str] = {}
    try:
        _require(mode in MODES)
        mutation = mode in MUTATING
        _require((dispatch_state_file is not None) is mutation)
        if dispatch_state_file is not None: _new_dispatch_path(dispatch_state_file)
        for path in (login_file, client_state_file):
            _protected_parent(path); info = path.stat()
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077)
        paths = [login_file, client_state_file] + ([dispatch_state_file] if dispatch_state_file is not None else [])
        _require(len({p.resolve() for p in paths}) == len(paths))
        parsed = oauth._validate_https_mcp_url(url)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", "")); issuer = f"{origin}{parsed.path}/oauth"
        login = _login(login_file)
        verify: str | bool = str(ca_file) if ca_file is not None else True
        async with httpx2.AsyncClient(timeout=30.0, follow_redirects=False, trust_env=False, verify=verify) as client:
            phase = "oauth"
            token, registered, reused, client_id = await oauth._oauth_token(client, url=url, origin=origin, issuer=issuer,
                username=login["username"], password=login["password"], client_state_file=client_state_file,
                include_operation_scope=mutation, require_existing_client=True)
            login.clear()
            try:
                _require(registered is False and reused is True)
                async with oauth._mcp_session(url, token, verify, timeout_seconds=MCP_TIMEOUT_SECONDS) as session:
                    phase = "discovery"
                    await session.initialize()
                    _require(MODE_TOOLS[mode] <= {tool.name for tool in (await session.list_tools()).tools})
                    if mode in {"inspect-user", "recover-pair"}:
                        phase = "user_inspection"
                        inspection = _body(await session.call_tool(INSPECT, {}))
                        preparation = _validate_inspection(inspection, require_absent=mutation)
                        observed = True
                    else: preparation = False
                    if mode.startswith("reconcile-"):
                        pair = mode == "reconcile-pair"; phase = "pair_reconciliation" if pair else "user_reconciliation"
                        result = _body(await session.call_tool(PAIR_RECONCILE if pair else USER_RECONCILE, {}))
                        _validate_reconciliation(result, pair=pair); reconciled = True
                    if mutation:
                        requester = None
                        for pair in ([False, True] if mode == "recover-user-pair" else [True]):
                            stage = "pair" if pair else "user"
                            phase = stage + "_preview"
                            preview = _body(await session.call_tool(PAIR_PREVIEW if pair else USER_PREVIEW, {}))
                            _validate_preview(preview, pair=pair, preparation=preparation)
                            if requester is not None: _require(preview["requester_digest"] == requester)
                            requester = preview["requester_digest"]
                            phase = stage + "_authorization"
                            auth = _body(await session.call_tool(PAIR_AUTHORIZE if pair else USER_AUTHORIZE,
                                {"preview_ref": preview["preview_ref"]}))
                            _validate_authorization(auth, preview, pair=pair)
                            if not reserved:
                                assert dispatch_state_file is not None
                                _reserve_dispatch(dispatch_state_file, mode); reserved = True
                            phase = stage + "_execution"
                            _fresh(auth["expires_at"])
                            result = _body(await session.call_tool(PAIR_EXECUTE if pair else USER_EXECUTE,
                                {"authorization_ref": auth["authorization_ref"]}))
                            _validate_execution(result, pair=pair)
                            if pair: pair_removed = True
                            else: user_removed = True
                            phase = stage + "_reconciliation"
                            result = _body(await session.call_tool(PAIR_RECONCILE if pair else USER_RECONCILE, {}))
                            _validate_reconciliation(result, pair=pair); reconciled = True
                            if not pair:
                                phase = "user_inspection"
                                inspection = _body(await session.call_tool(INSPECT, {}))
                                _validate_inspection(inspection, require_absent=True)
                                _require(inspection["evidence_mode"] == "consumed_delete"); observed = True
            finally:
                revoked = await oauth._revoke_and_prove_401(client, url, issuer, token, client_id)
                _require(revoked)
    except (Exception, BaseExceptionGroup, asyncio.CancelledError):
        reserved = reserved or (dispatch_state_file is not None and dispatch_state_file.exists())
        raise RadiusUserRecoveryAcceptanceError(f"RADIUS User recovery acceptance failed: phase={phase}; "
            f"dispatch_reserved={str(reserved).lower()}; reconciliation_required={str(reserved).lower()}; "
            f"token_revoked_and_401_verified={str(revoked).lower()}; retry_allowed=false.") from None
    finally: login.clear()
    return {"contract": "fortipam_v4_radius_user_recovery_mcp_oauth_acceptance_v1", "mode": mode,
        "oauth_metadata_verified": True, "existing_client_reused": True, "dynamic_client_registration_performed": False,
        "mcp_initialized": True, "user_remove_reported_verified": user_removed, "pair_remove_reported_verified": pair_removed,
        "user_cleanup_observation_verified": observed, "read_only_reconciliation_verified": reconciled,
        "dispatch_reserved": reserved, "prior_m4_outcomes_reported_unchanged": True, "retry_allowed": False,
        "token_revoked": True, "revoked_access_rejected": True, "user_authentication_qualified": False,
        "automatic_failover_qualified": False, "credential_values_returned": False, "raw_response_returned": False,
        "references_returned": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--mode", choices=MODES, required=True)
    for name in ("login-file", "client-state-file", "dispatch-state-file", "ca-file"):
        parser.add_argument("--" + name, type=Path, required=name in {"login-file", "client-state-file"})
    args = parser.parse_args()
    try: result = asyncio.run(run_radius_remote_user_recovery_mcp_oauth_acceptance(**vars(args)))
    except RadiusUserRecoveryAcceptanceError as error: raise SystemExit(str(error)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__": main()
