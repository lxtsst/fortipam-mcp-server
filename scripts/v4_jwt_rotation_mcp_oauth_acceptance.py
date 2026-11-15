#!/usr/bin/env python3
"""Accept the fixed JWT identity/rotation graph through an existing OAuth client."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import time
from typing import Any
from urllib.parse import urlunsplit

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx2
from v4_planning import canonical_digest
from scripts import v4_https_oauth_acceptance as oauth
from scripts.v4_jwt_manual_key_owner_mcp_oauth_acceptance import _body, _exact, _ref
from scripts.v4_radius_server_pair_lifecycle_mcp_oauth_acceptance import _protected_parent, _login, _new_dispatch_path

CONTRACT = "fortipam-build29-jwt-rotation-workflow-v5"
DIAGNOSTIC_CONTRACT = "fortipam-build29-manual-jwt-update-discriminator-v3"
PREVIEW = "preview_v4_jwt_manual_rotation_700"
AUTHORIZE = "authorize_v4_jwt_manual_rotation_700"
EXECUTE = "execute_v4_jwt_manual_rotation_700"
TOOLS = frozenset({PREVIEW, AUTHORIZE, EXECUTE})


class JwtRotationAcceptanceError(RuntimeError):
    """Categorical failure; retain all consumed client and server records."""
    stage: str | None = None
    dispatch_reserved: bool = False
    token_revoked_and_401_verified: bool = False


def _require(condition: bool) -> None:
    if not condition:
        raise JwtRotationAcceptanceError("JWT rotation acceptance contract rejected.")


def _fresh(value: Any) -> None:
    _require(type(value) is int and time.time() < value <= time.time()+300)


def _validate_preview(body: dict[str, Any], *, activation_diagnostic: bool = False) -> None:
    _ref(body.get("preview_ref"), "jwt-rotation-preview-", 32); _fresh(body.get("expires_at"))
    _require(type(body.get("Current State")) is dict)
    digest = body["Current State"].get("digest"); _ref(digest, ""); _ref(body.get("summary_digest"), "")
    expected: dict[str,Any] = {"contract":DIAGNOSTIC_CONTRACT if activation_diagnostic else CONTRACT,"policy_mode":"lab_auto","preview_ref":body["preview_ref"],
        "expires_at":body["expires_at"],"Current State":{"original_key_custody_verified":True,"jwt_user_absent":True,"digest":digest},
        "Proposed Changes":{"fixed_child_sequence":["user-create","user-initialize","overlap","cutover","restore","user-remove"],
            "owned_user_api_key_initialization":True,"generated_api_key_discarded":True,
            "overlap_submission_order":["new","old"],
            "maximum_native_mutations":6,"claim_match":"exact","lease_minutes":10,"private_assertion_algorithm":"RS256","secret_acl_changes":False},
        "Expected State":{"original_key_restored":True,"owned_jwt_user_absent":True,"authentication_and_lease_effects_observed":True},
        "recovery":"unused_original_owned_restore_then_user_removal_only_no_native_replay",
        "device_write_executed":False,"summary_digest":body["summary_digest"]}
    if activation_diagnostic:
        expected["Proposed Changes"]["failed_overlap_path"] = "single_new_key_probe_then_original_restore"
        expected["Proposed Changes"]["assertion_connection_policy"] = "new_verified_client_per_assertion"
        expected["Proposed Changes"]["runtime_sample_offsets_after_poststate_ms"] = [0,1000,4000]
        expected["Proposed Changes"]["maximum_authentication_requests"] = 32
        expected["Proposed Changes"]["maximum_lease_checks"] = 64
        expected["Expected State"]["rotation_accepted"] = False
    else:
        expected["Proposed Changes"].update(assertion_connection_policy="new_verified_client_per_assertion",
            runtime_readiness_offsets_after_poststate_ms=[0,1000,4000],maximum_authentication_requests=32,
            maximum_lease_checks=64,post_removal_denial_offsets_ms=[0,1000,4000],unqualified_http401_is_revocation_evidence=False)
    _exact(body, expected)
    _require(body["summary_digest"] == canonical_digest({k:v for k,v in body.items() if k != "summary_digest"}))


def _validate_authorization(body: dict[str, Any], preview: dict[str, Any], *, activation_diagnostic: bool = False) -> None:
    _ref(body.get("authorization_ref"), "jwt-rotation-auth-"); _fresh(body.get("expires_at"))
    _exact(body, {"contract":DIAGNOSTIC_CONTRACT if activation_diagnostic else CONTRACT,"policy_mode":"lab_auto","authorization_ref":body["authorization_ref"],"expires_at":preview["expires_at"]})


def _validate_execution(body: dict[str, Any], *, activation_diagnostic: bool = False) -> None:
    _require(body.get("existing_old_lease_after_cutover") in {"still-valid", "denied"})
    expected: dict[str,Any] = {"contract":DIAGNOSTIC_CONTRACT if activation_diagnostic else CONTRACT,"outcome":"succeeded","verification":"verified","idempotent_replay":False,
        "original_key_restored_and_user_absent":True,"existing_old_lease_after_cutover":body["existing_old_lease_after_cutover"],
        "overlap_authentication":{"old":True,"new":True},
        "all_issued_leases_denied_after_user_removal":True,"failure_stage":None,"native_phase_claims":6,
        "all_candidate_gates_closed":True,"owner_logout_and_cookie_rejection":True,"private_assertions_and_leases_cleared":True}
    if activation_diagnostic:
        for name in ("overlap_authentication","single_new_key_authentication"):
            value = body.get(name)
            _require(type(value) is dict and set(value) == {"old","new"} and all(type(v) is bool for v in value.values()))
            expected[name] = value
        expected.update(rotation_accepted=False,activation_discriminator_completed=True)
    samples = body.get("runtime_samples")
    if type(samples) is not dict or set(samples) != {"overlap","cutover","restore"}:
        raise JwtRotationAcceptanceError("JWT runtime observation contract rejected.")
    for phase,rows in samples.items():
        _require(type(rows) is list and 1<=len(rows)<=3 and (not activation_diagnostic or len(rows) == 3))
        for offset,row in zip((0,1000,4000),rows):
            _require(type(row) is dict and set(row) == {"requested_offset_ms","observed_offset_ms","old","new"})
            _require(type(row["requested_offset_ms"]) is int and row["requested_offset_ms"] == offset
                and type(row["observed_offset_ms"]) is int and offset<=row["observed_offset_ms"]<=30000
                and type(row["old"]) is bool and type(row["new"]) is bool)
        if not activation_diagnostic:
            predicate = {"old":phase != "cutover","new":phase != "restore"}
            _require({k:rows[-1][k]for k in predicate} == predicate)
            _require(all({k:row[k]for k in predicate} != predicate for row in rows[:-1]))
    if activation_diagnostic:
        for phase,name in (("overlap","overlap_authentication"),("cutover","single_new_key_authentication")):
            _require({k:samples[phase][-1][k]for k in ("old","new")} == body[name])
    _require(samples["restore"][-1]["old"] is True and samples["restore"][-1]["new"] is False)
    expected["runtime_samples"] = samples
    if not activation_diagnostic:
        removal = body.get("post_removal_samples")
        if type(removal) is not list or not 1<=len(removal)<=3:
            raise JwtRotationAcceptanceError("JWT removal observation contract rejected.")
        for offset,row in zip((0,1000,4000),removal):
            _require(type(row) is dict and set(row) == {"requested_offset_ms","observed_offset_ms","qualified_denial","unqualified_http401"}
                and type(row["requested_offset_ms"]) is int and row["requested_offset_ms"] == offset
                and type(row["observed_offset_ms"]) is int and offset<=row["observed_offset_ms"]<=30000
                and type(row["qualified_denial"]) is bool and type(row["unqualified_http401"]) is bool)
        _require(removal[-1]["qualified_denial"] is True and removal[-1]["unqualified_http401"] is False
            and not any(row["qualified_denial"]for row in removal[:-1]))
        expected["post_removal_samples"] = removal
    _exact(body, expected)


def _reserve(path: Path, *, activation_diagnostic: bool = False) -> None:
    _new_dispatch_path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            contract = "fortipam-jwt-update-discriminator-client-dispatch-v3" if activation_diagnostic else "fortipam-jwt-rotation-client-dispatch-v5"
            json.dump({"contract":contract,"dispatch_reserved":True,"retry_allowed":False},stream)
            stream.flush(); os.fsync(stream.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)


async def run_jwt_rotation_mcp_oauth_acceptance(url: str, login_file: Path,
        client_state_file: Path, dispatch_state_file: Path, *, ca_file: Path | None = None,
        activation_diagnostic: bool = False) -> dict[str, object]:
    stage = "inputs"; reserved = revoked = False; login: dict[str, str] = {}
    try:
        _require(type(activation_diagnostic) is bool)
        _new_dispatch_path(dispatch_state_file)
        for path in (login_file, client_state_file):
            _protected_parent(path); info = path.stat()
            _require(path.is_file() and not info.st_mode & 0o077 and info.st_nlink == 1)
        _require(len({p.resolve() for p in (login_file, client_state_file, dispatch_state_file)}) == 3)
        parsed = oauth._validate_https_mcp_url(url)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", "")); issuer = origin + parsed.path + "/oauth"
        login = _login(login_file); verify: str | bool = str(ca_file) if ca_file is not None else True
        async with httpx2.AsyncClient(timeout=30, follow_redirects=False, trust_env=False, verify=verify) as client:
            stage = "oauth"
            token, registered, reused, client_id = await oauth._oauth_token(client, url=url, origin=origin, issuer=issuer,
                username=login["username"], password=login["password"], client_state_file=client_state_file,
                include_operation_scope=True, require_existing_client=True)
            login.clear()
            try:
                _require(registered is False and reused is True)
                async with oauth._mcp_session(url, token, verify, timeout_seconds=480) as session:
                    stage = "discovery"; await session.initialize()
                    _require(TOOLS <= {t.name for t in (await session.list_tools()).tools})
                    stage = "preview"; preview = _body(await session.call_tool(PREVIEW, {})); _validate_preview(preview,activation_diagnostic=activation_diagnostic)
                    stage = "authorization"
                    authorization = _body(await session.call_tool(AUTHORIZE, {"preview_ref":preview["preview_ref"]}))
                    _validate_authorization(authorization, preview,activation_diagnostic=activation_diagnostic)
                    stage = "reservation"; _reserve(dispatch_state_file,activation_diagnostic=activation_diagnostic); reserved = True; _fresh(authorization["expires_at"])
                    stage = "execution"
                    result = _body(await session.call_tool(EXECUTE, {"authorization_ref":authorization["authorization_ref"]}))
                    _validate_execution(result,activation_diagnostic=activation_diagnostic)
            finally:
                revoked = await oauth._revoke_and_prove_401(client, url, issuer, token, client_id); _require(revoked)
    except (Exception, BaseExceptionGroup):
        failure = JwtRotationAcceptanceError(f"JWT rotation acceptance failed: stage={stage}; dispatch_reserved={str(reserved or dispatch_state_file.exists()).lower()}; "
            f"token_revoked_and_401_verified={str(revoked).lower()}; retry_allowed=false.")
        failure.stage, failure.dispatch_reserved, failure.token_revoked_and_401_verified = stage,reserved or dispatch_state_file.exists(),revoked
        raise failure from None
    finally:
        login.clear()
    proof: dict[str,object] = {"contract":"fortipam-jwt-rotation-mcp-acceptance-v5","completed":True,"ordinary_oauth_mcp_verified":True,
        "one_parent_dispatch_reserved":True,"six_native_phase_claims":True,"authentication_effects_verified":True,
        "existing_old_lease_after_cutover":result["existing_old_lease_after_cutover"],
        "original_key_restored_and_user_absent":True,"all_issued_leases_denied_after_user_removal":True,
        "token_revoked_and_401_verified":True,"independent_device_readback_verified":False,
        "server_process_and_listener_closure_verified":False,"raw_values_returned":False,"retry_allowed":False,
        "runtime_samples":result["runtime_samples"]}
    if activation_diagnostic:
        proof.update(contract="fortipam-jwt-update-discriminator-mcp-acceptance-v3",rotation_accepted=False,
            overlap_authentication=result["overlap_authentication"],single_new_key_authentication=result["single_new_key_authentication"],
            runtime_samples=result["runtime_samples"])
    else:
        proof["post_removal_samples"] = result["post_removal_samples"]
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--url", required=True)
    for name in ("login-file", "client-state-file", "dispatch-state-file"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--activation-diagnostic", action="store_true")
    try:
        result = asyncio.run(run_jwt_rotation_mcp_oauth_acceptance(**vars(parser.parse_args())))
    except JwtRotationAcceptanceError as error:
        raise SystemExit(str(error)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
