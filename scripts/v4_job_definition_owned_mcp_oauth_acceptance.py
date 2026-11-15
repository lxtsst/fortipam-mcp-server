#!/usr/bin/env python3
"""Accept one configured Owned disabled Job phase using an existing HTTPS OAuth client.

No key, product login, selector or source metadata is accepted over MCP. Keep the
client dispatch marker and original server records after every uncertain result.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
from urllib.parse import urlunsplit

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx2
from v4_planning import canonical_digest
from scripts import v4_https_oauth_acceptance as oauth
from scripts.v4_radius_server_pair_lifecycle_mcp_oauth_acceptance import _protected_parent, _login, _new_dispatch_path

CONTRACT = "fortipam-build29-owned-disabled-job-v3"
DISPATCH_CONTRACT = "fortipam-owned-job-client-dispatch-v3"
PREVIEW = "preview_v4_owned_disabled_job_700"
AUTHORIZE = "authorize_v4_owned_disabled_job_700"
EXECUTE = "execute_v4_owned_disabled_job_700"
TOOLS = frozenset({PREVIEW, AUTHORIZE, EXECUTE})


class JobOwnedAcceptanceError(RuntimeError):
    """Categorical client failure without raw replies or references."""


def _require(condition: bool) -> None:
    if not condition:
        raise JobOwnedAcceptanceError("Owned disabled Job acceptance contract rejected.")


def _exact(value: Any, expected: dict[str, Any]) -> None:
    _require(type(value) is dict and set(value) == set(expected))
    for name, wanted in expected.items():
        if type(wanted) is dict:
            _exact(value[name], wanted)
        else:
            _require(type(value[name]) is type(wanted) and value[name] == wanted)


def _body(reply: Any) -> dict[str, Any]:
    _require(getattr(reply, "is_error", True) is False)
    result = getattr(reply, "structured_content", None)
    _require(type(result) is dict)
    assert isinstance(result, dict)
    return result


def _ref(value: Any, prefix: str, size: int = 64) -> None:
    _require(type(value) is str and re.fullmatch(re.escape(prefix) + "[0-9a-f]{" + str(size) + "}", value) is not None)


def _fresh(value: Any) -> None:
    _require(type(value) is int and time.time() < value <= time.time() + 120)


def _validate_preview(body: dict[str, Any], phase: str) -> None:
    _require(phase in {"create", "recover"})
    _ref(body.get("preview_ref"), "job-preview-"); _fresh(body.get("expires_at"))
    _require(type(body.get("Current State")) is dict and type(body.get("Expected State")) is dict)
    current, expected = body["Current State"].get("digest"), body["Expected State"].get("digest")
    dependency = body["Current State"].get("dependency_digest")
    for value in (current,expected,dependency,body.get("summary_digest")):_ref(value, "")
    _exact(body, {"contract":CONTRACT, "phase":phase, "policy_mode":"lab_auto",
        "preview_ref":body["preview_ref"], "expires_at":body["expires_at"],
        "Current State":{"digest":current,"dependency_digest":dependency,"global_absence":phase == "create",
            "original_terminal_full_custody":phase == "recover"},
        "Proposed Changes":{"operation":"create_disabled_job" if phase == "create" else "remove_original_owned_job",
            "maximum_native_mutations":1,"activation_or_execution":False,"credential_or_policy_changes":False,
            "close_write_channel_before_readback":True,"wad_publication_delay_ms":3000},
        "Expected State":{"digest":expected,"complete_pristine_state_or_global_absence":True,"original_records_preserved":True},
        "recovery":"separate_fresh_m4_original_constructor_ack_full_state_only_no_replay",
        "device_write_executed":False,"summary_digest":body["summary_digest"]})
    _require(body["summary_digest"] == canonical_digest({k:v for k,v in body.items() if k != "summary_digest"}))


def _validate_authorization(body: dict[str, Any], preview: dict[str, Any]) -> None:
    _ref(body.get("authorization_ref"), "job-auth-"); _fresh(body.get("expires_at"))
    _exact(body, {"contract":CONTRACT,"phase":preview["phase"],"policy_mode":"lab_auto",
        "authorization_ref":body["authorization_ref"],"expires_at":preview["expires_at"]})


def _validate_execution(body: dict[str, Any], phase: str) -> None:
    _exact(body, {"contract":CONTRACT,"phase":phase,"outcome":"succeeded",
        "verification":"verified","idempotent_replay":False,
        "complete_pristine_state_or_global_absence":True,"original_records_preserved":True,
        "original_store_read_only":phase == "recover","activation_or_execution":False,"native_claim_count":1,
        "write_channel_closed_before_readback":True,"wad_publication_delay_observed":True,
        "source_failure":{"source_reader_phase":None,"reader_failure_stage":None},
        "all_candidate_gates_closed":True,"owner_logout_verified":True})


def _reserve(path: Path, phase: str) -> None:
    _new_dispatch_path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            json.dump({"contract":DISPATCH_CONTRACT,"phase":phase,"dispatch_reserved":True,"retry_allowed":False},stream)
            stream.flush(); os.fsync(stream.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)


async def run_job_definition_owned_mcp_oauth_acceptance(url: str, login_file: Path,
        client_state_file: Path, dispatch_state_file: Path, *, phase: str,
        ca_file: Path | None = None) -> dict[str, object]:
    stage = "inputs"; reserved = revoked = False; login: dict[str, str] = {}
    try:
        _require(phase in {"create", "recover"})
        _new_dispatch_path(dispatch_state_file)
        for path in (login_file, client_state_file):
            _protected_parent(path)
            info = path.stat()
            _require(path.is_file() and not info.st_mode & 0o077 and info.st_nlink == 1)
        _require(len({p.resolve() for p in (login_file, client_state_file, dispatch_state_file)}) == 3)
        parsed = oauth._validate_https_mcp_url(url)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", "")); issuer = origin + parsed.path + "/oauth"
        login = _login(login_file)
        verify: str | bool = str(ca_file) if ca_file is not None else True
        async with httpx2.AsyncClient(timeout=30, follow_redirects=False, trust_env=False, verify=verify) as client:
            stage = "oauth"
            token, registered, reused, client_id = await oauth._oauth_token(client, url=url, origin=origin, issuer=issuer,
                username=login["username"], password=login["password"], client_state_file=client_state_file,
                include_operation_scope=True, require_existing_client=True)
            login.clear()
            try:
                _require(registered is False and reused is True)
                async with oauth._mcp_session(url, token, verify, timeout_seconds=180) as session:
                    stage = "discovery"; await session.initialize()
                    _require(TOOLS <= {t.name for t in (await session.list_tools()).tools})
                    stage = "preview"; preview = _body(await session.call_tool(PREVIEW, {})); _validate_preview(preview, phase)
                    stage = "authorization"
                    authorization = _body(await session.call_tool(AUTHORIZE, {"preview_ref":preview["preview_ref"]}))
                    _validate_authorization(authorization, preview)
                    stage = "reservation"; _reserve(dispatch_state_file, phase); reserved = True
                    _fresh(authorization["expires_at"])
                    stage = "execution"
                    result = _body(await session.call_tool(EXECUTE, {"authorization_ref":authorization["authorization_ref"]}))
                    _validate_execution(result, phase)
            finally:
                revoked = await oauth._revoke_and_prove_401(client, url, issuer, token, client_id)
                _require(revoked)
    except (Exception, BaseExceptionGroup):
        raise JobOwnedAcceptanceError(f"Owned disabled Job acceptance failed: stage={stage}; dispatch_reserved={str(reserved or dispatch_state_file.exists()).lower()}; "
            f"token_revoked_and_401_verified={str(revoked).lower()}; retry_allowed=false.") from None
    finally:
        login.clear()
    return {"contract":"fortipam-owned-job-mcp-acceptance-v1","phase":phase,
        "completed":True,"ordinary_oauth_mcp_verified":True,"one_dispatch_reserved":True,
        "server_fixed_readback_verified":True,"token_revoked_and_401_verified":True,
        "activation_or_execution":False,"original_full_custody_required":True,
        "server_process_and_listener_closure_verified":False,"raw_values_returned":False,"retry_allowed":False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--phase", choices=("create", "recover"), required=True)
    for name in ("login-file", "client-state-file", "dispatch-state-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    try:
        result = asyncio.run(run_job_definition_owned_mcp_oauth_acceptance(**vars(parser.parse_args())))
    except JobOwnedAcceptanceError as error:
        raise SystemExit(str(error)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
