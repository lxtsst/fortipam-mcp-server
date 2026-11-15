"""Real startup, OAuth/MCP and M4 join with a synthetic native product peer."""
import asyncio
from dataclasses import asdict, replace
import hashlib
import json
import os
import time

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import jwt_manual_key_owner_runtime as runtime
from fortipam_mcp.http_server import create_http_app
from fortipam_mcp.jwt_manual_key_contract import _default_digest
from fortipam_mcp.jwt_manual_key_owner_http import JwtManualKeyOwnerHttp
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_ems_tag_principal_binding import settings
from test_ems_tag_mcp_oauth import headers, rpc, data
from test_http_server import _v4_environment
from test_jwt_manual_key_owner_http import Lab
from test_jwt_manual_key_contract import defaults, public_pem, synthetic_key
from scripts import v4_jwt_manual_key_owner_mcp_oauth_acceptance as acceptance

TOOLS = {v + "_v4_jwt_manual_key_owner_700" for v in ("preview", "authorize", "execute")}
SCOPE = "fortipam:read fortipam:plan fortipam:operate"


def call(client, token, verb, **arguments):
    return rpc(client, token, "tools/call", {"name": verb + "_v4_jwt_manual_key_owner_700", "arguments": arguments})


def setup(root, key, monkeypatch, *, fault="none", execution=True):
    cfg = settings(root)
    with TestClient(create_http_app(cfg), base_url="https://mcp.example.com") as client:
        token = headers(client, SCOPE)
        assert not TOOLS & {t["name"] for t in rpc(client, token, "tools/list")["tools"]}
    bearer = next(v for k, v in token.items() if k.lower() == "authorization").removeprefix("Bearer ")
    access = asyncio.run(LocalOAuthProvider(cfg.local_oauth).load_access_token(bearer))
    principal = planning_principal_from_access_token(access, cfg.v4_planning_authorization)
    candidate = root / "candidate"; candidate.mkdir(mode=0o700)
    lab = Lab(candidate, key, monkeypatch, fault)
    lab.wire.rename(candidate / "native"); lab.wire = candidate / "native"
    for directory in ("create-authority", "remove-authority"):
        (candidate / directory).mkdir(mode=0o700)
    for i, name in enumerate(runtime._KEYS):
        path = candidate / (name + ".key"); path.write_bytes(bytes([65 + i]) * 32); path.chmod(0o600)
    lab.ca.chmod(0o600)
    protected = candidate / "public.pem"; protected.write_bytes(public_pem(key)); protected.chmod(0o600)
    env = {runtime.OWNER_PREFIX + "SESSION_ENABLED":"true",
        runtime.OWNER_PREFIX + "LOGIN_ENV_FILE":str(candidate / "owner.env"),
        runtime.OWNER_PREFIX + "USERNAME_VARIABLE":"TEST_OWNER", runtime.OWNER_PREFIX + "PASSWORD_VARIABLE":"TEST_PASSWORD"}
    login = candidate / "owner.env"; login.write_text("TEST_OWNER=synthetic-owner\nTEST_PASSWORD=synthetic-password\n"); login.chmod(0o600)
    # The native peer's Owner is fixed by its synthetic role fixtures.
    login.write_text("TEST_OWNER=" + lab.config.owner_name + "\nTEST_PASSWORD=synthetic-password\n")
    reference = hashlib.sha256(json.dumps(env, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    lab.config = replace(lab.config, credential_reference_digest=reference,
        requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
    manifest = {"contract":runtime.CONTRACT, "phase":"create", "wire":asdict(lab.config),
        "binding":{"name":lab.request._name, "nonce":"a"*64, "schema_digest":lab.request.schema_digest,
            "serial_digest":lab.request.serial_digest, "defaults":defaults(),
            "public_key_digest":hashlib.sha256(public_pem(key)).hexdigest()},
        "identity":{"environment_ref":"synthetic-jwt-lab", "scope_ref":"synthetic-jwt-key", "audience_ref":"synthetic-jwt-client"},
        "public_key_file":str(protected)}
    manifest_path = candidate / "startup.create.json"; manifest_path.write_text(json.dumps(manifest)); manifest_path.chmod(0o600)
    env.update({runtime.PREFIX+"ENABLED":"true",runtime.PREFIX+"EXECUTION_ENABLED":str(execution).lower(),
        runtime.PREFIX+"STARTUP_MANIFEST_FILE":str(manifest_path)})
    init = JwtManualKeyOwnerHttp.__init__
    def synthetic_product(self, *args, **kwargs):
        kwargs.update(client_factory=lab.factory, clock=lambda:int(time.time()))
        return init(self, *args, **kwargs)
    monkeypatch.setattr(JwtManualKeyOwnerHttp, "__init__", synthetic_product)
    return cfg, token, principal, lab, env, manifest, manifest_path


@pytest.mark.parametrize("fault", ["none", "bad-post", "403", "timeout"])
def test_real_oauth_entry_native_custody_and_independent_original_recovery(tmp_path, synthetic_key, monkeypatch, fault):
    cfg, token, principal, lab, env, manifest, path = setup(tmp_path, synthetic_key, monkeypatch, fault=fault)
    action = runtime.build_jwt_manual_key_owner_candidate(env)
    assert action is not None and not lab.calls and action._workflow is None
    with TestClient(create_http_app(cfg, v4_jwt_owner_candidate_action=action), base_url="https://mcp.example.com") as client:
        entries = {t["name"]:t for t in rpc(client, token, "tools/list")["tools"] if t["name"] in TOOLS}
        assert set(entries) == TOOLS
        assert all(t["inputSchema"]["additionalProperties"] is False for t in entries.values())
        assert not entries["preview_v4_jwt_manual_key_owner_700"]["inputSchema"].get("properties")
        other = headers(client, SCOPE)
        assert call(client, other, "preview")["isError"] and not lab.calls
        assert call(client, token, "preview", key="SYNTHETIC_MATERIAL")["isError"] and not lab.calls
        plan_only = headers(client, "fortipam:read fortipam:plan")
        assert call(client, plan_only, "preview")["isError"] and not lab.calls
        preview = data(call(client, token, "preview"))
        acceptance._validate_preview(preview, "create")
        assert preview["Current State"]["owner_context_verified"] and lab.posts == 0
        authorization = data(call(client, token, "authorize", preview_ref=preview["preview_ref"]))
        acceptance._validate_authorization(authorization, preview)
        result = data(call(client, token, "execute", authorization_ref=authorization["authorization_ref"]))
        assert result["outcome"] == ("succeeded" if fault == "none" else "reconciliation_required")
        if fault == "none": acceptance._validate_execution(result, "create")
        assert action._closed and not action._enabled and not action._workflow._source._enabled
        assert action._workflow._source.logout_verified and lab.posts == 1
        assert call(client, token, "execute", authorization_ref=authorization["authorization_ref"])["isError"]
        assert lab.posts == 1 and all(c.is_closed for c in lab.clients)
    creator_claim = (lab.wire / "create.claim.json").read_bytes()
    creator_grant = (path.parent / "create-authority/grant.json").read_bytes()
    protected = path.parent / "public.pem"; protected.unlink()
    manifest["phase"] = "remove"
    removal = path.parent / "startup.remove.json"; removal.write_text(json.dumps(manifest)); removal.chmod(0o600)
    env[runtime.PREFIX + "STARTUP_MANIFEST_FILE"] = str(removal)
    lab.fault = "none"
    recovery = runtime.build_jwt_manual_key_owner_candidate(env)
    reads_before = lab.full_reads; calls_before = len(lab.calls)
    with TestClient(create_http_app(cfg, v4_jwt_owner_candidate_action=recovery), base_url="https://mcp.example.com") as client:
        if fault in {"403", "timeout"}:
            assert call(client, token, "preview")["isError"]
            assert len(lab.calls) == calls_before and lab.full_reads == reads_before and lab.deletes == 0
        else:
            preview = data(call(client, token, "preview"))
            acceptance._validate_preview(preview, "remove")
            assert preview["Current State"]["original_creation_qualified"]
            authorization = data(call(client, token, "authorize", preview_ref=preview["preview_ref"]))
            acceptance._validate_authorization(authorization, preview)
            result = data(call(client, token, "execute", authorization_ref=authorization["authorization_ref"]))
            assert result["outcome"] == "succeeded" and lab.deletes == 1 and not lab.exists
            acceptance._validate_execution(result, "remove")
            assert recovery._workflow._creator_store._read_only
            assert recovery._workflow._source._request._closed and not recovery._workflow._source._request._body
            assert recovery._workflow._source.logout_verified
    assert (lab.wire / "create.claim.json").read_bytes() == creator_claim
    assert (path.parent / "create-authority/grant.json").read_bytes() == creator_grant


def test_startup_is_closed_and_does_not_resolve_any_provider(monkeypatch):
    monkeypatch.setattr(runtime, "_manifest", lambda *_:pytest.fail("Disabled profile opened a manifest"))
    assert runtime.build_jwt_manual_key_owner_candidate({}) is None
    for flags in ({"EXECUTION_ENABLED":"true"}, {"ENABLED":"TRUE"}, {"ENABLED":True}):
        with pytest.raises(ValueError): runtime.build_jwt_manual_key_owner_candidate({runtime.PREFIX+k:v for k,v in flags.items()})


@pytest.mark.parametrize("mode", ["closed", "manifest-drift", "missing-public-key", "wrong-public-key", "shutdown"])
def test_provider_policy_drift_and_shutdown_never_dispatch(tmp_path, synthetic_key, monkeypatch, mode):
    cfg, token, _, lab, env, manifest, path = setup(tmp_path, synthetic_key, monkeypatch, execution=mode != "closed")
    action = runtime.build_jwt_manual_key_owner_candidate(env)
    with TestClient(create_http_app(cfg, v4_jwt_owner_candidate_action=action), base_url="https://mcp.example.com") as client:
        if mode == "missing-public-key": (path.parent / "public.pem").unlink()
        if mode == "wrong-public-key": (path.parent / "public.pem").write_bytes(b"PRIVATE_KEY_IS_NOT_ACCEPTED")
        if mode in {"missing-public-key", "wrong-public-key"}:
            assert call(client, token, "preview")["isError"] and not lab.calls
        else:
            preview = data(call(client, token, "preview"))
            if mode == "manifest-drift": path.write_text(json.dumps({**manifest,"phase":"remove"}))
            if mode != "shutdown":
                assert call(client, token, "authorize", preview_ref=preview["preview_ref"])["isError"]
    assert lab.posts == lab.deletes == 0 and action._closed
    assert not any(c for c in lab.clients if not c.is_closed)
    if action._workflow is not None: assert action._workflow._source.logout_verified


@pytest.mark.parametrize("app_failure", [False, True])
def test_normal_main_composes_and_closes_the_exact_candidate(tmp_path, synthetic_key, monkeypatch, app_failure):
    from fortipam_mcp import http_server
    import uvicorn
    _, _, _, _, env, _, _ = setup(tmp_path, synthetic_key, monkeypatch)
    action = runtime.build_jwt_manual_key_owner_candidate(env)
    main_env = _v4_environment(tmp_path / "main-oauth"); main_env["FORTIPAM_MCP_RUNTIME_PROFILE"] = "v4-controlled"
    monkeypatch.setattr(os, "environ", main_env)
    monkeypatch.setattr(http_server, "load_http_runtime_environment", lambda:False)
    monkeypatch.setattr(runtime, "build_jwt_manual_key_owner_candidate", lambda _:action)
    captured = []
    def create(settings, **kwargs):
        assert kwargs["v4_jwt_owner_candidate_action"] is action
        captured.append(True)
        if app_failure: raise http_server.HttpConfigurationError("Synthetic startup refusal")
        return object()
    async def serve(self, sockets=None): captured.append(True)
    monkeypatch.setattr(http_server, "create_http_app", create)
    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    if app_failure:
        with pytest.raises(SystemExit): http_server.main()
    else: http_server.main()
    assert captured == ([True] if app_failure else [True, True]) and action._closed
