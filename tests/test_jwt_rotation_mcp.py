"""Normal startup and real OAuth/MCP over the actual fixed rotation graph."""
import asyncio
from dataclasses import asdict,replace
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives import serialization
import httpx
import pytest
from starlette.testclient import TestClient

from fortipam_mcp import jwt_rotation_runtime as runtime
from fortipam_mcp.jwt_manual_key_owner_http import JwtManualKeyOwnerHttp
from fortipam_mcp.jwt_manual_key_owner_workflow import JwtManualKeyOwnerWorkflow
from fortipam_mcp.jwt_rotation_authentication import JwtRotationAuthenticationProbe
from fortipam_mcp.jwt_rotation_workflow import JwtRotationWorkflow
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.http_server import create_http_app,HttpConfigurationError
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_ems_tag_principal_binding import settings
from test_ems_tag_mcp_oauth import headers,rpc,data
from test_http_server import _v4_environment
from test_jwt_rotation_phase import RotationLab,keyfile
from test_jwt_rotation_authentication import Peer
from test_jwt_manual_rotation_contract import replacement
from test_jwt_manual_key_contract import synthetic_key,defaults,public_pem
from test_jwt_manual_key_owner_workflow import run,IDENTITY

SCOPE = "fortipam:read fortipam:plan fortipam:operate"
TOOLS = {verb+"_v4_jwt_manual_rotation_700" for verb in ("preview","authorize","execute")}


def write(path,data):
    raw = data if isinstance(data,bytes) else json.dumps(data).encode()
    path.write_bytes(raw); path.chmod(0o600); return path


def call(client,token,verb,**arguments):
    return rpc(client,token,"tools/call",{"name":verb+"_v4_jwt_manual_rotation_700","arguments":arguments})


def setup(root,old,new,monkeypatch,*,enabled=True,auth_fault="none",activation_diagnostic=False):
    cfg = settings(root)
    with TestClient(create_http_app(cfg),base_url="https://mcp.example.com") as client:
        token = headers(client,SCOPE)
        assert not TOOLS & {t["name"] for t in rpc(client,token,"tools/list")["tools"]}
    bearer = next(v for k,v in token.items() if k.lower() == "authorization").removeprefix("Bearer ")
    access = asyncio.run(LocalOAuthProvider(cfg.local_oauth).load_access_token(bearer))
    principal = planning_principal_from_access_token(access,cfg.v4_planning_authorization)
    original = root/"definition"; original.mkdir(mode=0o700)
    lab = RotationLab(original,old,new,monkeypatch)
    lab.wire.rename(original/"native"); lab.wire = original/"native"; lab.ca.chmod(0o600)
    (original/"create-authority").mkdir(mode=0o700); (original/"remove-authority").mkdir(mode=0o700)
    for name,key in (("create.authority",b"a"*32),("create.execution",b"s"*32),("remove.authority",b"r"*32),("remove.execution",b"t"*32)):
        keyfile(original/(name+".key"),key)
    env = {runtime.OWNER_PREFIX+"SESSION_ENABLED":"true",runtime.OWNER_PREFIX+"LOGIN_ENV_FILE":str(original/"owner.env"),
        runtime.OWNER_PREFIX+"USERNAME_VARIABLE":"OWNER_USERNAME",runtime.OWNER_PREFIX+"PASSWORD_VARIABLE":"OWNER_PASSWORD"}
    write(original/"owner.env",("OWNER_USERNAME="+lab.config.owner_name+"\nOWNER_PASSWORD=synthetic-password\n").encode())
    credential_ref = hashlib.sha256(json.dumps(env,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    lab.config = replace(lab.config,credential_reference_digest=credential_ref,requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest)
    old_public = write(original/"public.pem",public_pem(old))
    original_manifest = {"contract":runtime.definition.CONTRACT,"phase":"create","wire":asdict(lab.config),"public_key_file":str(old_public),
        "binding":{"name":lab.request._name,"nonce":"a"*64,"schema_digest":lab.request.schema_digest,"serial_digest":lab.request.serial_digest,
            "defaults":defaults(),"public_key_digest":hashlib.sha256(public_pem(old)).hexdigest()},"identity":IDENTITY}
    old_manifest = write(original/"startup.create.json",original_manifest)
    store = PersistentM4ExecutionStateStore(original/"create.sqlite3",original/"create.execution.key")
    with lab.session() as owner:
        creator = JwtManualKeyOwnerWorkflow(owner,store,phase="create",directory=original/"create-authority",
            authority_key_file=original/"create.authority.key",**IDENTITY,execution_enabled=True,source_guard=lambda:lab.source,clock=lambda:1000)
        identity = {"requester_digest":principal.requester.digest,"transport_digest":principal.transport_namespace_digest}
        preview = creator.preview(**identity)
        plan,authorization = creator.issue(preview,**identity)
        result = creator.execute(plan,authorization); assert result.outcome == "succeeded"
    target = root/"rotation"; target.mkdir(mode=0o700)
    (target/"native").mkdir(mode=0o700); lab.rotation = target/"native"
    parent = target/"parent"; parent.mkdir(mode=0o700); keyfile(parent/"authority.key",b"Z"*32)
    keyfile(target/"rotation.witness.key",b"W"*32)
    for i,name in enumerate(runtime.PHASES):
        directory = target/("phase-"+name); directory.mkdir(mode=0o700)
        keyfile(directory/"authority.key",bytes([65+i])*32); keyfile(directory/"execution.key",bytes([80+i])*32)
    new_public = write(target/"new.public.pem",public_pem(new))
    signer_paths = []
    for name,key in (("old",old),("new",new)):
        signer_paths.append(write(target/(name+".private.pem"),key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption())))
    metadata = write(target/"metadata.json",{"schema":lab.user_schema,"defaults":lab.user_defaults,"serial_digest":lab.request.serial_digest,
        "schema_projection_sha256":runtime._digest(lab.user_schema),"defaults_projection_sha256":runtime._digest(lab.user_defaults)})
    path = write(target/"startup.json",{"contract":runtime.DIAGNOSTIC_CONTRACT if activation_diagnostic else runtime.CONTRACT,"original_manifest_file":str(old_manifest),"user_metadata_file":str(metadata),
        "user_name":lab.binding._user_name,"private_nonce":lab.binding._nonce,"old_public_file":str(old_public),"new_public_file":str(new_public),
        "new_public_digest":hashlib.sha256(public_pem(new)).hexdigest(),"old_signer_file":str(signer_paths[0]),"new_signer_file":str(signer_paths[1])})
    env.update({runtime.PREFIX+"ENABLED":"true",runtime.PREFIX+"EXECUTION_ENABLED":str(enabled).lower(),runtime.PREFIX+"STARTUP_MANIFEST_FILE":str(path)})
    auth = Peer(target,old,new,monkeypatch,fault=auth_fault); actual = auth.reply
    def reply(req):
        members = lab.row["key"][:1] if activation_diagnostic else lab.row["key"]
        auth.active = {name for name,key in (("old",lab.keys._old),("new",lab.keys._new))if any(row["key-name"] == key._pem.decode()for row in members)}
        auth.revoked = lab.user is None
        if req.url.path == "/auth/jwt/login" and (lab.user is None or not lab.key_initialized): return httpx.Response(401,json={"status":"error"})
        return actual(req)
    auth.reply = reply
    owner_init,probe_init = JwtManualKeyOwnerHttp.__init__,JwtRotationAuthenticationProbe.__init__
    def native_owner(self,*a,**k): k["client_factory"] = lab.factory; return owner_init(self,*a,**k)
    def native_probe(self,*a,**k): k.update(client_factory=auth.factory,clock=lambda:auth.clock); return probe_init(self,*a,**k)
    monkeypatch.setattr(JwtManualKeyOwnerHttp,"__init__",native_owner); monkeypatch.setattr(JwtRotationAuthenticationProbe,"__init__",native_probe)
    if activation_diagnostic:
        from test_jwt_rotation_workflow import SamplingClock
        workflow_init = JwtRotationWorkflow.__init__
        def timed_workflow(self,*a,**k):
            clock = SamplingClock();k.update(sampling_clock=clock,sampling_wait=clock.wait)
            return workflow_init(self,*a,**k)
        monkeypatch.setattr(JwtRotationWorkflow,"__init__",timed_workflow)
    return cfg,token,lab,auth,env,path,access


@pytest.mark.parametrize("fault", ["none","wrong-role"])
@pytest.mark.parametrize("activation_diagnostic", [False,True])
def test_normal_startup_real_oauth_and_six_child_m4s_never_accept_material_arguments(tmp_path,synthetic_key,replacement,monkeypatch,fault,activation_diagnostic):
    cfg,token,lab,auth,env,path,access = setup(tmp_path,synthetic_key,replacement,monkeypatch,auth_fault=fault,activation_diagnostic=activation_diagnostic)
    if activation_diagnostic:lab.rotation_fault = "reorder-overlap"
    loads = []; loader = runtime._signer; public_loads = []; public_reader = runtime._read_public
    monkeypatch.setattr(runtime,"_signer",lambda p:(loads.append(p.name),loader(p))[1])
    monkeypatch.setattr(runtime,"_read_public",lambda p:(public_loads.append(p.name),public_reader(p))[1])
    action = runtime.build_jwt_rotation_candidate(env)
    assert action is not None and not loads and not public_loads
    calls_before = len(lab.calls)
    with TestClient(create_http_app(cfg,v4_jwt_rotation_candidate_action=action),base_url="https://mcp.example.com") as client:
        entries = {t["name"]:t for t in rpc(client,token,"tools/list")["tools"]if t["name"] in TOOLS}
        assert set(entries) == TOOLS and all(t["inputSchema"]["additionalProperties"] is False for t in entries.values())
        assert not entries["preview_v4_jwt_manual_rotation_700"]["inputSchema"].get("properties")
        other = headers(client,SCOPE); plan = headers(client,"fortipam:read fortipam:plan")
        assert call(client,other,"preview")["isError"] and call(client,plan,"preview")["isError"]
        assert call(client,token,"preview",private_key="SYNTHETIC_FORBIDDEN")["isError"]
        assert call(client,token,"preview",activation_diagnostic=True)["isError"]
        assert len(lab.calls) == calls_before and not public_loads and not loads
        preview = data(call(client,token,"preview")); assert preview["Current State"]["original_key_custody_verified"]
        assert public_loads and not loads and lab.user_posts == 0 and not auth.clients
        authorization = data(call(client,token,"authorize",preview_ref=preview["preview_ref"]))
        assert not loads and lab.user_posts == 0
        result = data(call(client,token,"execute",authorization_ref=authorization["authorization_ref"]))
        assert result["outcome"] == ("succeeded"if fault == "none"else"reconciliation_required"),result
        assert len(loads) == 2 and lab.user_posts == lab.user_deletes == 1
        assert lab.key_generations == 1
        assert lab.puts == (3 if fault == "none" else 0)
        assert result["all_candidate_gates_closed"] and result["owner_logout_and_cookie_rejection"]
        if activation_diagnostic:
            assert result["rotation_accepted"] is False
            if fault == "none":
                assert result["overlap_authentication"] == {"old":True,"new":False}
                assert result["single_new_key_authentication"] == {"old":False,"new":True}
        assert action._workflow._execution_deadline <= access.expires_at
        assert call(client,token,"execute",authorization_ref=authorization["authorization_ref"])["isError"]
        assert not any(word in json.dumps(result)for word in("BEGIN","access-token","synthetic-password","mcp-v4-jwt-u-"))
    assert all(c.is_closed for c in auth.clients+lab.clients)
    with pytest.raises(ValueError): runtime.build_jwt_rotation_candidate(env)


def test_closed_startup_and_execution_do_not_load_private_signers(tmp_path,synthetic_key,replacement,monkeypatch):
    monkeypatch.setattr(runtime,"_document",lambda *_:pytest.fail("Closed startup opened metadata"))
    assert runtime.build_jwt_rotation_candidate({}) is None
    for flags in ({"EXECUTION_ENABLED":"true"},{"ENABLED":"TRUE"},{"ENABLED":True}):
        with pytest.raises(ValueError): runtime.build_jwt_rotation_candidate({runtime.PREFIX+k:v for k,v in flags.items()})
    monkeypatch.undo()
    cfg,token,lab,_,env,_,_ = setup(tmp_path,synthetic_key,replacement,monkeypatch,enabled=False)
    monkeypatch.setattr(runtime,"_signer",lambda *_:pytest.fail("Closed candidate resolved a private signer"))
    action = runtime.build_jwt_rotation_candidate(env)
    with TestClient(create_http_app(cfg,v4_jwt_rotation_candidate_action=action),base_url="https://mcp.example.com") as client:
        p = data(call(client,token,"preview"))
        assert call(client,token,"authorize",preview_ref=p["preview_ref"])["isError"]
    assert lab.user_posts == lab.user_deletes == lab.puts == 0 and action._closed


@pytest.mark.parametrize("version", [1,2,3,4,"diagnostic-v1","diagnostic-v2"])
def test_old_startup_cannot_gain_the_v3_ordered_overlap_effect(tmp_path,synthetic_key,replacement,monkeypatch,version):
    _,_,lab,_,env,path,_ = setup(tmp_path,synthetic_key,replacement,monkeypatch)
    manifest = json.loads(path.read_bytes());manifest["contract"] = ("fortipam-build29-manual-jwt-update-discriminator-startup-"+version.removeprefix("diagnostic-")
        if type(version) is str else "fortipam-build29-jwt-rotation-startup-v"+str(version))
    path.write_text(json.dumps(manifest));calls = len(lab.calls)
    monkeypatch.setattr(runtime,"_read_public",lambda *_:pytest.fail("A legacy manifest loaded a public key"))
    monkeypatch.setattr(runtime,"_signer",lambda *_:pytest.fail("A legacy manifest loaded a signer"))
    with pytest.raises(ValueError): runtime.build_jwt_rotation_candidate(env)
    assert len(lab.calls) == calls and lab.user_posts == lab.key_generations == 0


@pytest.mark.parametrize("app_failure", [False,True])
def test_normal_main_composes_or_closes_its_candidate_without_replacing_dependencies(tmp_path,synthetic_key,replacement,monkeypatch,app_failure):
    from fortipam_mcp import http_server
    import uvicorn
    _,_,_,_,env,_,_ = setup(tmp_path,synthetic_key,replacement,monkeypatch)
    action = runtime.build_jwt_rotation_candidate(env); captured = []
    main_env = _v4_environment(tmp_path/"main-oauth"); main_env["FORTIPAM_MCP_RUNTIME_PROFILE"] = "v4-controlled"
    monkeypatch.setattr(os,"environ",main_env); monkeypatch.setattr(http_server,"load_http_runtime_environment",lambda:False)
    monkeypatch.setattr(runtime,"build_jwt_rotation_candidate",lambda _:action)
    def create(settings,**kwargs):
        assert kwargs["v4_jwt_rotation_candidate_action"] is action; captured.append(True)
        if app_failure: raise HttpConfigurationError("Synthetic configuration failure")
        return object()
    async def serve(self,sockets=None): captured.append(True)
    monkeypatch.setattr(http_server,"create_http_app",create); monkeypatch.setattr(uvicorn.Server,"serve",serve)
    if app_failure:
        with pytest.raises(SystemExit): http_server.main()
    else: http_server.main()
    assert action._closed and captured == ([True]if app_failure else[True,True])
