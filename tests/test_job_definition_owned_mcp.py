"""Real normal builder/OAuth/MCP over fixed synthetic native Job sources."""
import asyncio
from dataclasses import asdict
import json

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import job_definition_owned_runtime as runtime
from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from fortipam_mcp.job_definition_owned_workflow import JobDefinitionOwnedWorkflow
from fortipam_mcp.job_definition_sources import JobDefinitionSources
from test_job_definition_sources import make, CANDIDATE, TARGET, SERIAL
from test_job_definition_detail_reader import _body
from test_job_definition_create_m4_adapter import Native as CreateNative
from test_job_definition_recovery_m4_adapter import Native as RecoverNative
from test_ems_tag_principal_binding import settings
from test_ems_tag_mcp_oauth import headers, rpc, data
from test_m4_execution_store import _ExternalM4Checkpoint

TOOLS = {verb+"_v4_owned_disabled_job_700" for verb in ("preview","authorize","execute")}


def write(path, value):
    path.write_text(json.dumps(value));path.chmod(0o600);return path


def setup(root, monkeypatch):
    cfg = settings(root)
    with TestClient(create_http_app(cfg),base_url="https://mcp.example.com") as client:
        token = headers(client,"fortipam:read fortipam:plan fortipam:operate")
        assert not TOOLS & {t["name"] for t in rpc(client,token,"tools/list")["tools"]}
    bearer = next(v for k,v in token.items() if k.lower() == "authorization").removeprefix("Bearer ")
    access = asyncio.run(LocalOAuthProvider(cfg.local_oauth).load_access_token(bearer))
    principal = planning_principal_from_access_token(access,cfg.v4_planning_authorization)
    source,api,*_ = make(root,monkeypatch)
    owned = root/"owned";owned.mkdir(mode=0o700)
    for i,phase in enumerate(("create","recover")):
        p=owned/phase;p.mkdir(mode=0o700);(p/"native").mkdir(mode=0o700)
        for j,k in enumerate(("authority","execution","witness")):
            path=p/(k+".key");path.write_bytes(bytes([65+i*3+j])*32);path.chmod(0o600)
    doc = {"candidate_name":CANDIDATE,"anchor_name":TARGET,"requester_name":"adminapi","secret_id":999,
        "serial":SERIAL,"body":dict(_body(),name=CANDIDATE),"max_timeout":0,"ssh_host":source._ssh.host,
        "ssh_port":22,"known_hosts_file":str(source._ssh.known_hosts_file),"ssh_timeout_seconds":30}
    source_path = write(owned/"source.json",doc)
    manifest = {"contract":runtime.CONTRACT,"phase":"create","source_file":str(source_path),
        "identity":{"environment_ref":"job-lab-environment","scope_ref":"owned-job-lab","audience_ref":"private-client",
            "requester_digest":principal.requester.digest,"transport_digest":principal.transport_namespace_digest},
        "checkpoint":{"socket":str(owned/"cp.sock"),"authority_ref":"job-checkpoint",
            "create_store_ref":"job-create-store","recover_store_ref":"job-recover-store"}}
    manifest_path = write(owned/"startup.json",manifest)
    monkeypatch.setattr(runtime,"owner_login_provider",lambda env:source._owner._credentials)
    monkeypatch.setattr(runtime,"load_secret_metadata_http_transport_config",lambda env:source._config)
    monkeypatch.setattr(runtime,"OwnerSessionMetadataTransport",lambda *a,**k:source._owner)
    monkeypatch.setattr(runtime,"JobDefinitionSources",lambda **kwargs:JobDefinitionSources(**kwargs,client_factory=api.factory,clock=lambda:api.now))
    checkpoints = {}
    monkeypatch.setattr(runtime,"_M4PlanningCheckpoint",lambda client,ref:checkpoints.setdefault(ref,_ExternalM4Checkpoint(ref)))
    native = []
    def workflow(*args,**kwargs):
        elapsed=[0.0]
        def wait(seconds):elapsed[0]+=seconds
        value = JobDefinitionOwnedWorkflow(*args,**kwargs,publication_wait=wait,publication_clock=lambda:elapsed[0])
        def factory(*a,**k):
            if value.phase == "create":peer=CreateNative(api,value._original,value._original._pins)
            else:peer=RecoverNative(api)
            native.append(peer);return peer.factory(*a,**k)
        value._factory=factory
        return value
    monkeypatch.setattr(runtime,"JobDefinitionOwnedWorkflow",workflow)
    env = {runtime.PREFIX+"ENABLED":"true",runtime.PREFIX+"EXECUTION_ENABLED":"true",
        runtime.PREFIX+"STARTUP_MANIFEST_FILE":str(manifest_path)}
    return cfg,token,env,manifest,manifest_path,source_path,api,native


def call(client,token,verb,**args):
    return rpc(client,token,"tools/call",{"name":verb+"_v4_owned_disabled_job_700","arguments":args})


def test_real_normal_builder_and_oauth_mcp_create_then_independent_recovery(tmp_path,monkeypatch):
    cfg,token,env,manifest,path,source_path,api,native=setup(tmp_path,monkeypatch)
    for phase in ("create","recover"):
        manifest["phase"]=phase;write(path,manifest)
        action=runtime.build_job_definition_owned_candidate(env)
        with TestClient(create_http_app(cfg,v4_job_definition_owned_candidate_action=action),base_url="https://mcp.example.com") as client:
            tools={t["name"]:t for t in rpc(client,token,"tools/list")["tools"]}
            assert TOOLS <= tools.keys()
            assert all(tools[n]["inputSchema"]["additionalProperties"] is False for n in TOOLS)
            assert call(client,token,"preview",phase=phase)["isError"]
            p=data(call(client,token,"preview"));assert p["phase"]==phase
            a=data(call(client,token,"authorize",preview_ref=p["preview_ref"]))
            r=data(call(client,token,"execute",authorization_ref=a["authorization_ref"]))
            assert r["outcome"]=="succeeded" and r["verification"]=="verified",r
            assert r["all_candidate_gates_closed"] and r["original_store_read_only"] is (phase=="recover")
            assert call(client,token,"execute",authorization_ref=a["authorization_ref"])["isError"]
    assert not api.present and sum(len(peer.calls) for peer in native)==2


@pytest.mark.parametrize("fault", ["extra-field","legacy-contract","same-store","path-drift","source-drift"])
def test_startup_and_source_drift_refuse_before_product_or_store_io(tmp_path,monkeypatch,fault):
    cfg,token,env,manifest,path,source_path,api,native=setup(tmp_path,monkeypatch)
    if fault=="extra-field":manifest["body"]={}
    elif fault=="legacy-contract":manifest["contract"]="fortipam-build29-owned-disabled-job-startup-v1"
    elif fault=="same-store":manifest["checkpoint"]["recover_store_ref"]=manifest["checkpoint"]["create_store_ref"]
    write(path,manifest)
    calls=len(api.calls)
    if fault in {"path-drift","source-drift"}:
        action=runtime.build_job_definition_owned_candidate(env)
        if fault=="path-drift":write(path,dict(manifest,phase="recover"))
        else:write(source_path,{})
        with pytest.raises(RuntimeError):
            action.preview(type("Foreign",(),{})())
        with TestClient(create_http_app(cfg,v4_job_definition_owned_candidate_action=action),base_url="https://mcp.example.com") as client:
            assert call(client,token,"preview")["isError"]
    else:
        with pytest.raises(ValueError):runtime.build_job_definition_owned_candidate(env)
    assert len(api.calls)==calls and not native


def test_opt_in_profile_cannot_bypass_oauth_runtime_or_default_off(tmp_path,monkeypatch):
    cfg,token,env,*_=setup(tmp_path,monkeypatch)
    assert runtime.build_job_definition_owned_candidate({}) is None
    with pytest.raises(ValueError):runtime.build_job_definition_owned_candidate({runtime.PREFIX+"EXECUTION_ENABLED":"true"})
    action=runtime.build_job_definition_owned_candidate(env)
    from dataclasses import replace
    with pytest.raises(HttpConfigurationError):create_http_app(replace(cfg,v4_planning_authorization=None),v4_job_definition_owned_candidate_action=action)


@pytest.mark.parametrize("version", [1,2])
def test_consumed_legacy_startup_refuses_before_credential_resolution(tmp_path,monkeypatch,version):
    cfg,token,env,manifest,path,source_path,api,native=setup(tmp_path,monkeypatch)
    manifest["contract"]="fortipam-build29-owned-disabled-job-startup-v"+str(version);write(path,manifest)
    resolved=[]
    monkeypatch.setattr(runtime,"owner_login_provider",lambda env:resolved.append(True))
    calls=len(api.calls)
    with pytest.raises(ValueError):runtime.build_job_definition_owned_candidate(env)
    assert not resolved and not native and len(api.calls)==calls


def test_v4_fixed_selected_secret_retains_original_source_and_anchor(tmp_path,monkeypatch):
    import httpx
    cfg,token,env,manifest,path,source_path,api,native=setup(tmp_path,monkeypatch)
    source=json.loads(source_path.read_bytes())
    source['source_secret_id']=999;source['secret_id']=998;source['body']['secret']=998
    write(source_path,source);manifest['contract']=runtime.SELECTED_SECRET_CONTRACT
    original_job=api.job;original_respond=api.respond
    def job(name):
        row=original_job(name)
        if name==CANDIDATE:row['secret']=998
        return row
    api.job=job
    def respond(request):
        if request.url.path=='/api/v2/cmdb/secret/database/998':
            response=original_respond(httpx.Request(request.method,request.url.copy_with(path='/api/v2/cmdb/secret/database/999'),headers=request.headers))
            response.read();value=response.json()
            for row in value['results']:row['id']=998
            return httpx.Response(200,stream=httpx.ByteStream(json.dumps(value).encode()),headers={"content-type":"application/json"})
        return original_respond(request)
    api.respond=respond
    for phase in ('create','recover'):
        manifest['phase']=phase;write(path,manifest)
        action=runtime.build_job_definition_owned_candidate(env)
        with TestClient(create_http_app(cfg,v4_job_definition_owned_candidate_action=action),base_url='https://mcp.example.com') as client:
            first=call(client,token,'preview')
            assert not first.get('isError'), (first,action._workflow.source._failure_diagnostics() if action._workflow else 'factory')
            p=data(first)
            a=data(call(client,token,'authorize',preview_ref=p['preview_ref']))
            result=data(call(client,token,'execute',authorization_ref=a['authorization_ref']))
            assert result['outcome']=='succeeded' and result['verification']=='verified',result
        assert action._workflow.source._source_secret_id==999
        assert action._workflow.source._body['secret']==998
    assert not api.present and sum(len(peer.calls) for peer in native)==2


def test_v3_body_secret_mismatch_is_rejected_before_credential_resolution(tmp_path,monkeypatch):
    cfg,token,env,manifest,path,source_path,api,native=setup(tmp_path,monkeypatch)
    value=json.loads(source_path.read_bytes());value['body']['secret']=998;write(source_path,value)
    resolved=[];monkeypatch.setattr(runtime,'owner_login_provider',lambda env:resolved.append(True))
    with pytest.raises(ValueError):runtime.build_job_definition_owned_candidate(env)
    assert not resolved and not api.calls and not native
