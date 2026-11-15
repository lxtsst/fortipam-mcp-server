"""Normal OAuth/MCP execution entry over real M4 with synthetic product IO."""
import asyncio
import json
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import job_execution_owned_runtime as runtime
from fortipam_mcp import job_definition_owned_runtime as definition
from fortipam_mcp.job_execution_owned_mcp_action import JobExecutionOwnedMcpAction
from fortipam_mcp.http_server import create_http_app
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_ems_tag_principal_binding import settings
from test_ems_tag_mcp_oauth import headers,rpc,data
from test_job_definition_authority import IDENTITY
from test_job_definition_owned_workflow import CALLER
from test_job_execution_owned import graph
from scripts import v4_job_execution_owned_mcp_oauth_acceptance as acceptance

TOOLS={v+"_v4_owned_job_execution_700" for v in ("preview","authorize","execute","observe")}


def principal(root):
    cfg=settings(root)
    with TestClient(create_http_app(cfg),base_url="https://mcp.example.com") as client:
        token=headers(client,"fortipam:read fortipam:plan fortipam:operate")
        assert not TOOLS & {t["name"] for t in rpc(client,token,"tools/list")["tools"]}
    bearer=next(v for k,v in token.items() if k.lower()=="authorization").removeprefix("Bearer ")
    access=asyncio.run(LocalOAuthProvider(cfg.local_oauth).load_access_token(bearer))
    return cfg,token,planning_principal_from_access_token(access,cfg.v4_planning_authorization)


def call(client,token,verb,**args):
    return rpc(client,token,"tools/call",{"name":verb+"_v4_owned_job_execution_700","arguments":args})


def test_oauth_mcp_exact_scheduled_result_and_independent_cleanup(tmp_path,monkeypatch):
    cfg,token,p=principal(tmp_path)
    for key,value in {"requester_digest":p.requester.digest,"transport_digest":p.transport_namespace_digest}.items():
        monkeypatch.setitem(IDENTITY,key,value);monkeypatch.setitem(CALLER,key,value)
    make,state,now,calls,api,root=graph(tmp_path,monkeypatch)
    for phase in ("activate","observe","cleanup"):
        action=JobExecutionOwnedMcpAction(lambda:make(phase),phase=phase,requester_digest=p.requester.digest,
            transport_digest=p.transport_namespace_digest,execution_enabled=phase!="observe")
        with TestClient(create_http_app(cfg,v4_job_execution_owned_candidate_action=action),base_url="https://mcp.example.com") as client:
            tools={t["name"]:t for t in rpc(client,token,"tools/list")["tools"]}
            assert TOOLS<=tools.keys()
            assert all(tools[n]["inputSchema"]["additionalProperties"] is False for n in TOOLS)
            assert call(client,token,"preview",script="unexpected")["isError"]
            if phase=="observe":
                observed=data(call(client,token,"observe"));assert not acceptance._validate_observation(observed)
                state.update(start=1180,end=1181,output="BP008_JOB_OK\n");now[0]=1182
                assert acceptance._validate_observation(data(call(client,token,"observe")))
            else:
                preview=data(call(client,token,"preview"))
                # Client freshness uses real wall time; the workflow clock is synthetic.
                monkeypatch.setattr(acceptance,"_fresh",lambda value:None)
                acceptance._validate_preview(preview,phase)
                auth=data(call(client,token,"authorize",preview_ref=preview["preview_ref"]))
                acceptance._validate_authorization(auth,preview)
                result=data(call(client,token,"execute",authorization_ref=auth["authorization_ref"]))
                acceptance._validate_execution(result,phase)
                assert call(client,token,"execute",authorization_ref=auth["authorization_ref"])["isError"]
        assert action._closed
    assert calls==["PUT","DELETE"] and not api.present


def write(path,value):
    path.write_text(json.dumps(value));path.chmod(0o600);return path


@pytest.mark.parametrize("fault",["none","extra","old-definition","observe-enabled","same-store","drift"])
def test_startup_guard_and_disabled_default_before_factory(tmp_path,monkeypatch,fault):
    tmp_path.chmod(0o700)
    assert runtime.build_job_execution_owned_candidate({}) is None
    with pytest.raises(ValueError):runtime.build_job_execution_owned_candidate({runtime.PREFIX+"EXECUTION_ENABLED":"true"})
    make,*_=graph(tmp_path,monkeypatch)
    wf=make("activate");root=wf.root
    original=write(root.parent/"inspect.json",{"contract":definition.CONTRACT,"phase":"recover","identity":IDENTITY})
    target=write(root/"target.json",wf.source.target)
    doc={"contract":runtime.CONTRACT,"phase":"activate","original_manifest_file":str(original),"target_file":str(target),
        "checkpoint":{"socket":str(tmp_path/"cp.sock"),"authority_ref":"job-test-cp","activate_store_ref":"job-test-activate","cleanup_store_ref":"job-test-cleanup"}}
    if fault=="extra":doc["script"]="untrusted"
    elif fault=="old-definition":write(original,{"contract":"old-v1","phase":"recover"})
    elif fault=="observe-enabled":doc["phase"]="observe"
    elif fault=="same-store":doc["checkpoint"]["cleanup_store_ref"]=doc["checkpoint"]["activate_store_ref"]
    path=write(root/"startup.json",doc)
    env={runtime.PREFIX+"ENABLED":"true",runtime.PREFIX+"EXECUTION_ENABLED":"true",runtime.PREFIX+"STARTUP_MANIFEST_FILE":str(path)}
    factories=[]
    monkeypatch.setattr(definition,"build_job_definition_owned_candidate",lambda e:factories.append(e) or SimpleNamespace(_factory=lambda:wf.source.definition))
    if fault in {"extra","old-definition","observe-enabled","same-store"}:
        with pytest.raises(ValueError):runtime.build_job_execution_owned_candidate(env)
    else:
        action=runtime.build_job_execution_owned_candidate(env)
        assert not factories
        if fault=="drift":
            write(target,{})
            with pytest.raises(ValueError):action._factory()
            assert not factories
        else:
            assert action._phase=="activate"
            with pytest.raises(RuntimeError):action.preview(object())
            assert not factories
    wf.close()
