"""Real M4 original creation, activation, exact result and independent cleanup."""
import hashlib
import io
import json
from datetime import datetime

import httpx
import pytest

from fortipam_mcp.job_execution_sources import JobExecutionSources, UTC8
from fortipam_mcp.job_execution_owned_workflow import JobExecutionOwnedWorkflow
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportError
from test_job_definition_owned_workflow import prepared, invoke, CALLER
from test_job_definition_sources import CANDIDATE, SOURCE, TARGET, SERIAL, envelope
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF


def digest(values):
    return hashlib.sha256(b"".join(k.encode()+hashlib.sha256(json.dumps(values[k],separators=(",",":")).encode()).hexdigest().encode() for k in sorted(values))).hexdigest()


def graph(tmp_path,monkeypatch):
    source,api,root,definitions,_=prepared(tmp_path,monkeypatch)
    initial_job=api.job
    api.job=lambda name:{**initial_job(name),"updated-time":datetime.fromtimestamp(900,UTC8).strftime("%Y-%m-%d %H:%M:%S")}
    creator,_=definitions();assert invoke(creator)["outcome"]=="succeeded"
    secret={"id":999,"target":"unit-ssh-target","template":"Windows Machine","ssh-service-status":"up","need-approval-job":"disable","approval-profile":""}
    target={"name":"unit-ssh-target","address":"192.0.2.10","template":"Unix","service-addrs":[]}
    target_binding={"target_name":target["name"],"target_address":target["address"],"target_template":target["template"],
        "secret_template":secret["template"],"secret_target_digest":digest(secret),"target_digest":digest(target),"target_service_addresses_empty":True}
    actual=api.respond;old_job=api.job
    state={"body":None,"start":0,"end":0,"output":"","fault":None,"writer_connected":False,"source_reads_after_tls":0};now=[1000]
    def job(name):
        row=old_job(name)
        if name==CANDIDATE and state["body"]:
            row.update({k:v for k,v in state["body"].items() if k!="$originalName"})
            row["updated-time"]=datetime.fromtimestamp(state["end"] or state["updated_at"],UTC8).strftime("%Y-%m-%d %H:%M:%S")
            if state["start"]:row["execution-time-start"]="native-started"
            if state["end"]:row["execution-time-end"]="native-ended"
            row["result-txt"]=state["output"]
        return row
    api.job=job
    def reply(request):
        if state["writer_connected"]:state["source_reads_after_tls"]+=1
        path=request.url.path
        if path=="/api/v2/cmdb/secret/database/999" and "target" in request.url.params.get("format","").split("|"):
            row={**secret,"field":[{"value":"SYNTHETIC_NEVER_DECODE"}],"$native-ui":{}}
            if state["fault"]=="target":row["target"]="foreign-target"
            return httpx.Response(200,json=envelope([row],name="database",status="OK"))
        if path=="/api/v2/cmdb/secret/target/unit-ssh-target":
            assert "authorization" in request.headers
            if state["fault"]=="target-denied":return httpx.Response(403)
            return httpx.Response(200,headers={"content-type":"application/json"},
                stream=httpx.ByteStream(json.dumps(envelope([target],name="target")).encode()))
        if path=="/api/v2/cmdb/secret/job" and request.url.params.get("action")!="default":
            rows=[job(SOURCE),job(TARGET)]+([job(CANDIDATE)] if api.present else [])
            for row in rows:
                chosen=row["name"]==CANDIDATE
                row["execution-time-start"]=state["start"] if chosen else 0
                row["execution-time-end"]=state["end"] if chosen else 0
                row["scheduled-time"]=int(datetime.strptime(state["body"]["scheduled-time"],"%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC8).timestamp()) if chosen and state["body"] else 0
            return httpx.Response(200,json=envelope(rows,method="POST",status="OK"))
        return actual(request)
    api.respond=reply
    monkeypatch.setattr(JobExecutionSources,"clock",lambda self:now[0])
    directory=root/"execution";directory.mkdir(mode=0o700)
    checkpoints={}
    for i,phase in enumerate(("activate","cleanup")):
        path=directory/phase;path.mkdir(mode=0o700)
        for j,key in enumerate(("authority","witness","execution")):
            p=path/(key+".key");p.write_bytes(bytes([90+i*3+j])*32);p.chmod(0o600)
        checkpoints[phase]=_ExternalM4Checkpoint()
    def store(phase,readonly):return PersistentM4ExecutionStateStore(directory/phase/"execution.sqlite3",directory/phase/"execution.key",
        monotonic_checkpoint=checkpoints[phase],checkpoint_store_ref=CHECKPOINT_STORE_REF,read_only=readonly)
    calls=[]
    def factory(*a,**kw):
        class Connection:
            def connect(self):state["writer_connected"]=True
            def request(self,method,path,body,headers):
                calls.append(method)
                assert headers["User-Agent"]=="fortipam-mcp-owned-job-execution/1"
                if state["fault"]=="request-drop":raise OSError("synthetic dropped request before product acceptance")
                assert path.startswith("/api/v2/cmdb/secret/job/"+CANDIDATE)
                if method=="PUT":state["body"]=json.loads(body);state["updated_at"]=now[0]-120 if state["fault"]=="stale-updated" else now[0]
                else:assert method=="DELETE" and state["end"] and state["output"]=="BP008_JOB_OK\n";api.present=False
                self.method=method
            def getresponse(self):
                if state["fault"]=="lost-ack":raise OSError("synthetic lost response")
                raw={"version":"v7.0.0","build":29,"http_status":200,"http_method":self.method,"path":"secret","name":"job","vdom":"root","serial":SERIAL,"mkey":CANDIDATE,"status":"success","error":0}
                class Response:
                    status=200
                    stream=io.BytesIO(json.dumps(raw).encode())
                    def read(self,n):return self.stream.read(n)
                    def getheader(self,key,default=""):return "application/json" if key=="Content-Type" else default
                    def close(self):pass
                return Response()
            def close(self):state["writer_connected"]=False
        return Connection()
    def make(phase):
        definition,_=definitions("recover")
        sources=JobExecutionSources(definition,target_binding)
        clock=[0.0]
        def wait(seconds):clock[0]+=seconds
        return JobExecutionOwnedWorkflow(sources,phase=phase,root=directory,store_factory=store,source_guard=lambda:True,
            execution_enabled=phase!="observe",clock=lambda:now[0],connection_factory=factory,publication_wait=wait,publication_clock=lambda:clock[0])
    return make,state,now,calls,api,root


def execute(workflow):
    preview=workflow.preview(**CALLER);grant=workflow.authorize(preview["preview_ref"],**CALLER)
    return workflow.execute(grant["authorization_ref"],**CALLER)


def test_owned_activation_exact_result_and_cleanup_preserve_original(tmp_path,monkeypatch):
    make,state,now,calls,api,root=graph(tmp_path,monkeypatch)
    before={p:p.read_bytes() for p in (root/"create").rglob("*") if p.is_file()}
    active=make("activate");result=execute(active)
    assert result["outcome"]=="succeeded" and result["execution_state"]=="scheduled",result
    observer=make("observe")
    assert observer.observe(**CALLER)["completed_fixed_result"] is False
    state.update(start=1180,end=1181,output="BP008_JOB_OK\n");now[0]=1182
    observed=observer.observe(**CALLER);assert observed["completed_fixed_result"] and not observed["generic_exit_status_qualified"]
    observer.close()
    cleanup=make("cleanup");deleted=execute(cleanup)
    assert deleted["outcome"]=="succeeded" and deleted["execution_state"]=="owned_job_removed",deleted
    assert calls==["PUT","DELETE"] and not api.present
    assert all(p.read_bytes()==raw for p,raw in before.items())
    with pytest.raises(ValueError):make("activate")
    with pytest.raises(ValueError):make("cleanup")


@pytest.mark.parametrize("output,completed", [
    ("\x1b[32mBP008_JOB_OK\x1b[0m\r\n",True),
    ("\x1b[?2004lBP008_JOB_OK\r\n\x1b[?2004h",True),
    ("\x1b[2KBP008_JOB_OK\n",False),
    ("echo \x1b[32mBP008_JOB_OK\x1b[0m\nBP008_JOB_OK\n",False),
])
def test_native_sgr_preserves_exact_marker_and_never_interprets_terminal_commands(tmp_path,monkeypatch,output,completed):
    make,state,now,calls,api,root=graph(tmp_path,monkeypatch)
    assert execute(make("activate"))["outcome"]=="succeeded"
    state.update(start=1180,end=1181,output=output);now[0]=1182
    observer=make("observe")
    result=observer.observe(**CALLER);observer.close()
    assert result["completed_fixed_result"] is completed
    assert (root/"execution/activate/ended.json").exists() is completed
    assert calls==["PUT"]


@pytest.mark.parametrize("fault", ["command-echo","substring","outside-window","reversed-time","target","target-denied"])
def test_result_is_never_generic_success_or_cleanup_authority(tmp_path,monkeypatch,fault):
    make,state,now,calls,api,root=graph(tmp_path,monkeypatch)
    assert execute(make("activate"))["outcome"]=="succeeded"
    state.update(start=1180,end=1181,output="BP008_JOB_OK\n");now[0]=1182
    if fault=="command-echo":state["output"]="echo BP008_JOB_OK\nBP008_JOB_OK\n"
    elif fault=="substring":state["output"]="error BP008_JOB_OK unavailable\n"
    elif fault=="outside-window":state.update(start=1301,end=1302)
    elif fault=="reversed-time":state.update(end=1179)
    else:state["fault"]=fault
    observer=make("observe")
    if fault in {"reversed-time","target","target-denied","outside-window"}:
        with pytest.raises((ValueError,SecretMetadataHttpTransportError)):observer.observe(**CALLER)
    else:assert observer.observe(**CALLER)["completed_fixed_result"] is False
    observer.close()
    with pytest.raises(FileNotFoundError):execute(make("cleanup"))
    assert calls==["PUT"] and api.present


def test_uncertain_original_activation_cannot_replay_or_be_observed_as_owned_success(tmp_path,monkeypatch):
    make,state,now,calls,api,root=graph(tmp_path,monkeypatch)
    state["fault"]="lost-ack"
    result=execute(make("activate"))
    assert result["outcome"]=="reconciliation_required" and result["execution_state"]=="unknown"
    with pytest.raises(ValueError):make("activate")
    with pytest.raises(ValueError):make("observe")
    assert calls==["PUT"]


def test_native_user_agent_and_fresh_drift_check_after_tls_are_both_required(tmp_path,monkeypatch):
    make,state,now,calls,api,root=graph(tmp_path,monkeypatch)
    assert execute(make("activate"))["outcome"]=="succeeded"
    assert calls==["PUT"] and not state["writer_connected"] and state["source_reads_after_tls"]>0


def test_native_updated_time_must_be_inside_original_authorization_window(tmp_path,monkeypatch):
    make,state,now,calls,api,root=graph(tmp_path,monkeypatch)
    state["fault"]="stale-updated"
    result=execute(make("activate"))
    assert result["outcome"]=="reconciliation_required" and result["verification"]=="unknown"
    assert (root/"execution/activate/ack.json").exists()
    assert not(root/"execution/activate/state.json").exists()
    assert calls==["PUT"]
    with pytest.raises(ValueError):make("observe")


def test_only_runtime_transition_is_pending_without_partial_final_seal(tmp_path,monkeypatch):
    make,state,now,calls,api,root=graph(tmp_path,monkeypatch)
    assert execute(make("activate"))["outcome"]=="succeeded"
    now[0]=1182;original=api.respond;transitioned=[]
    def response(request):
        if request.url.path=="/api/v2/cmdb/secret/job" and not transitioned:
            state.update(start=1180,end=1181,output="BP008_JOB_OK\n");transitioned.append(True)
        return original(request)
    api.respond=response
    observer=make("observe")
    first=observer.observe(**CALLER)
    assert first["execution_state"]=="observing" and not first["completed_fixed_result"]
    assert not(root/"execution/activate/ended.json").exists()
    assert observer.observe(**CALLER)["completed_fixed_result"]
    observer.close()


def test_pristine_definition_delete_cannot_bypass_unknown_activation(tmp_path,monkeypatch):
    from fortipam_mcp.job_definition_sources import JobDefinitionSources
    from fortipam_mcp.job_definition_owned_workflow import JobDefinitionOwnedWorkflow
    make,state,now,calls,api,root=graph(tmp_path,monkeypatch)
    active=make("activate");original=active.source.definition
    state["fault"]="request-drop"
    assert execute(active)["outcome"]=="reconciliation_required"
    assert state["body"] is None and api.present
    old=original.source
    source=JobDefinitionSources(candidate=old._candidate,anchor=old._anchor,ssh=old._ssh,client_factory=api.factory,clock=lambda:api.now)
    recovery=JobDefinitionOwnedWorkflow(source,root=root,phase="recover",source_binding_digest=original._source_binding,
        identity=original._identity,store_factory=original._store_factory,source_guard=lambda:True,execution_enabled=True,clock=lambda:1000)
    before=len(api.calls)
    with pytest.raises(ValueError):recovery.preview(**CALLER)
    assert len(api.calls)==before and calls==["PUT"] and not(root/"recover/dispatch.json").exists()
    recovery.close()
