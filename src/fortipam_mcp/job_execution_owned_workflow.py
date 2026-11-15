"""One source-bound scheduled Job activation, categorical result and cleanup."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import hmac
import http.client
import json
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from v4_planning import M4AdapterDenied, M4AdapterAmbiguous, M4AuthorizationDenied, M4ExecutionPlan, M4ExecutionAuthorization, M4ExecutionKernel, canonical_digest
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from . import secret_bulk_import_metadata as m
from .job_definition_owned_workflow import _Records
from .job_definition_create_m4_adapter import _wait_for_job_wad_publication
from .job_definition_recovery_ack import consume_disabled_job_delete_ack
from .job_execution_sources import JobExecutionSources, JobExecutionSnapshot, JobExecutionObservationPending, UTC8
from .job_definition_detail_reader import _token
from .ldap_server_runtime import _key
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable
from .target_lifecycle_dependencies import _spans

CONTRACT = "fortipam-build29-owned-job-execution-v1"
_ERROR = "The fixed owned Job execution is unavailable."
_RUNTIME = {"execution-time-start", "execution-time-end", "result-txt"}


def _body(context: dict[str, Any]) -> dict[str, Any]:
    value: dict[str,Any] = json.loads(b"".join(bytes.fromhex(part) for part in context["body"]))
    return value


class JobExecutionOwnedWorkflow:
    def __init__(self, source: JobExecutionSources, *, phase: str, root: Path, store_factory: Any,
            source_guard: Any, execution_enabled: bool = False, clock: Any = lambda:int(time.time()),
            connection_factory: Any = http.client.HTTPSConnection, publication_wait: Any = time.sleep,
            publication_clock: Any = time.monotonic):
        if (type(source) is not JobExecutionSources or phase not in {"activate","observe","cleanup"}
                or type(execution_enabled) is not bool):raise ValueError(_ERROR)
        self.source,self.phase,self.root = source,phase,root
        self._identity = source.definition._identity
        self._guard,self._store_factory,self._clock,self._factory = source_guard,store_factory,clock,connection_factory
        self._wait,self._monotonic = publication_wait,publication_clock
        self._enabled,self._closed = execution_enabled,False
        self._issued: tuple[M4ExecutionPlan,M4ExecutionAuthorization] | None = None
        self._active_store: PersistentM4ExecutionStateStore | None = None
        self._context: dict[str,Any] | None = None
        self._result: dict[str,Any] | None = None
        self._namespace = canonical_digest((CONTRACT,source.definition._namespace,source.target,self._identity))
        self._records={p:_Records(root/p,canonical_digest((self._namespace,p)),root/p/"witness.key") for p in ("activate","cleanup")}
        self._keys={p:_key(root/p/"authority.key") for p in ("activate","cleanup")}
        all_keys={root/p/(k+".key"):_key(root/p/(k+".key")) for p in ("activate","cleanup") for k in ("authority","witness","execution")}
        all_keys.update(source.definition._keys)
        if len(set(all_keys.values()))!=len(all_keys):raise ValueError(_ERROR)
        self._all_keys=all_keys
        self._live()
        if phase=="activate":
            if (root/"activate"/"grant.json").exists() or (root/"activate"/"dispatch.json").exists():raise ValueError(_ERROR)
        else:self._activation()
        if phase=="cleanup" and (root/"cleanup"/"dispatch.json").exists():raise ValueError(_ERROR)

    def _live(self) -> None:
        self.source.live()
        if self._closed or not self._guard() or any(_key(p)!=key for p,key in self._all_keys.items()):raise ValueError(_ERROR)

    def _caller(self, caller: dict[str,str]) -> None:
        if caller!={k:self._identity[k] for k in ("requester_digest","transport_digest")}:raise ValueError(_ERROR)

    def _mac(self, purpose: str, value: Any) -> str:
        return hmac.new(self._keys[self.phase],(CONTRACT+"\x00"+purpose+"\x00"+canonical_digest(value)).encode(),hashlib.sha256).hexdigest()

    def _store(self, phase: str, readonly: bool=False) -> PersistentM4ExecutionStateStore:
        store=self._store_factory(phase,readonly)
        if (type(store) is not PersistentM4ExecutionStateStore or store._path!=self.root/phase/"execution.sqlite3"
                or store._key_path!=self.root/phase/"execution.key" or store._read_only is not readonly
                or not store.monotonic_checkpoint_protocol_bound):raise ValueError(_ERROR)
        return store

    def _activation(self) -> dict[str,Any]:
        grant=self._records["activate"].read("grant.json")
        plan=M4ExecutionPlan(**grant["plan"]);auth=M4ExecutionAuthorization(**grant["authorization"])
        claim=self._store("activate",True).inspect_claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest,authorization_digest=auth.authorization_digest,
            context_digest=canonical_digest({"plan_digest":plan.plan_digest,"authorization_digest":auth.authorization_digest,"revision":1}))
        if claim.result is None or str(claim.result.outcome)!="succeeded" or str(claim.result.verification)!="verified":raise ValueError(_ERROR)
        ack=self._records["activate"].read("ack.json");state=self._records["activate"].read("state.json")
        if (ack["plan_digest"]!=plan.plan_digest or state["plan_digest"]!=plan.plan_digest
                or state["digest"]!=plan.expected_state_digest or grant["workflow_namespace"]!=self._namespace
                or state["full_digest"]!=canonical_digest(state["tokens"])
                or {k:v for k,v in state["tokens"].items() if k!="updated-time"}!=grant["context"]["expected_tokens"]):raise ValueError(_ERROR)
        return grant

    def _names(self, *, absent: bool=False) -> tuple[str,str]:
        reader=self.source.base._namespace()
        try:
            observed=reader.read_namespace()
            if observed.global_name_absent is not absent:raise ValueError(_ERROR)
            remaining=tuple(v for v in reader._names if v!=self.source.base._candidate._name)
            return observed.namespace_digest,canonical_digest({"contract":"fortipam-700-build29-job-name-namespace-v1","names":sorted(remaining)})
        finally:reader.close()

    def _current(self, context: dict[str,Any]) -> str:
        if self.phase=="activate":
            tokens,dependency=self.source.pristine()
        else:
            original=self._activation();ended=self._records["activate"].read("ended.json")
            snapshot,dependency=self.source.snapshot(_body(original["context"]))
            if (snapshot.digest!=ended["digest"] or not snapshot.end or not snapshot.marker
                    or ended["activation_plan_digest"]!=original["plan"]["plan_digest"]
                    or ended["criterion"]!="exact_public_marker_within_window"):raise ValueError(_ERROR)
            tokens=snapshot.tokens
        names,after=self._names()
        return canonical_digest((tokens,dependency,names,after))

    def preview(self, **caller: str) -> dict[str,Any]:
        self._live();self._caller(caller)
        if self.phase=="observe":raise ValueError(_ERROR)
        now=self._clock();device=self.source.clock()
        if abs(now-device)>5:raise ValueError(_ERROR)
        context: dict[str,Any]={"nonce":secrets.token_hex(32),"created_at":now,"expires_at":now+60}
        if self.phase=="activate":
            tokens,dependency=self.source.pristine();names,after=self._names()
            scheduled=now+180;stamp=datetime.fromtimestamp(scheduled,UTC8).strftime("%Y-%m-%d %H:%M:%S")
            body={**self.source.base._body,"status":"enable","scheduled-time":stamp,
                "$originalName":self.source.base._candidate._name}
            expected={k:v for k,v in tokens.items() if k!="updated-time"}
            for name in ("status","scheduled-time"):expected[name]=hashlib.sha256(_token(body[name])).hexdigest()
            encoded=json.dumps(body,sort_keys=True,separators=(",",":")).encode().hex()
            context.update(body=[encoded[i:i+256] for i in range(0,len(encoded),256)],baseline=tokens,dependency=dependency,names=names,after=after,scheduled_at=scheduled,
                current=canonical_digest((tokens,dependency,names,after)),expected=canonical_digest(expected),expected_tokens=expected)
        else:
            original=self._activation();ended=self._records["activate"].read("ended.json")
            if now>original["context"]["scheduled_at"]+600:raise ValueError(_ERROR)
            snapshot,dependency=self.source.snapshot(_body(original["context"]))
            if (snapshot.digest!=ended["digest"] or not snapshot.end or not snapshot.marker
                    or ended["activation_plan_digest"]!=original["plan"]["plan_digest"]
                    or ended["criterion"]!="exact_public_marker_within_window"):raise ValueError(_ERROR)
            names,after=self._names()
            context.update(body=original["context"]["body"],current=canonical_digest((snapshot.tokens,dependency,names,after)),
                expected=after,names=names,after=after,scheduled_at=original["context"]["scheduled_at"])
        self._context=context
        preview_ref="job-execution-preview-"+self._mac("preview",context)
        result={"contract":CONTRACT,"phase":self.phase,"policy_mode":"lab_auto","preview_ref":preview_ref,"expires_at":context["expires_at"],
            "Current State":{"digest":context["current"],"original_successful_creation":True,"target_and_policy_verified":True,
                "approved":True,"completed_fixed_result":self.phase=="cleanup"},
            "Proposed Changes":{"operation":"schedule_fixed_echo_once" if self.phase=="activate" else "delete_completed_owned_job",
                "maximum_native_mutations":1,"script_or_target_selection":False,"approval_policy_changes":False,
                "schedule_lead_seconds":180 if self.phase=="activate" else 0,"wad_publication_delay_ms":3000},
            "Expected State":{"digest":context["expected"],"result_window_seconds":120,
                "criterion":"completed_timestamps_and_exact_public_marker","generic_exit_status_qualified":False},
            "recovery":"new_original_execution_ack_full_state_only_no_repeat","device_write_executed":False}
        result["summary_digest"]=canonical_digest(result);self._preview_ref=preview_ref
        return result

    def _derive(self, context: dict[str,Any]) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]:
        confirmation=self._mac("standing-intent",context);approval=self._mac("lab-policy",context)
        values=dict(plan_ref="job-execution-plan-"+self._mac("plan",context),revision=1,action_id="owned-job-"+self.phase,
            action_version="1.0.0",adapter_ref="fortipam-build29-owned-job-"+self.phase+"-v1",target_ref="bound-owned-job",
            requester_digest=self._identity["requester_digest"],summary_digest=self._mac("summary",context),confirmation_digest=confirmation,
            approval_digest=approval,parameters_digest=canonical_digest((self._namespace,context["body"])),
            expected_current_digest=context["current"],expected_state_digest=context["expected"],
            idempotency_digest=self._mac("once",context),expires_at=context["expires_at"],compensation_ref=None)
        plan=M4ExecutionPlan(**values,plan_digest=canonical_digest(values))
        values=dict(authorization_ref="job-execution-auth-"+self._mac("authorization",context),plan_ref=plan.plan_ref,plan_digest=plan.plan_digest,
            requester_digest=plan.requester_digest,confirmation_ref="job-execution-intent-"+self._mac("intent",context),confirmation_digest=confirmation,
            approval_ref="job-execution-policy-"+self._mac("policy",context),approval_digest=approval,
            approver_digest=self._mac("approver",self._identity),issued_at=context["created_at"],expires_at=context["expires_at"],one_time=True,execution_authorized=True)
        return plan,M4ExecutionAuthorization(**values,authorization_digest=canonical_digest(values))

    def authorize(self, preview_ref: str, **caller: str) -> dict[str,Any]:
        self._live();self._caller(caller)
        context=self._context
        if (not self._enabled or context is None or preview_ref!=self._preview_ref or self._issued is not None
                or self._clock()>=context["expires_at"] or self._current(context)!=context["current"]):raise ValueError(_ERROR)
        self._issued=self._derive(context)
        self._records[self.phase].write("grant.json",{"workflow_namespace":self._namespace,"context":context,
            "plan":asdict(self._issued[0]),"authorization":asdict(self._issued[1])})
        return {"contract":CONTRACT,"phase":self.phase,"policy_mode":"lab_auto","authorization_ref":self._issued[1].authorization_ref,"expires_at":context["expires_at"]}

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            self._live()
            if (not self._enabled or self._issued is None or plan is not self._issued[0] or authorization is not self._issued[1]
                    or self._context is None or not self._context["created_at"]<=now_epoch<=self._clock()<self._context["expires_at"]
                    or (plan,authorization)!=self._derive(self._context)):raise ValueError
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            if self._issued is None or self._context is None:raise ValueError
            self.verify(plan,self._issued[1],now_epoch=self._clock())
            return self._current(self._context)
        except Exception:raise M4AdapterDenied(_ERROR) from None

    def _ack(self, raw: bytearray, status: int, media: str, plan: M4ExecutionPlan) -> str:
        if self.phase=="cleanup":
            return consume_disabled_job_delete_ack(raw,job_name=self.source.base._candidate._name,
                serial_digest=self.source.base._candidate._serial_digest,context_digest=plan.plan_digest,
                http_status=status,content_type=media,witness_key=self._records[self.phase]._key)
        fields=_spans(raw)
        wanted={"http_method":"PUT","http_status":200,"status":"success","path":"secret","name":"job","vdom":"root",
            "mkey":self.source.base._candidate._name,"version":"v7.0.0","build":29,"serial":self.source.base._serial}
        if status!=200 or media.split(";",1)[0]!="application/json" or {"results","schema_errors","action"}&fields.keys():raise ValueError(_ERROR)
        for key,value in wanted.items():
            actual=m._scalar(raw,fields[key])
            if type(actual) is not type(value) or actual!=value:raise ValueError(_ERROR)
        if "error" in fields:
            error=m._scalar(raw,fields["error"])
            if type(error) is not int or error!=0:raise ValueError(_ERROR)
        return hmac.new(self._records[self.phase]._key,plan.plan_digest.encode()+raw,hashlib.sha256).hexdigest()

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        raw=body=bytearray();connection=response=None
        attempted=False
        if self._issued is None or self._context is None or self._active_store is None:raise M4AdapterDenied(_ERROR)
        issued,store=self._issued,self._active_store
        try:
            self.verify(plan,self._issued[1],now_epoch=self._clock());_require_m4_dispatch_ownership(plan,self._issued[1],self._active_store)
        except Exception:raise M4AdapterDenied(_ERROR) from None
        context=self._context
        def guard() -> float:
            self.verify(plan,issued[1],now_epoch=self._clock());_require_m4_dispatch_ownership(plan,issued[1],store)
            if self.phase=="activate" and context["scheduled_at"]-self._clock()<120:raise ValueError(_ERROR)
            return float(min(15.0,context["expires_at"]-self._clock()))
        stage="writer_tls"
        try:
            config=self.source.base._config;url=urlsplit(config.base_url)
            connection=self._factory(url.hostname,url.port or 443,timeout=guard(),context=self.source.base._tls);connection.connect()
            stage="fresh_current_after_tls"
            if self._current(context)!=plan.expected_current_digest:raise ValueError(_ERROR)
            guard();stage="native_claim"
            self._records[self.phase].write("native-claim.json",{"plan_digest":plan.plan_digest,"retry_allowed":False})
            body=bytearray(b"".join(bytes.fromhex(part) for part in context["body"])) if self.phase=="activate" else bytearray()
            stage="native_request";attempted=True
            connection.request("PUT" if self.phase=="activate" else "DELETE","/api/v2/cmdb/secret/job/"+quote(self.source.base._candidate._name,safe="")+("?with_meta=true&vdom=root" if self.phase=="activate" else "?vdom=root"),
                bytes(body) if body else None,{"Authorization":"Bearer "+config.bearer_token,"Accept":"application/json","Accept-Encoding":"identity",
                    "Content-Type":"application/json","Content-Length":str(len(body)),"Connection":"close","Cache-Control":"no-store",
                    "User-Agent":"fortipam-mcp-owned-job-execution/1"})
            guard();stage="native_response"
            response=connection.getresponse();status=response.status;media=response.getheader("Content-Type","")
            self._records[self.phase].write("response.json",{"plan_digest":plan.plan_digest,"http_status":status,
                "json_content":media.split(";",1)[0]=="application/json","raw_values_stored":False})
            if response.getheader("Content-Encoding","identity") not in ("","identity"):raise ValueError(_ERROR)
            while True:
                guard();chunk=response.read(min(4096,16385-len(raw)))
                if not chunk:break
                raw.extend(chunk)
                if len(raw)>16384:raise ValueError(_ERROR)
            stage="original_ack";ack=self._ack(raw,status,media,plan)
            self._records[self.phase].write("ack.json",{"plan_digest":plan.plan_digest,"ack_digest":ack})
            response.close();response=None;connection.close();connection=None
            stage="wad_publication";_wait_for_job_wad_publication(guard,self._wait,self._monotonic)
            stage="fixed_postcondition"
            if self.phase=="activate":
                snapshot,dependency=self.source.snapshot(_body(context))
                projected=canonical_digest({k:v for k,v in snapshot.tokens.items() if k!="updated-time"})
                if (snapshot.start or snapshot.end or projected!=plan.expected_state_digest or dependency!=context["dependency"]
                        or snapshot.scheduled_at!=context["scheduled_at"]
                        or not context["created_at"]-5<=snapshot.updated_at<=min(self._clock()+5,context["expires_at"])):raise ValueError(_ERROR)
                self._post=projected
                full={"full_digest":snapshot.digest,"tokens":snapshot.tokens,"updated_at":snapshot.updated_at}
            else:
                observed=self.source.base.observe_absence();self.source.base.check_current(observed)
                if observed.namespace_digest!=plan.expected_state_digest:raise ValueError(_ERROR)
                self._post=observed.namespace_digest
            self._records[self.phase].write("state.json",{"digest":self._post,"plan_digest":plan.plan_digest,
                **(full if self.phase=="activate" else {})})
        except Exception as error:
            self._failure_stage=stage
            self._records[self.phase].write("failure.json",{"stage":stage,"error_class":type(error).__name__,"native_attempted":attempted,"retry_allowed":False})
            if attempted:raise M4AdapterAmbiguous(_ERROR) from None
            raise M4AdapterDenied(_ERROR) from None
        finally:
            _zeroize_mutable(raw);_zeroize_mutable(body)
            for item in (response,connection):
                if item is not None:
                    try:item.close()
                    except Exception:self._resources_closed=False

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            if self._issued is None:raise ValueError
            self.verify(plan,self._issued[1],now_epoch=self._clock())
            if self._post!=plan.expected_state_digest or not getattr(self,"_resources_closed",True):raise ValueError(_ERROR)
            return self._post
        except Exception:raise M4AdapterAmbiguous(_ERROR) from None

    def execute(self, authorization_ref: str, **caller: str) -> dict[str,Any]:
        self._live();self._caller(caller)
        if self._issued is None or authorization_ref!=self._issued[1].authorization_ref or not self._enabled:raise ValueError(_ERROR)
        store=self._store(self.phase)
        if store.claim_count:raise ValueError(_ERROR)
        self._active_store=store
        self._records[self.phase].write("dispatch.json",{"plan_digest":self._issued[0].plan_digest,"retry_allowed":False})
        try:
            result=M4ExecutionKernel(self,self,store,clock=self._clock).execute(*self._issued)
            self._result={"contract":CONTRACT,"phase":self.phase,"outcome":str(result.outcome),"verification":str(result.verification),
                "idempotent_replay":result.idempotent_replay,"native_claim_count":store.claim_count,
                "execution_state":("scheduled" if self.phase=="activate" else "owned_job_removed") if str(result.outcome)=="succeeded" else "unknown",
                "generic_exit_status_qualified":False}
        finally:self.close()
        self._result.update(all_candidate_gates_closed=True,owner_logout_verified=self.source.base._owner.logout_verified)
        return self._result

    def observe(self, **caller: str) -> dict[str,Any]:
        self._live();self._caller(caller)
        grant=self._activation();context=grant["context"];now=self.source.clock()
        if now>context["scheduled_at"]+600:raise ValueError(_ERROR)
        try:snapshot,dependency=self.source.snapshot(_body(context))
        except JobExecutionObservationPending:
            return {"contract":CONTRACT,"phase":"observe","execution_state":"observing","completed_fixed_result":False,
                "exact_public_marker":False,"within_declared_window":False,"generic_exit_status_qualified":False,
                "deadline_elapsed":now>context["scheduled_at"]+120,"device_write_executed":False,"owner_logout_verified":self.source.logout_verified}
        receipt=self._records["activate"].read("state.json")
        fixed=_RUNTIME|{"updated-time"}
        expected={k:v for k,v in receipt["tokens"].items() if k not in fixed}
        updated_ok=(snapshot.tokens["updated-time"]==receipt["tokens"]["updated-time"] or
            bool(snapshot.start and context["scheduled_at"]-5<=snapshot.start
                and snapshot.start-5<=snapshot.updated_at<=min(now+5,context["scheduled_at"]+120,snapshot.end+5 if snapshot.end else now+5)))
        if (expected!={k:v for k,v in snapshot.tokens.items() if k not in fixed} or not updated_ok
                or dependency!=context["dependency"] or snapshot.scheduled_at!=context["scheduled_at"]):raise ValueError(_ERROR)
        state="not_started" if not snapshot.start and not snapshot.end else "started" if not snapshot.end else "ended"
        verified=bool(snapshot.start and snapshot.end and snapshot.marker
            and all(snapshot.tokens[k]!=context["baseline"][k] for k in ("execution-time-start","execution-time-end"))
            and context["scheduled_at"]-5<=snapshot.start<=snapshot.end<=context["scheduled_at"]+120)
        if verified and not(self.root/"activate"/"ended.json").exists():
            self._records["activate"].write("ended.json",{"digest":snapshot.digest,"activation_plan_digest":grant["plan"]["plan_digest"],"criterion":"exact_public_marker_within_window"})
        return {"contract":CONTRACT,"phase":"observe","execution_state":state,"completed_fixed_result":verified,
            "exact_public_marker":snapshot.marker,"within_declared_window":verified,"generic_exit_status_qualified":False,
            "deadline_elapsed":now>context["scheduled_at"]+120,"device_write_executed":False,"owner_logout_verified":self.source.logout_verified}

    def close(self) -> None:
        self._enabled,self._closed=False,True;self.source.close()
