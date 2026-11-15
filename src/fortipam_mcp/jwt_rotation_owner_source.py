"""Fixed Owner-session rotation wire source; original creation is never adopted.

This module registers no Tool and defaults to closed dispatch. Every write is a
child of a live original M4; the complete original Key grant/ACK/terminal ledger
and full invariant remain required throughout the separate rotation package.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
from typing import Any
from urllib.parse import quote

from v4_planning import M4ExecutionPlan, M4ExecutionAuthorization, canonical_digest
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from .jwt_manual_key_contract import _digest, _require_digest
from .jwt_manual_key_owner_actor import consume_jwt_manual_key_owner_actor_inputs, _state as _owner_state
from .jwt_manual_key_owner_http import JwtManualKeyOwnerHttp, _KEYS, _USERS, _STATE
from .jwt_manual_key_owner_workflow import JwtManualKeyOwnerWorkflow, _GrantReader, _mac, _derive
from .jwt_manual_key_owned_state import consume_jwt_manual_key_owned_state
from .jwt_manual_key_preflight import JwtManualKeyPreflight, _top
from .jwt_manual_rotation_contract import (JwtManualRotationBinding, JwtManualRotationKeys,
    JwtManualRotationRequest, JwtManualRotationContractError, consume_jwt_rotation_key_state)
from .jwt_rotation_dependency_projection import (USER_FIELDS, consume_jwt_rotation_dependencies,
    consume_jwt_rotation_owned_user, consume_jwt_rotation_user_absence)
from .jwt_rotation_user_initialization import consume_jwt_user_initialization
from .ldap_server_runtime import _key, _private_directory
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import MAX_RESPONSE_BYTES, _zeroize_mutable
from .secret_request_http_transport import _server_date
from .target_lifecycle_dependencies import _envelope, _one
from .target_operation_records import _TargetOperationRecords

CONTRACT = "fortipam-build29-jwt-rotation-owner-source-v3"
PHASES = ("user-create", "user-initialize", "overlap", "cutover", "restore", "user-remove")
_ERROR = "The fixed Owner JWT rotation source is unavailable."
_SCHEMA = "/api/v2/cmdb/system/api-user?action=schema&with_meta=true"
_DEFAULTS = "/api/v2/cmdb/system/api-user?action=default&with_meta=true"


class JwtRotationOwnerSourceError(RuntimeError):
    """Value-free refusal, preserving every consumed or uncertain operation."""


class JwtRotationOriginalCreation(_OpaqueC3Object):
    """Authenticate in-place original creation custody without changing it."""

    def __init__(self, owner: JwtManualKeyOwnerHttp, store: PersistentM4ExecutionStateStore,
            directory: Path, authority_key_file: Path, *, environment_ref: str, scope_ref: str, audience_ref: str) -> None:
        if (type(owner) is not JwtManualKeyOwnerHttp or type(store) is not PersistentM4ExecutionStateStore
                or store._read_only is not True):
            raise JwtRotationOwnerSourceError(_ERROR)
        self.owner,self.store,self.directory,self.key_file = owner,store,directory,authority_key_file
        self.refs = (environment_ref,scope_ref,audience_ref)
        self._pin = self.verify()

    def verify(self) -> str:
        try:
            owner,store,directory = self.owner,self.store,self.directory
            key = _key(self.key_file); _private_directory(directory)
            if (key == owner._witness or key == store._key or owner._witness == store._key
                    or not hmac.compare_digest(_key(store._key_path),store._key)):
                raise ValueError
            binding = JwtManualKeyOwnerWorkflow._binding_for(owner,store,"create",self.key_file,key,*self.refs,directory)
            grant = _GrantReader(directory,_digest(binding)).read()
            body = {k:v for k,v in grant.items() if k != "hmac"}
            if grant.get("binding") != binding or not hmac.compare_digest(grant.get("hmac",""),_mac(key,"grant",body)):
                raise ValueError
            plan,auth = _derive(binding,grant["context"],key)
            native = owner._sealed("create.claim.json"); ack = owner._acknowledged_creation()
            post = owner._sealed("create.state.json")
            if (grant["plan"] != asdict(plan) or grant["authorization"] != asdict(auth)
                    or native["plan"] != asdict(plan) or native["authorization"] != asdict(auth)
                    or post["ack_digest"] != _digest(ack) or post["request_digest"] != owner._request.digest):
                raise ValueError
            claim = store.inspect_claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
                idempotency_digest=plan.idempotency_digest,authorization_digest=auth.authorization_digest,
                context_digest=canonical_digest({"plan_digest":plan.plan_digest,"authorization_digest":auth.authorization_digest,"revision":plan.revision}))
            if claim.result is None or (claim.result.outcome,claim.result.verification) != ("succeeded","verified"):
                raise ValueError
            result = _digest({"grant":grant,"native":native,"ack":ack,"post":post})
            if hasattr(self,"_pin") and self._pin != result:
                raise ValueError
            return result
        except Exception:
            raise JwtRotationOwnerSourceError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class JwtRotationObservation(_OpaqueC3Object):
    current_digest: str
    key_phase: str
    user_present: bool
    key_invariant_hmac: str
    other_users_digest: str
    user_projection_hmac: str | None


class JwtRotationOwnerSource(_TargetOperationRecords):
    def __init__(self, original: JwtRotationOriginalCreation, binding: JwtManualRotationBinding,
            keys: JwtManualRotationKeys, *, directory: Path, witness_key_file: Path,
            user_schema_digest: str, user_defaults_digest: str, execution_enabled: bool = False) -> None:
        try:
            if (type(original) is not JwtRotationOriginalCreation or type(binding) is not JwtManualRotationBinding
                    or type(keys) is not JwtManualRotationKeys or type(execution_enabled) is not bool
                    or binding._key_name != original.owner._request._name
                    or binding.serial_digest != original.owner._request.serial_digest):
                raise ValueError
            _require_digest(user_schema_digest); _require_digest(user_defaults_digest)
            _private_directory(directory)
            self.original,self.owner,self.binding,self.keys = original,original.owner,binding,keys
            self._directory,self._identity = directory,(directory.stat().st_dev,directory.stat().st_ino)
            self._key_file,self._key = witness_key_file,_key(witness_key_file)
            if self._key in (self.owner._witness,original.store._key,_key(original.key_file)):
                raise ValueError
            self._schema_digest,self._defaults_digest = user_schema_digest,user_defaults_digest
            self._namespace = _digest({"contract":CONTRACT,"original":original.verify(),"owner":self.owner._namespace,
                "binding":binding.digest,"keys":keys.digest,"schema":user_schema_digest,"defaults":user_defaults_digest,
                "directory":str(directory),"identity":self._identity,"witness_file":str(witness_key_file),
                "witness":hashlib.sha256(self._key).hexdigest()})
            self._enabled = execution_enabled; self._closed = False
            self._user_absence = "/api/v2/cmdb/system/api-user/" + quote(binding._user_name,safe="") + "?format=name%7Ctype%7Cjwt-key&with_meta=true"
            self._user_detail = "/api/v2/cmdb/system/api-user/" + quote(binding._user_name,safe="") + "?format=" + "%7C".join(
                ("name","comments","accprofile","schedule","trusthost","vdom","type","claims","jwt-key","lease-duration")) + "&with_meta=true"
            self._last_observed = 0.0
            self.observation_failures: list[dict[str,Any]] = []
        except Exception:
            raise JwtRotationOwnerSourceError(_ERROR) from None

    def _integrity(self) -> None:
        _private_directory(self._directory)
        if ((self._directory.stat().st_dev,self._directory.stat().st_ino) != self._identity
                or not hmac.compare_digest(_key(self._key_file),self._key)):
            raise JwtRotationOwnerSourceError(_ERROR)

    def live(self) -> None:
        self._integrity(); self.owner._source(); self.original.verify()
        if self._closed or self.owner is not self.original.owner:
            raise JwtRotationOwnerSourceError(_ERROR)

    def _record_name(self, name: str) -> None:
        if name != "baseline.json" and name not in {phase+suffix for phase in PHASES for suffix in (".claim.json",".response.json",".ack.json",".state.json")}:
            raise ValueError

    def seal(self, name: str, value: dict[str,Any]) -> None:
        self._integrity(); self._record_name(name)
        payload = {"contract":CONTRACT,"namespace":self._namespace,**value}
        mac = hmac.new(self._key,(name+"\x00"+_digest(payload)).encode(),hashlib.sha256).hexdigest()
        with self._lock() as directory:
            self._write(directory,name,{**payload,"hmac":mac})

    def sealed(self, name: str) -> dict[str,Any]:
        self._integrity(); self._record_name(name)
        with self._lock() as directory:
            result = self._read(directory,name)
        payload = {k:v for k,v in result.items() if k != "hmac"}
        mac = hmac.new(self._key,(name+"\x00"+_digest(payload)).encode(),hashlib.sha256).hexdigest()
        if payload.get("contract") != CONTRACT or not hmac.compare_digest(result.get("hmac",""),mac):
            raise ValueError
        return payload

    def _user_ack(self) -> dict[str,Any]:
        claim,ack = self.sealed("user-create.claim.json"),self.sealed("user-create.ack.json")
        if ack["claim_digest"] != _digest(claim):
            raise ValueError
        return ack

    def _qualified_previous(self, phase: str) -> None:
        claim,ack,state = self.sealed(phase+".claim.json"),self.sealed(phase+".ack.json"),self.sealed(phase+".state.json")
        response = self.sealed(phase+".response.json")
        if (ack["claim_digest"] != _digest(claim) or ack["response_digest"] != _digest(response)
                or state["ack_digest"] != _digest(ack) or state["expected_digest"] != self.expected(phase)
                or claim["parameters_digest"] != self.parameters(phase)):
            raise ValueError
        key_path = Path(claim["store_key_file"])
        if hashlib.sha256(_key(key_path)).hexdigest() != claim["store_key_digest"]:
            raise ValueError
        store = PersistentM4ExecutionStateStore(Path(claim["store_path"]),key_path,read_only=True)
        plan,auth = M4ExecutionPlan(**claim["plan"]),M4ExecutionAuthorization(**claim["authorization"])
        original = store.inspect_claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest,authorization_digest=auth.authorization_digest,
            context_digest=canonical_digest({"plan_digest":plan.plan_digest,"authorization_digest":auth.authorization_digest,"revision":plan.revision}))
        if original.result is None or (original.result.outcome,original.result.verification) != ("succeeded","verified"):
            raise ValueError

    def _read_fixed(self, path: str, *, absent: bool = False) -> tuple[bytearray,datetime | None]:
        self.owner._source()
        if path not in {_SCHEMA,_DEFAULTS,self._user_absence,self._user_detail} or absent != (path == self._user_absence):
            raise ValueError
        if path == self._user_detail:
            self._user_ack()
        if self.owner._session is None or time.monotonic()>=self.owner._deadline:
            raise ValueError
        with self.owner._session.stream("GET",path,headers={"Accept":"application/json","Cache-Control":"no-cache, no-store"}) as response:
            if response.status_code != (404 if absent else 200):
                raise ValueError
            return self.owner._raw(response),_server_date(response.headers.get("date"))

    def _definitions(self, schema: bytearray, defaults: bytearray) -> None:
        values = []
        for raw,action in ((schema,"schema"),(defaults,"default")):
            span = _envelope(raw,path="system",name="api-user",serial_digest=self.binding.serial_digest,action=action)
            top = _top(raw)
            if "schema_errors" in top:
                raise ValueError
            fields = _object_spans(raw,*_one(raw,span))
            if action == "schema":
                fields = _object_spans(raw,*fields["children"])
            if not USER_FIELDS<=fields.keys():
                raise ValueError
            values.append(_digest({k:json.loads(raw[slice(*fields[k])])for k in sorted(USER_FIELDS)}))
        if tuple(values) != (self._schema_digest,self._defaults_digest):
            raise ValueError

    def _acknowledged_unknown_overlap(self) -> None:
        """Qualify original unknown overlap custody only for a fresh restore."""
        if os.path.lexists(self._directory/"overlap.state.json"):
            raise ValueError
        claim,ack,response = (self.sealed("overlap"+suffix) for suffix in (".claim.json",".ack.json",".response.json"))
        if (claim["namespace"] != self._namespace or ack["namespace"] != self._namespace
                or response["namespace"] != self._namespace
                or claim["parameters_digest"] != self.parameters("overlap")
                or ack["claim_digest"] != _digest(claim) or ack["response_digest"] != _digest(response)
                or response["http_status"] != 200 or response["native_status"] != "success"
                or response["native_context_matches"] is not True or response["mkey_matches"] is not True
                or response["complete"] is not True or response["content_kind"] != "json"):
            raise ValueError
        key_path = Path(claim["store_key_file"])
        if hashlib.sha256(_key(key_path)).hexdigest() != claim["store_key_digest"]:
            raise ValueError
        store = PersistentM4ExecutionStateStore(Path(claim["store_path"]),key_path,read_only=True)
        plan,auth = M4ExecutionPlan(**claim["plan"]),M4ExecutionAuthorization(**claim["authorization"])
        original = store.inspect_claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest,authorization_digest=auth.authorization_digest,
            context_digest=canonical_digest({"plan_digest":plan.plan_digest,"authorization_digest":auth.authorization_digest,"revision":plan.revision}))
        if original.result is None or (original.result.outcome,original.result.verification) != ("reconciliation_required","unknown"):
            raise ValueError

    def observe(self, *, key_phases: tuple[str,...], user_present: bool) -> JwtRotationObservation:
        buffers: list[bytearray] = []
        diagnostic: dict[str,Any] = {"stage":"source","user_present_expected":user_present}
        try:
            self.live(); self.owner._deadline = time.monotonic()+60
            first,date_before = self.owner._get(_STATE); buffers.append(first)
            _owner_state(first,self.owner._config.owner_name,self.binding.serial_digest)
            mapping,_ = self.owner._get(self.owner._owner_role); buffers.append(mapping)
            schema,_ = self._read_fixed(_SCHEMA); buffers.append(schema)
            defaults,_ = self._read_fixed(_DEFAULTS); buffers.append(defaults)
            diagnostic["stage"] = "definitions"
            self._definitions(schema,defaults)
            diagnostic["stage"] = "fixed_key_reads"
            key_before,_ = self.owner._get(self.owner._detail,owned=True); buffers.append(key_before)
            key_rows,_ = self.owner._get(_KEYS); buffers.append(key_rows)
            user_rows,_ = self.owner._get(_USERS); buffers.append(user_rows)
            key_after,_ = self.owner._get(self.owner._detail,owned=True); buffers.append(key_after)
            baseline = self.sealed("baseline.json") if os.path.lexists(self._directory/"baseline.json") else None
            if baseline is None:
                if user_present or key_phases != ("original",):
                    raise ValueError
                original_claim = self.owner._sealed("create.claim.json")
                original_post = self.owner._sealed("create.state.json")
                consume_jwt_manual_key_owned_state(bytearray(key_before),bytearray(key_rows),bytearray(user_rows),bytearray(key_after),
                    request=self.owner._request,baseline=JwtManualKeyPreflight(**original_claim["baseline"]),
                    witness_key=self.owner._witness,expected_full_row_hmac=original_post["full_row_hmac"])
            diagnostic["stage"] = "dependencies"
            deps = consume_jwt_rotation_dependencies(key_rows,user_rows,binding=self.binding,user_present=user_present,
                expected_other_users_digest=None if baseline is None else baseline["other_users_digest"])
            key_state = None
            diagnostic["stage"] = "key_state"
            key_fields = _object_spans(key_before,*_one(key_before,_envelope(key_before,path="secret",name="jwt-key",serial_digest=self.binding.serial_digest)))
            if "q_ref" in key_fields:
                refs = json.loads(key_before[slice(*key_fields["q_ref"])])
                diagnostic["key_reference_count"] = refs if type(refs) is int and 0<=refs<128 else "unqualified"
            for phase in key_phases:
                try:
                    key_state = consume_jwt_rotation_key_state(bytearray(key_before),bytearray(key_after),binding=self.binding,keys=self.keys,
                        phase=phase,reference_count=int(user_present),witness_key=self._key,
                        expected_invariant_hmac=None if baseline is None else baseline["key_invariant_hmac"])
                    break
                except JwtManualRotationContractError:
                    continue
            if key_state is None:
                raise ValueError
            user_state = None
            if user_present:
                diagnostic["stage"] = "owned_user_reads"
                user_before,_ = self._read_fixed(self._user_detail); buffers.append(user_before)
                user_after,_ = self._read_fixed(self._user_detail); buffers.append(user_after)
                user_fields = _object_spans(user_before,*_one(user_before,_envelope(user_before,path="system",name="api-user",serial_digest=self.binding.serial_digest)))
                diagnostic.update(stage="owned_user_state",user_field_count=len(user_fields),
                    user_missing_config_fields=sorted(USER_FIELDS-user_fields.keys()))
                diagnostic["user_config_matches"] = {name:(type(json.loads(user_before[slice(*user_fields[name])])) is type(value)
                    and json.loads(user_before[slice(*user_fields[name])]) == value) for name,value in self.binding.user_config().items() if name in user_fields}
                expected_meta = {"q_origin_key":self.binding._user_name,"q_path":"system","q_name":"api-user","q_mkey_type":"string",
                    "q_ref":0,"q_static":False,"q_no_edit":False,"q_no_rename":True,"q_global_entry":False}
                diagnostic["user_metadata_matches"] = {name:(name in user_fields
                    and type(json.loads(user_before[slice(*user_fields[name])])) is type(value)
                    and json.loads(user_before[slice(*user_fields[name])]) == value) for name,value in expected_meta.items()}
                expected_user = self.sealed("user-create.state.json")["user_projection_hmac"] if os.path.lexists(self._directory/"user-create.state.json") else None
                user_state = consume_jwt_rotation_owned_user(user_before,user_after,binding=self.binding,
                    witness_key=self._key,expected_projection_hmac=expected_user)
            else:
                diagnostic["stage"] = "user_absence"
                absence,_ = self._read_fixed(self._user_absence,absent=True); buffers.append(absence)
                consume_jwt_rotation_user_absence(absence,binding=self.binding)
            last,date_after = self.owner._get(_STATE); buffers.append(last)
            diagnostic["stage"] = "owner_brackets"
            if date_before is None or date_after is None:
                raise ValueError
            actor = consume_jwt_manual_key_owner_actor_inputs(first,mapping,last,expected_owner=self.owner._config.owner_name,
                serial_digest=self.binding.serial_digest,first_device_date=date_before,last_device_date=date_after)
            original_claim = self.owner._sealed("create.claim.json")
            if actor.actor_digest != original_claim["owner_actor_digest"] or actor.mapping_digest != original_claim["owner_mapping_digest"]:
                raise ValueError
            self.live()
            if baseline is None:
                self.seal("baseline.json",{"key_invariant_hmac":key_state.invariant_hmac,"other_users_digest":deps.other_users_digest,
                    "original_key_complete_hmac":key_state.complete_row_hmac})
            user_hmac = None if user_state is None else user_state.complete_projection_hmac
            current = _digest({"contract":CONTRACT,"namespace":self._namespace,"session":self.owner._session_digest,
                "actor":actor.actor_digest,"mapping":actor.mapping_digest,"key":asdict(key_state),"dependencies":asdict(deps),"user":user_hmac})
            self._last_observed = time.monotonic()
            return JwtRotationObservation(current,key_state.phase,user_present,key_state.invariant_hmac,deps.other_users_digest,user_hmac)
        except Exception:
            if len(self.observation_failures)<8:
                self.observation_failures.append(diagnostic)
            raise JwtRotationOwnerSourceError(_ERROR) from None
        finally:
            for raw in buffers:
                _zeroize_mutable(raw)

    def current(self, phase: str, *, recovery: bool = False) -> JwtRotationObservation:
        if phase not in PHASES:
            raise JwtRotationOwnerSourceError(_ERROR)
        if phase == "user-create":
            if os.path.lexists(self._directory/"user-create.claim.json"):
                raise JwtRotationOwnerSourceError(_ERROR)
            return self.observe(key_phases=("original",),user_present=False)
        self._user_ack()
        states: dict[str,tuple[str,...]] = {"user-initialize":("original",),"overlap":("original",),"cutover":("overlap",),"restore":("cutover",),"user-remove":("restore",)}
        if recovery and phase in {"restore","user-remove"}:
            states[phase] = ("original","overlap","cutover") if phase == "restore" else ("original","restore")
        else:
            previous = {"user-initialize":"user-create","overlap":"user-initialize","cutover":"overlap","restore":"cutover","user-remove":"restore"}[phase]
            self._qualified_previous(previous)
        if (recovery and phase == "restore" and os.path.lexists(self._directory/"overlap.claim.json")
                and not os.path.lexists(self._directory/"overlap.state.json")):
            self._acknowledged_unknown_overlap()
        observation = self.observe(key_phases=states[phase],user_present=True)
        if recovery and observation.key_phase in {"overlap","cutover"}:
            claim = self.sealed(observation.key_phase+".claim.json")
            if claim["parameters_digest"] != self.parameters(observation.key_phase):
                raise ValueError
        return observation

    def expected(self, phase: str) -> str:
        if phase not in PHASES:
            raise ValueError
        baseline = self.sealed("baseline.json")
        return _digest({"contract":CONTRACT,"namespace":self._namespace,"phase":phase,
            "key_invariant":baseline["key_invariant_hmac"],"other_users":baseline["other_users_digest"],"complete_fixed_transition":True})

    def _write_guard(self, phase: str, request_digest: str, plan: M4ExecutionPlan,
            auth: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore) -> None:
        self.live()
        if (not self._enabled or not self.owner._enabled or self.owner._session is None or self.owner._csrf is None
                or type(store) is not PersistentM4ExecutionStateStore or store._read_only
                or not hmac.compare_digest(_key(store._key_path),store._key)
                or store._key in (self._key,self.owner._witness,self.original.store._key,_key(self.original.key_file))
                or plan.action_id != "jwt-rotation-"+phase or plan.action_version != "3.0.0"
                or plan.adapter_ref != "fortipam-build29-jwt-rotation-"+phase+"-v3"
                or plan.target_ref != "bound-original-key-and-jwt-user" or plan.parameters_digest != request_digest
                or plan.requester_digest != self.owner._config.requester_digest or plan.compensation_ref is not None
                or not auth.issued_at <= int(time.time()) < min(auth.expires_at,plan.expires_at)):
            raise JwtRotationOwnerSourceError(_ERROR)
        _require_m4_dispatch_ownership(plan,auth,store)

    def parameters(self, phase: str) -> str:
        if phase == "user-remove":
            return _digest({"contract":CONTRACT,"binding":self.binding.digest,"keys":self.keys.digest,"phase":phase,"method":"DELETE"})
        request = JwtManualRotationRequest(self.binding,self.keys,phase=phase)
        try:
            return request.digest
        finally:
            request.close()

    def dispatch(self, phase: str, plan: M4ExecutionPlan, auth: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore, *, recovery: bool = False) -> None:
        raw = body = bytearray(); request = None
        try:
            params = self.parameters(phase); self._write_guard(phase,params,plan,auth,store)
            if os.path.lexists(self._directory/(phase+".claim.json")):
                raise ValueError
            current = self.current(phase,recovery=recovery)
            if current.current_digest != plan.expected_current_digest or self.expected(phase) != plan.expected_state_digest:
                raise ValueError
            if phase == "user-remove":
                method,path,table,mkey = "DELETE","/api/v2/cmdb/system/api-user/"+quote(self.binding._user_name,safe=""),"api-user",self.binding._user_name
            else:
                request = JwtManualRotationRequest(self.binding,self.keys,phase=phase)
                method,path = request.method,request.path+("?"+request.query if request.query else"")
                with request.borrow_body() as view:
                    body = bytearray(view)
                table,mkey = ("api-user",self.binding._user_name) if phase in {"user-create","user-initialize"} else ("jwt-key",self.binding._key_name)
            self._write_guard(phase,params,plan,auth,store)
            self.seal(phase+".claim.json",{"plan":asdict(plan),"authorization":asdict(auth),"parameters_digest":params,
                "store_path":str(store._path),"store_key_file":str(store._key_path),"store_key_digest":hashlib.sha256(store._key).hexdigest(),
                "recovery":recovery,"body_digest":hashlib.sha256(body).hexdigest()})
            status = None; complete = False; kind = "unknown"; interrupted = None
            try:
                with self.owner._session.stream(method,path,content=bytes(body) if method != "DELETE" else None,
                        headers={"Accept":"application/json","Content-Type":"application/json","X-Requested-With":"XMLHttpRequest","X-CSRFTOKEN":self.owner._csrf}) as response:
                    status = response.status_code; kind = "json" if response.headers.get("content-type","").split(";",1)[0].strip().lower() == "application/json" else "other"
                    for chunk in response.iter_bytes():
                        remaining = MAX_RESPONSE_BYTES-len(raw); raw.extend(chunk[:remaining])
                        if len(chunk)>remaining:
                            raise ValueError
                    complete = True
            except BaseException as error:
                if not isinstance(error,Exception):
                    interrupted = error
            summary: dict[str,Any] = {"native_status":"unknown","native_error":None,"native_context_matches":False,"mkey_matches":False,
                "native_action_matches":False,"initialization_token_field_present":False}
            if complete and kind == "json":
                try:
                    selected = _top(raw)
                    values = {k:json.loads(raw[slice(*selected[k])])for k in ("version","build","serial","http_method","status","path","name")}
                    native_error_code = json.loads(raw[slice(*selected["error"])]) if "error" in selected else None
                    summary.update(native_status=values["status"] if values["status"] in {"success","error"} else "unknown",
                        native_error=native_error_code if type(native_error_code) is int and -(2**31)<=native_error_code<2**31 else None,
                        native_context_matches=values["version"] == "v7.0.0" and type(values["build"]) is int and values["build"] == 29
                            and hashlib.sha256(values["serial"].encode()).hexdigest() == self.binding.serial_digest
                            and values["http_method"] == method and values["path"] == ("system" if table == "api-user" else "secret")
                            and values["name"] == table and ("vdom" not in selected or json.loads(raw[slice(*selected["vdom"])]) == "root"),
                        mkey_matches=(phase == "user-initialize" and "mkey" not in selected)
                            or "mkey" in selected and json.loads(raw[slice(*selected["mkey"])]) == mkey,
                        native_action_matches=(json.loads(raw[slice(*selected["action"])]) if "action" in selected else"")
                            == ("generate-key"if phase == "user-initialize"else""))
                    if phase == "user-initialize":
                        summary["initialization_metadata_presence"] = {name:name in selected for name in
                            ("version","build","serial","http_method","status","path","name","action","results","vdom","http_status","mkey","error")}
                        summary["initialization_top_field_count"] = len(selected)
                        if "results" in selected:
                            generated = _object_spans(raw,*selected["results"])
                            summary["initialization_token_field_present"] = "access_token" in generated
                            summary["initialization_result_field_count"] = len(generated)
                except Exception:
                    pass
            self.seal(phase+".response.json",{"claim_digest":_digest(self.sealed(phase+".claim.json")),"http_status":status,
                "content_kind":kind,"complete":complete,"body_bytes":len(raw),"body_hmac":hmac.new(self._key,raw,hashlib.sha256).hexdigest(),**summary})
            if interrupted is not None:
                raise interrupted
            if status != 200 or kind != "json" or not complete:
                raise ValueError
            initialization = None
            if phase == "user-initialize":
                initialization = consume_jwt_user_initialization(raw,binding=self.binding,
                    claim_digest=_digest(self.sealed(phase+".claim.json")),witness_key=self._key)
            else:
                self._qualify_cmdb_ack(raw,method=method,table=table,mkey=mkey)
            self.seal(phase+".ack.json",{"claim_digest":_digest(self.sealed(phase+".claim.json")),
                "response_digest":_digest(self.sealed(phase+".response.json")),
                **({"generated_key_witness":initialization,"generated_key_locally_discarded":True}if initialization is not None else{})})
            after_phase = {"user-create":"original","user-initialize":"original","overlap":"overlap","cutover":"cutover","restore":"restore","user-remove":"restore"}[phase]
            post = self.observe(key_phases=(after_phase,),user_present=phase != "user-remove")
            self.seal(phase+".state.json",{"ack_digest":_digest(self.sealed(phase+".ack.json")),
                "expected_digest":self.expected(phase),**asdict(post)})
        except Exception:
            raise JwtRotationOwnerSourceError(_ERROR) from None
        finally:
            _zeroize_mutable(raw); _zeroize_mutable(body)
            if request is not None:
                request.close()

    def _qualify_cmdb_ack(self, raw: bytearray, *, method: str, table: str, mkey: str) -> None:
        top = _top(raw)
        expected = {"version":"v7.0.0","build":29,"http_method":method,"http_status":200,"status":"success",
            "path":"system" if table == "api-user" else "secret","name":table,"vdom":"root","mkey":mkey}
        for field,value in expected.items():
            actual = json.loads(raw[slice(*top[field])])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        serial = json.loads(raw[slice(*top["serial"])])
        if hashlib.sha256(serial.encode()).hexdigest() != self.binding.serial_digest or "schema_errors" in top:
            raise ValueError
        if "error" in top:
            error_code = json.loads(raw[slice(*top["error"])])
            if type(error_code) is not int or error_code != 0:
                raise ValueError
        if "action" in top and json.loads(raw[slice(*top["action"])]) != "":
            raise ValueError

    def probe_ready(self) -> bool:
        self.live(); self._user_ack(); self._qualified_previous("user-initialize")
        return self._enabled and time.monotonic()-self._last_observed<=60

    def close(self) -> None:
        self._enabled = False; self._closed = True
