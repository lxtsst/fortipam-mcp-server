"""Default-off original-owned reset M4 using the fixed Owner REST primitive.

Version 1 proves the original changed ACK and preserved full configuration.
Explicit version 2 also requires one new-password identity check and logout
inside the same M4. Neither version delivers passwords or auto-compensates.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import http.client
import json
import os

import httpx
from threading import RLock
from typing import TYPE_CHECKING,Any

from v4_planning import M4AdapterAmbiguous,M4AdapterDenied,M4ExecutionPlan,canonical_digest
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from .ldap_server_runtime import _key,_private_directory,_read
from .local_user_reset_http_transport import (
    FortiPamLocalUserResetHttpTransport,LocalUserResetHttpOutcome,_POLICY_PATH,_CHANGE_PATH,_response_flag,
)
from .local_user_reset_material_source import _directory_identity,_write_once
from .local_user_reset_owned_authority import LocalResetOwnedM4Authority,LocalResetOwnedIssued
from .local_user_reset_owned_material import LocalResetOwnedMaterialSource
from .local_user_reset_owner_session import LocalUserResetOwnerSessionTransport
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end,_skip_json_space,_zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

if TYPE_CHECKING:
    from .local_user_reset_owned_login import LocalResetOwnedLogin

_ERROR="The private original-owned REST reset is unavailable."
_DOMAIN=b"original-owned-reset-journal/v1\x00"
_RUN,_RESULT,_FAILURE="reset-run.json","reset-result.json","reset-failure.json"
_FILES=(_RUN,_RESULT,_FAILURE,"login-send.json","login-result.json",*tuple(operation+suffix for operation in ("policy","change")
    for suffix in ("-send.json","-response.json","-ack.json","-identity.json")))


class LocalResetOwnedAdapter(_OpaqueC3Object):
    def __init__(self,material: LocalResetOwnedMaterialSource,authority: LocalResetOwnedM4Authority,issued: LocalResetOwnedIssued,
            *,execution_enabled: bool=False,connection_factory: Callable[...,Any]=http.client.HTTPSConnection,
            login_client_factory: Callable[...,Any]=httpx.Client) -> None:
        try:
            if (type(material) is not LocalResetOwnedMaterialSource or type(authority) is not LocalResetOwnedM4Authority
                    or type(issued) is not LocalResetOwnedIssued or authority._material is not material or authority._issued is not issued
                    or type(execution_enabled) is not bool or not callable(connection_factory) or not callable(login_client_factory)):raise ValueError
            material.require_unclaimed()
            self._material,self._authority,self._issued=material,authority,issued
            self._sources,self._store=material._sources,material._store
            self._plan,self._authorization=issued.plan,issued.authorization
            self._directory,self._identity,self._key_file,self._key=material._directory,material._identity,material._key_file,material._key
            self._context=canonical_digest(dict(contract="original-owned-reset-login-journal/v2" if material._verify_login else "original-owned-reset-journal/v1",plan=self._plan.plan_digest,
                authorization=self._authorization.authorization_digest,parameters=material.parameters_digest,
                fixture=material._inspector._creation_digest))
            self._enabled,self._closed=execution_enabled,False
            self._login_factory=login_client_factory;self._login: LocalResetOwnedLogin|None=None
            self._factory=connection_factory;self._lock=RLock();self._wires: list[_Wire]=[]
            self._operations: list[str]=[];self._resources_closed=True;self._native_attempts=0
            self._owner: LocalUserResetOwnerSessionTransport|None=None
            self._transport: FortiPamLocalUserResetHttpTransport|None=None
            self._dispatch_callback=self._guard
            self._pending()
        except Exception:raise M4AdapterDenied(_ERROR) from None

    def _journal_storage(self) -> None:
        _private_directory(self._directory);self._store.verify_ready()
        if (_directory_identity(self._directory)!=self._identity or not hmac.compare_digest(_key(self._key_file),self._key)
                or not hmac.compare_digest(_key(self._store._key_path),self._store._key)):raise ValueError

    def _signature(self,name: str,record: dict[str,Any]) -> str:
        return hmac.new(self._key,_DOMAIN+name.encode()+b"\x00"+
            json.dumps(record,sort_keys=True,separators=(",",":"),allow_nan=False).encode(),hashlib.sha256).hexdigest()

    def _write(self,name: str,fields: dict[str,Any]) -> None:
        self._journal_storage()
        if name not in _FILES:raise ValueError
        _require_m4_dispatch_ownership(self._plan,self._authorization,self._store)
        claim=self._store.inspect_claim(plan_ref=self._plan.plan_ref,requester_digest=self._plan.requester_digest,
            idempotency_digest=self._plan.idempotency_digest,authorization_digest=self._authorization.authorization_digest,
            context_digest=canonical_digest(dict(plan_digest=self._plan.plan_digest,
                authorization_digest=self._authorization.authorization_digest,revision=self._plan.revision)))
        if claim.result is not None:raise ValueError
        record={**fields,"context_digest":self._context}
        raw=bytearray(json.dumps({**record,"signature":self._signature(name,record)},sort_keys=True,separators=(",",":"),allow_nan=False).encode())
        try:_write_once(self._directory,self._identity,name,raw)
        finally:_zeroize_mutable(raw)

    def _record(self,name: str) -> dict[str,Any]:
        from . import secret_bulk_import_metadata as m
        if name not in _FILES:raise ValueError
        self._journal_storage();raw=_read(self._directory/name,8192)
        try:
            left=_skip_json_space(raw,0);right=_json_value_end(raw,left)
            if _skip_json_space(raw,right)!=len(raw):raise ValueError
            m._validate_json(raw,left,right,depth=0,budget=[10000])
            record={key:m._scalar(raw,span) for key,span in _object_spans(raw,left,right).items()};signature=record.pop("signature")
            if (record.get("context_digest")!=self._context or type(signature) is not str
                    or not hmac.compare_digest(signature,self._signature(name,record))):raise ValueError
            return record
        finally:_zeroize_mutable(raw)

    def _pending(self) -> None:
        self._journal_storage()
        if any(os.path.lexists(self._directory/name) for name in _FILES):raise ValueError

    def _active(self,plan: M4ExecutionPlan) -> None:
        if (not self._enabled or self._closed or plan is not self._plan or self._authority._issued is not self._issued
                or self._authority._material is not self._material or self._material._store is not self._store
                or self._plan.expected_state_digest!=self._authority.expected_digest):raise ValueError
        self._journal_storage();self._authority.check_active(self._issued)

    def _guard(self) -> None:
        self._active(self._plan);self._material._active(self._plan,self._authorization)
        remaining=self._authorization.expires_at-self._authority._now()
        for wire in self._wires:
            sock=getattr(wire._raw,"sock",None)
            if not wire._closed and sock is not None and sock.fileno()>=0:
                sock.settimeout(min(float(self._sources._config.timeout_seconds),float(remaining)))

    def read_current(self,plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan);self._pending()
                self._sources.observe_presence();self._authority.check_current(self._issued)
                return self._material.current_digest()
        except Exception:raise M4AdapterDenied(_ERROR) from None

    def _connection(self,*args: Any,**kwargs: Any) -> _Wire:
        self._guard()
        if self._owner is None or self._transport is None or self._owner._binding is not self._transport._binding:raise ValueError
        if len(self._operations)>=2:raise ValueError
        operation="policy_conform" if not self._operations else "change_password"
        if operation not in self._owner._reserved:raise ValueError
        self._operations.append(operation)
        raw=self._factory(*args,**kwargs);wire=_Wire(self,raw,operation);self._wires.append(wire)
        try:
            raw.connect();self._guard()
            # The fixed primitive already reads complete User state at each
            # decision; this read also catches drift during TLS before send.
            self._material.check_staged();self._guard()
            return wire
        except BaseException:
            wire.close();raise

    def dispatch(self,plan: M4ExecutionPlan) -> None:
        claimed=False;stage="original_dispatch"
        try:
            with self._lock,_private_http_logs():
                self._guard();self._pending();claimed=True
                self._write(_RUN,dict(current_digest=self._material.current_digest(),claimed_at=self._authority._now()))
                stage="initial_material_lease";lease=self._material.acquire_original(plan,self._authorization)
                binding=self._material.check_staged()
                self._owner=LocalUserResetOwnerSessionTransport(self._sources._config,owner_name=self._sources._ssh.username,
                    credentials=self._sources._provider,binding=binding,enabled=True,client_factory=self._sources._factory,
                    connection_factory=self._connection,clock=self._sources._clock)
                self._transport=FortiPamLocalUserResetHttpTransport(self._sources._config,binding=binding,
                    inspector=self._material._inspector,owner_session=self._owner,material_lease_provider=lambda:lease,enabled=True)
                stage="owner_session"
                with self._owner.authenticated():
                    self._guard();stage="fixed_rest_reset"
                    result=self._transport._reset_with_dispatch_guard(self._dispatch_callback)
                    stage="owner_logout"
                stage="original_result"
                self._guard()
                if (result.outcome is not LocalUserResetHttpOutcome.BACKEND_CHANGED_METADATA_PRESERVED
                        or not result.backend_changed or not result.metadata_preserved or not result.change_post_attempted
                        or result.login_verified or not self._owner.logout_verified or self._owner._client is not None
                        or not self._resources_closed or self._native_attempts!=2):raise ValueError
                policy,change=self._record("policy-ack.json"),self._record("change-ack.json")
                if policy["accepted"] is not True or change["accepted"] is not True:raise ValueError
                login_digest=None
                if self._material._verify_login:
                    from .local_user_reset_owned_login import LocalResetOwnedLogin
                    stage="new_password_login";self._login=LocalResetOwnedLogin(self,client_factory=self._login_factory)
                    login=self._login.run()
                    if not all(login[key] is True for key in ("login_post_attempted","login_verified","logout_verified","resources_closed")):raise ValueError
                    stage="post_login_configuration";self._guard();self._sources.observe_presence()
                    self._material.check_staged();self._guard()
                    login_digest=canonical_digest(self._record("login-result.json"))
                self._write(_RESULT,dict(run_digest=canonical_digest(self._record(_RUN)),
                    policy_ack_digest=canonical_digest(policy),change_ack_digest=canonical_digest(change),
                    nonmaterial_state_digest=binding.expected.nonmaterial_state_digest,
                    backend_changed=True,metadata_preserved=True,login_verified=self._material._verify_login,
                    **({"login_ack_digest":login_digest} if self._material._verify_login else {}),
                    owner_logout_verified=True,verified_at=self._authority._now()))
        except Exception as error:
            if claimed:
                try:self._write(_FAILURE,dict(stage=stage,native_attempts=self._native_attempts,
                    state_failure_stage=self._sources._state._last_failure_stage,
                    source_failure_stage=self._sources._last_failure_stage,
                    error_class=type(error).__name__ if type(error).__name__ in {"ValueError","OSError","TimeoutError"} else "unavailable",
                    original_request_replayable=False))
                except Exception:pass
            if claimed and self._native_attempts:raise M4AdapterAmbiguous(_ERROR) from None
            raise M4AdapterDenied(_ERROR) from None
        finally:
            if self._transport is not None:self._transport._enabled=False
            if self._owner is not None:self._owner._enabled=False
            for wire in self._wires:
                try:wire.close()
                except Exception:self._resources_closed=False
            for raw in self._material._buffers:_zeroize_mutable(raw)

    def read_postcondition(self,plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan)
                record=self._record(_RESULT);run=self._record(_RUN)
                policy,change=self._record("policy-ack.json"),self._record("change-ack.json")
                policy_send,change_send=self._record("policy-send.json"),self._record("change-send.json")
                if (not self._resources_closed or self._owner is None or not self._owner.logout_verified or self._owner._client is not None
                        or record["run_digest"]!=canonical_digest(run) or run["current_digest"]!=plan.expected_current_digest
                        or record["policy_ack_digest"]!=canonical_digest(policy) or record["change_ack_digest"]!=canonical_digest(change)
                        or policy["send_digest"]!=canonical_digest(policy_send) or change["send_digest"]!=canonical_digest(change_send)
                        or policy["operation"]!="policy_conform" or change["operation"]!="change_password"
                        or policy["accepted"] is not True or change["accepted"] is not True
                        or policy_send["current_digest"]!=plan.expected_current_digest
                        or change_send["current_digest"]!=plan.expected_current_digest
                        or record["backend_changed"] is not True or record["metadata_preserved"] is not True
                        or record["login_verified"] is not self._material._verify_login or record["owner_logout_verified"] is not True
                        or record["nonmaterial_state_digest"]!=self._material._inspector._sealed.nonmaterial_state_digest
                        or not self._authorization.issued_at<=run["claimed_at"]<=policy_send["sent_at"]<=policy["acknowledged_at"]
                            <=change_send["sent_at"]<=change["acknowledged_at"]<=record["verified_at"]<self._authorization.expires_at):raise ValueError
                if self._material._verify_login:
                    login=self._record("login-result.json");send=self._record("login-send.json")
                    if (self._login is None or self._login._client is not None or not self._login._resources_closed
                            or record["login_ack_digest"]!=canonical_digest(login) or login["send_digest"]!=canonical_digest(send)
                            or send["change_ack_digest"]!=canonical_digest(change)
                            or not all(login[key] is True for key in ("login_post_attempted","login_verified","logout_verified","resources_closed"))
                            or not change["acknowledged_at"]<=send["sent_at"]<=login["finished_at"]<=record["verified_at"]):raise ValueError
                return plan.expected_state_digest
        except Exception:raise M4AdapterAmbiguous(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled=False;self._closed=True
            if self._login is not None:self._login.close()
            if self._transport is not None:self._transport._enabled=False
            if self._owner is not None:self._owner._enabled=False
            for wire in self._wires:
                try:wire.close()
                except Exception:self._resources_closed=False


class _Wire:
    def __init__(self,adapter: LocalResetOwnedAdapter,raw: Any,operation: str) -> None:
        self._adapter,self._raw,self._operation=adapter,raw,operation
        self._closed=self._sent=self._received=False
        self._prefix="policy" if operation=="policy_conform" else "change"

    def request(self,method: str,path: str,*,body: memoryview,headers: dict[str,str]) -> None:
        a=self._adapter;a._guard()
        if self._closed or self._sent or method!="POST" or path!=(_POLICY_PATH if self._prefix=="policy" else _CHANGE_PATH):raise ValueError
        self._sent=True
        a._write(self._prefix+"-send.json",dict(operation=self._operation,current_digest=a._material.current_digest(),sent_at=a._authority._now()))
        a._native_attempts+=1
        self._raw.request(method,path,body=body,headers=headers)

    def getresponse(self) -> _WireResponse:
        if self._closed or not self._sent or self._received:raise ValueError
        self._received=True;raw=self._raw.getresponse()
        try:return _WireResponse(self,raw)
        except BaseException:
            try:raw.close()
            except Exception:self._adapter._resources_closed=False
            raise

    def close(self) -> None:
        if not self._closed:
            self._closed=True
            try:self._raw.close()
            except Exception:self._adapter._resources_closed=False;raise


class _WireResponse:
    def __init__(self,wire: _Wire,raw: Any) -> None:
        self._wire,self._raw=wire,raw;self.status=raw.status;self._content=bytearray();self._closed=self._complete=False
        if type(self.status) is not int or not 100<=self.status<=599:raise ValueError
        wire._adapter._write(wire._prefix+"-response.json",dict(http_status=self.status,
            exact_json=raw.getheader("content-type","").split(";",1)[0].strip().lower()=="application/json",
            identity_encoding=raw.getheader("content-encoding","identity").lower()=="identity",raw_values_stored=False))

    def getheader(self,name: str,default: str="") -> str:return str(self._raw.getheader(name,default))

    def readinto(self,view: memoryview) -> int:
        if self._closed or self._complete:raise ValueError
        count=self._raw.readinto(view)
        if type(count) is not int or not 0<=count<=len(view) or len(self._content)+count>16384:raise ValueError
        self._content.extend(view[:count])
        if count==0:
            self._complete=True
            try:self._seal()
            finally:_zeroize_mutable(self._content)
        return int(count)

    def _seal(self) -> None:
        wire=self._wire;a=wire._adapter;a._guard()
        if type(self.status) is not int or self.status!=200:raise ValueError
        accepted=_response_flag(self._content,wire._operation)  # type: ignore[arg-type]
        left=_skip_json_space(self._content,0);right=_json_value_end(self._content,left);spans=_object_spans(self._content,left,right)
        identity={}
        for name,expected in (("serial",a._sources._serial),("mkey",a._sources._state._draft.username)):
            present=name in spans
            matches=not present or self._content[slice(*spans[name])]==json.dumps(expected,ensure_ascii=True).encode()
            identity[name+"_present"],identity[name+"_matched"]=present,matches
        a._write(wire._prefix+"-identity.json",identity)
        if not all(identity[name+"_matched"] for name in ("serial","mkey")):raise ValueError
        ack=hmac.new(a._key,_DOMAIN+b"original-response\x00"+a._context.encode()+wire._operation.encode(),hashlib.sha256)
        ack.update(self._content)
        a._write(wire._prefix+"-ack.json",dict(operation=wire._operation,
            send_digest=canonical_digest(a._record(wire._prefix+"-send.json")),acknowledgement_digest=ack.hexdigest(),
            accepted=accepted,acknowledged_at=a._authority._now()))

    def close(self) -> None:
        if not self._closed:
            self._closed=True;_zeroize_mutable(self._content)
            try:self._raw.close()
            except Exception:self._wire._adapter._resources_closed=False;raise
