"""Independent, requester-bound MCP surface for one original-owned REST reset.

Only protected composition selects the User and material. The three tools take
opaque references, keep lab-auto authorization server-side, and cannot select a
device, identity, credential, path or arbitrary operation.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import hmac
import http.client
import re
import secrets
from threading import RLock
import time
from typing import Any

import httpx

from v4_planning import M4ExecutionKernel, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest,require_ref

from .local_user_reset_execution import _mcp_requester_digest
from .local_user_reset_owned_adapter import LocalResetOwnedAdapter
from .local_user_reset_owned_authority import LocalResetOwnedM4Authority,LocalResetOwnedPreview,LocalResetOwnedIssued
from .local_user_reset_owned_material import LocalResetOwnedMaterialSource,_FIXTURE_CLAIM

CONTRACT="fortipam-build29-original-owned-rest-reset-mcp-v1"
LOGIN_CONTRACT="fortipam-build29-original-owned-rest-reset-login-mcp-v2"
TOOLS=("preview_v4_owned_local_user_reset","authorize_v4_owned_local_user_reset","execute_v4_owned_local_user_reset")
_REF=re.compile(r"owned-reset-(?:preview|authorized)-[a-f0-9]{48}\Z")
_ERROR="The original-owned Local User reset candidate is unavailable."


class LocalResetOwnedMcpError(RuntimeError):
    """Fixed non-disclosing refusal at the authenticated MCP boundary."""


@dataclass(slots=True,repr=False)
class _Record(_OpaqueC3Object):
    requester: str
    transport: str
    preview_ref: str
    authority: LocalResetOwnedM4Authority
    preview: LocalResetOwnedPreview
    issued: LocalResetOwnedIssued|None=None
    authorization_ref: str|None=None
    result: dict[str,object]|None=None
    adapter: LocalResetOwnedAdapter|None=None


class LocalResetOwnedMcpAction(_OpaqueC3Object):
    def __init__(self,material: LocalResetOwnedMaterialSource,*,authority_key: bytes,
            environment_ref: str,scope_ref: str,audience_ref: str,transport_digest: str,
            execution_enabled: bool=False,clock: Callable[[],int]|None=None,
            connection_factory: Callable[...,Any]=http.client.HTTPSConnection,
            login_client_factory: Callable[...,Any]=httpx.Client) -> None:
        try:
            if (type(material) is not LocalResetOwnedMaterialSource or type(authority_key) is not bytes
                    or not 32<=len(authority_key)<=128 or type(execution_enabled) is not bool
                    or material._enabled is not execution_enabled or not callable(connection_factory) or not callable(login_client_factory)
                    or clock is not None and not callable(clock)):raise ValueError
            for value in (environment_ref,scope_ref,audience_ref):require_ref(value,"owned_reset_scope")
            require_digest(transport_digest,"owned_reset_transport")
            material._storage();material.reference
            original=material._inspector._original
            if any(hmac.compare_digest(authority_key,key) for key in (
                    material._key,material._store._key,material._initial._key,original._key,original._store._key)):raise ValueError
            self._material,self._key=material,authority_key
            self._contract=LOGIN_CONTRACT if material._verify_login else CONTRACT
            self._environment,self._scope,self._audience=environment_ref,scope_ref,audience_ref
            self._transport=transport_digest;self._enabled,self._closed=execution_enabled,False
            self._clock=clock if clock is not None else lambda:int(time.time())
            self._last=-1;self._lock=RLock();self._records: dict[str,_Record]={};self._factory=connection_factory;self._login_factory=login_client_factory
        except Exception:raise LocalResetOwnedMcpError(_ERROR) from None

    def _now(self) -> int:
        now=self._clock()
        if self._closed or type(now) is not int or now<0 or now<self._last:raise ValueError
        self._last=now;return now

    def _identity(self,principal: object) -> tuple[str,str]:
        requester=_mcp_requester_digest(principal)
        return requester,canonical_digest(dict(contract=self._contract,runtime_transport=self._transport,
            authenticated_transport=getattr(principal,"transport_namespace_digest")))

    def _available(self) -> bool:
        return (not self._material._consumed and self._material._store.claim_count==0
            and not (self._material._initial._directory/_FIXTURE_CLAIM).exists()
            and not (self._material._initial._directory/_FIXTURE_CLAIM).is_symlink())

    def _projection(self,*,state: str,can_authorize: bool,record: _Record|None=None) -> dict[str,object]:
        value: dict[str,object]=dict(contract=self._contract,state=state,can_authorize=can_authorize,
            execution_gate_enabled=self._enabled,policy_mode="lab_auto",device_write_executed=False,
            credentials_returned=False,authentication_verified=False)
        if state=="not_ready":
            value["gaps"]=["execution_reserved_or_consumed"]
            return value
        value["Current State"]=dict(target="one_original_owned_enabled_local_guest",status="enable",access_profile="Guest",
            sponsor_group="empty",schedule="empty",reported_references="zero",usage_entries="zero")
        value["Proposed Changes"]=dict(operation="validate_policy_then_change_one_password",material="private_not_returned",**({"new_password_login_attempts":1,"target_logout_required":True} if self._material._verify_login else {}))
        value["Expected State"]=dict(backend_change_acknowledgement="required",complete_nonmaterial_state="preserved",
            authentication_verified=self._material._verify_login)
        if record is not None:
            value.update(preview_ref=record.preview_ref,current_state_digest=record.preview.current_digest,
                created_at=record.preview.created_at,expires_at=record.preview.expires_at)
        return value

    def preview(self,principal: object) -> dict[str,object]:
        try:
            requester,transport=self._identity(principal)
            with self._lock:
                now=self._now()
                if not self._available():return self._projection(state="not_ready",can_authorize=False)
                self._material._sources.observe_presence();self._material.check_staged()
                if not self._enabled:return self._projection(state="previewed",can_authorize=False)
                old=self._records.get(requester)
                if old is not None and old.issued is not None and now<old.preview.expires_at:
                    old.authority.check_active(old.issued)
                    return self._projection(state="authorized",can_authorize=False,record=old)
                if old is None and len(self._records)>=32:raise ValueError
                if old is not None:old.authority.close()
                authority=LocalResetOwnedM4Authority(self._material,authority_key=self._key,
                    environment_ref=self._environment,scope_ref=self._scope,audience_ref=self._audience,
                    requester_digest=requester,transport_digest=transport,execution_enabled=True,clock=self._clock)
                preview=authority.preview(requester_digest=requester,transport_digest=transport)
                record=_Record(requester,transport,"owned-reset-preview-"+secrets.token_hex(24),authority,preview)
                self._records[requester]=record
                return self._projection(state="previewed",can_authorize=True,record=record)
        except Exception:raise LocalResetOwnedMcpError(_ERROR) from None

    def _get(self,reference: str,principal: object,*,authorized: bool) -> _Record:
        requester,transport=self._identity(principal);self._now()
        if type(reference) is not str or _REF.fullmatch(reference) is None:raise ValueError
        record=self._records.get(requester)
        if record is None or record.transport!=transport:raise ValueError
        expected=record.authorization_ref if authorized else record.preview_ref
        if expected is None or not hmac.compare_digest(reference,expected):raise ValueError
        return record

    def authorize(self,preview_ref: str,principal: object) -> dict[str,object]:
        try:
            with self._lock:
                record=self._get(preview_ref,principal,authorized=False)
                if not self._enabled or not self._available() or self._now()>=record.preview.expires_at:raise ValueError
                if record.issued is None:
                    record.issued=record.authority.issue(record.preview,requester_digest=record.requester,transport_digest=record.transport)
                    record.authorization_ref="owned-reset-authorized-"+secrets.token_hex(24)
                else:
                    self._material._sources.observe_presence();record.authority.check_current(record.issued)
                return dict(contract=self._contract,state="authorized",authorization_ref=record.authorization_ref,
                    policy_mode="lab_auto",expires_at=record.preview.expires_at,device_write_executed=False,credentials_returned=False)
        except Exception:raise LocalResetOwnedMcpError(_ERROR) from None

    def execute(self,authorization_ref: str,principal: object) -> dict[str,object]:
        try:
            with self._lock:
                record=self._get(authorization_ref,principal,authorized=True)
                if record.result is not None:return {**record.result,"idempotent_replay":True}
                if (not self._enabled or not self._available() or record.issued is None
                        or self._now()>=record.preview.expires_at):raise ValueError
                adapter=LocalResetOwnedAdapter(self._material,record.authority,record.issued,
                    execution_enabled=True,connection_factory=self._factory,login_client_factory=self._login_factory);record.adapter=adapter
                try:
                    result=M4ExecutionKernel(adapter,record.authority,self._material._store,clock=self._clock).execute(
                        record.issued.plan,record.issued.authorization)
                    projection=result.as_dict()
                except Exception:
                    # No manufactured terminal store result: a reservation may
                    # remain IN_PROGRESS if verification/observation failed.
                    if not self._material._store.claim_count:raise
                    projection=dict(outcome="reconciliation_required",verification="unknown",
                        compensation="not_requested",idempotent_replay=False)
                acknowledged: bool|None=None
                try:
                    ack=adapter._record("change-ack.json")
                    if type(ack["accepted"]) is bool:acknowledged=ack["accepted"]
                except Exception:pass
                login_ack=None
                if self._material._verify_login:
                    try:login_ack=adapter._record("login-result.json")
                    except Exception:pass
                record.result={**projection,"contract":self._contract,"credentials_returned":False,
                    "authentication_verified":bool(login_ack is not None and login_ack["login_verified"] is True),
                    **({"target_logout_verified":None if login_ack is None else login_ack["logout_verified"]} if self._material._verify_login else {}),
                    "backend_change_acknowledged":acknowledged,
                    "complete_nonmaterial_state_preserved":True if projection["outcome"]=="succeeded" else None,
                    "device_write_executed":adapter._native_attempts>0}
                return dict(record.result)
        except Exception:raise LocalResetOwnedMcpError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled=False;self._closed=True
            for record in self._records.values():
                if record.adapter is not None:record.adapter.close()
                record.authority.close()
            self._material.close()
            inspector=self._material._inspector
            for obj in (inspector,inspector._initial,inspector._original,inspector._sources,inspector._sources._state):obj.close()


def register_local_reset_owned_tools(server: Any,action: LocalResetOwnedMcpAction) -> None:
    if type(action) is not LocalResetOwnedMcpAction:raise LocalResetOwnedMcpError(_ERROR)
    from .server import READ_ONLY_TOOL_ANNOTATIONS,LOCAL_STATE_TOOL_ANNOTATIONS,LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS

    @server.mcp.tool(description="Preview the fixed original-owned REST password reset without returning credentials.",annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_owned_local_user_reset() -> dict[str,object]:
        return await asyncio.to_thread(action.preview,server._v4_planning_principal())

    @server.mcp.tool(description="Authorize the unchanged original-owned reset under the server lab policy.",annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def authorize_v4_owned_local_user_reset(preview_ref: str) -> dict[str,object]:
        return await asyncio.to_thread(action.authorize,preview_ref,server._v4_folder_action_principal())

    @server.mcp.tool(description="Execute the single authorized original-owned REST reset; credentials are never returned.",annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_v4_owned_local_user_reset(authorization_ref: str) -> dict[str,object]:
        return await asyncio.to_thread(action.execute,authorization_ref,server._v4_folder_action_principal())

    for name in TOOLS:
        tool=server.mcp._tool_manager.get_tool(name);model=tool.fn_metadata.arg_model
        model.model_config["extra"]="forbid";model.model_rebuild(force=True);schema=model.model_json_schema()
        if schema.get("additionalProperties") is not False:raise LocalResetOwnedMcpError(_ERROR)
        tool.parameters=schema


def wrap_local_reset_owned_shutdown(app: Any,action: LocalResetOwnedMcpAction) -> Any:
    async def bounded(scope: Any,receive: Any,send: Any) -> None:
        if scope["type"]!="lifespan":
            await app(scope,receive,send);return
        closed=False
        async def closing_send(message: Any) -> None:
            nonlocal closed
            if message["type"] in {"lifespan.shutdown.complete","lifespan.startup.failed","lifespan.shutdown.failed"}:
                await asyncio.to_thread(action.close);closed=True
            await send(message)
        try:await app(scope,receive,closing_send)
        finally:
            if not closed:await asyncio.to_thread(action.close)
    return bounded
