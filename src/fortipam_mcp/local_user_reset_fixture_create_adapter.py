"""Default-off fixed original User POST; no Tool or credential output surface."""
from __future__ import annotations

from collections.abc import Callable
import http.client
import os
from threading import RLock
from typing import Any
from urllib.parse import urlsplit

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from .mutable_json_buffer import _take_mutable_prefix
from .local_user_reset_fixture_authority import LocalResetFixtureM4Authority, LocalResetFixtureIssued
from .local_user_reset_fixture_custody import LocalResetFixtureAckCustody, _SEND, _ACK, _STATE, _ABSENCE
from .local_user_reset_fixture_material import LocalResetInitialMaterialSource, LocalResetInitialLease
from .local_user_reset_fixture_sources import LocalResetFixtureSources, LocalResetSourceObservation
from .local_user_reset_fixture_transport import _CREATE as _POST
from .secret_metadata_http_transport import _ssl_context, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

_ERROR = "The private original reset-fixture creation is unavailable."
_FAILURE, _RESPONSE = "create-failure.json", "create-response.json"


class LocalResetFixtureCreateAdapter(_OpaqueC3Object):
    def __init__(self, sources: LocalResetFixtureSources, custody: LocalResetFixtureAckCustody,
            material: LocalResetInitialMaterialSource, authority: LocalResetFixtureM4Authority,
            issued: LocalResetFixtureIssued, *, execution_enabled: bool = False,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection) -> None:
        try:
            if (type(sources) is not LocalResetFixtureSources or type(custody) is not LocalResetFixtureAckCustody
                    or type(material) is not LocalResetInitialMaterialSource or type(authority) is not LocalResetFixtureM4Authority
                    or type(issued) is not LocalResetFixtureIssued or type(execution_enabled) is not bool
                    or not callable(connection_factory) or authority._sources is not sources
                    or authority._material is not material or material._sources is not sources
                    or material._store is not custody._store or authority._binding["phase"] != "create"
                    or authority._issued is not issued or issued.plan is not custody._plan
                    or issued.authorization is not custody._authorization or custody._pins.material_ref != material.reference):
                raise ValueError
            self._sources,self._custody,self._material,self._authority,self._issued=sources,custody,material,authority,issued
            self._plan,self._authorization,self._store=issued.plan,issued.authorization,custody._store
            self._source=sources.source_context_digest
            self._enabled,self._closed=execution_enabled,False
            self._factory=connection_factory;self._lock=RLock();self._last=-1
            self._resources_closed=True
            self._absence: LocalResetSourceObservation|None=None
            self._pending()
        except Exception:raise M4AdapterDenied(_ERROR) from None

    def _pending(self) -> None:
        self._custody._validate()
        if any(os.path.lexists(self._custody._directory/name) for name in (_ABSENCE,_SEND,_ACK,_STATE,_FAILURE,_RESPONSE)):
            raise ValueError

    def _active(self,plan: M4ExecutionPlan) -> int:
        self._custody._validate()
        now=self._authority._now()
        if (not self._enabled or self._closed or not self._authority._enabled
                or plan is not self._plan or self._authority._issued is not self._issued
                or self._issued.plan is not self._custody._plan or self._issued.authorization is not self._custody._authorization
                or self._sources.source_context_digest!=self._source or self._material._sources is not self._sources
                or self._material._store is not self._store or self._store is not self._custody._store
                or plan.expected_state_digest!=self._authority.expected_digest
                or now<self._last or not self._authorization.issued_at<=now<self._authorization.expires_at):raise ValueError
        self._last=now;return now

    def read_current(self,plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan);self._pending()
                self._absence=self._sources.observe_absence()
                self._authority.check_current(self._issued,self._absence)
                return self._absence.current_digest
        except Exception:raise M4AdapterDenied(_ERROR) from None

    def dispatch(self,plan: M4ExecutionPlan) -> None:
        body=bytearray();raw=bytearray();view=None
        lease: LocalResetInitialLease|None=None
        response=connection=active_socket=None
        attempted=False;scope_claimed=False;stage="original_dispatch"
        try:
            with self._lock,_private_http_logs():
                self._active(plan);self._pending()
                _require_m4_dispatch_ownership(plan,self._authorization,self._store)
                scope_claimed=True
                config=self._sources._config;url=urlsplit(config.base_url)
                def guard(*,absence: bool=False) -> float:
                    now=self._active(plan)
                    _require_m4_dispatch_ownership(plan,self._authorization,self._store)
                    if self._custody._claim().result is not None:raise ValueError
                    if absence:
                        if self._absence is None:raise ValueError
                        self._sources.check_current(self._absence)
                    timeout=min(float(config.timeout_seconds),float(self._authorization.expires_at-now))
                    if active_socket is not None and active_socket.fileno()>=0:active_socket.settimeout(timeout)
                    return timeout
                connection=self._factory(url.hostname,url.port or 443,timeout=guard(),context=_ssl_context(config))
                stage="tls_connect";connection.connect();active_socket=getattr(connection,"sock",None)
                stage="fresh_source_after_tls"
                self._absence=self._sources.observe_absence()
                self._authority.check_current(self._issued,self._absence);guard(absence=True)
                stage="original_absence";self._custody.capture_original_absence(self._sources)
                stage="initial_material";lease=self._material.acquire_original(plan,self._authorization)
                body=self._sources._state._draft._encode(lease._consume());guard(absence=True)
                stage="original_send_claim";self._custody.begin_original_send();guard(absence=True)
                view=memoryview(body).toreadonly();attempted=True;stage="original_post"
                connection.request("POST",_POST,body=view,headers={"Authorization":"Bearer "+config.bearer_token,
                    "Accept":"application/json","Content-Type":"application/json","Content-Length":str(len(body)),
                    "Accept-Encoding":"identity","Cache-Control":"no-store","Connection":"close",
                    "User-Agent":"fortipam-mcp-reset-fixture-create/2"})
                guard();stage="original_response";response=connection.getresponse();guard()
                status=response.status;content_type=response.getheader("Content-Type","")
                encoding=response.getheader("Content-Encoding","identity")
                if type(status) is not int or not 100<=status<=599:raise ValueError
                self._custody._write(_RESPONSE,dict(context_digest=self._custody._context,http_status=status,
                    exact_json=content_type.split(";",1)[0].strip().lower()=="application/json",
                    identity_encoding=encoding in ("","identity"),raw_values_stored=False))
                if encoding not in ("","identity") or status!=200:raise ValueError
                raw=bytearray(16385);total=0
                while total<len(raw):
                    guard()
                    with memoryview(raw)[total:] as part:count=response.readinto(part)
                    guard()
                    if type(count) is not int or not 0<=count<=len(raw)-total:raise ValueError
                    if count==0:break
                    total+=count
                if total>16384:raise ValueError
                raw = _take_mutable_prefix(raw, total)
                stage="original_ack";self._custody.capture_original_ack(raw,http_status=status,content_type=content_type)
                guard();stage="original_full_state";self._custody.capture_original_full_state(self._sources._state)
                guard();stage="global_presence";observed=self._sources.observe_presence()
                original=self._custody.inspect_original_full_state();baseline=self._custody.inspect_original_absence()
                if (observed.absent or observed.state_digest!=original.state_digest
                        or observed.namespace_digest!=baseline.presence_namespace_digest
                        or observed.admin_count!=baseline.admin_count+1 or observed.api_user_count!=baseline.api_user_count):raise ValueError
                guard()
        except Exception as error:
            if scope_claimed:
                try:
                    self._custody._write(_FAILURE,dict(context_digest=self._custody._context,stage=stage,
                        source_failure_stage=self._sources._last_failure_stage,state_failure_stage=self._sources._state._last_failure_stage,
                        error_class=type(error).__name__ if type(error).__name__ in {"ValueError","OSError","RemoteDisconnected","TimeoutError","IncompleteRead"} else "unavailable",
                        original_request_replayable=False))
                except Exception:pass
            if attempted:raise M4AdapterAmbiguous(_ERROR) from None
            raise M4AdapterDenied(_ERROR) from None
        finally:
            if view is not None:view.release()
            _zeroize_mutable(body);_zeroize_mutable(raw)
            if lease is not None:lease.close()
            for resource in (response,connection):
                if resource is not None:
                    try:resource.close()
                    except Exception:self._resources_closed=False

    def read_postcondition(self,plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan)
                original=self._custody.inspect_original_full_state();baseline=self._custody.inspect_original_absence()
                observed=self._sources._current
                if observed is None:raise ValueError
                self._sources.check_current(observed)
                if (not self._resources_closed or observed.absent or observed.state_digest!=original.state_digest
                        or original.source_context_digest!=self._sources._state._context()
                        or baseline.source_context_digest!=self._source
                        or observed.namespace_digest!=baseline.presence_namespace_digest
                        or observed.admin_count!=baseline.admin_count+1 or observed.api_user_count!=baseline.api_user_count):raise ValueError
                return plan.expected_state_digest
        except Exception:raise M4AdapterAmbiguous(_ERROR) from None

    def close(self) -> None:
        with self._lock:self._enabled,self._closed=False,True
