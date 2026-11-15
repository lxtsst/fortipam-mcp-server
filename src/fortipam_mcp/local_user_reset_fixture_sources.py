"""Concrete read-only C/P/E source for one distinct local reset fixture.

Same-owner global namespace/reference controls, effective User administration
rights and complete created-state reads remain evidence, never authorization.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import math
import re
from threading import RLock
import time
from urllib.parse import quote

import httpx
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_projection import _object_spans
from .local_user_reset_fixture_state import LocalResetFixtureStateReader
from .local_user_reset_namespace import LocalResetNamespaceReader, CONTRACT as _NAMESPACE_CONTRACT
from .local_user_reset_references import LocalResetReferenceReader
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import _zeroize_mutable
from .target_lifecycle_dependencies import _envelope, _one, _spans
from .target_preservation_contract import _digest, _token_digest
from .target_ssh_transport import TargetSshTransportConfig
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-build29-local-reset-live-sources-v1"
_ERROR = "The private reset-fixture C/P/E source is unavailable."
_MONITOR = "/api/v2/monitor/web-ui/state"
_LEVELS = frozenset({"none", "read", "read-write"})
# Exact native routing token for this fixed build-29 table-hint response.
# Its envelope differs from the ordinary web-ui/state monitor envelope.
_HINT_PATH_TOKEN = "bb25fcc2eb4e057e1727c875fbdd9e30f9f49e20e3850268aa50a172175ceb06"


@dataclass(frozen=True, slots=True, repr=False)
class LocalResetSourceObservation(_OpaqueC3Object):
    source_context_digest: str
    current_digest: str
    dependency_digest: str
    namespace_digest: str
    references_digest: str
    state_digest: str | None
    absent: bool
    admin_count: int
    api_user_count: int
    observed_at: float
    expires_at: float


class LocalResetFixtureSources(_OpaqueC3Object):
    def __init__(self, *, state_reader: LocalResetFixtureStateReader, owner: OwnerSessionMetadataTransport,
            ssh: TargetSshTransportConfig, expected_serial: str,
            client_factory: Callable[..., httpx.Client] = httpx.Client, clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(state_reader) is not LocalResetFixtureStateReader or type(owner) is not OwnerSessionMetadataTransport
                    or type(ssh) is not TargetSshTransportConfig or not callable(client_factory) or not callable(clock)
                    or owner._config is not state_reader._config or owner._owner_name != ssh.username
                    or type(expected_serial) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None
                    or hashlib.sha256(expected_serial.encode()).hexdigest() != state_reader._serial): raise ValueError
            self._state, self._owner, self._ssh = state_reader, owner, ssh
            self._config, self._serial = state_reader._config, expected_serial
            self._factory, self._clock = client_factory, clock
            self._provider, self._owner_factory = owner._credentials, owner._session_factory
            self._namespace_proto = self._namespace(lambda:None)
            self._closed = self._failed = False
            self._last = -1.0
            self._source = self._context()
            self._current: LocalResetSourceObservation | None = None
            self._seal: str | None = None
            self._admin_names: tuple[str, ...] = ()
            self._api_names: tuple[str, ...] = ()
            self._last_failure_stage: str | None = None
            self.logout_verified = False
            self._lock = RLock()
        except Exception:
            raise ValueError(_ERROR) from None

    def _namespace(self, guard: Callable[[], None]) -> LocalResetNamespaceReader:
        return LocalResetNamespaceReader(self._ssh, candidate_name=self._state._draft.username,
            admin_witness=self._ssh.username, api_witness=self._state._principal,
            expected_serial=self._serial, before_send=guard)

    def _context(self) -> str:
        self._state._pins()
        if (self._owner._config is not self._config or self._owner._owner_name != self._ssh.username
                or self._owner._credentials is not self._provider or self._owner._session_factory is not self._owner_factory
                or self._owner._allow_secret_create or self._owner._allow_collector_credential_repair): raise ValueError
        return _digest((CONTRACT, self._state._source, self._namespace_proto._context(),
            "system-admin-effective-write-and-table-hint", "guest-system-admin-and-cfg-nonwrite",
            "api-and-cli-positive-reference-independent-counts-v2",_HINT_PATH_TOKEN))

    def _now(self) -> float:
        now = self._clock()
        if (self._closed or self._failed or type(now) not in (int, float) or not math.isfinite(now)
                or now < 0 or now < self._last or self._context() != self._source): raise ValueError
        self._last = float(now)
        return self._last

    @property
    def source_context_digest(self) -> str:
        try:
            self._now(); return self._source
        except Exception:
            raise ValueError(_ERROR) from None

    def _get(self, client: httpx.Client, path: str, deadline: float, *, owner: bool = False) -> bytearray:
        raw = bytearray()
        try:
            headers = {"Accept":"application/json", "Accept-Encoding":"identity", "Cache-Control":"no-store"}
            if not owner: headers["Authorization"] = "Bearer " + self._config.bearer_token
            remaining = deadline - self._now()
            if remaining <= 0: raise ValueError
            with client.stream("GET", path if owner else self._config.base_url + path, headers=headers,
                    timeout=min(10.0, remaining)) as response:
                if (response.status_code != 200 or response.headers.get("content-type", "").split(";",1)[0] != "application/json"
                        or response.headers.get("content-encoding","identity") not in ("","identity")): raise ValueError
                for chunk in response.iter_raw():
                    if self._now() >= deadline or len(raw) + len(chunk) > 1048576: raise ValueError
                    raw.extend(chunk)
            if self._now() >= deadline: raise ValueError
            _spans(raw)
            if "schema_errors" in _spans(raw): raise ValueError
            result, raw = raw, bytearray(); return result
        finally:
            _zeroize_mutable(raw)

    def _actor(self, raw: bytearray, expected: str) -> tuple[str, str, bool]:
        span = _envelope(raw, path="web-ui", name="state", serial_digest=self._state._serial, monitor=True)
        state = m._object_spans(raw, *span, frozenset({"admin","vdom_mode","maintenance_mode"}))
        admin = m._object_spans(raw, *state["admin"], frozenset({"profile","global_admin","super_admin"}))
        profile = m._object_spans(raw, *admin["profile"], frozenset({"name"}))
        maintenance = m._object_spans(raw, *state["maintenance_mode"], frozenset({"mode"}))
        role = m._scalar(raw, profile["name"]); super_admin = m._scalar(raw, admin["super_admin"])
        if (type(role) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",role) is None
                or type(super_admin) is not bool or m._scalar(raw,admin["global_admin"]) is not True
                or m._scalar(raw,state["vdom_mode"]) != "" or m._scalar(raw,maintenance["mode"]) != "disable"): raise ValueError
        return role, _actor_context(raw, expected_name=expected), super_admin

    def _row(self, raw: bytearray, table: str) -> tuple[int, int]:
        return _one(raw, _envelope(raw, path="system", name=table, serial_digest=self._state._serial))

    def _writer(self, client: httpx.Client, deadline: float) -> str:
        buffers = []
        try:
            raw = self._get(client, _MONITOR, deadline); buffers.append(raw)
            role, actor, _ = self._actor(raw, self._state._principal)
            if actor != self._state._actor: raise ValueError
            raw = self._get(client,"/api/v2/cmdb/system/api-user/"+quote(self._state._principal,safe="")+
                "?format=name%7Caccprofile&with_meta=true&vdom=root",deadline); buffers.append(raw)
            fields = m._object_spans(raw,*self._row(raw,"api-user"),frozenset({"name","accprofile"}))
            user = {key:m._scalar(raw,fields[key]) for key in ("name","accprofile")}
            if user != {"name":self._state._principal,"accprofile":role}: raise ValueError
            raw = self._get(client,"/api/v2/cmdb/system/accprofile/"+quote(role,safe="")+
                "?format=name%7Csysgrp%7Csysgrp-permission&with_meta=true&vdom=root",deadline); buffers.append(raw)
            fields = m._object_spans(raw,*self._row(raw,"accprofile"),frozenset({"name","sysgrp","sysgrp-permission"}))
            group = m._scalar(raw,fields["sysgrp"])
            rights = m._object_spans(raw,*fields["sysgrp-permission"],frozenset({"admin"}))
            admin = m._scalar(raw,rights["admin"])
            if (m._scalar(raw,fields["name"]) != role or group not in _LEVELS|{"custom"} or admin not in _LEVELS
                    or (admin if group == "custom" else group) != "read-write"): raise ValueError
            permission = _digest((role,group,admin))
            raw = self._get(client,"/api/v2/monitor/web-ui/object-urls?path=system.admin",deadline); buffers.append(raw)
            top=_spans(raw)
            for key,value in dict(version="v7.0.0",build=29,http_method="GET",status="success",name="object-urls",vdom="root").items():
                actual=m._scalar(raw,top[key])
                if type(actual) is not type(value) or actual!=value:raise ValueError
            if (_token_digest(raw,top["path"])!=_HINT_PATH_TOKEN
                    or hashlib.sha256(m._text(m._scalar(raw,top["serial"]),maximum=128).encode()).hexdigest()!=self._state._serial):raise ValueError
            if "http_status" in top:
                code=m._scalar(raw,top["http_status"])
                if type(code) is not int or code!=200:raise ValueError
            if "error" in top:
                code=m._scalar(raw,top["error"])
                if code is not None and (type(code) is not int or code!=0):raise ValueError
            span=top["results"]
            mapping = _object_spans(raw,*m._object_spans(raw,*span,frozenset({"by_type"}))["by_type"])
            if not 0 < len(mapping) <= 4096: raise ValueError
            matches = []
            for span in mapping.values():
                fields = m._object_spans(raw,*span,frozenset({"path","read_access","write_access"}))
                if m._scalar(raw,fields["path"]) == "system.admin":
                    matches.append((m._scalar(raw,fields["read_access"]),m._scalar(raw,fields["write_access"])))
            if len(matches)!=1 or matches[0][0] is not True or matches[0][1] is not True: raise ValueError
            return _digest((actor,user,permission,"native-system-admin-table-rw-hint"))
        finally:
            for raw in buffers:_zeroize_mutable(raw)

    def _guest(self, client: httpx.Client, deadline: float) -> str:
        raw = self._get(client,"/api/v2/cmdb/system/accprofile/Guest?with_meta=true&vdom=root",deadline)
        try:
            span = self._row(raw,"accprofile"); fields = _object_spans(raw,*span)
            if m._scalar(raw,fields["name"]) != "Guest": raise ValueError
            group = m._scalar(raw,fields["sysgrp"])
            rights = m._object_spans(raw,*fields["sysgrp-permission"],frozenset({"admin","cfg"}))
            if group not in _LEVELS|{"custom"}: raise ValueError
            for key in ("admin","cfg"):
                level = m._scalar(raw,rights[key])
                if level not in _LEVELS or (level if group=="custom" else group) == "read-write": raise ValueError
            return _digest({key:_token_digest(raw,span) for key,span in fields.items() if key!="q_ref"})
        finally:_zeroize_mutable(raw)

    def _owner_role(self, deadline: float) -> tuple[str,int]:
        client = self._owner._client
        if client is None: raise ValueError
        raw = self._get(client,_MONITOR,deadline,owner=True)
        try:
            role,actor,super_admin = self._actor(raw,self._ssh.username)
            if role!="super_admin" or not super_admin: raise ValueError
        finally:_zeroize_mutable(raw)
        raw = self._get(client,"/api/v2/cmdb/system/admin/"+quote(self._ssh.username,safe="")+
            "?format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard%7Cq_ref&with_meta=true&vdom=root",deadline,owner=True)
        try:
            fields=m._object_spans(raw,*self._row(raw,"admin"),frozenset({"name","accprofile","status","remote-auth","wildcard","q_ref"}))
            values={key:m._scalar(raw,fields[key]) for key in ("name","accprofile","status","remote-auth","wildcard")}
            if values!={"name":self._ssh.username,"accprofile":"super_admin","status":"enable","remote-auth":"disable","wildcard":"disable"}:raise ValueError
            count=m._scalar(raw,fields["q_ref"])
            if type(count) is not int or not 1<=count<=4096:raise ValueError
            return _digest((actor,values,count)),count
        finally:_zeroize_mutable(raw)

    def _observe(self, present: bool) -> LocalResetSourceObservation:
        namespace=references=None; stage="source_binding"
        try:
            with self._lock, _private_http_logs():
                started=self._now();deadline=started+60
                self._current=self._seal=None;self._admin_names=self._api_names=();self.logout_verified=False
                stage="preflight_before"; before=None
                if not present:
                    before=self._state._reader.read_preflight()
                    if before.draft!=self._state._draft or before.actor_context_digest!=self._state._actor:raise ValueError
                with self._factory(verify=self._state._reader._context,timeout=10,trust_env=False,follow_redirects=False) as client:
                    try:
                        stage="writer_before";writer=self._writer(client,deadline)
                        stage="guest_before";guest=self._guest(client,deadline)
                        with self._owner.authenticated():
                            stage="owner_before";owner,count=self._owner_role(deadline)
                            state_before=None
                            if present:
                                stage="complete_before";state_before=self._state.read_created();self._state.check_current(state_before)
                            names_started=self._now()
                            def guard() -> None:
                                if self._now()>=min(deadline,names_started+min(30,self._ssh.timeout_seconds)):raise ValueError
                            stage="global_namespace";namespace=self._namespace(guard);names=namespace.read_namespace()
                            if (names.global_name_absent is not (not present) or names.candidate_admin_occurrences!=int(present)
                                    or names.candidate_api_occurrences!=0):raise ValueError
                            stage="reference_controls"
                            references=LocalResetReferenceReader(self._ssh,candidate_name=self._state._draft.username,
                                positive_name=self._ssh.username,api_positive_count=count,expected_serial=self._serial,before_send=guard)
                            refs=references.read_references()
                            if not refs.candidate_unreferenced:raise ValueError
                            state=None
                            if present:
                                stage="complete_after";state=self._state.read_created();self._state.check_current(state)
                                if state_before is None or state.state_digest!=state_before.state_digest:raise ValueError
                            stage="owner_after"
                            if self._owner_role(deadline)!=(owner,count):raise ValueError
                        self.logout_verified=self._owner.logout_verified
                        stage="guest_after"
                        if not self.logout_verified or self._guest(client,deadline)!=guest:raise ValueError
                        stage="writer_after"
                        if self._writer(client,deadline)!=writer:raise ValueError
                    finally:client.cookies.clear()
                stage="preflight_after"
                if not present:
                    after=self._state._reader.read_preflight()
                    if before is None or after!=before:raise ValueError
                expires=min(deadline,names_started+min(30,self._ssh.timeout_seconds))
                if self._now()>=expires:raise ValueError
                dependency=_digest((CONTRACT,writer,guest,owner,refs.snapshot_digest,
                    None if before is None else before.state_digest))
                full=None if state is None else state.state_digest
                current=_digest((CONTRACT,self._source,dependency,names.namespace_digest,present,full))
                observed=LocalResetSourceObservation(self._source,current,dependency,names.namespace_digest,
                    refs.snapshot_digest,full,not present,names.admin_count,names.api_user_count,started,expires)
                self._current,self._seal=observed,_digest(asdict(observed))
                self._admin_names,self._api_names=namespace._admin_names,namespace._api_names
                self._last_failure_stage=None
                return observed
        except Exception:
            self._failed=True;self._current=self._seal=None;self._admin_names=self._api_names=();self._last_failure_stage=stage
            raise ValueError(_ERROR) from None
        finally:
            if namespace is not None:namespace.close()
            if references is not None:references.close()

    def observe_absence(self) -> LocalResetSourceObservation:return self._observe(False)

    def observe_presence(self) -> LocalResetSourceObservation:return self._observe(True)

    def check_current(self, observed: LocalResetSourceObservation) -> None:
        try:
            with self._lock:
                if (type(observed) is not LocalResetSourceObservation or observed is not self._current
                        or _digest(asdict(observed))!=self._seal or not observed.observed_at<=self._now()<observed.expires_at
                        or observed.admin_count != len(self._admin_names) or observed.api_user_count != len(self._api_names)
                        or observed.namespace_digest != canonical_digest(dict(contract=_NAMESPACE_CONTRACT,
                            admin_names=sorted(self._admin_names),api_names=sorted(self._api_names)))):raise ValueError
        except Exception:
            self._failed=True;self._current=self._seal=None;self._admin_names=self._api_names=()
            raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed=True;self._current=self._seal=None;self._admin_names=self._api_names=();self._namespace_proto.close()
