"""One fixed state GET borrowed from an already protected Owner cookie window.

No login, credential resolution, role edit, activation or logout is performed.
The producer owns the window lifetime. A cookie-bound actor read cannot prove
whether elevation affects this session, the account, or other live sessions.
"""
from __future__ import annotations

from collections.abc import Callable,Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import hmac
import math
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import urlsplit

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .glass_break_contract import (STATE_PATH,GlassBreakBinding,GlassBreakIncident,GlassBreakPlan,
    GlassBreakState,_profile_specs,project_glass_break_state)
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import _ssl_context,_zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam-build29-glass-break-cookie-source-local/v1'
_ERROR = 'The private glass-breaking state source is unavailable.'


@dataclass(frozen=True,slots=True,repr=False)
class GlassBreakObservation(_OpaqueC3Object):
    state: GlassBreakState
    observed_at: int
    expires_at: int


class GlassBreakSource(_OpaqueC3Object):
    def __init__(self, owner: OwnerSessionMetadataTransport, binding: GlassBreakBinding,
            profile_schema: object, incident: GlassBreakIncident, *, source_guard: Callable[[],bool] | None = None,
            clock: Callable[[],int] = lambda:int(time.time())) -> None:
        self._cookie=bytearray()
        try:
            if (type(owner) is not OwnerSessionMetadataTransport or type(binding) is not GlassBreakBinding
                    or type(incident) is not GlassBreakIncident or not callable(clock)
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            binding.__post_init__(); incident.__post_init__(); specs=_profile_specs(profile_schema)
            if (canonical_digest(specs)!=binding.profile_schema_digest or owner._owner_name!=binding.actor_name
                    or owner._client is None or not owner._session_lock.locked()): raise ValueError
            config=owner._config; url=urlsplit(config.base_url)
            if (url.scheme!='https' or not url.hostname or url.username is not None or url.password is not None
                    or url.path not in ('','/') or url.query or url.fragment): raise ValueError
            self._owner,self._client,self._config=owner,owner._client,config
            self._binding,self._schema,self._incident=binding,specs,incident
            self._host,self._port,self._tls=url.hostname,url.port or 443,_ssl_context(config)
            self._tls.minimum_version=max(self._tls.minimum_version,ssl.TLSVersion.TLSv1_2)
            self._factory,self._http_clock,self._clock=owner._raw_connection_factory,owner._clock,clock
            self._owner_expiry=owner._expires_at; self._last_mono,self._last_epoch,self._closed=-1.0,-1,False
            self._guard=self._guard_pin=source_guard; self._pins=(binding.digest,incident.digest,canonical_digest(specs))
            self._cookie=self._current_cookie(); self._lock=RLock()
            self._latest: GlassBreakObservation | None = None
            self._plan: GlassBreakPlan | None = None
            self._origin: GlassBreakObservation | None = None
            self._m4_session: object | None = None
            self._deadline_cap: float | None = None
            self._window()
        except Exception:
            _zeroize_mutable(self._cookie); raise ValueError(_ERROR) from None

    def _now(self) -> float:
        now=self._http_clock()
        if type(now) not in (int,float) or not math.isfinite(now) or now<0 or now<self._last_mono:
            self._closed=True; raise ValueError
        self._last_mono=float(now); return float(now)

    def _epoch(self) -> int:
        now=self._clock()
        if type(now) is not int or now<0 or now<self._last_epoch:
            self._closed=True; raise ValueError
        self._last_epoch=now; return now

    def _current_cookie(self) -> bytearray:
        # C3 remains volatile private memory, never a digest, plan or result.
        value=self._client.build_request('GET',self._config.base_url.rstrip('/')+STATE_PATH).headers.get('cookie')
        if (type(value) is not str or not 1<=len(value)<=8192 or not value.isascii()
                or any(ord(c)<32 or ord(c)==127 for c in value)): raise ValueError
        return bytearray(value.encode('ascii'))

    def _window(self) -> None:
        owner=self._owner
        if (self._closed or owner._client is not self._client or owner._config is not self._config
                or owner._owner_name!=self._binding.actor_name or not owner._session_lock.locked()
                or owner._expires_at!=self._owner_expiry or self._now()>=self._owner_expiry
                or (self._binding.digest,self._incident.digest,canonical_digest(self._schema))!=self._pins
                or not self._tls.check_hostname or self._tls.verify_mode!=ssl.CERT_REQUIRED
                or self._tls.minimum_version<ssl.TLSVersion.TLSv1_2): raise ValueError
        current=self._current_cookie()
        try:
            if not hmac.compare_digest(current,self._cookie): raise ValueError
        finally: _zeroize_mutable(current)

    def _available(self) -> None:
        self._window()
        if self._guard is None or self._guard is not self._guard_pin or self._guard() is not True: raise ValueError

    def _remaining(self, deadline: float) -> float:
        self._available(); remaining=min(deadline,self._owner_expiry)-self._now()
        if remaining<=0: raise ValueError
        return min(self._config.timeout_seconds,remaining)

    def _fetch(self, deadline: float) -> bytearray:
        connection=None; raw=bytearray(); transferred=False
        try:
            connection=self._factory(self._host,self._port,context=self._tls,timeout=self._remaining(deadline))
            connection.set_debuglevel(0); connection.connect(); handle=connection.sock
            handle.settimeout(self._remaining(deadline))
            connection.request('GET',STATE_PATH,headers={'Cookie':self._cookie.decode('ascii'),'Accept':'application/json',
                'Accept-Encoding':'identity','Connection':'close','Cache-Control':'no-cache,no-store'})
            raw=self._receive(connection,handle,deadline,1048576)
            transferred=True; return raw
        finally:
            failed=False
            for resource in (connection,):
                if resource is not None:
                    try: resource.close()
                    except Exception: failed=True
            if failed or not transferred: _zeroize_mutable(raw)
            if failed: raise ValueError

    def _receive(self, connection: Any, handle: Any, deadline: float, limit: int) -> bytearray:
        raw = bytearray()
        try:
            response=None; raw=bytearray(); transferred=False
            try:
                handle.settimeout(self._remaining(deadline)); response=connection.getresponse()
                if (type(response.status) is not int or response.status!=200
                        or response.getheader('Content-Type','').split(';',1)[0].strip().lower()!='application/json'
                        or response.getheader('Content-Encoding','identity').lower()!='identity'): raise ValueError
                length=response.getheader('Content-Length'); expected=None
                if length is not None:
                    if (type(length) is not str or not length.isascii() or not length.isdecimal() or len(length)>7
                            or response.getheader('Transfer-Encoding') is not None): raise ValueError
                    expected=int(length)
                    if not 0<expected<=limit: raise ValueError
                raw=bytearray(limit+1); offset=0
                while offset<len(raw):
                    remaining=self._remaining(deadline)
                    if not response.isclosed(): handle.settimeout(remaining)
                    with memoryview(raw)[offset:] as view: count=response.readinto(view)
                    if type(count) is not int or not 0<=count<=len(raw)-offset: raise ValueError
                    if not count: break
                    offset+=count
                if not 0<offset<=limit or expected is not None and offset!=expected: raise ValueError
                raw = _take_mutable_prefix(raw, offset); self._remaining(deadline); transferred=True; return raw
            finally:
                failed=False
                if response is not None:
                    try: response.close()
                    except Exception: failed=True
                if failed or not transferred: _zeroize_mutable(raw)
                if failed: raise ValueError
        except BaseException:
            _erase_transfer_storage(raw)
            raise

    def read(self) -> GlassBreakObservation:
        return self._read(None)

    @contextmanager
    def _bounded_by(self, deadline: float) -> Iterator[None]:
        with self._lock:
            previous=self._deadline_cap
            self._deadline_cap=deadline if previous is None else min(previous,deadline)
            try: yield
            finally: self._deadline_cap=previous

    def _read(self, budget_deadline: float | None) -> GlassBreakObservation:
        raw=bytearray()
        try:
            with self._lock,_private_http_logs():
                self._available(); started=self._epoch(); now=self._now()
                deadline=min(now+self._config.timeout_seconds,self._owner_expiry)
                if budget_deadline is not None: deadline=min(deadline,budget_deadline)
                if self._deadline_cap is not None: deadline=min(deadline,self._deadline_cap)
                raw=self._fetch(deadline); state=project_glass_break_state(raw,self._binding,self._schema)
                observed=GlassBreakObservation(state,started,min(started+10,started+int(self._owner_expiry-now)))
                self._remaining(deadline)
                if not started<=self._epoch()<observed.expires_at: raise ValueError
                self._latest=observed; return observed
        except Exception: raise ValueError(_ERROR) from None
        finally: _zeroize_mutable(raw)

    def prepare_plan(self) -> GlassBreakPlan:
        try:
            with self._lock:
                observed=self.read(); plan=GlassBreakPlan(observed.state,self._incident)
                self._plan,self._origin=plan,observed; return plan
        except Exception: raise ValueError(_ERROR) from None

    def compile(self, plan: GlassBreakPlan) -> bytearray:
        body=bytearray()
        try:
            with self._lock:
                self._available(); origin=self._origin
                if plan is not self._plan or origin is None or not origin.observed_at<=self._epoch()<origin.expires_at: raise ValueError
                deadline=self._now()+self._config.timeout_seconds; observed=self._read(deadline)
                if self._epoch()>=origin.expires_at: raise ValueError
                body=plan.compile(observed.state); self._remaining(deadline)
                if self._epoch()>=origin.expires_at: raise ValueError
                transferred=body; body=bytearray(); return transferred
        except Exception: raise ValueError(_ERROR) from None
        finally: _zeroize_mutable(body)

    def preview(self) -> dict[str,object]:
        public=self.prepare_plan().preview()
        public.update(read_source_contract=CONTRACT,borrowed_physical_cookie_window_bound=True,
            source_state_read_locally=True,source_role_shape_pin_matched=True,native_complete_role_schema_qualified=False,
            activation_sent=False,logout_performed=False,protected_credentials_resolved=False)
        return public

    def close(self) -> None:
        with self._lock: self._closed=True; _zeroize_mutable(self._cookie)
