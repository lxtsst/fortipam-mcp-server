"""Two fixed private User reads for the local FortiToken candidate.

The schema type tree is owner-pinned before the detail GET. Raw schema defaults
and User material never enter decoded observations. No inventory, mutation,
activation, material resolver or native qualification is supplied here.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import http.client
import math
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import quote, urlsplit

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from . import secret_bulk_import_metadata as metadata
from .fortitoken_user_contract import (FortitokenUserBinding, FortitokenUserState, FortitokenUserPlan,
    Operation, _schema_types, _validate_token, project_fortitoken_user, build_fortitoken_user_body,
    expected_fortitoken_user_state)
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (SecretMetadataHttpTransportConfig, _json_value_end,
    _skip_json_space, _ssl_context, _zeroize_mutable)
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam-build29-fortitoken-fixed-user-source-local/v1'
SCHEMA_PATH = '/api/v2/cmdb/system/admin?action=schema&with_meta=true'
_ERROR = 'The private FortiToken User source is unavailable.'


@dataclass(frozen=True, slots=True, repr=False)
class FortitokenUserObservation(_OpaqueC3Object):
    source_digest: str
    state: FortitokenUserState
    observed_at: int
    expires_at: int
    token_reference_matched: bool = False

    def __post_init__(self) -> None:
        require_digest(self.source_digest,'FortiToken User source')
        if (type(self.state) is not FortitokenUserState or type(self.observed_at) is not int
                or type(self.expires_at) is not int or type(self.token_reference_matched) is not bool
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at+10): raise ValueError


class FortitokenUserSource(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: FortitokenUserBinding, *,
            expected_serial: str, expected_schema_digest: str, source_digest: str,
            source_guard: Callable[[],bool] | None = None, connection_factory: Callable[...,Any] = http.client.HTTPSConnection,
            http_clock: Callable[[],float] = time.monotonic, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(binding) is not FortitokenUserBinding
                    or type(expected_serial) is not str or not 1 <= len(expected_serial) <= 128
                    or source_guard is not None and not callable(source_guard)
                    or not callable(connection_factory) or not callable(http_clock) or not callable(clock)): raise ValueError
            for value in (expected_schema_digest,source_digest): require_digest(value,'FortiToken User source')
            origin = urlsplit(config.base_url)
            if (origin.scheme != 'https' or not origin.hostname or origin.username is not None or origin.password is not None
                    or origin.path not in ('','/') or origin.query or origin.fragment
                    or origin.port is not None and not 1 <= origin.port <= 65535): raise ValueError
            self._config = self._config_pin = config; self._binding = self._binding_pin = binding
            self._guard = self._guard_pin = source_guard
            self._serial,self._schema_digest,self._source = expected_serial,expected_schema_digest,source_digest
            self._host,self._port,self._tls = origin.hostname,origin.port or 443,_ssl_context(config)
            self._tls.minimum_version = max(self._tls.minimum_version,ssl.TLSVersion.TLSv1_2)
            self._detail = '/api/v2/cmdb/system/admin/'+quote(binding.username,safe='')+'?with_meta=true'
            self._factory,self._http_clock,self._clock = connection_factory,http_clock,clock
            self._last_time,self._last_epoch,self._closed = -1.0,-1,False
            self._deadline_cap: float | None = None
            self._latest: FortitokenUserObservation | None = None
            self._compiled_plan: FortitokenUserPlan | None = None
            self._first_compiled_plan: FortitokenUserPlan | None = None
            self._admitted_plan: FortitokenUserPlan | None = None
            self._lock = RLock()
        except Exception: raise ValueError(_ERROR) from None

    def _available(self) -> None:
        if (self._closed or self._config is not self._config_pin or self._binding is not self._binding_pin
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True
                or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2): raise ValueError

    def _now(self) -> float:
        value = self._http_clock()
        if type(value) not in (int,float) or not math.isfinite(value) or value < 0 or value < self._last_time:
            self._closed = True
            raise ValueError
        self._last_time = float(value)
        return float(value)

    def _epoch(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0 or value < self._last_epoch:
            self._closed = True
            raise ValueError
        self._last_epoch = value
        return value

    def _remaining(self, deadline: float) -> float:
        if self._deadline_cap is not None: deadline = min(deadline,self._deadline_cap)
        self._available(); remaining = deadline-self._now()
        if remaining <= 0: raise ValueError
        return min(remaining,self._config.timeout_seconds)

    @contextmanager
    def _bounded_by(self, deadline: float) -> Iterator[None]:
        with self._lock:
            previous = self._deadline_cap
            self._deadline_cap = deadline if previous is None else min(previous,deadline)
            try: yield
            finally: self._deadline_cap = previous

    def _fetch(self, path: str, deadline: float) -> bytearray:
        connection = None; raw = bytearray(); transferred = False
        try:
            if path not in (SCHEMA_PATH,self._detail): raise ValueError
            connection = self._factory(self._host,self._port,context=self._tls,timeout=self._remaining(deadline))
            connection.set_debuglevel(0); connection.connect()
            connection.sock.settimeout(self._remaining(deadline))
            connection.request('GET',path,headers={'Authorization':'Bearer '+self._config.bearer_token,
                'Accept':'application/json','Accept-Encoding':'identity','Cache-Control':'no-cache,no-store','Connection':'close'})
            raw = self._receive(connection,deadline,1048576); transferred = True
            return raw
        finally:
            failed = False
            if connection is not None:
                try: connection.close()
                except Exception: failed = True
            if failed or not transferred: _zeroize_mutable(raw)
            if failed: raise ValueError

    def _receive(self, connection: Any, deadline: float, limit: int) -> bytearray:
        raw = bytearray()
        try:
            response = None; raw = bytearray(); transferred = False
            try:
                handle = connection.sock
                handle.settimeout(self._remaining(deadline)); response = connection.getresponse()
                if (type(response.status) is not int or response.status != 200
                        or response.getheader('Content-Type','').split(';',1)[0].strip().lower() != 'application/json'
                        or response.getheader('Content-Encoding','identity').lower() != 'identity'): raise ValueError
                expected = None; length = response.getheader('Content-Length')
                if length is not None:
                    if (type(length) is not str or not length.isascii() or not length.isdecimal() or len(length)>7
                            or response.getheader('Transfer-Encoding') is not None): raise ValueError
                    expected = int(length)
                    if not 0 < expected <= limit: raise ValueError
                raw = bytearray(limit+1); offset = 0
                while offset < len(raw):
                    remaining = self._remaining(deadline)
                    if not response.isclosed(): handle.settimeout(remaining)
                    with memoryview(raw)[offset:] as view: count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(raw)-offset: raise ValueError
                    if not count: break
                    offset += count
                if not 0 < offset <= limit or expected is not None and expected != offset: raise ValueError
                raw = _take_mutable_prefix(raw, offset); self._remaining(deadline); transferred = True
                return raw
            finally:
                failed = False
                if response is not None:
                    try: response.close()
                    except Exception: failed = True
                if failed or not transferred: _zeroize_mutable(raw)
                if failed: raise ValueError
        except BaseException:
            _erase_transfer_storage(raw)
            raise

    def _schema(self, raw: bytearray) -> dict[str,Any]:
        left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
        if _skip_json_space(raw,right) != len(raw): raise ValueError
        metadata._validate_json(raw,left,right,depth=0,budget=[50000]); root = _object_spans(raw,left,right)
        if not set(root) <= {'build','http_method','http_status','name','path','status','version','vdom','serial',
                'results','action','revision','error'}: raise ValueError
        required: dict[str,Any] = dict(build=29,http_method='GET',http_status=200,name='admin',path='system',
            status='success',version='v7.0.0',serial=self._serial,action='schema')
        for key,expected in required.items():
            value = metadata._scalar(raw,root[key])
            if type(value) is not type(expected) or value != expected: raise ValueError
        if 'vdom' in root and metadata._scalar(raw,root['vdom']) != 'root': raise ValueError
        if 'error' in root:
            error = metadata._scalar(raw,root['error'])
            if type(error) is not int or error != 0: raise ValueError
        result = _object_spans(raw,*root['results'])
        def fields(span: tuple[int,int], depth: int = 0) -> dict[str,Any]:
            if depth > 16: raise ValueError
            values: dict[str,Any] = {}
            for name,location in _object_spans(raw,*span).items():
                members = _object_spans(raw,*location); descriptor: dict[str,Any] = {}
                if 'type' in members:
                    kind = metadata._scalar(raw,members['type'])
                    if type(kind) is not str or not 1 <= len(kind) <= 64: raise ValueError
                    descriptor['type'] = kind
                if 'children' in members: descriptor['children'] = fields(members['children'],depth+1)
                values[name] = descriptor
            return values
        selected = fields(result['children'])
        if canonical_digest(_schema_types(selected)) != self._schema_digest: raise ValueError
        return {**required,'results':{'children':selected}}

    def read(self) -> FortitokenUserObservation:
        return self._read()

    def read_matching_token(self, *, token_reference_digest: str, token: memoryview) -> FortitokenUserObservation:
        """Private lease consumer; matches a selector, never MFA or ownership."""
        try:
            if token_reference_digest != self._binding.token_reference_digest: raise ValueError
            _validate_token(token)
            return self._read(matched_token=token)
        except Exception: raise ValueError(_ERROR) from None

    def _read(self, *, matched_token: memoryview | None = None) -> FortitokenUserObservation:
        buffers: list[bytearray] = []
        try:
            with self._lock, _private_http_logs():
                self._available(); started = self._epoch(); deadline = self._now()+self._config.timeout_seconds
                schema_raw = self._fetch(SCHEMA_PATH,deadline); buffers.append(schema_raw); schema = self._schema(schema_raw)
                raw = self._fetch(self._detail,deadline); buffers.append(raw)
                state = project_fortitoken_user(raw,schema,self._binding,expected_serial=self._serial,matched_token=matched_token)
                observation = FortitokenUserObservation(self._source,state,started,started+10,matched_token is not None)
                for buffer in buffers: _zeroize_mutable(buffer)
                self._remaining(deadline)
                if not observation.observed_at <= self._epoch() < observation.expires_at: raise ValueError
                self._latest = observation
                return observation
        except Exception: raise ValueError(_ERROR) from None
        finally:
            for buffer in buffers: _zeroize_mutable(buffer)

    def bind_plan(self, plan: FortitokenUserPlan) -> None:
        """Retain physical read provenance before later current-state refreshes.

This is metadata admission only. Fresh reads, full drift checks and external
execution authorization remain mandatory; admission cannot renew a dispatch.
        """
        try:
            with self._lock:
                self._available(); now = self._epoch(); observed = self._latest
                if self._admitted_plan is plan: return
                if (type(plan) is not FortitokenUserPlan or observed is None or plan.current is not observed.state
                        or not observed.observed_at <= now < observed.expires_at): raise ValueError
                plan.__post_init__(); self._admitted_plan = plan
        except Exception: raise ValueError(_ERROR) from None

    def compile_body(self, plan: FortitokenUserPlan, *, token_reference_digest: str, token: memoryview) -> bytearray:
        """Private serialization after two fresh GETs; never submits a request."""
        buffers: list[bytearray] = []; body = bytearray(); transferred = False
        try:
            with self._lock, _private_http_logs():
                self._available(); now = self._epoch(); baseline = self._latest
                if self._admitted_plan is not plan: self.bind_plan(plan)
                if (type(plan) is not FortitokenUserPlan or baseline is None
                        or not baseline.observed_at <= now < baseline.expires_at): raise ValueError
                deadline = self._now()+self._config.timeout_seconds
                schema_raw = self._fetch(SCHEMA_PATH,deadline); buffers.append(schema_raw); schema = self._schema(schema_raw)
                raw = self._fetch(self._detail,deadline); buffers.append(raw)
                body = build_fortitoken_user_body(plan,raw,schema,expected_serial=self._serial,
                    token_reference_digest=token_reference_digest,token=token)
                for buffer in buffers: _zeroize_mutable(buffer)
                self._remaining(deadline)
                if self._epoch() >= baseline.expires_at: raise ValueError
                self._compiled_plan = plan
                if self._first_compiled_plan is None: self._first_compiled_plan = plan
                transferred = True
                return body
        except Exception: raise ValueError(_ERROR) from None
        finally:
            for buffer in buffers: _zeroize_mutable(buffer)
            if not transferred: _zeroize_mutable(body)

    def verify_postcondition(self, plan: FortitokenUserPlan, observed: FortitokenUserObservation) -> None:
        """Compare the complete strict local profile; supplies no ACK/authority."""
        try:
            with self._lock:
                if plan is not self._compiled_plan: raise ValueError
                self._verify_expected(expected_fortitoken_user_state(plan),observed)
        except Exception: raise ValueError(_ERROR) from None

    def verify_original_nonmaterial_state(self, original: FortitokenUserPlan, observed: FortitokenUserObservation) -> None:
        """Compare configuration plus a live supplied selector match.

This does not prove original material-source continuity, restore ownership,
global token custody or repair an uncertain dispatch result.
        """
        try:
            with self._lock:
                if original is not self._first_compiled_plan: raise ValueError
                self._verify_expected(original.current,observed)
        except Exception: raise ValueError(_ERROR) from None

    def _verify_expected(self, expected: FortitokenUserState, observed: FortitokenUserObservation) -> None:
        self._available(); now = self._epoch()
        if (type(observed) is not FortitokenUserObservation or observed is not self._latest
                or observed.source_digest != self._source or observed.state.binding is not self._binding
                or not observed.observed_at <= now < observed.expires_at
                or expected.token_present and not observed.token_reference_matched
                or observed.state.digest != expected.digest): raise ValueError

    def preview(self, operation: Operation) -> dict[str,object]:
        try:
            with self._lock:
                if operation not in ('assign','revoke'): raise ValueError
                observed = self.read(); public = FortitokenUserPlan(observed.state,operation).preview()
                public.update(read_source_contract=CONTRACT,observed_at=observed.observed_at,expires_at=observed.expires_at,
                    configuration_observed_locally=True,source_qualified=False)
                self._available()
                if not observed.observed_at <= self._epoch() < observed.expires_at: raise ValueError
                return public
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock: self._closed = True
