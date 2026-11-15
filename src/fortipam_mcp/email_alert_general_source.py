"""Two fixed general-alert GETs and a physical private draft; no writer or SMTP."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hmac
import http.client
import math
import re
import ssl
from threading import RLock
import time
from typing import Any,Protocol
from urllib.parse import urlsplit

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from .mutable_json_buffer import _take_mutable_prefix
from . import secret_bulk_import_metadata as metadata
from .email_alert_general_contract import (EmailAlertGeneralPlan,EmailAlertGeneralState,EmailAlertMailScope,
    _encoded,email_alert_general_schema_digest,project_email_alert_general)
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (SecretMetadataHttpTransportConfig,_json_value_end,_skip_json_space,
    _ssl_context,_zeroize_mutable)
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam-build29-email-alert-general-source-local/v1'
SCHEMA_PATH = '/api/v2/cmdb/alertemail/setting?action=schema&vdom=root'
CURRENT_PATH = '/api/v2/cmdb/alertemail/setting?with_meta=true&vdom=root'
_ERROR = 'The private general email-alert source is unavailable.'


class _ResponseDeadline(Protocol):
    def _remaining(self, deadline: float) -> float: ...


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertGeneralObservation(_OpaqueC3Object):
    source_digest: str
    state: EmailAlertGeneralState
    observed_at: int
    expires_at: int


class EmailAlertGeneralSource(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig, mail_scope: EmailAlertMailScope, *,
            expected_serial: str, expected_schema_digest: str, source_digest: str,
            source_guard: Callable[[],bool] | None = None,
            connection_factory: Callable[...,Any] = http.client.HTTPSConnection,
            http_clock: Callable[[],float] = time.monotonic, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(mail_scope) is not EmailAlertMailScope
                    or type(expected_serial) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,128}',expected_serial) is None
                    or source_guard is not None and not callable(source_guard)
                    or not all(callable(v) for v in (connection_factory,http_clock,clock))): raise ValueError
            for digest in (expected_schema_digest,source_digest): require_digest(digest,'general alert source')
            mail_scope.__post_init__(); url = urlsplit(config.base_url)
            if (url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
                    or url.path not in ('','/') or url.query or url.fragment): raise ValueError
            self._config = self._config_pin = config; self._scope = mail_scope
            self._serial,self._schema_pin,self._source = expected_serial,expected_schema_digest,source_digest
            self._host,self._port,self._tls = url.hostname,url.port or 443,_ssl_context(config)
            self._tls.minimum_version = max(self._tls.minimum_version,ssl.TLSVersion.TLSv1_2)
            self._guard = self._guard_pin = source_guard
            self._pins = (expected_serial,expected_schema_digest,source_digest,mail_scope.digest)
            self._factory,self._http_clock,self._clock = connection_factory,http_clock,clock
            self._last_time,self._last_epoch,self._closed = -1.0,-1,False; self._lock = RLock()
            self._latest: EmailAlertGeneralObservation | None = None
            self._plan: EmailAlertGeneralPlan | None = None
            self._origin: EmailAlertGeneralObservation | None = None
        except Exception: raise ValueError(_ERROR) from None

    def _available(self) -> None:
        if (self._closed or self._config is not self._config_pin
                or (self._serial,self._schema_pin,self._source,self._scope.digest) != self._pins
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True
                or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2): raise ValueError

    def _now(self) -> float:
        value = self._http_clock()
        if type(value) not in (int,float) or not math.isfinite(value) or value < 0 or value < self._last_time:
            self._closed = True; raise ValueError
        self._last_time = float(value); return float(value)

    def _epoch(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0 or value < self._last_epoch:
            self._closed = True; raise ValueError
        self._last_epoch = value; return value

    def _remaining(self, deadline: float) -> float:
        self._available(); value = deadline-self._now()
        if value <= 0: raise ValueError
        return min(self._config.timeout_seconds,value)

    def _fetch(self, path: str, deadline: float) -> bytearray:
        return _fetch_fixed_alert(self,path,deadline,(SCHEMA_PATH,CURRENT_PATH))

    def _schema(self, raw: bytearray) -> dict[str,Any]:
        expected = _project_alert_schema(raw,path='alertemail',table='setting',serial=self._serial)
        if email_alert_general_schema_digest(expected,expected_serial=self._serial) != self._schema_pin: raise ValueError
        return expected

    def read(self) -> EmailAlertGeneralObservation:
        return self._read(None)

    def _read(self, budget_deadline: float | None) -> EmailAlertGeneralObservation:
        buffers: list[bytearray] = []
        try:
            with self._lock, _private_http_logs():
                self._available(); started = self._epoch(); deadline = self._now()+self._config.timeout_seconds
                if budget_deadline is not None: deadline = min(deadline,budget_deadline)
                raw = self._fetch(SCHEMA_PATH,deadline); buffers.append(raw); schema = self._schema(raw)
                raw = self._fetch(CURRENT_PATH,deadline); buffers.append(raw)
                state = project_email_alert_general(raw,schema,expected_serial=self._serial,expected_schema_digest=self._schema_pin)
                observed = EmailAlertGeneralObservation(self._source,state,started,started+10)
                for buffer in buffers: _zeroize_mutable(buffer)
                self._remaining(deadline)
                if not started <= self._epoch() < observed.expires_at: raise ValueError
                self._latest = observed; return observed
        except Exception: raise ValueError(_ERROR) from None
        finally:
            for buffer in buffers: _zeroize_mutable(buffer)

    def prepare_plan(self) -> EmailAlertGeneralPlan:
        with self._lock:
            observed = self.read(); plan = EmailAlertGeneralPlan(observed.state,self._scope)
            # Reject the no-op here; an equal active view is not inverse custody.
            if plan.expected().digest == plan.baseline.digest: raise ValueError(_ERROR)
            self._plan,self._origin = plan,observed; return plan

    def compile(self, plan: EmailAlertGeneralPlan) -> bytearray:
        body = bytearray()
        try:
            with self._lock:
                self._available(); origin = self._origin
                if plan is not self._plan or origin is None or not origin.observed_at <= self._epoch() < origin.expires_at: raise ValueError
                deadline = self._now()+self._config.timeout_seconds; observed = self._read(deadline)
                if not self._epoch() < origin.expires_at: raise ValueError
                body = plan.compile(observed.state); self._remaining(deadline)
                if not self._epoch() < origin.expires_at: raise ValueError
                transferred = body; body = bytearray(); return transferred
        except Exception: raise ValueError(_ERROR) from None
        finally: _zeroize_mutable(body)

    def preview(self) -> dict[str,object]:
        plan = self.prepare_plan(); public = plan.preview()
        public.update(source_contract=CONTRACT,source_configuration_observed_locally=True,schema_pin_matched_locally=True,
            product_actor_verified=False,native_complete_schema_qualified=False,configuration_written=False,mail_contacted=False)
        return public

    def close(self) -> None:
        with self._lock: self._closed = True


def _fetch_fixed_alert(source: EmailAlertGeneralSource, path: str, deadline: float, allowed_paths: tuple[str,...], *,
        additional_guard: Callable[[],None] | None = None) -> bytearray:
    connection = response = None; raw = bytearray(); transferred = False
    try:
        if path not in allowed_paths: raise ValueError
        connection = source._factory(source._host,source._port,context=source._tls,timeout=source._remaining(deadline))
        connection.set_debuglevel(0); connection.connect(); handle = connection.sock; handle.settimeout(source._remaining(deadline))
        if additional_guard is not None: additional_guard()
        connection.request('GET',path,headers={'Authorization':'Bearer '+source._config.bearer_token,'Accept':'application/json',
            'Accept-Encoding':'identity','Connection':'close','Cache-Control':'no-cache,no-store'})
        handle.settimeout(source._remaining(deadline)); response = connection.getresponse()
        raw = _read_alert_response(source,response,handle,deadline,1048576)
        transferred = True; return raw
    finally:
        failed = False
        for resource in (response,connection):
            if resource is not None:
                try: resource.close()
                except Exception: failed = True
        if failed or not transferred: _zeroize_mutable(raw)
        if failed: raise ValueError


def _read_alert_response(source: _ResponseDeadline, response: Any, handle: Any,
        deadline: float, limit: int) -> bytearray:
    raw = bytearray(); transferred = False
    try:
        if (type(response.status) is not int or response.status != 200
                or response.getheader('Content-Type','').split(';',1)[0].strip().lower() != 'application/json'
                or response.getheader('Content-Encoding','identity').lower() != 'identity'): raise ValueError
        length = response.getheader('Content-Length'); expected = None
        if length is not None:
            if (type(length) is not str or not length.isascii() or not length.isdecimal() or len(length)>7
                    or response.getheader('Transfer-Encoding') is not None): raise ValueError
            expected = int(length)
            if not 0 < expected <= limit: raise ValueError
        raw = bytearray(limit+1); offset = 0
        while offset < len(raw):
            remaining = source._remaining(deadline)
            if not response.isclosed(): handle.settimeout(remaining)
            with memoryview(raw)[offset:] as view: count = response.readinto(view)
            if type(count) is not int or not 0 <= count <= len(raw)-offset: raise ValueError
            if not count: break
            offset += count
        if not 0 < offset <= limit or expected is not None and expected != offset: raise ValueError
        raw = _take_mutable_prefix(raw, offset); source._remaining(deadline); transferred = True; return raw
    finally:
        if not transferred: _zeroize_mutable(raw)


def _project_alert_schema(raw: bytearray, *, path: str, table: str, serial: str) -> dict[str,Any]:
    left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
    if _skip_json_space(raw,right) != len(raw): raise ValueError
    metadata._validate_json(raw,left,right,depth=0,budget=[50000]); root = _object_spans(raw,left,right)
    if not root.keys() <= {'build','http_method','http_status','name','path','status','version','vdom','serial','mkey','results','revision','error','action'}: raise ValueError
    expected: dict[str,Any] = dict(build=29,http_method='GET',http_status=200,name=table,path=path,
        version='v7.0.0',serial=serial,action='schema')
    for name,value in expected.items():
        with memoryview(raw)[slice(*root[name])] as actual:
            if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
    status = metadata._scalar(raw,root['status'])
    if status not in ('success','OK'): raise ValueError
    expected['status'] = status
    for name,value in (('vdom','root'),('mkey',''),('error',0)):
        if name in root:
            actual_value = metadata._scalar(raw,root[name])
            if type(actual_value) is not type(value) or actual_value != value: raise ValueError
    def fields(span: tuple[int,int], depth: int = 0) -> dict[str,Any]:
        if depth>16: raise ValueError
        result = {}
        for name,descriptor_span in _object_spans(raw,*span).items():
            descriptor = _object_spans(raw,*descriptor_span); item: dict[str,Any] = {}
            for key in ('type','size','min-value','max-value'):
                if key in descriptor: item[key] = metadata._scalar(raw,descriptor[key])
            if 'options' in descriptor:
                item['options'] = [dict(name=metadata._scalar(raw,_object_spans(raw,*option)['name']))
                    for option in metadata._array(raw,descriptor['options'],128)]
            if 'children' in descriptor: item['children'] = fields(descriptor['children'],depth+1)
            result[name] = item
        return result
    expected['results'] = dict(children=fields(_object_spans(raw,*root['results'])['children']))
    return expected
