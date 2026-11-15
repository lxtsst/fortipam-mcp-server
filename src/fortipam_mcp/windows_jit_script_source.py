"""Fixed private Script reads for one local JIT pair; no write or custody.

Collection POST is the retained fixed GET override, never Script creation.
Unselected Script content and schema defaults are neither decoded nor hashed.
The visible namespace and exact pair definitions supply no global ownership.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import http.client
import json
import math
import re
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
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (SecretMetadataHttpTransportConfig, _json_value_end,
    _skip_json_space, _ssl_context, _zeroize_mutable)
from .target_api_dependency_reader import _private_http_logs
from .windows_jit_script_contract import compile_windows_jit_script_pair, preview_windows_jit_script_pair

CONTRACT = 'fortipam-build29-windows-jit-fixed-script-source-local/v1'
BASE_PATH = '/api/v2/cmdb/secret/script'
SCHEMA_PATH = BASE_PATH+'?action=schema&vdom=root'
DEFAULT_PATH = BASE_PATH+'?action=default&vdom=root'
COLLECTION_PATH = BASE_PATH+'?with_meta=true&vdom=root'
_FIELDS = frozenset({'name','type','comments','script','expect-type','expect-string','log-trigger'})
_OPTIONS = {'type':{'powershell','ssh-script'},'expect-type':{'success','failure'},'log-trigger':{'failure','any'}}
_META = {'q_origin_key','q_mkey_type','q_name','q_path','q_ref','q_type','q_no_edit','q_no_rename','q_static','q_global_entry'}
_TOP = {'http_method','http_status','status','path','name','results','serial','version','build','vdom','revision',
    'mkey','action','size','matched_count','limit_reached','error'}
_ERROR = 'The private Windows JIT Script source is unavailable.'


def _encoded(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _default() -> dict[str,Any]:
    return dict(version='v7.0.0',build=29,http_status=200,http_method='GET',status='success',path='secret',name='script',
        results=dict(name='',type='powershell',comments='',script='',**{'expect-type':'success','expect-string':'','log-trigger':'failure'}))


@dataclass(frozen=True, slots=True, repr=False)
class WindowsJitScriptObservation(_OpaqueC3Object):
    source_digest: str
    schema_digest: str
    namespace_digest: str
    state_digest: str
    script_count: int
    present: tuple[bool,bool]
    observed_at: int
    expires_at: int
    _names: tuple[str,...] = ()


@dataclass(frozen=True, slots=True, repr=False)
class WindowsJitScriptPlan(_OpaqueC3Object):
    _origin: WindowsJitScriptObservation


class WindowsJitScriptSource(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig, *, nonce: str, expected_serial: str,
            expected_schema_digest: str, source_digest: str, source_guard: Callable[[],bool] | None = None,
            connection_factory: Callable[...,Any] = http.client.HTTPSConnection,
            http_clock: Callable[[],float] = time.monotonic, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(expected_serial) is not str
                    or re.fullmatch(r'[A-Za-z0-9_-]{1,128}',expected_serial) is None
                    or source_guard is not None and not callable(source_guard)
                    or not all(callable(value) for value in (connection_factory,http_clock,clock))): raise ValueError
            for value in (expected_schema_digest,source_digest): require_digest(value,'Windows JIT Script source')
            self._expected = compile_windows_jit_script_pair(_default(),nonce=nonce)
            self._expected_pin = tuple(body.copy() for body in self._expected)
            self._definition_digest = hashlib.sha256(_encoded(self._expected)).hexdigest()
            url = urlsplit(config.base_url)
            if (url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
                    or url.path not in ('','/') or url.query or url.fragment): raise ValueError
            self._config = self._config_pin = config; self._guard = self._guard_pin = source_guard
            self._nonce,self._serial,self._schema_pin,self._source = nonce,expected_serial,expected_schema_digest,source_digest
            self._host,self._port,self._tls = url.hostname,url.port or 443,_ssl_context(config)
            self._tls.minimum_version = max(self._tls.minimum_version,ssl.TLSVersion.TLSv1_2)
            self._details = tuple(BASE_PATH+'/'+quote(body['name'],safe='')+'?with_meta=true&vdom=root' for body in self._expected)
            self._binding_pin = (nonce,expected_serial,expected_schema_digest,source_digest,self._details,self._definition_digest)
            self._factory,self._http_clock,self._clock = connection_factory,http_clock,clock
            self._last_time,self._last_epoch,self._closed = -1.0,-1,False
            self._deadline_cap: float | None = None
            self._latest: WindowsJitScriptObservation | None = None
            self._plan: WindowsJitScriptPlan | None = None
            self._lock = RLock()
        except Exception: raise ValueError(_ERROR) from None

    def _available(self) -> None:
        if (self._closed or self._config is not self._config_pin or self._guard is None
                or (self._nonce,self._serial,self._schema_pin,self._source,self._details,self._definition_digest) != self._binding_pin
                or self._expected != self._expected_pin
                or self._guard is not self._guard_pin or self._guard() is not True
                or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2): raise ValueError

    def _now(self) -> float:
        value = self._http_clock()
        if type(value) not in (int,float) or not math.isfinite(value) or value < 0 or value < self._last_time:
            self._closed = True
            raise ValueError
        self._last_time = float(value); return float(value)

    def _epoch(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0 or value < self._last_epoch:
            self._closed = True
            raise ValueError
        self._last_epoch = value; return value

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

    def _fetch(self, path: str, deadline: float) -> tuple[int,bytearray]:
        connection = None; raw = bytearray(); transferred = False
        try:
            if path not in (SCHEMA_PATH,DEFAULT_PATH,COLLECTION_PATH,*self._details): raise ValueError
            connection = self._factory(self._host,self._port,context=self._tls,timeout=self._remaining(deadline))
            connection.set_debuglevel(0); connection.connect(); handle = connection.sock
            handle.settimeout(self._remaining(deadline))
            headers = {'Authorization':'Bearer '+self._config.bearer_token,'Accept':'application/json',
                'Accept-Encoding':'identity','Cache-Control':'no-cache,no-store','Connection':'close'}
            if path == COLLECTION_PATH:
                headers.update({'X-HTTP-Method-Override':'GET','Content-Type':'application/json'})
                connection.request('POST',path,body=b'{"json_filter":[]}',headers=headers)
            else: connection.request('GET',path,headers=headers)
            status,raw = self._receive(connection,deadline,1048576,allow_absent=path in self._details)
            transferred = True; return status,raw
        finally:
            failed = False
            if connection is not None:
                try: connection.close()
                except Exception: failed = True
            if failed or not transferred: _zeroize_mutable(raw)
            if failed: raise ValueError

    def _receive(self, connection: Any, deadline: float, limit: int, *, allow_absent: bool = False) -> tuple[int,bytearray]:
        raw = bytearray()
        try:
            response = None; raw = bytearray(); transferred = False
            try:
                handle = connection.sock
                handle.settimeout(self._remaining(deadline)); response = connection.getresponse(); status = response.status
                if (type(status) is not int or status not in ((200,404) if allow_absent else (200,))
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
                    remaining = self._remaining(deadline)
                    if not response.isclosed(): handle.settimeout(remaining)
                    with memoryview(raw)[offset:] as view: count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(raw)-offset: raise ValueError
                    if not count: break
                    offset += count
                if not 0 < offset <= limit or expected is not None and expected != offset: raise ValueError
                raw = _take_mutable_prefix(raw, offset); self._remaining(deadline); transferred = True
                return status,raw
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

    def _root(self, raw: bytearray, path: str, status: int) -> dict[str,tuple[int,int]]:
        left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
        if _skip_json_space(raw,right) != len(raw): raise ValueError
        metadata._validate_json(raw,left,right,depth=0,budget=[50000]); fields = _object_spans(raw,left,right)
        if not fields.keys() <= _TOP: raise ValueError
        for name,expected in dict(http_method='POST' if path == COLLECTION_PATH else 'GET',http_status=status,
                serial=self._serial,version='v7.0.0',build=29,path='secret',name='script',
                status='error' if status == 404 else 'success').items():
            with memoryview(raw)[slice(*fields[name])] as actual:
                if not hmac.compare_digest(actual,_encoded(expected)): raise ValueError
        if 'vdom' in fields and metadata._scalar(raw,fields['vdom']) != 'root': raise ValueError
        if status == 200 and 'error' in fields:
            error = metadata._scalar(raw,fields['error'])
            if type(error) is not int or error != 0: raise ValueError
        if 'action' in fields:
            expected_action = 'schema' if path == SCHEMA_PATH else 'default' if path == DEFAULT_PATH else ''
            if metadata._scalar(raw,fields['action']) != expected_action: raise ValueError
        if path in self._details and 'mkey' in fields:
            if metadata._scalar(raw,fields['mkey']) != self._expected[self._details.index(path)]['name']: raise ValueError
        return fields

    def _schema(self, raw: bytearray) -> dict[str,dict[str,Any]]:
        root = self._root(raw,SCHEMA_PATH,200); fields = _object_spans(raw,*_object_spans(raw,*root['results'])['children'])
        if set(fields) != _FIELDS: raise ValueError
        specs: dict[str,dict[str,Any]] = {}
        for name,span in fields.items():
            descriptor = _object_spans(raw,*span); kind = metadata._scalar(raw,descriptor['type'])
            if name in _OPTIONS:
                if kind != 'option': raise ValueError
                values = [metadata._scalar(raw,_object_spans(raw,*option)['name'])
                    for option in metadata._array(raw,descriptor['options'],8)]
                if (any(type(value) is not str for value in values) or set(values) != _OPTIONS[name]
                        or len(values) != len(_OPTIONS[name])): raise ValueError
                specs[name] = dict(type=kind,options=sorted(_OPTIONS[name]))
            else:
                if kind not in ('string','var-string'): raise ValueError
                size = metadata._scalar(raw,descriptor['size'])
                if type(size) is not int or not 1 <= size <= 8192: raise ValueError
                if any(len(body[name].encode()) > size for body in self._expected): raise ValueError
                specs[name] = dict(type=kind,size=size)
        if canonical_digest(specs) != self._schema_pin: raise ValueError
        return specs

    def _definition(self, raw: bytearray, span: tuple[int,int], expected: dict[str,str], *, record: bool) -> dict[str,object]:
        fields = _object_spans(raw,*span)
        if not _FIELDS <= fields.keys() <= _FIELDS | (_META if record else set()): raise ValueError
        for name,value in expected.items():
            with memoryview(raw)[slice(*fields[name])] as actual:
                if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
        result: dict[str,object] = {}
        for name in fields.keys()-_FIELDS:
            meta_value = metadata._scalar(raw,fields[name])
            if name in ('q_ref','q_type'):
                if type(meta_value) is not int or not 0 <= meta_value <= 2147483647: raise ValueError
            elif name in ('q_no_edit','q_no_rename','q_static','q_global_entry'):
                if type(meta_value) is not bool: raise ValueError
            else:
                required = dict(q_origin_key=expected['name'],q_mkey_type='string',q_name='script',q_path='secret')[name]
                if meta_value != required: raise ValueError
            result[name] = meta_value
        return result

    def read(self) -> WindowsJitScriptObservation:
        buffers: list[bytearray] = []
        try:
            with self._lock, _private_http_logs():
                self._available(); started = self._epoch(); deadline = self._now()+self._config.timeout_seconds
                def fetch(path: str) -> tuple[int,bytearray]:
                    status,raw = self._fetch(path,deadline); buffers.append(raw); return status,raw
                _,raw = fetch(SCHEMA_PATH); self._schema(raw)
                _,raw = fetch(DEFAULT_PATH); root = self._root(raw,DEFAULT_PATH,200)
                self._definition(raw,root['results'],_default()['results'],record=False)
                _,collection = fetch(COLLECTION_PATH); root = self._root(collection,COLLECTION_PATH,200)
                rows = metadata._array(collection,root['results'],256); names = []; found: dict[str,dict[str,object]] = {}
                for name in ('size','matched_count'):
                    count = metadata._scalar(collection,root[name])
                    if type(count) is not int or count != len(rows): raise ValueError
                if 'limit_reached' in root and metadata._scalar(collection,root['limit_reached']) is not False: raise ValueError
                for span in rows:
                    fields = metadata._object_spans(collection,*span,frozenset({'name'})); entry_name = metadata._scalar(collection,fields['name'])
                    if type(entry_name) is not str or not 1 <= len(entry_name.encode()) <= 35 or entry_name in names: raise ValueError
                    names.append(entry_name)
                    for expected in self._expected:
                        if entry_name == expected['name']: found[entry_name] = self._definition(collection,span,expected,record=True)
                candidates = []
                for path,expected in zip(self._details,self._expected):
                    status,raw = fetch(path); root = self._root(raw,path,status); candidate = None
                    if status == 404:
                        if expected['name'] in found: raise ValueError
                        if 'results' in root:
                            with memoryview(raw)[slice(*root['results'])] as value:
                                if not any(hmac.compare_digest(value,literal) for literal in (b'null',b'[]')): raise ValueError
                    else:
                        span = root['results']
                        if raw[span[0]] == 91:
                            details = metadata._array(raw,span,1)
                            if len(details) != 1: raise ValueError
                            span = details[0]
                        candidate = self._definition(raw,span,expected,record=True)
                        if expected['name'] not in found or candidate != found[expected['name']]: raise ValueError
                    candidates.append(candidate)
                namespace = canonical_digest(dict(names=sorted(names)))
                state = canonical_digest(dict(contract=CONTRACT,source=self._source,schema=self._schema_pin,
                    definitions=self._definition_digest,namespace=namespace,candidates=candidates))
                observed = WindowsJitScriptObservation(self._source,self._schema_pin,namespace,state,len(names),
                    (candidates[0] is not None,candidates[1] is not None),started,started+10,tuple(sorted(names)))
                for buffer in buffers: _zeroize_mutable(buffer)
                self._remaining(deadline)
                if not observed.observed_at <= self._epoch() < observed.expires_at: raise ValueError
                self._latest = observed; return observed
        except Exception: raise ValueError(_ERROR) from None
        finally:
            for buffer in buffers: _zeroize_mutable(buffer)

    def prepare_plan(self) -> WindowsJitScriptPlan:
        try:
            with self._lock:
                observed = self.read()
                if any(observed.present): raise ValueError
                self._plan = WindowsJitScriptPlan(observed); return self._plan
        except Exception: raise ValueError(_ERROR) from None

    def compile_pair(self, plan: WindowsJitScriptPlan) -> tuple[bytearray,bytearray]:
        bodies: list[bytearray] = []; transferred = False
        try:
            with self._lock:
                self._available()
                if type(plan) is not WindowsJitScriptPlan or plan is not self._plan: raise ValueError
                if not plan._origin.observed_at <= self._epoch() < plan._origin.expires_at: raise ValueError
                deadline = self._now()+self._config.timeout_seconds
                observed = self.read()
                if observed.state_digest != plan._origin.state_digest or self._epoch() >= plan._origin.expires_at: raise ValueError
                bodies = [bytearray(_encoded(body)) for body in compile_windows_jit_script_pair(_default(),nonce=self._nonce)]
                self._available(); self._remaining(deadline)
                if self._epoch() >= plan._origin.expires_at: raise ValueError
                transferred = True; return bodies[0],bodies[1]
        except Exception: raise ValueError(_ERROR) from None
        finally:
            if not transferred:
                for body in bodies: _zeroize_mutable(body)

    def preview(self) -> dict[str,object]:
        try:
            with self._lock:
                plan = self.prepare_plan(); observed = plan._origin
                public = preview_windows_jit_script_pair(_default(),nonce=self._nonce)
                public.update(read_source_contract=CONTRACT,observed_at=observed.observed_at,expires_at=observed.expires_at,
                    visible_script_count=observed.script_count,candidate_names_absent_in_visible_view=True,
                    schema_pin_matched_locally=True,product_actor_verified=False,global_namespace_qualified=False)
                self._available()
                if self._epoch() >= observed.expires_at: raise ValueError
                return public
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock: self._closed = True
