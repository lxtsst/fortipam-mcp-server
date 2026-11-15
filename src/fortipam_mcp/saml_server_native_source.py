"""Four fixed build29 SAML reads, with a separate prebound dependency source.

No normal runtime binds this private candidate. Global/proxy/IdP/certificate
observations remain independently supplied and source-bound; neither zero
references nor synthetic endpoints prove shared-runtime isolation.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import http.client
import json
import math
import ssl
from threading import RLock
import time
from typing import Any, Iterator, Protocol, runtime_checkable
from urllib.parse import quote, urlsplit

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from . import secret_bulk_import_metadata as metadata
from .local_user_reset_projection import _object_spans
from .saml_server_contract import (CONFIG_FIELDS, ENDPOINT_FIELDS, NATIVE_SOURCE_NAME, SamlServerCreateBinding,
    SamlServerCreatePlan, Scalar, _META, _config, _digest, _record, _source)
from .secret_metadata_http_transport import (SecretMetadataHttpTransportConfig, _json_value_end,
    _skip_json_space, _ssl_context, _zeroize_mutable)
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam-build29-saml-fixed-read-local-candidate/v1'
BASE_PATH = '/api/v2/cmdb/user/saml'
SCHEMA_PATH = BASE_PATH+'?action=schema&with_meta=true'
DEFAULT_PATH = BASE_PATH+'?action=default&with_meta=true'
COLLECTION_PATH = BASE_PATH+'?with_meta=true'
_TOP = {'http_method','http_status','status','path','name','results','serial','version','build',
    'vdom','revision','mkey','action','size','matched_count','limit_reached','error'}
_NATIVE_TYPES = {name:'string' for name in CONFIG_FIELDS}
_NATIVE_TYPES.update({name:'option' for name in ('adfs-claim','group-claim-type','user-claim-type')})
_SERVER_FIELDS = {'digest-method','limit-relaystate','require-signed-resp-and-asrt','scim-group-attr-type'}
_NATIVE_TYPES['clock-tolerance'] = 'integer'
_ERROR = 'The private SAML metadata source is unavailable.'


@dataclass(frozen=True, slots=True, repr=False)
class SamlDependencyObservation(_OpaqueC3Object):
    source_digest: str
    record_digest: str
    dependencies_digest: str
    idp_metadata_digest: str
    idp_certificate_sha256: str
    certificate_reference_count: int
    complete: bool
    runtime_isolation_verified: bool
    independent_recovery_ready: bool
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.record_digest,self.dependencies_digest,
                self.idp_metadata_digest,self.idp_certificate_sha256): require_digest(value,'SAML dependency')
        if (type(self.certificate_reference_count) is not int or not 0 <= self.certificate_reference_count <= 2147483647
                or any(type(value) is not bool for value in (self.complete,self.runtime_isolation_verified,self.independent_recovery_ready))
                or type(self.observed_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at+10): raise ValueError


@runtime_checkable
class SamlDependencyReader(Protocol):
    def observe(self, record_digest: str, *, timeout_seconds: float) -> SamlDependencyObservation: ...


@dataclass(frozen=True, slots=True, repr=False)
class SamlNativeObservation(_OpaqueC3Object):
    plan: SamlServerCreatePlan
    source_digest: str
    dependencies: SamlDependencyObservation
    _collection: bytes
    _candidate: bytes | None

    def __post_init__(self) -> None:
        require_digest(self.source_digest,'SAML source')
        if (type(self.plan) is not SamlServerCreatePlan or type(self.dependencies) is not SamlDependencyObservation
                or type(self._collection) is not bytes or self._candidate is not None and type(self._candidate) is not bytes): raise ValueError

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,plan=self.plan.digest,source=self.source_digest,
            dependency_source=self.dependencies.source_digest,collection=hashlib.sha256(self._collection).hexdigest(),
            candidate=None if self._candidate is None else hashlib.sha256(self._candidate).hexdigest(),
            certificate_references=self.dependencies.certificate_reference_count,
            isolation=self.dependencies.runtime_isolation_verified,recovery=self.dependencies.independent_recovery_ready))

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT,configuration_field_count=22,record_field_count=32,
            candidate_present=self._candidate is not None,collection_detail_agree=True,
            runtime_isolation_reported=self.dependencies.runtime_isolation_verified,
            independent_recovery_reported=self.dependencies.independent_recovery_ready,
            native_backend_qualified=False,configuration_write_authorized=False,saml_login_verified=False)


def _encoded(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=True,allow_nan=False).encode('ascii')


class SamlNativeSource(_OpaqueC3Object):
    """One prebound candidate; bounded schema/default/collection/detail GETs."""
    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: SamlServerCreateBinding, *,
            expected_serial: str, source_digest: str, dependency_source_digest: str,
            dependencies: SamlDependencyReader | None = None, source_guard: Callable[[],bool] | None = None,
            connection_factory: Callable[...,Any] = http.client.HTTPSConnection,
            http_clock: Callable[[],float] = time.monotonic, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(binding) is not SamlServerCreateBinding
                    or type(expected_serial) is not str or not 1 <= len(expected_serial) <= 128
                    or dependencies is not None and not isinstance(dependencies,SamlDependencyReader)
                    or source_guard is not None and not callable(source_guard)
                    or not callable(connection_factory) or not callable(http_clock) or not callable(clock)): raise ValueError
            for value in (source_digest,dependency_source_digest): require_digest(value,'SAML source')
            if source_digest == dependency_source_digest: raise ValueError
            url = urlsplit(config.base_url)
            if (url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
                    or url.path not in ('','/') or url.query or url.fragment): raise ValueError
            self._config = self._config_pin = config
            self._binding, self._serial = binding, expected_serial
            self._source, self._dependency_source, self._dependencies = source_digest, dependency_source_digest, dependencies
            self._guard = self._guard_pin = source_guard
            self._host, self._port, self._tls = url.hostname, url.port or 443, _ssl_context(config)
            self._tls.minimum_version = max(self._tls.minimum_version,ssl.TLSVersion.TLSv1_2)
            self._detail = BASE_PATH+'/'+quote(binding.name,safe='')+'?with_meta=true'
            self._factory, self._http_clock, self._clock = connection_factory, http_clock, clock
            self._last_time, self._last_epoch = -1.0, -1
            self._closed = self._failed_clock = False
            self._deadline_cap: float | None = None
            self._latest: SamlNativeObservation | None = None
            self._lock = RLock()
        except Exception: raise ValueError(_ERROR) from None

    def _available(self) -> None:
        if (self._closed or self._failed_clock or self._config is not self._config_pin
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True
                or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2): raise ValueError

    def _now(self) -> float:
        value = self._http_clock()
        if (type(value) not in (int,float) or not math.isfinite(value) or value < 0 or value < self._last_time):
            self._failed_clock = True
            raise ValueError
        self._last_time = float(value)
        return float(value)

    def _remaining(self, deadline: float) -> float:
        self._available(); remaining = deadline-self._now()
        if remaining <= 0: raise ValueError
        return min(self._config.timeout_seconds,remaining)

    def _epoch(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0 or value < self._last_epoch:
            self._failed_clock = True
            raise ValueError
        self._last_epoch = value
        return value

    def _fetch(self, path: str, deadline: float) -> tuple[int,bytearray]:
        connection = None; raw = bytearray(); transferred = False
        try:
            if path not in (SCHEMA_PATH,DEFAULT_PATH,COLLECTION_PATH,self._detail): raise ValueError
            connection = self._factory(self._host,self._port,context=self._tls,timeout=self._remaining(deadline))
            connection.set_debuglevel(0); connection.connect()
            handle = connection.sock; handle.settimeout(self._remaining(deadline))
            connection.request('GET',path,headers={'Authorization':'Bearer '+self._config.bearer_token,
                'Accept':'application/json','Accept-Encoding':'identity','Cache-Control':'no-cache,no-store','Connection':'close'})
            status,raw = self._receive(connection,deadline,131072,allow_absent=path == self._detail)
            transferred = True
            return status,raw
        finally:
            failed = False
            if connection is not None:
                try: connection.close()
                except Exception: failed = True
            if failed or not transferred: _zeroize_mutable(raw)
            if failed: raise ValueError

    @contextmanager
    def _bounded_by(self, deadline: float) -> Iterator[None]:
        with self._lock:
            previous = self._deadline_cap
            self._deadline_cap = deadline if previous is None else min(previous,deadline)
            try: yield
            finally: self._deadline_cap = previous

    def _receive(self, connection: Any, deadline: float, limit: int, *, allow_absent: bool = False) -> tuple[int,bytearray]:
        raw = bytearray()
        try:
            response = None; raw = bytearray(); transferred = False
            try:
                handle = connection.sock
                handle.settimeout(self._remaining(deadline)); response = connection.getresponse()
                status = response.status
                if (type(status) is not int or status not in ((200,404) if allow_absent else (200,))
                        or response.getheader('Content-Type','').split(';',1)[0].strip().lower() != 'application/json'
                        or response.getheader('Content-Encoding','identity').lower() != 'identity'): raise ValueError
                length = response.getheader('Content-Length'); expected = None
                if length is not None:
                    if (type(length) is not str or not length.isascii() or not length.isdecimal() or len(length)>6
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
                if not 0 < offset <= limit or expected is not None and offset != expected: raise ValueError
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

    def _envelope(self, raw: bytearray, path: str, status: int) -> dict[str,tuple[int,int]]:
        left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
        if _skip_json_space(raw,right) != len(raw): raise ValueError
        metadata._validate_json(raw,left,right,depth=0,budget=[20000]); fields = _object_spans(raw,left,right)
        if not set(fields) <= _TOP: raise ValueError
        for key,expected in dict(http_method='GET',http_status=status,serial=self._serial,version='v7.0.0',build=29,
                path='user',name='saml').items():
            value = metadata._scalar(raw,fields[key])
            if type(value) is not type(expected) or value != expected: raise ValueError
        if metadata._scalar(raw,fields['status']) not in (('error',) if status == 404 else ('success','OK')): raise ValueError
        if 'mkey' in fields and path == self._detail and metadata._scalar(raw,fields['mkey']) != self._binding.name: raise ValueError
        if 'vdom' in fields and metadata._scalar(raw,fields['vdom']) != 'root': raise ValueError
        if 'action' in fields:
            action = 'schema' if path == SCHEMA_PATH else 'default' if path == DEFAULT_PATH else ''
            if metadata._scalar(raw,fields['action']) != action: raise ValueError
        return fields

    def _schema(self, raw: bytearray) -> dict[str,dict[str,Any]]:
        root = self._envelope(raw,SCHEMA_PATH,200)
        fields = _object_spans(raw,*_object_spans(raw,*root['results'])['children'])
        if set(fields) != set(CONFIG_FIELDS): raise ValueError
        result = {}
        for name in CONFIG_FIELDS:
            item = _object_spans(raw,*fields[name]); kind = metadata._scalar(raw,item['type'])
            if kind not in ('option','string','integer') or name not in _SERVER_FIELDS and kind != _NATIVE_TYPES[name]: raise ValueError
            spec: dict[str,Any] = dict(type=kind)
            if kind == 'string':
                size = metadata._scalar(raw,item['size'])
                if type(size) is not int or not 1 <= size <= 8192 or name == 'name' and size != 35: raise ValueError
                spec['size'] = size
            elif kind == 'integer':
                minimum,maximum = (metadata._scalar(raw,item[key]) for key in ('min-value','max-value'))
                if type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum <= 4294967295: raise ValueError
                spec.update(minimum=minimum,maximum=maximum)
            else:
                options = [metadata._scalar(raw,_object_spans(raw,*option)['name'])
                    for option in metadata._array(raw,item['options'],64)]
                if (not options or any(type(value) is not str or len(value) > 128 for value in options)
                        or len(set(options)) != len(options)): raise ValueError
                spec['options'] = sorted(options)
            result[name] = spec
        return result

    def _values(self, raw: bytearray, span: tuple[int,int], specs: dict[str,dict[str,Any]], *, record: bool) -> dict[str,Scalar]:
        fields = _object_spans(raw,*span)
        if set(fields) != set(CONFIG_FIELDS) | (set(_META) if record else set()): raise ValueError
        values = {name:metadata._scalar(raw,fields[name]) for name in fields}
        for name,spec in specs.items():
            value,kind = values[name],spec['type']
            if kind == 'integer':
                if type(value) is not int or not spec['minimum'] <= value <= spec['maximum']: raise ValueError
            elif type(value) is not str: raise ValueError
            elif kind == 'string' and len(value.encode()) > spec['size']: raise ValueError
            elif kind == 'option' and value not in spec['options']: raise ValueError
        # Every collection row participates in the preservation fingerprint,
        # including unrelated records. URL userinfo is credential material,
        # so it cannot be retained or fingerprinted as configuration.
        for endpoint in ENDPOINT_FIELDS:
            address = values[endpoint]
            if type(address) is not str: raise ValueError
            if address:
                url = urlsplit(address)
                if url.username is not None or url.password is not None: raise ValueError
        if record:
            record_name = values['name']
            if type(record_name) is not str or not 1 <= len(record_name.encode()) <= 35: raise ValueError
            return _record(values,record_name)
        return _config(values)

    def read(self) -> SamlNativeObservation:
        buffers: list[bytearray] = []
        try:
            with self._lock, _private_http_logs():
                self._available(); self._epoch()
                if self._dependencies is None: raise ValueError
                deadline = self._now()+self._config.timeout_seconds
                if self._deadline_cap is not None: deadline = min(deadline,self._deadline_cap)
                def fetch(path: str) -> tuple[int,bytearray]:
                    status,raw = self._fetch(path,deadline); buffers.append(raw); return status,raw
                _,raw = fetch(SCHEMA_PATH); specs = self._schema(raw)
                _,raw = fetch(DEFAULT_PATH); root = self._envelope(raw,DEFAULT_PATH,200)
                defaults = self._values(raw,root['results'],specs,record=False)
                _,raw = fetch(COLLECTION_PATH); root = self._envelope(raw,COLLECTION_PATH,200)
                spans = metadata._array(raw,root['results'],64)
                for key in ('size','matched_count'):
                    value = metadata._scalar(raw,root[key])
                    if type(value) is not int or value != len(spans): raise ValueError
                if 'limit_reached' in root and metadata._scalar(raw,root['limit_reached']) is not False: raise ValueError
                rows = [self._values(raw,span,specs,record=True) for span in spans]
                if len({row['name'] for row in rows}) != len(rows): raise ValueError
                sources = [row for row in rows if row['name'] == NATIVE_SOURCE_NAME]
                if len(sources) != 1: raise ValueError
                original = _source(sources[0])
                candidates = [row for row in rows if row['name'] == self._binding.name]
                status,raw = fetch(self._detail); root = self._envelope(raw,self._detail,status)
                candidate = None
                if status == 404:
                    if candidates or 'results' in root and bytes(raw[slice(*root['results'])]) not in (b'null',b'[]'): raise ValueError
                else:
                    span = root['results']
                    if raw[span[0]] == 91:
                        details = metadata._array(raw,span,1)
                        if len(details) != 1: raise ValueError
                        span = details[0]
                    candidate = self._values(raw,span,specs,record=True)
                    if candidates != [candidate]: raise ValueError
                dependency = self._dependencies.observe(_digest(original),timeout_seconds=self._remaining(deadline))
                if (type(dependency) is not SamlDependencyObservation or not dependency.complete
                        or dependency.source_digest != self._dependency_source or dependency.record_digest != _digest(original)
                        or not dependency.observed_at <= self._epoch() < dependency.expires_at): raise ValueError
                plan = SamlServerCreatePlan(self._binding,original,defaults,schema_digest=_digest(specs),
                    serial_digest=hashlib.sha256(self._serial.encode()).hexdigest(),dependencies_digest=dependency.dependencies_digest,
                    idp_metadata_digest=dependency.idp_metadata_digest,idp_certificate_sha256=dependency.idp_certificate_sha256)
                result = SamlNativeObservation(plan,self._source,dependency,_encoded(rows),None if candidate is None else _encoded(candidate))
                self._remaining(deadline)
        except Exception: raise ValueError(_ERROR) from None
        finally:
            for raw in buffers: _zeroize_mutable(raw)
        try:
            if not dependency.observed_at <= self._epoch() < dependency.expires_at: raise ValueError
            self._remaining(deadline)
            self._latest = result
            return result
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock: self._closed = True
