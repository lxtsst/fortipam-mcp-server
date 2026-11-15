"""Fixed build29 SCIM metadata reads and a prebound, credential-free TLS probe.

No credential field/default is scalar-decoded. Read projection and TLS evidence
remain local candidates: API ownership, native qualification and independent
credential/sender/effect evidence are separate. No normal startup binds this.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import http.client
import json
import math
import socket
import ssl
from threading import RLock
import time
from typing import Any, Iterator, Protocol, runtime_checkable
from urllib.parse import urlsplit

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from . import secret_bulk_import_metadata as metadata
from .local_user_reset_projection import _object_spans
from .scim_client_contract import NATIVE_NAME, NONMATERIAL_FIELDS, ScimNonmaterialState, _context
from .scim_client_m4_adapter import ScimConfigurationReadback
from .secret_metadata_http_transport import (SecretMetadataHttpTransportConfig, _ssl_context,
    _zeroize_mutable, _json_value_end, _skip_json_space)
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam-build29-scim-fixed-read-local-candidate/v1'
BASE_PATH = '/api/v2/cmdb/user/scim'
DETAIL_PATH = BASE_PATH+'/'+NATIVE_NAME
SCHEMA_PATH = BASE_PATH+'?action=schema'
CURRENT_PATH = BASE_PATH+'?format='+'%7C'.join(sorted(NONMATERIAL_FIELDS))
GLOBAL_PATH = '/api/v2/cmdb/system/global?format=scim-https-port%7Cscim-server-cert'
INTERFACES_PATH = '/api/v2/cmdb/system/interface?format=allowaccess%7Cname'
SAML_PATH = '/api/v2/cmdb/user/saml?format=name%7Cscim-client'
_ROUTES = {SCHEMA_PATH: ('user','scim'), CURRENT_PATH: ('user','scim'), GLOBAL_PATH: ('system','global'),
    INTERFACES_PATH: ('system','interface'), SAML_PATH: ('user','saml')}
_TYPES = {'id':'integer', 'name':'string', 'status':'option', 'base-url':'string', 'auth-method':'option',
    'secret':'password', 'client-identity-check':'option', 'certificate':'string', 'token-certificate':'string'}
_LIMITS = {'name':35, 'base-url':127, 'secret':59, 'certificate':79, 'token-certificate':79}
_TOP = {'http_method','http_status','status','path','name','results','serial','version','build',
    'vdom','revision','mkey','action','size','matched_count','limit_reached'}
_ERROR = 'The private SCIM metadata source is unavailable.'


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def scim_trust_binding(base_url: str, port: int, certificate_selector: str) -> str:
    return _digest(dict(base_url=base_url, port=port, certificate=certificate_selector))


@dataclass(frozen=True, slots=True, repr=False)
class ScimTrustObservation(_OpaqueC3Object):
    """Pinned configuration identity, with a separate live-handshake flag.

    False means only the prebound configuration was matched. It attests to
    neither a current served certificate, credentials nor listener absence.
    """
    source_digest: str
    binding_digest: str
    certificate_sha256: str
    observed_at: int
    expires_at: int
    active_tls_verified: bool = True

    def __post_init__(self) -> None:
        for value in (self.source_digest, self.binding_digest, self.certificate_sha256): require_digest(value, 'SCIM trust')
        if (type(self.observed_at) is not int or type(self.expires_at) is not int or type(self.active_tls_verified) is not bool
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at+10): raise ValueError


@runtime_checkable
class ScimTrustReader(Protocol):
    def observe(self, base_url: str, port: int, certificate_selector: str, *, timeout_seconds: float,
            service_enabled: bool = True) -> ScimTrustObservation: ...


class ScimTlsTrustProbe(_OpaqueC3Object):
    """One prebound service and certificate; handshake only, no SCIM request/auth."""
    def __init__(self, base_url: str, port: int, certificate_selector: str, *, ca_file: str,
            certificate_sha256: str, source_digest: str, enabled: bool = False,
            connection_factory: Callable[..., Any] = socket.create_connection,
            http_clock: Callable[[], float] = time.monotonic,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            url = urlsplit(base_url)
            if (type(base_url) is not str or len(base_url) > 127 or url.scheme != 'https' or not url.hostname
                    or url.username is not None or url.password is not None or url.port is not None
                    or not url.path.endswith('/scim/v2') or url.query or url.fragment or '\\' in base_url
                    or any(c.isspace() for c in base_url) or type(port) is not int or not 1 <= port <= 65535
                    or type(certificate_selector) is not str or not 1 <= len(certificate_selector) <= 79
                    or any(ord(c) < 32 or ord(c) == 127 for c in certificate_selector)
                    or type(enabled) is not bool or not callable(connection_factory) or not callable(clock)
                    or not callable(http_clock)): raise ValueError
            require_digest(certificate_sha256, 'SCIM certificate'); require_digest(source_digest, 'SCIM trust source')
            self._context = ssl.create_default_context(cafile=ca_file)
            self._context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._target, self._host = (base_url,port,certificate_selector), url.hostname
            self._certificate, self._source = certificate_sha256, source_digest
            self._enabled, self._factory, self._http_clock, self._clock = enabled, connection_factory, http_clock, clock
            self._last_time, self._last_epoch, self._failed = -1.0, -1, False
        except Exception: raise ValueError(_ERROR) from None

    def _now(self) -> float:
        value = self._http_clock()
        if self._failed or type(value) not in (float,int) or not math.isfinite(value) or value < 0 or value < self._last_time:
            self._failed = True
            raise ValueError
        self._last_time = float(value)
        return float(value)

    def observe(self, base_url: str, port: int, certificate_selector: str, *, timeout_seconds: float,
            service_enabled: bool = True) -> ScimTrustObservation:
        """Disabled service: check the configured binding without claiming live TLS.

        Authoritative CMDB status decides the mode. A connection failure never
        becomes evidence of disablement, credential preservation or recovery.
        """
        raw = tls = None
        try:
            if (not self._enabled or self._failed or (base_url,port,certificate_selector) != self._target
                    or type(service_enabled) is not bool
                    or type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30
                    or not self._context.check_hostname or self._context.verify_mode != ssl.CERT_REQUIRED
                    or self._context.minimum_version < ssl.TLSVersion.TLSv1_2): raise ValueError
            deadline = self._now()+timeout_seconds
            if service_enabled:
                raw = self._factory((self._host,port), timeout=timeout_seconds)
                remaining = deadline-self._now()
                if remaining <= 0: raise ValueError
                raw.settimeout(remaining)
                tls = self._context.wrap_socket(raw, server_hostname=self._host)
                certificate = tls.getpeercert(binary_form=True)
                if not certificate or hashlib.sha256(certificate).hexdigest() != self._certificate: raise ValueError
        except Exception: raise ValueError(_ERROR) from None
        finally:
            failed = False
            for resource in (tls,raw):
                if resource is not None:
                    try: resource.close()
                    except Exception: failed = True
            if failed: raise ValueError(_ERROR) from None
        try:
            if self._now() >= deadline: raise ValueError
            now = self._clock()
            if type(now) is not int or now < 0 or now < self._last_epoch:
                self._failed = True
                raise ValueError
            self._last_epoch = now
            return ScimTrustObservation(self._source, scim_trust_binding(*self._target), self._certificate, now, now+10,
                active_tls_verified=service_enabled)
        except Exception: raise ValueError(_ERROR) from None


class ScimNativeSource(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig, *, expected_serial: str,
            source_digest: str, trust_source_digest: str, trust_reader: ScimTrustReader | None = None,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            http_clock: Callable[[], float] = time.monotonic, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(expected_serial) is not str
                    or not 1 <= len(expected_serial) <= 128 or not callable(connection_factory) or not callable(http_clock)
                    or not callable(clock) or trust_reader is not None and not isinstance(trust_reader, ScimTrustReader)): raise ValueError
            require_digest(source_digest, 'SCIM source'); require_digest(trust_source_digest, 'SCIM trust source')
            url = urlsplit(config.base_url)
            if (url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment
                    or url.path not in ('','/')): raise ValueError
            self._config, self._config_pin, self._serial = config, config, expected_serial
            self._source, self._trust_source, self._trust = source_digest, trust_source_digest, trust_reader
            self._host, self._port, self._context = url.hostname, url.port or 443, _ssl_context(config)
            self._context.minimum_version = max(self._context.minimum_version, ssl.TLSVersion.TLSv1_2)
            self._factory, self._http_clock, self._clock = connection_factory, http_clock, clock
            self._last_time, self._last_epoch, self._closed, self._failed_clock = -1.0, -1, False, False
            self._deadline_cap: float | None = None
            self._latest: ScimConfigurationReadback | None = None
            self._last_trust: ScimTrustObservation | None = None
            self._lock = RLock()
            self._available()
        except Exception: raise ValueError(_ERROR) from None

    def _available(self) -> None:
        if (self._closed or self._failed_clock or self._config is not self._config_pin
                or not self._context.check_hostname or self._context.verify_mode != ssl.CERT_REQUIRED
                or self._context.minimum_version < ssl.TLSVersion.TLSv1_2): raise ValueError

    def _now(self) -> float:
        value = self._http_clock()
        if type(value) not in (float,int) or not math.isfinite(value) or value < 0 or value < self._last_time:
            self._failed_clock = True
            raise ValueError
        self._last_time = float(value)
        return float(value)

    def _remaining(self, deadline: float) -> float:
        self._available(); remaining = deadline-self._now()
        if remaining <= 0: raise ValueError
        return min(self._config.timeout_seconds, remaining)

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
            if path not in _ROUTES: raise ValueError
            connection = self._factory(self._host,self._port,context=self._context,timeout=self._remaining(deadline))
            connection.set_debuglevel(0); connection.connect(); handle = connection.sock
            handle.settimeout(self._remaining(deadline))
            connection.request('GET',path,headers={'Authorization':'Bearer '+self._config.bearer_token,
                'Accept':'application/json','Accept-Encoding':'identity','Connection':'close','Cache-Control':'no-cache,no-store'})
            raw = self._receive(connection,deadline,131072)
            transferred = True
            return raw
        finally:
            failed = False
            if connection is not None:
                try: connection.close()
                except Exception: failed = True
            if failed or not transferred: _zeroize_mutable(raw)
            if failed: raise ValueError

    def _receive(self, connection: Any, deadline: float, limit: int) -> bytearray:
        """Bound response framing/cleanup for the fixed GET and PUT callers."""
        raw = bytearray()
        try:
            response = None; raw = bytearray(); transferred = False
            try:
                handle = connection.sock
                handle.settimeout(self._remaining(deadline)); response = connection.getresponse()
                if (type(response.status) is not int or response.status != 200
                        or response.getheader('Content-Type','').split(';',1)[0].strip().lower() != 'application/json'
                        or response.getheader('Content-Encoding','identity').lower() != 'identity'): raise ValueError
                header = response.getheader('Content-Length'); expected = None
                if header is not None:
                    if (type(header) is not str or not header.isascii() or not header.isdecimal() or len(header) > 6
                            or response.getheader('Transfer-Encoding') is not None): raise ValueError
                    expected = int(header)
                    if not 0 < expected <= limit: raise ValueError
                raw = bytearray(limit+1); offset = 0
                while offset < len(raw):
                    remaining = self._remaining(deadline)
                    if not response.isclosed(): handle.settimeout(remaining)
                    view = memoryview(raw)[offset:]
                    try: count = response.readinto(view)
                    finally: view.release()
                    if type(count) is not int or not 0 <= count <= len(raw)-offset: raise ValueError
                    if count == 0: break
                    offset += count
                if not 0 < offset <= limit or expected is not None and offset != expected: raise ValueError
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

    def _envelope(self, raw: bytearray, path: str) -> tuple[dict[str,tuple[int,int]], tuple[int,int]]:
        left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
        if _skip_json_space(raw,right) != len(raw): raise ValueError
        metadata._validate_json(raw,left,right,depth=0,budget=[20000]); fields = _object_spans(raw,left,right)
        if not set(fields) <= _TOP: raise ValueError
        table_path, table_name = _ROUTES[path]
        for key, expected in dict(http_method='GET',http_status=200,serial=self._serial,version='v7.0.0',build=29,
                path=table_path,name=table_name).items():
            value = metadata._scalar(raw,fields[key])
            if type(value) is not type(expected) or value != expected: raise ValueError
        if metadata._scalar(raw,fields['status']) not in ('success','OK'): raise ValueError
        if 'action' in fields and metadata._scalar(raw,fields['action']) != ('schema' if path == SCHEMA_PATH else ''): raise ValueError
        return fields, fields['results']

    def _schema(self, raw: bytearray) -> dict[str,Any]:
        _, result = self._envelope(raw,SCHEMA_PATH)
        children = _object_spans(raw,*result)['children']; fields = _object_spans(raw,*children)
        if set(fields) != set(_TYPES): raise ValueError
        specs: dict[str,Any] = {}
        for name, kind in _TYPES.items():
            field = _object_spans(raw,*fields[name])
            if metadata._scalar(raw,field['type']) != kind: raise ValueError
            spec: dict[str,Any] = dict(type=kind)
            if name in _LIMITS:
                if metadata._scalar(raw,field['size']) != _LIMITS[name]: raise ValueError
                spec['size'] = _LIMITS[name]
            if name == 'id':
                for key, expected in (('min-value',0),('max-value',4294967295)):
                    value = metadata._scalar(raw,field[key])
                    if type(value) is not int or value != expected: raise ValueError
                    spec[key] = value
            if kind == 'option':
                choices = [metadata._scalar(raw,_object_spans(raw,*item)['name']) for item in metadata._array(raw,field['options'],16)]
                if (not choices or any(type(choice) is not str or not 1 <= len(choice) <= 64 for choice in choices)
                        or len(set(choices)) != len(choices)): raise ValueError
                spec['options'] = sorted(choices)
            specs[name] = spec
        return specs

    def _projection(self, raw: bytearray, path: str, names: set[str]) -> list[dict[str,Any]]:
        root, span = self._envelope(raw,path)
        if path == GLOBAL_PATH:
            spans = [span] if raw[span[0]] == 123 else metadata._array(raw,span,1)
            if len(spans) != 1: raise ValueError
        else:
            spans = metadata._array(raw,span,128)
            for key in ('size','matched_count'):
                value = metadata._scalar(raw,root[key])
                if type(value) is not int or value != len(spans): raise ValueError
            if 'limit_reached' in root and metadata._scalar(raw,root['limit_reached']) is not False: raise ValueError
        result = []
        for span in spans:
            fields = _object_spans(raw,*span)
            if not names <= set(fields) <= names | {'q_origin_key'}: raise ValueError
            row = {key:metadata._scalar(raw,fields[key]) for key in sorted(names)}
            if 'q_origin_key' in fields:
                origin = metadata._scalar(raw,fields['q_origin_key'])
                if 'name' in names:
                    if origin != row['name']: raise ValueError
                elif type(origin) is not str or len(origin) > 35 or any(ord(c)<32 or ord(c)==127 for c in origin): raise ValueError
                else: row['q_origin_key'] = origin
            result.append(row)
        if 'name' in names and len({row['name'] for row in result}) != len(result): raise ValueError
        return result

    def read(self) -> ScimConfigurationReadback:
        buffers: list[bytearray] = []
        try:
            with self._lock, _private_http_logs():
                self._available()
                if self._trust is None: raise ValueError
                deadline = self._now()+self._config.timeout_seconds
                if self._deadline_cap is not None: deadline = min(deadline,self._deadline_cap)
                def fetch(path: str) -> bytearray:
                    raw = self._fetch(path,deadline); buffers.append(raw); return raw
                schema = self._schema(fetch(SCHEMA_PATH))
                rows = self._projection(fetch(CURRENT_PATH),CURRENT_PATH,set(NONMATERIAL_FIELDS))
                if len(rows) != 1 or rows[0]['name'] != NATIVE_NAME: raise ValueError
                state = ScimNonmaterialState.from_values(rows[0])
                for name, spec in schema.items():
                    if spec['type'] == 'option' and rows[0][name] not in spec['options']: raise ValueError
                general = self._projection(fetch(GLOBAL_PATH),GLOBAL_PATH,{'scim-https-port','scim-server-cert'})[0]
                port, certificate = general['scim-https-port'], general['scim-server-cert']
                if (type(port) is not int or not 1 <= port <= 65535 or type(certificate) is not str
                        or not 1 <= len(certificate.encode()) <= 79 or any(ord(c)<32 or ord(c)==127 for c in certificate)): raise ValueError
                interfaces = self._projection(fetch(INTERFACES_PATH),INTERFACES_PATH,{'name','allowaccess'})
                saml = self._projection(fetch(SAML_PATH),SAML_PATH,{'name','scim-client'})
                for row in interfaces+saml:
                    if any(type(value) is not str or len(value.encode()) > 4096
                            or any(ord(c)<32 or ord(c)==127 for c in value) for value in row.values()): raise ValueError
                if not any('scim' in row['allowaccess'].split() for row in interfaces): raise ValueError
                base_url = rows[0]['base-url']
                service_enabled = rows[0]['status'] == 'enable'
                trust = self._trust.observe(base_url,port,certificate,timeout_seconds=self._remaining(deadline),
                    service_enabled=service_enabled)
                now = self._clock()
                if type(now) is not int or now < 0 or now < self._last_epoch:
                    self._failed_clock = True
                    raise ValueError
                if (type(trust) is not ScimTrustObservation
                        or trust.source_digest != self._trust_source or trust.binding_digest != scim_trust_binding(base_url,port,certificate)
                        or trust.active_tls_verified is not service_enabled
                        or not trust.observed_at <= now < trust.expires_at): raise ValueError
                self._last_epoch = now; self._remaining(deadline)
                # Trust identity stays stable across enable/disable. Live TLS
                # is required only for an enabled record and is never inferred
                # from this configuration digest or a failed connection.
                context = _context(dict(serial_digest=hashlib.sha256(self._serial.encode()).hexdigest(), schema_digest=_digest(schema),
                    global_digest=_digest(general), interfaces_digest=_digest(sorted(interfaces,key=lambda row:row['name'])),
                    saml_digest=_digest(sorted(saml,key=lambda row:row['name'])), trust_digest=canonical_digest(dict(
                        kind='configured_service_trust',source=trust.source_digest,
                        binding=trust.binding_digest,certificate=trust.certificate_sha256))))
                result = ScimConfigurationReadback(state,context,self._source)
        except Exception: raise ValueError(_ERROR) from None
        finally:
            for raw in buffers: _zeroize_mutable(raw)
        self._available()
        self._last_trust = trust
        self._latest = result
        return result

    def close(self) -> None:
        with self._lock: self._closed = True
