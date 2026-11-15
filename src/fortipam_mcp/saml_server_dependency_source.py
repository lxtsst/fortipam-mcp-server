"""Four fixed SAML dependency reads joined to prebound public IdP metadata.

This private local profile accepts only explicitly classified proxy/gateway
fields. Unknown gateway shapes refuse the read. No combination of these reads
establishes shared-runtime isolation, independent recovery or write authority.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
import http.client
import math
import re
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import quote, urlsplit

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from . import secret_bulk_import_metadata as metadata
from .local_user_reset_projection import _object_spans
from .saml_idp_metadata_probe import SamlIdpMetadataProbe, SamlMetadataObservation
from .saml_server_contract import _digest, _source
from .saml_server_native_source import SamlDependencyObservation
from .secret_metadata_http_transport import (SecretMetadataHttpTransportConfig, _ssl_context,
    _json_value_end, _skip_json_space, _zeroize_mutable)
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam_build29_saml_fixed_dependencies_local_v1'
GLOBAL_PATH = '/api/v2/cmdb/system/global?format=saml-authentication'
CERTIFICATES_PATH = '/api/v2/monitor/system/available-certificates?with_ca=1&with_crl=1&with_remote=1'
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,78}\Z')
_TOP = {'http_method','http_status','status','path','name','results','serial','version','build',
    'vdom','revision','mkey','action','size','matched_count','limit_reached','error'}
_GATEWAY = {'id','service','url-map','saml-server','virtual-host','ssl-certificate','q_origin_key'}
_ERROR = 'The private SAML dependency source is unavailable.'


def _name(value: object) -> str:
    if type(value) is not str or _NAME.fullmatch(value) is None: raise ValueError
    return value


def _text(value: object, maximum: int = 8192) -> str:
    if (type(value) is not str or len(value.encode()) > maximum
            or any(ord(char)<32 or ord(char)==127 for char in value)): raise ValueError
    return value


class SamlDependencySource(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig, source_record: Mapping[str,object], *,
            expected_serial: str, proxy_name: str, source_digest: str, metadata_source_digest: str,
            metadata_probe: SamlIdpMetadataProbe, source_guard: Callable[[],bool] | None = None,
            connection_factory: Callable[...,Any] = http.client.HTTPSConnection,
            http_clock: Callable[[],float] = time.monotonic, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(metadata_probe) is not SamlIdpMetadataProbe
                    or type(expected_serial) is not str or not 1 <= len(expected_serial) <= 128
                    or source_guard is not None and not callable(source_guard)
                    or not callable(connection_factory) or not callable(http_clock) or not callable(clock)): raise ValueError
            record = _source(source_record); certificate_name = _name(record['idp-cert']); _name(proxy_name)
            for value in (source_digest,metadata_source_digest): require_digest(value,'SAML dependency source')
            if (source_digest == metadata_source_digest or metadata_probe._source != metadata_source_digest
                    or metadata_probe._binding.record_digest != _digest(record)): raise ValueError
            url = urlsplit(config.base_url)
            if (url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
                    or url.path not in ('','/') or url.query or url.fragment
                    or url.port is not None and not 1 <= url.port <= 65535): raise ValueError
            self._config = self._config_pin = config
            self._record,self._proxy_name,self._certificate_name = _digest(record),proxy_name,certificate_name
            self._serial,self._source,self._metadata_source = expected_serial,source_digest,metadata_source_digest
            self._metadata,self._metadata_binding = metadata_probe,metadata_probe._binding
            self._guard = self._guard_pin = source_guard
            self._host,self._port,self._tls = url.hostname,url.port or 443,_ssl_context(config)
            self._tls.minimum_version = max(self._tls.minimum_version,ssl.TLSVersion.TLSv1_2)
            self._proxy_path = '/api/v2/cmdb/firewall/access-proxy/'+quote(proxy_name,safe='')+'?format=name%7Cvip%7Cclient-cert%7Capi-gateway%7Capi-gateway6'
            self._certificate_path = '/api/v2/cmdb/vpn.certificate/remote/'+quote(certificate_name,safe='')+'?format=name'
            self._routes = {GLOBAL_PATH:('system','global'),self._proxy_path:('firewall','access-proxy'),
                self._certificate_path:('vpn.certificate','remote'),CERTIFICATES_PATH:('system','available-certificates')}
            self._factory,self._http_clock,self._clock = connection_factory,http_clock,clock
            self._last_time,self._last_epoch,self._closed = -1.0,-1,False
            self._lock = RLock()
        except Exception: raise ValueError(_ERROR) from None

    def _available(self) -> None:
        if (self._closed or self._config is not self._config_pin or self._guard is None or self._guard is not self._guard_pin
                or self._guard() is not True or self._metadata._source != self._metadata_source
                or self._metadata._binding is not self._metadata_binding or not self._tls.check_hostname
                or self._tls.verify_mode != ssl.CERT_REQUIRED or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2): raise ValueError

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
        self._available(); remaining = deadline-self._now()
        if remaining <= 0: raise ValueError
        return min(self._config.timeout_seconds,remaining)

    def _get(self, path: str, deadline: float) -> bytearray:
        raw = bytearray()
        try:
            connection = response = None; raw = bytearray(); transferred = False
            try:
                if path not in self._routes: raise ValueError
                connection = self._factory(self._host,self._port,context=self._tls,timeout=self._remaining(deadline))
                connection.set_debuglevel(0); connection.connect(); handle = connection.sock
                handle.settimeout(self._remaining(deadline))
                connection.request('GET',path,headers={'Authorization':'Bearer '+self._config.bearer_token,
                    'Accept':'application/json','Accept-Encoding':'identity','Cache-Control':'no-cache,no-store','Connection':'close'})
                handle.settimeout(self._remaining(deadline)); response = connection.getresponse()
                if (type(response.status) is not int or response.status != 200
                        or response.getheader('Content-Type','').split(';',1)[0].strip().lower() != 'application/json'
                        or response.getheader('Content-Encoding','identity').lower() != 'identity'): raise ValueError
                length = response.getheader('Content-Length'); expected = None
                if length is not None:
                    if (type(length) is not str or not length.isascii() or not length.isdecimal() or len(length)>6
                            or response.getheader('Transfer-Encoding') is not None): raise ValueError
                    expected = int(length)
                    if not 0 < expected <= 131072: raise ValueError
                raw = bytearray(131073); offset = 0
                while offset < len(raw):
                    remaining = self._remaining(deadline)
                    if not response.isclosed(): handle.settimeout(remaining)
                    with memoryview(raw)[offset:] as view: count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(raw)-offset: raise ValueError
                    if not count: break
                    offset += count
                if not 0 < offset <= 131072 or expected is not None and offset != expected: raise ValueError
                raw = _take_mutable_prefix(raw, offset); self._remaining(deadline); transferred = True
                return raw
            finally:
                failed = False
                for resource in (response,connection):
                    if resource is not None:
                        try: resource.close()
                        except Exception: failed = True
                if failed or not transferred: _zeroize_mutable(raw)
                if failed: raise ValueError
        except BaseException:
            _erase_transfer_storage(raw)
            raise

    def _envelope(self, raw: bytearray, path: str) -> dict[str,tuple[int,int]]:
        left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
        if _skip_json_space(raw,right) != len(raw): raise ValueError
        metadata._validate_json(raw,left,right,depth=0,budget=[20000]); fields = _object_spans(raw,left,right)
        if not set(fields) <= _TOP: raise ValueError
        table_path,table = self._routes[path]
        for key,expected in dict(http_method='GET',http_status=200,serial=self._serial,version='v7.0.0',build=29,
                path=table_path,name=table).items():
            value = metadata._scalar(raw,fields[key])
            if type(value) is not type(expected) or value != expected: raise ValueError
        if metadata._scalar(raw,fields['status']) not in ('success','OK'): raise ValueError
        if 'vdom' in fields and metadata._scalar(raw,fields['vdom']) != 'root': raise ValueError
        if 'error' in fields:
            error = metadata._scalar(raw,fields['error'])
            if type(error) is not int or error != 0: raise ValueError
        if 'limit_reached' in fields and metadata._scalar(raw,fields['limit_reached']) is not False: raise ValueError
        return fields

    def _detail(self, raw: bytearray, path: str, names: set[str], key: str | None = None) -> dict[str,tuple[int,int]]:
        root = self._envelope(raw,path); span = root['results']
        if raw[span[0]] == 91:
            rows = metadata._array(raw,span,1)
            if len(rows) != 1: raise ValueError
            span = rows[0]
        fields = _object_spans(raw,*span)
        if not names <= set(fields) <= names | {'q_origin_key'}: raise ValueError
        if key is not None and metadata._scalar(raw,fields['name']) != key: raise ValueError
        if 'q_origin_key' in fields:
            origin = _text(metadata._scalar(raw,fields['q_origin_key']),79)
            if key is not None and origin != key: raise ValueError
        return fields

    def _proxy(self, raw: bytearray) -> dict[str,Any]:
        fields = self._detail(raw,self._proxy_path,{'name','vip','client-cert','api-gateway','api-gateway6'},self._proxy_name)
        result: dict[str,Any] = {key:_text(metadata._scalar(raw,fields[key]),79) for key in ('name','vip','client-cert')}
        if result['client-cert'] not in ('enable','disable'): raise ValueError
        for name in ('api-gateway','api-gateway6'):
            gateways = []
            for item in metadata._array(raw,fields[name],64):
                members = _object_spans(raw,*item)
                if not {'id','service'} <= set(members) <= _GATEWAY: raise ValueError
                identifier = metadata._scalar(raw,members['id'])
                if type(identifier) is not int or not 0 <= identifier <= 2147483647: raise ValueError
                gateway: dict[str,Any] = dict(id=identifier)
                for field in members.keys()-{'id','q_origin_key'}:
                    gateway[field] = _text(metadata._scalar(raw,members[field]),8192 if field == 'url-map' else 79)
                if not gateway['service'] or 'url-map' in gateway and gateway['url-map'] and not gateway['url-map'].startswith('/'): raise ValueError
                if 'q_origin_key' in members:
                    origin = metadata._scalar(raw,members['q_origin_key'])
                    if type(origin) not in (int,str) or origin not in (identifier,str(identifier)): raise ValueError
                    gateway['q_origin_key'] = origin
                gateways.append(gateway)
            if len({row['id'] for row in gateways}) != len(gateways): raise ValueError
            result[name] = gateways
        return result

    def _certificate(self, raw: bytearray) -> dict[str,Any]:
        root = self._envelope(raw,CERTIFICATES_PATH)
        rows = metadata._array(raw,root['results'],99); selected = []
        for key in ('size','matched_count'):
            if key in root:
                count = metadata._scalar(raw,root[key])
                if type(count) is not int or count != len(rows): raise ValueError
        for span in rows:
            fields = _object_spans(raw,*span)
            if not {'name','type'} <= set(fields): raise ValueError
            name = _text(metadata._scalar(raw,fields['name']),79)
            kind = _text(metadata._scalar(raw,fields['type']),79)
            if name == self._certificate_name and kind == 'remote-cer': selected.append(fields)
        if len(selected) != 1: raise ValueError
        fields = selected[0]
        fingerprint = _text(metadata._scalar(raw,fields['fingerprint']),256).replace(':','').replace(' ','').lower()
        require_digest(fingerprint,'SAML configured certificate')
        valid_from,valid_to,references = (metadata._scalar(raw,fields[key]) for key in ('valid_from','valid_to','q_ref'))
        if (type(valid_from) is not int or type(valid_to) is not int or type(references) is not int
                or not 0 <= references <= 2147483647 or not -(2**63) <= valid_from < valid_to < 2**63): raise ValueError
        return dict(name=self._certificate_name,type='remote-cer',fingerprint=fingerprint,
            valid_from=valid_from,valid_to=valid_to,q_ref=references)

    def observe(self, record_digest: str, *, timeout_seconds: float) -> SamlDependencyObservation:
        buffers: list[bytearray] = []
        try:
            with self._lock, _private_http_logs():
                self._available(); self._metadata._available()
                if (record_digest != self._record or type(timeout_seconds) not in (int,float)
                        or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30): raise ValueError
                started = self._epoch(); deadline = self._now()+min(timeout_seconds,self._config.timeout_seconds)
                def get(path: str) -> bytearray:
                    raw = self._get(path,deadline); buffers.append(raw); return raw
                raw = get(GLOBAL_PATH); fields = self._detail(raw,GLOBAL_PATH,{'saml-authentication'})
                global_status = _text(metadata._scalar(raw,fields['saml-authentication']),16)
                if global_status not in ('enable','disable'): raise ValueError
                proxy = self._proxy(get(self._proxy_path))
                raw = get(self._certificate_path); self._detail(raw,self._certificate_path,{'name'},self._certificate_name)
                certificate = self._certificate(get(CERTIFICATES_PATH))
                trust = self._metadata.observe(record_digest,timeout_seconds=self._remaining(deadline))
                now = self._epoch()
                if (type(trust) is not SamlMetadataObservation or trust.source_digest != self._metadata_source
                        or trust.record_digest != self._record or trust.binding_digest != self._metadata_binding.digest
                        or trust.signing_certificate_sha256 != certificate['fingerprint']
                        or trust.certificate_valid_from != certificate['valid_from'] or trust.certificate_expires_at != certificate['valid_to']
                        or not certificate['valid_from'] <= now < certificate['valid_to']
                        or not trust.observed_at <= now < trust.expires_at): raise ValueError
                dependencies = _digest(dict(contract=CONTRACT,serial=self._serial,global_saml=global_status,proxy=proxy,
                    certificate={key:value for key,value in certificate.items() if key != 'q_ref'},
                    metadata_source=trust.source_digest,metadata_binding=trust.binding_digest))
                result = SamlDependencyObservation(self._source,self._record,dependencies,trust.metadata_digest,
                    certificate['fingerprint'],certificate['q_ref'],True,False,False,started,min(started+10,trust.expires_at))
                self._remaining(deadline)
        except Exception: raise ValueError(_ERROR) from None
        finally:
            for raw in buffers: _zeroize_mutable(raw)
        try:
            if not result.observed_at <= self._epoch() < result.expires_at: raise ValueError
            self._remaining(deadline)
            return result
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock: self._closed = True
