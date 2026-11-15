"""Prebound credential-free SAML metadata/leaf signing-certificate observation.

This optional local candidate requires the saml-metadata extra. A metadata
match cannot qualify device certificate provenance, XML signatures, IdP login,
global/proxy isolation or independent recovery. Normal startup never binds it.
"""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.client
import math
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import urlsplit
from xml.parsers import expat

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .mutable_json_buffer import _take_mutable_prefix
from .saml_server_contract import _Private, _digest, _source
from .secret_metadata_http_transport import _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam_saml_prebound_idp_metadata_local_v1'
_MD = '{urn:oasis:names:tc:SAML:2.0:metadata}'
_DS = '{http://www.w3.org/2000/09/xmldsig#}'
_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol'
_HTTP_BINDINGS = {_PROTOCOL.replace(':protocol',':bindings:HTTP-POST'),
    _PROTOCOL.replace(':protocol',':bindings:HTTP-Redirect')}
_ERROR = 'The private SAML metadata trust observation is unavailable.'


class SamlMetadataBinding(_Private):
    """An owner-side source record, explicit metadata URL and public-cert pin."""
    __slots__ = ('record_digest','signing_certificate_sha256','_url','_expected','digest')
    record_digest: str
    signing_certificate_sha256: str
    _url: str
    _expected: tuple[str,str,str]
    digest: str

    def __init__(self, source_record: Mapping[str,object], *, metadata_url: str, signing_certificate_sha256: str) -> None:
        try:
            record = _source(source_record); require_digest(signing_certificate_sha256,'SAML signing certificate')
            url = urlsplit(metadata_url)
            if (type(metadata_url) is not str or not 1 <= len(metadata_url) <= 2048 or url.scheme != 'https'
                    or not url.hostname or url.username is not None or url.password is not None or url.query or url.fragment
                    or '\\' in metadata_url or any(c.isspace() for c in metadata_url)): raise ValueError
            if url.port is not None and not 1 <= url.port <= 65535: raise ValueError
            expected = tuple(record[key] for key in ('idp-entity-id','idp-single-sign-on-url','idp-single-logout-url'))
            if any(type(value) is not str for value in expected): raise ValueError
            for key,value in dict(record_digest=_digest(record),signing_certificate_sha256=signing_certificate_sha256,
                    _url=metadata_url,_expected=expected,digest=_digest(dict(contract=CONTRACT,record=_digest(record),
                        metadata_url=metadata_url,certificate=signing_certificate_sha256))).items():
                object.__setattr__(self,key,value)
        except Exception: raise ValueError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class SamlMetadataObservation(_OpaqueC3Object):
    source_digest: str
    record_digest: str
    binding_digest: str
    metadata_digest: str
    signing_certificate_sha256: str
    authn_requests_signature_required: bool
    certificate_valid_from: int
    certificate_expires_at: int
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.record_digest,self.binding_digest,self.metadata_digest,
                self.signing_certificate_sha256): require_digest(value,'SAML metadata observation')
        if (type(self.authn_requests_signature_required) is not bool
                or any(type(value) is not int for value in (self.certificate_valid_from,self.certificate_expires_at,self.observed_at,self.expires_at))
                or not self.certificate_valid_from <= self.observed_at
                or not 0 <= self.observed_at < self.expires_at <= min(self.observed_at+10,self.certificate_expires_at)): raise ValueError

    def summary(self) -> dict[str,object]:
        return dict(contract=CONTRACT,metadata_projection_kind='entity_endpoints_signing_certificates',
            configured_entity_and_endpoints_listed=True,prebound_signing_certificate_pin_matched=True,
            authn_requests_signature_required=self.authn_requests_signature_required,
            native_certificate_source_verified=False,metadata_signature_verified=False,saml_login_verified=False,
            runtime_isolation_verified=False,independent_recovery_ready=False)


def _listed_endpoints(descriptor: Any, kind: str, expected: str) -> list[tuple[str,str,str | None]]:
    endpoints = []
    for element in descriptor.findall(_MD+kind):
        address,binding = element.get('Location'),element.get('Binding')
        if type(address) is not str or type(binding) is not str or not 1 <= len(binding) <= 1024: raise ValueError
        url = urlsplit(address)
        if (not 1 <= len(address) <= 8192 or url.scheme != 'https' or not url.hostname or url.username is not None
                or url.password is not None or url.fragment or any(c.isspace() for c in address)): raise ValueError
        _ = url.port
        response_address = element.get('ResponseLocation')
        if response_address is not None:
            if kind == 'SingleSignOnService': raise ValueError
            response_url = urlsplit(response_address)
            if (not 1 <= len(response_address) <= 8192 or response_url.scheme != 'https' or not response_url.hostname
                    or response_url.username is not None or response_url.password is not None or response_url.fragment
                    or any(c.isspace() for c in response_address)): raise ValueError
            _ = response_url.port
        endpoints.append((binding,address,response_address))
    if (not 1 <= len(endpoints) <= 8 or not any(address == expected and binding in _HTTP_BINDINGS for binding,address,_ in endpoints)):
        raise ValueError
    return sorted(endpoints,key=lambda item:(item[0],item[1],item[2] or ''))


def _project(raw: bytearray, binding: SamlMetadataBinding, parse: Callable[...,Any], now: int) -> tuple[str,int,int,int,bool]:
    root = parse(raw,forbid_dtd=True,forbid_entities=True,forbid_external=True)
    pending = [(root,1)]; count = 0
    while pending:
        element,depth = pending.pop(); count += 1
        if count > 512 or depth > 16 or len(element.attrib) > 16: raise ValueError
        pending.extend((child,depth+1) for child in element)
    if root.tag != _MD+'EntityDescriptor' or root.get('entityID') != binding._expected[0]: raise ValueError
    descriptors = root.findall(_MD+'IDPSSODescriptor')
    if len(descriptors) != 1 or _PROTOCOL not in descriptors[0].get('protocolSupportEnumeration','').split(): raise ValueError
    descriptor = descriptors[0]
    wants_signed = descriptor.get('WantAuthnRequestsSigned','false')
    if wants_signed not in ('true','false','1','0'): raise ValueError
    metadata_expires = now+10
    for element in (root,descriptor):
        value = element.get('validUntil')
        if value is not None:
            instant = datetime.fromisoformat(value.replace('Z','+00:00'))
            if instant.tzinfo is None: raise ValueError
            metadata_expires = min(metadata_expires,int(instant.timestamp()))
    sso = _listed_endpoints(descriptor,'SingleSignOnService',binding._expected[1])
    slo = _listed_endpoints(descriptor,'SingleLogoutService',binding._expected[2])
    certificates = []
    for key in descriptor.findall(_MD+'KeyDescriptor'):
        if key.get('use') not in (None,'signing'): continue
        for item in key.findall(_DS+'KeyInfo/'+_DS+'X509Data/'+_DS+'X509Certificate'):
            if len(item): raise ValueError
            encoded = ''.join((item.text or '').split())
            if not 1 <= len(encoded) <= 16384: raise ValueError
            der = base64.b64decode(encoded.encode('ascii'),validate=True)
            certificate = x509.load_der_x509_certificate(der)
            if certificate.public_bytes(Encoding.DER) != der: raise ValueError
            certificates.append((hashlib.sha256(der).hexdigest(),certificate))
    if not 1 <= len(certificates) <= 4: raise ValueError
    matches = [certificate for digest,certificate in certificates if digest == binding.signing_certificate_sha256]
    if len(matches) != 1: raise ValueError
    selected = matches[0]; current = datetime.fromtimestamp(now,timezone.utc)
    if not selected.not_valid_before_utc <= current < selected.not_valid_after_utc: raise ValueError
    certificate_expires = int(selected.not_valid_after_utc.timestamp())
    expires = min(metadata_expires,certificate_expires)
    if now >= expires: raise ValueError
    # Only the selected public metadata projection is fingerprinted. Unknown
    # extensions, contact data, signatures and raw XML never enter the digest.
    fingerprint = _digest(dict(contract=CONTRACT,binding=binding.digest,entity=binding._expected[0],sso=sso,slo=slo,
        protocol_support=sorted(descriptor.get('protocolSupportEnumeration').split()),
        wants_signed=wants_signed in ('true','1'),entity_valid_until=root.get('validUntil'),role_valid_until=descriptor.get('validUntil'),
        signing_certificates=sorted(digest for digest,_ in certificates)))
    return fingerprint,int(selected.not_valid_before_utc.timestamp()),certificate_expires,expires,wants_signed in ('true','1')


class SamlIdpMetadataProbe(_OpaqueC3Object):
    def __init__(self, binding: SamlMetadataBinding, *, source_digest: str, ca_file: str | None = None,
            enabled: bool = False, source_guard: Callable[[],bool] | None = None,
            connection_factory: Callable[...,Any] = http.client.HTTPSConnection,
            http_clock: Callable[[],float] = time.monotonic, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(binding) is not SamlMetadataBinding or type(enabled) is not bool
                    or source_guard is not None and not callable(source_guard)
                    or not callable(connection_factory) or not callable(http_clock) or not callable(clock)): raise ValueError
            require_digest(source_digest,'SAML metadata source')
            self._parse: Callable[...,Any] | None = None
            if enabled:
                from defusedxml.ElementTree import fromstring  # type: ignore[import-untyped]
                self._parse = fromstring
            self._binding,self._source = binding,source_digest
            self._enabled,self._guard,self._guard_pin = enabled,source_guard,source_guard
            url = urlsplit(binding._url)
            self._host,self._port,self._path = url.hostname,url.port or 443,url.path or '/'
            self._tls = ssl.create_default_context(cafile=ca_file); self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self._factory,self._http_clock,self._clock = connection_factory,http_clock,clock
            self._last_time,self._last_epoch,self._closed = -1.0,-1,False
            self._lock = RLock()
        except Exception: raise ValueError(_ERROR) from None

    def _available(self) -> None:
        if (self._closed or not self._enabled or self._parse is None or self._guard is None or self._guard is not self._guard_pin
                or self._guard() is not True or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2 or expat.version_info < (2,6,0)
                or not hasattr(x509.Certificate,'not_valid_before_utc')): raise ValueError

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
        return remaining

    def observe(self, record_digest: str, *, timeout_seconds: float) -> SamlMetadataObservation:
        connection = response = None; raw = bytearray()
        try:
            with self._lock, _private_http_logs():
                self._available()
                if (record_digest != self._binding.record_digest or type(timeout_seconds) not in (int,float)
                        or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30): raise ValueError
                self._epoch(); deadline = self._now()+timeout_seconds
                connection = self._factory(self._host,self._port,context=self._tls,timeout=self._remaining(deadline))
                connection.set_debuglevel(0); connection.connect(); handle = connection.sock
                handle.settimeout(self._remaining(deadline))
                connection.request('GET',self._path,headers={'Accept':'application/samlmetadata+xml, application/xml, text/xml',
                    'Accept-Encoding':'identity','Cache-Control':'no-cache,no-store','Connection':'close'})
                handle.settimeout(self._remaining(deadline)); response = connection.getresponse()
                if (type(response.status) is not int or response.status != 200
                        or response.getheader('Content-Type','').split(';',1)[0].strip().lower() not in
                            ('application/samlmetadata+xml','application/xml','text/xml')
                        or response.getheader('Content-Encoding','identity').lower() != 'identity'): raise ValueError
                length = response.getheader('Content-Length'); expected = None
                if length is not None:
                    if (type(length) is not str or not length.isascii() or not length.isdecimal() or len(length)>6
                            or response.getheader('Transfer-Encoding') is not None): raise ValueError
                    expected = int(length)
                    if not 0 < expected <= 65536: raise ValueError
                raw = bytearray(65537); offset = 0
                while offset < len(raw):
                    remaining = self._remaining(deadline)
                    if not response.isclosed(): handle.settimeout(remaining)
                    with memoryview(raw)[offset:] as view: count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(raw)-offset: raise ValueError
                    if not count: break
                    offset += count
                if not 0 < offset <= 65536 or expected is not None and offset != expected: raise ValueError
                raw = _take_mutable_prefix(raw, offset); now = self._epoch()
                if self._parse is None: raise ValueError
                fingerprint,certificate_from,certificate_expires,expires,wants_signed = _project(raw,self._binding,self._parse,now)
                self._remaining(deadline)
                result = SamlMetadataObservation(self._source,self._binding.record_digest,self._binding.digest,fingerprint,
                    self._binding.signing_certificate_sha256,wants_signed,certificate_from,certificate_expires,now,expires)
        except Exception: raise ValueError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
            failed = False
            for resource in (response,connection):
                if resource is not None:
                    try: resource.close()
                    except Exception: failed = True
            if failed: raise ValueError(_ERROR) from None
        try:
            if not result.observed_at <= self._epoch() < result.expires_at: raise ValueError
            self._remaining(deadline)
            return result
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock: self._closed = True
