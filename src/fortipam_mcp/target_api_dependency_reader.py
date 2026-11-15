"""Fixed same-Bearer dependency observations, never an execution authority."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import logging
import math
from pathlib import Path
import re
import ssl
from threading import RLock, get_ident
import time
from urllib.parse import quote, urlsplit

import httpx
from v4_planning.material_provider import _OpaqueC3Object
from . import target_lifecycle_dependencies as d
from . import secret_bulk_import_metadata as m
from . import target_preservation_contract as c
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable

_ERROR = 'Protected Target API dependency observation unavailable.'
_MONITOR = '/api/v2/monitor/web-ui/state'
_TEMPLATES = '/api/v2/cmdb/secret/template?format=name%7Cfield%7Cpermissions&with_meta=true'
_TARGET_NAMES = '/api/v2/cmdb/secret/target?format=name&with_meta=true&vdom=root'
_SCHEMA = '/api/v2/cmdb/secret/target?action=schema&with_meta=true&vdom=root'
_DETAIL = re.compile(
    r'/api/v2/cmdb/system/(?:api-user/[A-Za-z0-9](?:[A-Za-z0-9._-]|%40){0,63}'
    r'\?format=name%7Caccprofile|accprofile/[A-Za-z0-9](?:[A-Za-z0-9._-]|%40){0,63}'
    r'\?format=name%7Csecretgrp%7Csecretgrp-permission)&with_meta=true&vdom=root\Z')


@contextmanager
def _private_http_logs() -> Iterator[None]:
    # HTTPX logs URLs and HTTPCore debug traces can contain response headers.
    # Suppress only this synchronous operation's thread; preserve other filters.
    thread = get_ident()
    class PrivateOperation(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return record.thread != thread
    guard = PrivateOperation()
    loggers = [logging.getLogger(name) for name in (
        'httpx', 'httpcore.connection', 'httpcore.http11', 'httpcore.http2',
        'httpcore.proxy', 'httpcore.socks')]
    try:
        for logger in loggers:
            logger.addFilter(guard)
        yield
    finally:
        for logger in loggers:
            logger.removeFilter(guard)


class TargetApiDependencyReadError(ValueError):
    """Fixed non-disclosing failure; no partial observation is returned."""


@dataclass(frozen=True, slots=True, repr=False)
class TargetApiDependencyObservation(_OpaqueC3Object):
    dependencies: d.TargetLifecycleDependencies
    source_context_digest: str
    observed_at: float
    expires_at: float


@dataclass(frozen=True, slots=True, repr=False)
class TargetApiNamesObservation(_OpaqueC3Object):
    names: tuple[str, ...]
    source_context_digest: str
    names_digest: str
    observed_at: float
    expires_at: float


def _project_names(content: bytearray, serial_digest: str) -> tuple[str, ...]:
    # Decode only compiled envelope fields and row names, never configured values.
    from .target_qualified_namespace_reader import _names
    fields = d._spans(content)
    d._equal(content, fields, {'version': 'v7.0.0', 'build': 29, 'path': 'secret',
        'name': 'target', 'http_method': 'POST', 'status': 'OK', 'http_status': 200,
        'vdom': 'root'})
    serial = m._text(m._scalar(content, fields['serial']), maximum=128)
    if hashlib.sha256(serial.encode()).hexdigest() != serial_digest:
        raise ValueError
    if 'error' in fields and bytes(content[slice(*fields['error'])]) not in (b'0', b'null'):
        raise ValueError
    if 'limit_reached' in fields and bytes(content[slice(*fields['limit_reached'])]) != b'false':
        raise ValueError
    rows = m._array(content, fields['results'], 128)
    if 'size' in fields:
        size = m._scalar(content, fields['size'])
        if type(size) is not int or size != len(rows):
            raise ValueError
    names = _names(tuple(m._text(m._scalar(content,
        m._object_spans(content, *row, frozenset({'name'}))['name'])) for row in rows))
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError
    return tuple(sorted(names))


class TargetApiDependencyReader(_OpaqueC3Object):
    """Read-only fixed routes; trusted composition supplies the writer config.

    The POST uses the native GET override and a fixed empty filter, never a
    configuration body. A later write still needs independent M4, ownership,
    current-state and postcondition checks. No runtime Tool is registered.
    """

    def __init__(self, config: SecretMetadataHttpTransportConfig, *, serial_digest: str,
                 clock: Callable[[], float] = time.monotonic,
                 client_factory: Callable[..., httpx.Client] = httpx.Client) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                or type(serial_digest) is not str or c._DIGEST.fullmatch(serial_digest) is None):
                raise ValueError
            config.__post_init__()
            url = urlsplit(config.base_url)
            if not url.hostname or url.username is not None or url.password is not None:
                raise ValueError
            ca_digest = None
            if config.ca_file is None:
                context = ssl.create_default_context()
            else:
                with Path(config.ca_file).open('rb') as stream:
                    ca = stream.read(1048577)
                if not 0 < len(ca) <= 1048576:
                    raise ValueError
                ca_digest = hashlib.sha256(ca).hexdigest()
                context = ssl.create_default_context(cadata=ca.decode('ascii'))
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._config = config
            self._context = context
            self._serial = serial_digest
            self._source = c._api_source_context(config.base_url,
                hashlib.sha256(config.bearer_token.encode()).hexdigest(), ca_digest, serial_digest)
            self._clock = clock
            self._factory = client_factory
            self._lock = RLock()
            self._closed = False
            self._failed_clock = False
            self._last_time: float | None = None
            self._current: TargetApiDependencyObservation | None = None
            self._names_current: TargetApiNamesObservation | None = None
            self._names_parent: TargetApiDependencyObservation | None = None
        except Exception:
            raise TargetApiDependencyReadError(_ERROR) from None

    def _now(self) -> float:
        try:
            value = self._clock()
            if (type(value) not in (float, int) or not math.isfinite(value) or value < 0
                or self._failed_clock or self._closed
                or self._last_time is not None and value < self._last_time):
                raise ValueError
            self._last_time = float(value)
            return float(value)
        except Exception:
            self._failed_clock = True
            raise TargetApiDependencyReadError(_ERROR) from None

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._now()
        if remaining <= 0:
            raise TargetApiDependencyReadError(_ERROR)
        return min(10.0, float(self._config.timeout_seconds), remaining)

    def _receive(self, client: httpx.Client, path: str, deadline: float,
                 *, template: bool = False, target_names: bool = False,
                 target_name: str | None = None) -> bytearray:
        content = bytearray()
        transfer = False
        try:
            target_detail = None
            if target_name is not None:
                m._text(target_name, maximum=79)
                if target_name in {'.', '..'} or any(char in target_name for char in '/\\?#'):
                    raise ValueError
                target_detail = '/api/v2/cmdb/secret/target/' + quote(target_name, safe='') + '?with_meta=true&vdom=root'
                if path != target_detail or template or target_names:
                    raise ValueError
            if (type(template) is not bool or type(target_names) is not bool
                or template != (path == _TEMPLATES) or target_names != (path == _TARGET_NAMES)
                or path not in (_MONITOR, _TEMPLATES, _SCHEMA, _TARGET_NAMES, target_detail)
                and _DETAIL.fullmatch(path) is None):
                raise ValueError
            headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity',
                       'Authorization': 'Bearer ' + self._config.bearer_token}
            if template or target_names:
                headers.update({'X-HTTP-Method-Override': 'GET', 'Content-Type': 'application/json'})
            timeout = self._remaining(deadline)
            with client.stream('POST' if template or target_names else 'GET', self._config.base_url.rstrip('/') + path,
                    headers=headers, content=b'{"json_filter":[]}' if template or target_names else None,
                    timeout=timeout) as response:
                self._remaining(deadline)
                if (response.status_code != 200
                    or response.headers.get('content-type', '').split(';')[0].lower() != 'application/json'
                    or response.headers.get('content-encoding', 'identity') not in ('', 'identity')):
                    raise ValueError
                iterator = response.iter_raw()
                while True:
                    self._remaining(deadline)
                    try:
                        chunk = next(iterator)
                    except StopIteration:
                        self._remaining(deadline)
                        break
                    self._remaining(deadline)
                    if len(content) + len(chunk) > m._MAX_BYTES:
                        raise ValueError
                    content.extend(chunk)
                self._remaining(deadline)
            self._remaining(deadline)
            transfer = True
            return content
        finally:
            if not transfer:
                _zeroize_mutable(content)

    def read_target_state(self, baseline: c.TargetState, observation: TargetApiDependencyObservation,
                          *, before_send: Callable[[], None]) -> c.TargetState:
        """Read one bound existing Target; retain only coordinates and full-state digests."""
        with self._lock:
            content = bytearray()
            try:
                c._checked_state(baseline)
                self.check_current(observation)
                if baseline.serial_digest != self._serial or not callable(before_send):
                    raise ValueError
                path = '/api/v2/cmdb/secret/target/' + quote(baseline.name, safe='') + '?with_meta=true&vdom=root'
                before_send()
                self.check_current(observation)
                with _private_http_logs(), self._factory(verify=self._context,
                        timeout=min(10.0, self._config.timeout_seconds),
                        follow_redirects=False, trust_env=False) as client:
                    content = self._receive(client, path, observation.expires_at, target_name=baseline.name)
                current = c.capture_target_state(content, expected_name=baseline.name,
                    expected_serial_digest=baseline.serial_digest)
                before_send()
                self.check_current(observation)
                return current
            except Exception:
                self._current = None
                raise TargetApiDependencyReadError(_ERROR) from None
            finally:
                _zeroize_mutable(content)

    def observe(self, coordinates: tuple[c.TargetCoordinates, ...]) -> TargetApiDependencyObservation:
        with self._lock:
            buffers: list[bytearray] = []
            self._current = None
            try:
                if type(coordinates) is not tuple or not 1 <= len(coordinates) <= 2:
                    raise ValueError
                for coordinate in coordinates:
                    if type(coordinate) is not c.TargetCoordinates:
                        raise ValueError
                    coordinate.__post_init__()
                started = self._now()
                deadline = started + min(60.0, float(self._config.timeout_seconds))
                with _private_http_logs(), self._factory(verify=self._context, timeout=min(10.0, self._config.timeout_seconds),
                        follow_redirects=False, trust_env=False) as client:
                    def fetch(path: str, *, template: bool = False, target_names: bool = False) -> bytearray:
                        value = self._receive(client, path, deadline, template=template)
                        buffers.append(value)
                        return value
                    actor = fetch(_MONITOR)
                    span = d._envelope(actor, path='web-ui', name='state', serial_digest=self._serial, monitor=True)
                    fields = m._object_spans(actor, *span, frozenset({'admin'}))
                    identity = m._object_spans(actor, *fields['admin'], frozenset({'name'}))
                    name = m._text(m._scalar(actor, identity['name']), maximum=64)
                    if d._API_NAME.fullmatch(name) is None:
                        raise ValueError
                    api_path = '/api/v2/cmdb/system/api-user/' + quote(name, safe='') + '?format=name%7Caccprofile&with_meta=true&vdom=root'
                    api = fetch(api_path)
                    span = d._one(api, d._envelope(api, path='system', name='api-user', serial_digest=self._serial))
                    fields = m._object_spans(api, *span, frozenset({'name', 'accprofile'}))
                    d._equal(api, fields, {'name': name})
                    profile = m._text(m._scalar(api, fields['accprofile']), maximum=64)
                    if d._API_NAME.fullmatch(profile) is None:
                        raise ValueError
                    profile_path = '/api/v2/cmdb/system/accprofile/' + quote(profile, safe='') + '?format=name%7Csecretgrp%7Csecretgrp-permission&with_meta=true&vdom=root'
                    fetch(profile_path)
                    fetch(_TEMPLATES, template=True)
                    fetch(_SCHEMA)
                    fetch(profile_path)
                    fetch(api_path)
                    fetch(_MONITOR)
                    dependencies = d.qualify_target_api_lifecycle_dependencies(*buffers,
                        expected_actor=name, expected_serial_digest=self._serial, coordinates=coordinates)
                    self._remaining(deadline)
                self._remaining(deadline)
                observed = TargetApiDependencyObservation(dependencies, self._source, started, deadline)
                self._current = observed
                return observed
            except Exception:
                raise TargetApiDependencyReadError(_ERROR) from None
            finally:
                for buffer in buffers:
                    _zeroize_mutable(buffer)

    def observe_names(self, dependency: TargetApiDependencyObservation) -> TargetApiNamesObservation:
        """Private API witnesses only; neither global absence nor write authority."""
        with self._lock:
            self._names_current = None
            self._names_parent = None
            buffers: list[bytearray] = []
            try:
                self.check_current(dependency)
                started = self._now()
                deadline = dependency.expires_at
                with _private_http_logs(), self._factory(verify=self._context,
                        timeout=self._remaining(deadline), follow_redirects=False, trust_env=False) as client:
                    for _ in range(2):
                        self.check_current(dependency)
                        buffers.append(self._receive(client, _TARGET_NAMES, deadline, target_names=True))
                    first = _project_names(buffers[0], self._serial)
                    if first != _project_names(buffers[1], self._serial):
                        raise ValueError
                    self.check_current(dependency)
                self.check_current(dependency)
                observed = TargetApiNamesObservation(first, self._source,
                    c._digest(tuple(sorted(first))), started, deadline)
                self._names_parent = dependency
                self._names_current = observed
                return observed
            except Exception:
                raise TargetApiDependencyReadError(_ERROR) from None
            finally:
                for buffer in buffers:
                    _zeroize_mutable(buffer)

    def check_names_current(self, observation: TargetApiNamesObservation) -> None:
        with self._lock:
            try:
                if (type(observation) is not TargetApiNamesObservation
                    or observation is not self._names_current or self._names_parent is None):
                    raise ValueError
                self.check_current(self._names_parent)
                if not observation.observed_at <= self._now() < observation.expires_at:
                    raise ValueError
            except Exception:
                raise TargetApiDependencyReadError(_ERROR) from None

    def check_current(self, observation: TargetApiDependencyObservation) -> None:
        """Reject expired, superseded, failed-read, foreign or closed observations."""
        with self._lock:
            try:
                if type(observation) is not TargetApiDependencyObservation or observation is not self._current:
                    raise ValueError
                if not observation.observed_at <= self._now() < observation.expires_at:
                    raise ValueError
            except Exception:
                raise TargetApiDependencyReadError(_ERROR) from None

    def check_transport_source(self, observation: TargetApiDependencyObservation,
                               transport: object) -> None:
        """Check fresh source equivalence only, not ownership or write authority.

        Explicit CA snapshots are required: a system-trust selection alone does
        not establish identical loaded trust stores across separate constructors.
        The trusted caller must run this again at its dispatch-time guard.
        """
        from .target_creation_http_transport import TargetCreationHttpTransport
        from .target_preservation_http_transport import TargetCoordinateHttpTransport
        with self._lock:
            try:
                self.check_current(observation)
                if type(transport) not in (TargetCreationHttpTransport, TargetCoordinateHttpTransport):
                    raise ValueError
                if not isinstance(transport, (TargetCreationHttpTransport, TargetCoordinateHttpTransport)):
                    raise ValueError
                if (transport._source_context_digest is None
                    or transport._source_context_digest != self._source
                    or observation.source_context_digest != self._source):
                    raise ValueError
            except Exception:
                raise TargetApiDependencyReadError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None
            self._names_current = None
            self._names_parent = None
