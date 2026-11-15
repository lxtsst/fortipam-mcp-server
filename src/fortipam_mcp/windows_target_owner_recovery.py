"""Default-off Owner recovery bridge for an originally sealed Windows Target.

The owning creator/lifecycle supplies the durable original-ACK claim, independent
M4 authorization and drift/reference guards. This private bridge supplies only
the fixed CSRF transport and a privileged Owner/global namespace absence read.
It cannot adopt an unknown creation or register a callable runtime action.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hashlib
import http.client
from http.cookies import SimpleCookie
import os
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlsplit

import httpx

from . import secret_bulk_import_metadata as m
from . import target_creation_evidence as e
from . import target_preservation_contract as c
from .local_user_reset_fixture_preflight import _actor_context
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, _ssl_context, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .target_lifecycle_dependencies import _envelope, _one
from .target_namespace_preflight import TargetNamespacePreflight
from .windows_target_owner_source import WindowsTargetOwnerSource

if TYPE_CHECKING:
    from .target_creation_http_transport import TargetCreationHttpTransport

_CONTRACT = 'fortipam-build29-windows-target-owner-recovery-v1'
_ERROR = 'Protected Windows Target Owner recovery unavailable.'
_ADMIN_FIELDS = frozenset({'name', 'accprofile', 'status', 'remote-auth', 'wildcard'})
_LIMIT = 2 * 1048576


class WindowsTargetOwnerRecoveryError(ValueError):
    """No raw values or partial mutable result in failures."""


class WindowsTargetOwnerRecovery:
    """One fixed DELETE; source readers and credentials remain privately bound."""

    def __init__(self, creator: TargetCreationHttpTransport, namespace: TargetNamespacePreflight, *,
                 execution_enabled: bool = False,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection) -> None:
        try:
            from .target_creation_http_transport import TargetCreationHttpTransport
            if (type(creator) is not TargetCreationHttpTransport
                or type(namespace) is not TargetNamespacePreflight
                or type(creator._owner_read_source) is not WindowsTargetOwnerSource
                or type(execution_enabled) is not bool or not callable(connection_factory)
                or namespace._source != creator._source_context_digest
                or namespace._api._config is not creator._config):
                raise ValueError
            self._creator, self._source, self._namespace = creator, creator._owner_read_source, namespace
            self._original = creator.load_creation_evidence()
            if self._original.created.coordinates.template != 'Windows Machine':
                raise ValueError
            self._ssh = namespace._namespace._ssh._config
            if (self._ssh.username != self._source._owner
                or namespace._serial != self._original.created.serial_digest):
                raise ValueError
            self._ssh_pin = self._ssh_context()
            self._context = self._source.check_binding(creator._config,
                target_name=self._original.created.name, serial_digest=self._original.created.serial_digest)
            self.binding_digest = c._digest((_CONTRACT, creator._namespace, self._context,
                self._original.evidence_digest, namespace._source, self._ssh_pin))
            self.expected_digest = c._digest((_CONTRACT, 'owner-and-global-absence', self.binding_digest))
            self._enabled, self._closed, self._dispatched = execution_enabled, False, False
            self._factory, self._lock = connection_factory, RLock()
            self._active_session: OwnerSessionMetadataTransport | None = None
            self.role_digest: str | None = None
            self.logout_verified = False
        except Exception:
            raise WindowsTargetOwnerRecoveryError(_ERROR) from None

    def _ssh_context(self) -> str:
        self._ssh.__post_init__()
        return c._digest((self._ssh.host, self._ssh.port, self._ssh.username,
            hashlib.sha256(Path(self._ssh.known_hosts_file).read_bytes()).hexdigest()))

    def check_binding(self, creator: TargetCreationHttpTransport, evidence: e.TargetCreationEvidence,
                      current: c.TargetState) -> str:
        if (self._closed or creator is not self._creator or evidence != self._original
            or current != evidence.created or self._ssh_context() != self._ssh_pin
            or self._namespace._source != creator._source_context_digest
            or self._namespace._api._config is not creator._config
            or self._source.check_binding(creator._config, target_name=current.name,
                serial_digest=current.serial_digest) != self._context):
            raise WindowsTargetOwnerRecoveryError(_ERROR)
        return self.binding_digest

    def _guard(self, deadline: int, callback: Callable[[], None]) -> float:
        self.check_binding(self._creator, self._original, self._original.created)
        callback()
        self.check_binding(self._creator, self._original, self._original.created)
        remaining = deadline - self._creator._now()
        if type(deadline) is not int or not 0 < remaining <= 60:
            raise WindowsTargetOwnerRecoveryError(_ERROR)
        return min(float(self._creator._config.timeout_seconds), float(remaining))

    def _get(self, session: OwnerSessionMetadataTransport, path: str, deadline: int,
             guard: Callable[[], None], *, absent: bool = False) -> bytearray:
        raw = bytearray()
        try:
            if session._client is None or session._clock() >= session._expires_at:
                raise ValueError
            with session._client.stream('GET', path, timeout=self._guard(deadline, guard), headers={
                'Accept':'application/json', 'Accept-Encoding':'identity', 'Cache-Control':'no-store'}) as response:
                self._guard(deadline, guard)
                if (response.status_code != (404 if absent else 200)
                    or response.headers.get('content-type', '').split(';')[0] != 'application/json'
                    or response.headers.get('content-encoding', 'identity') not in ('', 'identity')):
                    raise ValueError
                for part in response.iter_raw():
                    self._guard(deadline, guard)
                    if len(raw) + len(part) > _LIMIT:
                        raise ValueError
                    raw.extend(part)
            self._guard(deadline, guard)
            result, raw = raw, bytearray()
            return result
        finally:
            _zeroize_mutable(raw)

    def _role(self, session: OwnerSessionMetadataTransport, deadline: int, guard: Callable[[], None]) -> str:
        raw = self._get(session, '/api/v2/monitor/web-ui/state', deadline, guard)
        try:
            actor = _actor_context(raw, expected_name=self._source._owner)
            span = _envelope(raw, path='web-ui', name='state', serial_digest=self._source._serial, monitor=True)
            fields = m._object_spans(raw, *span, frozenset({'admin'}))
            admin = m._object_spans(raw, *fields['admin'], frozenset({'super_admin', 'global_admin', 'profile'}))
            for key in ('super_admin', 'global_admin'):
                value = m._scalar(raw, admin[key])
                if type(value) is not bool or value is not True:
                    raise ValueError
            profile = m._object_spans(raw, *admin['profile'], frozenset({'name'}))
            if m._scalar(raw, profile['name']) != 'super_admin':
                raise ValueError
        finally:
            _zeroize_mutable(raw)
        raw = self._get(session, '/api/v2/cmdb/system/admin/' + quote(self._source._owner, safe='') +
            '?format=' + quote('|'.join(sorted(_ADMIN_FIELDS)), safe='') + '&with_meta=true&vdom=root', deadline, guard)
        try:
            row = _one(raw, _envelope(raw, path='system', name='admin', serial_digest=self._source._serial))
            fields = m._object_spans(raw, *row, _ADMIN_FIELDS)
            expected = {'name':self._source._owner, 'accprofile':'super_admin', 'status':'enable',
                'remote-auth':'disable', 'wildcard':'disable'}
            for key, value in expected.items():
                if m._scalar(raw, fields[key]) != value:
                    raise ValueError
            return c._digest((_CONTRACT, actor, expected, 'native-super-global-admin'))
        finally:
            _zeroize_mutable(raw)

    @contextmanager
    def _session(self, deadline: int, guard: Callable[[], None]) -> Iterator[OwnerSessionMetadataTransport]:
        self.logout_verified = False
        self._guard(deadline, guard)
        source = self._source
        session = OwnerSessionMetadataTransport(self._creator._config, owner_name=source._owner,
            credentials=source._credentials, folder_path='windows-target-recovery', secret_name='windows-target-recovery',
            target_name=source._name, witness=FortiPamSecretMetadataHttpTransport(self._creator._config),
            client_factory=source._factory)
        try:
            with _private_http_logs(), session.authenticated():
                before = self._role(session, deadline, guard)
                if self.role_digest is not None and self.role_digest != before:
                    raise ValueError
                yield session
                if self._role(session, deadline, guard) != before:
                    raise ValueError
            if not session.logout_verified:
                raise ValueError
            self._guard(deadline, guard)
            self.role_digest = before
        finally:
            self.logout_verified = session.logout_verified

    def inspect(self, *, expires_at: int, before_send: Callable[[], None]) -> str:
        try:
            with self._lock, self._session(expires_at, before_send):
                pass
            if self.role_digest is None:
                raise ValueError
            return self.role_digest
        except Exception:
            raise WindowsTargetOwnerRecoveryError(_ERROR) from None

    def read_current_for_dispatch(self, *, expires_at: int, before_send: Callable[[], None]) -> c.TargetState:
        """Reuse the dispatch session for the core's last state/reference guard."""
        raw = bytearray()
        try:
            if not self._enabled or self._active_session is None or not self._dispatched:
                raise ValueError
            raw = self._get(self._active_session, '/api/v2/cmdb/secret/target/' + quote(self._source._name, safe='') +
                '?with_meta=true&vdom=root', expires_at, before_send)
            return c.capture_target_state(raw, expected_name=self._source._name,
                expected_serial_digest=self._source._serial)
        except Exception:
            raise WindowsTargetOwnerRecoveryError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)

    def dispatch(self, *, directory: int, claim: dict[str, object], expires_at: int,
                 before_read: Callable[[], None], before_delete: Callable[[], None]) -> bytearray:
        raw = bytearray(); connection = response = None
        try:
            with self._lock:
                if not self._enabled or self._dispatched or self.role_digest is None:
                    raise ValueError
                info = os.fstat(directory)
                if ((info.st_dev, info.st_ino) != self._creator._identity
                    or self._creator._read(directory, 'delete.claim.json') != claim
                    or claim.get('namespace') != self._creator._namespace
                    or claim.get('creation_evidence_digest') != self._original.evidence_digest
                    or claim.get('current_digest') != self._original.created.state_digest):
                    raise ValueError
                self._dispatched = True
                path = '/api/v2/cmdb/secret/target/' + quote(self._source._name, safe='')
                with self._session(expires_at, before_read) as session:
                    self._active_session = session
                    if self.read_current_for_dispatch(expires_at=expires_at, before_send=before_read) != self._original.created:
                        raise ValueError
                    cookie = session._client.build_request('GET', path).headers.get('cookie', '')
                    parsed = SimpleCookie(); parsed.load(cookie)
                    token = parsed.get('ccsrftoken')
                    if token is None or not 0 < len(token.value) <= 4096 or any(not 33 <= ord(ch) <= 126 for ch in token.value):
                        raise ValueError
                    config = self._creator._config; origin = urlsplit(config.base_url)
                    connection = self._factory(origin.hostname, origin.port or 443,
                        timeout=self._guard(expires_at, before_read), context=_ssl_context(config))
                    connection.connect()
                    self._guard(expires_at, before_delete)
                    if self._role(session, expires_at, before_read) != self.role_digest:
                        raise ValueError
                    if not self._enabled or not self._creator._recovery_enabled:
                        raise ValueError
                    connection.timeout = self._guard(expires_at, before_read)
                    if getattr(connection, 'sock', None) is not None:
                        connection.sock.settimeout(connection.timeout)
                    connection.request('DELETE', path, None, {'Cookie':cookie, 'X-CSRFTOKEN':token.value,
                        'Content-Length':'0', 'Accept':'application/json', 'Accept-Encoding':'identity', 'Connection':'close'})
                    response = connection.getresponse()
                    self._creator._observe_native_response(directory,'delete',claim,response)
                    if (response.status != 200 or 'json' not in response.getheader('Content-Type', '').lower()
                        or response.getheader('Content-Encoding', 'identity') not in ('', 'identity')):
                        raise ValueError
                    while True:
                        remaining = self._guard(expires_at, before_read)
                        if getattr(connection, 'sock', None) is not None:
                            connection.sock.settimeout(remaining)
                        part = response.read(min(65536, _LIMIT + 1 - len(raw)))
                        if not part:
                            break
                        raw.extend(part)
                        if len(raw) > _LIMIT:
                            raise ValueError
                self._guard(expires_at, before_read)
                result, raw = raw, bytearray()
                return result
        except Exception:
            raise WindowsTargetOwnerRecoveryError(_ERROR) from None
        finally:
            self._active_session = None
            _zeroize_mutable(raw)
            for resource in (response, connection):
                if resource is not None:
                    resource.close()

    def observe_absence(self, *, expires_at: int, before_send: Callable[[], None]) -> tuple[bytearray, str]:
        raw = bytearray()
        try:
            if self.role_digest is None:
                raise ValueError
            with self._lock, self._session(expires_at, before_send) as session:
                raw = self._get(session, '/api/v2/cmdb/secret/target/' + quote(self._source._name, safe='') +
                    '?with_meta=true&vdom=root', expires_at, before_send, absent=True)
                digest = e._envelope(raw, self._creator._proposal, absent=True)
                observed = self._namespace.observe(self._source._name, (self._original.created.coordinates,))
                self._namespace.check_transport_source(observed, candidate_name=self._source._name, transport=self._creator)
                if not observed.candidate_absent:
                    raise ValueError
                witness = c._digest((_CONTRACT, self.binding_digest, digest, self.role_digest,
                    observed.dependency_digest, observed.namespace_digest, observed.api_witness_digest))
            self._namespace.check_current(observed, candidate_name=self._source._name)
            self._guard(expires_at, before_send)
            result, raw = raw, bytearray()
            return result, witness
        except Exception:
            raise WindowsTargetOwnerRecoveryError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)

    def close(self) -> None:
        with self._lock:
            self._enabled, self._closed = False, True
