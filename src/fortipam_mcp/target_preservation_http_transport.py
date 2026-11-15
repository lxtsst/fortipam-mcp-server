"""Inactive fixed coordinate PUTs; caller supplies independent M4/ownership authority.

One private directory binds one change and API identity. Update/restore have
separate durable no-replay claims. This does not create/adopt/delete Targets,
prove Template compatibility, or register an executable runtime action.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import stat
import time
from typing import Literal
from urllib.parse import quote, urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from . import target_preservation_contract as c
from . import secret_bulk_import_metadata as m
from .ldap_server_http_transport import _Connection
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable, _skip_json_space, _json_value_end
from .target_operation_records import _TargetOperationRecords

_ERROR = 'Protected Target coordinate transport unavailable.'
_CONTRACT = 'fortipam-build29-target-coordinates-v1'
_LIMIT = 2 * 1048576
Phase = Literal['update', 'restore']


class TargetCoordinateTransportError(RuntimeError):
    """Fixed failure; a failed dispatch may have changed the device."""


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _require_digest(value: object) -> None:
    if type(value) is not str or c._DIGEST.fullmatch(value) is None:
        raise ValueError


def _ack(content: bytearray, change: c.TargetCoordinateChange) -> str:
    try:
        start = _skip_json_space(content, 0)
        end = _json_value_end(content, start)
        if _skip_json_space(content, end) != len(content):
            raise ValueError
        m._validate_json(content, start, end, depth=0, budget=[50000])
        fields = m._object_spans(content, start, end, c._ENVELOPE)
        for key, expected in {'version':'v7.0.0', 'build':29, 'path':'secret', 'name':'target',
                'http_method':'PUT', 'status':'success', 'http_status':200, 'vdom':'root',
                'mkey':change.baseline.name}.items():
            actual = m._scalar(content, fields[key])
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError
        serial = m._text(m._scalar(content, fields['serial']), maximum=128)
        if hashlib.sha256(serial.encode()).hexdigest() != change.baseline.serial_digest:
            raise ValueError
        if 'error' in fields:
            error = m._scalar(content, fields['error'])
            if error is not None and (type(error) is not int or error != 0):
                raise ValueError
        return hashlib.sha256(content).hexdigest()
    finally:
        _zeroize_mutable(content)


class TargetCoordinateHttpTransport(_TargetOperationRecords):
    """Private fixed adapter, disabled by default; no authorization inferred from state."""

    __slots__ = ('_config', '_change', '_directory', '_identity', '_namespace', '_enabled',
                 '_clock', '_last_clock', '_clock_failed', '_factory', '_path', '_context', '_source_context_digest')

    def __init__(self, config: SecretMetadataHttpTransportConfig, change: c.TargetCoordinateChange, *,
                 state_directory: Path, execution_enabled: bool = False,
                 clock: Callable[[], int] | None = None,
                 connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if type(config) is not SecretMetadataHttpTransportConfig or type(execution_enabled) is not bool:
                raise ValueError
            config.__post_init__()
            c._checked_change(change)
            url = urlsplit(config.base_url)
            if url.username is not None or url.password is not None or not url.hostname:
                raise ValueError
            name = change.baseline.name
            if name in ('.', '..') or any(char in name for char in '/\\?#'):
                raise ValueError
            if (not isinstance(state_directory, Path) or not state_directory.is_absolute()
                    or '..' in state_directory.parts or any(p.is_symlink() for p in (state_directory, *state_directory.parents))):
                raise ValueError
            info = state_directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            identity = (info.st_dev, info.st_ino)
            ca_digest = None
            if config.ca_file is None:
                context = _ssl_context(config)
            else:
                with Path(config.ca_file).open('rb') as stream:
                    ca_snapshot = stream.read(1048577)
                if not 0 < len(ca_snapshot) <= 1048576:
                    raise ValueError
                ca_digest = hashlib.sha256(ca_snapshot).hexdigest()
                context = ssl.create_default_context(cadata=ca_snapshot.decode('ascii'))
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            namespace = _digest((_CONTRACT, change.baseline.state_digest,
                tuple(getattr(change.desired, key) for key in c._COORDINATES), config.base_url,
                hashlib.sha256(config.bearer_token.encode()).hexdigest(),
                ca_digest,
                str(state_directory), identity))
            for key, value in {'_config':config, '_change':change, '_directory':state_directory,
                '_identity':identity, '_namespace':namespace, '_enabled':execution_enabled,
                '_clock':clock or (lambda: int(time.time())), '_last_clock':None, '_clock_failed':False,
                '_factory':connection_factory or http.client.HTTPSConnection, '_context':context,
                '_source_context_digest':None if ca_digest is None else c._api_source_context(
                    config.base_url,hashlib.sha256(config.bearer_token.encode()).hexdigest(),
                    ca_digest,change.baseline.serial_digest),
                '_path':'/api/v2/cmdb/secret/target/'+quote(name, safe='')+'?with_meta=true&vdom=root'}.items():
                object.__setattr__(self, key, value)
        except Exception:
            raise TargetCoordinateTransportError(_ERROR) from None

    _config: SecretMetadataHttpTransportConfig
    _change: c.TargetCoordinateChange
    _directory: Path
    _identity: tuple[int, int]
    _namespace: str
    _enabled: bool
    _clock: Callable[[], int]
    _last_clock: int | None
    _clock_failed: bool
    _factory: Callable[..., _Connection]
    _path: str
    _context: ssl.SSLContext
    _source_context_digest: str | None

    def _request(self, method: Literal['GET', 'PUT'], *, deadline: int,
                 guard: Callable[[], None], body: bytearray | None = None) -> bytearray:
        response = connection = view = active_socket = None
        raw = bytearray(_LIMIT+1)
        transfer = False
        def check_deadline(*, refresh: bool = False) -> float:
            remaining = deadline-self._now()
            if remaining <= 0: raise ValueError
            timeout = min(self._config.timeout_seconds, remaining)
            if refresh and active_socket is not None and active_socket.fileno() >= 0:
                active_socket.settimeout(timeout)
            return timeout
        try:
            try:
                timeout = check_deadline()
                context = self._context
                if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                    raise ValueError
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                url = urlsplit(self._config.base_url)
                connection = self._factory(url.hostname, url.port or 443, timeout=timeout, context=context)
                guard(); setattr(connection, 'timeout', check_deadline()); connection.connect()
                active_socket = getattr(connection, 'sock', None)
                guard(); check_deadline(refresh=True)
                if body is not None:
                    view = memoryview(body).toreadonly()
                connection.request(method, self._path, view, {'Authorization':'Bearer '+self._config.bearer_token,
                    'Accept':'application/json', 'Content-Type':'application/json', 'Accept-Encoding':'identity',
                    'Connection':'close', 'Cache-Control':'no-store','User-Agent':'fortipam-mcp-target-lifecycle/1'})
                check_deadline(refresh=True)
                response = connection.getresponse()
                check_deadline()
                if response.status != 200 or 'json' not in response.getheader('Content-Type','').lower() or response.getheader('Content-Encoding','identity') not in ('','identity'):
                    raise ValueError
                used = 0
                while used <= _LIMIT:
                    check_deadline(refresh=True)
                    with memoryview(raw)[used:] as buffer:
                        count = response.readinto(buffer)
                    check_deadline()
                    if type(count) is not int or count < 0 or used+count > _LIMIT:
                        raise ValueError
                    if not count:
                        break
                    used += count
                raw = _take_mutable_prefix(raw, used)
            finally:
                if view is not None: view.release()
                for resource in (response, connection):
                    if resource is not None:
                        try: resource.close()
                        except Exception: pass
            check_deadline()
            transfer = True
            return raw
        finally:
            if not transfer: _zeroize_mutable(raw)

    def read_current(self, *, expires_at: int, before_send: Callable[[], None]) -> c.TargetState:
        """Read the fixed full Target state without claiming a lifecycle phase.

        Return an actual observation, not the proposal, baseline or retained
        mutation receipt. The trusted caller supplies fresh dependency checks;
        this read grants no ownership or write authority.
        """
        content = bytearray()
        try:
            now = self._now()
            if (not callable(before_send) or type(expires_at) is not int
                    or not 0 < expires_at-now <= 60):
                raise ValueError
            def guard() -> None:
                if not now <= self._now() < expires_at: raise ValueError
                before_send()
                if not now <= self._now() < expires_at: raise ValueError
            content = self._request('GET',deadline=expires_at,guard=guard)
            current = c.capture_target_state(content,expected_name=self._change.baseline.name,
                expected_serial_digest=self._change.baseline.serial_digest)
            guard()
            return current
        except Exception:
            raise TargetCoordinateTransportError(_ERROR) from None
        finally:
            _zeroize_mutable(content)

    def dispatch(self, *, phase: Phase, plan_digest: str, authorization_digest: str,
                 expires_at: int, before_send: Callable[[], None],
                 updated: c.TargetState | None = None) -> c.TargetState:
        """Consume one phase, guard each send, fixed PUT/ACK/readback; never retry."""
        body = bytearray()
        try:
            if not self._enabled or type(phase) is not str or phase not in ('update','restore') or not callable(before_send):
                raise ValueError
            for value in (plan_digest, authorization_digest): _require_digest(value)
            now = self._now()
            if type(expires_at) is not int or not 0 < expires_at-now <= 60:
                raise ValueError
            with self._lock() as directory:
                before_send()
                if phase == 'restore':
                    if updated is None: raise ValueError
                    c._checked_state(updated)
                    receipt = self._read(directory, 'update.verified.json')
                    claim_before = self._read(directory, 'update.claim.json')
                    ack_before = self._read(directory, 'update.ack.json')
                    if (receipt.get('claim_digest') != _digest(claim_before)
                            or receipt.get('ack_digest') != _digest(ack_before)
                            or ack_before.get('claim_digest') != _digest(claim_before)
                            or receipt.get('state_digest') != updated.state_digest):
                        raise ValueError
                elif updated is not None:
                    raise ValueError
                claim = {'namespace':self._namespace, 'phase':phase, 'plan_digest':plan_digest,
                    'authorization_digest':authorization_digest, 'claimed_at':now, 'expires_at':expires_at}
                self._write(directory, phase+'.claim.json', claim)
                def guard() -> None:
                    location = self._directory.lstat()
                    if ((location.st_dev, location.st_ino) != self._identity
                            or not stat.S_ISDIR(location.st_mode) or location.st_uid != os.getuid()
                            or stat.S_IMODE(location.st_mode) != 0o700):
                        raise ValueError
                    if not now <= self._now() < expires_at or self._read(directory, phase+'.claim.json') != claim:
                        raise ValueError
                    before_send()
                    if not now <= self._now() < expires_at:
                        raise ValueError
                current = self._request('GET', deadline=expires_at, guard=guard)
                if phase == 'update':
                    body, _ = c.compile_target_coordinate_update(current, baseline=self._change.baseline, desired=self._change.desired)
                else:
                    if updated is None: raise ValueError
                    body = c.compile_target_coordinate_restore(current, change=self._change, updated=updated)
                ack = {'namespace':self._namespace, 'claim_digest':_digest(claim),
                    'response_digest':_ack(self._request('PUT', deadline=expires_at, guard=guard, body=body), self._change)}
                _zeroize_mutable(body)
                self._write(directory, phase+'.ack.json', ack)
                after = self._request('GET', deadline=expires_at, guard=guard)
                state = (c.verify_target_coordinate_update(after, change=self._change) if phase == 'update'
                    else c.verify_target_coordinate_restore(after, change=self._change))
                guard()
                self._write(directory, phase+'.verified.json', {'namespace':self._namespace,
                    'claim_digest':_digest(claim), 'ack_digest':_digest(ack), 'state_digest':state.state_digest})
                return state
        except Exception:
            raise TargetCoordinateTransportError(_ERROR) from None
        finally:
            _zeroize_mutable(body)
