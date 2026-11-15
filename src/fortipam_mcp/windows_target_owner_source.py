"""Fixed Windows Target Owner reads; no dispatch or ownership authority."""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import math
from pathlib import Path
import re
from threading import RLock
import time
from urllib.parse import quote

import httpx

from . import secret_bulk_import_metadata as m
from . import target_preservation_contract as c
from .local_user_reset_fixture_preflight import _actor_context
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, FortiPamSecretMetadataHttpTransport, _ssl_context, _zeroize_mutable,
    _skip_json_space, _json_value_end,
)
from .target_api_dependency_reader import _private_http_logs
from .target_lifecycle_dependencies import _envelope, _one

_ERROR = 'Protected Windows Target Owner source unavailable.'
_CONTRACT = 'fortipam-build29-windows-target-owner-read-v1'
_NAME = re.compile(r'MCPV4WinTarget[0-9]{8}R[1-9][0-9]{0,2}\Z')
_MAX_BYTES = 2 * 1048576


def _ca_digest(config: SecretMetadataHttpTransportConfig) -> str | None:
    if config.ca_file is None:
        return None
    with Path(config.ca_file).open('rb') as stream:
        ca = stream.read(1048577)
    if not 0 < len(ca) <= 1048576:
        raise ValueError
    return hashlib.sha256(ca).hexdigest()


class WindowsTargetOwnerSourceError(ValueError):
    """No raw values or partial source evidence in failures."""


class WindowsTargetOwnerSource:
    """Explicitly bound read source, never an API permission fallback.

    Each read brackets one complete Target GET with the exact Owner actor and
    verified logout. The writer/dependency API remains a separate authority.
    A current row alone cannot supply a creation receipt or enable a mutation.
    """

    def __init__(self, config: SecretMetadataHttpTransportConfig, *, target_name: str,
                 owner_name: str, serial_digest: str, credentials: Callable[[], tuple[str, str]],
                 client_factory: Callable[..., httpx.Client] = httpx.Client,
                 clock: Callable[[], float] = time.time) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                or type(target_name) is not str or _NAME.fullmatch(target_name) is None
                or type(owner_name) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._@-]{0,63}', owner_name) is None
                or type(serial_digest) is not str or c._DIGEST.fullmatch(serial_digest) is None
                or not callable(credentials) or not callable(clock) or not callable(client_factory)):
                raise ValueError
            config.__post_init__()
            _ssl_context(config)
            self._config, self._name, self._owner, self._serial = config, target_name, owner_name, serial_digest
            self._ca = _ca_digest(config)
            self._context = c._digest((_CONTRACT, target_name, owner_name, serial_digest,
                config.base_url, hashlib.sha256(config.bearer_token.encode()).hexdigest(), self._ca))
            self._credentials, self._factory, self._clock = credentials, client_factory, clock
            self._lock, self._closed, self._failed, self._last = RLock(), False, False, -1.0
            self.logout_verified = False
        except Exception:
            raise WindowsTargetOwnerSourceError(_ERROR) from None

    def check_binding(self, config: SecretMetadataHttpTransportConfig, *, target_name: str,
                      serial_digest: str) -> str:
        try:
            if (self._closed or self._failed or self._config is not config
                or target_name != self._name or serial_digest != self._serial
                or self._ca != _ca_digest(config)):
                raise ValueError
            return self._context
        except Exception:
            raise WindowsTargetOwnerSourceError(_ERROR) from None

    def _now(self) -> float:
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0 or now < self._last:
            raise ValueError
        self._last = float(now)
        return float(now)

    def check_request(self, content: bytearray) -> None:
        """Reject an Owner/request mismatch before any M4 or network operation."""
        try:
            start = _skip_json_space(content, 0)
            end = _json_value_end(content, start)
            if _skip_json_space(content, end) != len(content):
                raise ValueError
            self._owner_acl(content, (start, end), request=True)
        except Exception:
            raise WindowsTargetOwnerSourceError(_ERROR) from None

    def _owner_acl(self, content: bytearray, row: tuple[int, int], *, request: bool = False) -> None:
        fields = m._object_spans(content, *row, c.TARGET_STATE_FIELDS | (frozenset({'$originalName'}) if request else c._METADATA))
        if m._scalar(content, fields['name']) != self._name or m._array(content, fields['group-permission'], 1):
            raise ValueError
        entries = m._array(content, fields['user-permission'], 2)
        if len(entries) != 1:
            raise ValueError
        acl = m._object_spans(content, *entries[0], frozenset({'id', 'user-name', 'permission', 'q_origin_key'}))
        if c._member_count(content, entries[0]) != len(acl):
            raise ValueError
        identifier = m._scalar(content, acl['id'])
        if (type(identifier) is not int or identifier != 1 or m._scalar(content, acl['permission']) != 'owner'
            or 'q_origin_key' in acl and (type(m._scalar(content, acl['q_origin_key'])) is not int
                or m._scalar(content, acl['q_origin_key']) != identifier)):
            raise ValueError
        names = m._array(content, acl['user-name'], 2)
        if len(names) != 1:
            raise ValueError
        name = m._object_spans(content, *names[0], frozenset({'name', 'q_origin_key'}))
        if c._member_count(content, names[0]) != len(name):
            raise ValueError
        if (m._scalar(content, name['name']) != self._owner
            or 'q_origin_key' in name and m._scalar(content, name['q_origin_key']) != self._owner):
            raise ValueError

    def read(self, *, expires_at: int, before_send: Callable[[], None]) -> bytearray:
        raw = bytearray()
        session = None
        try:
            with self._lock:
                self.check_binding(self._config, target_name=self._name, serial_digest=self._serial)
                if type(expires_at) is not int or not callable(before_send) or not 0 < expires_at - self._now() <= 60:
                    raise ValueError
                self.logout_verified = False
                def guard() -> float:
                    self.check_binding(self._config, target_name=self._name, serial_digest=self._serial)
                    before_send()
                    self.check_binding(self._config, target_name=self._name, serial_digest=self._serial)
                    remaining = expires_at - self._now()
                    if remaining <= 0:
                        raise ValueError
                    return min(float(self._config.timeout_seconds), remaining)
                session = OwnerSessionMetadataTransport(self._config, owner_name=self._owner,
                    credentials=self._credentials, folder_path='windows-target-owner-source',
                    secret_name='windows-target-owner-source', target_name=self._name,
                    witness=FortiPamSecretMetadataHttpTransport(self._config), client_factory=self._factory)
                def receive(path: str) -> bytearray:
                    data = bytearray()
                    try:
                        timeout = guard()
                        with session._client.stream('GET', path, timeout=timeout, headers={
                            'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}) as response:
                            guard()
                            if (response.status_code != 200
                                or response.headers.get('content-type', '').split(';')[0] != 'application/json'
                                or response.headers.get('content-encoding', 'identity') not in ('', 'identity')):
                                raise ValueError
                            for chunk in response.iter_raw():
                                guard()
                                if len(data) + len(chunk) > _MAX_BYTES:
                                    raise ValueError
                                data.extend(chunk)
                        guard()
                        result, data = data, bytearray()
                        return result
                    finally:
                        _zeroize_mutable(data)
                guard()
                with _private_http_logs(), session.authenticated():
                    actor = receive('/api/v2/monitor/web-ui/state')
                    try:
                        actor_digest = _actor_context(actor, expected_name=self._owner)
                        _envelope(actor, path='web-ui', name='state', serial_digest=self._serial, monitor=True)
                    finally:
                        _zeroize_mutable(actor)
                    raw = receive('/api/v2/cmdb/secret/target/' + quote(self._name, safe='') + '?with_meta=true&vdom=root')
                    row = _one(raw, _envelope(raw, path='secret', name='target', serial_digest=self._serial))
                    self._owner_acl(raw, row)
                    c.capture_target_state(bytearray(raw), expected_name=self._name, expected_serial_digest=self._serial)
                    actor = receive('/api/v2/monitor/web-ui/state')
                    try:
                        if _actor_context(actor, expected_name=self._owner) != actor_digest:
                            raise ValueError
                        _envelope(actor, path='web-ui', name='state', serial_digest=self._serial, monitor=True)
                    finally:
                        _zeroize_mutable(actor)
                self.logout_verified = session.logout_verified
                guard()
                if not self.logout_verified:
                    raise ValueError
                result, raw = raw, bytearray()
                return result
        except Exception:
            self._failed = True
            raise WindowsTargetOwnerSourceError(_ERROR) from None
        finally:
            if session is not None:
                self.logout_verified = session.logout_verified
            _zeroize_mutable(raw)

    def close(self) -> None:
        with self._lock:
            self._closed = True
