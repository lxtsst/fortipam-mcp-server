"""Inactive original-row actor guard using the existing exact lab Role snapshot.

This qualifies the configured API identity and declared Secret/Folder access,
not object ACLs, workload separation, ownership, M4 or an execution grant.
"""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import http.client
import math
from pathlib import Path
import time
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from . import dlp_api_actor_guard as g
from .dlp_sensor_delete_http_transport import DlpSensorDeleteHttpTransportConfig
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable


class _OriginalRowApiActorGuard(_OpaqueC3Object):
    """Two fresh, fixed three-GET windows, bound to the exact writer config."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: g.DlpApiActorGuardBinding,
                 *, connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or type(binding) is not g.DlpApiActorGuardBinding
                    or type(config.timeout_seconds) not in {int, float}
                    or not math.isfinite(config.timeout_seconds)):
                raise ValueError
            config.__post_init__()
            binding.__post_init__()
            self._config = config
            self._actor_config = DlpSensorDeleteHttpTransportConfig(
                config.base_url, config.bearer_token, config.timeout_seconds, config.ca_file)
            self._binding, self._factory, self._clock = binding, connection_factory, clock
            self._ca_digest = self._ca_snapshot()
            self._last_time: float | None = None
            self._before: g.DlpApiActorEvidence | None = None
            self._started = self._completed = False
            self._guard = g.DlpApiActorGuard(self._actor_config, binding)
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    @property
    def serial_digest(self) -> str:
        return hashlib.sha256(self._binding.expected_serial.encode()).hexdigest()

    def _ca_snapshot(self) -> str | None:
        if self._config.ca_file is None:
            return None
        with Path(self._config.ca_file).open('rb') as stream:
            content = stream.read(1048577)
        if not 0 < len(content) <= 1048576:
            raise ValueError
        return hashlib.sha256(content).hexdigest()

    def _require_config(self, config: SecretMetadataHttpTransportConfig) -> None:
        if (config is not self._config or any(getattr(config, name) != getattr(self._actor_config, name)
                for name in ('base_url', 'bearer_token', 'timeout_seconds', 'ca_file'))
                or self._ca_snapshot() != self._ca_digest):
            raise BulkImportIntakeError(_ERROR)

    def _tls_for_transport(self, config: SecretMetadataHttpTransportConfig) -> Any:
        self._require_config(config)
        # The actor and product observations use this same loaded trust store.
        return self._guard._context

    def _now(self) -> float:
        value = self._clock()
        if (type(value) not in {int, float} or not math.isfinite(value) or value < 0
                or self._last_time is not None and value < self._last_time):
            raise BulkImportIntakeError(_ERROR)
        self._last_time = float(value)
        return float(value)

    def _observe(self, *, completed: bool, deadline: float) -> None:
        resources: list[Any] = []
        permissions: dict[str, bool] = {}
        self._require_config(self._config)
        if (type(completed) is not bool or type(deadline) not in {int, float} or not math.isfinite(deadline)
                or self._completed or completed != self._started):
            raise BulkImportIntakeError(_ERROR)
        if completed:
            self._completed = True
        else:
            self._started = True
        until = min(deadline, self._now() + self._config.timeout_seconds, self._now() + 30)
        def remaining() -> float:
            seconds = until - self._now()
            if seconds <= 0:
                raise BulkImportIntakeError(_ERROR)
            return min(10.0, seconds)
        outer = self
        class Connection:
            def __init__(self, host: str, port: int, **kwargs: Any) -> None:
                kwargs['timeout'] = remaining()
                self.inner = outer._factory(host, port, **kwargs)
                self.closed = False
                resources.append(self)
            def request(self, method: str, path: str, **kwargs: Any) -> None:
                remaining()
                self.inner.request(method, path, **kwargs)
                remaining()
            def getresponse(self) -> Any:
                remaining()
                response = Response(self.inner.getresponse())
                remaining()
                return response
            def close(self) -> None:
                self.inner.close()
                self.closed = True
        class Response:
            def __init__(self, inner: Any) -> None:
                self.inner, self.status, self.closed = inner, inner.status, False
                resources.append(self)
            def getheader(self, name: str, default: str = '') -> str:
                value = self.inner.getheader(name, default)
                if type(value) is not str:
                    raise BulkImportIntakeError(_ERROR)
                return value
            def readinto(self, view: memoryview) -> int:
                remaining()
                count = self.inner.readinto(view)
                remaining()
                if type(count) is not int:
                    raise BulkImportIntakeError(_ERROR)
                return count
            def close(self) -> None:
                self.inner.close()
                self.closed = True
        class Guard(g.DlpApiActorGuard):
            def _read(self, path: str) -> bytearray:
                raw = super()._read(path)
                try:
                    if any(not resource.closed for resource in resources):
                        raise BulkImportIntakeError(_ERROR)
                    if path == self._role_path:
                        row = g._selected_row(raw, 'accprofile', outer._binding.expected_profile,
                            outer._binding.expected_serial, frozenset(g._ROLE_FIELDS))
                        g._role_policy(row)
                        permissions['secret_write'] = row['secretgrp'] == 'read-write' or (
                            row['secretgrp'] == 'custom' and row['secretgrp-permission']['secret-table'] == 'read-write')
                        permissions['folder_read'] = row['secretgrp'] == 'read-write' or (
                            row['secretgrp'] == 'custom' and row['secretgrp-permission']['folder-table'] in {'read', 'read-write'})
                    return raw
                except BaseException:
                    _zeroize_mutable(raw)
                    raise
        try:
            guard = Guard(self._actor_config, self._binding, connection_factory=Connection)
            guard._context = self._guard._context
            evidence = guard.observe()
            remaining()
            self._require_config(self._config)
            if (permissions != {'secret_write': True, 'folder_read': True}
                    or completed and (self._before is None or self._before.evidence_digest != evidence.evidence_digest)):
                raise ValueError
            if not completed:
                self._before = evidence
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            for resource in reversed(resources):
                if not resource.closed:
                    try:
                        resource.close()
                    except Exception:
                        pass
            if any(not resource.closed for resource in resources):
                raise BulkImportIntakeError(_ERROR)
