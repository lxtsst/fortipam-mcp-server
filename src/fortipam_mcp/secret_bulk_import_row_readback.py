"""Private original-row native postcondition, with no dispatch or public route.

Compile the original C2 pins inside its active M4 dispatch, before intake is
armed. Later reads use the retained original ACK while M4 is still in progress;
only a fresh fixed GET and complete C2 comparison yield the expected digest.
This does not supply current-state or complete catalog source qualification.
"""

from __future__ import annotations

from collections.abc import Callable
import http.client
import math
from pathlib import Path
from threading import RLock
import time
from typing import Any
from urllib.parse import urlsplit

from v4_planning import M4ExecutionPlan
from v4_planning.material_provider import _OpaqueC3Object

from .dlp_api_actor_guard import DlpApiActorGuardBinding
from .secret_bulk_import_dependencies import ImportDependencyCatalog, ResolvedImportDependencies
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_row_action_worker import _compile_original_channel_action_pins
from .secret_bulk_import_row_actor import _OriginalRowApiActorGuard
from .secret_bulk_import_row_channel import OriginalRowChannelOwner
from .secret_bulk_import_row_http_transport import _NativeResponse
from .secret_bulk_import_row_wire import _Build29SecretWireDefaults, _compare_build29_detail
from .secret_bulk_import_token_channel import _PinnedKey
from .secret_metadata_http_transport import COLLECTION_PATH, SecretMetadataHttpTransportConfig

_LIMIT = 1048576


class _OriginalRowNativeReadback(_OpaqueC3Object):
    """Fresh ACK-ID reads under the original dispatch's nonrenewable deadline."""

    def __init__(self, owner: OriginalRowChannelOwner, catalog: ImportDependencyCatalog,
                 projected: ResolvedImportDependencies, defaults: _Build29SecretWireDefaults,
                 config: SecretMetadataHttpTransportConfig, actor_binding: DlpApiActorGuardBinding, *,
                 namespace_key_path: Path, index: int, target_name: str | None,
                 associated_secret_id: int | None,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or config.ca_file is None
                    or type(actor_binding) is not DlpApiActorGuardBinding
                    or not callable(connection_factory) or not callable(clock)):
                raise ValueError
            config.__post_init__()
            self._pins = _compile_original_channel_action_pins(owner, catalog, projected, defaults,
                namespace_key_path=namespace_key_path, index=index, target_name=target_name,
                associated_secret_id=associated_secret_id)
            self._owner, self._config, self._actor = owner, config, actor_binding
            self._factory, self._clock = connection_factory, clock
            self._key = _PinnedKey(namespace_key_path, owner._binding.namespace_key_digest)
            self._lock = RLock()
            self._closed = self._failed = False
            self._last: float | None = None
            self._window: float | None = None
            self._guard = _OriginalRowApiActorGuard(config, actor_binding,
                connection_factory=connection_factory, clock=self._now)
            if self._guard.serial_digest != self._pins.capture.serial_digest:
                raise ValueError
            self._guard._require_config(config)
            self._now()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _now(self) -> float:
        value = self._clock()
        if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                or self._closed or self._failed
                or self._last is not None and value < self._last
                or value >= self._pins.deadline
                or self._window is not None and value >= self._window):
            raise BulkImportIntakeError(_ERROR)
        self._last = float(value)
        return float(value)

    def _check_source(self) -> None:
        self._now()
        self._guard._require_config(self._config)
        raw = self._key.load()
        _wipe(raw)
        self._now()

    def _read(self, response: _NativeResponse) -> bytearray:
        raw, chunk = bytearray(), bytearray(4096)
        try:
            while True:
                self._now()
                with memoryview(chunk)[:min(len(chunk), _LIMIT - len(raw) + 1)] as view:
                    count = response.readinto1(view)
                    self._now()
                    if type(count) is not int or not 0 <= count <= len(view) or len(raw) + count > _LIMIT:
                        raise ValueError
                    raw.extend(view[:count])
                _wipe(chunk)
                if not count:
                    return raw
        except BaseException:
            _wipe(raw)
            raise
        finally:
            _wipe(chunk)

    def _detail(self, native_id: int, deadline: float) -> bytearray:
        origin = urlsplit(self._config.base_url)
        if origin.hostname is None or type(native_id) is not int or not 0 < native_id < 2**31:
            raise ValueError
        tls = self._guard._tls_for_transport(self._config)
        tls.set_alpn_protocols(['http/1.1'])
        headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity',
            'Authorization': 'Bearer ' + self._config.bearer_token,
            'Cache-Control': 'no-cache, no-store', 'Connection': 'close',
            'User-Agent': 'fortipam-private-original-row/1'}
        connection = response = None
        raw = bytearray()
        try:
            connection = self._factory(origin.hostname, origin.port or 443,
                timeout=min(self._config.timeout_seconds, deadline - self._now()), context=tls)
            connection.request('GET', f'{COLLECTION_PATH}/{native_id}?vdom=root', None, headers)
            self._now()
            response = connection.getresponse()
            self._now()
            kind = response.getheader('Content-Type')
            if (type(response.status) is not int or response.status != 200 or kind is None
                    or kind.split(';', 1)[0].strip().lower() != 'application/json'
                    or response.getheader('Content-Encoding') not in {None, '', 'identity'}
                    or response.getheader('Transfer-Encoding') not in {None, ''}):
                raise ValueError
            raw = self._read(response)
            # Close before returning so a failed close cannot retain raw material.
            response.close()
            response = None
            connection.close()
            connection = None
            self._now()
            return raw
        except BaseException:
            _wipe(raw)
            raise
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                if connection is not None:
                    connection.close()

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            raw = bytearray()
            try:
                if type(plan) is not M4ExecutionPlan or plan != self._owner._binding.plan:
                    raise ValueError
                started = self._now()
                self._window = min(self._pins.deadline, started + min(30.0, self._config.timeout_seconds))
                self._check_source()
                before = self._owner._inspect_ack_for_readback()
                if (before.serial_digest != self._pins.capture.serial_digest
                        or before.defaults_digest != self._pins.defaults_digest
                        or before.ack_source_digest != self._pins.capture.source_digest):
                    raise ValueError
                # Each decision gets a new actor window using the originally loaded CA.
                guard = _OriginalRowApiActorGuard(self._config, self._actor,
                    connection_factory=self._factory, clock=self._now)
                if guard._ca_digest != self._guard._ca_digest:
                    raise ValueError
                guard._guard._context = self._guard._tls_for_transport(self._config)
                guard._observe(completed=False, deadline=self._window)
                raw = self._detail(before.native_secret_id, self._window)
                if not _compare_build29_detail(raw, metadata=self._pins.metadata,
                        serial_digest=before.serial_digest, expected_secret_id=before.native_secret_id):
                    raise ValueError
                guard._observe(completed=True, deadline=self._window)
                self._check_source()
                if self._owner._inspect_ack_for_readback() != before:
                    raise ValueError
                self._now()
                return plan.expected_state_digest
            except BaseException as error:
                self._failed = True
                if not isinstance(error, Exception):
                    raise
                raise BulkImportIntakeError(_ERROR) from None
            finally:
                self._window = None
                _wipe(raw)

    def close(self) -> None:
        with self._lock:
            self._closed = True
