"""Default-closed fixed Windows execution Secret POST and metadata readback.

This is private candidate wiring, never an MCP endpoint. Actual use still needs
the owning package's namespace/Target/Folder projection, trusted authorization,
independent recovery and lab acceptance. No caller route, selector or arbitrary
request body can enter from MCP. Material comes only from the private C3 adapter.
"""
from __future__ import annotations

from collections.abc import Callable
import http.client
import math
import os
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import quote, urlsplit

from v4_planning.material_provider import MaterialLeaseRequest, _OpaqueC3Object
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome

from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable,
)
from .windows_execution_secret_ack import WindowsExecutionSecretAckCustody
from .windows_execution_secret_ack import _SEND, _ACK, _METADATA
from .windows_execution_secret_contract import WindowsExecutionSecretBinding, REQUEST_UUID, _proposed_metadata

_COLLECTION = "/api/v2/cmdb/secret/database"
_ERROR = "The private Windows execution Secret transport is unavailable."


class WindowsExecutionSecretHttpError(RuntimeError):
    """Categorical refusal without request, response or selectors."""


class WindowsExecutionSecretHttpTransport(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig,
            custody: WindowsExecutionSecretAckCustody, *, execution_enabled: bool = False,
            source_guard: Callable[[], bool] | None = None,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            http_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or type(custody) is not WindowsExecutionSecretAckCustody or config != custody._config
                    or type(execution_enabled) is not bool or not callable(connection_factory)
                    or source_guard is not None and not callable(source_guard)
                    or not callable(http_clock) or type(config.timeout_seconds) not in (int, float)
                    or not math.isfinite(config.timeout_seconds) or not 1 <= config.timeout_seconds <= 60):
                raise ValueError
            custody._validate()
            parsed = urlsplit(config.base_url)
            if parsed.hostname is None or parsed.username is not None or parsed.password is not None:
                raise ValueError
            context = _ssl_context(config)
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._config, self._custody, self._tls = config, custody, context
            self._factory, self._clock, self._enabled = connection_factory, http_clock, execution_enabled
            self._source_guard = self._source_guard_pin = source_guard
            self._host, self._port = parsed.hostname, parsed.port or 443
            keys = sorted(set(_proposed_metadata(custody._profile, REQUEST_UUID)) | {"q_ref", "q_static", "target-info"})
            self._detail_query = "format=" + quote("|".join(keys), safe="") + "&with_meta=true&vdom=root"
            self._attempted = self._failed_clock = False
            self._last_time: float | None = None
            self._deadline: float | None = None
            self._lock = RLock()
        except Exception:
            raise WindowsExecutionSecretHttpError(_ERROR) from None

    def _now(self) -> float:
        try:
            value = self._clock()
            if (self._failed_clock or type(value) not in (int, float) or not math.isfinite(value)
                    or value < 0 or self._last_time is not None and value < self._last_time):
                raise ValueError
            self._last_time = float(value)
            return float(value)
        except Exception:
            self._failed_clock = True
            raise WindowsExecutionSecretHttpError(_ERROR) from None

    def _windows_execution_secret_ready(self, binding: WindowsExecutionSecretBinding,
            request: MaterialLeaseRequest) -> bool:
        """Deny disabled or previously consumed custody before loading C3 material."""
        try:
            with self._lock, self._custody._lock:
                self._check_source()
                self._custody._validate()
                self._custody._guard.require()
                return (self._enabled is True and not self._attempted and not self._custody._closed
                    and type(binding) is WindowsExecutionSecretBinding and binding == self._custody._profile
                    and type(request) is MaterialLeaseRequest and request == self._custody._request
                    and not any(os.path.lexists(self._custody._directory / name) for name in (_SEND, _ACK, _METADATA)))
        except Exception:
            return False

    def _check_source(self) -> None:
        if (self._source_guard is None or self._source_guard is not self._source_guard_pin
                or self._source_guard() is not True):
            raise WindowsExecutionSecretHttpError(_ERROR)

    def _remaining(self) -> float:
        if self._deadline is None:
            raise WindowsExecutionSecretHttpError(_ERROR)
        value = self._deadline - self._now()
        if value <= 0:
            raise WindowsExecutionSecretHttpError(_ERROR)
        return min(10.0, value)

    def _receive(self, response: Any, maximum: int) -> bytearray:
        raw, chunk = bytearray(), bytearray(4096)
        transferred = False
        try:
            content_type = response.getheader("Content-Type")
            if (type(response.status) is not int or response.status != 200
                    or type(content_type) is not str or content_type.split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("Content-Encoding") not in (None, "", "identity")
                    or response.getheader("Transfer-Encoding") not in (None, "")):
                raise ValueError
            while True:
                self._remaining()
                with memoryview(chunk)[:min(len(chunk), maximum - len(raw) + 1)] as view:
                    count = response.readinto1(view)
                    self._remaining()
                    if type(count) is not int or not 0 <= count <= len(view) or len(raw) + count > maximum:
                        raise ValueError
                    if count:
                        raw.extend(view[:count])
                for offset in range(len(chunk)):
                    chunk[offset] = 0
                if count == 0:
                    break
            transferred = True
            return raw
        finally:
            _zeroize_mutable(chunk)
            if not transferred:
                _zeroize_mutable(raw)

    def _request(self, *, create_body: memoryview | None = None) -> None:
        raw = bytearray()
        connection = response = None
        try:
            self._check_source()
            self._custody._writing_now()
            if create_body is None:
                original = self._custody.inspect_original_creation()
                path = _COLLECTION + "/" + str(original.native_secret_id) + "?" + self._detail_query
            else:
                path = _COLLECTION + "?vdom=root"
            connection = self._factory(self._host, self._port, timeout=self._remaining(), context=self._tls)
            connection.connect()
            self._check_source()
            self._custody._writing_now()
            self._remaining()
            headers = {"Accept": "application/json", "Accept-Encoding": "identity",
                "Authorization": "Bearer " + self._config.bearer_token, "Connection": "close",
                "Cache-Control": "no-store", "User-Agent": "fortipam-mcp-windows-execution-secret/1"}
            if create_body is not None:
                headers["Content-Type"] = "application/json"
                self._custody.begin_original_send(create_body)
            self._check_source()
            self._custody._writing_now()
            self._remaining()
            connection.request("POST" if create_body is not None else "GET", path,
                body=create_body, headers=headers)
            response = connection.getresponse()
            raw = self._receive(response, 16384 if create_body is not None else 1048576)
            self._custody._writing_now()
            if create_body is not None:
                self._custody.capture_original_ack(raw, http_status=response.status,
                    content_type=response.getheader("Content-Type"))
            else:
                self._custody.capture_original_metadata(raw)
            self._remaining()
        finally:
            _zeroize_mutable(raw)
            # A close failure still closes the other resource and prevents success.
            try:
                if response is not None:
                    response.close()
            finally:
                if connection is not None:
                    connection.close()

    def _create_windows_execution_secret(self, binding: WindowsExecutionSecretBinding,
            request: MaterialLeaseRequest, body: memoryview) -> SecretCreateAdapterOutcome:
        try:
            with self._lock:
                if self._attempted:
                    raise ValueError
                self._attempted = True
                if (not self._enabled or type(binding) is not WindowsExecutionSecretBinding
                        or binding != self._custody._profile or type(request) is not MaterialLeaseRequest
                        or request != self._custody._request):
                    raise ValueError
                self._custody._writing_now()
                self._deadline = self._now() + min(30.0, float(self._config.timeout_seconds))
                self._request(create_body=body)
                self._request()
                self._custody._writing_now()
                self._remaining()
                return SecretCreateAdapterOutcome.VERIFIED_CREATED
        except Exception:
            return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
