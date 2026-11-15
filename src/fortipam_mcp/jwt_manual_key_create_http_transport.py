"""Default-denied single JWT-key POST and original-ACK-only owned readback.

Private candidate only: no Tool, issuer, environment loader or deletion. Native
POST/full-row compatibility and independent recovery must be qualified before
any distinct authorized lab trial. This never retries or adopts an old send.
"""
from __future__ import annotations

from collections.abc import Callable
import http.client
import math
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import quote

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionPlan
from v4_planning.material_provider import _OpaqueC3Object

from .jwt_manual_key_owned_state import consume_jwt_manual_key_owned_state, expected_jwt_manual_key_created_state
from .jwt_manual_key_preflight_reader import (JwtManualKeyPreflightRead, JwtManualKeyPreflightReader,
    jwt_manual_create_current_from_preflight)
from .jwt_manual_key_response_custody import JwtManualKeyResponseCustody, JwtManualOriginalResponse
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable

_ERROR = "The private manual JWT-key create transport is unavailable."
_MAX_BYTES = 524288


class JwtManualKeyCreateHttpError(RuntimeError):
    """Fixed private refusal without body, response, credentials or selectors."""


class JwtManualKeyCreateHttpTransport(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig, custody: JwtManualKeyResponseCustody,
                 reader: JwtManualKeyPreflightReader, baseline: JwtManualKeyPreflightRead, *,
                 execution_enabled: Callable[[], bool] | None = None, source_guard: Callable[[], bool] | None = None,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 http_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(custody) is not JwtManualKeyResponseCustody
                    or type(reader) is not JwtManualKeyPreflightReader or type(baseline) is not JwtManualKeyPreflightRead
                    or config is not reader._config or not callable(connection_factory) or not callable(http_clock)
                    or any(value is not None and not callable(value) for value in (execution_enabled, source_guard))):
                raise ValueError
            custody._integrity()
            if (reader._source != baseline.source_digest or custody._source != baseline.source_digest
                    or custody._state != baseline.state.state_digest or custody._actor_digest != baseline.actor.digest
                    or jwt_manual_create_current_from_preflight(custody._request, baseline) != custody._current
                    or expected_jwt_manual_key_created_state(custody._request, baseline.state) != custody._plan.expected_state_digest):
                raise ValueError
            self._config, self._custody, self._reader, self._baseline = config, custody, reader, baseline
            self._enabled, self._source_guard = execution_enabled, source_guard
            self._source_guard_pin, self._enabled_pin = source_guard, execution_enabled
            self._factory, self._clock = connection_factory, http_clock
            self._post_path = custody._request.path + "?" + custody._request.query
            self._detail_path = custody._request.path + "/" + quote(custody._name, safe="") + "?with_meta=true"
            self._get_paths = (self._detail_path, reader._paths[6], reader._paths[7], self._detail_path)
            self._attempted = self._wire_attempted = self._capture_attempted = self._failed_clock = False
            self._deadline: float | None = None
            self._last_time: float | None = None
            self._lock = RLock()
        except Exception:
            raise JwtManualKeyCreateHttpError(_ERROR) from None

    def _bound_plan(self, plan: M4ExecutionPlan) -> None:
        if type(plan) is not M4ExecutionPlan or plan != self._custody._plan:
            raise JwtManualKeyCreateHttpError(_ERROR)
        self._custody._integrity()

    def _source(self) -> None:
        if (self._enabled is None or self._enabled is not self._enabled_pin or self._enabled() is not True
                or self._source_guard is None or self._source_guard is not self._source_guard_pin
                or self._source_guard() is not True or self._reader._fingerprint() != self._baseline.source_digest):
            raise JwtManualKeyCreateHttpError(_ERROR)
        self._custody._integrity()
        request = self._custody._request
        if (request._request_digest() != self._custody._request_digest or request._name != self._custody._name
                or request.serial_digest != self._custody._serial_digest):
            raise JwtManualKeyCreateHttpError(_ERROR)
        _, valid = self._custody._observed_clock()
        if not valid:
            raise JwtManualKeyCreateHttpError(_ERROR)

    def _now(self) -> float:
        try:
            value = self._clock()
            if (self._failed_clock or type(value) not in (int, float) or not math.isfinite(value) or value < 0
                    or self._last_time is not None and value < self._last_time):
                raise ValueError
            self._last_time = float(value)
            return float(value)
        except Exception:
            self._failed_clock = True
            raise JwtManualKeyCreateHttpError(_ERROR) from None

    def _remaining(self) -> float:
        if self._deadline is None:
            raise JwtManualKeyCreateHttpError(_ERROR)
        value = self._deadline - self._now()
        if value <= 0:
            raise JwtManualKeyCreateHttpError(_ERROR)
        return min(10.0, value)

    def _connect(self) -> Any:
        self._source()
        context = _ssl_context(self._config)
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise JwtManualKeyCreateHttpError(_ERROR)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = self._factory(self._reader._host, self._reader._port, timeout=self._remaining(), context=context)
        try:
            connection.connect()
            self._source(); self._remaining()
            return connection
        except BaseException:
            connection.close()
            raise

    def _headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self._config.bearer_token, "Accept": "application/json",
            "Content-Type": "application/json", "Accept-Encoding": "identity", "Connection": "close",
            "Cache-Control": "no-store", "User-Agent": "fortipam-mcp-manual-jwt-create/1"}

    def _receive(self, response: Any, connection: Any, raw: bytearray) -> str:
        chunk = bytearray(4096)
        try:
            while True:
                timeout = self._remaining()
                if getattr(connection, "sock", None) is not None: connection.sock.settimeout(timeout)
                count = response.readinto(chunk)
                if type(count) is not int or not 0 <= count <= len(chunk):
                    raise JwtManualKeyCreateHttpError(_ERROR)
                if not count: return "complete"
                size = min(count, _MAX_BYTES + 1 - len(raw))
                with memoryview(chunk)[:size] as part: raw.extend(part)
                chunk[:] = b"\x00" * len(chunk)
                if len(raw) > _MAX_BYTES: return "oversize"
        finally:
            _zeroize_mutable(chunk)

    @staticmethod
    def _close(response: Any, connection: Any) -> None:
        failure: BaseException | None = None
        for resource in (response, connection):
            if resource is not None:
                try: resource.close()
                except BaseException as error: failure = failure or error
        if failure is not None: raise failure

    def _post(self) -> JwtManualOriginalResponse:
        connection = response = None
        raw = bytearray()
        status = None
        content_type = None
        state = "partial"
        encoding_qualified = False
        observed = None
        pending: BaseException | None = None
        try:
            connection = self._connect()
            fresh = self._reader.observe()
            if jwt_manual_create_current_from_preflight(self._custody._request, fresh) != self._custody._current:
                raise JwtManualKeyCreateHttpError(_ERROR)
            self._custody.begin_original_send()
            self._source(); self._remaining()
            self._custody._request.validate()
            with self._custody._request.borrow_body() as body:
                if getattr(connection, "sock", None) is not None: connection.sock.settimeout(self._remaining())
                self._wire_attempted = True
                connection.request("POST", self._post_path, body=body, headers=self._headers())
            response = connection.getresponse()
            status = response.status
            content_type = response.getheader("Content-Type")
            state = self._receive(response, connection, raw)
            encoding = response.getheader("Content-Encoding", "identity")
            encoding_qualified = type(encoding) is str and encoding.strip().lower() == "identity"
            if state == "complete" and not encoding_qualified:
                state = "encoded"
        except BaseException as error:
            pending = error
        finally:
            try:
                if self._wire_attempted and not self._capture_attempted:
                    self._capture_attempted = True
                    producer_valid = False
                    try:
                        self._source(); self._remaining()
                        producer_valid = encoding_qualified
                    except BaseException as error:
                        pending = pending or error
                    observed = self._custody.capture_original_response(raw, http_status=status,
                        content_type=content_type, body_state=state, producer_context_valid=producer_valid)
            except BaseException as error:
                pending = pending or error
            finally:
                _zeroize_mutable(raw)
                try: self._close(response, connection)
                except BaseException as error: pending = pending or error
        if pending is not None: raise pending
        if observed is None or not observed.success_ack_retained:
            raise JwtManualKeyCreateHttpError(_ERROR)
        return observed

    def _owned_get(self, index: int) -> bytearray:
        raw = bytearray()
        connection = response = None
        transferred = False
        try:
            if type(index) is not int or not 0 <= index < 4 or not self._wire_attempted:
                raise JwtManualKeyCreateHttpError(_ERROR)
            if not self._custody.inspect_original_response().success_ack_retained:
                raise JwtManualKeyCreateHttpError(_ERROR)
            connection = self._connect()
            self._source(); self._remaining()
            connection.request("GET", self._get_paths[index], headers=self._headers())
            response = connection.getresponse()
            if (type(response.status) is not int or response.status != 200
                    or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("Content-Encoding", "identity").strip().lower() != "identity"):
                raise JwtManualKeyCreateHttpError(_ERROR)
            if self._receive(response, connection, raw) != "complete": raise JwtManualKeyCreateHttpError(_ERROR)
            self._source(); self._remaining()
            transferred = True
            return raw
        finally:
            try: self._close(response, connection)
            except BaseException:
                _zeroize_mutable(raw)
                raise
            finally:
                if not transferred: _zeroize_mutable(raw)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            try:
                self._bound_plan(plan); self._source()
            except Exception:
                raise M4AdapterDenied(_ERROR) from None
            try:
                return jwt_manual_create_current_from_preflight(self._custody._request, self._reader.observe())
            except Exception:
                raise M4AdapterAmbiguous(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        with self._lock:
            buffers: list[bytearray] = []
            try:
                self._bound_plan(plan)
                if self._attempted: raise JwtManualKeyCreateHttpError(_ERROR)
                self._attempted = True
                self._custody._active()
                self._source()
                self._deadline = self._now() + min(30.0, float(self._config.timeout_seconds))
                self._post()
                for index in range(4): buffers.append(self._owned_get(index))
                self._custody.capture_original_owned_state(*buffers, baseline=self._baseline.state)
                self._source(); self._remaining()
            except Exception:
                raise M4AdapterAmbiguous(_ERROR) from None
            finally:
                self._deadline = None
                for raw in buffers: _zeroize_mutable(raw)
                self._custody._request.close()

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            buffers: list[bytearray] = []
            try:
                self._bound_plan(plan); self._source()
                original = self._custody.inspect_original_owned_state()
                self._deadline = self._now() + min(30.0, float(self._config.timeout_seconds))
                for index in range(4): buffers.append(self._owned_get(index))
                observed = consume_jwt_manual_key_owned_state(*buffers, request=self._custody._request,
                    baseline=self._baseline.state, witness_key=self._custody._key,
                    expected_full_row_hmac=original.state.full_row_hmac)
                if (self._custody.inspect_original_owned_state() != original
                        or observed.key_namespace_digest != original.state.key_namespace_digest):
                    raise JwtManualKeyCreateHttpError(_ERROR)
                self._source(); self._remaining()
                return observed.postcondition_digest
            except Exception:
                raise M4AdapterAmbiguous(_ERROR) from None
            finally:
                self._deadline = None
                for raw in buffers: _zeroize_mutable(raw)


__all__ = ["JwtManualKeyCreateHttpError", "JwtManualKeyCreateHttpTransport"]
