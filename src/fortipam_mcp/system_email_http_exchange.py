"""Private shared exchange for exactly two system-email HTTP candidates.

Routes/bodies have retained static source evidence. ACK envelopes remain local
candidates, not qualified native contracts. This module has no runtime binding.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import http.client
import math
import ssl
import time
from typing import Any, Literal

from v4_planning.material_provider import _OpaqueC3Object
from .mutable_json_buffer import _take_mutable_prefix
from . import secret_bulk_import_metadata as metadata
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .system_email_delivery_contract import TEST_MESSAGE_PATH
from .system_email_native_source import SystemEmailNativeSource, _PATH

_ERROR = "The private system-email HTTP exchange is unavailable."
_MAX_ACK_BYTES = 16384
_ACK_REQUIRED = {"http_method", "http_status", "status", "path", "name", "serial", "version", "build"}
_ACK_OPTIONAL = {"vdom", "revision", "revision_changed", "mkey", "error"}

@dataclass(frozen=True, slots=True, repr=False)
class SystemEmailOriginalHttpAck(_OpaqueC3Object):
    """Digest of this backend's original response, not native qualification."""
    source_serial_digest: str
    request_digest: str
    response_digest: str


def _candidate_ack(raw: bytearray, serial: str, request_digest: str, operation: str) -> SystemEmailOriginalHttpAck:
    left = _skip_json_space(raw, 0)
    right = _json_value_end(raw, left)
    if _skip_json_space(raw, right) != len(raw):
        raise ValueError
    metadata._validate_json(raw, left, right, depth=0, budget=[256])
    fields = _object_spans(raw, left, right)
    required = _ACK_REQUIRED | ({"action"} if operation == "test-delivery" else set())
    optional = _ACK_OPTIONAL if operation == "configuration" else {"vdom", "error"}
    if not required <= set(fields) <= required | optional:
        raise ValueError
    expected = dict(http_method="PUT" if operation == "configuration" else "POST",
                    http_status=200, path="system",
                    name="email-server" if operation == "configuration" else "debug",
                    serial=serial, version="v7.0.0", build=29)
    if operation == "test-delivery":
        expected["action"] = "email"
    for name, value in expected.items():
        actual = metadata._scalar(raw, fields[name])
        if type(actual) is not type(value) or actual != value:
            raise ValueError
    if metadata._scalar(raw, fields["status"]) not in ("success", "OK"):
        raise ValueError
    for optional_name, optional_value in dict(vdom="root", mkey="", error=0, revision_changed=True).items():
        if optional_name in fields:
            actual = metadata._scalar(raw, fields[optional_name])
            if type(actual) is not type(optional_value) or actual != optional_value:
                raise ValueError
    if "revision" in fields:
        revision = metadata._scalar(raw, fields["revision"])
        if (type(revision) is not str or not 1 <= len(revision) <= 256
                or any(ord(c) < 32 or ord(c) == 127 for c in revision)):
            raise ValueError
    return SystemEmailOriginalHttpAck(hashlib.sha256(serial.encode()).hexdigest(),
        request_digest, hashlib.sha256(raw).hexdigest())


class _SystemEmailHttpExchange(_OpaqueC3Object):
    def __init__(self, source: SystemEmailNativeSource, *,
                 execution_enabled: Callable[[], bool] | None = None,
                 source_guard: Callable[[], bool] | None = None,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 http_clock: Callable[[], float] = time.monotonic) -> None:
        if (type(source) is not SystemEmailNativeSource or not callable(connection_factory)
                or not callable(http_clock)
                or any(value is not None and not callable(value) for value in (execution_enabled, source_guard))):
            raise ValueError(_ERROR)
        self._source, self._config = source, source._config
        self._enabled, self._source_guard = execution_enabled, source_guard
        self._factory, self._clock = connection_factory, http_clock
        self._closed = self._failed_clock = False
        self._last_time: float | None = None

    def _available(self, *, write: bool = False) -> None:
        if (self._closed or self._source._closed or self._source._config is not self._config
                or not self._source._context.check_hostname
                or self._source._context.verify_mode != ssl.CERT_REQUIRED):
            raise ValueError
        if write and (self._enabled is None or self._enabled() is not True
                      or self._source_guard is None or self._source_guard() is not True):
            raise ValueError

    def _now(self) -> float:
        try:
            now = self._clock()
            if (self._failed_clock or type(now) not in (int, float) or not math.isfinite(now) or now < 0
                    or self._last_time is not None and now < self._last_time):
                raise ValueError
            self._last_time = float(now)
            return float(now)
        except Exception:
            self._failed_clock = True
            raise ValueError from None

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._now()
        if remaining <= 0:
            raise ValueError
        return min(self._config.timeout_seconds, remaining)

    def exchange(self, operation: Literal["configuration", "test-delivery"], body: bytearray,
                 request_digest: str, before_send: Callable[[], int],
             timeout_seconds: int) -> SystemEmailOriginalHttpAck:
        connection = response = None
        raw = bytearray()
        try:
            if operation not in ("configuration", "test-delivery"):
                raise ValueError
            deadline = self._now() + min(self._config.timeout_seconds, timeout_seconds)
            context = self._source._context
            context.minimum_version = max(context.minimum_version, ssl.TLSVersion.TLSv1_2)
            self._available(write=True)
            connection = self._factory(self._source._host, self._source._port,
                context=context, timeout=self._remaining(deadline))
            connection.set_debuglevel(0)
            connection.connect()
            socket = connection.sock
            self._available(write=True)
            self._remaining(deadline)
            # The real adapter rechecks kernel/thread, authority, drift and the
            # checkpoint after TLS setup, immediately before request egress.
            budget = before_send()
            if type(budget) is not int or budget <= 0:
                raise ValueError
            now = self._now()
            deadline = min(deadline, now + budget)
            self._available(write=True)
            socket.settimeout(self._remaining(deadline))
            method, path = ("PUT", _PATH) if operation == "configuration" else ("POST", TEST_MESSAGE_PATH)
            connection.request(method, path, body=body, headers={
                "Authorization": "Bearer " + self._config.bearer_token,
                "Accept": "application/json", "Content-Type": "application/json",
                "Accept-Encoding": "identity", "Connection": "close",
                "Cache-Control": "no-cache,no-store", "User-Agent": "fortipam-mcp-system-email-candidate/1"})
            _zeroize_mutable(body)
            socket.settimeout(self._remaining(deadline))
            response = connection.getresponse()
            if (type(response.status) is not int or response.status != 200
                    or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("Content-Encoding", "identity").strip().lower() != "identity"):
                raise ValueError
            length_header = response.getheader("Content-Length")
            expected_length = None
            if length_header is not None:
                if (type(length_header) is not str or not 1 <= len(length_header) <= 5
                        or not length_header.isascii() or not length_header.isdecimal()
                        or response.getheader("Transfer-Encoding") is not None):
                    raise ValueError
                expected_length = int(length_header)
                if not 0 < expected_length <= _MAX_ACK_BYTES:
                    raise ValueError
            raw = bytearray(_MAX_ACK_BYTES + 1)
            offset = 0
            while offset < len(raw):
                remaining = self._remaining(deadline)
                # HTTPResponse closes the socket after its last length-framed
                # read. Its next readinto still returns EOF; setting a timeout
                # on the now-closed TLS socket would reject a complete ACK.
                if not response.isclosed():
                    socket.settimeout(remaining)
                with memoryview(raw)[offset:] as part:
                    count = response.readinto(part)
                if type(count) is not int or not 0 <= count <= len(raw) - offset:
                    raise ValueError
                if count == 0:
                    break
                offset += count
            if (not 0 < offset <= _MAX_ACK_BYTES
                    or expected_length is not None and offset != expected_length):
                raise ValueError
            raw = _take_mutable_prefix(raw, offset)
            self._available(write=True)
            self._remaining(deadline)
            ack = _candidate_ack(raw, self._source._serial, request_digest, operation)
        finally:
            _zeroize_mutable(body)
            _zeroize_mutable(raw)
            failed = False
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        failed = True
            if failed:
                raise ValueError(_ERROR) from None
        self._available(write=True)
        self._remaining(deadline)
        return ack

    def close(self) -> None:
        self._closed = True
