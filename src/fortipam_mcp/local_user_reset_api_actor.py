"""Private fixed API actor for the build-29 Local User reset candidate.

The bound bearer identity may submit the policy validator and, only after its
accepted result, one matching password change. This is a transport boundary,
not authorization to execute a reset or to register an MCP action.
"""

from __future__ import annotations

from contextlib import contextmanager
import hmac
import http.client
import secrets
import ssl
import threading
import time
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .local_user_reset_http_transport import (
    LocalUserResetBinding, LocalUserResetHttpTransportError, _CHANGE_PATH,
    _MAX_RESPONSE, _Operation, _POLICY_PATH, _response_flag,
)
from .local_user_reset_owner_session import _ResetResponse, _body_tags
from .local_user_reset_provenance_inspector import FortiPamLocalUserResetProvenanceInspector
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable,
)

_UNAVAILABLE = "The private Local User reset API actor is unavailable."
_MAX_BODY = 65_536


class LocalUserResetApiActor:
    """Short-lived, one-use transport bound to the existing API principal."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, *, binding: LocalUserResetBinding,
        inspector: FortiPamLocalUserResetProvenanceInspector, enabled: bool = False,
        connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        try:
            parsed = urlsplit(config.base_url)
            port = 443 if parsed.port is None else parsed.port
            context = _ssl_context(config)
            if (
                type(config) is not SecretMetadataHttpTransportConfig
                or parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or not 1 <= port <= 65535
                or type(binding) is not LocalUserResetBinding
                or type(inspector) is not FortiPamLocalUserResetProvenanceInspector
                or inspector._config is not config
                or type(enabled) is not bool or not callable(connection_factory)
                or not callable(clock)
                or context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname
            ):
                raise ValueError
        except Exception:
            raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None
        self._config, self._binding, self._inspector = config, binding, inspector
        self._host, self._port, self._context = parsed.hostname, port, context
        self._connection_factory, self._clock, self._enabled = connection_factory, clock, enabled
        self._session_lock, self._lock = threading.Lock(), threading.RLock()
        self._generation, self._expires_at = 0, 0.0
        self._key = bytearray()
        self._reserved: set[str] = set()
        self._material_tags: tuple[bytes, bytes] | None = None
        self._policy_accepted = False
        self._connections: list[_ApiResetConnection] = []
        self._runtime_guard: Callable[[], None] | None = None
        self._observations: dict[str, dict[str, object]] = {}

    @contextmanager
    def authenticated(self) -> Iterator[LocalUserResetApiActor]:
        """Pin a fresh exact target/actor read for one bounded API operation."""
        if not self._session_lock.acquire(blocking=False):
            raise LocalUserResetHttpTransportError(_UNAVAILABLE)
        try:
            baseline = self._inspector.read_nonmaterial_baseline()
            if type(baseline) is not type(self._binding.expected) or baseline != self._binding.expected:
                raise ValueError
            with self._lock:
                self._generation += 1
                self._expires_at = self._clock() + 300
                self._key = bytearray(secrets.token_bytes(32))
                self._reserved.clear()
                self._material_tags = None
                self._policy_accepted = False
                self._observations.clear()
            yield self
        except Exception:
            raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None
        finally:
            with self._lock:
                self._generation += 1
                self._expires_at = 0.0
                self._policy_accepted = False
                self._material_tags = None
                self._runtime_guard = None
                _zeroize_mutable(self._key)
                for connection in self._connections:
                    connection.close()
                self._connections.clear()
            self._session_lock.release()

    def _active(self, generation: int) -> bool:
        return bool(self._key) and generation == self._generation and self._clock() < self._expires_at

    def local_user_reset_connection(
        self, host: str, port: int, *, binding: LocalUserResetBinding, operation: _Operation,
        dispatch_guard: Callable[[], None] | None = None,
    ) -> _ApiResetConnection:
        with self._lock:
            if (
                not self._enabled or not self._active(self._generation)
                or host != self._host or type(port) is not int or port != self._port
                or binding is not self._binding or operation not in {"policy_conform", "change_password"}
                or dispatch_guard is None or dispatch_guard is not self._runtime_guard
                or not getattr(getattr(dispatch_guard, "__self__", None), "_claim_active", False)
                or not getattr(getattr(getattr(dispatch_guard, "__self__", None), "_verifier", None),
                               "_verified", False)
                or operation in self._reserved
                or operation == "change_password" and not self._policy_accepted
            ):
                raise LocalUserResetHttpTransportError(_UNAVAILABLE)
            self._reserved.add(operation)
            self._observations[operation] = {"connection_reserved": True,
                                             "request_sent": False,
                                             "response_received": False,
                                             "accepted": False}
            try:
                raw = self._connection_factory(self._host, self._port,
                    timeout=self._config.timeout_seconds, context=self._context)
                connection = _ApiResetConnection(self, raw, operation, self._generation, dispatch_guard)
                self._connections.append(connection)
                return connection
            except Exception:
                raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None


class _ApiResetConnection:
    def __init__(
        self, actor: LocalUserResetApiActor, raw: Any, operation: _Operation,
        generation: int, dispatch_guard: Callable[[], None],
    ) -> None:
        self._actor, self._raw = actor, raw
        self._operation, self._generation, self._guard = operation, generation, dispatch_guard
        self._sent = self._received = self._closed = False
        self._response: _ResetResponse | None = None

    def request(self, method: str, url: str, body: memoryview, headers: dict[str, str]) -> None:
        actor = self._actor
        with actor._lock:
            content = bytearray()
            try:
                if self._sent or self._closed or not actor._active(self._generation):
                    raise ValueError
                self._sent = True
                path = _POLICY_PATH if self._operation == "policy_conform" else _CHANGE_PATH
                if (
                    method != "POST" or url != path or not isinstance(body, memoryview)
                    or not isinstance(body.obj, bytearray) or body.ndim != 1
                    or body.format != "B" or not body.c_contiguous
                    or not 0 < body.nbytes <= _MAX_BODY
                    or headers != {"Accept": "application/json", "Content-Type": "application/json",
                        "Content-Length": str(body.nbytes), "Connection": "close"}
                ):
                    raise ValueError
                content.extend(body)
                tags = _body_tags(content, actor._binding, self._operation, actor._key)
                if self._operation == "policy_conform":
                    actor._material_tags = tags
                elif (
                    not actor._policy_accepted or actor._material_tags is None
                    or not all(hmac.compare_digest(a, b) for a, b in zip(tags, actor._material_tags))
                ):
                    raise ValueError
                safe_headers = {
                    "Authorization": "Bearer " + actor._config.bearer_token,
                    "Accept": "application/json", "Content-Type": "application/json",
                    "Content-Length": str(len(content)), "Connection": "close",
                    "Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store",
                    "User-Agent": "fortipam-bp002-bound-api-reset/1",
                }
                with memoryview(content).toreadonly() as outgoing:
                    self._guard()
                    if not actor._enabled or not actor._active(self._generation):
                        raise ValueError
                    self._raw.request("POST", path, body=outgoing, headers=safe_headers)
                    actor._observations[self._operation]["request_sent"] = True
            except Exception:
                raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None
            finally:
                _zeroize_mutable(content)

    def getresponse(self) -> _ResetResponse:
        actor = self._actor
        with actor._lock:
            content = bytearray()
            pending_response: _ResetResponse | None = None
            try:
                content = bytearray(_MAX_RESPONSE + 1)
                raw: Any = None
                try:
                    if not self._sent or self._received or self._closed or not actor._active(self._generation):
                        raise ValueError
                    self._received = True
                    raw = self._raw.getresponse()
                    if raw.getheader("content-encoding", "identity").lower() != "identity":
                        raise ValueError
                    status = raw.status
                    media = raw.getheader("content-type", "")
                    actor._observations[self._operation]["response_received"] = True
                    actor._observations[self._operation]["http_status"] = (
                        status if type(status) is int and status in {200, 400, 401, 403, 404, 405, 409, 422, 429}
                        else "other")
                    if type(status) is not int or media.split(";", 1)[0].strip().lower() != "application/json":
                        raise ValueError
                    total = 0
                    while total < len(content):
                        with memoryview(content)[total:] as view:
                            count = raw.readinto(view)
                        if type(count) is not int or not 0 <= count <= len(content) - total:
                            raise ValueError
                        if count == 0:
                            break
                        total += count
                    if total > _MAX_RESPONSE:
                        raise ValueError
                    content = _take_mutable_prefix(content, total)
                    accepted = status == 200 and _response_flag(content, self._operation)
                    actor._observations[self._operation]["accepted"] = accepted
                    if self._operation == "policy_conform":
                        actor._policy_accepted = accepted
                    self._response = _ResetResponse(status, media, content)
                    pending_response = self._response
                    content = bytearray()
                    return self._response
                except Exception:
                    raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None
                finally:
                    _zeroize_mutable(content)
                    if raw is not None:
                        try:
                            raw.close()
                        except Exception:
                            pass
            except BaseException:
                try:
                    _erase_transfer_storage(content)
                finally:
                    if pending_response is not None:
                        try:
                            pending_response.close()
                        finally:
                            _erase_transfer_storage(pending_response._content)
                raise

    def close(self) -> None:
        with self._actor._lock:
            if not self._closed:
                self._closed = True
                try:
                    self._raw.close()
                finally:
                    if self._response is not None:
                        self._response.close()
