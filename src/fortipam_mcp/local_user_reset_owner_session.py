"""Private, unregistered BP002 Owner session; never a runtime authorization.

Only one fixed policy/check then password-change pair can be dispatched by an
instance. A future live runner still needs a durable claim and independently
qualified inspector. No credential or arbitrary request interface is exposed.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hmac
from html.parser import HTMLParser
import http.client
from http.cookies import SimpleCookie
import json
import secrets
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .local_user_reset_http_transport import (
    LocalUserResetBinding, LocalUserResetHttpTransportError, _CHANGE_PATH,
    _MAX_RESPONSE, _Operation, _POLICY_PATH, _members, _response_flag,
)
from .secret_create_191_http_transport import _quoted_text, _valid_utf8
from .secret_metadata_http_transport import (
    SYSTEM_STATUS_PATH, SecretMetadataHttpTransportConfig, _json_value_end,
    _skip_json_space, _ssl_context, _zeroize_mutable,
)

_UNAVAILABLE = "The private Local User reset Owner session is unavailable."
_LOGIN = "/remote/login?lang=en"
_AUTH = "/XX/YY/ZZ/AUTH"
_MAX_BODY = 65_536


class _LoginForm(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.matches = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "form":
            values = dict(attrs)
            if values.get("action") == _AUTH:
                self.matches += 1


class LocalUserResetOwnerSessionTransport:
    """Fresh fixed-origin login with a default-off, lifetime one-shot write gate."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, *, owner_name: str,
        credentials: Callable[[], tuple[str, str]], binding: LocalUserResetBinding,
        enabled: bool = False, client_factory: Callable[..., Any] = httpx.Client,
        connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        try:
            parsed = urlsplit(config.base_url)
            port = 443 if parsed.port is None else parsed.port
            if (
                type(config) is not SecretMetadataHttpTransportConfig
                or parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or not 1 <= port <= 65535
                or type(binding) is not LocalUserResetBinding
                or not isinstance(owner_name, str) or not 1 <= len(owner_name) <= 64
                or any(ord(c) < 33 or ord(c) == 127 for c in owner_name)
                or owner_name.casefold() == binding.expected.username.casefold()
                or type(enabled) is not bool or not callable(credentials)
                or not callable(client_factory) or not callable(connection_factory)
                or not callable(clock)
            ):
                raise ValueError
            context = _ssl_context(config)
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise ValueError
        except Exception:
            raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None
        self._config, self._binding, self._owner_name = config, binding, owner_name
        self._host, self._port = parsed.hostname, port
        self._credentials, self._client_factory = credentials, client_factory
        self._connection_factory, self._clock = connection_factory, clock
        self._context, self._enabled = context, enabled
        self._lock, self._session_lock = threading.RLock(), threading.Lock()
        self._client: Any = None
        self._generation, self._expires_at = 0, 0.0
        self._reserved: set[str] = set()
        self._policy_accepted = False
        self._key = bytearray()
        self._material_tags: tuple[bytes, bytes] | None = None
        self._connections: list[_ResetConnection] = []
        self.logout_verified = False

    @contextmanager
    def authenticated(self) -> Iterator[LocalUserResetOwnerSessionTransport]:
        if not self._session_lock.acquire(blocking=False):
            raise LocalUserResetHttpTransportError(_UNAVAILABLE)
        client: Any = None
        attempted = failed = False
        try:
            self.logout_verified = False
            client = self._client_factory(
                base_url=self._config.base_url, verify=self._context,
                timeout=self._config.timeout_seconds, follow_redirects=False, trust_env=False,
                headers={"Accept-Encoding": "identity"},
            )
            with self._lock:
                self._client = client
                self._generation += 1
                self._key = bytearray(secrets.token_bytes(32))
            status, _, page = self._fixed_exchange("GET", _LOGIN, limit=_MAX_BODY)
            try:
                form = _LoginForm()
                form.feed(page.decode("utf-8"))
                if status != 200 or form.matches != 1:
                    raise ValueError
            finally:
                _zeroize_mutable(page)
            username, password = self._credentials()
            try:
                if username != self._owner_name or not isinstance(password, str) or not password:
                    raise ValueError
                attempted = True
                status, location, content = self._fixed_exchange("POST", _AUTH, data={
                    "username": username, "password": password, "magic": "0",
                    "4Tredir": "/", "4Tmthd": "0",
                })
            finally:
                del username, password
            _zeroize_mutable(content)
            origin = httpx.URL(self._config.base_url)
            destination = origin.join(location or "")
            redirect = urlsplit(location or "")
            if (
                status != 303 or not location or len(location) > 2048
                or redirect.scheme or redirect.netloc or redirect.fragment
                or not redirect.path.startswith("/") or redirect.path.startswith("//")
                or "%" in redirect.path
                or any(ord(character) < 33 or ord(character) > 126 for character in location)
                or destination.path == "/api" or destination.path.startswith("/api/")
                or destination.path in {_AUTH, "/logout"}
                or (destination.scheme, destination.host, destination.port)
                != (origin.scheme, origin.host, origin.port)
                or destination.username or destination.password
            ):
                raise ValueError
            # The accepted Owner metadata client visits the same-origin UI
            # landing once. Its status/body never authenticate this session;
            # only the subsequent fixed build-29 status read does.
            with self._client.stream("GET", str(destination)):
                pass
            status, _, content = self._fixed_exchange("GET", SYSTEM_STATUS_PATH)
            try:
                payload = json.loads(content)
                if (status != 200 or not isinstance(payload, dict)
                    or payload.get("version") not in {"v7.0.0", "7.0.0"}
                    or type(payload.get("build")) is not int or payload["build"] != 29):
                    raise ValueError
            finally:
                _zeroize_mutable(content)
            with self._lock:
                self._expires_at = self._clock() + 300
            yield self
        except Exception:
            failed = True
            raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None
        finally:
            cleanup_failed = False
            try:
                with self._lock:
                    self._generation += 1
                    self._expires_at = 0.0
                    self._policy_accepted = False
                    self._material_tags = None
                    _zeroize_mutable(self._key)
                    for connection in self._connections:
                        connection.close()
                    self._connections.clear()
                if client is not None and attempted:
                    status, _, content = self._fixed_exchange("GET", "/logout")
                    _zeroize_mutable(content)
                    denied, _, content = self._fixed_exchange("GET", SYSTEM_STATUS_PATH)
                    _zeroize_mutable(content)
                    self.logout_verified = status == 200 and denied in {401, 403}
            except Exception:
                self.logout_verified = False
            finally:
                if client is not None:
                    try:
                        client.cookies.clear()
                    except Exception:
                        cleanup_failed = True
                    try:
                        client.close()
                    except Exception:
                        cleanup_failed = True
                self._client = None
                self._session_lock.release()
            if attempted and (not self.logout_verified or cleanup_failed) and not failed:
                raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None

    def _fixed_exchange(
        self, method: str, path: str, *, data: dict[str, str] | None = None,
        limit: int = _MAX_RESPONSE,
    ) -> tuple[int, str | None, bytearray]:
        if ((method, path) not in {("GET", _LOGIN), ("POST", _AUTH),
            ("GET", "/logout"), ("GET", SYSTEM_STATUS_PATH)}
            or self._client is None or (data is not None) != (path == _AUTH)):
            raise LocalUserResetHttpTransportError(_UNAVAILABLE)
        content = bytearray()
        try:
            with self._client.stream(method, path, data=data) as response:
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise ValueError
                if path == SYSTEM_STATUS_PATH and response.status_code == 200:
                    if response.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
                        raise ValueError
                for chunk in response.iter_bytes(chunk_size=4096):
                    if len(content) + len(chunk) > limit:
                        raise ValueError
                    content.extend(chunk)
                return int(response.status_code), response.headers.get("location"), content
        except Exception:
            _zeroize_mutable(content)
            raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None

    def _active(self, generation: int) -> bool:
        return (self._client is not None and generation == self._generation
                and self._clock() < self._expires_at)

    def local_user_reset_connection(
        self, host: str, port: int, *, binding: LocalUserResetBinding, operation: _Operation,
        dispatch_guard: Callable[[], None] | None = None,
    ) -> _ResetConnection:
        with self._lock:
            if (not self._enabled or not self._active(self._generation)
                or host != self._host or type(port) is not int or port != self._port
                or binding is not self._binding or operation not in {"policy_conform", "change_password"}
                or (dispatch_guard is not None and not callable(dispatch_guard))
                or operation in self._reserved
                or operation == "change_password" and not self._policy_accepted):
                raise LocalUserResetHttpTransportError(_UNAVAILABLE)
            self._reserved.add(operation)
            try:
                raw = self._connection_factory(self._host, self._port,
                    timeout=self._config.timeout_seconds, context=self._context)
                connection = _ResetConnection(self, raw, operation, self._generation, dispatch_guard)
                self._connections.append(connection)
                return connection
            except Exception:
                raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None


class _ResetConnection:
    def __init__(self, owner: LocalUserResetOwnerSessionTransport, raw: Any,
                 operation: _Operation, generation: int,
                 dispatch_guard: Callable[[], None] | None = None) -> None:
        self._owner, self._raw = owner, raw
        self._operation, self._generation = operation, generation
        self._sent = self._received = self._closed = False
        self._response: _ResetResponse | None = None
        self._dispatch_guard = (lambda: None) if dispatch_guard is None else dispatch_guard

    def request(self, method: str, url: str, body: memoryview, headers: dict[str, str]) -> None:
        owner = self._owner
        with owner._lock:
            content = bytearray()
            try:
                if self._sent or self._closed or not owner._active(self._generation):
                    raise ValueError
                self._sent = True
                path = _POLICY_PATH if self._operation == "policy_conform" else _CHANGE_PATH
                if (method != "POST" or url != path or not isinstance(body, memoryview)
                    or not isinstance(body.obj, bytearray) or body.ndim != 1
                    or body.format != "B" or not body.c_contiguous or not 0 < body.nbytes <= _MAX_BODY
                    or headers != {"Accept": "application/json", "Content-Type": "application/json",
                        "Content-Length": str(body.nbytes), "Connection": "close"}):
                    raise ValueError
                content.extend(body)
                tags = _body_tags(content, owner._binding, self._operation, owner._key)
                if self._operation == "policy_conform":
                    owner._material_tags = tags
                elif (not owner._policy_accepted or owner._material_tags is None
                    or not all(hmac.compare_digest(a, b) for a, b in zip(tags, owner._material_tags))):
                    raise ValueError
                cookie = owner._client.build_request("GET", path).headers.get("cookie")
                if not cookie:
                    raise ValueError
                cookies: SimpleCookie = SimpleCookie()
                cookies.load(cookie)
                token = cookies.get("ccsrftoken")
                if (token is None or not token.value or len(token.value) > 4096
                    or any(ord(c) < 33 or ord(c) > 126 for c in token.value)):
                    raise ValueError
                safe_headers = {"Accept": "application/json", "Content-Type": "application/json",
                    "Content-Length": str(len(content)), "Connection": "close",
                    "Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store",
                    "Cookie": cookie, "X-CSRFTOKEN": token.value,
                    "User-Agent": owner._client.headers["User-Agent"]}
                # Send the validated snapshot, not mutable caller storage that
                # another thread could alter between validation and dispatch.
                with memoryview(content).toreadonly() as outgoing:
                    # Validate after waiting for the session lock, parsing the
                    # body and obtaining CSRF metadata, not only at the caller.
                    self._dispatch_guard()
                    if not owner._enabled or not owner._active(self._generation):
                        raise ValueError
                    self._raw.request("POST", path, body=outgoing, headers=safe_headers)
            except Exception:
                raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None
            finally:
                _zeroize_mutable(content)

    def getresponse(self) -> _ResetResponse:
        owner = self._owner
        with owner._lock:
            content = bytearray()
            pending_response: _ResetResponse | None = None
            try:
                content = bytearray(_MAX_RESPONSE + 1)
                raw: Any = None
                try:
                    if (not self._sent or self._received or self._closed
                        or not owner._active(self._generation)):
                        raise ValueError
                    self._received = True
                    raw = self._raw.getresponse()
                    if raw.getheader("content-encoding", "identity").lower() != "identity":
                        raise ValueError
                    status = raw.status
                    media = raw.getheader("content-type", "")
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
                    if self._operation == "policy_conform":
                        owner._policy_accepted = accepted
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
        self._closed = True
        if self._response is not None:
            self._response.close()
        try:
            self._raw.close()
        except Exception:
            pass


class _ResetResponse:
    def __init__(self, status: int, media: str, content: bytearray) -> None:
        self.status, self._media, self._content = status, media, content
        self._offset = 0

    def getheader(self, name: str, default: str = "") -> str:
        return self._media if name.lower() == "content-type" else default

    def readinto(self, buffer: memoryview) -> int:
        count = min(buffer.nbytes, len(self._content) - self._offset)
        with memoryview(self._content)[self._offset:self._offset + count] as view:
            buffer[:count] = view
        self._offset += count
        return count

    def close(self) -> None:
        _zeroize_mutable(self._content)
        self._offset = 0


def _body_tags(content: bytearray, binding: LocalUserResetBinding,
               operation: _Operation, key: bytearray) -> tuple[bytes, bytes]:
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError
    old_key = b'"old_password"'
    new_key = b'"password"' if operation == "policy_conform" else b'"new_password"'
    allowed = {b'"mkey"', old_key, new_key}
    if operation == "policy_conform":
        allowed.add(b'"apply_to"')
    fields = _members(content, start, end, allowed)
    if fields.keys() != allowed:
        raise ValueError
    expected = {b'"mkey"': binding.expected.username}
    if operation == "policy_conform":
        expected[b'"apply_to"'] = "guest-admin" if binding.expected.guest_auth == "enable" else "admin"
    for field, value in expected.items():
        encoded = bytearray()
        try:
            encoded = _quoted_text(value)
            left, right = fields[field]
            with memoryview(content)[left:right] as actual:
                if actual != encoded:
                    raise ValueError
        finally:
            _zeroize_mutable(encoded)
    tags: list[bytes] = []
    for field in (old_key, new_key):
        left, right = fields[field]
        with memoryview(content)[left:right] as token:
            if field == old_key:
                if len(token) != 2 or token[0] != 34 or token[1] != 34:
                    raise ValueError
            else:
                _validate_string(token)
            tags.append(hmac.digest(key, token, "sha256"))
    return tags[0], tags[1]


def _validate_string(token: memoryview) -> None:
    """Validate JSON encoding without making a decoded password string."""
    if len(token) < 3 or token[0] != 34 or token[-1] != 34 or not _valid_utf8(token):
        raise ValueError
    index = 1
    while index < len(token) - 1:
        value = token[index]
        if value < 32 or value == 34:
            raise ValueError
        if value == 92:
            index += 1
            if index >= len(token) - 1:
                raise ValueError
            if token[index] == 117:
                if index + 4 >= len(token) - 1 or any(
                    token[i] not in b"0123456789abcdefABCDEF" for i in range(index + 1, index + 5)
                ):
                    raise ValueError
                index += 4
            elif token[index] not in b'"\\/bfnrt':
                raise ValueError
        index += 1
