"""Default-denied, fixed license-status GET under a borrowed Owner window.

The host owns authentication and logout. No frontend polling helper, CSF proxy,
FortiGuard update, license upload or configuration request is used here.
The optional static-symbol GET needs an explicit host scope and the same guard.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack
import hmac
from http.cookiejar import Cookie, CookieJar
import math
import ssl
from threading import RLock
from time import monotonic as _monotonic
from urllib.parse import urlsplit

import httpx

from v4_planning.material_provider import _OpaqueC3Object

from .license_vm_projection import LicenseVmProjection, MAX_BYTES, STATUS_PATH, project_provided_license_vm
from .license_status_symbols import BUILD_PATH, _decode_static_symbols
from .mutable_json_buffer import _clear_mutable_group, _erase_transfer_storage, _take_mutable_prefix
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import _ssl_context
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-build29-license-vm-cookie-source-local/v1"
_ERROR = "The private license VM source is unavailable."


class LicenseVmSource(_OpaqueC3Object):
    """One private observation, not a complete license or installation baseline.

    The projection remains private and usable only while this exact source and
    its original borrowed window remain valid. Closing releases our references
    and Cookie copy; it never closes the host's client or logs its Owner out.
    """

    def __init__(self, owner: OwnerSessionMetadataTransport, *, expected_actor: str,
            expected_serial: str, source_guard: Callable[[], bool] | None = None,
            include_static_symbols: bool = False) -> None:
        self._lock = RLock()
        self._cookie = bytearray()
        self._projection: LicenseVmProjection | None = None
        self._closed, self._attempted = False, False
        self._deadline: float | None = None
        self._monotonic_deadline: float | None = None
        self._last_now = -1.0
        try:
            if (type(owner) is not OwnerSessionMetadataTransport
                    or type(expected_actor) is not str or not expected_actor
                    or owner._owner_name != expected_actor or type(owner._client) is not httpx.Client
                    or not owner._session_lock.locked()
                    or type(expected_serial) is not str or not 0 < len(expected_serial) <= 128
                    or source_guard is not None and not callable(source_guard)
                    or type(include_static_symbols) is not bool):
                raise ValueError
            self._owner, self._client, self._config = owner, owner._client, owner._config
            self._cookie_jar = self._client.cookies.jar
            if type(self._cookie_jar) is not CookieJar:
                raise ValueError
            self._cookie_pin = self._cookie_state()
            # Keep the original objects/field values alive: raw id snapshots
            # alone could be fooled by allocator reuse after a jar replacement.
            self._cookie_anchors = tuple((cookie, tuple(vars(cookie).items()),
                tuple(vars(cookie)["_rest"].items())) for cookie in self._cookie_jar)
            self._session_lock = owner._session_lock
            self._actor, self._serial = expected_actor, expected_serial
            self._guard = self._guard_pin = source_guard
            # Opt-in host scope: its qualified guard must cover both fixed GETs.
            # No MCP argument or environment switch enables the additional read.
            self._static_symbols = self._static_symbols_pin = include_static_symbols
            self._expiry = owner._expires_at
            if type(self._expiry) not in (int, float) or not math.isfinite(self._expiry) or self._expiry <= 0:
                raise ValueError
            self._clock, self._factory = owner._clock, owner._raw_connection_factory
            url = urlsplit(self._config.base_url)
            if (url.scheme != "https" or not url.hostname or url.username is not None
                    or url.password is not None or url.path not in ("", "/") or url.query or url.fragment):
                raise ValueError
            self._host, self._port = url.hostname, url.port or 443
            self._tls = _ssl_context(self._config)
            self._tls.minimum_version = max(self._tls.minimum_version, ssl.TLSVersion.TLSv1_2)
            self._tls_pin = self._tls
            self._cookie = self._current_cookie()
            self._window()
        except BaseException as error:
            self.close()
            if isinstance(error, Exception):
                raise ValueError(_ERROR) from None
            raise

    def _pinned_window(self) -> None:
        owner = self._owner
        if (self._closed or owner._client is not self._client or owner._config is not self._config
                or type(self._client.headers) is not httpx.Headers or "cookie" in self._client.headers
                or owner._owner_name != self._actor or owner._expires_at != self._expiry
                or owner._session_lock is not self._session_lock or not self._session_lock.locked()
                or owner._clock is not self._clock or owner._raw_connection_factory is not self._factory
                or self._guard is not self._guard_pin
                or self._static_symbols is not self._static_symbols_pin
                or self._tls is not self._tls_pin
                or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2):
            raise ValueError

    def _cookie_state(self) -> tuple[object, ...]:
        # Exact stdlib CookieJar and its data objects: no host callback, request
        # builder, decoding, hashing or new material strings after the guard.
        if type(self._client.cookies) is not httpx.Cookies or self._client.cookies.jar is not self._cookie_jar:
            raise ValueError
        rows = []
        for cookie in self._cookie_jar:
            if type(cookie) is not Cookie:
                raise ValueError
            attributes = vars(cookie)
            rest = attributes.get("_rest")
            if type(rest) is not dict:
                raise ValueError
            rows.append((id(cookie), tuple((id(name), id(value)) for name, value in attributes.items()),
                tuple((id(name), id(value)) for name, value in rest.items())))
        return tuple(rows)

    def _now(self) -> float:
        now = self._clock()
        self._pinned_window()
        if (type(now) not in (int, float) or not math.isfinite(now)
                or now < 0 or now < self._last_now):
            raise ValueError
        self._last_now = float(now)
        return float(now)

    def _current_cookie(self) -> bytearray:
        value = self._client.build_request("GET", self._config.base_url.rstrip("/") + STATUS_PATH).headers.get("cookie")
        if (type(value) is not str or not 1 <= len(value) <= 8192 or not value.isascii()
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError
        return bytearray(value.encode("ascii"))

    def _window(self) -> float:
        self._pinned_window()
        now = self._now()
        if now >= self._expiry:
            raise ValueError
        current = self._current_cookie()
        try:
            if not hmac.compare_digest(current, self._cookie):
                raise ValueError
        finally:
            _erase_transfer_storage(current)
        # In particular, a clock callback cannot change the Cookie after its
        # final comparison and still obtain a request or private observation.
        self._pinned_window()
        return now

    def _available(self) -> float:
        now = self._window()
        if self._guard is None or self._guard() is not True:
            raise ValueError
        # The authorization callback is last. Only local pinned data and the
        # trusted monotonic budget are checked afterward, never another host
        # clock/request callback that could revoke this decision in turn.
        self._pinned_window()
        if self._cookie_state() != self._cookie_pin:
            raise ValueError
        return now

    def _remaining(self, deadline: float) -> float:
        now = self._available()
        if self._monotonic_deadline is None:
            raise ValueError
        remaining = min(min(deadline, self._expiry) - now, self._monotonic_deadline - _monotonic())
        if remaining <= 0:
            raise ValueError
        return min(self._config.timeout_seconds, remaining)

    def _fetch(self, deadline: float, *, static_symbols: bool = False) -> bytearray:
        raw = bytearray()
        decoded: bytearray | None = None
        try:
            if static_symbols and not self._static_symbols_pin: raise ValueError
            with ExitStack() as resources:
                connection = self._factory(self._host, self._port,
                    context=self._tls, timeout=self._remaining(deadline))
                resources.callback(connection.close)
                connection.set_debuglevel(0)
                connection.connect()
                handle = connection.sock
                handle.settimeout(self._remaining(deadline))
                connection.request("GET", BUILD_PATH if static_symbols else STATUS_PATH, headers={"Cookie": self._cookie.decode("ascii"),
                    "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
                    "Cache-Control": "no-cache,no-store"})
                handle.settimeout(self._remaining(deadline))
                response = connection.getresponse()
                resources.callback(response.close)
                encoding = response.getheader("Content-Encoding", "identity").lower()
                if static_symbols: encoding = encoding.strip()
                if (type(response.status) is not int or response.status != 200
                        or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"
                        or encoding not in (('', 'identity', 'gzip', 'deflate') if static_symbols else ('identity',))):
                    raise ValueError
                length, expected = response.getheader("Content-Length"), None
                if length is not None:
                    if (type(length) is not str or not length.isascii() or not length.isdecimal()
                            or len(length) > 7 or response.getheader("Transfer-Encoding") is not None):
                        raise ValueError
                    expected = int(length)
                    if not 0 < expected <= MAX_BYTES:
                        raise ValueError
                raw, offset = bytearray(MAX_BYTES + 1), 0
                while offset < len(raw):
                    remaining = self._remaining(deadline)
                    if not response.isclosed():
                        handle.settimeout(remaining)
                    with memoryview(raw)[offset:] as view:
                        count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(raw) - offset:
                        raise ValueError
                    if not count:
                        break
                    offset += count
                if not 0 < offset <= MAX_BYTES or expected is not None and offset != expected:
                    raise ValueError
                raw = _take_mutable_prefix(raw, offset)
            # No bytes or projection may escape failed response/connection cleanup.
            self._remaining(deadline)
            if static_symbols:
                decoded = _decode_static_symbols(raw, encoding)
                if decoded is not raw: _erase_transfer_storage(raw)
                self._remaining(deadline)
                return decoded
            return raw
        except BaseException:
            _clear_mutable_group((raw, decoded), _erase_transfer_storage)
            raise

    def read(self, *, monotonic_deadline: float | None = None) -> dict[str, object]:
        """Observe once; return structure/flags without license values or IDs."""
        raw = bytearray()
        symbols: bytearray | None = None
        try:
            with self._lock, _private_http_logs():
                try:
                    if self._attempted:
                        raise ValueError
                    self._attempted = True
                    if monotonic_deadline is not None and (type(monotonic_deadline) not in (int, float)
                            or not math.isfinite(monotonic_deadline)):
                        raise ValueError
                    # Start the total budget before the first host read guard.
                    started = _monotonic()
                    now = self._now()
                    self._deadline = min(now + self._config.timeout_seconds, self._expiry)
                    self._monotonic_deadline = started + self._deadline - now
                    if monotonic_deadline is not None:
                        self._monotonic_deadline = min(self._monotonic_deadline, monotonic_deadline)
                    raw = self._fetch(self._deadline)
                    if self._static_symbols_pin:
                        symbols = self._fetch(self._deadline, static_symbols=True)
                    projection = project_provided_license_vm(raw, expected_serial=self._serial, static_symbols=symbols)
                    self._remaining(self._deadline)
                    self._projection = projection
                    return self.summary()
                finally:
                    _clear_mutable_group((raw, symbols), _erase_transfer_storage)
        except BaseException as error:
            self.close()
            if isinstance(error, Exception):
                raise ValueError(_ERROR) from None
            raise

    def _current(self) -> LicenseVmProjection:
        """Revalidate before a host privately consumes the partial observation."""
        try:
            with self._lock:
                if self._projection is None or self._deadline is None:
                    raise ValueError
                self._remaining(self._deadline)
                if self._projection is None:
                    raise ValueError
                return self._projection
        except BaseException as error:
            self.close()
            if isinstance(error, Exception):
                raise ValueError(_ERROR) from None
            raise

    def summary(self) -> dict[str, object]:
        public = dict(contract=CONTRACT, fixed_get_completed=self._projection is not None,
            borrowed_physical_cookie_window_bound=True, closed=self._closed,
            projection=self._projection.summary() if self._projection is not None else None,
            frontend_polling_helper_invoked=False, fortiguard_update_requested=False,
            native_response_contract_qualified=False, whole_license_state_verified=False,
            deployment_or_ha_verified=False, entitlement_verified=False,
            post_boot_license_verified=False, installation_authorized=False,
            configuration_written=False, login_or_logout_performed=False,
            protected_credentials_resolved=False)
        if self._static_symbols_pin:
            public.update(static_symbol_get_completed=self._projection is not None, observations_are_atomic=False)
        return public

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._projection = None
            self._cookie_pin = ()
            self._cookie_anchors = ()
            _erase_transfer_storage(self._cookie)
