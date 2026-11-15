"""Private fixed GET and one compilation under an existing Owner window.

This candidate never logs in, resolves credentials, writes configuration or
logs out. Its host owns the borrowed window. A matching response envelope does
not qualify backend masking, the whole singleton, material custody or recovery.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import ExitStack, contextmanager
import hmac
import math
import ssl
from threading import RLock
from typing import Any, Iterator
from urllib.parse import urlsplit

from v4_planning.material_provider import _OpaqueC3Object

from .approval_delivery_material_contract import ApprovalDeliveryMaterialDraft, _bindings, _ROLES
from .approval_delivery_material_projection import (
    ApprovalDeliveryMaterialProjection, project_material_approval_delivery,
)
from .mutable_json_buffer import _erase_transfer_storage, _take_mutable_prefix
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import _ssl_context
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-build29-approval-email-cookie-source-local/v1"
CURRENT_PATH = "/api/v2/cmdb/secret/setting"
_LIMIT = 2 * 1024 * 1024
_ERROR = "The private approval-delivery source is unavailable."


class ApprovalDeliverySource(_OpaqueC3Object):
    """One private read; retain material only until close or one compilation.

    Binding digests are supplied private facts, never inferred provenance. No
    M4/provider lease, restoration authority or callable MCP binding is supplied.
    """

    def __init__(self, owner: OwnerSessionMetadataTransport, *, expected_actor: str,
            expected_serial: str, material_binding_digests: Mapping[str, str],
            source_guard: Callable[[], bool] | None = None) -> None:
        self._lock = RLock()
        self._cookie = bytearray()
        self._projection: ApprovalDeliveryMaterialProjection | None = None
        self._draft: ApprovalDeliveryMaterialDraft | None = None
        self._closed, self._attempted = False, False
        self._deadline: float | None = None
        self._deadline_cap: float | None = None
        self._last_now = -1.0
        try:
            if (type(owner) is not OwnerSessionMetadataTransport
                    or type(expected_actor) is not str or not expected_actor
                    or owner._owner_name != expected_actor or owner._client is None
                    or not owner._session_lock.locked()
                    or type(expected_serial) is not str or not 0 < len(expected_serial) <= 128
                    or source_guard is not None and not callable(source_guard)):
                raise ValueError
            bindings = _bindings(material_binding_digests)
            self._bindings = dict(zip(_ROLES, bindings, strict=True))
            self._owner, self._client, self._config = owner, owner._client, owner._config
            self._actor, self._serial = expected_actor, expected_serial
            self._guard = self._guard_pin = source_guard
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
            self._cookie = self._current_cookie()
            self._window()
        except BaseException as error:
            self.close()
            if isinstance(error, Exception):
                raise ValueError(_ERROR) from None
            raise

    def _now(self) -> float:
        now = self._clock()
        if (type(now) not in (int, float) or not math.isfinite(now)
                or now < 0 or now < self._last_now):
            self._closed = True
            raise ValueError
        self._last_now = float(now)
        return float(now)

    def _current_cookie(self) -> bytearray:
        value = self._client.build_request("GET", self._config.base_url.rstrip("/") + CURRENT_PATH).headers.get("cookie")
        if (type(value) is not str or not 1 <= len(value) <= 8192 or not value.isascii()
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError
        return bytearray(value.encode("ascii"))

    def _pinned_window(self) -> None:
        owner = self._owner
        if (self._closed or owner._client is not self._client or owner._config is not self._config
                or owner._owner_name != self._actor or not owner._session_lock.locked()
                or owner._expires_at != self._expiry
                or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2):
            raise ValueError

    def _cookie_continuity(self) -> None:
        current = self._current_cookie()
        try:
            if not hmac.compare_digest(current, self._cookie):
                raise ValueError
        finally:
            _erase_transfer_storage(current)

    def _window(self) -> None:
        self._pinned_window()
        if self._now() >= self._expiry:
            raise ValueError
        self._cookie_continuity()
        self._pinned_window()

    def _available(self) -> None:
        self._window()
        if self._guard is None or self._guard is not self._guard_pin or self._guard() is not True:
            raise ValueError
        # A guard is a callback: it may close the source, revoke or replace the
        # window, advance its clock, or change its own binding before returning.
        if self._guard is not self._guard_pin:
            raise ValueError
        self._window()

    def _remaining(self, deadline: float) -> float:
        self._available()
        remaining = min(deadline, self._expiry) - self._now()
        if remaining <= 0:
            raise ValueError
        return min(self._config.timeout_seconds, remaining)

    def _fetch(self, deadline: float) -> bytearray:
        raw = bytearray()
        try:
            with ExitStack() as resources:
                connection = self._factory(self._host, self._port,
                    context=self._tls, timeout=self._remaining(deadline))
                resources.callback(connection.close)
                connection.set_debuglevel(0)
                connection.connect()
                handle = connection.sock
                handle.settimeout(self._remaining(deadline))
                connection.request("GET", CURRENT_PATH, headers={"Cookie": self._cookie.decode("ascii"),
                    "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
                    "Cache-Control": "no-cache,no-store"})
                handle.settimeout(self._remaining(deadline))
                response = connection.getresponse()
                resources.callback(response.close)
                if (type(response.status) is not int or response.status != 200
                        or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"
                        or response.getheader("Content-Encoding", "identity").lower() != "identity"):
                    raise ValueError
                length, expected = response.getheader("Content-Length"), None
                if length is not None:
                    if (type(length) is not str or not length.isascii() or not length.isdecimal()
                            or len(length) > 7 or response.getheader("Transfer-Encoding") is not None):
                        raise ValueError
                    expected = int(length)
                    if not 0 < expected <= _LIMIT:
                        raise ValueError
                raw, offset = bytearray(_LIMIT + 1), 0
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
                if not 0 < offset <= _LIMIT or expected is not None and offset != expected:
                    raise ValueError
                raw = _take_mutable_prefix(raw, offset)
            # Complete both resource cleanups before returning any owned bytes.
            self._remaining(deadline)
            return raw
        except BaseException:
            _erase_transfer_storage(raw)
            raise

    def read(self) -> dict[str, object]:
        """Read once and return counts/flags, never configuration or material."""
        raw = bytearray()
        try:
            with self._lock, _private_http_logs():
                try:
                    if self._attempted:
                        raise ValueError
                    self._attempted = True
                    self._available()
                    self._deadline = min(self._now() + self._config.timeout_seconds, self._expiry)
                    if self._deadline_cap is not None:
                        self._deadline = min(self._deadline, self._deadline_cap)
                    raw = self._fetch(self._deadline)
                    self._projection = project_material_approval_delivery(raw, expected_serial=self._serial,
                        material_binding_digests=self._bindings)
                    self._remaining(self._deadline)
                    result = self.summary()
                finally:
                    _erase_transfer_storage(raw)
                return result
        except BaseException as error:
            self.close()
            if isinstance(error, Exception):
                raise ValueError(_ERROR) from None
            raise

    @contextmanager
    def _bounded_by(self, deadline: float) -> Iterator[None]:
        with self._lock:
            previous = self._deadline_cap
            self._deadline_cap = deadline if previous is None else min(previous, deadline)
            try:
                yield
            finally:
                self._deadline_cap = previous

    def _prepare_request(self, values: Mapping[str, Any], *, enabled: bool) -> ApprovalDeliveryMaterialDraft:
        try:
            with self._lock:
                if self._projection is None or self._deadline is None:
                    raise ValueError
                self._remaining(self._deadline)
                draft = self._projection._prepare_request(values, enabled=enabled)
                self._remaining(self._deadline)
                self._draft = draft
                return draft
        except BaseException as error:
            self.close()
            if isinstance(error, Exception):
                raise ValueError(_ERROR) from None
            raise

    def _compile_once(self, draft: ApprovalDeliveryMaterialDraft) -> bytearray:
        body = bytearray()
        try:
            with self._lock:
                try:
                    if self._projection is None or self._deadline is None or draft is not self._draft:
                        raise ValueError
                    self._remaining(self._deadline)
                    body = self._projection._compile_once(draft)
                    self._remaining(self._deadline)
                finally:
                    self.close()
            return body
        except BaseException as error:
            _erase_transfer_storage(body)
            if isinstance(error, Exception):
                raise ValueError(_ERROR) from None
            raise

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, fixed_get_completed=self._projection is not None,
            borrowed_physical_cookie_window_bound=True, closed=self._closed,
            model_field_count=14, protected_slot_count=3,
            native_current_response_contract_qualified=False, backend_masking_or_material_preservation_qualified=False,
            whole_setting_baseline_verified=False, material_binding_is_provenance=False,
            provider_lease_or_operation_replay_protection=False, partial_put_merge_qualified=False,
            restore_authorized=False, execution_authorized=False, configuration_written=False,
            login_or_logout_performed=False, protected_credentials_resolved=False)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._draft = None
            try:
                if self._projection is not None:
                    self._projection.close()
            finally:
                _erase_transfer_storage(self._cookie)
