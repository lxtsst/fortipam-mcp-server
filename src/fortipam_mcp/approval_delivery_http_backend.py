"""Default-closed fixed singleton PUT using a borrowed Owner Cookie window.

The ACK grammar is a strict LOCAL CANDIDATE, not an observed native contract.
No login, credentials, resolver or startup/MCP binding is provided. Native ACK,
whole-singleton and material semantics still require independent qualification.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack, contextmanager
from http.cookies import SimpleCookie
import hmac
from threading import RLock
from types import MethodType
from typing import Any, Iterator

from v4_planning import canonical_digest
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as metadata
from .approval_delivery_contract import _wire
from .approval_delivery_execution_contract import ApprovalDeliveryExecutionIntent, ApprovalDeliveryReadback, readback_from_approval_source
from .approval_delivery_material_contract import ApprovalDeliveryMaterialDraft, _ROLES, build_approval_delivery_material_body
from .approval_delivery_material import ApprovalDeliveryMaterialProvider
from .approval_delivery_m4 import ApprovalDeliveryBackendReceipt, ApprovalDeliveryM4Adapter
from .approval_delivery_schema import _members
from .approval_delivery_source import ApprovalDeliverySource, CURRENT_PATH
from .mutable_json_buffer import _erase_transfer_storage, _take_mutable_prefix
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import _json_value_end, _skip_json_space
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-build29-approval-email-fixed-http-local/v1"
_ERROR = "The private approval-delivery HTTP candidate is unavailable."
_ACK_KEYS = frozenset({"http_method", "http_status", "status", "serial", "version", "build", "path", "name"})
_ACK_OPTIONAL = frozenset({"vdom", "revision", "revision_changed", "error"})


def _ack_candidate(raw: bytearray, serial: str) -> None:
    start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
    if _skip_json_space(raw, end) != len(raw): raise ValueError
    metadata._validate_json(raw, start, end, depth=0, budget=[512])
    fields, count = _members(raw, (start, end), _ACK_KEYS | _ACK_OPTIONAL)
    if count != len(fields) or not _ACK_KEYS <= fields.keys(): raise ValueError
    expected = dict(http_method="PUT", http_status=200, status="success", serial=serial,
        version="v7.0.0", build=29, path="secret", name="setting")
    for key, value in expected.items():
        with memoryview(raw)[slice(*fields[key])] as token:
            if not hmac.compare_digest(token, _wire(value)): raise ValueError
    for key, value in dict(vdom="root", revision_changed=True, error=0).items():
        if key in fields:
            with memoryview(raw)[slice(*fields[key])] as token:
                if not hmac.compare_digest(token, _wire(value)): raise ValueError
    if "revision" in fields:
        left, right = fields["revision"]
        if raw[left] != 34 or not 2 < right-left <= 1024: raise ValueError


def _matching_body(body: memoryview, draft: ApprovalDeliveryMaterialDraft,
        provider: ApprovalDeliveryMaterialProvider) -> bytearray:
    raw, expected = bytearray(), bytearray()
    try:
        try:
            if (type(body) is not memoryview or not body.readonly or body.format != "B" or body.ndim != 1
                    or type(body.obj) is not bytearray or not body.c_contiguous or not 0 < body.nbytes <= 131072
                    or type(provider) is not ApprovalDeliveryMaterialProvider or not provider._consumed or provider._closed
                    or provider._lease is None or len(provider._buffers) != 3): raise ValueError
            with ExitStack() as stack:
                views = {role: stack.enter_context(memoryview(buffer).toreadonly())
                    for role, buffer in zip(_ROLES, provider._buffers, strict=True)}
                expected = build_approval_delivery_material_body(draft, username=views["username"], credential=views["credential"],
                    client_secret=views["client-secret"], material_binding_digests=dict(zip(_ROLES, draft._binding_digests, strict=True)))
            if not hmac.compare_digest(body, expected): raise ValueError
            raw = bytearray(body)
        finally:
            _erase_transfer_storage(expected)
        return raw
    except BaseException:
        _erase_transfer_storage(raw)
        raise


class ApprovalDeliveryHttpBackend(_OpaqueC3Object):
    def __init__(self, owner: OwnerSessionMetadataTransport, intent: ApprovalDeliveryExecutionIntent,
            parameters_digest: str, *, expected_actor: str, expected_serial: str, source_digest: str,
            clock: Callable[[], int], execution_enabled: bool = False,
            source_guard: Callable[[], bool] | None = None) -> None:
        window: ApprovalDeliverySource | None = None
        try:
            if (type(intent) is not ApprovalDeliveryExecutionIntent or not callable(clock)
                    or type(execution_enabled) is not bool
                    or canonical_digest(dict(serial=expected_serial)) != intent.original.serial_digest
                    or source_digest != intent.original.source_digest): raise ValueError
            require_digest(parameters_digest, "Approval Email HTTP parameters")
            window = ApprovalDeliverySource(owner, expected_actor=expected_actor, expected_serial=expected_serial,
                material_binding_digests=dict(zip(_ROLES, intent.original_draft._binding_digests, strict=True)), source_guard=source_guard)
            self._window = window
            self._intent, self._parameters, self._source_digest, self._clock = intent, parameters_digest, source_digest, clock
            self._enabled, self._closed = execution_enabled, False
            self._attempted: set[bool] = set()
            self._acks: dict[bool, ApprovalDeliveryBackendReceipt] = {}
            self._deadline_cap: float | None = None
            self._lock = RLock()
        except BaseException as error:
            if window is not None: window.close()
            if isinstance(error, Exception): raise ValueError(_ERROR) from None
            raise

    def _available(self, *, writing: bool = False) -> None:
        self._window._available()
        if self._closed or writing and not self._enabled: raise ValueError

    def _remaining(self, deadline: float, *, writing: bool = False) -> float:
        self._available(writing=writing)
        remaining = min(deadline, self._window._expiry) - self._window._now()
        if remaining <= 0: raise ValueError
        return min(remaining, self._window._config.timeout_seconds)

    @contextmanager
    def _bounded_by(self, deadline: float) -> Iterator[None]:
        previous = self._deadline_cap
        self._deadline_cap = deadline if previous is None else min(previous, deadline)
        try: yield
        finally: self._deadline_cap = previous

    def inspect(self) -> ApprovalDeliveryReadback:
        source = None
        try:
            with self._lock, _private_http_logs():
                self._available()
                window = self._window
                source = ApprovalDeliverySource(window._owner, expected_actor=window._actor, expected_serial=window._serial,
                    material_binding_digests=window._bindings, source_guard=window._guard)
                deadline = min(window._now()+window._config.timeout_seconds, window._expiry)
                if self._deadline_cap is not None: deadline = min(deadline, self._deadline_cap)
                with source._bounded_by(deadline):
                    source.read()
                    observed = readback_from_approval_source(source, source_digest=self._source_digest, clock=self._clock)
                self._remaining(deadline)
                return observed
        except Exception:
            raise ValueError(_ERROR) from None
        finally:
            if source is not None: source.close()

    def _owned_adapter(self, callback: Callable[[], int], restore: bool) -> ApprovalDeliveryM4Adapter:
        if (not isinstance(callback, MethodType) or callback.__func__ is not ApprovalDeliveryM4Adapter._before_send
                or type(callback.__self__) is not ApprovalDeliveryM4Adapter): raise ValueError
        adapter: ApprovalDeliveryM4Adapter = callback.__self__
        base = adapter._original if restore else adapter
        if (adapter._backend is not self or base is None or base._backend is not self or base._intent is not self._intent
                or adapter._intent is not self._intent or adapter._plan.parameters_digest != self._parameters
                or (adapter._original is not None) is not restore
                or restore and self._acks.get(False) is not base._receipt): raise ValueError
        _require_m4_dispatch_ownership(adapter._plan, adapter._authorization, adapter._store)
        return adapter

    def _receive_ack(self, connection: Any, deadline: float) -> bytearray:
        raw = bytearray()
        try:
            with ExitStack() as resources:
                handle = connection.sock
                handle.settimeout(self._remaining(deadline, writing=True))
                response = connection.getresponse(); resources.callback(response.close)
                if (type(response.status) is not int or response.status != 200
                        or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"
                        or response.getheader("Content-Encoding", "identity").lower() != "identity"): raise ValueError
                length, expected = response.getheader("Content-Length"), None
                if length is not None:
                    if (type(length) is not str or not length.isascii() or not length.isdecimal() or len(length)>7
                            or response.getheader("Transfer-Encoding") is not None): raise ValueError
                    expected = int(length)
                    if not 0 < expected <= 16384: raise ValueError
                raw, offset = bytearray(16385), 0
                while offset < len(raw):
                    remaining = self._remaining(deadline, writing=True)
                    if not response.isclosed(): handle.settimeout(remaining)
                    with memoryview(raw)[offset:] as view: count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(raw)-offset: raise ValueError
                    if not count: break
                    offset += count
                if not 0 < offset <= 16384 or expected is not None and expected != offset: raise ValueError
                raw = _take_mutable_prefix(raw, offset)
            self._remaining(deadline, writing=True)
            return raw
        except BaseException:
            _erase_transfer_storage(raw)
            raise

    def submit(self, body: memoryview, *, parameters_digest: str, restore: bool,
            before_send: Callable[[], int], timeout_seconds: int) -> ApprovalDeliveryBackendReceipt:
        owned, raw = bytearray(), bytearray()
        try:
            try:
                with self._lock, _private_http_logs():
                    if (parameters_digest != self._parameters or type(restore) is not bool or restore in self._attempted
                            or type(timeout_seconds) is not int or not 0 < timeout_seconds <= 60): raise ValueError
                    adapter = self._owned_adapter(before_send, restore)
                    provider = adapter._provider
                    self._attempted.add(restore)
                    self._available(writing=True)
                    if (adapter._provider._binding is not adapter._material_binding
                            or adapter._provider._request is not adapter._material_request): raise ValueError
                    owned = _matching_body(body, self._intent.original_draft if restore else self._intent.proposed, adapter._provider)
                    window = self._window
                    deadline = min(window._now()+min(timeout_seconds, window._config.timeout_seconds), window._expiry)
                    cookies: SimpleCookie = SimpleCookie(); cookies.load(window._cookie.decode("ascii"))
                    csrf = cookies.get("ccsrftoken")
                    if (csrf is None or not 1 <= len(csrf.value) <= 4096 or not csrf.value.isascii()
                            or any(ord(char)<33 or ord(char)>126 for char in csrf.value)): raise ValueError
                    with self._bounded_by(deadline), ExitStack() as resources:
                        connection = window._factory(window._host, window._port, context=window._tls,
                            timeout=self._remaining(deadline, writing=True))
                        resources.callback(connection.close)
                        connection.set_debuglevel(0); connection.connect()
                        budget = before_send()
                        if type(budget) is not int or budget <= 0: raise ValueError
                        deadline = min(deadline, window._now()+budget)
                        connection.sock.settimeout(self._remaining(deadline, writing=True))
                        # No guard runs after final M4 admission. Cookie
                        # continuity and physical pins still precede the PUT.
                        window._window()
                        self._owned_adapter(before_send, restore)._check(adapter._plan, material_ready=True)
                        window._cookie_continuity()
                        if window._now() >= min(deadline, window._expiry): raise ValueError
                        window._pinned_window()
                        if (self._closed or not self._enabled or not adapter._enabled
                                or adapter._guard is not adapter._guard_pin
                                or window._guard is None or window._guard is not window._guard_pin
                                or adapter._provider is not provider or provider._closed or provider._failed
                                or provider._binding is not adapter._material_binding or provider._request is not adapter._material_request
                                or not provider._consumed or provider._lease is None or len(provider._buffers) != 3): raise ValueError
                        connection.request("PUT", CURRENT_PATH, body=owned, headers={
                            "Cookie": window._cookie.decode("ascii"), "X-CSRFTOKEN": csrf.value,
                            "Accept": "application/json", "Content-Type": "application/json", "Accept-Encoding": "identity",
                            "Cache-Control": "no-cache,no-store", "Connection": "close"})
                        _erase_transfer_storage(owned)
                        raw = self._receive_ack(connection, deadline)
                        _ack_candidate(raw, window._serial)
                    self._remaining(deadline, writing=True)
                    receipt = ApprovalDeliveryBackendReceipt(self._source_digest, parameters_digest, restore)
                    _erase_transfer_storage(raw); _erase_transfer_storage(owned)
                    self._acks[restore] = receipt
                    return receipt
            finally:
                try: _erase_transfer_storage(raw)
                finally: _erase_transfer_storage(owned)
        except Exception:
            raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._window.close()
