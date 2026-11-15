"""Inactive single-row product process over an inherited private socket.

The trusted launcher must independently pin the original action and restrict the
two workloads. This module supplies neither launch authority nor a public route.
The intake peer receives C2 acknowledgements and fixed outcomes only. Credentials,
raw product responses and TLS state stay in the product process. ACK receipt is
an ordering handshake, not an assertion of durable M4/Owner retention.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import http.client
import math
from pathlib import Path
import socket
import struct
import time
from urllib.parse import urlsplit

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning import canonical_digest
from v4_planning.execution_kernel import _ACTIVE_DISPATCH, _require_m4_dispatch_ownership, M4ClaimState

from . import secret_bulk_import_metadata as m
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_dependencies import ImportDependencyCatalog, ResolvedImportDependencies
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_row_actor import _OriginalRowApiActorGuard
from .secret_bulk_import_row_http_transport import _NativeConnection, _NativeResponse
from .secret_bulk_import_row_wire import (
    _READBACK_ARRAYS, _SCALAR_KEYS, _TOTP, _WIRE_KEYS, _compare_build29_detail,
    _project_build29_secret_wire_defaults, _Build29SecretWireDefaults, _original_product_metadata,
)
from .secret_metadata_http_transport import (
    COLLECTION_PATH, SecretMetadataHttpTransportConfig, _json_string_end,
    _json_value_end, _skip_json_space,
)
from .web_secret_create_ack import (
    WebSecretCreateAckCapture, WebSecretCreateAcknowledgement, _ack_digest, read_web_secret_create_ack,
)

_LIMIT = 1048576


@dataclass(frozen=True, slots=True, repr=False)
class _OriginalRowActionPins(_OpaqueC3Object):
    """Private startup data; constructing this object confers no authority."""

    context_digest: str
    defaults_digest: str
    capture: WebSecretCreateAckCapture
    metadata: tuple[tuple[str, str | int], ...]
    field_names: tuple[str, ...]
    deadline: float

    def __post_init__(self) -> None:
        if (any(type(value) is not str or m._DIGEST.fullmatch(value) is None
                for value in (self.context_digest, self.defaults_digest))
                or type(self.capture) is not WebSecretCreateAckCapture or self.capture.observe_source
                or type(self.deadline) not in {int, float} or not math.isfinite(self.deadline)
                or not 0 < self.deadline - time.monotonic() <= 60
                or type(self.metadata) is not tuple
                or len(self.metadata) != len(_SCALAR_KEYS - {'description'})
                or any(type(pair) is not tuple or len(pair) != 2 for pair in self.metadata)
                or {key for key, _ in self.metadata} != _SCALAR_KEYS - {'description'}
                or any(type(value) not in {str, int} for _, value in self.metadata)
                or dict(self.metadata)['id'] != 0
                or type(self.field_names) is not tuple or not 0 <= len(self.field_names) <= 64
                or any(type(name) is not str or not name or len(name.encode()) > 4096
                       for name in self.field_names)
                or len(set(self.field_names)) != len(self.field_names)):
            raise BulkImportIntakeError(_ERROR)
        self.capture.__post_init__()


def _compile_original_action_pins(encoder: object, capture: WebSecretCreateAckCapture) -> _OriginalRowActionPins:
    """Owner-side C2 compilation in the original active M4 dispatch only.

    No file decode, material acquisition, worker launch or product I/O occurs.
    The descriptor remains data; launcher/OS qualification is separate.
    """
    from .secret_bulk_import_row_http_transport import _product_action_context_digest
    from .secret_bulk_import_row_loader import _PreboundOriginalImportRowLoader
    from .secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder
    try:
        if type(encoder) is not _Build29OriginalRowWireEncoder:
            raise ValueError
        bridge = encoder._converter._bridge
        loader = bridge._loader
        if (type(loader) is not _PreboundOriginalImportRowLoader or bridge._used or loader._used
                or bridge._owned is not None or type(capture) is not WebSecretCreateAckCapture
                or capture.observe_source or capture.serial_digest != encoder._defaults.serial_digest):
            raise ValueError
        bridge._verify()
        metadata, fields = encoder._product_metadata()
        if loader._acquisition_deadline is None:
            raise ValueError
        deadline = min(bridge._deadline, loader._acquisition_deadline, time.monotonic() + 60)
        return _OriginalRowActionPins(_product_action_context_digest(bridge._context), encoder._digest,
            capture, metadata, fields, deadline)
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None


def _compile_original_channel_action_pins(owner: object, catalog: ImportDependencyCatalog,
                                         projected: ResolvedImportDependencies,
                                         defaults: _Build29SecretWireDefaults, *,
                                         namespace_key_path: Path, index: int,
                                         target_name: str | None,
                                         associated_secret_id: int | None) -> _OriginalRowActionPins:
    """Compile from original Owner C2 records without a source session or decoder."""
    from .secret_bulk_import_row_channel import OriginalRowChannelOwner
    from .secret_bulk_import_row_adapter import _OriginalRowUseContext
    from .secret_bulk_import_row_conversion import _select_original_row_metadata
    from .secret_bulk_import_row_http_transport import _product_action_context_digest
    from .secret_bulk_import_row_namespace import OriginalImportOperation, PinnedOriginalImportRows
    try:
        if (type(owner) is not OriginalRowChannelOwner or type(catalog) is not ImportDependencyCatalog
                or type(projected) is not ResolvedImportDependencies
                or type(defaults) is not _Build29SecretWireDefaults):
            raise ValueError
        b, ack = owner._binding, owner._ack_pins
        b.__post_init__()
        _require_m4_dispatch_ownership(b.plan, b.authorization, owner._execution)
        scope = _ACTIVE_DISPATCH.get()
        if (scope is None or scope.product_reserved or scope.material_reserved or owner._scope is not None
                or ack is None or owner._material_store is None
                or b.material_requested_at is None or b.material_expires_at is None
                or b.ack_pins_digest != ack.digest()
                or ack.capture.observe_source or ack.defaults_digest != defaults.digest()
                or ack.capture.serial_digest != defaults.serial_digest):
            raise ValueError
        context_digest = canonical_digest({'authorization_digest': b.authorization.authorization_digest,
            'plan_digest': b.plan.plan_digest, 'revision': b.plan.revision})
        claim = owner._execution.inspect_claim(plan_ref=b.plan.plan_ref,
            requester_digest=b.plan.requester_digest, idempotency_digest=b.plan.idempotency_digest,
            context_digest=context_digest, authorization_digest=b.authorization.authorization_digest)
        if claim.state is not M4ClaimState.IN_PROGRESS:
            raise ValueError
        started, now = time.monotonic(), owner._clock()
        if (type(now) is not int or not b.authorization.issued_at <= now < b.authorization.expires_at
                or not b.source.issued_at <= now < b.source.expires_at
                or not b.material_requested_at <= now < b.material_expires_at
                or not catalog.observed_at <= started < catalog.expires_at):
            raise ValueError
        record = owner._record()
        verified_selectors = owner._verify_parent_forward(now)
        fields = asdict(record)
        fields.pop('plan_digest'); fields.pop('namespace_key_digest')
        rows = PinnedOriginalImportRows(OriginalImportOperation(**fields),
            key_path=namespace_key_path, key_sha256=b.namespace_key_digest)
        rows._verify_dependencies_binding(b.source, projected, catalog,
            authenticated_requester_digest=b.plan.requester_digest)
        row = rows.row(index)
        row.verify_m4_plan(b.plan)
        if row != ack.row:
            raise ValueError
        dependency, template, _ = _select_original_row_metadata(catalog, projected,
            file_digest=b.source.file_sha256, index=index, target_name=target_name,
            associated_secret_id=associated_secret_id)
        from v4_planning.import_parent import FileImportParentRecord
        parent = owner._parent.get_import_parent(b.plan.plan_ref)
        if type(parent) is FileImportParentRecord:
            for line in parent.lines:
                if line.kind == 'target' and line.index == dependency.target_group:
                    if verified_selectors.get(line.line_ref) != target_name:
                        raise ValueError
                elif line.kind == 'secret' and line.index == dependency.association_row:
                    if verified_selectors.get(line.line_ref) != associated_secret_id:
                        raise ValueError
        metadata, field_names = _original_product_metadata(defaults, dependency, template,
            target_name=target_name, associated_secret_id=associated_secret_id)
        owner._permission.verify_row_acquisition(b.plan, b.authorization, b.source, now_epoch=now)
        owner._verify_material_key()
        owner._material_store.verify_ready()
        until = min(b.material_expires_at, b.plan.expires_at, b.authorization.expires_at,
            b.source.expires_at, owner._permission.acquisition_expires_at())
        if owner._record() != record:
            raise ValueError
        ended = owner._clock()
        if type(ended) is not int or not now <= ended < until:
            raise ValueError
        context = _OriginalRowUseContext(row, b.permission, b.material_requested_at, b.material_expires_at)
        deadline = min(catalog.expires_at, started + min(60.0, until - now),
            time.monotonic() + min(60.0, until - ended))
        return _OriginalRowActionPins(_product_action_context_digest(context), ack.defaults_digest,
            ack.capture, metadata, field_names, deadline)
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if not math.isfinite(value) or value <= 0:
        raise BulkImportIntakeError(_ERROR)
    return min(value, 10.0)


def _accept_deadline(deadline: float, previous: float) -> float:
    if not math.isfinite(deadline) or not time.monotonic() < deadline <= previous:
        raise ValueError
    return deadline


def _receive(peer: socket.socket, deadline: float, maximum: int) -> bytearray:
    """Read one bounded frame directly into owned memory, never bytes payloads."""
    header, payload = bytearray(4), bytearray()
    try:
        for part in (header, payload):
            if part is payload:
                size = struct.unpack('!I', header)[0]
                if not 0 < size <= maximum:
                    raise ValueError
                payload.extend(bytearray(size))
            position = 0
            while position < len(part):
                peer.settimeout(_remaining(deadline))
                with memoryview(part)[position:] as view:
                    count = peer.recv_into(view)
                if count <= 0:
                    raise ValueError
                position += count
                _remaining(deadline)
        return payload
    except BaseException:
        _wipe(payload)
        raise
    finally:
        _wipe(header)


def _send(peer: socket.socket, deadline: float, payload: bytes | bytearray | memoryview) -> None:
    if not 0 < len(payload) <= _LIMIT:
        raise ValueError
    peer.settimeout(_remaining(deadline))
    peer.sendall(struct.pack('!I', len(payload)))
    peer.settimeout(_remaining(deadline))
    peer.sendall(payload)
    _remaining(deadline)


def _exact_keys(raw: bytearray, start: int, end: int, keys: frozenset[str]) -> dict[str, tuple[int, int]]:
    selected = m._object_spans(raw, start, end, keys)
    if set(selected) != keys:
        raise ValueError
    cursor = _skip_json_space(raw, start + 1)
    count = 0
    while cursor < end - 1:
        key_end = _json_string_end(raw, cursor) + 1
        separator = _skip_json_space(raw, key_end)
        right = _json_value_end(raw, _skip_json_space(raw, separator + 1))
        count += 1
        cursor = _skip_json_space(raw, right)
        if cursor == end - 1:
            break
        cursor = _skip_json_space(raw, cursor + 1)
    if count != len(keys):
        raise ValueError
    return selected


def _validate_wire(raw: bytearray, pins: _OriginalRowActionPins) -> None:
    """Check independently pinned C2 and fixed shape without decoding C3."""
    start = _skip_json_space(raw, 0)
    end = _json_value_end(raw, start)
    if _skip_json_space(raw, end) != len(raw):
        raise ValueError
    m._validate_json(raw, start, end, depth=0, budget=[50000])
    selected = _exact_keys(raw, start, end, frozenset(_WIRE_KEYS))
    for key, expected in pins.metadata:
        value = m._scalar(raw, selected[key])
        if type(value) is not type(expected) or value != expected:
            raise ValueError
    for key in _READBACK_ARRAYS:
        if m._array(raw, selected[key], 1):
            raise ValueError
    with memoryview(raw)[slice(*selected['totp-setting'])] as totp:
        if totp != _TOTP:
            raise ValueError
    fields = m._array(raw, selected['field'], 64)
    if len(fields) != len(pins.field_names):
        raise ValueError
    for span, expected in zip(fields, pins.field_names, strict=True):
        field = _exact_keys(raw, *span, frozenset({'name', 'value'}))
        if m._scalar(raw, field['name']) != expected or raw[field['value'][0]] != 34:
            raise ValueError
    if raw[selected['description'][0]] != 34:
        raise ValueError


class _OriginalRowActionClient(_OpaqueC3Object):
    """Intake endpoint with C2 pins only; no product config, token or raw reply."""

    def __init__(self, peer: socket.socket, pins: _OriginalRowActionPins) -> None:
        if (type(peer) is not socket.socket or peer.family != socket.AF_UNIX
                or peer.type != socket.SOCK_STREAM or type(pins) is not _OriginalRowActionPins):
            raise BulkImportIntakeError(_ERROR)
        pins.__post_init__()
        self._peer, self._pins = peer, pins
        self._deadline = pins.deadline
        self._phase = 'new'
        self._ack: WebSecretCreateAcknowledgement | None = None

    def close(self) -> None:
        self._phase = 'closed'
        self._peer.close()

    def _tighten_deadline(self, deadline: float) -> None:
        if (self._phase not in {'new', 'ready', 'ack'}
                or type(deadline) not in {int, float} or not math.isfinite(deadline)):
            raise ValueError
        self._deadline = _accept_deadline(min(deadline, self._deadline, self._pins.deadline), self._deadline)

    def prepare_once(self) -> None:
        raw = bytearray()
        try:
            if self._phase != 'new':
                raise ValueError
            self._phase = 'preparing'
            _send(self._peer, self._deadline, b'P' + bytes.fromhex(self._pins.context_digest)
                + struct.pack('!d', self._deadline))
            raw = _receive(self._peer, self._deadline, 1)
            if raw != b'R':
                raise ValueError
            self._phase = 'ready'
        except BaseException:
            self.close()
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            _wipe(raw)

    def submit_once(self, body: memoryview) -> WebSecretCreateAcknowledgement:
        raw = bytearray()
        try:
            if (self._phase != 'ready' or type(body) is not memoryview or not body.readonly
                    or type(body.obj) is not bytearray or body.format != 'B' or not body.c_contiguous
                    or not 0 < body.nbytes <= _LIMIT):
                raise ValueError
            self._phase = 'dispatched'
            _send(self._peer, self._deadline, b'C' + struct.pack('!d', self._deadline))
            _send(self._peer, self._deadline, body)
            raw = _receive(self._peer, self._deadline, 37)
            if len(raw) != 37 or raw[0] != ord('A'):
                raise ValueError
            native_id = struct.unpack_from('!I', raw, 1)[0]
            digest = raw[5:].hex()
            if not 0 < native_id <= 2**31 - 1 or digest != _ack_digest(native_id, self._pins.capture):
                raise ValueError
            self._ack = WebSecretCreateAcknowledgement(native_id, self._pins.capture.serial_digest, digest)
            self._phase = 'ack'
            return self._ack
        except BaseException:
            self.close()
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            _wipe(raw)

    def finish_after_retention(self, ack: WebSecretCreateAcknowledgement, retained_digest: str) -> None:
        """Caller must first verify the original Owner retention receipt.

        A digest is a local ordering check, not an independent receipt verifier.
        Runtime activation must bind this call to the existing native adapter.
        """
        raw = bytearray()
        try:
            if (self._phase != 'ack' or ack is not self._ack or type(retained_digest) is not str
                    or m._DIGEST.fullmatch(retained_digest) is None):
                raise ValueError
            self._phase = 'finishing'
            _send(self._peer, self._deadline, b'K' + bytes.fromhex(ack.acknowledgement_digest)
                + struct.pack('!d', self._deadline))
            raw = _receive(self._peer, self._deadline, 1)
            if raw != b'V':
                raise ValueError
        except BaseException:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            _wipe(raw)
            self.close()


class _OriginalRowActionWorker(_OpaqueC3Object):
    """One inherited socket, one fixed POST; no source file or ledger access."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, guard: _OriginalRowApiActorGuard,
                 pins: _OriginalRowActionPins, *,
                 connection_factory: Callable[..., _NativeConnection] | None = None) -> None:
        if (type(config) is not SecretMetadataHttpTransportConfig
                or type(guard) is not _OriginalRowApiActorGuard or type(pins) is not _OriginalRowActionPins
                or guard.serial_digest != pins.capture.serial_digest):
            raise BulkImportIntakeError(_ERROR)
        pins.__post_init__()
        guard._require_config(config)
        self._config, self._guard, self._pins = config, guard, pins
        self._deadline = pins.deadline
        self._factory = connection_factory or http.client.HTTPSConnection
        self._started = False
        self._post_attempted = False
        self._dispatch_body: memoryview | None = None
        self._detail_id: int | None = None
        self._default_attempted = False
        # Fixed process diagnostics only; neither zero nor a stage proves M4 success.
        self._exit_stage = 16

    @contextmanager
    def _response(self, operation: str, *, body: memoryview | None = None,
                  native_id: int | None = None) -> Iterator[_NativeResponse]:
        if operation == 'default' and body is None and native_id is None and self._started and not self._default_attempted:
            self._default_attempted = True
            method, path = 'GET', COLLECTION_PATH + '?action=default&vdom=root'
        elif (operation == 'create' and body is not None and body is self._dispatch_body
                and body.readonly and native_id is None and not self._post_attempted):
            self._post_attempted = True
            method, path = 'POST', COLLECTION_PATH
        elif (operation == 'detail' and body is None and type(native_id) is int
                and native_id > 0 and native_id == self._detail_id):
            self._detail_id = None
            method, path = 'GET', f'{COLLECTION_PATH}/{native_id}?vdom=root'
        else:
            raise ValueError
        origin = urlsplit(self._config.base_url)
        if origin.hostname is None:
            raise ValueError
        tls = self._guard._tls_for_transport(self._config)
        tls.set_alpn_protocols(['http/1.1'])
        headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity',
            'Authorization': 'Bearer ' + self._config.bearer_token,
            'Cache-Control': 'no-cache, no-store', 'Connection': 'close',
            'User-Agent': 'fortipam-private-original-row/1'}
        if body is not None:
            headers.update({'Content-Type': 'application/json', 'Content-Length': str(len(body))})
        connection = response = None
        try:
            timeout = min(self._config.timeout_seconds, _remaining(self._deadline))
            connection = self._factory(origin.hostname, origin.port or 443, timeout=timeout, context=tls)
            _remaining(self._deadline)
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            _remaining(self._deadline)
            kind = response.getheader('Content-Type')
            if (type(response.status) is not int or response.status != 200 or kind is None
                    or kind.split(';', 1)[0].strip().lower() != 'application/json'
                    or response.getheader('Content-Encoding') not in {None, '', 'identity'}
                    or response.getheader('Transfer-Encoding') not in {None, ''}):
                raise ValueError
            yield response
            _remaining(self._deadline)
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                if connection is not None:
                    connection.close()

    def _read(self, response: _NativeResponse) -> bytearray:
        raw, chunk = bytearray(), bytearray(4096)
        try:
            while True:
                _remaining(self._deadline)
                with memoryview(chunk)[:min(len(chunk), _LIMIT - len(raw) + 1)] as view:
                    count = response.readinto1(view)
                    _remaining(self._deadline)
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

    def serve_once(self, peer: socket.socket) -> None:
        """Run only in the dedicated action process; peer loss is terminal."""
        raw, body, request = bytearray(), bytearray(), bytearray()
        self._exit_stage = 16
        try:
            if self._started or peer.family != socket.AF_UNIX or peer.type != socket.SOCK_STREAM:
                raise ValueError
            self._started = True
            request = _receive(peer, self._deadline, 41)
            if len(request) != 41 or request[:33] != b'P' + bytes.fromhex(self._pins.context_digest):
                raise ValueError
            self._deadline = _accept_deadline(struct.unpack_from('!d', request, 33)[0], self._deadline)
            self._exit_stage = 17
            self._guard._observe(completed=False, deadline=self._deadline)
            self._exit_stage = 18
            with self._response('default') as response:
                raw = self._read(response)
            if _project_build29_secret_wire_defaults(raw,
                    serial_digest=self._pins.capture.serial_digest).digest() != self._pins.defaults_digest:
                raise ValueError
            _send(peer, self._deadline, b'R')
            self._exit_stage = 19
            _wipe(request)
            request = _receive(peer, self._deadline, 9)
            if len(request) != 9 or request[0] != ord('C'):
                raise ValueError
            self._deadline = _accept_deadline(struct.unpack_from('!d', request, 1)[0], self._deadline)
            body = _receive(peer, self._deadline, _LIMIT)
            _validate_wire(body, self._pins)
            with memoryview(body).toreadonly() as view:
                self._dispatch_body = view
                self._exit_stage = 20
                with self._response('create', body=view) as response:
                    ack = read_web_secret_create_ack(response, capture=self._pins.capture,
                        timeout_seconds=_remaining(self._deadline))
                    _send(peer, self._deadline, b'A' + struct.pack('!I', ack.native_secret_id)
                        + bytes.fromhex(ack.acknowledgement_digest))
                    self._exit_stage = 21
                    _wipe(request)
                    request = _receive(peer, self._deadline, 41)
                    if len(request) != 41 or request[:33] != b'K' + bytes.fromhex(ack.acknowledgement_digest):
                        raise ValueError
                    self._deadline = _accept_deadline(struct.unpack_from('!d', request, 33)[0], self._deadline)
                    self._detail_id = ack.native_secret_id
            self._dispatch_body = None
            _wipe(body)
            self._exit_stage = 22
            with self._response('detail', native_id=ack.native_secret_id) as response:
                raw = self._read(response)
            _compare_build29_detail(raw, metadata=self._pins.metadata,
                serial_digest=self._pins.capture.serial_digest, expected_secret_id=ack.native_secret_id)
            self._exit_stage = 23
            self._guard._observe(completed=True, deadline=self._deadline)
            _send(peer, self._deadline, b'V')
            self._exit_stage = 0
        except Exception:
            # Closing the private channel conveys uncertainty without exposing
            # exceptions, raw replies or material through a logging/error sink.
            pass
        finally:
            self._dispatch_body = None
            self._detail_id = None
            _wipe(raw)
            _wipe(body)
            _wipe(request)
            peer.close()
