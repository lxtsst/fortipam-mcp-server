"""Inactive fixed original-row POST/ACK/detail composition.

This reuses the claimed original handoff, native encoder and existing ACK parser.
Original ACK evidence uses the existing owner-side parent ledger; it grants no
adoption. There is no Tool, caller-selected route, retry or cleanup authority.
Actor/dependency qualification and original child ownership remain
separate requirements before activation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import http.client
import math
import threading
import time
from typing import TYPE_CHECKING, Protocol
from urllib.parse import urlsplit

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning import canonical_digest
from v4_planning.execution_kernel import M4ClaimState, _require_m4_dispatch_ownership
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome
from v4_planning.store import OriginalImportRowAckRecord

from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_row_adapter import _OriginalRowUseContext
from .secret_bulk_import_row_loader import _PreboundOriginalImportRowLoader
from .secret_bulk_import_row_actor import _OriginalRowApiActorGuard
from .secret_bulk_import_row_channel import (
    _RemoteOriginalImportRowLoader, _OriginalRowAckPins, UnixOriginalRowChannelClient,
)
from .secret_bulk_import_row_wire import (
    _Build29OriginalRowWireEncoder, _READBACK_QUERY, _project_build29_secret_wire_defaults,
)
from .secret_metadata_http_transport import (
    COLLECTION_PATH, SecretMetadataHttpTransportConfig, _ssl_context,
)
from .web_secret_create_ack import (
    WebSecretCreateAckCapture, WebSecretCreateAcknowledgement, _ack_digest, read_web_secret_create_ack,
)

_LIMIT = 1048576

if TYPE_CHECKING:
    from .secret_bulk_import_row_action_worker import _OriginalRowActionClient


def _product_action_context_digest(context: _OriginalRowUseContext) -> str:
    return canonical_digest({'plan': context.permission.plan.plan_digest,
        'authorization': context.permission.authorization.authorization_digest,
        'row': context.row.parameters_digest, 'scope': context.permission.scope_digest,
        'audience': context.permission.audience_digest,
        'requested_at': context.requested_at, 'expires_at': context.expires_at})


class _NativeResponse(Protocol):
    status: int
    def getheader(self, name: str) -> str | None: ...
    def readinto1(self, buffer: memoryview) -> int: ...
    def close(self) -> None: ...


class _NativeConnection(Protocol):
    def request(self, method: str, url: str, body: memoryview | None,
                headers: dict[str, str]) -> None: ...
    def getresponse(self) -> _NativeResponse: ...
    def close(self) -> None: ...


class _Build29OriginalRowHttpTransport(_OpaqueC3Object):
    """One fixed default check, original POST/ACK and ACK-ID detail read."""

    def __init__(self, config: SecretMetadataHttpTransportConfig | None,
                 encoder: _Build29OriginalRowWireEncoder, ack_capture: WebSecretCreateAckCapture,
                 *, connection_factory: Callable[..., _NativeConnection] | None = None,
                 actor_guard: _OriginalRowApiActorGuard | None = None,
                 product_client: _OriginalRowActionClient | None = None) -> None:
        try:
            if (type(encoder) is not _Build29OriginalRowWireEncoder
                    or type(ack_capture) is not WebSecretCreateAckCapture
                    or ack_capture.observe_source or ack_capture.serial_digest != encoder._defaults.serial_digest
                    or type(encoder._converter._bridge._loader) not in {
                        _PreboundOriginalImportRowLoader, _RemoteOriginalImportRowLoader}):
                raise ValueError
            ack_capture.__post_init__()
            if product_client is not None:
                from .secret_bulk_import_row_action_worker import _OriginalRowActionClient
                if (type(product_client) is not _OriginalRowActionClient or config is not None
                        or actor_guard is not None or connection_factory is not None
                        or product_client._pins.capture != ack_capture
                        or product_client._pins.defaults_digest != encoder._digest
                        or product_client._pins.context_digest != _product_action_context_digest(encoder._converter._context)):
                    raise ValueError
                product_client._tighten_deadline(encoder._converter._bridge._deadline)
            else:
                if (type(config) is not SecretMetadataHttpTransportConfig
                        or type(config.timeout_seconds) not in {int, float}
                        or not math.isfinite(config.timeout_seconds)):
                    raise ValueError
                config.__post_init__()
            if actor_guard is not None and config is not None:
                if type(actor_guard) is not _OriginalRowApiActorGuard or actor_guard.serial_digest != ack_capture.serial_digest:
                    raise ValueError
                actor_guard._require_config(config)
            elif connection_factory is None and product_client is None:
                # Real product I/O cannot use an unqualified actor. Synthetic
                # factory injection remains a trusted inactive test seam.
                raise ValueError
            loader = encoder._converter._bridge._loader
            if type(loader) is _RemoteOriginalImportRowLoader:
                if (type(loader._authority) is not UnixOriginalRowChannelClient
                        or loader._authority._binding.ack_pins_digest != _OriginalRowAckPins(
                            loader._row, encoder._digest, ack_capture).digest()):
                    raise ValueError
            if config is not None:
                origin = urlsplit(config.base_url)
                if origin.hostname is None or origin.username is not None or origin.password is not None:
                    raise ValueError
            self._config, self._encoder, self._capture = config, encoder, ack_capture
            self._product_client = product_client
            self._factory = connection_factory
            self._actor_guard = actor_guard
            self._actor_prepared = False
            self._used, self._lock = False, threading.Lock()
            self._ack: WebSecretCreateAcknowledgement | None = None
            self._ack_record: OriginalImportRowAckRecord | None = None
            self._ack_retained_digest: str | None = None
            self._ack_retention_attempted = False
            self._reading_original_ack = False
            self._post_matches = False
            self._failure_stage: str | None = None
            self._dispatch_body: memoryview | None = None
            self._post_attempted = False
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _check(self, deadline: float) -> float:
        self._encoder._converter._check(deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BulkImportIntakeError(_ERROR)
        return min(10.0, self._config.timeout_seconds if self._config is not None else 10.0, remaining)

    @contextmanager
    def _response(self, operation: str, deadline: float,
                  body: memoryview | None = None) -> Iterator[_NativeResponse]:
        if self._config is None or self._product_client is not None:
            raise ValueError
        if operation == 'defaults' and body is None:
            method, path = 'GET', COLLECTION_PATH + '?action=default&vdom=root'
        elif operation == 'create' and body is not None:
            if (type(body) is not memoryview or not body.readonly or body.format != 'B'
                    or body is not self._dispatch_body or self._post_attempted
                    or self._encoder._active_thread != threading.get_ident()
                    or self._encoder._active_metadata is None):
                raise ValueError
            self._encoder._converter._bridge._verify()
            self._post_attempted = True
            method, path = 'POST', COLLECTION_PATH
        elif operation == 'detail' and body is None and self._ack is not None:
            method, path = 'GET', f'{COLLECTION_PATH}/{self._ack.native_secret_id}?{_READBACK_QUERY}'
        else:
            raise ValueError
        timeout = self._check(deadline)
        if timeout < 1:
            raise ValueError
        headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity',
            'Authorization': 'Bearer ' + self._config.bearer_token,
            'Cache-Control': 'no-cache, no-store', 'User-Agent': 'fortipam-private-original-row/1',
            'Connection': 'close'}
        if body is not None:
            headers.update({'Content-Type': 'application/json', 'Content-Length': str(body.nbytes)})
        factory = self._factory or http.client.HTTPSConnection
        connection = response = None
        try:
            origin = urlsplit(self._config.base_url)
            if origin.hostname is None:
                raise ValueError
            tls = self._actor_guard._tls_for_transport(self._config) if self._actor_guard is not None else _ssl_context(self._config)
            tls.set_alpn_protocols(['http/1.1'])
            connection = factory(origin.hostname, origin.port or 443, timeout=timeout, context=tls)
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            self._check(deadline)
            if type(response.status) is not int or response.status != 200:
                raise ValueError
            self._headers(response)
            yield response
            self._check(deadline)
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                if connection is not None:
                    connection.close()

    @staticmethod
    def _headers(response: _NativeResponse) -> None:
        kind = response.getheader('Content-Type')
        if (kind is None or kind.split(';', 1)[0].strip().lower() != 'application/json'
                or response.getheader('Content-Encoding') not in {None, '', 'identity'}
                or response.getheader('Transfer-Encoding') not in {None, ''}):
            raise ValueError

    def _read(self, response: _NativeResponse, deadline: float) -> bytearray:
        raw, chunk = bytearray(), bytearray(4096)
        try:
            while True:
                self._check(deadline)
                with memoryview(chunk)[:min(len(chunk), _LIMIT - len(raw) + 1)] as view:
                    count = response.readinto1(view)
                    self._check(deadline)
                    if type(count) is not int or not 0 <= count <= len(view) or len(raw) + count > _LIMIT:
                        raise ValueError
                    if count:
                        raw.extend(view[:count])
                _wipe(chunk)
                if not count:
                    return raw
        except BaseException:
            _wipe(raw)
            raise
        finally:
            _wipe(chunk)

    def _retain_original_ack(self) -> None:
        """Original POST parser only, before detail/close; never adopts a clone.

        Restricted intake uses the fixed signed channel; parent/M4/material
        ledgers remain on Owner, never copied into this consumer.
        """
        bridge, ack = self._encoder._converter._bridge, self._ack
        loader = bridge._loader
        if (not self._reading_original_ack or self._ack_retention_attempted
                or not self._post_attempted or self._dispatch_body is None
                or self._encoder._active_thread != threading.get_ident()
                or self._encoder._active_metadata is None
                or type(loader) not in {_PreboundOriginalImportRowLoader, _RemoteOriginalImportRowLoader}
                or type(ack) is not WebSecretCreateAcknowledgement
                or ack.serial_digest != self._capture.serial_digest
                or ack.acknowledgement_digest != _ack_digest(ack.native_secret_id, self._capture)
                or ack.observed_status is not None):
            raise ValueError
        self._ack_retention_attempted = True
        bridge._verify_context()
        if type(loader) is _RemoteOriginalImportRowLoader:
            if type(loader._authority) is not UnixOriginalRowChannelClient:
                raise ValueError
            self._ack_retained_digest = loader._authority._retain_ack_from_transport(self)
            return
        plan, auth, row = loader._plan, loader._authorization, loader._row
        row.verify_m4_plan(plan)
        _require_m4_dispatch_ownership(plan, auth, loader._execution)
        context_digest = canonical_digest({"authorization_digest": auth.authorization_digest,
            "plan_digest": plan.plan_digest, "revision": plan.revision})
        claim = loader._execution.inspect_claim(plan_ref=plan.plan_ref,
            requester_digest=plan.requester_digest, idempotency_digest=plan.idempotency_digest,
            context_digest=context_digest, authorization_digest=auth.authorization_digest)
        if claim.state is not M4ClaimState.IN_PROGRESS:
            raise ValueError
        binding = loader._parent.get_original_import_binding(plan.plan_ref,
            expected_plan_digest=loader._parent_digest, requester_digest=plan.requester_digest,
            namespace_key_digest=loader._rows._key.digest)
        record = OriginalImportRowAckRecord(plan_ref=plan.plan_ref,
            parent_binding_digest=canonical_digest(binding.as_dict()), requester_digest=plan.requester_digest,
            row_index=row.index, idempotency_digest=row.idempotency_digest,
            parameters_digest=row.parameters_digest, child_plan_digest=plan.plan_digest,
            child_revision=plan.revision, authorization_digest=auth.authorization_digest,
            context_digest=context_digest, serial_digest=ack.serial_digest,
            defaults_digest=self._encoder._digest, ack_source_digest=self._capture.source_digest,
            acknowledgement_digest=ack.acknowledgement_digest, native_secret_id=ack.native_secret_id)
        # Do not repeat a pre-state observation after POST changed the object.
        # Retaining evidence does not authorize more I/O or return VERIFIED.
        loader._parent._put_original_import_row_ack(record)
        retained = loader._parent._get_original_import_row_ack(record.plan_ref,
            idempotency_digest=record.idempotency_digest, requester_digest=record.requester_digest,
            parent_binding_digest=record.parent_binding_digest, parameters_digest=record.parameters_digest)
        if retained != record:
            raise ValueError
        self._ack_record = retained
        self._ack_retained_digest = canonical_digest(retained.as_dict())

    def _prepare_actor_once(self, context: _OriginalRowUseContext, *, deadline: float) -> None:
        """Exact adapter only, after material claim but before source decoding."""
        bridge = self._encoder._converter._bridge
        if (self._actor_prepared or self._used or bridge._transport is not self or not bridge._used
                or bridge._owned is not None or context != self._encoder._converter._context):
            raise ValueError
        self._actor_prepared = True
        if self._product_client is not None:
            self._failure_stage = 'actor_before'
            bridge._verify()
            self._product_client._tighten_deadline(min(deadline, bridge._deadline))
            self._product_client.prepare_once()
            self._check(deadline)
        elif self._actor_guard is not None:
            self._failure_stage = 'actor_before'
            bridge._verify()
            self._actor_guard._observe(completed=False, deadline=deadline)
            self._check(deadline)

    def _create_in_product_process(self, context: _OriginalRowUseContext,
                                   columns: tuple[memoryview, ...], deadline: float) -> None:
        client = self._product_client
        if client is None or not self._actor_prepared:
            raise ValueError
        self._failure_stage = 'row_conversion'
        with self._encoder._serialize_once(context, columns, deadline=deadline) as body:
            self._encoder._converter._bridge._verify()
            loader = self._encoder._converter._bridge._loader
            if type(loader) is _RemoteOriginalImportRowLoader:
                authority = loader._authority
                if type(authority) is not UnixOriginalRowChannelClient:
                    raise ValueError
                authority._call('verify-before-create')
            self._check(deadline)
            self._failure_stage = 'create_request'
            self._dispatch_body = body
            self._post_attempted = True
            try:
                client._tighten_deadline(min(deadline, self._encoder._converter._bridge._deadline))
                self._ack = client.submit_once(body)
                self._failure_stage = 'ack_retention'
                self._reading_original_ack = True
                try:
                    self._retain_original_ack()
                finally:
                    self._reading_original_ack = False
                if self._ack_retained_digest is None:
                    raise ValueError
                self._failure_stage = 'detail_compare'
                client._tighten_deadline(min(deadline, self._encoder._converter._bridge._deadline))
                client.finish_after_retention(self._ack, self._ack_retained_digest)
            finally:
                self._dispatch_body = None
        self._failure_stage = 'completion_permission'
        self._encoder._converter._bridge._verify(completed=True)
        self._check(deadline)

    def _create_and_verify_with_original_row(self, context: _OriginalRowUseContext,
                                            columns: tuple[memoryview, ...], *,
                                            deadline: float) -> SecretCreateAdapterOutcome:
        if not self._lock.acquire(blocking=False):
            return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        raw = bytearray()
        try:
            if (self._used or type(context) is not _OriginalRowUseContext
                    or context != self._encoder._converter._context
                    or type(deadline) not in {int, float} or not math.isfinite(deadline)
                    or self._actor_guard is not None and not self._actor_prepared
                    or deadline > self._encoder._converter._bridge._deadline):
                raise ValueError
            self._used = True
            self._failure_stage = 'original_permission'
            self._encoder._converter._bridge._verify()
            if self._product_client is not None:
                self._create_in_product_process(context, columns, deadline)
                self._post_matches = True
                self._failure_stage = None
                return SecretCreateAdapterOutcome.VERIFIED_CREATED
            self._failure_stage = 'defaults_read'
            with self._response('defaults', deadline) as response:
                raw = self._read(response, deadline)
            self._failure_stage = 'defaults_drift'
            current = _project_build29_secret_wire_defaults(raw, serial_digest=self._capture.serial_digest)
            if current.digest() != self._encoder._digest:
                raise ValueError
            self._failure_stage = 'row_conversion'
            with self._encoder._serialize_once(context, columns, deadline=deadline) as body:
                self._encoder._converter._bridge._verify()
                self._failure_stage = 'create_request'
                self._dispatch_body = body
                try:
                    with self._response('create', deadline, body) as response:
                        self._failure_stage = 'create_ack'
                        ack_timeout = self._check(deadline)
                        if ack_timeout < 1:
                            raise ValueError
                        self._ack = read_web_secret_create_ack(response, capture=self._capture,
                            timeout_seconds=ack_timeout)
                        self._failure_stage = 'ack_retention'
                        self._reading_original_ack = True
                        try:
                            self._retain_original_ack()
                        finally:
                            self._reading_original_ack = False
                        self._failure_stage = 'create_close'
                finally:
                    self._dispatch_body = None
                self._failure_stage = 'detail_read'
                with self._response('detail', deadline) as response:
                    raw = self._read(response, deadline)
                self._failure_stage = 'detail_compare'
                if not self._encoder._inspect_detail_once(context, raw,
                        expected_secret_id=self._ack.native_secret_id, deadline=deadline):
                    raise ValueError
            self._failure_stage = 'completion_permission'
            self._encoder._converter._bridge._verify(completed=True)
            if self._actor_guard is not None:
                self._failure_stage = 'actor_after'
                self._actor_guard._observe(completed=True, deadline=deadline)
            self._check(deadline)
            self._post_matches = True
            self._failure_stage = None
            return SecretCreateAdapterOutcome.VERIFIED_CREATED
        except Exception:
            return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        finally:
            if self._product_client is not None:
                self._product_client.close()
            self._reading_original_ack = False
            self._dispatch_body = None
            _wipe(raw)
            self._lock.release()
