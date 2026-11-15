"""Private composition of an admitted original Text file and its existing row authorities."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
import hashlib
import hmac
import math
from pathlib import Path
import socket
from threading import RLock
import time
from typing import cast

from v4_planning import M4ExecutionKernel, canonical_digest
from v4_planning.execution_kernel import M4ClaimState
from v4_planning.import_parent import FileImportParentRecord
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .m4_execution_store import PersistentM4ExecutionStateStore
from .reference_authority_sidecar import UnixReferenceAuthorityClient
from .secret_bulk_import_batch import _OriginalImportBatch, _OriginalImportRowExecution
from .secret_bulk_import_dependencies import ResolvedImportDependencies
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_parent_graph import _OriginalImportGraph, _compile_original_import_graph
from .secret_bulk_import_parent_handoff import _OriginalParentReceiver
from .secret_bulk_import_row_authority import (
    PinnedOriginalRowAcquisitionAuthority, _OriginalRowM4Authority, _OriginalRowPermissionPins,
)
from .secret_bulk_import_row_channel import OriginalRowChannelBinding, OriginalRowChannelOwner, _OriginalRowAckPins
from .secret_bulk_import_row_channel_runtime import _OriginalRowChannelRuntime
from .secret_bulk_import_row_current import _OriginalRowNativeCurrent
from .secret_bulk_import_row_dispatch import _OriginalRowOwnerAdapter
from .secret_bulk_import_row_namespace import PinnedOriginalImportRows
from .secret_bulk_import_row_wire import _Build29SecretWireDefaults
from .secret_bulk_import_source_catalog import _QualifiedTextImport, _TextOnlyImportSource
from .secret_bulk_import_token_channel import _canonical
from .secret_create_m4_runtime import SecretCreateProjectionReader
from .web_secret_create_ack import WebSecretCreateAckCapture


class _OriginalTextBatchOwner(_OpaqueC3Object):
    """Consume one received parent; references are supplied, never issued here.

    The object owns the supplied control socket and the original source profile.
    The caller retains responsibility for the separate source-process handle.
    """

    def __init__(self, original: PinnedOriginalImportRows, receiver: _OriginalParentReceiver,
                 projected: ResolvedImportDependencies, graph: _OriginalImportGraph,
                 execution: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
                 defaults: _Build29SecretWireDefaults, capture: WebSecretCreateAckCapture, *,
                 control_peer: socket.socket, authenticated_requester_digest: str, authority_key: bytes,
                 transport_digest: str, reference_authority: UnixReferenceAuthorityClient,
                 authority_ref: str, reference_by_index: dict[int, str],
                 scope_key_path: Path, scope_key_sha256: str,
                 socket_path: Path, request_key_path: Path, request_key_sha256: str,
                 signing_key_path: Path, signing_key_sha256: str,
                 product_source_path: Path, product_source_digest: str,
                 execution_enabled: bool = False, clock: Callable[[], int] = lambda: int(time.time()),
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(original) is not PinnedOriginalImportRows or type(receiver) is not _OriginalParentReceiver
                    or type(projected) is not ResolvedImportDependencies or type(graph) is not _OriginalImportGraph
                    or type(execution) is not PersistentM4ExecutionStateStore
                    or type(material_store) is not PersistentMaterialUseStateStore
                    or not execution.monotonic_checkpoint_protocol_bound
                    or not material_store.monotonic_checkpoint_protocol_bound
                    or type(defaults) is not _Build29SecretWireDefaults or type(capture) is not WebSecretCreateAckCapture
                    or capture.observe_source or capture.serial_digest != defaults.serial_digest
                    or type(control_peer) is not socket.socket or control_peer.family != socket.AF_UNIX
                    or control_peer.type != socket.SOCK_STREAM or control_peer.get_inheritable()
                    or type(reference_authority) is not UnixReferenceAuthorityClient
                    or type(reference_by_index) is not dict or type(execution_enabled) is not bool
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or hmac.compare_digest(authority_key, material_store._key)
                    or not callable(clock) or not callable(monotonic)):
                raise ValueError
            control_peer.getpeername()
            require_digest(authenticated_requester_digest, 'requester')
            require_digest(transport_digest, 'transport')
            profile, qualified = receiver._text_source, receiver._qualified
            if (type(profile) is not _TextOnlyImportSource or type(qualified) is not _QualifiedTextImport
                    or not receiver._endpoint._used or receiver._plan_digest is None
                    or receiver._requester != authenticated_requester_digest
                    or qualified.projected is not projected or qualified.catalog is not receiver._endpoint._catalog
                    or original._key.path != receiver._key_path or original._key.digest != receiver._key_digest
                    or original._operation.parent_idempotency_digest != receiver._idempotency
                    or graph.parent_ref != receiver._plan_ref or graph.parent_digest != receiver._plan_digest
                    or not 1 <= len(graph.steps) <= 256
                    or any(step.kind != 'secret' or step.index != index or step.depends_on
                           for index, step in enumerate(graph.steps))
                    or set(reference_by_index) != set(range(len(graph.steps)))
                    or any(type(index) is not int or type(reference) is not str
                           for index, reference in reference_by_index.items())
                    or len(set(reference_by_index.values())) != len(graph.steps)):
                raise ValueError
            record = receiver._store.get_import_parent(receiver._plan_ref)
            if type(record) is not FileImportParentRecord or record.requester_digest != authenticated_requester_digest:
                raise ValueError
            capture.__post_init__()
            self._original, self._receiver, self._projected, self._graph = original, receiver, projected, graph
            self._source, self._catalog = receiver._endpoint._binding, qualified.catalog
            self._profile, self._qualified, self._parent, self._record = profile, qualified, receiver._store, record
            self._execution, self._material, self._defaults, self._capture = execution, material_store, defaults, capture
            self._control, self._key, self._requester, self._transport = (
                control_peer, authority_key, authenticated_requester_digest, transport_digest)
            self._clock, self._monotonic, self._lock = clock, monotonic, RLock()
            self._last_wall, self._last_mono = record.created_at, -1.0
            self._deadline = min(graph.deadline, receiver._endpoint._deadline, self._catalog.expires_at,
                                 profile._folders.expires_at, profile._namespace.expires_at)
            self._enabled, self._previewed, self._authorized, self._used = execution_enabled, False, False, False
            self._closed = self._failed = False
            self._rows: list[tuple[_OriginalRowNativeCurrent, _OriginalRowM4Authority,
                                  _OriginalRowPermissionPins, PinnedOriginalRowAcquisitionAuthority]] = []
            self._currents: list[_OriginalRowNativeCurrent] = []
            self._issuers: list[_OriginalRowM4Authority] = []
            self._channels: list[_OriginalRowChannelRuntime] = []
            self._adapters: list[_OriginalRowOwnerAdapter] = []
            self._batch: _OriginalImportBatch | None = None
            self._socket_path, self._request_path, self._request_digest = socket_path, request_key_path, request_key_sha256
            self._signing_path, self._signing_digest = signing_key_path, signing_key_sha256
            self._product_path, self._product_digest = product_source_path, product_source_digest
            self._check()
            for index in range(len(graph.steps)):
                current = _OriginalRowNativeCurrent(original, self._source, projected, self._catalog,
                    self._parent, execution, profile, qualified, defaults, index=index,
                    expected_parent_digest=record.plan_digest, authenticated_requester_digest=self._requester,
                    clock=monotonic, wall_clock=clock)
                self._currents.append(current)
                # Original-row authorities use only the two fixed projection reads of this older protocol.
                reader = cast(SecretCreateProjectionReader, current)
                issuer = _OriginalRowM4Authority(original, self._source, projected, self._catalog,
                    self._parent, execution, reader, index=index, expected_parent_digest=record.plan_digest,
                    authority_key=authority_key, authenticated_requester_digest=self._requester,
                    transport_digest=transport_digest, execution_enabled=execution_enabled, clock=clock)
                self._issuers.append(issuer)
                pins = issuer._derive()
                permission = PinnedOriginalRowAcquisitionAuthority(self._source, pins.plan, pins.authorization,
                    policy_decision_digest=pins.policy_decision_digest, scope_digest=pins.scope_digest,
                    audience_digest=pins.audience_digest, authority=reference_authority, authority_ref=authority_ref,
                    reference=reference_by_index[index], scope_key_path=scope_key_path,
                    scope_key_sha256=scope_key_sha256, projection_reader=reader, clock=clock)
                self._rows.append((current, issuer, pins, permission))
            binding = dict(parent=record.plan_digest, graph=graph.graph_digest, requester=self._requester,
                transport=self._transport, defaults=defaults.digest(), capture=capture.source_digest,
                rows=[canonical_digest(asdict(pins)) for _, _, pins, _ in self._rows])
            self._preview_ref = self._ref(b'preview', binding)
            self._authorization_ref = self._ref(b'authorization', dict(binding, preview=self._preview_ref))
        except BaseException as error:
            if hasattr(self, '_rows'):
                self._abort()
            if not isinstance(error, Exception):
                raise
            raise BulkImportIntakeError(_ERROR) from None

    def _ref(self, purpose: bytes, binding: object) -> str:
        return 'text-import-' + purpose.decode('ascii') + '-' + hmac.new(self._key,
            b'fortipam-original-text-batch-reference/v1\0' + purpose + b'\0' + _canonical(binding),
            hashlib.sha256).hexdigest()

    def _principal(self, requester: str, transport: str) -> None:
        if (type(requester) is not str or type(transport) is not str
                or not hmac.compare_digest(requester, self._requester)
                or not hmac.compare_digest(transport, self._transport)):
            raise BulkImportIntakeError(_ERROR)

    def _reference_bootstrap(self) -> tuple[dict[str, object], ...]:
        """Protected external bootstrap metadata; never an MCP result or grant."""
        with self._lock:
            try:
                self._check()
                if self._previewed or self._authorized or self._used:
                    raise ValueError
                result: list[dict[str, object]] = []
                for _, issuer, pins, permission in self._rows:
                    if issuer._issued is not None or issuer._derive() != pins:
                        raise ValueError
                    checker = permission._checker
                    result.append(dict(references=[dict(reference=checker._reference,
                            reference_kind=checker._reference_kind)], requester_digest=checker._requester,
                        environment_ref=checker._environment, scope_ref=checker._scope,
                        expires_at=min(pins.plan.expires_at, pins.authorization.expires_at, self._source.expires_at)))
                return tuple(result)
            except Exception:
                raise BulkImportIntakeError(_ERROR) from None

    def _check(self) -> int:
        now, monotonic = self._clock(), self._monotonic()
        if (self._closed or self._failed or type(now) is not int
                or not self._last_wall <= now < min(self._record.expires_at, self._source.expires_at)
                or type(monotonic) not in (int, float) or not math.isfinite(monotonic)
                or not self._last_mono <= monotonic < self._deadline
                or self._receiver._qualified is not self._qualified
                or self._parent.get_import_parent(self._record.plan_ref) != self._record):
            raise ValueError
        self._last_wall, self._last_mono = now, float(monotonic)
        self._profile.check_current(self._qualified,
            file_digest=self._source.file_sha256, scope_digest=self._source.scope_digest)
        compiled = _compile_original_import_graph(self._original, self._source, self._projected, self._catalog,
            self._parent, expected_parent_digest=self._record.plan_digest,
            authenticated_requester_digest=self._requester, clock=self._clock)
        if (compiled.graph_digest != self._graph.graph_digest or compiled.steps != self._graph.steps
                or self._defaults.serial_digest != self._capture.serial_digest):
            raise ValueError
        claims = self._execution._inspect_original_claims(plan_ref=self._record.plan_ref,
            requester_digest=self._requester,
            idempotency_digests=tuple(self._original.row(i).idempotency_digest for i in range(len(self._graph.steps))))
        if any(claim.state is not M4ClaimState.NEW for claim in claims):
            raise ValueError
        return now

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        with self._lock:
            self._principal(requester_digest, transport_digest)
            if self._closed or self._authorized or self._used:
                raise BulkImportIntakeError(_ERROR)
            try:
                self._check()
                for _, _, pins, permission in self._rows:
                    permission.verify_row_acquisition(pins.plan, pins.authorization, self._source,
                        now_epoch=self._check())
                self._check()
                self._previewed = True
                count = len(self._rows)
                return dict(status='preview', preview_ref=self._preview_ref, rows=count, targets=0,
                    current=dict(candidate_names='absent', writable_folders=1),
                    proposed=dict(secret_creates=count, template_profile='single_text_field'),
                    expected=dict(verified_secret_creates=count))
            except BaseException as error:
                self._abort()
                if not isinstance(error, Exception):
                    raise
                raise BulkImportIntakeError(_ERROR) from None

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        with self._lock:
            self._principal(requester_digest, transport_digest)
            if type(preview_ref) is not str or not hmac.compare_digest(preview_ref, self._preview_ref):
                raise BulkImportIntakeError(_ERROR)
            if self._closed or not self._enabled or not self._previewed or self._authorized or self._used:
                raise BulkImportIntakeError(_ERROR)
            try:
                self._check()
                rows = []
                for index, (current, issuer, pins, permission) in enumerate(self._rows):
                    checker = permission._checker
                    checker(self._source, canonical_digest(checker._reference), self._check())
                    if issuer.issue() != pins:
                        raise ValueError
                    checker(self._source, canonical_digest(checker._reference), self._check())
                    ack = _OriginalRowAckPins(self._original.row(index), self._defaults.digest(), self._capture)
                    binding = OriginalRowChannelBinding(self._source, pins.plan, pins.authorization,
                        self._record.plan_digest, self._original._key.digest, pins,
                        material_requested_at=self._record.created_at,
                        material_expires_at=min(self._record.expires_at, self._source.expires_at,
                                                self._record.created_at + 60), ack_pins_digest=ack.digest())
                    owner = OriginalRowChannelOwner(binding, self._parent, self._execution, permission,
                        material_store=self._material, ack_pins=ack, clock=self._clock)
                    channel = _OriginalRowChannelRuntime(owner, socket_path=self._socket_path,
                        request_key_path=self._request_path, request_key_sha256=self._request_digest,
                        signing_key_path=self._signing_path, signing_key_sha256=self._signing_digest)
                    self._channels.append(channel)
                    peer = self._control.dup()
                    try:
                        adapter = _OriginalRowOwnerAdapter(owner, current, intake_peer=peer,
                            source_path=self._product_path, source_digest=self._product_digest, channel=channel)
                    except BaseException:
                        peer.close()
                        raise
                    self._adapters.append(adapter)
                    rows.append(_OriginalImportRowExecution(owner,
                        M4ExecutionKernel(adapter, issuer, self._execution, clock=self._clock)))
                self._batch = _OriginalImportBatch(self._original, self._source, self._projected, self._catalog,
                    self._parent, self._execution, expected_parent_digest=self._record.plan_digest,
                    targets=(), rows=tuple(rows), execution_enabled=self._enabled, clock=self._clock)
                self._check()
                self._authorized = True
                return dict(status='authorized', authorization_ref=self._authorization_ref, rows=len(rows), targets=0)
            except BaseException as error:
                self._abort()
                if not isinstance(error, Exception):
                    raise
                raise BulkImportIntakeError(_ERROR) from None

    def execute_once(self, authorization_ref: str, *, requester_digest: str,
                     transport_digest: str) -> dict[str, object]:
        with self._lock:
            self._principal(requester_digest, transport_digest)
            if type(authorization_ref) is not str or not hmac.compare_digest(authorization_ref, self._authorization_ref):
                raise BulkImportIntakeError(_ERROR)
            if self._closed or not self._authorized or self._used or self._batch is None:
                raise BulkImportIntakeError(_ERROR)
            try:
                self._check()
                self._used = True
                result = self._batch.execute_once()
                self.close()
                return dict(status='succeeded' if result.completed else 'reconciliation_required',
                    verified_lines=result.verified_lines, total_lines=result.total_lines, completed=result.completed)
            except BaseException as error:
                self._abort()
                if not isinstance(error, Exception):
                    raise
                raise BulkImportIntakeError(_ERROR) from None

    def _abort(self) -> None:
        self._failed = True
        try:
            self._parent.invalidate_plan(self._record.plan_ref, evaluated_at=self._last_wall,
                reason_codes=('current_state_unavailable_or_unsafe',))
        finally:
            self.close()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            failed = False
            for close in (*(adapter.close for adapter in self._adapters),
                          *(channel.close for channel in self._channels),
                          *(current.close for current in self._currents),
                          *(issuer.close for issuer in self._issuers), self._control.close,
                          self._receiver.close, self._profile._folder_reader.close,
                          self._profile._namespace_reader.close, self._profile.close):
                try:
                    close()
                except Exception:
                    failed = True
            if failed:
                raise BulkImportIntakeError(_ERROR)
