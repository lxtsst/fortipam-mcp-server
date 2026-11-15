"""Fixed inherited control peer for an already authenticated Text-file session.

Only original C2 row bindings cross this peer. The signed row channel still
verifies every material operation; this worker has no authority or device inputs.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, fields
import json
from pathlib import Path
import select
import socket
import threading
import time
from typing import Any, TypeVar, cast

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.material_runtime import MaterialRuntimeOutcome

from .secret_bulk_import_dependencies import (
    ImportDependencyCatalog, ImportRowDependency, ImportTargetDependency,
    ResolvedImportDependencies, dependency_catalog_digest,
)
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_intake_authority import _members
from .secret_bulk_import_row_action_worker import _receive, _send
from .secret_bulk_import_row_authority import _OriginalRowPermissionPins
from .secret_bulk_import_row_channel import OriginalRowChannelBinding, UnixOriginalRowChannelClient
from .secret_bulk_import_row_execution import _serve_original_text_row_once
from .secret_bulk_import_row_wire import _Build29SecretWireDefaults
from .secret_bulk_import_session import _OwnerFileSourceSession
from .web_secret_create_ack import WebSecretCreateAckCapture

_CONTRACT = 'original-text-intake-row-v1'
_LIMIT = 16384
_FIELDS = frozenset({'contract', 'index', 'plan', 'authorization', 'parent_digest',
    'namespace_key_digest', 'policy_decision_digest', 'scope_digest', 'audience_digest',
    'material_requested_at', 'material_expires_at', 'ack_pins_digest'})
_Record = TypeVar('_Record', M4ExecutionPlan, M4ExecutionAuthorization)


def _wait_original_text_row(peer: socket.socket, deadline: float, closed: threading.Event) -> None:
    """Wait for a row before starting the existing bounded frame receive."""
    while True:
        remaining = deadline - time.monotonic()
        if closed.is_set() or remaining <= 0:
            raise ValueError
        readable, _, _ = select.select([peer], [], [], min(remaining, 0.1))
        if readable:
            if closed.is_set() or time.monotonic() >= deadline:
                raise ValueError
            return


def _record(value: object, kind: type[_Record]) -> _Record:
    if type(value) is not dict or set(value) != {field.name for field in fields(kind)}:
        raise ValueError
    return kind(**cast(dict[str, Any], value))


def _send_original_text_row(peer: socket.socket, binding: OriginalRowChannelBinding,
                            index: int, *, deadline: float) -> None:
    """Owner dispatch sends only its exact original row, never source selectors."""
    raw = bytearray()
    try:
        if type(binding) is not OriginalRowChannelBinding or type(index) is not int or not 0 <= index < 256:
            raise ValueError
        binding.__post_init__()
        value = dict(contract=_CONTRACT, index=index, plan=asdict(binding.plan),
            authorization=asdict(binding.authorization), parent_digest=binding.parent_digest,
            namespace_key_digest=binding.namespace_key_digest,
            policy_decision_digest=binding.permission.policy_decision_digest,
            scope_digest=binding.permission.scope_digest, audience_digest=binding.permission.audience_digest,
            material_requested_at=binding.material_requested_at, material_expires_at=binding.material_expires_at,
            ack_pins_digest=binding.ack_pins_digest)
        raw = bytearray(json.dumps(value, separators=(',', ':'), allow_nan=False).encode())
        if len(raw) > _LIMIT:
            raise ValueError
        _send(peer, deadline, raw)
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        _wipe(raw)


def _read_original_text_row(raw: bytearray, source: OwnerFileIntakeBinding,
                            index: int, key_digest: str) -> OriginalRowChannelBinding:
    value = json.loads(raw, object_pairs_hook=_members)
    if (type(value) is not dict or set(value) != _FIELDS or value['contract'] != _CONTRACT
            or type(value['index']) is not int or value['index'] != index
            or value['namespace_key_digest'] != key_digest):
        raise ValueError
    plan = _record(value['plan'], M4ExecutionPlan)
    authorization = _record(value['authorization'], M4ExecutionAuthorization)
    permission = _OriginalRowPermissionPins(plan, authorization, value['policy_decision_digest'],
        value['scope_digest'], value['audience_digest'])
    binding = OriginalRowChannelBinding(source, plan, authorization,
        value['parent_digest'], key_digest, permission,
        value['material_requested_at'], value['material_expires_at'], value['ack_pins_digest'])
    if (binding.material_requested_at is None or binding.ack_pins_digest is None
            or plan.summary_digest != binding.parent_digest):
        raise ValueError
    return binding


class _OriginalTextIntakeWorker(_OpaqueC3Object):
    """One admitted session and its existing projection; no re-admission or retry."""

    def __init__(self, peer: socket.socket, binding: OwnerFileIntakeBinding,
                 defaults: _Build29SecretWireDefaults, capture: WebSecretCreateAckCapture, *,
                 namespace_key_path: Path, namespace_key_sha256: str, socket_path: Path,
                 request_key_path: Path, request_key_sha256: str,
                 public_key_path: Path, public_key_sha256: str,
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(peer) is not socket.socket or peer.family != socket.AF_UNIX or peer.type != socket.SOCK_STREAM
                    or type(binding) is not OwnerFileIntakeBinding
                    or type(defaults) is not _Build29SecretWireDefaults
                    or type(capture) is not WebSecretCreateAckCapture or capture.observe_source
                    or capture.serial_digest != defaults.serial_digest or not callable(clock)):
                raise ValueError
            peer.getpeername()
            peer.set_inheritable(False)
            binding.__post_init__()
            defaults.digest()
            capture.__post_init__()
            self._peer, self._binding, self._defaults, self._capture = peer, binding, defaults, capture
            self._key_path, self._key_digest = namespace_key_path, namespace_key_sha256
            self._settings: dict[str, Any] = dict(socket_path=socket_path, request_key_path=request_key_path,
                request_key_sha256=request_key_sha256, public_key_path=public_key_path,
                public_key_sha256=public_key_sha256)
            self._clock, self._lock = clock, threading.Lock()
            self._session: _OwnerFileSourceSession | None = None
            self._thread: threading.Thread | None = None
            self._used = self._completed = False
            self._closed = threading.Event()
        except Exception:
            if type(peer) is socket.socket:
                peer.close()
            raise BulkImportIntakeError(_ERROR) from None

    def start_once(self, session: _OwnerFileSourceSession, catalog: ImportDependencyCatalog,
                   projected: ResolvedImportDependencies) -> None:
        with self._lock:
            try:
                if (self._used or self._closed.is_set() or type(session) is not _OwnerFileSourceSession
                        or session._transaction._binding != self._binding):
                    raise ValueError
                self._used = True
                if (type(catalog) is not ImportDependencyCatalog or len(catalog.templates) != 1
                        or len(catalog.templates[0].fields) != 1 or catalog.templates[0].fields[0].kind != 'text'):
                    raise ValueError
                template = catalog.templates[0]

                def check(rows: tuple[ImportRowDependency, ...], targets: tuple[ImportTargetDependency, ...],
                          order: tuple[int, ...]) -> tuple[int, ...]:
                    if (not rows or targets or order != tuple(range(len(rows)))
                            or len({row.folder_id for row in rows}) != 1
                            or any(row.template != template.name or row.target_group is not None
                                or row.association_row is not None or row.association_id is not None
                                or row.services for row in rows)):
                        raise ValueError
                    return order

                order = projected._inspect_private(check, file_digest=self._binding.file_sha256,
                    catalog_digest=dependency_catalog_digest(catalog))
                self._deadline = min(catalog.expires_at, time.monotonic() + session._remaining())
                self._session = session
                self._thread = threading.Thread(target=self._run, args=(catalog, projected, order),
                    name='original-text-intake', daemon=True)
                self._thread.start()
            except BaseException as error:
                if type(session) is _OwnerFileSourceSession:
                    session.close()
                self._close_peer()
                if not isinstance(error, Exception):
                    raise
                raise BulkImportIntakeError(_ERROR) from None

    def _run(self, catalog: ImportDependencyCatalog, projected: ResolvedImportDependencies,
             order: tuple[int, ...]) -> None:
        raw = bytearray()
        parent: tuple[str, str] | None = None
        session = self._session
        try:
            if session is None:
                raise ValueError
            for index in order:
                if self._closed.is_set():
                    raise ValueError
                session._remaining()
                _wait_original_text_row(self._peer, self._deadline, self._closed)
                session._remaining()
                raw = _receive(self._peer, self._deadline, _LIMIT)
                binding = _read_original_text_row(raw, self._binding, index, self._key_digest)
                _wipe(raw)
                selected = binding.plan.plan_ref, binding.parent_digest
                if parent is not None and selected != parent:
                    raise ValueError
                parent = selected
                client = UnixOriginalRowChannelClient(binding, clock=self._clock, **self._settings)
                outcome = _serve_original_text_row_once(self._peer.dup(), session, catalog, projected,
                    client, self._defaults, self._capture, index=index,
                    namespace_key_path=self._key_path, now_epoch=self._clock())
                if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
                    raise ValueError
            self._completed = True
        except BaseException:
            # The Owner observes a closed peer and retains the original uncertainty.
            pass
        finally:
            _wipe(raw)
            if session is not None:
                session.close()
            self._close_peer()

    def _close_peer(self) -> None:
        self._closed.set()
        try:
            self._peer.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._peer.close()

    def close(self) -> None:
        self._close_peer()
        if self._session is not None:
            self._session.close()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)
