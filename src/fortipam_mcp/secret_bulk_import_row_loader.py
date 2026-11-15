"""Inactive private original-row decode candidate, never a registered provider.

The prebound loader requires the original M4 kernel's active newly claimed
adapter dispatch. An IN_PROGRESS inspection by itself is not dispatch ownership;
this module does not expose a runtime or resumption tool.
The existing kernel prevents reopening active/completed/uncertain operations.
"""

from __future__ import annotations

from pathlib import Path
import threading
import time
from typing import Protocol

from v4_planning import M4AuthorizationReplay, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import (
    M4ClaimState, _require_m4_dispatch_ownership, _reserve_m4_material_acquisition,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.persistence import PersistentProtectedPlanningStore

from . import _secret_bulk_import_worker as worker
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_bulk_import_file import ProtectedBulkImportRows, _ParserLifetime, _Rows, _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_row_namespace import OriginalImportRow, resolve_original_import_rows
from .secret_bulk_import_session import _OwnerFileSourceSession


class OriginalRowAcquisitionAuthority(Protocol):
    """Read-only exact child/source authorization, not an M4 approval consumer.

    Trusted composition must check the original child, requester, initial-
    onboarding purpose, policy, scope, audience and fresh dependencies. This
    candidate defines no production implementation or authority issuance path.
    """

    def verify_row_acquisition(
        self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
        source: OwnerFileIntakeBinding, *, now_epoch: int,
    ) -> object: ...

    def acquisition_expires_at(self) -> int: ...

    def verify_row_completion(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                              source: OwnerFileIntakeBinding, *, now_epoch: int) -> object: ...


class _OwnedOriginalImportRow(_OpaqueC3Object):
    """One selected native row, all fields preserved in owned mutable memory.

    No material getter or caller-selected consumer exists. A fixed row adapter
    still needs qualification before this can become a consumable material lease.
    """

    __slots__ = ("_row", "_buffers", "_lifetime", "_lock", "_closed", "_watchdog", "_consumed")

    def __init__(self, row: OriginalImportRow, buffers: tuple[bytearray, ...],
                 lifetime: _ParserLifetime) -> None:
        self._row, self._buffers, self._lifetime = row, buffers, lifetime
        self._lock, self._closed = threading.RLock(), threading.Event()
        self._consumed = False
        self._watchdog: threading.Thread | None = None
        try:
            if len(buffers) != len(worker.HEADERS) or any(type(value) is not bytearray for value in buffers):
                raise ValueError
            lifetime.check()
            self._watchdog = threading.Thread(target=self._watch, name="owner-row-disposal", daemon=True)
            self._watchdog.start()
        except BaseException:
            self.close()
            raise BulkImportIntakeError(_ERROR) from None

    def _watch(self) -> None:
        try:
            while not self._closed.wait(min(0.05, self._lifetime.deadline - time.monotonic())):
                self._lifetime.check()
        except BaseException:
            pass
        finally:
            self.close()

    def close(self) -> None:
        self._closed.set()
        with self._lock:
            for value in self._buffers:
                _wipe(value)
        watchdog = self._watchdog
        if watchdog is not None and watchdog is not threading.current_thread() and watchdog.ident is not None:
            watchdog.join(timeout=1)

    def __enter__(self) -> _OwnedOriginalImportRow:
        try:
            if self._closed.is_set():
                raise ValueError
            self._lifetime.check()
            return self
        except BaseException:
            self.close()
            raise BulkImportIntakeError(_ERROR) from None

    def __exit__(self, *_: object) -> None:
        self.close()


class _PreboundOriginalImportRowLoader(_OpaqueC3Object):
    """One private loader for a newly dispatched original exact child binding."""

    def __init__(
        self, session: _OwnerFileSourceSession, parent_store: PersistentProtectedPlanningStore,
        execution_store: PersistentM4ExecutionStateStore, plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization, *, expected_parent_digest: str,
        index: int, key_path: Path, key_sha256: str,
        acquisition_authority: OriginalRowAcquisitionAuthority | None = None,
    ) -> None:
        try:
            if (type(session) is not _OwnerFileSourceSession
                    or type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or not execution_store.monotonic_checkpoint_protocol_bound):
                raise ValueError
            self._rows = resolve_original_import_rows(session, parent_store,
                original_plan_ref=plan.plan_ref, expected_plan_digest=expected_parent_digest,
                authenticated_requester_digest=plan.requester_digest,
                key_path=key_path, key_sha256=key_sha256)
            self._row = self._rows.row(index)
            self._row.verify_m4_plan(plan)
            self._session, self._parent = session, parent_store
            self._parent_digest = expected_parent_digest
            self._execution, self._plan, self._authorization = execution_store, plan, authorization
            self._authority = acquisition_authority
            self._acquisition_deadline: float | None = None
            self._lifetime: _ParserLifetime | None = None
            self._used, self._lock = False, threading.Lock()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _verify(self, *, completed: bool = False) -> None:
        session, plan, auth = self._session, self._plan, self._authorization
        _require_m4_dispatch_ownership(plan, auth, self._execution)
        context = canonical_digest({"authorization_digest": auth.authorization_digest,
            "plan_digest": plan.plan_digest, "revision": plan.revision})
        claim = self._execution.inspect_claim(plan_ref=plan.plan_ref,
            requester_digest=plan.requester_digest, idempotency_digest=plan.idempotency_digest,
            context_digest=context, authorization_digest=auth.authorization_digest)
        if claim.state is not M4ClaimState.IN_PROGRESS:
            raise ValueError
        self._parent.get_original_import_binding(plan.plan_ref,
            expected_plan_digest=self._parent_digest, requester_digest=plan.requester_digest,
            namespace_key_digest=self._rows._key.digest)
        self._verify_source_authority(completed=completed)

    def _reserve(self) -> None:
        _reserve_m4_material_acquisition(self._plan, self._authorization, self._execution)

    def _verify_source_authority(self, *, completed: bool = False) -> None:
        session, plan, auth = self._session, self._plan, self._authorization
        session._remaining()
        now = int(session._transaction._last_wall)
        if (auth.plan_ref != plan.plan_ref or auth.plan_digest != plan.plan_digest
                or auth.requester_digest != plan.requester_digest
                or auth.confirmation_digest != plan.confirmation_digest
                or auth.approval_digest != plan.approval_digest
                or not auth.issued_at <= now < min(auth.expires_at, plan.expires_at)):
            raise ValueError
        if self._authority is None:
            raise ValueError
        verify = self._authority.verify_row_completion if completed else self._authority.verify_row_acquisition
        if (verify(
                plan, auth, session._transaction._binding, now_epoch=now) is not None):
            raise ValueError
        # RPC/current-state observation can advance time. Cap against a fresh
        # sample so that verification latency never extends the grant horizon.
        session._remaining()
        until = self._authority.acquisition_expires_at()
        if type(until) is not int or not now < until <= min(auth.expires_at, plan.expires_at):
            raise ValueError
        deadline = time.monotonic() + min(60.0, until - session._transaction._last_wall)
        self._acquisition_deadline = (deadline if self._acquisition_deadline is None
                                     else min(deadline, self._acquisition_deadline))
        if time.monotonic() >= self._acquisition_deadline:
            raise ValueError
        if self._lifetime is not None:
            self._lifetime.deadline = min(self._lifetime.deadline, self._acquisition_deadline)
            self._lifetime.check()
        self._rows.verify_source_session(session, authenticated_requester_digest=plan.requester_digest)
        transaction = session._transaction
        if transaction._authority.verify(transaction._binding, now_epoch=now) is not None:
            raise ValueError
        session._remaining()

    def _load_once(self) -> _OwnedOriginalImportRow:
        """Kernel dispatch only: fresh decode, selected-row copy, whole-frame wipe."""
        if not self._lock.acquire(blocking=False):
            raise BulkImportIntakeError(_ERROR)
        acquired = False
        attempted = False
        password = bytearray()
        frame: ProtectedBulkImportRows | None = None
        selected: list[bytearray] = []
        owned: _OwnedOriginalImportRow | None = None
        try:
            if self._used:
                raise ValueError
            self._verify()
            acquired = self._session._projection_lock.acquire(blocking=False)
            if not acquired:
                raise ValueError
            self._used, attempted = True, True
            try:
                self._reserve()
            except M4AuthorizationReplay:
                # A known local refusal has not dispatched a new acquisition;
                # ambiguous remote reservation failures must clear the session.
                attempted = False
                raise
            with self._session._memory_lock:
                remaining = min(self._session._remaining(), 60.0,
                    self._authorization.expires_at - self._session._transaction._last_wall,
                    self._plan.expires_at - self._session._transaction._last_wall)
                assert self._acquisition_deadline is not None
                lifetime = _ParserLifetime(min(time.monotonic() + remaining, self._acquisition_deadline),
                                           self._session._transaction._closed)
                self._lifetime = lifetime
                password = bytearray(self._session._password)
            frame = self._session._transaction._source.decode(workbook_password=password, _lifetime=lifetime)
            self._verify()

            def select(values: _Rows) -> None:
                lifetime.check()
                if len(values) != self._rows._operation.row_count:
                    raise ValueError
                row = values[self._row.index]
                if len(row) != len(worker.HEADERS):
                    raise ValueError
                for value in row:
                    selected.append(bytearray(value))

            frame._consume_once(select, expected_sha256=self._session._transaction._binding.file_sha256)
            self._verify()
            owned = _OwnedOriginalImportRow(self._row, tuple(selected), lifetime)
            selected.clear()
            lifetime.check()
            return owned
        except BaseException:
            if owned is not None:
                owned.close()
            if attempted:
                self._session.close()
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            if frame is not None:
                frame.clear()
            for value in selected:
                _wipe(value)
            _wipe(password)
            if acquired:
                self._session._projection_lock.release()
            self._lock.release()
