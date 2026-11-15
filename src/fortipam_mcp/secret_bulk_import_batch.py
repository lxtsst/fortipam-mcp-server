"""Inactive sequential execution of the complete, retained original file graph.

Trusted composition supplies the existing fixed Target owners and original row
kernels. This coordinator has no source decoder, credentials, signing keys,
device adapter, retry or compensation capability. It adds no journal or route.
"""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Callable

from v4_planning import M4ExecutionKernel
from v4_planning.execution_kernel import M4ClaimState, M4Compensation, M4ExecutionResult, M4Outcome, M4Verification
from v4_planning.import_parent import FileImportParentRecord
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.persistence import PersistentProtectedPlanningStore

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_bulk_import_dependencies import ImportDependencyCatalog, ResolvedImportDependencies
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_parent_graph import (
    _OriginalImportTargetCreateBinding, _OriginalImportTargetReuse, _OriginalImportTargetUpdateBinding,
    _compile_original_import_graph,
)
from .secret_bulk_import_row_authority import _OriginalRowM4Authority
from .secret_bulk_import_row_channel import OriginalRowChannelOwner
from .secret_bulk_import_row_namespace import PinnedOriginalImportRows
from .target_coordinate_lifecycle import TargetCoordinateLifecycle
from .target_create_lifecycle import TargetCreateLifecycle

_TargetOwner = TargetCreateLifecycle | TargetCoordinateLifecycle | _OriginalImportTargetReuse


@dataclass(frozen=True, slots=True, repr=False)
class _OriginalImportRowExecution(_OpaqueC3Object):
    owner: OriginalRowChannelOwner
    kernel: M4ExecutionKernel

    def check(self, parent: PersistentProtectedPlanningStore, execution: PersistentM4ExecutionStateStore) -> None:
        if (type(self.owner) is not OriginalRowChannelOwner or type(self.kernel) is not M4ExecutionKernel
                or self.owner._parent is not parent or self.owner._execution is not execution
                or self.kernel._state is not execution
                or type(self.kernel._authorizer) is not _OriginalRowM4Authority
                or self.kernel._authorizer._execution is not execution
                or self.kernel._authorizer._parent_store is not parent
                or self.kernel._authorizer._issued != self.owner._binding.permission
                or self.owner._ack_pins is None or self.owner._material_store is None):
            raise BulkImportIntakeError(_ERROR)


@dataclass(frozen=True, slots=True)
class _OriginalImportBatchResult:
    """Counts only; exact action outcomes remain in the original durable stores."""

    verified_lines: int
    total_lines: int
    completed: bool


def _verified(result: M4ExecutionResult) -> None:
    if (type(result) is not M4ExecutionResult or result.idempotent_replay
            or result.outcome is not M4Outcome.SUCCEEDED
            or result.verification is not M4Verification.VERIFIED
            or result.compensation is not M4Compensation.NOT_REQUESTED):
        raise BulkImportIntakeError(_ERROR)


def _target_binding(owner: _TargetOwner) -> _OriginalImportTargetCreateBinding | _OriginalImportTargetUpdateBinding | _OriginalImportTargetReuse:
    if type(owner) is _OriginalImportTargetReuse:
        return owner
    if type(owner) is TargetCreateLifecycle:
        binding = owner._authority._original_import
        if type(binding) is _OriginalImportTargetCreateBinding:
            return binding
    if type(owner) is TargetCoordinateLifecycle and owner._phase == 'update':
        binding = owner._authority._original_import
        if type(binding) is _OriginalImportTargetUpdateBinding:
            return binding
    raise BulkImportIntakeError(_ERROR)


class _OriginalImportBatch(_OpaqueC3Object):
    """One operator, one exact graph, no replay or continuation after a stop."""

    def __init__(self, original: PinnedOriginalImportRows, source: OwnerFileIntakeBinding,
                 projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog,
                 parent: PersistentProtectedPlanningStore, execution: PersistentM4ExecutionStateStore, *,
                 expected_parent_digest: str, targets: tuple[_TargetOwner, ...],
                 rows: tuple[_OriginalImportRowExecution, ...], execution_enabled: bool = False,
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(execution) is not PersistentM4ExecutionStateStore
                    or not execution.monotonic_checkpoint_protocol_bound
                    or type(targets) is not tuple or len(targets) > 256
                    or type(rows) is not tuple or not 1 <= len(rows) <= 256
                    or any(type(row) is not _OriginalImportRowExecution for row in rows)
                    or type(execution_enabled) is not bool or not callable(clock)):
                raise ValueError
            graph = _compile_original_import_graph(original, source, projected, catalog, parent,
                expected_parent_digest=expected_parent_digest,
                authenticated_requester_digest=original._operation.requester_digest, clock=clock)
            record = parent.get_import_parent(graph.parent_ref)
            if type(record) is not FileImportParentRecord:
                raise ValueError
            self._original, self._source, self._projected, self._catalog = original, source, projected, catalog
            self._parent, self._execution, self._record, self._graph = parent, execution, record, graph
            self._targets, self._rows, self._clock = targets, rows, clock
            self._enabled, self._used, self._lock = execution_enabled, False, threading.Lock()
            self._last_now = record.created_at
            self._check()
            self._check_composition()
            self._claims(set())
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _check(self) -> int:
        now, record = self._clock(), self._record
        if (type(now) is not int or not self._last_now <= now < min(record.expires_at, self._source.expires_at)
                or time.monotonic() >= self._graph.deadline
                or self._parent.get_import_parent(record.plan_ref) != record):
            raise BulkImportIntakeError(_ERROR)
        self._last_now = now
        self._parent.get_original_import_binding(record.plan_ref, expected_plan_digest=record.plan_digest,
            requester_digest=record.requester_digest, namespace_key_digest=record.namespace_key_digest)
        self._original._verify_dependencies_binding(self._source, self._projected, self._catalog,
            authenticated_requester_digest=record.requester_digest)
        return now

    def _check_composition(self) -> None:
        record = self._record
        target_lines = tuple(line for line in record.lines if line.kind == 'target')
        row_lines = tuple(line for line in record.lines if line.kind == 'secret')
        if (len(self._targets) != len(target_lines) or len(self._rows) != len(row_lines)
                or len({id(owner) for owner in self._targets}) != len(self._targets)
                or len({id(row.owner) for row in self._rows}) != len(self._rows)):
            raise BulkImportIntakeError(_ERROR)
        owners: dict[str, _TargetOwner | OriginalRowChannelOwner] = {}
        for line, owner in zip(target_lines, self._targets, strict=True):
            binding = _target_binding(owner)
            if (binding.parent != record or binding.line != line or binding._parent_store is not self._parent
                    or binding._source != self._source
                    or not isinstance(owner, _OriginalImportTargetReuse) and owner._store is not self._execution):
                raise BulkImportIntakeError(_ERROR)
            owners[line.line_ref] = owner
        for line, row in zip(row_lines, self._rows, strict=True):
            row.check(self._parent, self._execution)
            b = row.owner._binding
            if (b.plan.plan_ref != record.plan_ref or b.parent_digest != record.plan_digest
                    or b.source != self._source or b.plan.requester_digest != record.requester_digest
                    or b.plan.idempotency_digest != line.idempotency_digest
                    or b.plan.parameters_digest != line.parameters_digest
                    or b.plan.target_ref != line.line_ref
                    or b.namespace_key_digest != record.namespace_key_digest
                    or {id(owner) for owner in (*row.owner._dependency_owners, *row.owner._target_owners)}
                        != {id(owners[ref]) for ref in line.depends_on}):
                raise BulkImportIntakeError(_ERROR)
            owners[line.line_ref] = row.owner

    def _claims(self, verified: set[str]) -> None:
        lines = tuple(line for line in self._record.lines if line.idempotency_digest is not None)
        identities = tuple(line.idempotency_digest for line in lines if line.idempotency_digest is not None)
        claims = self._execution._inspect_original_claims(plan_ref=self._record.plan_ref,
            requester_digest=self._record.requester_digest, idempotency_digests=identities)
        for line, claim in zip(lines, claims, strict=True):
            if line.line_ref in verified:
                if claim.state is not M4ClaimState.REPLAY or claim.result is None:
                    raise BulkImportIntakeError(_ERROR)
                # Inspecting an existing terminal is evidence, never a dispatch replay.
                result = claim.result
                if (result.outcome is not M4Outcome.SUCCEEDED or result.verification is not M4Verification.VERIFIED
                        or result.compensation is not M4Compensation.NOT_REQUESTED):
                    raise BulkImportIntakeError(_ERROR)
            elif claim.state is not M4ClaimState.NEW:
                raise BulkImportIntakeError(_ERROR)

    def execute_once(self) -> _OriginalImportBatchResult:
        if not self._lock.acquire(blocking=False):
            raise BulkImportIntakeError(_ERROR)
        verified: set[str] = set()
        try:
            if not self._enabled or self._used:
                raise BulkImportIntakeError(_ERROR)
            self._used = True
            try:
                self._check_composition()
                self._check()
                self._claims(verified)
                targets = iter(self._targets)
                rows = iter(self._rows)
                for step in self._graph.steps:
                    self._check()
                    self._claims(verified)
                    if not set(step.depends_on) <= verified:
                        raise BulkImportIntakeError(_ERROR)
                    if step.kind == 'target':
                        owner = next(targets)
                        if not isinstance(owner, _OriginalImportTargetReuse):
                            issued = owner.issue(owner.preview())
                            _verified(owner.execute(issued))
                        owner._inspect_verified_import_target()
                    else:
                        row = next(rows)
                        row.check(self._parent, self._execution)
                        row.owner.prepare_original_dispatch()
                        b = row.owner._binding
                        _verified(row.kernel.execute(b.plan, b.authorization, now_epoch=self._check()))
                        row.owner._inspect_verified_ack()
                    verified.add(step.line_ref)
                self._check()
                self._claims(verified)
                return _OriginalImportBatchResult(len(verified), len(self._graph.steps), True)
            except BaseException as error:
                # Reuse the existing append-only parent refusal; never clear child claims.
                self._parent.invalidate_plan(self._record.plan_ref, evaluated_at=self._last_now,
                    reason_codes=('current_state_unavailable_or_unsafe',))
                if not isinstance(error, Exception):
                    raise
                return _OriginalImportBatchResult(len(verified), len(self._graph.steps), False)
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            self._lock.release()
