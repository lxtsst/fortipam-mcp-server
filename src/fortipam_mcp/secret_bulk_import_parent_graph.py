"""Private complete original-import DAG; no M2 profile or execution authority.

The existing M2 profile describes AD discovery and has a different cardinality.
This candidate decomposes the retained file graph without truncating it or
changing that profile. Parent intent, fixed child authorization, fresh product
predicates and verified dependency ownership remain separate requirements.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hmac
import math
import time
from typing import Callable, Literal

from v4_planning import canonical_digest
from v4_planning.import_parent import CONTRACT, FileImportParentRecord, FileImportPlanLine
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.persistence import PersistentProtectedPlanningStore
from v4_planning.secret_create_adapter import SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION
from v4_planning.store import OriginalImportBindingRecord

from .secret_bulk_import_dependencies import (
    ImportDependencyCatalog, ImportRowDependency, ImportTargetDependency,
    ResolvedImportDependencies, dependency_catalog_digest,
)
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_row_namespace import PinnedOriginalImportRows, _commit
from .m4_execution_store import PersistentM4ExecutionStateStore
from .target_creation_http_transport import TargetCreationHttpTransport
from .target_preservation_http_transport import TargetCoordinateHttpTransport
from .target_api_dependency_reader import TargetApiDependencyReader
from . import target_preservation_contract as target_contract
from v4_planning.execution_kernel import M4ClaimState, M4Outcome, M4Verification, M4Compensation


@dataclass(frozen=True, slots=True, repr=False)
class _OriginalImportStep(_OpaqueC3Object):
    line_ref: str
    kind: Literal['target', 'secret']
    index: int
    action_id: str | None
    action_version: str | None
    idempotency_digest: str | None
    parameters_digest: str
    depends_on: tuple[str, ...]


@dataclass(frozen=True, slots=True, repr=False)
class _OriginalImportGraph(_OpaqueC3Object):
    parent_ref: str
    parent_digest: str
    dependency_commitment: str
    steps: tuple[_OriginalImportStep, ...]
    graph_digest: str
    deadline: float


class _OriginalImportTargetReuse(_OpaqueC3Object):
    """Fresh read prerequisite for one unchanged Target in the original import.

    This object has no mutation, acquisition, M4 claim or cleanup capability.
    The row owner still verifies all original batch claims before material use.
    """

    def __init__(self, original: PinnedOriginalImportRows, source: OwnerFileIntakeBinding,
                 projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog,
                 parent_store: PersistentProtectedPlanningStore, reader: TargetApiDependencyReader,
                 baseline: target_contract.TargetState, *, index: int, expected_parent_digest: str,
                 expected_source_context_digest: str, clock: Callable[[], int]) -> None:
        try:
            target_contract._checked_state(baseline)
            if (type(reader) is not TargetApiDependencyReader or type(index) is not int
                    or not callable(clock) or reader._source != expected_source_context_digest
                    or reader._serial != baseline.serial_digest):
                raise ValueError
            now = clock()
            if type(now) is not int:
                raise ValueError
            _compile_original_import_graph(original, source, projected, catalog, parent_store,
                expected_parent_digest=expected_parent_digest,
                authenticated_requester_digest=original._operation.requester_digest, clock=lambda: now)
            parent = parent_store.get_import_parent(original._operation.plan_ref)
            if type(parent) is not FileImportParentRecord:
                raise ValueError
            targets = projected._inspect_private(lambda _rows, targets, _order: targets,
                file_digest=source.file_sha256, catalog_digest=dependency_catalog_digest(catalog))
            if not 0 <= index < len(targets):
                raise ValueError
            target = targets[index]
            lines = [line for line in parent.lines if line.kind == 'target' and line.index == index]
            if (target.effect != 'reuse' or len(lines) != 1 or lines[0].effect != 'reuse'
                    or lines[0].idempotency_digest is not None or target.existing_name != baseline.name
                    or target.baseline_digest != baseline.state_digest
                    or baseline.coordinates != target_contract.TargetCoordinates(
                        target.template, target.address, target.domain, target.url)):
                raise ValueError
            self.parent, self.line = parent, lines[0]
            self._parent_store, self._reader, self._baseline = parent_store, reader, baseline
            self._original, self._source = original, source
            self._source_context, self._clock, self._last_now = expected_source_context_digest, clock, now
            self._check()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _check(self) -> None:
        now, parent = self._clock(), self.parent
        if (type(now) is not int or not parent.created_at <= self._last_now <= now < parent.expires_at
                or self._parent_store.get_import_parent(parent.plan_ref) != parent
                or self._reader._source != self._source_context
                or self._reader._serial != self._baseline.serial_digest):
            raise BulkImportIntakeError(_ERROR)
        self._last_now = now
        self._parent_store.get_original_import_binding(parent.plan_ref,
            expected_plan_digest=parent.plan_digest, requester_digest=parent.requester_digest,
            namespace_key_digest=parent.namespace_key_digest)
        self._original._verify_source_binding(self._source, authenticated_requester_digest=parent.requester_digest)

    def _inspect_verified_import_target(self) -> target_contract.TargetState:
        try:
            self._check()
            observed = self._reader.observe((self._baseline.coordinates,))
            current = self._reader.read_target_state(self._baseline, observed, before_send=self._check)
            if current != self._baseline:
                raise ValueError
            self._check()
            return current
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None


class _OriginalImportTargetCreateBinding(_OpaqueC3Object):
    """Bind the existing fixed creator to one retained original parent line.

    Trusted composition supplies separately qualified API source/device pins.
    This join grants no source permission or device authority by itself.
    """

    def __init__(self, original: PinnedOriginalImportRows, source: OwnerFileIntakeBinding,
                 projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog,
                 parent_store: PersistentProtectedPlanningStore, execution: PersistentM4ExecutionStateStore,
                 creator: TargetCreationHttpTransport, *, index: int, expected_parent_digest: str,
                 expected_source_context_digest: str, expected_serial_digest: str, now_epoch: int) -> None:
        try:
            if (type(execution) is not PersistentM4ExecutionStateStore
                    or not execution.monotonic_checkpoint_protocol_bound
                    or type(creator) is not TargetCreationHttpTransport or type(index) is not int
                    or type(now_epoch) is not int
                    or creator._source_context_digest != expected_source_context_digest
                    or creator._proposal.serial_digest != expected_serial_digest):
                raise ValueError
            _compile_original_import_graph(original, source, projected, catalog, parent_store,
                expected_parent_digest=expected_parent_digest,
                authenticated_requester_digest=original._operation.requester_digest, clock=lambda: now_epoch)
            parent = parent_store.get_import_parent(original._operation.plan_ref)
            if type(parent) is not FileImportParentRecord:
                raise ValueError
            targets = projected._inspect_private(lambda _rows, targets, _order: targets,
                file_digest=source.file_sha256, catalog_digest=dependency_catalog_digest(catalog))
            if not 0 <= index < len(targets):
                raise ValueError
            target = targets[index]
            coordinates = target_contract.TargetCoordinates(target.template, target.address, target.domain, target.url)
            lines = [line for line in parent.lines if line.kind == 'target' and line.index == index]
            if (target.effect != 'create' or len(lines) != 1 or lines[0].effect != 'create'
                    or lines[0].idempotency_digest is None or creator._proposal.coordinates != coordinates):
                raise ValueError
            self.parent, self.line = parent, lines[0]
            self._parent_store, self.execution, self.creator = parent_store, execution, creator
            self._original, self._source = original, source
            self._source_context, self._serial = expected_source_context_digest, expected_serial_digest
            self.input_digest = target_contract._digest((creator._namespace, creator._body_digest,
                                                         creator._proposal.state_digest))
            self._last_now = now_epoch
            self.check(now_epoch, pending=True)
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def check(self, now_epoch: int, *, pending: bool = False, completed: bool = False) -> None:
        """Read one original batch snapshot; never mint or consume another tuple."""
        try:
            parent = self.parent
            if (type(now_epoch) is not int or not self._last_now <= now_epoch < parent.expires_at
                    or now_epoch < parent.created_at or pending and completed
                    or self._parent_store.get_import_parent(parent.plan_ref) != parent
                    or self.creator._source_context_digest != self._source_context
                    or self.creator._proposal.serial_digest != self._serial
                    or self.input_digest != target_contract._digest((self.creator._namespace,
                        self.creator._body_digest, self.creator._proposal.state_digest))):
                raise ValueError
            self._last_now = now_epoch
            self._parent_store.get_original_import_binding(parent.plan_ref,
                expected_plan_digest=parent.plan_digest, requester_digest=parent.requester_digest,
                namespace_key_digest=parent.namespace_key_digest)
            self._original._verify_source_binding(self._source, authenticated_requester_digest=parent.requester_digest)
            ids = tuple(line.idempotency_digest for line in parent.lines if line.idempotency_digest is not None)
            claims = self.execution._inspect_original_claims(plan_ref=parent.plan_ref,
                requester_digest=parent.requester_digest, idempotency_digests=ids)
            for identity, claim in zip(ids, claims, strict=True):
                selected = identity == self.line.idempotency_digest
                if completed and not selected:
                    continue
                if selected and pending:
                    if claim.state is not M4ClaimState.NEW:
                        raise ValueError
                    continue
                if claim.state is M4ClaimState.NEW and not (selected and completed):
                    continue
                if selected and claim.state is M4ClaimState.IN_PROGRESS and not completed:
                    continue
                result = claim.result
                if (claim.state is not M4ClaimState.REPLAY or result is None
                        or result.outcome is not M4Outcome.SUCCEEDED
                        or result.verification is not M4Verification.VERIFIED
                        or result.compensation is not M4Compensation.NOT_REQUESTED):
                    raise ValueError
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None


class _OriginalImportTargetUpdateBinding(_OpaqueC3Object):
    """Bind an existing Target update to its original file line, without creation ownership."""

    def __init__(self, original: PinnedOriginalImportRows, source: OwnerFileIntakeBinding,
                 projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog,
                 parent_store: PersistentProtectedPlanningStore, execution: PersistentM4ExecutionStateStore,
                 transport: TargetCoordinateHttpTransport, *, index: int, expected_parent_digest: str,
                 expected_source_context_digest: str, expected_serial_digest: str, now_epoch: int) -> None:
        try:
            if (type(execution) is not PersistentM4ExecutionStateStore
                    or not execution.monotonic_checkpoint_protocol_bound
                    or type(transport) is not TargetCoordinateHttpTransport or type(index) is not int
                    or type(now_epoch) is not int or transport._source_context_digest is None
                    or transport._source_context_digest != expected_source_context_digest
                    or transport._change.baseline.serial_digest != expected_serial_digest):
                raise ValueError
            _compile_original_import_graph(original, source, projected, catalog, parent_store,
                expected_parent_digest=expected_parent_digest,
                authenticated_requester_digest=original._operation.requester_digest, clock=lambda: now_epoch)
            parent = parent_store.get_import_parent(original._operation.plan_ref)
            if type(parent) is not FileImportParentRecord:
                raise ValueError
            targets = projected._inspect_private(lambda _rows, targets, _order: targets,
                file_digest=source.file_sha256, catalog_digest=dependency_catalog_digest(catalog))
            if not 0 <= index < len(targets):
                raise ValueError
            target, change = targets[index], transport._change
            target_contract._checked_change(change)
            lines = [line for line in parent.lines if line.kind == 'target' and line.index == index]
            if (target.effect != 'update' or len(lines) != 1 or lines[0].effect != 'update'
                    or lines[0].idempotency_digest is None or target.existing_name != change.baseline.name
                    or target.baseline_digest != change.baseline.state_digest
                    or change.desired != target_contract.TargetCoordinates(
                        target.template, target.address, target.domain, target.url)):
                raise ValueError
            self.parent, self.line = parent, lines[0]
            self._parent_store, self.execution, self.transport = parent_store, execution, transport
            self._original, self._source, self._change = original, source, change
            self._source_context, self._serial = expected_source_context_digest, expected_serial_digest
            self.input_digest = target_contract._digest((transport._namespace, change.baseline.state_digest,
                tuple(getattr(change.desired, key) for key in target_contract._COORDINATES)))
            self._last_now = now_epoch
            self.check(now_epoch, pending=True)
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def check(self, now_epoch: int, *, pending: bool = False, completed: bool = False,
              restoring: bool = False) -> None:
        """Unknown operations stop forward work; restore also requires unused child rows."""
        try:
            parent, transport = self.parent, self.transport
            if (type(now_epoch) is not int or not parent.created_at <= self._last_now <= now_epoch < parent.expires_at
                    or pending and (completed or restoring)
                    or self._parent_store.get_import_parent(parent.plan_ref) != parent
                    or transport._source_context_digest != self._source_context
                    or transport._change != self._change or transport._change.baseline.serial_digest != self._serial
                    or self.input_digest != target_contract._digest((transport._namespace,
                        self._change.baseline.state_digest,
                        tuple(getattr(self._change.desired, key) for key in target_contract._COORDINATES)))):
                raise ValueError
            self._last_now = now_epoch
            self._parent_store.get_original_import_binding(parent.plan_ref,
                expected_plan_digest=parent.plan_digest, requester_digest=parent.requester_digest,
                namespace_key_digest=parent.namespace_key_digest)
            self._original._verify_source_binding(self._source, authenticated_requester_digest=parent.requester_digest)
            lines = tuple(line for line in parent.lines if line.idempotency_digest is not None)
            ids = tuple(line.idempotency_digest for line in lines if line.idempotency_digest is not None)
            claims = self.execution._inspect_original_claims(plan_ref=parent.plan_ref,
                requester_digest=parent.requester_digest, idempotency_digests=ids)
            for line, claim in zip(lines, claims, strict=True):
                selected = line == self.line
                if restoring and self.line.line_ref in line.depends_on and claim.state is not M4ClaimState.NEW:
                    raise ValueError
                if completed and not selected and not restoring:
                    continue
                if selected and pending:
                    if claim.state is not M4ClaimState.NEW:
                        raise ValueError
                    continue
                if claim.state is M4ClaimState.NEW and not (selected and (completed or restoring)):
                    continue
                if selected and claim.state is M4ClaimState.IN_PROGRESS and not (completed or restoring):
                    continue
                result = claim.result
                if (claim.state is not M4ClaimState.REPLAY or result is None
                        or result.outcome is not M4Outcome.SUCCEEDED
                        or result.verification is not M4Verification.VERIFIED
                        or result.compensation is not M4Compensation.NOT_REQUESTED):
                    raise ValueError
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None


def _validate_graph(rows: tuple[ImportRowDependency, ...], targets: tuple[ImportTargetDependency, ...],
                    order: tuple[int, ...], catalog: ImportDependencyCatalog) -> None:
    if (not 1 <= len(rows) <= 256 or len(targets) > len(rows)
            or any(type(index) is not int for index in order)
            or sorted(order) != list(range(len(rows)))):
        raise ValueError
    positions = {index: position for position, index in enumerate(order)}
    used: set[int] = set()
    folders = {folder.identifier for folder in catalog.folders if folder.can_add}
    templates = {template.name for template in catalog.templates}
    associations = {secret.identifier for secret in catalog.secrets if secret.can_associate}
    names = {name.casefold() for name in catalog.secret_names}
    for index, row in enumerate(rows):
        if (type(row) is not ImportRowDependency or type(row.name) is not str
                or type(row.index) is not int or row.index != index
                or not row.name or row.name.casefold() in names
                or type(row.folder_id) is not int or row.folder_id not in folders
                or type(row.template) is not str or row.template not in templates):
            raise ValueError
        names.add(row.name.casefold())
        group, association = row.target_group, row.association_row
        if group is not None:
            if (type(group) is not int or not 0 <= group < len(targets)
                    or targets[group].template != row.template):
                raise ValueError
            used.add(group)
        if association is not None:
            if (type(association) is not int or association not in positions
                    or row.association_id is not None or positions[association] >= positions[row.index]):
                raise ValueError
        elif row.association_id is not None and (type(row.association_id) is not int
                                                or row.association_id not in associations):
            raise ValueError
    if used != set(range(len(targets))):
        raise ValueError
    existing = {target.name: target for target in catalog.targets}
    affected: set[str] = set()
    for target in targets:
        if type(target) is not ImportTargetDependency or target.effect not in ('create', 'update', 'reuse'):
            raise ValueError
        coordinates = (target.address, target.domain, target.url)
        if not any(coordinates):
            raise ValueError
        # Match the resolver's overlap rule; never generate a second Target
        # write for an overlapping destination hidden behind a different index.
        overlaps = [current for current in catalog.targets if any(value and value == old for value, old
            in zip(coordinates, (current.address, current.domain, current.url), strict=True))]
        if target.effect == 'create':
            if target.existing_name is not None or target.baseline_digest is not None or overlaps:
                raise ValueError
        else:
            current = existing.get(target.existing_name or '')
            if (current is None or current.baseline_digest != target.baseline_digest
                    or overlaps != [current] or current.name in affected):
                raise ValueError
            affected.add(current.name)
            unchanged = (current.template, current.address, current.domain, current.url) == (
                target.template, *coordinates)
            if (target.effect == 'reuse') is not unchanged:
                raise ValueError
    for index, target in enumerate(targets):
        if any(any(value and value == other for value, other in zip(
            (target.address, target.domain, target.url), (prior.address, prior.domain, prior.url), strict=True))
            for prior in targets[:index]):
            raise ValueError


def _compile_steps(
    original: PinnedOriginalImportRows, binding: OwnerFileIntakeBinding,
    projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog, key: bytearray,
) -> tuple[tuple[_OriginalImportStep, ...], tuple[FileImportPlanLine, ...]]:
    rows, targets, order = projected._inspect_private(lambda rows, targets, order: (rows, targets, order),
        file_digest=binding.file_sha256, catalog_digest=dependency_catalog_digest(catalog))
    _validate_graph(rows, targets, order, catalog)
    secret_rows = tuple(original.row(index) for index in range(len(rows)))
    context = asdict(original._operation)
    target_refs = tuple('import-target-' + _commit(key, b'target-line', [context, index])
                        for index in range(len(targets)))
    secret_refs = tuple('import-secret-' + row.idempotency_digest for row in secret_rows)
    steps: list[_OriginalImportStep] = []
    for index, target in enumerate(targets):
        action = None if target.effect == 'reuse' else 'target-lifecycle-' + target.effect
        action_context = [context, index, action, '1.0.0', asdict(target)]
        steps.append(_OriginalImportStep(target_refs[index], 'target', index, action,
            '1.0.0' if action else None,
            _commit(key, b'target-idempotency', action_context) if action else None,
            _commit(key, b'target-parameters', action_context), ()))
    for index in order:
        dependency, row = rows[index], secret_rows[index]
        dependencies = tuple(ref for ref in (
            target_refs[dependency.target_group] if dependency.target_group is not None else None,
            secret_refs[dependency.association_row] if dependency.association_row is not None else None,
        ) if ref is not None)
        steps.append(_OriginalImportStep(secret_refs[index], 'secret', index,
            SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION, row.idempotency_digest,
            row.parameters_digest, dependencies))
    # A fixed topological sequence retains all nodes. It is not permission
    # to schedule a child or to infer a reused Target has been verified.
    seen: set[str] = set()
    for step in steps:
        if step.line_ref in seen or any(ref not in seen for ref in step.depends_on):
            raise ValueError
        seen.add(step.line_ref)
    if not 1 <= len(steps) <= 512:
        raise ValueError

    intent_lines = []
    for step in steps:
        selected_target = targets[step.index] if step.kind == 'target' else None
        effect = selected_target.effect if selected_target else 'create'
        current = _commit(key, b'line-current', [context, step.kind, step.index,
            selected_target.baseline_digest if selected_target else None, effect != 'create'])
        expected = current if effect == 'reuse' else _commit(key, b'line-expected',
            [context, step.kind, step.index, step.parameters_digest, True])
        intent_lines.append(FileImportPlanLine(step.line_ref, step.kind, effect, step.index,
            step.parameters_digest, current, expected, step.idempotency_digest, step.depends_on))
    return tuple(steps), tuple(intent_lines)


def _build_file_import_parent(
    original: PinnedOriginalImportRows, binding: OwnerFileIntakeBinding,
    projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog, *,
    source_policy_digest: str, owner_decision_digest: str, created_at: int, expires_at: int,
    standing_lab_authorization: bool = False,
) -> FileImportParentRecord:
    """Trusted Owner composition only, after fresh identity/Reference checks.

    The exact lab intent is a technical record, not a human approval claim or
    device authorization. It binds complete private C/P/E before child promotion.
    No Tool accepts the standing flag, source selectors, graph or returned record.
    """
    key = None
    try:
        if (standing_lab_authorization is not True or catalog.scope_digest != binding.scope_digest
                or not binding.issued_at <= created_at < expires_at <= binding.expires_at):
            raise ValueError
        original._verify_dependencies_binding(binding, projected, catalog,
            authenticated_requester_digest=original._operation.requester_digest)
        key = original._key.load()
        _, lines = _compile_steps(original, binding, projected, catalog, key)
        payload = dict(asdict(original._operation), contract=CONTRACT, policy_mode='lab_auto',
            dispatchable=False, namespace_key_digest=original._key.digest,
            environment_digest=binding.deployment_digest, scope_digest=binding.scope_digest,
            audience_digest=_commit(key, b'parent-audience', binding.planning_resource),
            source_policy_digest=source_policy_digest, owner_decision_digest=owner_decision_digest,
            created_at=created_at, expires_at=expires_at,
            line_groups=[[line.as_dict() for line in lines[start:start + 64]]
                         for start in range(0, len(lines), 64)])
        payload['intent_policy_digest'] = _commit(key, b'lab-parent-intent', payload)
        return FileImportParentRecord.from_payload({**payload, 'plan_digest': canonical_digest(payload)})
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        if key is not None:
            _wipe(key)


def _compile_original_import_graph(
    original: PinnedOriginalImportRows, binding: OwnerFileIntakeBinding,
    projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog,
    store: PersistentProtectedPlanningStore, *, expected_parent_digest: str,
    authenticated_requester_digest: str, clock: Callable[[], float] = time.time,
) -> _OriginalImportGraph:
    """Read-only compilation from the retained original, not a new operation.

    Reuse Targets remain fixed read prerequisites with no mutation identity.
    Target mutation identities are private original-graph candidates: their
    existing lifecycle authority still has to bind them before dispatch. Secret
    identities are exactly those already used by the original row/M4 channel.
    """
    key = None
    try:
        if (type(original) is not PinnedOriginalImportRows or type(store) is not PersistentProtectedPlanningStore
                or type(binding) is not OwnerFileIntakeBinding or type(catalog) is not ImportDependencyCatalog
                or type(projected) is not ResolvedImportDependencies or not callable(clock)
                or catalog.scope_digest != binding.scope_digest):
            raise ValueError
        start, mono = float(clock()), time.monotonic()
        last_wall = start
        operation = original._operation
        expected = OriginalImportBindingRecord(plan_digest=expected_parent_digest,
            namespace_key_digest=original._key.digest, **asdict(operation))

        def verify_parent() -> float:
            nonlocal last_wall
            record = store.get_original_import_binding(operation.plan_ref,
                expected_plan_digest=expected_parent_digest, requester_digest=authenticated_requester_digest,
                namespace_key_digest=original._key.digest)
            parent = store.get_import_parent(operation.plan_ref)
            now = float(clock())
            if (record != expected or not math.isfinite(now) or not math.isfinite(start) or now < last_wall
                    or not parent.created_at <= start <= now < parent.expires_at
                    or parent.plan_digest != expected_parent_digest
                    or parent.requester_digest != authenticated_requester_digest
                    or not binding.issued_at <= start <= now < binding.expires_at):
                raise ValueError
            last_wall = now
            return min(parent.expires_at, binding.expires_at)

        until = verify_parent()
        original._verify_dependencies_binding(binding, projected, catalog,
            authenticated_requester_digest=authenticated_requester_digest)
        key = original._key.load()
        steps, intent_lines = _compile_steps(original, binding, projected, catalog, key)
        parent = store.get_import_parent(operation.plan_ref)
        if type(parent) is FileImportParentRecord:
            intent = parent.canonical_content()
            intent.pop('intent_policy_digest')
            if (parent.lines != intent_lines or parent.environment_digest != binding.deployment_digest
                    or parent.scope_digest != binding.scope_digest
                    or parent.audience_digest != _commit(key, b'parent-audience', binding.planning_resource)
                    or not hmac.compare_digest(parent.intent_policy_digest, _commit(key, b'lab-parent-intent', intent))):
                raise ValueError
        digest = _commit(key, b'compiled-parent-graph', dict(
            parent=expected_parent_digest, original=asdict(operation), steps=[asdict(step) for step in steps]))
        if verify_parent() != until:
            raise ValueError
        original._verify_dependencies_binding(binding, projected, catalog,
            authenticated_requester_digest=authenticated_requester_digest)
        after = float(clock())
        deadline = min(catalog.expires_at, mono + min(60.0, until - start))
        if not math.isfinite(after) or not last_wall <= after < until or time.monotonic() >= deadline:
            raise ValueError
        return _OriginalImportGraph(operation.plan_ref, expected_parent_digest,
            operation.dependency_commitment, tuple(steps), digest, deadline)
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        if key is not None:
            _wipe(key)
