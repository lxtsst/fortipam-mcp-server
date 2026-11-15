"""Private original-row M4 namespace binding; no claim, acquisition or authority.

Trusted parent-plan composition retains the original binding in its existing
protected records. A fresh intake can validate that binding, never replace it.
The existing M4 kernel/store remain responsible for authorization and replay.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from pathlib import Path

from v4_planning import M4ExecutionPlan
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref
from v4_planning.persistence import PersistentProtectedPlanningStore
from v4_planning.store import OriginalImportBindingRecord
from v4_planning.secret_create_adapter import SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION

from .secret_bulk_import_dependencies import (
    ImportDependencyCatalog, ResolvedImportDependencies, dependency_catalog_digest,
)
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_session import _OwnerFileSourceSession
from .secret_bulk_import_token_channel import _PinnedKey

_DOMAIN = b"fortipam-original-import-row/v1\0"


def _commit(key: bytearray, purpose: bytes, value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hmac.new(key, _DOMAIN + purpose + b"\0" + raw, hashlib.sha256).hexdigest()


def _input(binding: OwnerFileIntakeBinding) -> dict[str, object]:
    # Original input identity excludes paths, admission times, new clients and
    # workload instances. Each new session must independently authorize those.
    return {name: getattr(binding, name) for name in (
        "file_sha256", "file_format", "issuer", "subject", "planning_resource",
        "deployment_digest", "scope_digest", "batch_digest")}


def _dependency_commitment(key: bytearray, binding: OwnerFileIntakeBinding,
                           projected: ResolvedImportDependencies,
                           catalog: ImportDependencyCatalog) -> tuple[int, str]:
    from .secret_bulk_import_dependencies import ImportRowDependency, ImportTargetDependency
    catalog_digest = dependency_catalog_digest(catalog)
    metadata = asdict(catalog)
    for name in ("observed_at", "expires_at"):
        metadata.pop(name)
    for name in ("coverage", "service_types"):
        metadata[name] = sorted(metadata[name])
    def original_graph(rows: object, targets: object, order: object) -> tuple[int, str]:
        if (type(rows) is not tuple or not all(type(row) is ImportRowDependency for row in rows)
                or type(targets) is not tuple or not all(type(target) is ImportTargetDependency for target in targets)
                or type(order) is not tuple or any(type(index) is not int for index in order)
                or any(type(row.index) is not int for row in rows) or sorted(order) != list(range(len(rows)))
                or [row.index for row in rows] != list(range(len(rows)))):
            raise ValueError
        return len(rows), _commit(key, b"dependencies", [metadata,
            [asdict(row) for row in rows], [asdict(target) for target in targets], order])
    return projected._inspect_private(original_graph,
        file_digest=binding.file_sha256, catalog_digest=catalog_digest)


@dataclass(frozen=True, slots=True, repr=False)
class OriginalImportOperation(_OpaqueC3Object):
    """Immutable original parent commitments; consistency evidence, not authority."""

    plan_ref: str
    requester_digest: str
    parent_idempotency_digest: str
    input_commitment: str
    source_commitment: str
    dependency_commitment: str
    row_count: int

    def __post_init__(self) -> None:
        try:
            require_ref(self.plan_ref, "original plan")
            for name in ("requester_digest", "parent_idempotency_digest", "input_commitment",
                         "source_commitment", "dependency_commitment"):
                require_digest(getattr(self, name), name)
            if type(self.row_count) is not int or not 1 <= self.row_count <= 256:
                raise ValueError
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class OriginalImportRow(_OpaqueC3Object):
    plan_ref: str
    requester_digest: str
    idempotency_digest: str
    parameters_digest: str
    index: int

    def verify_m4_plan(self, plan: M4ExecutionPlan) -> None:
        """Narrow a compiled child plan before passing it to the existing kernel."""
        if (type(plan) is not M4ExecutionPlan or plan.plan_ref != self.plan_ref
                or plan.requester_digest != self.requester_digest
                or plan.idempotency_digest != self.idempotency_digest
                or plan.parameters_digest != self.parameters_digest
                or plan.action_id != SECRET_CREATE_ACTION_ID
                or plan.action_version != SECRET_CREATE_ACTION_VERSION):
            raise BulkImportIntakeError(_ERROR)


class PinnedOriginalImportRows(_OpaqueC3Object):
    """Derive only original namespaces using the original pinned commitment key."""

    def __init__(self, operation: OriginalImportOperation, *, key_path: Path, key_sha256: str) -> None:
        if type(operation) is not OriginalImportOperation:
            raise BulkImportIntakeError(_ERROR)
        operation.__post_init__()
        self._operation, self._key = operation, _PinnedKey(key_path, key_sha256)

    def verify_source_session(self, session: _OwnerFileSourceSession, *, authenticated_requester_digest: str) -> None:
        """A new session must match the original input and authenticated requester."""
        try:
            if type(session) is not _OwnerFileSourceSession:
                raise ValueError
            session._remaining()
            self._verify_source_binding(session._transaction._binding,
                authenticated_requester_digest=authenticated_requester_digest)
            session._remaining()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _verify_source_binding(self, binding: OwnerFileIntakeBinding, *, authenticated_requester_digest: str) -> None:
        """Verify original C2 commitments only; no source admission or file read."""
        key = None
        try:
            if (type(binding) is not OwnerFileIntakeBinding
                    or authenticated_requester_digest != self._operation.requester_digest):
                raise ValueError
            binding.__post_init__()
            key = self._key.load()
            actual = _commit(key, b"input", _input(binding))
            if not hmac.compare_digest(actual, self._operation.input_commitment):
                raise ValueError
            source = _input(binding)
            source.pop("batch_digest")
            if not hmac.compare_digest(_commit(key, b"source", source), self._operation.source_commitment):
                raise ValueError
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            if key is not None:
                _wipe(key)

    def row(self, index: int) -> OriginalImportRow:
        """No new plan/auth/session/catalog fingerprint can change an original row."""
        key = None
        try:
            if type(index) is not int or not 0 <= index < self._operation.row_count:
                raise ValueError
            key = self._key.load()
            value = dict(parent=asdict(self._operation), index=index,
                         action_id=SECRET_CREATE_ACTION_ID, action_version=SECRET_CREATE_ACTION_VERSION)
            result = OriginalImportRow(self._operation.plan_ref, self._operation.requester_digest,
                _commit(key, b"idempotency", value), _commit(key, b"parameters", value), index)
            return result
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            if key is not None:
                _wipe(key)

    def verify_dependencies(self, session: _OwnerFileSourceSession,
                            projected: ResolvedImportDependencies,
                            catalog: ImportDependencyCatalog, *, authenticated_requester_digest: str) -> None:
        """Check the complete original graph; fresh metadata is not authority."""
        try:
            if type(session) is not _OwnerFileSourceSession:
                raise ValueError
            session._remaining()
            self._verify_dependencies_binding(session._transaction._binding, projected, catalog,
                authenticated_requester_digest=authenticated_requester_digest)
            session._remaining()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _verify_dependencies_binding(self, binding: OwnerFileIntakeBinding,
                                     projected: ResolvedImportDependencies,
                                     catalog: ImportDependencyCatalog, *, authenticated_requester_digest: str) -> None:
        """Read-only original graph check for a separately authorized Owner."""
        key = None
        try:
            self._verify_source_binding(binding, authenticated_requester_digest=authenticated_requester_digest)
            if type(projected) is not ResolvedImportDependencies or type(catalog) is not ImportDependencyCatalog:
                raise ValueError
            key = self._key.load()
            count, digest = _dependency_commitment(key, binding, projected, catalog)
            if count != self._operation.row_count or not hmac.compare_digest(digest, self._operation.dependency_commitment):
                raise ValueError
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            if key is not None:
                _wipe(key)


def bind_original_import_rows(
    session: _OwnerFileSourceSession, projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog,
    *, original_plan_ref: str, authenticated_requester_digest: str, parent_idempotency_digest: str,
    key_path: Path, key_sha256: str,
) -> PinnedOriginalImportRows:
    """Initial trusted parent compilation only; resumption loads the original record.

    This does not verify a parent plan, grant an action, store a new journal or
    reserve a row. Use only the existing original parent-plan authority/records.
    Fresh dependency checks remain required by the independent child authorizer.
    """
    try:
        if type(session) is not _OwnerFileSourceSession or type(projected) is not ResolvedImportDependencies:
            raise ValueError
        session._remaining()
        result = _bind_original_import_metadata(session._transaction._binding, projected, catalog,
            original_plan_ref=original_plan_ref, authenticated_requester_digest=authenticated_requester_digest,
            parent_idempotency_digest=parent_idempotency_digest, key_path=key_path, key_sha256=key_sha256)
        session._remaining()
        return result
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None


def _bind_original_import_metadata(
    binding: OwnerFileIntakeBinding, projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog,
    *, original_plan_ref: str, authenticated_requester_digest: str, parent_idempotency_digest: str,
    key_path: Path, key_sha256: str,
) -> PinnedOriginalImportRows:
    """C2 compilation only; callers must independently authenticate provenance."""
    key = None
    try:
        if type(binding) is not OwnerFileIntakeBinding or type(projected) is not ResolvedImportDependencies:
            raise ValueError
        binding.__post_init__()
        if key_path.parts[1:] == binding.path.parts[1:]:
            raise ValueError
        pin = _PinnedKey(key_path, key_sha256)
        key = pin.load()
        count, dependencies = _dependency_commitment(key, binding, projected, catalog)
        source = _input(binding)
        source.pop("batch_digest")
        operation = OriginalImportOperation(original_plan_ref, authenticated_requester_digest,
            parent_idempotency_digest, _commit(key, b"input", _input(binding)),
            _commit(key, b"source", source), dependencies, count)
        return PinnedOriginalImportRows(operation, key_path=key_path, key_sha256=key_sha256)
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        if key is not None:
            _wipe(key)


def retain_original_import_rows(
    rows: PinnedOriginalImportRows, session: _OwnerFileSourceSession,
    store: PersistentProtectedPlanningStore, *, expected_plan_digest: str,
    authenticated_requester_digest: str,
) -> None:
    """Trusted compilation joins source consistency to the existing parent ledger.

    Neither this private metadata write nor a prepared plan grants a child action.
    The caller supplies its independently authenticated requester and parent pin.
    """
    key = None
    try:
        if type(rows) is not PinnedOriginalImportRows or type(store) is not PersistentProtectedPlanningStore:
            raise ValueError
        rows.verify_source_session(session, authenticated_requester_digest=authenticated_requester_digest)
        key = rows._key.load()
        if store.uses_key_material(bytes(key)):
            raise ValueError
        operation = rows._operation
        record = OriginalImportBindingRecord(plan_digest=expected_plan_digest,
            namespace_key_digest=rows._key.digest, **asdict(operation))
        store.put_original_import_binding(record)
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        if key is not None:
            _wipe(key)


def resolve_original_import_rows(
    session: _OwnerFileSourceSession, store: PersistentProtectedPlanningStore,
    *, original_plan_ref: str, expected_plan_digest: str, authenticated_requester_digest: str,
    key_path: Path, key_sha256: str,
) -> PinnedOriginalImportRows:
    """Resume from authenticated parent records, never from replacement metadata."""
    try:
        if type(store) is not PersistentProtectedPlanningStore:
            raise ValueError
        record = store.get_original_import_binding(original_plan_ref,
            expected_plan_digest=expected_plan_digest, requester_digest=authenticated_requester_digest,
            namespace_key_digest=key_sha256)
        fields = asdict(record)
        fields.pop("plan_digest")
        fields.pop("namespace_key_digest")
        rows = PinnedOriginalImportRows(OriginalImportOperation(**fields),
            key_path=key_path, key_sha256=key_sha256)
        rows.verify_source_session(session, authenticated_requester_digest=authenticated_requester_digest)
        return rows
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
