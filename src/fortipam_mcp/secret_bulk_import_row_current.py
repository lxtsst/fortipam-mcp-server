"""Private native current state for one original, source-qualified Text row.

Each decision reads fresh fixed sources and defaults under the original source
deadline. Global names may grow between rows; only this row must remain absent.
This reader neither authorizes dispatch nor substitutes current evidence for ACK
readback. It reads no file material and has no caller evidence callback.
"""

from __future__ import annotations

from collections.abc import Callable
import math
from threading import RLock
import time

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import (
    M4ClaimState, M4Compensation, M4Outcome, M4Verification, _ACTIVE_DISPATCH, _M4DispatchScope,
)
from v4_planning.import_parent import FileImportParentRecord
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.persistence import PersistentProtectedPlanningStore

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_bulk_import_dependencies import ImportDependencyCatalog, ResolvedImportDependencies
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_namespace_source import ImportSecretNamespaceSourceReader
from .secret_bulk_import_parent_graph import _OriginalImportGraph, _compile_original_import_graph
from .secret_bulk_import_row_conversion import _select_original_row_metadata
from .secret_bulk_import_row_namespace import PinnedOriginalImportRows
from .secret_bulk_import_row_readback import _OriginalRowNativeReadback
from .secret_bulk_import_row_wire import _Build29SecretWireDefaults, _project_build29_secret_wire_defaults
from .secret_bulk_import_source_catalog import (
    ImportTemplateFolderSourceReader, _QualifiedTextImport, _TextOnlyImportSource,
)
from .secret_metadata_http_transport import COLLECTION_PATH
from .target_api_dependency_reader import _private_http_logs


class _OriginalRowNativeCurrent(_OpaqueC3Object):
    """Original C2 bindings before Owner construction; fixed native reads only."""

    def __init__(self, original: PinnedOriginalImportRows, source: OwnerFileIntakeBinding,
                 projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog,
                 parent_store: PersistentProtectedPlanningStore, execution: PersistentM4ExecutionStateStore,
                 text_source: _TextOnlyImportSource, qualified: _QualifiedTextImport,
                 defaults: _Build29SecretWireDefaults, *, index: int, expected_parent_digest: str,
                 authenticated_requester_digest: str, clock: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(original) is not PinnedOriginalImportRows or type(source) is not OwnerFileIntakeBinding
                    or type(projected) is not ResolvedImportDependencies or type(catalog) is not ImportDependencyCatalog
                    or type(parent_store) is not PersistentProtectedPlanningStore
                    or type(execution) is not PersistentM4ExecutionStateStore
                    or not execution.monotonic_checkpoint_protocol_bound
                    or type(text_source) is not _TextOnlyImportSource or type(qualified) is not _QualifiedTextImport
                    or type(defaults) is not _Build29SecretWireDefaults
                    or qualified.catalog is not catalog or qualified.projected is not projected
                    or not callable(clock) or not callable(wall_clock)):
                raise ValueError
            self._original, self._source, self._projected, self._catalog = original, source, projected, catalog
            self._parent_store, self._execution, self._profile, self._qualified = parent_store, execution, text_source, qualified
            self._defaults, self._defaults_digest = defaults, defaults.digest()
            self._parent_digest, self._requester = expected_parent_digest, authenticated_requester_digest
            self._clock, self._wall_clock, self._lock = clock, wall_clock, RLock()
            self._closed = self._failed = False
            self._last: float | None = None
            self._last_wall = -1
            self._deadline: float | None = None
            self._plan: M4ExecutionPlan | None = None
            self._post: _OriginalRowNativeReadback | None = None
            self._dispatch_seed: M4ExecutionAuthorization | None = None
            self._current_scope: _M4DispatchScope | None = None
            self._current_sealed = False
            text_source.check_current(qualified, file_digest=source.file_sha256, scope_digest=source.scope_digest)
            self._row = original.row(index)
            self._graph = self._compile_graph()
            parent = parent_store.get_import_parent(original._operation.plan_ref)
            if type(parent) is not FileImportParentRecord:
                raise ValueError
            self._parent = parent
            self._line = next(line for line in parent.lines if line.kind == 'secret' and line.index == index)
            self._dependency, self._template, self._folder = _select_original_row_metadata(catalog, projected,
                file_digest=source.file_sha256, index=index, target_name=None, associated_secret_id=None)
            if (self._line.depends_on or len(catalog.templates) != 1
                    or self._template != catalog.templates[0] or len(self._template.fields) != 1
                    or self._template.fields[0].kind != 'text' or not self._folder.can_add
                    or defaults.serial_digest != text_source._folders.serial_digest):
                raise ValueError
            self._deadline = min(self._graph.deadline, catalog.expires_at,
                text_source._folders.expires_at, text_source._namespace.expires_at)
            self._check_original()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _now(self) -> float:
        value = self._clock()
        if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                or self._closed or self._failed or self._last is not None and value < self._last
                or self._deadline is not None and value >= self._deadline):
            raise ValueError
        self._last = float(value)
        return float(value)

    def _wall(self) -> int:
        now = self._wall_clock()
        if type(now) is not int or now < 0 or now < self._last_wall:
            raise ValueError
        self._last_wall = now
        return now

    def _compile_graph(self) -> _OriginalImportGraph:
        return _compile_original_import_graph(self._original, self._source, self._projected, self._catalog,
            self._parent_store, expected_parent_digest=self._parent_digest,
            authenticated_requester_digest=self._requester, clock=self._wall)

    def _check_original(self) -> None:
        self._now()
        self._profile.check_current(self._qualified,
            file_digest=self._source.file_sha256, scope_digest=self._source.scope_digest)
        current = self._compile_graph()
        if (current.graph_digest != self._graph.graph_digest or current.steps != self._graph.steps
                or self._parent_store.get_import_parent(current.parent_ref) != self._parent
                or self._defaults.digest() != self._defaults_digest):
            raise ValueError
        ids = tuple(line.idempotency_digest for line in self._parent.lines if line.idempotency_digest is not None)
        claims = self._execution._inspect_original_claims(plan_ref=self._parent.plan_ref,
            requester_digest=self._requester, idempotency_digests=ids)
        for identifier, claim in zip(ids, claims, strict=True):
            if identifier == self._row.idempotency_digest:
                if claim.state not in (M4ClaimState.NEW, M4ClaimState.IN_PROGRESS):
                    raise ValueError
            elif claim.state is not M4ClaimState.NEW:
                result = claim.result
                if (claim.state is not M4ClaimState.REPLAY or result is None
                        or result.outcome is not M4Outcome.SUCCEEDED or result.verification is not M4Verification.VERIFIED
                        or result.compensation is not M4Compensation.NOT_REQUESTED):
                    raise ValueError
        self._now()

    def _check_plan(self, plan: M4ExecutionPlan) -> None:
        self._row.verify_m4_plan(plan)
        plan.__post_init__()
        if (plan.summary_digest != self._parent.plan_digest or plan.confirmation_digest != self._parent.intent_policy_digest
                or plan.target_ref != self._line.line_ref or plan.expected_current_digest != self._line.current_digest
                or plan.expected_state_digest != self._line.expected_digest or plan.expires_at != self._parent.expires_at
                or plan.adapter_ref != 'fortipam-build29-original-row-create-v1' or plan.revision != 1
                or self._plan is not None and plan != self._plan):
            raise ValueError

    def _read_defaults(self) -> None:
        original = self._profile._folder_reader
        config = original._config
        raw = bytearray()
        try:
            assert self._deadline is not None
            with _private_http_logs(), original._factory(verify=original._guard._tls_for_transport(config),
                    timeout=min(10.0, self._deadline - self._now()), follow_redirects=False, trust_env=False) as client:
                try:
                    client.cookies.clear()
                    with client.stream('GET', config.base_url.rstrip('/') + COLLECTION_PATH + '?action=default&vdom=root',
                            headers={'Authorization': 'Bearer ' + config.bearer_token, 'Accept': 'application/json',
                                'Accept-Encoding': 'identity', 'Cache-Control': 'no-store',
                                'User-Agent': 'fortipam-private-original-row/1'},
                            timeout=min(10.0, self._deadline - self._now())) as response:
                        self._now()
                        if (response.status_code != 200
                                or response.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json'
                                or response.headers.get('content-encoding', 'identity').strip().lower() != 'identity'):
                            raise ValueError
                        iterator = response.iter_raw()
                        while True:
                            self._now()
                            try:
                                chunk = next(iterator)
                            except StopIteration:
                                break
                            self._now()
                            if len(raw) + len(chunk) > 1048576:
                                raise ValueError
                            raw.extend(chunk)
                finally:
                    client.cookies.clear()
            if not client.is_closed:
                raise ValueError
            self._now()
            if _project_build29_secret_wire_defaults(raw,
                    serial_digest=self._defaults.serial_digest).digest() != self._defaults_digest:
                raise ValueError
        finally:
            _wipe(raw)

    def _check_current_scope(self, plan: M4ExecutionPlan) -> None:
        scope = self._current_scope
        if (scope is None or not scope.active or scope.store is not self._execution
                or scope.plan != plan or self._dispatch_seed != scope.authorization or self._current_sealed):
            raise ValueError
        auth = scope.authorization
        now = self._wall()
        if not auth.issued_at <= now < min(auth.expires_at, plan.expires_at, self._source.expires_at):
            raise ValueError
        claim = self._execution.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest,
            context_digest=canonical_digest({'authorization_digest': auth.authorization_digest,
                'plan_digest': plan.plan_digest, 'revision': plan.revision}),
            authorization_digest=auth.authorization_digest)
        if claim.state is not M4ClaimState.IN_PROGRESS:
            raise ValueError

    def _read_for_kernel(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> str:
        with self._lock:
            if self._dispatch_seed is not None or self._current_scope is not None or self._current_sealed:
                raise BulkImportIntakeError(_ERROR)
            result = self.read_current(plan)
            self._dispatch_seed = authorization
            return result

    def _bind_current_scope(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> None:
        with self._lock:
            scope = _ACTIVE_DISPATCH.get()
            if (scope is None or scope.authorization != authorization or self._current_scope is not None
                    or self._dispatch_seed != authorization or self._plan != plan):
                raise BulkImportIntakeError(_ERROR)
            self._current_scope = scope
            self._check_plan(plan)
            self._check_original()
            self._check_current_scope(plan)

    def _discard_current_scope(self) -> None:
        with self._lock:
            self._current_sealed = True
            self._dispatch_seed = None
            self._current_scope = None

    def _read_before_create(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check_current_scope(plan)
            try:
                return self._read_current(plan, fresh=True)
            finally:
                # A lost reply or subsequent POST cannot reopen pre-state reuse.
                self._discard_current_scope()

    def read_current(self, plan: M4ExecutionPlan) -> str:
        return self._read_current(plan, fresh=False)

    def _read_current(self, plan: M4ExecutionPlan, *, fresh: bool) -> str:
        with self._lock:
            folders = namespace = None
            try:
                self._check_plan(plan)
                self._check_original()
                if self._current_sealed:
                    raise ValueError
                if self._current_scope is not None:
                    self._check_current_scope(plan)
                    if not fresh:
                        return self._line.current_digest
                old_folder, old_namespace = self._profile._folder_reader, self._profile._namespace_reader
                config, actor = old_folder._config, old_namespace._binding
                folders = ImportTemplateFolderSourceReader(config, actor,
                    connection_factory=old_folder._guard._factory, client_factory=old_folder._factory, clock=self._now)
                namespace = ImportSecretNamespaceSourceReader(config, old_namespace._ssh_config, actor,
                    connection_factory=old_namespace._guard._factory, client_factory=old_namespace._factory, clock=self._now)
                # Keep the original loaded CA for every actor, metadata and default read.
                tls = old_folder._guard._tls_for_transport(config)
                folders._guard._guard._context = namespace._guard._guard._context = tls
                fresh_folders = folders.read_once()
                self._read_defaults()
                fresh_namespace = namespace.read_once()
                for observation in (fresh_folders, fresh_namespace):
                    if (observation.source_context_digest != self._profile._folders.source_context_digest
                            or observation.actor_evidence_digest != self._profile._folders.actor_evidence_digest
                            or observation.serial_digest != self._defaults.serial_digest):
                        raise ValueError
                if (fresh_namespace.owner_evidence_digest != self._profile._namespace.owner_evidence_digest
                        or fresh_namespace.ssh_source_digest != self._profile._namespace.ssh_source_digest
                        or tuple(item for item in fresh_folders.metadata.folders if item.identifier == self._folder.identifier)
                            != (self._folder,)
                        or tuple(item for item in fresh_folders.metadata.templates
                            if len(item.fields) == 1 and item.fields[0].kind == 'text')
                            != (self._template,)
                        or self._dependency.name.casefold() in {name.casefold() for name in fresh_namespace.namespace.names}):
                    raise ValueError
                folders.check_current(fresh_folders)
                namespace.check_current(fresh_namespace)
                self._check_original()
                self._plan = plan
                return self._line.current_digest
            except BaseException as error:
                self._discard_current_scope()
                self._failed = True
                if not isinstance(error, Exception):
                    raise
                raise BulkImportIntakeError(_ERROR) from None
            finally:
                if folders is not None:
                    folders.close()
                if namespace is not None:
                    namespace.close()

    def bind_postcondition(self, reader: _OriginalRowNativeReadback) -> None:
        """Bind the exact original ACK reader after Owner/active dispatch exist."""
        with self._lock:
            try:
                self._check_original()
                if (type(reader) is not _OriginalRowNativeReadback or self._post is not None or self._plan is None
                        or reader._owner._binding.plan != self._plan or reader._owner._binding.source != self._source
                        or reader._owner._binding.parent_digest != self._parent_digest
                        or reader._owner._parent is not self._parent_store or reader._owner._execution is not self._execution
                        or reader._config is not self._profile._folder_reader._config
                        or reader._actor != self._profile._namespace_reader._binding
                        or reader._key.path != self._original._key.path or reader._key.digest != self._original._key.digest
                        or reader._pins.defaults_digest != self._defaults_digest
                        or reader._pins.capture.serial_digest != self._defaults.serial_digest):
                    raise ValueError
                self._post = reader
            except Exception:
                self._failed = True
                raise BulkImportIntakeError(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._discard_current_scope()
            try:
                self._now()
                self._check_plan(plan)
                if self._post is None:
                    raise ValueError
                return self._post.read_postcondition(plan)
            except Exception:
                self._failed = True
                raise BulkImportIntakeError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._discard_current_scope()
            self._closed = True
            if self._post is not None:
                self._post.close()
