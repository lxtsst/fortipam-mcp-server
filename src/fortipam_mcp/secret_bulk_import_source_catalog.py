"""Private source qualification and a fixed targetless Text import profile.

The fixed API actor/Role window brackets the existing six metadata reads. Only
explicit native Folder permissions and complete observed ancestry determine
``can_add``. Template definitions retain their actor-visible metadata meaning.
The general profile still needs qualified Target/association dependencies and
the global Secret collision namespace. The fixed Text profile explicitly excludes
Targets, services and all associations; its catalog applies only to its bound
file. Neither profile supplies an owner-file grant, M4 authority or public route.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import http.client
import math
from threading import RLock
import time
from typing import Any, TYPE_CHECKING

import httpx
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .dlp_api_actor_guard import DlpApiActorGuardBinding
from .secret_bulk_import_dependencies import (
    ImportDependencyCatalog, ImportRowDependency, ImportTargetDependency, ResolvedImportDependencies,
    dependency_catalog_digest, resolve_import_dependencies,
)
from .secret_bulk_import_file import ProtectedBulkImportRows
from .secret_bulk_import_namespace_source import (
    ImportSecretNamespaceSourceObservation, ImportSecretNamespaceSourceReader,
)
from .secret_bulk_import_reference_reader import (
    ImportTemplateFolderObservation, read_import_template_folder_metadata,
)
from .secret_bulk_import_row_actor import _OriginalRowApiActorGuard
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from .target_preservation_contract import _api_source_context

if TYPE_CHECKING:
    from .secret_bulk_import_intake import OwnerFileIntakeBinding
    from .secret_bulk_import_row_namespace import PinnedOriginalImportRows

_ERROR = "Protected bulk-import Folder source unavailable."


class BulkImportSourceCatalogError(ValueError):
    """Fixed non-disclosing refusal; no partial source result is returned."""


@dataclass(frozen=True, slots=True, repr=False)
class ImportTemplateFolderSourceObservation(_OpaqueC3Object):
    """Stable visible metadata under the verified API actor, not global coverage."""

    metadata: ImportTemplateFolderObservation
    source_context_digest: str
    actor_evidence_digest: str
    serial_digest: str
    observed_at: float
    expires_at: float


class ImportTemplateFolderSourceReader(_OpaqueC3Object):
    """One fixed read window; a failed or consumed reader cannot start another."""

    def __init__(self, config: SecretMetadataHttpTransportConfig,
                 actor_binding: DlpApiActorGuardBinding, *,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 client_factory: Callable[..., httpx.Client] = httpx.Client,
                 clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or config.ca_file is None
                    or type(actor_binding) is not DlpApiActorGuardBinding
                    or not callable(connection_factory) or not callable(client_factory) or not callable(clock)):
                raise ValueError
            config.__post_init__()
            self._config, self._factory, self._clock = config, client_factory, clock
            self._lock = RLock()
            self._used = self._closed = self._failed = False
            self._last: float | None = None
            self._deadline: float | None = None
            self._current: ImportTemplateFolderSourceObservation | None = None
            self._guard = _OriginalRowApiActorGuard(config, actor_binding,
                connection_factory=connection_factory, clock=self._now)
            self._guard._require_config(config)
            self._source = _api_source_context(config.base_url,
                hashlib.sha256(config.bearer_token.encode()).hexdigest(), self._guard._ca_digest,
                self._guard.serial_digest)
        except Exception:
            raise BulkImportSourceCatalogError(_ERROR) from None

    def _now(self) -> float:
        try:
            value = self._clock()
            if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                    or self._closed or self._failed
                    or self._last is not None and value < self._last
                    or self._deadline is not None and value >= self._deadline):
                raise ValueError
            self._last = float(value)
            return float(value)
        except Exception:
            self._failed = True
            raise BulkImportSourceCatalogError(_ERROR) from None

    def read_once(self) -> ImportTemplateFolderSourceObservation:
        with self._lock:
            try:
                if self._used:
                    raise ValueError
                self._used = True
                started = self._now()
                deadline = started + min(30.0, self._config.timeout_seconds)
                self._deadline = deadline
                self._guard._observe(completed=False, deadline=deadline)

                def client(**options: Any) -> httpx.Client:
                    self._now()
                    # Share the actor's loaded trust store, not merely its CA path.
                    options['verify'] = self._guard._tls_for_transport(self._config)
                    return self._factory(**options)

                metadata = read_import_template_folder_metadata(self._config,
                    serial_digest=self._guard.serial_digest, client_factory=client, clock=self._now)
                self._guard._observe(completed=True, deadline=deadline)
                evidence = self._guard._before
                if (evidence is None or not self._guard._completed
                        or not started <= metadata.observed_at <= metadata.completed_at <= self._now()):
                    raise ValueError
                result = ImportTemplateFolderSourceObservation(metadata, self._source,
                    evidence.evidence_digest, self._guard.serial_digest, started, deadline)
                self._current = result
                self.check_current(result)
                return result
            except Exception:
                self._failed = True
                self._current = None
                raise BulkImportSourceCatalogError(_ERROR) from None

    def check_current(self, observation: ImportTemplateFolderSourceObservation) -> None:
        """Check this original window's freshness and pinned source; never renew it."""
        with self._lock:
            try:
                if (type(observation) is not ImportTemplateFolderSourceObservation
                        or observation is not self._current
                        or observation.source_context_digest != self._source
                        or not observation.observed_at <= self._now() < observation.expires_at):
                    raise ValueError
                self._guard._require_config(self._config)
                self._now()
            except Exception:
                self._failed = True
                self._current = None
                raise BulkImportSourceCatalogError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None


@dataclass(frozen=True, slots=True, repr=False)
class _QualifiedTextImport(_OpaqueC3Object):
    """One source-qualified file projection; not a child execution grant."""

    catalog: ImportDependencyCatalog
    projected: ResolvedImportDependencies
    file_digest: str
    scope_digest: str


class _TextOnlyImportSource(_OpaqueC3Object):
    """Resolve one file with one actual single-text-field Template and Folder.

Empty Target/association views mean these dependencies are excluded by this
profile, not that those objects or eligible IDs are absent from the device.
The generic resolver result is never returned before the entire profile passes.
Original parent/row compilation must retain these exact file/catalog bindings.
"""

    def __init__(self, folder_reader: ImportTemplateFolderSourceReader,
                 folders: ImportTemplateFolderSourceObservation,
                 namespace_reader: ImportSecretNamespaceSourceReader,
                 namespace: ImportSecretNamespaceSourceObservation) -> None:
        try:
            if (type(folder_reader) is not ImportTemplateFolderSourceReader
                    or type(folders) is not ImportTemplateFolderSourceObservation
                    or type(namespace_reader) is not ImportSecretNamespaceSourceReader
                    or type(namespace) is not ImportSecretNamespaceSourceObservation
                    or folder_reader._config is not namespace_reader._config
                    or folders.source_context_digest != namespace.source_context_digest
                    or folders.serial_digest != namespace.serial_digest
                    or folders.actor_evidence_digest != namespace.actor_evidence_digest):
                raise ValueError
            self._folder_reader, self._folders = folder_reader, folders
            self._namespace_reader, self._namespace = namespace_reader, namespace
            self._lock = RLock()
            self._used = self._failed = self._closed = False
            self._current: _QualifiedTextImport | None = None
            self._catalog_digest: str | None = None
            self._prepared_catalog: ImportDependencyCatalog | None = None
            self._prepared_file_digest: str | None = None
            self._check_sources()
        except Exception:
            raise BulkImportSourceCatalogError(_ERROR) from None

    def _check_sources(self) -> None:
        if self._closed or self._failed:
            raise ValueError
        self._folder_reader.check_current(self._folders)
        self._namespace_reader.check_current(self._namespace)

    def _check_rows(self, result: _QualifiedTextImport) -> None:
        templates = result.catalog.templates
        if (len(templates) != 1 or len(templates[0].fields) != 1
                or templates[0].fields[0].kind != 'text'):
            raise ValueError
        def inspect(rows: tuple[ImportRowDependency, ...], targets: tuple[ImportTargetDependency, ...],
                    order: tuple[int, ...]) -> None:
            if (not rows or targets or order != tuple(range(len(rows)))
                    or len({row.folder_id for row in rows}) != 1
                    or any(row.template != templates[0].name or row.target_group is not None
                           or row.association_row is not None or row.association_id is not None
                           or row.services for row in rows)):
                raise ValueError
        result.projected._inspect_private(inspect, file_digest=result.file_digest,
            catalog_digest=dependency_catalog_digest(result.catalog))

    def prepare_catalog(self, *, expected_file_digest: str, scope_digest: str) -> ImportDependencyCatalog:
        """Pin one source catalog for the isolated authenticated file workload."""
        with self._lock:
            try:
                if self._used or self._prepared_catalog is not None:
                    raise ValueError
                require_digest(expected_file_digest, 'original file')
                require_digest(scope_digest, 'original scope')
                self._check_sources()
                metadata, namespace = self._folders.metadata, self._namespace
                templates = tuple(item for item in metadata.templates
                    if len(item.fields) == 1 and item.fields[0].kind == 'text')
                if len(templates) != 1:
                    raise ValueError
                source = canonical_digest({'profile': 'targetless-single-text-field-no-association-v1',
                    'template': (templates[0].name, tuple((field.name, field.kind, field.mandatory)
                        for field in templates[0].fields)),
                    'file': expected_file_digest, 'scope': scope_digest,
                    'api': self._folders.source_context_digest,
                    'actor': self._folders.actor_evidence_digest,
                    'owner': namespace.owner_evidence_digest, 'ssh': namespace.ssh_source_digest})
                catalog = ImportDependencyCatalog(scope_digest=scope_digest, source_digest=source,
                    observed_at=min(self._folders.observed_at, namespace.observed_at),
                    expires_at=min(self._folders.expires_at, namespace.expires_at),
                    coverage=frozenset({'folders', 'templates', 'targets', 'secret_names', 'association_ids'}),
                    folders=metadata.folders, templates=templates, targets=(),
                    secret_names=namespace.namespace.names, secrets=(),
                    # The resolver requires a known nonempty service vocabulary;
                    # every actual service declaration is rejected below.
                    service_types=frozenset({'ssh', 'sftp', 'rdp', 'http', 'samba', 'telnet'}))
                self._catalog_digest = dependency_catalog_digest(catalog)
                self._prepared_catalog, self._prepared_file_digest = catalog, expected_file_digest
                self._check_prepared_catalog(catalog, file_digest=expected_file_digest, scope_digest=scope_digest)
                return catalog
            except BaseException as error:
                self._failed = True
                self._current = None
                if not isinstance(error, Exception):
                    raise
                raise BulkImportSourceCatalogError(_ERROR) from None

    def _check_prepared_catalog(self, catalog: ImportDependencyCatalog, *,
                                file_digest: str, scope_digest: str) -> None:
        if (type(catalog) is not ImportDependencyCatalog or catalog is not self._prepared_catalog
                or file_digest != self._prepared_file_digest or catalog.scope_digest != scope_digest
                or dependency_catalog_digest(catalog) != self._catalog_digest):
            raise ValueError
        self._check_sources()

    def _qualify(self, projected: ResolvedImportDependencies, *, file_digest: str,
                 scope_digest: str) -> _QualifiedTextImport:
        catalog = self._prepared_catalog
        if catalog is None or type(projected) is not ResolvedImportDependencies:
            raise ValueError
        self._check_prepared_catalog(catalog, file_digest=file_digest, scope_digest=scope_digest)
        result = _QualifiedTextImport(catalog, projected, file_digest, scope_digest)
        self._check_rows(result)
        self._check_sources()
        self._current = result
        self.check_current(result, file_digest=file_digest, scope_digest=scope_digest)
        return result

    def resolve_once(self, rows: ProtectedBulkImportRows, *, expected_file_digest: str,
                     scope_digest: str) -> _QualifiedTextImport:
        with self._lock:
            try:
                if self._used or type(rows) is not ProtectedBulkImportRows:
                    raise ValueError
                catalog = self._prepared_catalog
                if catalog is None:
                    catalog = self.prepare_catalog(expected_file_digest=expected_file_digest, scope_digest=scope_digest)
                self._used = True
                self._check_prepared_catalog(catalog, file_digest=expected_file_digest, scope_digest=scope_digest)
                projected = resolve_import_dependencies(rows, catalog,
                    expected_file_digest=expected_file_digest, expected_catalog_digest=dependency_catalog_digest(catalog),
                    expected_scope_digest=scope_digest)
                return self._qualify(projected, file_digest=expected_file_digest, scope_digest=scope_digest)
            except BaseException as error:
                self._failed = True
                self._current = None
                if not isinstance(error, Exception):
                    raise
                raise BulkImportSourceCatalogError(_ERROR) from None
            finally:
                if type(rows) is ProtectedBulkImportRows:
                    rows.clear()

    def qualify_original_projection_once(self, original: PinnedOriginalImportRows,
                                         binding: OwnerFileIntakeBinding,
                                         projected: ResolvedImportDependencies) -> _QualifiedTextImport:
        """Owner-only completion from the original authenticated C2 handoff, without raw rows."""
        from .secret_bulk_import_intake import OwnerFileIntakeBinding
        from .secret_bulk_import_row_namespace import PinnedOriginalImportRows

        with self._lock:
            try:
                if (self._used or type(original) is not PinnedOriginalImportRows
                        or type(binding) is not OwnerFileIntakeBinding or self._prepared_catalog is None):
                    raise ValueError
                self._used = True
                self._check_prepared_catalog(self._prepared_catalog,
                    file_digest=binding.file_sha256, scope_digest=binding.scope_digest)
                original._verify_dependencies_binding(binding, projected, self._prepared_catalog,
                    authenticated_requester_digest=original._operation.requester_digest)
                return self._qualify(projected, file_digest=binding.file_sha256, scope_digest=binding.scope_digest)
            except BaseException as error:
                self._failed = True
                self._current = None
                if not isinstance(error, Exception):
                    raise
                raise BulkImportSourceCatalogError(_ERROR) from None

    def check_current(self, result: _QualifiedTextImport, *, file_digest: str, scope_digest: str) -> None:
        with self._lock:
            try:
                if (type(result) is not _QualifiedTextImport or result is not self._current
                        or result.file_digest != file_digest or result.scope_digest != scope_digest
                        or result.catalog is not self._prepared_catalog
                        or result.file_digest != self._prepared_file_digest
                        or result.catalog.scope_digest != scope_digest
                        or dependency_catalog_digest(result.catalog) != self._catalog_digest):
                    raise ValueError
                self._check_sources()
                self._check_rows(result)
                self._check_sources()
            except Exception:
                self._failed = True
                self._current = None
                raise BulkImportSourceCatalogError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None
