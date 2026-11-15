"""Private build-29 import DTO conversion; not a wire body or product writer.

The fixed handoff owns the row. Conversion verifies its complete original graph
and yields one temporary readonly DTO inside that handoff only. Resolved Target
and association selectors are conversion data, never child ACK/ownership proof.
The eventual native transport must independently bind those proofs and unparse
the DTO; this module neither dispatches nor qualifies any product action.
"""

from __future__ import annotations

from contextlib import contextmanager
import math
import threading
import time
from typing import Iterator

from v4_planning.material_provider import _OpaqueC3Object

from . import _secret_bulk_import_worker as worker
from .secret_bulk_import_dependencies import (
    ImportDependencyCatalog, ImportRowDependency, ImportTargetDependency, ImportTemplate, ImportFolder,
    ResolvedImportDependencies, _FIELD_COLUMNS, _MATERIAL_COLUMNS, _folder_path,
    _identifier, _services, _text, dependency_catalog_digest,
)
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter, _OriginalRowUseContext
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_material, _append_text, _valid_utf8

_NORMALIZED = frozenset({"private-key", "public-key", "text"})


def _append_value(body: _MutableJSONBuffer, value: memoryview, *, normalize: bool) -> None:
    if not normalize:
        _append_material(body, value)
        return
    # Normalize CRLF while streaming; never create an immutable material string.
    body.append(34)
    for index, byte in enumerate(value):
        if byte == 13 and index + 1 < len(value) and value[index + 1] == 10:
            continue
        if byte in {34, 92}:
            body.append(92)
            body.append(byte)
        elif byte < 32:
            body.extend(f"\\u00{byte:02x}".encode("ascii"))
        else:
            body.append(byte)
    body.append(34)


def _select_original_row_metadata(catalog: ImportDependencyCatalog, projected: ResolvedImportDependencies,
                                  *, file_digest: str, index: int, target_name: str | None,
                                  associated_secret_id: int | None) -> tuple[ImportRowDependency, ImportTemplate, ImportFolder]:
    """Select checked C2 metadata; callers must verify the full original graph."""
    def select(rows: tuple[ImportRowDependency, ...], targets: tuple[ImportTargetDependency, ...],
               order: tuple[int, ...]) -> tuple[ImportRowDependency, ImportTemplate, ImportFolder]:
        if type(index) is not int or not 0 <= index < len(rows):
            raise ValueError
        dependency = rows[index]
        template = next(item for item in catalog.templates if item.name == dependency.template)
        folder = next(item for item in catalog.folders if item.identifier == dependency.folder_id)
        if dependency.target_group is None:
            if target_name is not None:
                raise ValueError
        else:
            target = targets[dependency.target_group]
            _text(target_name)
            if target.effect == "reuse" and target_name != target.existing_name:
                raise ValueError
        if dependency.association_id is not None:
            if associated_secret_id != dependency.association_id:
                raise ValueError
            _identifier(associated_secret_id)
        elif dependency.association_row is not None:
            _identifier(associated_secret_id)
        elif associated_secret_id is not None:
            raise ValueError
        return dependency, template, folder
    return projected._inspect_private(select, file_digest=file_digest,
        catalog_digest=dependency_catalog_digest(catalog))


class _Build29OriginalRowConversion(_OpaqueC3Object):
    """Prebound, single-use conversion with no dispatch or material getter."""

    def __init__(self, bridge: _OriginalRowSecretCreateAdapter,
                 catalog: ImportDependencyCatalog, projected: ResolvedImportDependencies,
                 *, target_name: str | None, associated_secret_id: int | None) -> None:
        try:
            if (type(bridge) is not _OriginalRowSecretCreateAdapter
                    or type(catalog) is not ImportDependencyCatalog
                    or type(projected) is not ResolvedImportDependencies):
                raise ValueError
            self._bridge, self._catalog, self._projected = bridge, catalog, projected
            self._context = bridge._context
            self._verify_graph()
            self._dependency, self._template, self._folder = _select_original_row_metadata(catalog, projected,
                file_digest=bridge._loader._session._transaction._binding.file_sha256,
                index=self._context.row.index, target_name=target_name, associated_secret_id=associated_secret_id)
            self._target, self._associated = target_name, associated_secret_id
            self._used, self._lock = False, threading.Lock()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    @staticmethod
    def _graph(rows: tuple[ImportRowDependency, ...], targets: tuple[ImportTargetDependency, ...],
               order: tuple[int, ...]) -> tuple[tuple[ImportRowDependency, ...], tuple[ImportTargetDependency, ...], tuple[int, ...]]:
        return rows, targets, order

    def _verify_graph(self) -> None:
        bridge = self._bridge
        bridge._context.__post_init__()
        if bridge._context != self._context:
            raise ValueError
        loader = bridge._loader
        loader._rows.verify_dependencies(loader._session, self._projected, self._catalog,
            authenticated_requester_digest=self._context.permission.plan.requester_digest)

    @contextmanager
    def _convert_once(self, context: _OriginalRowUseContext, columns: tuple[memoryview, ...],
                      *, deadline: float) -> Iterator[memoryview]:
        if not self._lock.acquire(blocking=False):
            raise BulkImportIntakeError(_ERROR)
        body = bytearray()
        builder = _MutableJSONBuffer()
        try:
            if self._used:
                raise ValueError
            self._used = True
            bridge, dep = self._bridge, self._dependency
            bridge._verify()
            owned = bridge._owned
            if (context != self._context or type(context) is not _OriginalRowUseContext
                    or type(deadline) not in {int, float} or not math.isfinite(deadline)
                    or not time.monotonic() < deadline <= bridge._deadline
                    or owned is None or not owned._consumed or owned._closed.is_set()
                    or type(columns) is not tuple or len(columns) != len(worker.HEADERS)):
                raise ValueError
            for column, buffer in zip(columns, owned._buffers, strict=True):
                if (type(column) is not memoryview or not column.readonly or column.ndim != 1
                        or column.format != "B" or column.obj is not buffer or column.nbytes != len(buffer)
                        or column.nbytes > worker.MAX_CELL_BYTES or 0 in column or not _valid_utf8(column)):
                    raise ValueError
            self._verify_graph()
            metadata = {index: _text(bytes(columns[index]).decode("utf-8"), empty=True)
                        for index in (0, 1, 2, 3, 4, 10, 12, 13, 14)}
            if (metadata[0] != self._template.name or metadata[1] != dep.name
                    or _folder_path(metadata[2]) != self._folder.path
                    or _services(metadata[12], metadata[13], self._catalog.service_types) != dep.services):
                raise ValueError
            used = {_FIELD_COLUMNS[field.kind] for field in self._template.fields}
            if (any(columns[index] and index not in used for index in _MATERIAL_COLUMNS)
                    or any(field.mandatory and not columns[_FIELD_COLUMNS[field.kind]] for field in self._template.fields)):
                raise ValueError
            builder.extend(b'{"name":')
            _append_text(builder, dep.name)
            builder.extend(b',"folder":')
            builder.extend(str(dep.folder_id).encode("ascii"))
            builder.extend(b',"template":')
            _append_text(builder, self._template.name)
            builder.extend(b',"field":[')
            for index, field in enumerate(self._template.fields):
                self._check(deadline)
                if index:
                    builder.append(44)
                builder.extend(b'{"name":')
                _append_text(builder, field.name)
                builder.extend(b',"value":')
                _append_value(builder, columns[_FIELD_COLUMNS[field.kind]], normalize=field.kind in _NORMALIZED)
                builder.extend(b',"type":')
                _append_text(builder, field.kind)
                builder.append(125)
            builder.extend(b'],"description":')
            _append_material(builder, columns[15])
            if self._target is not None:
                builder.extend(b',"target":')
                _append_text(builder, self._target)
            if self._associated is not None:
                builder.extend(b',"associated-secret":')
                builder.extend(str(self._associated).encode("ascii"))
            for service, port in dep.services:
                builder.append(44)
                _append_text(builder, f"{service}-service-status")
                builder.extend(b':"up"')
                if port is not None:
                    builder.append(44)
                    _append_text(builder, f"{service}-service-port")
                    builder.append(58)
                    builder.extend(str(port).encode("ascii"))
            builder.extend(b',"inherit-permission":"enable","user-permission":[],"group-permission":[],"launch-with":')
            _append_text(builder, "associate" if self._associated is not None else "itself")
            builder.append(125)
            body = builder.finish()
            self._check(deadline)
            bridge._verify()
            with self._borrow_body(body, deadline) as view:
                yield view
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            builder.close()
            _wipe(body)
            self._lock.release()

    @contextmanager
    def _borrow_body(self, body: bytearray, deadline: float) -> Iterator[memoryview]:
        """DTO and wire bytes share the same owned, non-renewing disposal."""
        stop, view = threading.Event(), None
        def watch() -> None:
            try:
                while not stop.wait(min(0.05, max(0.0, deadline - time.monotonic()))):
                    self._check(deadline)
            except BaseException:
                _wipe(body)
        watcher = threading.Thread(target=watch, name="owner-row-conversion-disposal", daemon=True)
        try:
            self._check(deadline)
            watcher.start()
            view = memoryview(body).toreadonly()
            yield view
            self._check(deadline)
        finally:
            stop.set()
            if view is not None:
                view.release()
            _wipe(body)
            if watcher.ident is not None and watcher is not threading.current_thread():
                watcher.join(timeout=1.0)

    def _check(self, deadline: float) -> None:
        if time.monotonic() >= deadline or self._bridge._loader._session._transaction._closed.is_set():
            raise ValueError
