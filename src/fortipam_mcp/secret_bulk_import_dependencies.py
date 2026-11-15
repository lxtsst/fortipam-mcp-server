"""Private, non-dispatching whole-batch dependency resolution for build 29.

This is NOT an authoritative projection, M2 Scheme, provider, or M4 plan. The
catalog is private input, not evidence of its own completeness or permissions.
Live source qualification and independently authorized child actions are still
required. Credential columns are never decoded or retained in the result.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import math
import re
import time
from typing import Callable, Literal, TypeVar

from v4_planning.material_provider import _OpaqueC3Object

from .secret_bulk_import_file import ProtectedBulkImportRows
from .secret_bulk_import_metadata import ImportMetadataField, ImportMetadataFolder, ImportMetadataTemplate

_ERROR = "Protected bulk-import dependencies unavailable."
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"(?:(.*?) )?\(ID:\s*([1-9][0-9]{0,9})\)\Z")
_FIELD_COLUMNS = {
    "target-address": 3, "domain": 4, "username": 5, "password": 6,
    "passphrase": 6, "private-key": 7, "public-key": 8, "cert": 9,
    "url": 10, "text": 11,
}
_TARGET_COLUMNS = (3, 4, 10)
_MATERIAL_COLUMNS = (5, 6, 7, 8, 9, 11)
_COVERAGE = frozenset({"folders", "templates", "targets", "secret_names", "association_ids"})
_T = TypeVar("_T")


class BulkImportDependencyError(ValueError):
    """Fixed non-disclosing failure; no partial row plan is returned."""


@dataclass(frozen=True, slots=True, repr=False)
class ImportTemplateField(_OpaqueC3Object):
    name: str
    kind: str
    mandatory: bool


@dataclass(frozen=True, slots=True, repr=False)
class ImportTemplate(_OpaqueC3Object):
    name: str
    fields: tuple[ImportTemplateField, ...]


@dataclass(frozen=True, slots=True, repr=False)
class ImportFolder(_OpaqueC3Object):
    path: str
    identifier: int
    can_add: bool


@dataclass(frozen=True, slots=True, repr=False)
class ImportTarget(_OpaqueC3Object):
    name: str
    template: str
    address: str
    domain: str
    url: str
    baseline_digest: str


@dataclass(frozen=True, slots=True, repr=False)
class ImportExistingSecret(_OpaqueC3Object):
    identifier: int
    name: str
    can_associate: bool


@dataclass(frozen=True, slots=True, repr=False)
class ImportDependencyCatalog(_OpaqueC3Object):
    scope_digest: str
    source_digest: str
    observed_at: float
    expires_at: float
    coverage: frozenset[str]
    folders: tuple[ImportFolder, ...]
    templates: tuple[ImportTemplate, ...]
    targets: tuple[ImportTarget, ...]
    # Complete collision namespace is independent of accessible/eligible IDs.
    secret_names: tuple[str, ...]
    secrets: tuple[ImportExistingSecret, ...]
    service_types: frozenset[str]
    product_version: str = "v7.0.0"
    product_build: int = 29


@dataclass(frozen=True, slots=True, repr=False)
class ImportRowDependency(_OpaqueC3Object):
    # All names/IDs remain protected selectors. Indices refer to the decoded
    # nonempty rows, not physical CSV line numbers (fields may contain newlines).
    index: int
    name: str
    folder_id: int
    template: str
    target_group: int | None
    association_row: int | None
    association_id: int | None
    services: tuple[tuple[str, int | None], ...]


@dataclass(frozen=True, slots=True, repr=False)
class ImportTargetDependency(_OpaqueC3Object):
    effect: Literal["create", "reuse", "update"]
    existing_name: str | None
    baseline_digest: str | None
    template: str
    address: str
    domain: str
    url: str


class ResolvedImportDependencies(_OpaqueC3Object):
    """Metadata only; no credentials, payload, callback, or execution authority."""

    __slots__ = ("__rows", "__targets", "__order", "__file_digest", "__catalog_digest", "__expires")
    _display_name = "ResolvedImportDependencies"

    def __init__(self, rows: tuple[ImportRowDependency, ...],
                 targets: tuple[ImportTargetDependency, ...], order: tuple[int, ...],
                 *, file_digest: str, catalog_digest: str, expires: float) -> None:
        self.__rows, self.__targets, self.__order = rows, targets, order
        self.__file_digest, self.__catalog_digest, self.__expires = file_digest, catalog_digest, expires

    def _inspect_private(self, consumer: Callable[[tuple[ImportRowDependency, ...],
                         tuple[ImportTargetDependency, ...], tuple[int, ...]], _T], *,
                         file_digest: str, catalog_digest: str) -> _T:
        try:
            if (time.monotonic() >= self.__expires or file_digest != self.__file_digest
                    or catalog_digest != self.__catalog_digest):
                raise ValueError
            return consumer(self.__rows, self.__targets, self.__order)
        except Exception:
            raise BulkImportDependencyError(_ERROR) from None


def _text(value: object, *, empty: bool = False) -> str:
    if (type(value) is not str or (not empty and not value) or len(value.encode("utf-8")) > 65536
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or value != value.strip()):
        raise ValueError
    return value


def _identifier(value: object) -> None:
    if type(value) is not int or not 0 < value <= 2_147_483_647:
        raise ValueError


def _folder_path(value: str) -> str:
    path = _text(value).strip("/")
    if not path or any(not part or part in {".", ".."} for part in path.split("/")):
        raise ValueError
    return path


def _unique(values: list[str]) -> None:
    if len({value.casefold() for value in values}) != len(values):
        raise ValueError


def project_importable_templates(
    records: tuple[ImportMetadataTemplate, ...],
) -> tuple[ImportTemplate, ...]:
    """Select expressible, explicitly usable definitions; never qualify source truth."""
    try:
        if type(records) is not tuple or len(records) > 4096:
            raise ValueError
        names: list[str] = []
        result: list[ImportTemplate] = []
        for record in records:
            if (type(record) is not ImportMetadataTemplate or type(record.fields) is not tuple
                    or len(record.fields) > 64 or record.permission not in (None, "none", "create-secret", "owner")):
                raise ValueError
            name = _text(record.name)
            if len(name.encode("utf-8")) > 255:
                raise ValueError
            names.append(name)
            definitions: list[ImportTemplateField] = []
            for field in record.fields:
                if type(field) is not ImportMetadataField or type(field.mandatory) is not bool or type(field.kind) is not str:
                    raise ValueError
                label = _text(field.name)
                if len(label.encode("utf-8")) > 255:
                    raise ValueError
                definitions.append(ImportTemplateField(label, field.kind, field.mandatory))
            _unique([field.name for field in definitions])
            if (record.permission in ("create-secret", "owner") and definitions
                    and all(field.kind in _FIELD_COLUMNS for field in definitions)
                    and len({field.kind for field in definitions}) == len(definitions)):
                result.append(ImportTemplate(name, tuple(definitions)))
        _unique(names)
        return tuple(result)
    except Exception:
        raise BulkImportDependencyError(_ERROR) from None


def project_import_folder_paths(
    records: tuple[ImportMetadataFolder, ...],
) -> tuple[ImportFolder, ...]:
    """Join complete observed ancestry; missing parents/cycles/ambiguous paths deny."""
    try:
        if type(records) is not tuple or len(records) > 4096:
            raise ValueError
        nodes: dict[int, ImportMetadataFolder] = {}
        for record in records:
            if (type(record) is not ImportMetadataFolder or type(record.parent_identifier) is not int
                    or not 0 <= record.parent_identifier <= 2147483647 or record.kind not in ("public", "personal")
                    or record.permission not in (None, "none", "view", "add-secret", "edit", "owner")):
                raise ValueError
            _identifier(record.identifier)
            name = _text(record.name)
            if len(name.encode("utf-8")) > 255 or "/" in name or name in (".", ".."):
                raise ValueError
            if record.identifier in nodes and nodes[record.identifier] != record:
                raise ValueError
            nodes[record.identifier] = record
        result: list[ImportFolder] = []
        for record in nodes.values():
            parts: list[str] = []
            seen: set[int] = set()
            current = record
            while True:
                if current.identifier in seen:
                    raise ValueError
                seen.add(current.identifier)
                parts.append(current.name)
                if current.parent_identifier == 0:
                    break
                current = nodes[current.parent_identifier]
            path = _folder_path("/".join(reversed(parts)))
            result.append(ImportFolder(path, record.identifier, record.permission in ("add-secret", "edit", "owner")))
        _unique([folder.path for folder in result])
        return tuple(result)
    except Exception:
        raise BulkImportDependencyError(_ERROR) from None


def dependency_catalog_digest(catalog: ImportDependencyCatalog) -> str:
    """Private metadata digest, NOT a signature or source-qualification receipt."""
    try:
        if (type(catalog) is not ImportDependencyCatalog or type(catalog.coverage) is not frozenset
                or catalog.coverage != _COVERAGE
                or catalog.product_version != "v7.0.0" or type(catalog.product_build) is not int
                or catalog.product_build != 29 or _DIGEST.fullmatch(catalog.scope_digest) is None
                or _DIGEST.fullmatch(catalog.source_digest) is None
                or any(type(value) not in (int, float) or not math.isfinite(value)
                       for value in (catalog.observed_at, catalog.expires_at))
                or not time.monotonic() < catalog.expires_at <= catalog.observed_at + 60
                or not 0 <= catalog.observed_at <= time.monotonic()):
            raise ValueError
        if any(type(items) is not tuple or len(items) > 4096
               for items in (catalog.folders, catalog.templates, catalog.targets,
                             catalog.secret_names, catalog.secrets)):
            raise ValueError
        folders, templates, targets, secrets = [], [], [], []
        for folder in catalog.folders:
            if type(folder) is not ImportFolder:
                raise ValueError
            _identifier(folder.identifier)
            if type(folder.can_add) is not bool:
                raise ValueError
            folders.append((_folder_path(folder.path), folder.identifier, folder.can_add))
        _unique([item[0] for item in folders])
        if len({item[1] for item in folders}) != len(folders):
            raise ValueError
        for template in catalog.templates:
            if type(template) is not ImportTemplate:
                raise ValueError
            _text(template.name)
            if type(template.fields) is not tuple or not 1 <= len(template.fields) <= 64:
                raise ValueError
            fields = []
            for field in template.fields:
                if type(field) is not ImportTemplateField:
                    raise ValueError
                _text(field.name)
                if field.kind not in _FIELD_COLUMNS or type(field.mandatory) is not bool:
                    raise ValueError
                fields.append((field.name, field.kind, field.mandatory))
            _unique([field[0] for field in fields])
            if len({field[1] for field in fields}) != len(fields):
                raise ValueError
            templates.append((template.name, fields))
        _unique([item[0] for item in templates])
        for target in catalog.targets:
            if type(target) is not ImportTarget:
                raise ValueError
            _text(target.name)
            _text(target.template)
            if _DIGEST.fullmatch(target.baseline_digest) is None:
                raise ValueError
            targets.append((target.name, target.template, *(_text(value, empty=True)
                for value in (target.address, target.domain, target.url)), target.baseline_digest))
        _unique([item[0] for item in targets])
        namespace = [_text(name) for name in catalog.secret_names]
        if any(len(name.encode("utf-8")) > 255 for name in namespace):
            raise ValueError
        for secret in catalog.secrets:
            if type(secret) is not ImportExistingSecret:
                raise ValueError
            _identifier(secret.identifier)
            _text(secret.name)
            if type(secret.can_associate) is not bool:
                raise ValueError
            secrets.append((secret.identifier, secret.name, secret.can_associate))
        if len({item[0] for item in secrets}) != len(secrets):
            raise ValueError
        namespace_counts = Counter(namespace)
        if any(namespace_counts[name] < count for name, count in
               Counter(item[1] for item in secrets).items()):
            raise ValueError
        if (type(catalog.service_types) is not frozenset or not catalog.service_types
                or not catalog.service_types <= {"ssh", "sftp", "rdp", "http", "samba", "telnet"}):
            raise ValueError
        payload = [catalog.scope_digest, catalog.source_digest, catalog.observed_at, catalog.expires_at,
                   folders, templates, targets, namespace, secrets, sorted(catalog.service_types)]
        return hashlib.sha256(json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
    except Exception:
        raise BulkImportDependencyError(_ERROR) from None


def _services(kind: str, port: str, allowed: frozenset[str]) -> tuple[tuple[str, int | None], ...]:
    if not kind:
        if port:
            raise ValueError
        return ()
    kinds = [value.strip().lower() for value in kind.split(";")]
    kinds = ["http" if value == "web" else value for value in kinds]
    ports = [value.strip() for value in port.split(";")] if port else []
    if (len(ports) > len(kinds) or len(set(kinds)) != len(kinds)
            or not set(kinds) <= allowed):
        raise ValueError
    ports.extend([""] * (len(kinds) - len(ports)))
    result = []
    for service, value in zip(kinds, ports, strict=True):
        number = None
        if value:
            if re.fullmatch(r"[1-9][0-9]{0,4}", value) is None or int(value) > 65535 or service == "samba":
                raise ValueError
            number = int(value)
        result.append((service, number))
    return tuple(result)


def resolve_import_dependencies(
    rows: ProtectedBulkImportRows, catalog: ImportDependencyCatalog, *,
    expected_file_digest: str, expected_catalog_digest: str, expected_scope_digest: str,
) -> ResolvedImportDependencies:
    """Consume/clear the entire batch, or return only protected metadata joins.

    Caller-supplied catalog data never becomes execution authority. An update
    decision explicitly requires an independently qualified full-preservation
    Target update/restore child; a create decision still needs a bound new name.
    """
    try:
        if type(rows) is not ProtectedBulkImportRows:
            raise ValueError

        def resolve(values: tuple[tuple[memoryview, ...], ...]) -> ResolvedImportDependencies:
            if (any(type(value) is not str or _DIGEST.fullmatch(value) is None
                    for value in (expected_file_digest, expected_catalog_digest, expected_scope_digest))
                    or catalog.scope_digest != expected_scope_digest
                    or dependency_catalog_digest(catalog) != expected_catalog_digest):
                raise ValueError
            folders = {_folder_path(item.path): item for item in catalog.folders}
            templates = {item.name: item for item in catalog.templates}
            existing_ids = {item.identifier: item for item in catalog.secrets}
            existing_names = {name.casefold() for name in catalog.secret_names}
            metadata = [{column: _text(bytes(row[column]).decode("utf-8"), empty=True)
                         for column in (0, 1, 2, 3, 4, 10, 12, 13, 14)} for row in values]
            names = [item[1] for item in metadata]
            _unique(names)
            if any(name.casefold() in existing_names for name in names):
                raise ValueError
            names_to_rows = {name: index for index, name in enumerate(names)}
            result: list[ImportRowDependency] = []
            target_groups: list[ImportTargetDependency] = []
            for index, (row, meta) in enumerate(zip(values, metadata, strict=True)):
                folder, template = folders[_folder_path(meta[2])], templates[meta[0]]
                if not folder.can_add:
                    raise ValueError
                used_columns = {_FIELD_COLUMNS[field.kind] for field in template.fields}
                if (any(field.mandatory and not row[_FIELD_COLUMNS[field.kind]] for field in template.fields)
                        or any(row[column] and column not in used_columns for column in _MATERIAL_COLUMNS)):
                    raise ValueError
                target_group = None
                proposed = tuple(meta[column] for column in _TARGET_COLUMNS)
                if any(proposed):
                    if not used_columns.intersection(_TARGET_COLUMNS):
                        raise ValueError
                    # Include every overlapping candidate, not a last-wins map.
                    candidates = [target for target in catalog.targets if any(
                        value and value == current for value, current in
                        zip(proposed, (target.address, target.domain, target.url), strict=True))]
                    if len(candidates) > 1:
                        raise ValueError
                    target = candidates[0] if candidates else None
                    if target is not None and any(value and current and value != current for value, current
                            in zip(proposed, (target.address, target.domain, target.url), strict=True)):
                        raise ValueError
                    # Preserve existing unspecified fields. The native frontend
                    # instead clears them; no such update is inferred here.
                    final = tuple(value or current for value, current in zip(proposed,
                        (target.address, target.domain, target.url) if target else ("", "", ""), strict=True))
                    effect: Literal["create", "reuse", "update"] = "create"
                    if target:
                        effect = "reuse" if (target.template == template.name and final ==
                            (target.address, target.domain, target.url)) else "update"
                    dependency = ImportTargetDependency(effect, target.name if target else None,
                        target.baseline_digest if target else None, template.name, *final)
                    for group, prior in enumerate(target_groups):
                        overlap = ((dependency.existing_name is not None and
                                    dependency.existing_name == prior.existing_name)
                                   or any(value and value == current for value, current in zip(final,
                                       (prior.address, prior.domain, prior.url), strict=True)))
                        if overlap:
                            if dependency != prior:
                                raise ValueError
                            target_group = group
                            break
                    if target_group is None:
                        target_group = len(target_groups)
                        target_groups.append(dependency)
                association_row = association_id = None
                if meta[14]:
                    matched = _ID.fullmatch(meta[14])
                    if matched:
                        if meta[14] in names_to_rows:
                            raise ValueError
                        association_id = int(matched[2])
                        _identifier(association_id)
                        existing = existing_ids[association_id]
                        if (not existing.can_associate
                                or (matched[1] is not None and matched[1] != existing.name)):
                            raise ValueError
                    else:
                        association_row = names_to_rows[meta[14]]
                result.append(ImportRowDependency(index, meta[1], folder.identifier, template.name,
                    target_group, association_row, association_id, _services(meta[12], meta[13], catalog.service_types)))
            order: list[int] = []
            pending = set(range(len(result)))
            while pending:
                ready = sorted(index for index in pending if result[index].association_row is None
                               or result[index].association_row in order)
                if not ready:
                    raise ValueError
                order.extend(ready)
                pending.difference_update(ready)
            if dependency_catalog_digest(catalog) != expected_catalog_digest:
                raise ValueError
            return ResolvedImportDependencies(tuple(result), tuple(target_groups), tuple(order),
                file_digest=expected_file_digest, catalog_digest=expected_catalog_digest, expires=catalog.expires_at)

        return rows._consume_once(resolve, expected_sha256=expected_file_digest)
    except Exception:
        raise BulkImportDependencyError(_ERROR) from None
