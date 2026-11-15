"""Private fixed-route reference read; no Tool, eligibility or write authority."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import math
import ssl
import time
from typing import Literal
from urllib.parse import urlsplit

import httpx

from . import secret_bulk_import_metadata as m
from . import secret_bulk_import_dependencies as d
from v4_planning.material_provider import _OpaqueC3Object
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

_ERROR = "Protected bulk-import reference read unavailable."
_COLLECTION = "/api/v2/cmdb/secret/database"
_QUERY = "?format=id%7Cname%7Cpermissions&with_meta=true&vdom=root"
_PERSONAL_BODY = (b'{"json_filter":[{"logic":"and","filters":[{"key":"folder-type",'
                  b'"type":"string","operator":"exact","pattern":"personal"}]}]}')
_View = Literal["database", "detail", "template", "public", "personal"]


class BulkImportReferenceReadError(ValueError):
    """Fixed failure without partial references or response values."""


@dataclass(frozen=True, slots=True, repr=False)
class ImportTemplateFolderObservation(_OpaqueC3Object):
    """Stable actor-visible metadata, not a complete catalog or permission grant."""

    template_view: m.NativeImportMetadataCollection
    public_folder_view: m.NativeImportMetadataCollection
    personal_folder_view: m.NativeImportMetadataCollection
    templates: tuple[d.ImportTemplate, ...]
    folders: tuple[d.ImportFolder, ...]
    observed_at: float
    completed_at: float


def _read_import_metadata(
    config: SecretMetadataHttpTransportConfig, *, serial_digest: str,
    expected: m.ImportMetadataSecret | None,
    client_factory: Callable[..., httpx.Client] = httpx.Client,
    clock: Callable[[], float] = time.monotonic,
) -> m.ImportMetadataSecret | ImportTemplateFolderObservation:
    """Shared transport for two compiled sequences; no caller route/body/operation."""
    buffers: list[bytearray] = []
    try:
        if (type(config) is not SecretMetadataHttpTransportConfig
                or expected is not None and type(expected) is not m.ImportMetadataSecret
                or type(serial_digest) is not str or m._DIGEST.fullmatch(serial_digest) is None):
            raise ValueError
        config.__post_init__()
        origin = urlsplit(config.base_url)
        if not origin.hostname or origin.username is not None or origin.password is not None:
            raise ValueError
        if expected is not None:
            m._integer(expected.identifier)
            m._text(expected.name)
            if expected.permission is not None and (
                    type(expected.permission) is not str or expected.permission not in m._PERMISSIONS["database"]):
                raise ValueError
        previous: float | None = None

        def now() -> float:
            nonlocal previous
            value = clock()
            if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                    or previous is not None and value < previous):
                raise ValueError
            previous = float(value)
            return float(value)

        started = now()
        deadline = started + min(30.0, config.timeout_seconds)

        def remaining() -> float:
            value = deadline - now()
            if value <= 0:
                raise ValueError
            return min(10.0, value)

        context = _ssl_context(config)
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with _private_http_logs(), client_factory(verify=context, timeout=remaining(),
                follow_redirects=False, trust_env=False) as client:
            try:
                reads = 0

                def fetch(view: _View) -> bytearray:
                    nonlocal reads
                    if reads >= (3 if expected is not None else 6):
                        raise ValueError
                    reads += 1
                    detail = view == "detail"
                    body = b'{"json_filter":[]}'
                    if view in ("database", "detail"):
                        if expected is None:
                            raise ValueError
                        path = _COLLECTION + (f"/{expected.identifier}" if detail else "") + _QUERY
                    elif view == "template":
                        path = "/api/v2/cmdb/secret/template?format=name%7Cfield%7Cpermissions&with_meta=true&vdom=root"
                    elif view in ("public", "personal"):
                        path = "/api/v2/cmdb/secret/folder?format=id%7Cname%7Cparent-folder%7Cfolder-type%7Cpermissions&with_meta=true&vdom=root"
                        if view == "personal":
                            body = _PERSONAL_BODY
                    else:
                        raise ValueError
                    raw = bytearray()
                    buffers.append(raw)
                    client.cookies.clear()
                    headers = {"Authorization": "Bearer " + config.bearer_token,
                        "Accept": "application/json", "Accept-Encoding": "identity",
                        "User-Agent": "fortipam-mcp-bulk-import-reference/1", "Cache-Control": "no-store"}
                    if not detail:
                        headers.update({"X-HTTP-Method-Override": "GET", "Content-Type": "application/json"})
                    with client.stream("GET" if detail else "POST", config.base_url.rstrip("/") + path,
                            headers=headers, content=None if detail else body,
                            timeout=remaining()) as response:
                        remaining()
                        if (response.status_code != 200
                                or response.headers.get("content-type", "").split(";")[0].lower() != "application/json"
                                or response.headers.get("content-encoding", "identity") not in ("", "identity")):
                            raise ValueError
                        iterator = response.iter_raw()
                        while True:
                            remaining()
                            try:
                                chunk = next(iterator)
                            except StopIteration:
                                remaining()
                                break
                            remaining()
                            if len(raw) + len(chunk) > m._MAX_BYTES:
                                raise ValueError
                            raw.extend(chunk)
                    remaining()
                    return raw

                def collection() -> tuple[m.ImportMetadataSecret, ...]:
                    projected = m.project_native_import_metadata(fetch("database"),
                        table="database", expected_serial_digest=serial_digest)
                    rows = projected.rows
                    if any(type(row) is not m.ImportMetadataSecret for row in rows):
                        raise ValueError
                    return tuple(sorted((row for row in rows if isinstance(row, m.ImportMetadataSecret)),
                        key=lambda row: row.identifier))

                result: m.ImportMetadataSecret | ImportTemplateFolderObservation
                if expected is not None:
                    before = collection()
                    if expected not in before:
                        raise ValueError
                    result = m.project_native_import_secret_detail(fetch("detail"),
                        expected_serial_digest=serial_digest, expected=expected)
                    if collection() != before:
                        raise ValueError
                else:
                    def metadata(view: Literal["template", "public", "personal"]) -> m.NativeImportMetadataCollection:
                        selected = m.project_native_import_metadata(fetch(view),
                            table="template" if view == "template" else "folder", expected_serial_digest=serial_digest)
                        remaining()
                        if view == "template":
                            if any(type(row) is not m.ImportMetadataTemplate for row in selected.rows):
                                raise ValueError
                            rows: tuple[m._Row, ...] = tuple(sorted(
                                (row for row in selected.rows if isinstance(row, m.ImportMetadataTemplate)),
                                key=lambda row: row.name.casefold()))
                        else:
                            if (selected.filtered_count != len(selected.rows)
                                    or any(type(row) is not m.ImportMetadataFolder or row.kind != view for row in selected.rows)):
                                raise ValueError
                            folder_rows = [row for row in selected.rows if isinstance(row, m.ImportMetadataFolder)]
                            folder_rows.sort(key=lambda row: row.identifier)
                            rows = tuple(folder_rows)
                        return replace(selected, rows=rows)

                    templates, public, personal = metadata("template"), metadata("public"), metadata("personal")
                    if (metadata("template"), metadata("public"), metadata("personal")) != (templates, public, personal):
                        raise ValueError
                    importable = d.project_importable_templates(tuple(
                        row for row in templates.rows if isinstance(row, m.ImportMetadataTemplate)))
                    folders = d.project_import_folder_paths(tuple(
                        row for view in (public, personal) for row in view.rows if isinstance(row, m.ImportMetadataFolder)))
                    remaining()
                    result = ImportTemplateFolderObservation(templates, public, personal,
                        importable, folders, started, now())
            finally:
                client.cookies.clear()
        remaining()
        if isinstance(result, ImportTemplateFolderObservation):
            result = replace(result, completed_at=now())
            remaining()
        return result
    except Exception:
        raise BulkImportReferenceReadError(_ERROR) from None
    finally:
        for raw in buffers:
            _zeroize_mutable(raw)


def read_import_secret_reference(
    config: SecretMetadataHttpTransportConfig, *, serial_digest: str,
    expected: m.ImportMetadataSecret,
    client_factory: Callable[..., httpx.Client] = httpx.Client,
    clock: Callable[[], float] = time.monotonic,
) -> m.ImportMetadataSecret:
    """Read one exact reference with collection/detail/collection; no eligibility grant."""
    if type(expected) is not m.ImportMetadataSecret:
        raise BulkImportReferenceReadError(_ERROR)
    result = _read_import_metadata(config, serial_digest=serial_digest, expected=expected,
        client_factory=client_factory, clock=clock)
    if not isinstance(result, m.ImportMetadataSecret):
        raise BulkImportReferenceReadError(_ERROR)
    return result


def read_import_template_folder_metadata(
    config: SecretMetadataHttpTransportConfig, *, serial_digest: str,
    client_factory: Callable[..., httpx.Client] = httpx.Client,
    clock: Callable[[], float] = time.monotonic,
) -> ImportTemplateFolderObservation:
    """Read template/public-folder/personal-folder twice under one bounded Bearer.

    Explicit visible metadata and ancestry only: no global completeness, actor
    role qualification, association eligibility, catalog or execution authority.
    """
    result = _read_import_metadata(config, serial_digest=serial_digest, expected=None,
        client_factory=client_factory, clock=clock)
    if not isinstance(result, ImportTemplateFolderObservation):
        raise BulkImportReferenceReadError(_ERROR)
    return result
