"""Default-closed pre-create configuration scope for one unused service Target.

Borrow genuine current Target-reference evidence and its live Owner session.
Global grouped configuration must contain no direct or dependency reference to
that Target and no proposed-name collision. Unrelated rows outside the Owner's
metadata view are never fetched or interpreted as missing. Original Secret
runtime/material/association, activity, permission and M4 admission are separate.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
import re
import secrets
from threading import RLock
from typing import Any

import httpx
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from . import secret_dlp_dependency_ssh_reader as anchors
from . import secret_namespace_ssh_reader as namespace
from . import target_qualified_reference_reader as frames
from .cli_safety import _complete_pre_login
from .folder_namespace_ssh_reader import _frame_lines, _projection_lines
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .target_preservation_contract import _digest
from .target_ssh_transport import _send_and_read, _send_and_read_dynamic_prompt
from .windows_service_credential_associations import GROUPED_COMMAND, ServiceAssociationSecret, project_service_association_columns
from .windows_service_credential_contract import _NAME
from .windows_service_credential_target_references import (
    WindowsServiceCredentialTargetReferences, WindowsServiceTargetReferenceObservation,
)

_ERROR = "The private service credential association source is unavailable."
_CONTRACT = "fortipam-build29-service-empty-target-configuration-scope-v1"
_CATALOG = "/api/v2/cmdb/secret/database?format=id%7Cname%7Ctarget%7Cdependency&with_meta=true&vdom=root"
_BODY = b'{"json_filter":[]}'
_PAGING = frozenset({"has_more", "next_index", "offset", "start", "limit", "total", "total_count"})


class WindowsServiceAssociationSourceError(ValueError):
    """Categorical failure without selectors, private data or partial evidence."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceAssociationObservation(_OpaqueC3Object):
    source_context_digest: str
    target_reference_context_digest: str
    association_context_digest: str
    global_secret_count: int
    visible_secret_count: int
    unrelated_not_read_count: int
    positive_target_matches: int
    observed_at: float
    expires_at: float

    def summary(self) -> dict[str, object]:
        return dict(global_configuration_namespace_bound=True, proposed_name_absent=True,
            selected_target_configuration_reference_count=0, selected_precreate_configuration_scope_closed=True,
            original_secret_runtime_association_qualified=False, activity_qualified=False,
            material_qualified=False, execution_authorized=False, runtime_registered=False)


@dataclass(frozen=True, slots=True, repr=False)
class _Visible(_OpaqueC3Object):
    identifier: int
    name: str
    target: str
    dependencies: tuple[tuple[int, str, str], ...]


class WindowsServiceCredentialAssociationSources(_OpaqueC3Object):
    """One source attempt; closing preserves all borrowed source/session assets."""

    def __init__(self, references: WindowsServiceCredentialTargetReferences, *,
            observation: WindowsServiceTargetReferenceObservation, proposed_secret_name: str,
            read_enabled: bool = False, client_factory: Callable[..., httpx.Client] = httpx.Client) -> None:
        self._key = bytearray()
        try:
            if (type(references) is not WindowsServiceCredentialTargetReferences
                    or type(observation) is not WindowsServiceTargetReferenceObservation
                    or type(proposed_secret_name) is not str or _NAME.fullmatch(proposed_secret_name) is None
                    or type(read_enabled) is not bool or not callable(client_factory)):
                raise ValueError
            references.check_current(observation)
            self._parent, self._borrowed = references, observation
            self._name, self._enabled, self._factory = proposed_secret_name, read_enabled, client_factory
            self._identity = (references, observation, client_factory, proposed_secret_name)
            self._helpers = (_complete_pre_login, _send_and_read, _send_and_read_dynamic_prompt,
                project_service_association_columns)
            self._key.extend(secrets.token_bytes(32))
            self._closed = self._failed = self._used = False
            self._deadline: float | None = None
            self._current: WindowsServiceAssociationObservation | None = None
            self._seal: str | None = None
            self._phase: str | None = None
            self._lock = RLock()
            self._source = self._context()
        except Exception:
            _zeroize_mutable(self._key)
            raise WindowsServiceAssociationSourceError(_ERROR) from None

    def _context(self) -> str:
        self._parent.check_current(self._borrowed)
        return canonical_digest(dict(contract=_CONTRACT, parent_source=self._borrowed.source_context_digest,
            reference_scope=self._borrowed.reference_scope_digest, proposed_name=self._name,
            target=self._borrowed.target_reference_context_digest))

    def _guard(self) -> float:
        if (self._closed or self._failed or self._enabled is not True
                or any(current is not pinned for current, pinned in zip(
                    (self._parent, self._borrowed, self._factory, self._name), self._identity, strict=True))
                or self._helpers != (_complete_pre_login, _send_and_read, _send_and_read_dynamic_prompt,
                    project_service_association_columns)
                or type(self._key) is not bytearray or len(self._key) != 32
                or self._context() != self._source):
            raise ValueError
        now = self._parent._guard()
        if self._deadline is not None and now >= self._deadline:
            raise ValueError
        return now

    def _remaining(self) -> float:
        now = self._guard()
        if self._deadline is None:
            raise ValueError
        return min(10.0, self._deadline-now)

    def _catalog(self) -> tuple[_Visible, ...]:
        raw, consumed = bytearray(), bytearray()
        client: httpx.Client | None = None
        parent = self._parent
        try:
            self._guard()
            cookie, csrf = parent._owner._validated_cookie("POST", _CATALOG)
            with _private_http_logs(), self._factory(verify=parent._target._tls, timeout=self._remaining(),
                    trust_env=False, follow_redirects=False) as client:
                with client.stream("POST", parent._config.base_url+_CATALOG, headers={"Cookie": cookie,
                        "X-CSRFTOKEN": csrf, "X-HTTP-Method-Override": "GET", "Content-Type": "application/json",
                        "Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-store"},
                        content=_BODY) as response:
                    self._guard()
                    length, transfer = response.headers.get("content-length"), response.headers.get("transfer-encoding", "").strip().lower()
                    if (response.status_code != 200 or response.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                            or response.headers.get("content-encoding", "identity") != "identity"
                            or transfer not in ("", "chunked") or transfer and length is not None
                            or length is not None and (re.fullmatch(r"[0-9]{1,7}", length) is None or not 0 < int(length) <= 524288)):
                        raise ValueError
                    for chunk in response.iter_raw():
                        self._guard()
                        if len(raw)+len(chunk) > 524288:
                            raise ValueError
                        raw.extend(chunk)
                    if length is not None and len(raw) != int(length):
                        raise ValueError
                self._guard(); client.cookies.clear()
            consumed.extend(raw)
            projected = metadata.project_native_import_metadata(consumed, table="database", expected_serial_digest=parent._serial)
            if not 1 <= len(projected.rows) <= 128:
                raise ValueError
            start = _skip_json_space(raw, 0)
            top = _object_spans(raw, start, _json_value_end(raw, start))
            if _PAGING & top.keys() or "action" in top and metadata._scalar(raw, top["action"]) != "":
                raise ValueError
            result = []
            for view, span in zip(projected.rows, metadata._array(raw, top["results"], 128), strict=True):
                if type(view) is not metadata.ImportMetadataSecret:
                    raise ValueError
                fields = metadata._object_spans(raw, *span, frozenset({"target", "dependency"}))
                target = metadata._text(metadata._scalar(raw, fields["target"]), maximum=127, empty=True)
                dependencies = []
                for item in metadata._array(raw, fields["dependency"], 64):
                    child = metadata._object_spans(raw, *item, frozenset({"id", "target", "updater"}))
                    identifier = metadata._scalar(raw, child["id"])
                    if type(identifier) is not int or not 0 < identifier <= 64:
                        raise ValueError
                    dependencies.append((identifier, metadata._text(metadata._scalar(raw, child["target"]), maximum=127),
                        metadata._text(metadata._scalar(raw, child["updater"]), maximum=79)))
                if len(dependencies) != len({item[0] for item in dependencies}):
                    raise ValueError
                result.append(_Visible(view.identifier, view.name, target, tuple(dependencies)))
            self._guard()
            return tuple(result)
        finally:
            _zeroize_mutable(raw); _zeroize_mutable(consumed)
            if client is not None:
                client.cookies.clear(); client.close()

    async def _cli(self) -> tuple[ServiceAssociationSecret, ...]:
        connection: Any = None
        process: Any = None
        parent = self._parent
        try:
            now = self._guard()
            if self._deadline is None:
                raise ValueError
            deadline = self._deadline
            async with asyncio.timeout(deadline-now):
                connection = await parent._connect()
                self._guard()
                process = await connection.create_process(term_type="vt100", term_size=(512, 24), encoding=None)
                root = await _complete_pre_login(process.stdout, process.stdin, deadline, 65536, accept_pre_login_banner=False)
                if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", root) is None:
                    raise ValueError
                count = 0
                async def command(text: str, prompt: bytes) -> bytes:
                    nonlocal count
                    self._guard(); count += 1
                    if count > 10:
                        raise ValueError
                    result = await _send_and_read(process, text, prompt, deadline)
                    self._guard()
                    return result
                async def identity() -> None:
                    lines = frames._lines(await command(frames._SERIAL, root), frames._SERIAL, root)
                    match = re.fullmatch(rb"Serial-Number: ([A-Za-z0-9_-]{1,128})", lines[0]) if len(lines) == 1 else None
                    if match is None or hashlib.sha256(match[1]).hexdigest() != parent._serial:
                        raise ValueError
                    frames._version(frames._lines(await command(frames._VERSION, root), frames._VERSION, root))
                await identity(); count += 1
                prompt = await _send_and_read_dynamic_prompt(process, "config secret database", root, deadline)
                if prompt != root[:-2]+b" (database) #":
                    raise ValueError
                first = await command(GROUPED_COMMAND, prompt)
                rows = project_service_association_columns(_projection_lines(_frame_lines(first, GROUPED_COMMAND, prompt)))
                ids = anchors._edit_values(await command(anchors._EDIT_PROJECTION, prompt), prompt, numeric=True)
                names = namespace._secret_names(await command(namespace._NAME_PROJECTION, prompt), prompt)
                if (tuple(str(row.identifier) for row in rows) != ids or tuple(row.name for row in rows) != names
                        or first != await command(GROUPED_COMMAND, prompt)):
                    raise ValueError
                count += 1
                if await _send_and_read_dynamic_prompt(process, "end", root, deadline) != root:
                    raise ValueError
                await identity()
                if count != 10:
                    raise ValueError
                self._guard()
                return rows
        finally:
            try:
                if process is not None:
                    process.close()
                    async with asyncio.timeout(1): await process.wait_closed()
            finally:
                if connection is not None:
                    connection.abort()
                    async with asyncio.timeout(1): await connection.wait_closed()

    def read_once(self) -> WindowsServiceAssociationObservation:
        try:
            with self._lock:
                if self._used:
                    raise ValueError
                self._used = True
                started = self._guard()
                self._deadline = min(started+30.0, self._borrowed.expires_at)
                self._phase = "catalog-before"; before = self._catalog()
                self._phase = "global-configuration"; rows = asyncio.run(self._cli())
                self._phase = "catalog-after"; after = self._catalog()
                if before != after:
                    raise ValueError
                self._phase = "scoped-join"
                by_id = {row.identifier: row for row in rows}
                for view in before:
                    native = by_id[view.identifier]
                    if ((native.name, native.target) != (view.name, view.target)
                            or tuple((item.identifier, item.target, item.updater) for item in native.dependencies or ()) != view.dependencies):
                        raise ValueError
                target = self._parent._target._name
                if any(row.name == self._name or row.target == target
                        or any(item.target == target for item in row.dependencies or ()) for row in rows):
                    raise ValueError
                visible = Counter(row.target for row in before if row.target)
                global_values = Counter(row.target for row in rows if row.target)
                if not visible or any(global_values[name] < count for name, count in visible.items()):
                    raise ValueError
                positive = max(global_values[name] for name in visible)
                scope = _digest((tuple(asdict(row) for row in rows), tuple(asdict(row) for row in before)))
                association = canonical_digest(dict(contract=_CONTRACT, source=self._source, scope=scope,
                    target=self._borrowed.target_reference_context_digest, empty_relevant_configuration=True))
                self._guard()
                self._current = WindowsServiceAssociationObservation(self._source, self._borrowed.target_reference_context_digest,
                    association, len(rows), len(before), len(rows)-len(before), positive, started, self._deadline)
                self._seal = hmac.new(self._key, _digest(asdict(self._current)).encode(), hashlib.sha256).hexdigest()
                self._phase = None
                return self._current
        except Exception:
            self._failed = True
            raise WindowsServiceAssociationSourceError(_ERROR) from None

    def check_current(self, observed: WindowsServiceAssociationObservation) -> None:
        try:
            with self._lock:
                now = self._guard()
                if (type(observed) is not WindowsServiceAssociationObservation or observed is not self._current
                        or now >= observed.expires_at or self._seal is None
                        or not hmac.compare_digest(hmac.new(self._key, _digest(asdict(observed)).encode(), hashlib.sha256).hexdigest(), self._seal)):
                    raise ValueError
        except Exception:
            self._failed = True
            raise WindowsServiceAssociationSourceError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None; self._seal = None
            _zeroize_mutable(self._key)
