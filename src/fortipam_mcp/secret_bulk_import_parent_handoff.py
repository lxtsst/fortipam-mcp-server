"""Inactive, one-use C2 handoff on a trusted startup's inherited private socket.

The sole sender belongs to the authenticated submission workload. The descriptor
provides custody, not human authentication: submission verifies both tokens and
Owner independently verifies its exact Reference permission. Never accept a
caller-selected peer, graph or plan through HTTP/MCP. This supplies no child
execution, new journal or deployed workload qualification.
"""

from __future__ import annotations

from dataclasses import asdict, fields
import json
import math
from pathlib import Path
import socket
import threading
import time
from typing import Callable, TYPE_CHECKING

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref
from v4_planning.persistence import PersistentProtectedPlanningStore
from v4_planning.store import OriginalImportBindingRecord

from .reference_authority_sidecar import UnixReferenceAuthorityClient
from .secret_bulk_import_dependencies import (
    ImportDependencyCatalog, ImportRowDependency, ImportTargetDependency,
    ResolvedImportDependencies, _identifier, _text, dependency_catalog_digest,
)
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_intake_authority import PinnedOwnerFileIntakeAuthority, _members
from .secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility
from .secret_bulk_import_row_action_worker import _receive, _send
from .secret_bulk_import_row_namespace import PinnedOriginalImportRows, _bind_original_import_metadata
from .secret_bulk_import_parent_graph import (
    _OriginalImportGraph, _build_file_import_parent, _compile_original_import_graph, _validate_graph,
)

if TYPE_CHECKING:
    from .secret_bulk_import_source_catalog import _QualifiedTextImport, _TextOnlyImportSource

_LIMIT = 1048576
_RECEIPT = b'original-import-binding-retained/v1'


def _decode_graph(raw: bytearray, binding: OwnerFileIntakeBinding,
                  catalog: ImportDependencyCatalog, context: str) -> ResolvedImportDependencies:
    value = json.loads(raw, object_pairs_hook=_members)
    if (type(value) is not dict or set(value) != {'context', 'rows', 'targets', 'order'}
            or value['context'] != context or type(value['rows']) is not list
            or not 1 <= len(value['rows']) <= 256 or type(value['targets']) is not list
            or len(value['targets']) > 256 or type(value['order']) is not list
            or any(type(index) is not int for index in value['order'])
            or sorted(value['order']) != list(range(len(value['rows'])))):
        raise ValueError
    rows: list[ImportRowDependency] = []
    targets: list[ImportTargetDependency] = []
    for item in value['targets']:
        if type(item) is not dict or set(item) != {field.name for field in fields(ImportTargetDependency)}:
            raise ValueError
        if item['effect'] not in ('create', 'reuse', 'update'):
            raise ValueError
        for name in ('template', 'address', 'domain', 'url'):
            _text(item[name], empty=name != 'template')
        if item['effect'] == 'create':
            if item['existing_name'] is not None or item['baseline_digest'] is not None:
                raise ValueError
        else:
            _text(item['existing_name'])
            require_digest(item['baseline_digest'], 'target baseline')
        targets.append(ImportTargetDependency(**item))
    for index, item in enumerate(value['rows']):
        if (type(item) is not dict or set(item) != {field.name for field in fields(ImportRowDependency)}
                or type(item['index']) is not int or item['index'] != index):
            raise ValueError
        _text(item['name'])
        _text(item['template'])
        _identifier(item['folder_id'])
        for name, bound in (('target_group', len(targets)), ('association_row', len(value['rows']))):
            if item[name] is not None and (type(item[name]) is not int or not 0 <= item[name] < bound):
                raise ValueError
        if item['association_id'] is not None:
            _identifier(item['association_id'])
        if item['association_row'] is not None:
            if (item['association_id'] is not None
                    or value['order'].index(item['association_row']) >= value['order'].index(index)):
                raise ValueError
        services = item['services']
        if type(services) is not list or len(services) > len(catalog.service_types):
            raise ValueError
        names: set[str] = set()
        for service in services:
            if (type(service) is not list or len(service) != 2 or type(service[0]) is not str
                    or service[0] not in catalog.service_types or service[0] in names
                    or (service[1] is not None and (type(service[1]) is not int or not 1 <= service[1] <= 65535))):
                raise ValueError
            names.add(service[0])
        item['services'] = tuple((service[0], service[1]) for service in services)
        rows.append(ImportRowDependency(**item))
    _validate_graph(tuple(rows), tuple(targets), tuple(value['order']), catalog)
    return ResolvedImportDependencies(tuple(rows), tuple(targets), tuple(value['order']),
        file_digest=binding.file_sha256, catalog_digest=dependency_catalog_digest(catalog), expires=catalog.expires_at)


class _OriginalParentHandoff(_OpaqueC3Object):
    """Intake endpoint, prebound by trusted startup; no Owner keys or source read."""

    def __init__(self, peer: socket.socket, binding: OwnerFileIntakeBinding,
                 catalog: ImportDependencyCatalog, context: str, deadline: float) -> None:
        if (type(peer) is not socket.socket or peer.family != socket.AF_UNIX or peer.type != socket.SOCK_STREAM
                or type(binding) is not OwnerFileIntakeBinding or type(catalog) is not ImportDependencyCatalog
                or not math.isfinite(deadline) or not time.monotonic() < deadline <= time.monotonic() + 60):
            raise BulkImportIntakeError(_ERROR)
        require_digest(context, 'handoff context')
        peer.getpeername()
        peer.set_inheritable(False)
        self._peer, self._binding, self._catalog = peer, binding, catalog
        self._context, self._deadline = context, deadline
        self._lock, self._used = threading.Lock(), False

    def close(self) -> None:
        try:
            self._peer.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._peer.close()

    def _forward(self, projected: ResolvedImportDependencies) -> None:
        """Called only after actual authenticated projection in the fixed handler."""
        raw = receipt = None
        with self._lock:
            try:
                if self._used or type(projected) is not ResolvedImportDependencies:
                    raise ValueError
                self._used = True
                value = projected._inspect_private(lambda rows, targets, order:
                    dict(context=self._context, rows=[asdict(row) for row in rows],
                         targets=[asdict(target) for target in targets], order=order),
                    file_digest=self._binding.file_sha256, catalog_digest=dependency_catalog_digest(self._catalog))
                raw = bytearray(json.dumps(value, separators=(',', ':'), allow_nan=False).encode())
                if len(raw) > _LIMIT:
                    raise ValueError
                _decode_graph(raw, self._binding, self._catalog, self._context)
                _send(self._peer, self._deadline, raw)
                receipt = _receive(self._peer, self._deadline, len(_RECEIPT))
                if receipt != _RECEIPT:
                    raise ValueError
            except Exception:
                raise BulkImportIntakeError(_ERROR) from None
            finally:
                for owned in (raw, receipt):
                    if owned is not None:
                        _wipe(owned)
                self.close()


class _OriginalParentReceiver(_OpaqueC3Object):
    """Owner verifies permission/parent and commits C2 once before receipt."""

    def __init__(self, peer: socket.socket, binding: OwnerFileIntakeBinding, catalog: ImportDependencyCatalog,
                 *, store: PersistentProtectedPlanningStore, authority: PinnedOwnerFileIntakeAuthority,
                 plan_ref: str, plan_digest: str | None, requester_digest: str, parent_idempotency_digest: str,
                 key_path: Path, key_sha256: str, clock: Callable[[], float] = time.time,
                 standing_lab_authorization: bool = False,
                 text_source: _TextOnlyImportSource | None = None) -> None:
        try:
            from .secret_bulk_import_source_catalog import _TextOnlyImportSource

            if (type(store) is not PersistentProtectedPlanningStore
                    or type(authority) is not PinnedOwnerFileIntakeAuthority or authority._binding != binding
                    or type(authority._human_owner_verifier) is not ReferenceOwnerFileEligibility
                    or type(authority._human_owner_verifier._authority) is not UnixReferenceAuthorityClient
                    or authority._human_owner_verifier._requester != requester_digest
                    or catalog.scope_digest != binding.scope_digest
                    or type(standing_lab_authorization) is not bool
                    or (plan_digest is None) is not standing_lab_authorization):
                raise ValueError
            require_ref(plan_ref, 'original parent')
            for digest in (requester_digest, parent_idempotency_digest, key_sha256):
                require_digest(digest, 'original parent pin')
            if plan_digest is not None:
                require_digest(plan_digest, 'original parent pin')
            if text_source is not None:
                if type(text_source) is not _TextOnlyImportSource or text_source._used:
                    raise ValueError
                text_source._check_prepared_catalog(catalog,
                    file_digest=binding.file_sha256, scope_digest=binding.scope_digest)
            self._text_source = text_source
            self._qualified: _QualifiedTextImport | None = None
            self._store, self._authority, self._clock = store, authority, clock
            self._plan_ref, self._plan_digest, self._requester = plan_ref, plan_digest, requester_digest
            self._idempotency, self._key_path, self._key_digest = parent_idempotency_digest, key_path, key_sha256
            self._lab_intent = standing_lab_authorization
            self._last_wall = float(clock())
            context = canonical_digest(dict(binding={**asdict(binding), 'path': str(binding.path)},
                catalog=dependency_catalog_digest(catalog), plan=plan_ref, digest=plan_digest,
                requester=requester_digest, idempotency=parent_idempotency_digest, namespace=key_sha256,
                intent_mode='lab_auto_file_import' if standing_lab_authorization else 'existing_parent'))
            self._endpoint = _OriginalParentHandoff(peer, binding, catalog, context,
                min(time.monotonic() + min(60.0, binding.expires_at - self._last_wall), catalog.expires_at))
            self._check()
        except Exception:
            peer.close()
            raise BulkImportIntakeError(_ERROR) from None

    def _check(self) -> None:
        endpoint = self._endpoint
        now = float(self._clock())
        if (not math.isfinite(now) or now < self._last_wall
                or not endpoint._binding.issued_at <= now < endpoint._binding.expires_at
                or time.monotonic() >= endpoint._deadline):
            raise ValueError
        self._last_wall = now
        if self._text_source is not None:
            if self._qualified is None:
                self._text_source._check_prepared_catalog(endpoint._catalog,
                    file_digest=endpoint._binding.file_sha256, scope_digest=endpoint._binding.scope_digest)
            else:
                self._text_source.check_current(self._qualified,
                    file_digest=endpoint._binding.file_sha256, scope_digest=endpoint._binding.scope_digest)
        self._authority.verify(endpoint._binding, now_epoch=int(now))
        checker = self._authority._human_owner_verifier
        if type(checker) is not ReferenceOwnerFileEligibility:
            raise ValueError
        permission_expires = min(checker._verified_until, self._authority._load()['expires_at'])
        self._permission_expires = permission_expires
        plan = self._store.get_import_parent(self._plan_ref) if self._plan_digest is not None else None
        after = float(self._clock())
        if ((plan is not None and (plan.plan_digest != self._plan_digest or plan.requester_digest != self._requester
                                  or not plan.created_at <= now <= after < plan.expires_at))
                or not math.isfinite(after) or after < now
                or after >= min(endpoint._binding.expires_at, permission_expires)
                or time.monotonic() >= endpoint._deadline):
            raise ValueError
        self._last_wall = after
        endpoint._deadline = min(endpoint._deadline, time.monotonic() + permission_expires - after)

    def receive_once(self) -> tuple[PinnedOriginalImportRows, ResolvedImportDependencies, _OriginalImportGraph]:
        endpoint, raw, key = self._endpoint, None, None
        with endpoint._lock:
            try:
                if endpoint._used:
                    raise ValueError
                endpoint._used = True
                self._check()
                raw = _receive(endpoint._peer, endpoint._deadline, _LIMIT)
                graph = _decode_graph(raw, endpoint._binding, endpoint._catalog, endpoint._context)
                self._check()
                rows = _bind_original_import_metadata(endpoint._binding, graph, endpoint._catalog,
                    original_plan_ref=self._plan_ref, authenticated_requester_digest=self._requester,
                    parent_idempotency_digest=self._idempotency, key_path=self._key_path, key_sha256=self._key_digest)
                if self._text_source is not None:
                    self._qualified = self._text_source.qualify_original_projection_once(rows, endpoint._binding, graph)
                key = rows._key.load()
                if self._store.uses_key_material(bytes(key)):
                    raise ValueError
                self._check()
                if self._plan_digest is None:
                    policy = self._authority._load()
                    now = int(self._last_wall)
                    parent = _build_file_import_parent(rows, endpoint._binding, graph, endpoint._catalog,
                        source_policy_digest=self._authority._policy_digest,
                        owner_decision_digest=policy['owner_decision_digest'], created_at=now,
                        expires_at=min(now + 60, endpoint._binding.expires_at, int(self._permission_expires),
                                       int(self._last_wall + endpoint._deadline - time.monotonic())),
                        standing_lab_authorization=self._lab_intent)
                    self._check()
                    self._store.put_file_import_parent(parent)
                    self._plan_digest = parent.plan_digest
                    self._check()
                self._store.put_original_import_binding(OriginalImportBindingRecord(
                    plan_digest=self._plan_digest, namespace_key_digest=self._key_digest, **asdict(rows._operation)))
                compiled = _compile_original_import_graph(rows, endpoint._binding, graph, endpoint._catalog,
                    self._store, expected_parent_digest=self._plan_digest,
                    authenticated_requester_digest=self._requester, clock=self._clock)
                self._check()
                _send(endpoint._peer, endpoint._deadline, _RECEIPT)
                return rows, graph, compiled
            except BaseException as error:
                self._qualified = None
                if self._text_source is not None:
                    self._text_source.close()
                if not isinstance(error, Exception):
                    raise
                raise BulkImportIntakeError(_ERROR) from None
            finally:
                for owned in (raw, key):
                    if owned is not None:
                        _wipe(owned)
                endpoint.close()

    def close(self) -> None:
        self._endpoint.close()
