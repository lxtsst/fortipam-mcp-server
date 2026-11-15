"""Inactive pinned private submission composition; no listener or normal route.

The owner operator separately pins metadata and an expected source intent.
Neither custody nor this profile grants source permission. Independent signed
policy, Reference authorization and both remote token verifiers remain required.
"""

from __future__ import annotations

from dataclasses import fields
import hashlib
import json
from pathlib import Path
import socket
import threading
import time
from typing import Any, Callable

from starlette.applications import Starlette
from v4_planning.material_provider import _OpaqueC3Object

from .reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
from .secret_bulk_import_dependencies import (
    ImportDependencyCatalog, ImportExistingSecret, ImportFolder, ImportTarget,
    ImportTemplate, ImportTemplateField, dependency_catalog_digest,
)
from .secret_bulk_import_file import _read_owned, _wipe, _SourceIdentity
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _clock_sample, _ERROR
from .secret_bulk_import_intake_authority import PinnedOwnerFileIntakeAuthority, _members
from .secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility
from .secret_bulk_import_submission import create_owner_file_submission_app, create_owner_file_session_submission_app
from .secret_bulk_import_session_authority import PinnedOwnerFileSessionAuthority
from .secret_bulk_import_token_channel import IntakeTokenChannelBinding, UnixIntakeTokenVerifier
from .secret_bulk_import_parent_handoff import _OriginalParentHandoff
from .secret_bulk_import_intake_execution import _OriginalTextIntakeWorker

CONTRACT = "fortipam-owner-file-submission-startup-v1"
_MAX_PROFILE = 65536
_FIELDS = frozenset({"contract", "purpose", "source", "channel", "channel_options", "permission", "policy", "catalog"})


def _map(value: object, keys: set[str] | frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError
    return dict(value)


def _path(value: object) -> Path:
    if type(value) is not str or not value or len(value) > 4096 or any(ord(char) < 32 for char in value):
        raise ValueError
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError
    return path


def _record(value: object, kind: type[Any]) -> Any:
    return kind(**_map(value, {field.name for field in fields(kind)}))


def _catalog(value: object) -> ImportDependencyCatalog:
    payload = _map(value, {field.name for field in fields(ImportDependencyCatalog)})
    for name in ('folders', 'templates', 'targets', 'secrets', 'secret_names', 'coverage', 'service_types'):
        if type(payload[name]) is not list or len(payload[name]) > 4096:
            raise ValueError
    payload['folders'] = tuple(_record(item, ImportFolder) for item in payload['folders'])
    payload['targets'] = tuple(_record(item, ImportTarget) for item in payload['targets'])
    payload['secrets'] = tuple(_record(item, ImportExistingSecret) for item in payload['secrets'])
    templates = []
    for item in payload['templates']:
        template = _map(item, {'name', 'fields'})
        if type(template['fields']) is not list or len(template['fields']) > 64:
            raise ValueError
        templates.append(ImportTemplate(template['name'], tuple(_record(field, ImportTemplateField) for field in template['fields'])))
    payload['templates'] = tuple(templates)
    payload['secret_names'] = tuple(payload['secret_names'])
    for name in ('coverage', 'service_types'):
        if any(type(item) is not str for item in payload[name]) or len(set(payload[name])) != len(payload[name]):
            raise ValueError
        payload[name] = frozenset(payload[name])
    catalog = ImportDependencyCatalog(**payload)
    dependency_catalog_digest(catalog)
    return catalog


class PinnedOwnerFileSubmissionStartup(_OpaqueC3Object):
    """Build one private app from an externally pinned, exact metadata profile."""

    _display_name = "PinnedOwnerFileSubmissionStartup"

    def __init__(self, binding: OwnerFileIntakeBinding, *, profile_path: Path, profile_sha256: str,
                 clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(binding) is not OwnerFileIntakeBinding or not isinstance(profile_path, Path)
                    or profile_path.parts[1:] == binding.path.parts[1:]
                    or type(profile_sha256) is not str or len(profile_sha256) != 64
                    or any(char not in '0123456789abcdef' for char in profile_sha256)
                    or not callable(clock) or not callable(monotonic)):
                raise ValueError
            binding.__post_init__()
            self._binding, self._path, self._sha = binding, profile_path, profile_sha256
            self._clock, self._monotonic = clock, monotonic
            self._wall, self._mono = _clock_sample(clock), _clock_sample(monotonic)
            if not binding.issued_at <= self._wall < binding.expires_at <= binding.issued_at + 900:
                raise ValueError
            self._deadline = self._mono + binding.expires_at - self._wall
            self._identity: _SourceIdentity | None = None
            self._used, self._lock = False, threading.Lock()
            self._load()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _check(self) -> None:
        wall, mono = _clock_sample(self._clock), _clock_sample(self._monotonic)
        if (wall < self._wall or mono < self._mono or wall >= self._binding.expires_at or mono >= self._deadline):
            raise ValueError
        self._wall, self._mono = wall, mono

    def _load(self) -> dict[str, Any]:
        raw = None
        try:
            self._check()
            raw, identity = _read_owned(self._path, self._identity)
            if not 0 < len(raw) <= _MAX_PROFILE or hashlib.sha256(raw).hexdigest() != self._sha:
                raise ValueError
            value = _map(json.loads(raw, object_pairs_hook=_members), _FIELDS)
            if value['contract'] != CONTRACT or value['purpose'] != 'private-dependency-projection-only':
                raise ValueError
            source = _map(value['source'], {field.name for field in fields(OwnerFileIntakeBinding)})
            source['path'] = _path(source['path'])
            if OwnerFileIntakeBinding(**source) != self._binding:
                raise ValueError
            channel = _record(value['channel'], IntakeTokenChannelBinding)
            if (any(getattr(channel, name) != getattr(self._binding, name) for name in (
                    'issuer', 'planning_resource', 'intake_resource', 'deployment_digest', 'workload_digest'))
                    or not channel.issued_at <= self._binding.issued_at < self._binding.expires_at <= channel.expires_at):
                raise ValueError
            transport = _map(value['channel_options'], {'socket_path', 'request_key_path', 'request_key_sha256', 'public_key_path', 'public_key_sha256'})
            permission = _map(value['permission'], {'authority_ref', 'reference', 'requester_digest', 'scope_key_path', 'scope_key_sha256', 'socket_path'})
            policy = _map(value['policy'], {'policy_path', 'policy_sha256', 'key_path', 'key_sha256'})
            selectors = [self._path, self._binding.path]
            selectors.extend(_path(payload[name]) for payload, names in (
                (transport, ('socket_path', 'request_key_path', 'public_key_path')),
                (permission, ('socket_path', 'scope_key_path')), (policy, ('policy_path', 'key_path')),
            ) for name in names)
            if len({path.parts[1:] for path in selectors}) != len(selectors):
                raise ValueError
            catalog = _catalog(value['catalog'])
            if catalog.scope_digest != self._binding.scope_digest:
                raise ValueError
            self._check()
            self._identity = identity
            return value
        finally:
            if raw is not None:
                _wipe(raw)

    def create_app_once(self) -> Starlette:
        """Build without reading the source or granting a lease/action/listener."""
        return self._create_app_once(None)

    def create_source_session_app_once(self, session_authority: PinnedOwnerFileSessionAuthority) -> Starlette:
        """Additional independently pinned session permission; same one-use startup."""
        return self._create_app_once(session_authority, require_session=True)

    def create_original_parent_app_once(self, peer: socket.socket, *, context_digest: str, deadline: float,
                                       session_authority: PinnedOwnerFileSessionAuthority | None = None,
                                       execution_worker: _OriginalTextIntakeWorker | None = None) -> Starlette:
        """Consume an inherited Owner endpoint, never a request-supplied selector.

        Trusted startup owns descriptor delivery and pins the original context.
        The existing profile, token/Reference verification and creation slot all
        remain required. This does not open a listener or grant a child action.
        """
        try:
            return self._create_app_once(session_authority, require_session=session_authority is not None,
                parent_handoff=(peer, context_digest, deadline), execution_worker=execution_worker)
        except BaseException:
            if type(peer) is socket.socket:
                peer.close()
            if type(execution_worker) is _OriginalTextIntakeWorker:
                execution_worker.close()
            raise

    def _create_app_once(self, session_authority: PinnedOwnerFileSessionAuthority | None,
                         *, require_session: bool = False,
                         parent_handoff: tuple[socket.socket, str, float] | None = None,
                         execution_worker: _OriginalTextIntakeWorker | None = None) -> Starlette:
        acquired = self._lock.acquire(blocking=False)
        handoff = None
        try:
            if not acquired or self._used:
                raise ValueError
            self._used = True
            if execution_worker is not None and session_authority is None:
                raise ValueError
            if require_session and (type(session_authority) is not PinnedOwnerFileSessionAuthority
                                    or session_authority._binding != self._binding):
                raise ValueError
            value = self._load()
            channel = _record(value['channel'], IntakeTokenChannelBinding)
            transport = dict(value['channel_options'])
            for name in ('socket_path', 'request_key_path', 'public_key_path'):
                transport[name] = _path(transport[name])
            epoch = lambda: int(_clock_sample(self._clock))
            planning = UnixIntakeTokenVerifier(channel, planning=True, clock=epoch, monotonic=self._monotonic, **transport)
            private = UnixIntakeTokenVerifier(channel, planning=False, clock=epoch, monotonic=self._monotonic, **transport)
            permission = dict(value['permission'])
            socket_path = _path(permission.pop('socket_path'))
            permission['authority'] = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(socket_path, permission['authority_ref']))
            permission['scope_key_path'] = _path(permission['scope_key_path'])
            eligibility = ReferenceOwnerFileEligibility(self._binding, clock=epoch, **permission)
            policy = dict(value['policy'])
            for name in ('policy_path', 'key_path'):
                policy[name] = _path(policy[name])
            authority = PinnedOwnerFileIntakeAuthority(self._binding, human_owner_verifier=eligibility, clock=epoch, **policy)
            catalog = _catalog(value['catalog'])
            if parent_handoff is not None:
                peer, context, deadline = parent_handoff
                handoff = _OriginalParentHandoff(peer, self._binding, catalog, context, deadline)
            if session_authority is None:
                app = create_owner_file_submission_app(self._binding, planning_verifier=planning, intake_verifier=private,
                    authority=authority, catalog=catalog, clock=self._clock, monotonic=self._monotonic,
                    parent_handoff=handoff)
            else:
                app = create_owner_file_session_submission_app(self._binding, planning_verifier=planning,
                    intake_verifier=private, authority=authority, session_authority=session_authority,
                    catalog=catalog, clock=self._clock, monotonic=self._monotonic, parent_handoff=handoff,
                    execution_worker=execution_worker)
            if self._load() != value:
                raise ValueError
            self._check()
            return app
        except Exception:
            if handoff is not None:
                handoff.close()
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            if acquired:
                self._lock.release()
