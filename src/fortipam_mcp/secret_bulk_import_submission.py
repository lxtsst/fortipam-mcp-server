"""Inactive fixed private submission; never a generic upload or MCP route.

Trusted startup prebinds one file, permission, catalog and remote verifiers.
Serve only inside the dedicated owner-side workload. This factory registers no
normal HTTP path, grants no permission and supplies no provider or write action.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import struct
import time
from typing import AsyncIterator, Callable

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from .reference_authority_sidecar import UnixReferenceAuthorityClient
from .secret_bulk_import_dependencies import ImportDependencyCatalog, dependency_catalog_digest
from ._secret_bulk_import_worker import MAX_PASSWORD_BYTES
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import (
    BulkImportIntakeError, OwnerFileIntakeBinding, _AdmittedOwnerFile, admit_prebound_owner_file, _ERROR,
)
from .secret_bulk_import_intake_authority import PinnedOwnerFileIntakeAuthority
from .secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility
from .secret_bulk_import_token_channel import UnixIntakeTokenVerifier
from .secret_bulk_import_session import _OwnerFileSourceSession, admit_prebound_owner_file_session
from .secret_bulk_import_session_authority import PinnedOwnerFileSessionAuthority
from .secret_bulk_import_parent_handoff import _OriginalParentHandoff
from .secret_bulk_import_intake_execution import _OriginalTextIntakeWorker

PATH = "/v1/owner-file-intake/project"
CONTENT_TYPE = "application/vnd.fortipam.owner-file-intake.v1"
_MAGIC = b"FPBIsub1"
_HEADER = 14
_MAX_FRAME = _HEADER + 2 * 16384 + MAX_PASSWORD_BYTES


class _SessionProjectionResponse(JSONResponse):
    def __init__(self, summary: dict[str, object], session: _OwnerFileSourceSession,
                 worker: _OriginalTextIntakeWorker | None = None) -> None:
        super().__init__(summary)
        self._session = session
        self._worker = worker

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        except BaseException:
            if self._worker is not None:
                self._worker.close()
            self._session.close()
            raise


async def _read_frame(request: Request) -> bytearray:
    raw = bytearray()
    try:
        lengths = request.headers.getlist("content-length")
        if (request.url.query or request.headers.get("origin") is not None
                or request.headers.getlist("content-type") != [CONTENT_TYPE]
                or request.headers.get("content-encoding") not in (None, "identity")
                or request.headers.get("transfer-encoding") is not None
                or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                or len(lengths[0]) > 5 or not _HEADER < int(lengths[0]) <= _MAX_FRAME):
            raise ValueError
        count = 0
        async with asyncio.timeout(2):
            async for chunk in request.stream():
                count += 1
                if count > 256 or len(raw) + len(chunk) > int(lengths[0]):
                    raise ValueError
                raw.extend(chunk)
        if len(raw) != int(lengths[0]):
            raise ValueError
        return raw
    except BaseException:
        _wipe(raw)
        raise


def _credentials(raw: bytearray) -> tuple[str, str, int]:
    if raw[:8] != _MAGIC:
        raise ValueError
    plan_length, intake_length, password_length = struct.unpack_from("!HHH", raw, 8)
    if (not 0 < plan_length <= 16384 or not 0 < intake_length <= 16384
            or password_length > MAX_PASSWORD_BYTES
            or _HEADER + plan_length + intake_length + password_length != len(raw)):
        raise ValueError
    offset = _HEADER + plan_length
    planning = raw[_HEADER:offset].decode("ascii")
    private = raw[offset:offset + intake_length].decode("ascii")
    if any(ord(char) <= 32 or ord(char) >= 127 for token in (planning, private) for char in token):
        raise ValueError
    return planning, private, offset + intake_length


def create_owner_file_submission_app(
    binding: OwnerFileIntakeBinding, *, planning_verifier: UnixIntakeTokenVerifier,
    intake_verifier: UnixIntakeTokenVerifier, authority: PinnedOwnerFileIntakeAuthority,
    catalog: ImportDependencyCatalog, clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
    parent_handoff: _OriginalParentHandoff | None = None,
) -> Starlette:
    """Fixed owner-workload candidate; trusted configuration, no caller selectors.

    This is one metadata projection per live instance, not a persistent M4 claim.
    No password survives the request and no import or child lease is authorized.
    """
    return _create_owner_file_submission_app(binding, planning_verifier=planning_verifier,
        intake_verifier=intake_verifier, authority=authority, catalog=catalog, clock=clock, monotonic=monotonic,
        parent_handoff=parent_handoff)


def create_owner_file_session_submission_app(
    binding: OwnerFileIntakeBinding, *, planning_verifier: UnixIntakeTokenVerifier,
    intake_verifier: UnixIntakeTokenVerifier, authority: PinnedOwnerFileIntakeAuthority,
    session_authority: PinnedOwnerFileSessionAuthority, catalog: ImportDependencyCatalog,
    clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
    parent_handoff: _OriginalParentHandoff | None = None,
    execution_worker: _OriginalTextIntakeWorker | None = None,
) -> Starlette:
    """Separate inactive candidate with an additional exact source-session grant.

    Serve with ASGI lifespan enabled. The optional fixed worker retains this
    session and projection, then waits for original Owner dispatch authority.
    Request data cannot select a worker or grant a row action.
    """
    if type(session_authority) is not PinnedOwnerFileSessionAuthority or session_authority._binding != binding:
        raise BulkImportIntakeError(_ERROR)
    return _create_owner_file_submission_app(binding, planning_verifier=planning_verifier,
        intake_verifier=intake_verifier, authority=authority, session_authority=session_authority,
        catalog=catalog, clock=clock, monotonic=monotonic, parent_handoff=parent_handoff,
        execution_worker=execution_worker)


def _create_owner_file_submission_app(
    binding: OwnerFileIntakeBinding, *, planning_verifier: UnixIntakeTokenVerifier,
    intake_verifier: UnixIntakeTokenVerifier, authority: PinnedOwnerFileIntakeAuthority,
    catalog: ImportDependencyCatalog, clock: Callable[[], float], monotonic: Callable[[], float],
    session_authority: PinnedOwnerFileSessionAuthority | None = None,
    parent_handoff: _OriginalParentHandoff | None = None,
    execution_worker: _OriginalTextIntakeWorker | None = None,
) -> Starlette:
    try:
        if (type(binding) is not OwnerFileIntakeBinding or type(catalog) is not ImportDependencyCatalog
                or type(planning_verifier) is not UnixIntakeTokenVerifier
                or type(intake_verifier) is not UnixIntakeTokenVerifier
                or planning_verifier._planning is not True or intake_verifier._planning is not False
                or planning_verifier._binding != intake_verifier._binding
                or type(authority) is not PinnedOwnerFileIntakeAuthority or authority._binding != binding
                or type(authority._human_owner_verifier) is not ReferenceOwnerFileEligibility
                or authority._human_owner_verifier._binding != binding
                or type(authority._human_owner_verifier._authority) is not UnixReferenceAuthorityClient
                or catalog.scope_digest != binding.scope_digest or not callable(clock) or not callable(monotonic)):
            raise ValueError
        binding.__post_init__()
        channel = planning_verifier._binding
        if (any(getattr(channel, name) != getattr(binding, name) for name in (
                "issuer", "planning_resource", "intake_resource", "deployment_digest", "workload_digest"))
                or not channel.issued_at <= binding.issued_at < binding.expires_at <= channel.expires_at):
            raise ValueError
        catalog_digest = dependency_catalog_digest(catalog)
        if execution_worker is not None and (type(execution_worker) is not _OriginalTextIntakeWorker
                or execution_worker._binding != binding or session_authority is None or parent_handoff is None):
            raise ValueError
        if parent_handoff is not None and (type(parent_handoff) is not _OriginalParentHandoff
                or parent_handoff._binding != binding or parent_handoff._catalog != catalog):
            raise ValueError
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    lock, consumed = asyncio.Lock(), False
    active_session: _OwnerFileSourceSession | None = None
    pending_session: _OwnerFileSourceSession | None = None
    closing, started = False, False

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        nonlocal closing, started
        started = True
        try:
            yield
        finally:
            closing = True
            if execution_worker is not None:
                execution_worker.close()
            if parent_handoff is not None:
                parent_handoff.close()
            if active_session is not None:
                active_session.close()
            if pending_session is not None:
                pending_session.close()

    async def project(request: Request) -> JSONResponse:
        nonlocal consumed, active_session, pending_session
        if lock.locked() or consumed or closing or (session_authority is not None and not started):
            return JSONResponse({"status": "unavailable"}, status_code=409)
        async with lock:
            raw: bytearray | None = None
            password: bytearray | None = None
            transaction: _AdmittedOwnerFile | _OwnerFileSourceSession | None = None
            try:
                raw = await _read_frame(request)
                planning_token, intake_token, offset = _credentials(raw)
                if session_authority is None:
                    transaction = await admit_prebound_owner_file(
                        binding, planning_token=planning_token, intake_token=intake_token,
                        planning_verifier=planning_verifier, intake_verifier=intake_verifier,
                        authority=authority, clock=clock, monotonic=monotonic,
                    )
                    consumed = True
                    with memoryview(raw) as view:
                        password = bytearray(view[offset:])
                    _wipe(raw)
                    result = transaction.project_dependencies_once(catalog, workbook_password=password)
                else:
                    with memoryview(raw) as view:
                        password = bytearray(view[offset:])
                    _wipe(raw)
                    transaction = await admit_prebound_owner_file_session(
                        binding, planning_token=planning_token, intake_token=intake_token,
                        planning_verifier=planning_verifier, intake_verifier=intake_verifier,
                        authority=authority, session_authority=session_authority, workbook_password=password,
                        clock=clock, monotonic=monotonic,
                    )
                    consumed = True
                    pending_session = transaction
                    result = await asyncio.to_thread(transaction.project_dependencies_once, catalog)
                summary = result._inspect_private(
                    lambda rows, targets, order: {"status": "projected", "rows": len(rows), "targets": len(targets)},
                    file_digest=binding.file_sha256, catalog_digest=catalog_digest,
                )
                if parent_handoff is not None:
                    await asyncio.to_thread(parent_handoff._forward, result)
                if isinstance(transaction, _OwnerFileSourceSession):
                    transaction._remaining()
                    response = _SessionProjectionResponse(summary, transaction, execution_worker)
                    if execution_worker is not None:
                        execution_worker.start_once(transaction, catalog, result)
                    active_session = transaction
                    return response
                else:
                    transaction._check()
                return JSONResponse(summary)
            except Exception:
                return JSONResponse({"status": "unavailable"}, status_code=409)
            finally:
                if parent_handoff is not None and consumed:
                    parent_handoff.close()
                if transaction is not None and transaction is not active_session:
                    if execution_worker is not None:
                        execution_worker.close()
                    transaction.close()
                pending_session = None
                for owned in (raw, password):
                    if owned is not None:
                        _wipe(owned)

    return Starlette(routes=[Route(PATH, project, methods=["POST"])], lifespan=lifespan)
