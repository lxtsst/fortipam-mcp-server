"""Inactive private owner-file admission; no route, provider, lease, or writer.

Trusted composition supplies token verifiers and an independent admission
authority. A token object, file pin, or caller-created binding grants nothing.
Only one metadata projection is supported; no unlock password is retained.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import math
from pathlib import Path
import re
import threading
import time
from typing import Callable, Protocol
from urllib.parse import urlsplit

from mcp.server.auth.provider import AccessToken, TokenVerifier

from v4_planning.material_provider import _OpaqueC3Object

from ._secret_bulk_import_worker import MAX_PASSWORD_BYTES
from .secret_bulk_import_dependencies import (
    ImportDependencyCatalog, ResolvedImportDependencies,
    dependency_catalog_digest, resolve_import_dependencies,
)
from .secret_bulk_import_file import PinnedBulkImportFile, ProtectedBulkImportRows, _ParserLifetime

_ERROR = "Private bulk-import intake unavailable."
_INTAKE_SCOPE = "fortipam:bulk-import-intake"
_TOKEN_VERIFY_SECONDS = 10.0
_DIGEST = re.compile(r"[a-f0-9]{64}")


class BulkImportIntakeError(ValueError):
    """Fixed non-disclosing intake rejection."""


def _text(value: object) -> bool:
    return (type(value) is str and 0 < len(value.encode("utf-8")) <= 4096
            and value == value.strip() and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _https(value: str) -> bool:
    parsed = urlsplit(value)
    return bool(_text(value) and parsed.scheme == "https" and parsed.netloc
                and not parsed.username and not parsed.password and not parsed.query
                and not parsed.fragment)


@dataclass(frozen=True, slots=True, repr=False)
class OwnerFileIntakeBinding(_OpaqueC3Object):
    """Private server-prebound admission intent, never proof of its own authority."""

    path: Path
    file_sha256: str
    file_format: str
    issuer: str
    subject: str
    planning_resource: str
    intake_resource: str
    planning_client: str
    intake_client: str
    deployment_digest: str
    scope_digest: str
    batch_digest: str
    workload_digest: str
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        try:
            if (not isinstance(self.path, Path) or not self.path.is_absolute()
                    or ".." in self.path.parts or self.file_format not in ("csv", "xlsm")
                    or any(type(v) is not str or _DIGEST.fullmatch(v) is None for v in (
                        self.file_sha256, self.deployment_digest, self.scope_digest,
                        self.batch_digest, self.workload_digest))
                    or any(not _https(v) for v in (
                        self.issuer, self.planning_resource, self.intake_resource))
                    or any(not _text(v) for v in (self.subject, self.planning_client, self.intake_client))
                    or self.planning_resource == self.intake_resource
                    or self.planning_client == self.intake_client
                    or type(self.issued_at) is not int or type(self.expires_at) is not int
                    or not 0 <= self.issued_at < self.expires_at <= 2**63 - 1):
                raise ValueError
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None


class OwnerFileIntakeAuthority(Protocol):
    """Trusted local policy verifies this exact intent and human/deployment grant.

    It must establish human-operator eligibility and the batch, file, workload,
    scope and validity from authoritative state. It must not accept an arbitrary
    caller binding merely because its shape is valid. No authority is packaged.
    """

    def verify(self, binding: OwnerFileIntakeBinding, *, now_epoch: int) -> object:
        """Return exactly None on authorization; raise to deny. Booleans deny."""
        ...


def _clock_sample(clock: Callable[[], float]) -> float:
    value = clock()
    if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
        raise ValueError
    return float(value)


def _verified_expiry(
    token: AccessToken | None, binding: OwnerFileIntakeBinding, *, planning: bool,
) -> int:
    resource = binding.planning_resource if planning else binding.intake_resource
    client = binding.planning_client if planning else binding.intake_client
    required = "fortipam:plan" if planning else _INTAKE_SCOPE
    allowed = {"fortipam:plan", "fortipam:read", "fortipam:operate"} if planning else {_INTAKE_SCOPE}
    if (not isinstance(token, AccessToken) or token.resource != resource
            or token.client_id != client or token.subject != binding.subject
            or type(token.expires_at) is not int or token.expires_at <= 0
            or not isinstance(token.claims, dict)
            or token.claims.get("iss") != binding.issuer
            or token.claims.get("sub") != binding.subject
            or (token.claims.get("client_id") or token.claims.get("azp")) != client
            or type(token.scopes) is not list or not 1 <= len(token.scopes) <= 3
            or any(type(scope) is not str for scope in token.scopes)
            or len(set(token.scopes)) != len(token.scopes)
            or required not in token.scopes or not set(token.scopes) <= allowed):
        raise ValueError
    return token.expires_at


class _AdmittedOwnerFile(_OpaqueC3Object):
    """One admitted metadata transaction, with no retained token or password."""

    __slots__ = ("_binding", "_source", "_authority", "_clock", "_monotonic",
                 "_expires", "_deadline", "_last_wall", "_last_mono", "_closed", "_lock", "_used",
                 "_state_lock", "_session_claimed")

    def __init__(self, binding: OwnerFileIntakeBinding, authority: OwnerFileIntakeAuthority,
                 clock: Callable[[], float], monotonic: Callable[[], float],
                 expires: float, deadline: float, wall: float, mono: float) -> None:
        self._binding, self._authority = binding, authority
        self._clock, self._monotonic = clock, monotonic
        self._expires, self._deadline = expires, deadline
        self._last_wall, self._last_mono = wall, mono
        self._closed, self._lock, self._used = threading.Event(), threading.Lock(), False
        self._state_lock, self._session_claimed = threading.RLock(), False
        self._check()
        if authority.verify(binding, now_epoch=int(self._last_wall)) is not None:
            raise ValueError
        self._check()
        self._source = PinnedBulkImportFile(binding.path, expected_sha256=binding.file_sha256,
                                           file_format=binding.file_format)
        self._check()
        if authority.verify(binding, now_epoch=int(self._last_wall)) is not None:
            raise ValueError
        self._check()

    def _check(self) -> None:
        with self._state_lock:
            wall, mono = _clock_sample(self._clock), _clock_sample(self._monotonic)
            if (self._closed.is_set() or wall < self._last_wall or mono < self._last_mono
                    or wall >= self._expires or mono >= self._deadline):
                self._closed.set()
                raise ValueError
            self._last_wall, self._last_mono = wall, mono

    def close(self) -> None:
        """Cancel future work; in-flight work must fail its next guard and clear."""
        self._closed.set()

    def project_dependencies_once(
        self, catalog: ImportDependencyCatalog, *, workbook_password: bytearray | None = None,
        _lifetime: _ParserLifetime | None = None,
    ) -> ResolvedImportDependencies:
        """Consume an unlock copy for this transaction; return private metadata only."""
        owned = bytearray()
        rows: ProtectedBulkImportRows | None = None
        acquired = False
        try:
            if workbook_password is not None:
                if type(workbook_password) is not bytearray or len(workbook_password) > MAX_PASSWORD_BYTES:
                    raise ValueError
                owned = bytearray(workbook_password)
                workbook_password[:] = b"\x00" * len(workbook_password)
            acquired = self._lock.acquire(blocking=False)
            if not acquired or self._used:
                raise ValueError
            self._used = True
            self._check()
            if self._authority.verify(self._binding, now_epoch=int(self._last_wall)) is not None:
                raise ValueError
            self._check()
            catalog_digest = dependency_catalog_digest(catalog)
            if catalog.scope_digest != self._binding.scope_digest:
                raise ValueError
            self._check()
            if _lifetime is None:
                rows = self._source.decode(workbook_password=owned)
            else:
                rows = self._source.decode(workbook_password=owned, _lifetime=_lifetime)
            self._check()
            result = resolve_import_dependencies(
                rows, catalog, expected_file_digest=self._binding.file_sha256,
                expected_catalog_digest=catalog_digest, expected_scope_digest=self._binding.scope_digest,
            )
            self._check()
            if self._authority.verify(self._binding, now_epoch=int(self._last_wall)) is not None:
                raise ValueError
            self._check()
            return result
        except BaseException:
            if acquired:
                self.close()
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            owned[:] = b"\x00" * len(owned)
            if type(workbook_password) is bytearray:
                workbook_password[:] = b"\x00" * len(workbook_password)
            if rows is not None:
                rows.clear()
            if acquired:
                self._lock.release()


async def admit_prebound_owner_file(
    binding: OwnerFileIntakeBinding, *, planning_token: str, intake_token: str,
    planning_verifier: TokenVerifier | None = None, intake_verifier: TokenVerifier | None = None,
    authority: OwnerFileIntakeAuthority | None = None,
    clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
) -> _AdmittedOwnerFile:
    """Verify both private tokens and independent admission before any file read.

    Verifiers and authority are trusted construction dependencies, never request
    arguments on a Tool/route. Defaults deny. This registers no scope or endpoint.
    """
    try:
        if (type(binding) is not OwnerFileIntakeBinding or planning_verifier is None
                or intake_verifier is None or authority is None
                or type(planning_token) is not str or not 0 < len(planning_token) <= 16384
                or type(intake_token) is not str or not 0 < len(intake_token) <= 16384):
            raise ValueError
        wall, mono = _clock_sample(clock), _clock_sample(monotonic)
        if not binding.issued_at <= wall < binding.expires_at:
            raise ValueError
        loop = asyncio.get_running_loop()
        verification_deadline = loop.time() + _TOKEN_VERIFY_SECONDS
        async with asyncio.timeout_at(verification_deadline):
            planning = await planning_verifier.verify_token(planning_token)
            if loop.time() >= verification_deadline:
                raise ValueError
            intake = await intake_verifier.verify_token(intake_token)
            if loop.time() >= verification_deadline:
                raise ValueError
        expires = min(float(binding.expires_at), wall + 900,
                      _verified_expiry(planning, binding, planning=True),
                      _verified_expiry(intake, binding, planning=False))
        return _AdmittedOwnerFile(binding, authority, clock, monotonic, expires,
                                  mono + expires - wall, wall, mono)
    except BaseException:
        raise BulkImportIntakeError(_ERROR) from None
