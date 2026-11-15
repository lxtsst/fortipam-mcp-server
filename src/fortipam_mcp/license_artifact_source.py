"""Private opaque license-file custody; no parser, upload or entitlement claim.

Only a future exact adapter may borrow the read-only view. This source does not
authorize a device action, provide durable dispatch replay protection, qualify
a native license, or expose a material getter through MCP.
"""
from __future__ import annotations

from collections.abc import Callable,Iterator
from contextlib import contextmanager
import hashlib
import hmac
from pathlib import Path
from threading import RLock

from v4_planning.material_provider import MaterialAccessDenied,MaterialBindingStatus,_OpaqueC3Object
from v4_planning.models import require_digest
from .ldap_server_runtime import _private_directory,_private_file,_read
from .mutable_json_buffer import _erase_transfer_storage

CONTRACT='fortipam-private-license-artifact-source-local/v1'
# Conservative local resource bound, not a native license format/size limit.
MAX_LICENSE_BYTES=65536
_ERROR='The private license artifact is unavailable.'


class LicenseArtifactSource(_OpaqueC3Object):
    """Pin an owner-only external file without opening its contents at startup.

    A single physical source permits one borrow attempt. A fresh source is not
    new license-install authority: the future exact M4 ledger must separately
    retain consumed/UNKNOWN dispatches and irreversible recovery semantics.
    """
    def __init__(self,path: Path,*,expected_sha256: str,scope_digest: str,audience_digest: str,
            source_guard: Callable[[],bool] | None=None) -> None:
        try:
            if type(path) is not type(Path()) or source_guard is not None and not callable(source_guard): raise ValueError
            for digest in (expected_sha256,scope_digest,audience_digest): require_digest(digest,'license binding')
            _private_directory(path.parent); _private_file(path)
            if any((parent/'.git').exists() for parent in path.parents): raise ValueError
            self._path=path; self._sha=expected_sha256; self._scope,self._audience=scope_digest,audience_digest
            self._guard=self._guard_pin=source_guard; self._identity=self._file_identity()
            self._lock=RLock(); self._used=False; self._closed=False; self._buffer: bytearray | None=None
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    def _file_identity(self) -> tuple[int,...]:
        _private_directory(self._path.parent); _private_file(self._path)
        parent=self._path.parent.stat(); info=self._path.stat()
        if not 0<info.st_size<=MAX_LICENSE_BYTES: raise ValueError
        return (parent.st_dev,parent.st_ino,info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

    def _current(self) -> None:
        guard=self._guard
        if self._closed or guard is None or guard is not self._guard_pin: raise ValueError
        allowed=guard()
        # The callback can close/revoke this source reentrantly under its RLock.
        if (self._closed or self._guard is not guard or guard is not self._guard_pin or allowed is not True
                or self._file_identity()!=self._identity): raise ValueError

    def validate_prebound(self) -> MaterialBindingStatus:
        # Availability is metadata/guard only, never artifact/native validation.
        with self._lock:
            try:
                self._current()
                return MaterialBindingStatus.UNAVAILABLE if self._used else MaterialBindingStatus.AVAILABLE
            except Exception: return MaterialBindingStatus.UNAVAILABLE

    @contextmanager
    def _borrow_once(self,*,scope_digest: str,audience_digest: str) -> Iterator[memoryview]:
        """Caller-owned private adapter scope; the view expires on every exit."""
        with self._lock:
            raw=None; view=None
            try:
                if (type(scope_digest) is not str or type(audience_digest) is not str
                        or (scope_digest,audience_digest)!=(self._scope,self._audience) or self._used): raise ValueError
                self._used=True; self._current()
                raw=self._buffer=_read(self._path,MAX_LICENSE_BYTES)
                if (len(raw)!=self._identity[4] or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),self._sha)): raise ValueError
                self._current(); view=memoryview(raw).toreadonly()
                yield view
                self._current()
            except Exception: raise MaterialAccessDenied(_ERROR) from None
            finally:
                try:
                    if view is not None: view.release()
                finally:
                    try:
                        if raw is not None: _erase_transfer_storage(raw)
                    finally:
                        self._buffer=None

    def close(self) -> None:
        with self._lock:
            self._closed=True
            try:
                if self._buffer is not None: _erase_transfer_storage(self._buffer)
            finally:
                self._buffer=None
