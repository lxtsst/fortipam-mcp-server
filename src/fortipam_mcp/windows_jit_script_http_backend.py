"""Default-closed HTTP candidate for two fixed Script definitions only.

POST/DELETE routes follow retained build29 evidence. ACK normalization and the
strict metadata profile remain local candidates, with no native qualification,
eligibility producer, startup binding, Script execution or Secret assignment.
"""
from __future__ import annotations

from collections.abc import Callable
import hmac
from threading import RLock

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as metadata
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .windows_jit_script_m4 import JitScriptReceipt
from .windows_jit_script_source import COLLECTION_PATH, WindowsJitScriptSource, _encoded

CONTRACT = 'fortipam-build29-windows-jit-fixed-script-http-local/v1'
_ERROR = 'The private Windows JIT Script HTTP candidate is unavailable.'
_REQUIRED = {'http_method','http_status','status','path','name','serial','version','build'}
_OPTIONAL = {'vdom','mkey','error','revision','revision_changed','results'}


class WindowsJitScriptHttpError(RuntimeError):
    """Fixed error without endpoint, body, identity or response content."""


def _ack(raw: bytearray, source: WindowsJitScriptSource, index: int, remove: bool) -> str:
    left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
    if _skip_json_space(raw,right) != len(raw): raise ValueError
    metadata._validate_json(raw,left,right,depth=0,budget=[512])
    fields = _object_spans(raw,left,right)
    if not _REQUIRED <= fields.keys() <= _REQUIRED | _OPTIONAL: raise ValueError
    expected = dict(http_method='DELETE' if remove else 'POST',http_status=200,status='success',
        path='secret',name='script',serial=source._serial,version='v7.0.0',build=29)
    for name,value in expected.items():
        with memoryview(raw)[slice(*fields[name])] as actual:
            if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
    minimized: dict[str,object] = dict(contract=CONTRACT,**expected)
    for name,optional_value in dict(vdom='root',mkey=source._expected[index]['name'],error=0,revision_changed=True).items():
        if name not in fields: continue
        with memoryview(raw)[slice(*fields[name])] as actual:
            if not hmac.compare_digest(actual,_encoded(optional_value)): raise ValueError
        minimized[name] = optional_value
    # Opaque revision contents and any arbitrary result never enter a decoder
    # or digest. Only empty native result shapes are admitted in this profile.
    if 'revision' in fields:
        start,end = fields['revision']
        if raw[start] != 34 or not 2 <= end-start <= 514: raise ValueError
    if 'results' in fields:
        with memoryview(raw)[slice(*fields['results'])] as result_view:
            if not any(hmac.compare_digest(result_view,empty) for empty in (b'null',b'{}',b'[]')): raise ValueError
    return canonical_digest(minimized)


class WindowsJitScriptHttpBackend(_OpaqueC3Object):
    """Each fixed definition's create/remove slot is attempted at most once.

    The physical M4 session and its persistent journal own authorization and
    original custody. This process-local slot table cannot recover a restart.
    """
    def __init__(self, source: WindowsJitScriptSource, *,
            execution_enabled: Callable[[],bool] | None = None,
            source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(source) is not WindowsJitScriptSource
                    or any(value is not None and not callable(value) for value in (execution_enabled,source_guard))): raise ValueError
            source._available()
            self._source = source; self._config = source._config
            self._enabled = self._enabled_pin = execution_enabled
            self._guard = self._guard_pin = source_guard
            self._definitions = source._definition_digest
            self._attempted: set[tuple[int,bool]] = set()
            self._acks: dict[tuple[int,bool],JitScriptReceipt] = {}
            self._closed = False; self._lock = RLock()
        except Exception: raise WindowsJitScriptHttpError(_ERROR) from None

    def _available(self) -> None:
        self._source._available()
        if (self._closed or self._source._config is not self._config
                or self._source._definition_digest != self._definitions
                or self._enabled is None or self._enabled is not self._enabled_pin or self._enabled() is not True
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True): raise ValueError

    def submit(self, body: memoryview | None, *, index: int, remove: bool, parameters_digest: str,
            before_send: Callable[[],int], timeout_seconds: int) -> JitScriptReceipt:
        connection = None; raw = bytearray(); receipt = None
        try:
            with self._lock, _private_http_logs():
                self._available(); require_digest(parameters_digest,'JIT Script parameters')
                if (type(index) is not int or index not in (0,1) or type(remove) is not bool
                        or type(timeout_seconds) is not int or not 0 < timeout_seconds <= 60
                        or not callable(before_send) or (index,remove) in self._attempted): raise ValueError
                if remove:
                    if body is not None or (index,False) not in self._acks: raise ValueError
                elif (not isinstance(body,memoryview) or not body.readonly or body.ndim != 1 or body.format != 'B'
                        or not body.c_contiguous or not hmac.compare_digest(body,_encoded(self._source._expected[index]))): raise ValueError
                s = self._source; deadline = s._now()+min(timeout_seconds,self._config.timeout_seconds)
                self._attempted.add((index,remove))
                with s._bounded_by(deadline):
                    try:
                        connection = s._factory(s._host,s._port,context=s._tls,timeout=s._remaining(deadline))
                        connection.set_debuglevel(0); connection.connect(); self._available(); s._remaining(deadline)
                        budget = before_send()
                        if type(budget) is not int or not 0 < budget <= 60: raise ValueError
                        deadline = min(deadline,s._now()+budget)
                        self._available(); connection.sock.settimeout(s._remaining(deadline))
                        path = s._details[index] if remove else COLLECTION_PATH
                        connection.request('DELETE' if remove else 'POST',path,body=body,headers={
                            'Authorization':'Bearer '+self._config.bearer_token,'Accept':'application/json',
                            'Content-Type':'application/json','Accept-Encoding':'identity','Connection':'close',
                            'Cache-Control':'no-cache,no-store'})
                        _,raw = s._receive(connection,deadline,16384)
                        digest = _ack(raw,s,index,remove)
                        self._available(); s._remaining(deadline)
                        receipt = JitScriptReceipt(s._source,parameters_digest,index,remove,digest)
                    finally:
                        _zeroize_mutable(raw)
                        if connection is not None: connection.close()
                        self._available(); s._remaining(deadline)
                self._acks[(index,remove)] = receipt
                return receipt
        except Exception: raise WindowsJitScriptHttpError(_ERROR) from None

    def close(self) -> None:
        with self._lock: self._closed = True
