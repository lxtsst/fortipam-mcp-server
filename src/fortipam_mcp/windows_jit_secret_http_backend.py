"""Default-closed seven-control JIT PUT candidate for one fixed Secret.

No credential, field or TOTP value is submitted. The native preservation
semantics, ACK normalization and derived Script reference counts remain
unqualified; the M4 evidence boundary requires independent qualification before
dispatch. This module supplies no eligibility producer or startup binding.
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
from .windows_jit_secret_contract import WindowsJitSecretPlan, _encoded
from .windows_jit_secret_m4 import JitSecretReceipt
from .windows_jit_secret_source import WindowsJitSecretSource

CONTRACT = 'fortipam-build29-windows-jit-fixed-secret-http-local/v1'
_ERROR = 'The private Windows JIT Secret HTTP candidate is unavailable.'
_REQUIRED = {'http_method','http_status','status','path','name','serial','version','build'}
_OPTIONAL = {'vdom','mkey','error','revision','revision_changed','results'}


class WindowsJitSecretHttpError(RuntimeError):
    """A categorical refusal without material, private identity or response."""


def _ack(raw: bytearray, source: WindowsJitSecretSource) -> str:
    left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
    if _skip_json_space(raw,right) != len(raw): raise ValueError
    metadata._validate_json(raw,left,right,depth=0,budget=[512]); fields = _object_spans(raw,left,right)
    if not _REQUIRED <= fields.keys() <= _REQUIRED | _OPTIONAL: raise ValueError
    expected = dict(http_method='PUT',http_status=200,status='OK',path='secret',name='database',
        serial=source._scripts._serial,version='v7.0.0',build=29)
    for name,value in expected.items():
        with memoryview(raw)[slice(*fields[name])] as actual:
            if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
    minimized: dict[str,object] = dict(contract=CONTRACT,**expected)
    for name,optional_value in dict(vdom='root',mkey=source._binding.secret_id,error=0,revision_changed=True).items():
        if name not in fields: continue
        with memoryview(raw)[slice(*fields[name])] as actual:
            if not hmac.compare_digest(actual,_encoded(optional_value)): raise ValueError
        minimized[name] = optional_value
    if 'revision' in fields:
        start,end = fields['revision']
        if raw[start] != 34 or not 2 <= end-start <= 514: raise ValueError
    if 'results' in fields:
        with memoryview(raw)[slice(*fields['results'])] as actual:
            if not any(hmac.compare_digest(actual,empty) for empty in (b'null',b'{}',b'[]')): raise ValueError
    return canonical_digest(minimized)


class WindowsJitSecretHttpBackend(_OpaqueC3Object):
    def __init__(self, source: WindowsJitSecretSource, initial: WindowsJitSecretPlan, *,
            execution_enabled: Callable[[],bool] | None = None,
            source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(source) is not WindowsJitSecretSource or type(initial) is not WindowsJitSecretPlan
                    or source._plan is not initial or source._plan_origin is None or source._plan_origin.secret is not initial.baseline
                    or any(value is not None and not callable(value) for value in (execution_enabled,source_guard))): raise ValueError
            source._available(); initial.__post_init__()
            if not source._plan_origin.observed_at <= source._scripts._epoch() < source._plan_origin.expires_at: raise ValueError
            self._source,self._initial,self._config = source,initial,source._scripts._config
            self._enabled = self._enabled_pin = execution_enabled; self._guard = self._guard_pin = source_guard
            self._binding_pin = (source._source,source._binding,source._detail,initial.baseline.digest)
            self._attempted: set[bool] = set(); self._acks: dict[bool,JitSecretReceipt] = {}
            self._lock = RLock(); self._closed = False
        except Exception: raise WindowsJitSecretHttpError(_ERROR) from None

    def _available(self) -> None:
        self._source._available()
        if (self._closed or self._source._scripts._config is not self._config
                or (self._source._source,self._source._binding,self._source._detail,self._initial.baseline.digest) != self._binding_pin
                or self._enabled is None or self._enabled is not self._enabled_pin or self._enabled() is not True
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True): raise ValueError

    def submit(self, body: memoryview, *, restore: bool, parameters_digest: str,
            before_send: Callable[[],int], timeout_seconds: int) -> JitSecretReceipt:
        connection = None; raw = bytearray()
        try:
            with self._lock, _private_http_logs():
                self._available(); require_digest(parameters_digest,'JIT Secret parameters')
                if (type(restore) is not bool or restore in self._attempted or not callable(before_send)
                        or type(timeout_seconds) is not int or not 0 < timeout_seconds <= 60
                        or restore and False not in self._acks or not isinstance(body,memoryview)
                        or not body.readonly or body.ndim != 1 or body.format != 'B' or not body.c_contiguous): raise ValueError
                expected = self._initial.compile_metadata_patch(self._initial.expected() if restore else self._initial.baseline,restore=restore)
                if not hmac.compare_digest(body,_encoded(expected)): raise ValueError
                s = self._source._scripts; deadline = s._now()+min(timeout_seconds,self._config.timeout_seconds)
                self._attempted.add(restore)
                with s._bounded_by(deadline):
                    try:
                        connection = s._factory(s._host,s._port,context=s._tls,timeout=s._remaining(deadline))
                        connection.set_debuglevel(0); connection.connect(); self._available(); s._remaining(deadline)
                        budget = before_send()
                        if type(budget) is not int or not 0 < budget <= 60: raise ValueError
                        deadline = min(deadline,s._now()+budget); self._available()
                        connection.sock.settimeout(s._remaining(deadline))
                        connection.request('PUT',self._source._detail,body=body,headers={
                            'Authorization':'Bearer '+self._config.bearer_token,'Accept':'application/json',
                            'Content-Type':'application/json','Accept-Encoding':'identity','Connection':'close',
                            'Cache-Control':'no-cache,no-store'})
                        _,raw = s._receive(connection,deadline,16384)
                        receipt = JitSecretReceipt(self._source._source,parameters_digest,restore,_ack(raw,self._source))
                        self._available(); s._remaining(deadline)
                    finally:
                        _zeroize_mutable(raw)
                        if connection is not None: connection.close()
                        self._available(); s._remaining(deadline)
                self._acks[restore] = receipt; return receipt
        except Exception: raise WindowsJitSecretHttpError(_ERROR) from None

    def close(self) -> None:
        with self._lock: self._closed = True
