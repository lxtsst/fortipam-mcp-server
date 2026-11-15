"""Fixed cookie/CSRF activation and independent exit HTTP candidate.

The strict monitor ACK below is a LOCAL CANDIDATE, not an observed native
contract. Real ACK/action semantics and account/session scope must be qualified
by the independent M4 producer before any write. No producer or startup binding
is supplied. ACK messages are opaque and never decoded, hashed or returned.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
from http.cookies import SimpleCookie
from threading import RLock

from v4_planning import canonical_digest
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from . import secret_bulk_import_metadata as metadata
from .email_alert_general_contract import _encoded
from .glass_break_contract import ACTIVATE_PATH,DEACTIVATE_PATH,GlassBreakPlan
from .glass_break_m4 import GlassBreakM4Adapter,GlassBreakM4Session,GlassBreakReceipt
from .glass_break_source import GlassBreakSource
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end,_skip_json_space,_zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam-build29-glass-break-fixed-http-candidate/v1'
_ERROR = 'The private glass-breaking HTTP candidate is unavailable.'
_REQUIRED = {'http_method','http_status','status','path','name','action','serial','version','build','results'}
_OPTIONAL = {'vdom','error','revision'}


class GlassBreakHttpError(RuntimeError):
    """Categorical refusal without cookie, CSRF, actor, reason or response."""


def _ack_candidate(raw: bytearray, source: GlassBreakSource, deactivate: bool) -> str:
    left=_skip_json_space(raw,0); right=_json_value_end(raw,left)
    if _skip_json_space(raw,right)!=len(raw): raise ValueError
    metadata._validate_json(raw,left,right,depth=0,budget=[512]); fields=_object_spans(raw,left,right)
    if not _REQUIRED<=fields.keys()<=_REQUIRED|_OPTIONAL: raise ValueError
    expected=dict(http_method='POST',http_status=200,status='success',path='user',name='break-glass',
        action='deactivate' if deactivate else 'activate',version='v7.0.0',build=29)
    for key,value in expected.items():
        with memoryview(raw)[slice(*fields[key])] as actual:
            if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
    serial=metadata._scalar(raw,fields['serial'])
    if (type(serial) is not str or not 1<=len(serial)<=128
            or hashlib.sha256(serial.encode('utf-8')).hexdigest()!=source._binding.serial_digest): raise ValueError
    minimized: dict[str,object] = dict(contract=CONTRACT,serial_digest=source._binding.serial_digest,**expected)
    for key,value in dict(vdom='root',error=0).items():
        if key not in fields: continue
        with memoryview(raw)[slice(*fields[key])] as actual:
            if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
        minimized[key]=value
    results=_object_spans(raw,*fields['results'])
    if set(results)!={'msg'}: raise ValueError
    start,end=results['msg']
    if raw[start]!=34 or not 2<=end-start<=4096: raise ValueError
    if 'revision' in fields:
        start,end=fields['revision']
        if raw[start]!=34 or not 2<=end-start<=514: raise ValueError
    return canonical_digest(minimized)


class GlassBreakHttpBackend(_OpaqueC3Object):
    def __init__(self, source: GlassBreakSource, initial: GlassBreakPlan, *,
            execution_enabled: Callable[[],bool] | None=None, source_guard: Callable[[],bool] | None=None) -> None:
        try:
            if (type(source) is not GlassBreakSource or type(initial) is not GlassBreakPlan or source._plan is not initial
                    or source._origin is None or source._origin is not source._latest or source._origin.state is not initial.baseline
                    or any(value is not None and not callable(value) for value in (execution_enabled,source_guard))): raise ValueError
            source._available(); initial.__post_init__()
            if not source._origin.observed_at<=source._epoch()<source._origin.expires_at: raise ValueError
            self._source,self._initial,self._origin,self._config=source,initial,source._origin,source._config
            self._enabled=self._enabled_pin=execution_enabled; self._guard=self._guard_pin=source_guard
            self._binding_pin=(source._binding.digest,initial.digest); self._attempted: set[bool] = set()
            self._acks: dict[bool,GlassBreakReceipt] = {}; self._closed=False; self._lock=RLock()
        except Exception: raise GlassBreakHttpError(_ERROR) from None

    def _available(self) -> None:
        self._source._available()
        if (self._closed or self._source._config is not self._config or self._source._plan is not self._initial
                or self._source._origin is not self._origin or (self._source._binding.digest,self._initial.digest)!=self._binding_pin
                or self._enabled is None or self._enabled is not self._enabled_pin or self._enabled() is not True
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True): raise ValueError

    def _owned_adapter(self, deactivate: bool, parameters: str, callback: Callable[[],int]) -> GlassBreakM4Adapter:
        session=self._source._m4_session
        if (type(session) is not GlassBreakM4Session or session._backend is not self or session._initial is not self._initial
                or type(session._pending) is not GlassBreakM4Adapter): raise ValueError
        adapter: GlassBreakM4Adapter = session._pending
        owner: object = getattr(callback,'__self__',None); function: object = getattr(callback,'__func__',None)
        if (adapter._session is not session or (adapter._step.deactivate,adapter._step.parameters_digest)!=(deactivate,parameters)
                or owner is not adapter or function is not GlassBreakM4Adapter._before_send): raise ValueError
        _require_m4_dispatch_ownership(adapter._plan,adapter._authorization,session._store); adapter._check()
        if deactivate and self._acks.get(False) is not session._adapters[False]._receipt: raise ValueError
        return adapter

    def submit(self, body: memoryview, *, deactivate: bool, parameters_digest: str,
            before_send: Callable[[],int], timeout_seconds: int) -> GlassBreakReceipt:
        connection=None; raw=bytearray(); expected=bytearray()
        try:
            with self._lock,_private_http_logs():
                self._available(); require_digest(parameters_digest,'glass-breaking parameters')
                if (type(deactivate) is not bool or deactivate in self._attempted or not callable(before_send)
                        or type(timeout_seconds) is not int or not 0<timeout_seconds<=60 or not isinstance(body,memoryview)
                        or not body.readonly or body.ndim!=1 or body.format!='B' or not body.c_contiguous): raise ValueError
                adapter=self._owned_adapter(deactivate,parameters_digest,before_send); source=self._source
                deadline=min(source._now()+min(timeout_seconds,self._config.timeout_seconds),source._owner_expiry)
                expected=self._initial.compile(self._initial.expected() if deactivate else self._initial.baseline,deactivate=deactivate)
                if not hmac.compare_digest(body,expected): raise ValueError
                cookies: SimpleCookie = SimpleCookie(); cookies.load(source._cookie.decode('ascii'))
                csrf=cookies.get('ccsrftoken')
                if (csrf is None or not csrf.value or len(csrf.value)>4096 or not csrf.value.isascii()
                        or any(ord(c)<33 or ord(c)>126 for c in csrf.value)): raise ValueError
                source._remaining(deadline); self._attempted.add(deactivate)
                with source._bounded_by(deadline):
                    try:
                        connection=source._factory(source._host,source._port,context=source._tls,timeout=source._remaining(deadline))
                        connection.set_debuglevel(0); connection.connect(); self._available()
                        self._owned_adapter(deactivate,parameters_digest,before_send); source._remaining(deadline)
                        budget=before_send()
                        if type(budget) is not int or not 0<budget<=60: raise ValueError
                        deadline=min(deadline,source._now()+budget); self._available(); self._owned_adapter(deactivate,parameters_digest,before_send)
                        handle=connection.sock; handle.settimeout(source._remaining(deadline))
                        connection.request('POST',DEACTIVATE_PATH if deactivate else ACTIVATE_PATH,body=body,headers={
                            'Cookie':source._cookie.decode('ascii'),'X-CSRFTOKEN':csrf.value,'Accept':'application/json',
                            'Content-Type':'application/json','Accept-Encoding':'identity','Connection':'close','Cache-Control':'no-cache,no-store'})
                        raw=source._receive(connection,handle,deadline,16384)
                        receipt=GlassBreakReceipt(source._binding.source_digest,parameters_digest,deactivate,_ack_candidate(raw,source,deactivate))
                        self._available(); adapter._check(); source._remaining(deadline)
                    finally:
                        _zeroize_mutable(raw)
                        if connection is not None: connection.close()
                        self._available(); source._remaining(deadline)
                self._acks[deactivate]=receipt; return receipt
        except Exception: raise GlassBreakHttpError(_ERROR) from None
        finally: _zeroize_mutable(raw); _zeroize_mutable(expected)

    def close(self) -> None:
        with self._lock: self._closed=True
