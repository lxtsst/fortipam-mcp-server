"""Fixed eight-object PUT candidate, bound to the original active M4 adapter.

Native ACK and partial-update semantics remain unqualified. Independent M4
evidence and explicit guards are mandatory; there is no real producer, startup
binding or public writer. A TLS/ACK/readback/cleanup failure is never retried.
"""
from __future__ import annotations

from collections.abc import Callable
import hmac
from threading import RLock

from v4_planning import canonical_digest
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from . import secret_bulk_import_metadata as metadata
from .email_alert_compound_contract import EmailAlertCompoundPlan,Step,STEPS,_identity
from .email_alert_compound_source import EmailAlertCompoundSource,DETAILS
from .email_alert_general_contract import _encoded
from .email_alert_general_source import _read_alert_response
from .email_alert_m4 import EmailAlertM4Adapter,EmailAlertM4Session,EmailAlertReceipt
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end,_skip_json_space,_zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam-build29-email-alert-fixed-http-local/v1'
_ERROR = 'The private email-alert HTTP candidate is unavailable.'
_REQUIRED = {'http_method','http_status','status','path','name','serial','version','build'}
_OPTIONAL = {'vdom','mkey','error','revision','revision_changed','results'}
_ROUTES = {'general':('/api/v2/cmdb/alertemail/setting?vdom=root','alertemail','setting',''),
    **{('certificate' if kind == 'settings' else str(slot)+'_'+kind):
        (detail.replace('?with_meta=true&vdom=root','?vdom=root'),*_identity(kind,slot))
        for kind,slot,detail in DETAILS if kind != 'trigger'}}


class EmailAlertHttpError(RuntimeError):
    """Categorical refusal without private mail identities, wire body or ACK."""


def _route(step: Step) -> tuple[str,str,str,str]:
    return _ROUTES[step]


def _ack(raw: bytearray, source: EmailAlertCompoundSource, step: Step) -> str:
    left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
    if _skip_json_space(raw,right) != len(raw): raise ValueError
    metadata._validate_json(raw,left,right,depth=0,budget=[512]); fields = _object_spans(raw,left,right)
    if not _REQUIRED <= fields.keys() <= _REQUIRED | _OPTIONAL: raise ValueError
    _,path,table,name = _route(step)
    expected = dict(http_method='PUT',http_status=200,status='OK',path=path,name=table,
        serial=source._general._serial,version='v7.0.0',build=29)
    for key,value in expected.items():
        with memoryview(raw)[slice(*fields[key])] as actual:
            if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
    minimized: dict[str,object] = dict(contract=CONTRACT,**expected)
    for key,value in dict(vdom='root',mkey=name,error=0,revision_changed=True).items():
        if key not in fields: continue
        with memoryview(raw)[slice(*fields[key])] as actual:
            if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
        if key == 'mkey' and value == '': minimized['singleton_mkey_empty'] = True
        else: minimized[key] = value
    if 'revision' in fields:
        start,end = fields['revision']
        if raw[start] != 34 or not 2 <= end-start <= 514: raise ValueError
    if 'results' in fields:
        with memoryview(raw)[slice(*fields['results'])] as actual:
            if not any(hmac.compare_digest(actual,empty) for empty in (b'null',b'{}',b'[]')): raise ValueError
    return canonical_digest(minimized)


class EmailAlertHttpBackend(_OpaqueC3Object):
    def __init__(self, source: EmailAlertCompoundSource, initial: EmailAlertCompoundPlan, *,
            execution_enabled: Callable[[],bool] | None = None, source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(source) is not EmailAlertCompoundSource or type(initial) is not EmailAlertCompoundPlan
                    or source._plan is not initial or source._origin is None or source._origin is not source._latest
                    or source._origin.state is not initial.baseline
                    or any(value is not None and not callable(value) for value in (execution_enabled,source_guard))): raise ValueError
            source._available(); initial.__post_init__()
            if not source._origin.observed_at <= source._general._epoch() < source._origin.expires_at: raise ValueError
            self._source,self._initial,self._origin,self._config = source,initial,source._origin,source._general._config
            self._enabled = self._enabled_pin = execution_enabled; self._guard = self._guard_pin = source_guard
            self._binding_pin = (source._source,initial.digest)
            self._attempted: set[tuple[Step,bool]] = set(); self._acks: dict[tuple[Step,bool],EmailAlertReceipt] = {}
            self._lock = RLock(); self._closed = False
        except Exception: raise EmailAlertHttpError(_ERROR) from None

    def _available(self) -> None:
        self._source._available()
        if (self._closed or self._source._general._config is not self._config or self._source._plan is not self._initial
                or self._source._origin is not self._origin or (self._source._source,self._initial.digest) != self._binding_pin
                or self._enabled is None or self._enabled is not self._enabled_pin or self._enabled() is not True
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True): raise ValueError

    def _owned_adapter(self, step: Step, restore: bool, parameters: str, callback: Callable[[],int]) -> EmailAlertM4Adapter:
        session = self._source._m4_session
        if (type(session) is not EmailAlertM4Session or session._backend is not self or session._initial is not self._initial
                or type(session._pending) is not EmailAlertM4Adapter): raise ValueError
        adapter: EmailAlertM4Adapter = session._pending
        owner: object = getattr(callback,'__self__',None)
        function: object = getattr(callback,'__func__',None)
        if (adapter._session is not session or (adapter._step.name,adapter._step.restore,adapter._step.parameters_digest) != (step,restore,parameters)
                or owner is not adapter or function is not EmailAlertM4Adapter._before_send): raise ValueError
        _require_m4_dispatch_ownership(adapter._plan,adapter._authorization,session._store); adapter._check()
        if restore and self._acks.get((step,False)) is not session._adapters[(step,False)]._receipt: raise ValueError
        return adapter

    def submit(self, body: memoryview, *, step: Step, restore: bool, parameters_digest: str,
            before_send: Callable[[],int], timeout_seconds: int) -> EmailAlertReceipt:
        connection = response = None; raw = bytearray(); expected = bytearray()
        try:
            with self._lock, _private_http_logs():
                self._available(); require_digest(parameters_digest,'email-alert parameters')
                if (step not in STEPS or type(restore) is not bool or (step,restore) in self._attempted or not callable(before_send)
                        or type(timeout_seconds) is not int or not 0 < timeout_seconds <= 60 or not isinstance(body,memoryview)
                        or not body.readonly or body.ndim != 1 or body.format != 'B' or not body.c_contiguous): raise ValueError
                adapter = self._owned_adapter(step,restore,parameters_digest,before_send)
                general = self._source._general; deadline = general._now()+min(timeout_seconds,self._config.timeout_seconds)
                index = STEPS.index(step)+(1 if restore else 0)
                expected = self._initial.compile(step,self._initial.expected(index),restore=restore)
                if not hmac.compare_digest(body,expected): raise ValueError
                general._remaining(deadline)
                self._attempted.add((step,restore))
                with self._source._bounded_by(deadline):
                    try:
                        connection = general._factory(general._host,general._port,context=general._tls,timeout=general._remaining(deadline))
                        connection.set_debuglevel(0); connection.connect(); self._available()
                        self._owned_adapter(step,restore,parameters_digest,before_send); general._remaining(deadline)
                        budget = before_send()
                        if type(budget) is not int or not 0 < budget <= 60: raise ValueError
                        deadline = min(deadline,general._now()+budget); self._available()
                        self._owned_adapter(step,restore,parameters_digest,before_send)
                        handle = connection.sock; handle.settimeout(general._remaining(deadline))
                        connection.request('PUT',_route(step)[0],body=body,headers={'Authorization':'Bearer '+self._config.bearer_token,
                            'Accept':'application/json','Content-Type':'application/json','Accept-Encoding':'identity',
                            'Connection':'close','Cache-Control':'no-cache,no-store'})
                        handle.settimeout(general._remaining(deadline)); response = connection.getresponse()
                        raw = _read_alert_response(general,response,handle,deadline,16384)
                        receipt = EmailAlertReceipt(self._source._source,parameters_digest,step,restore,_ack(raw,self._source,step))
                        self._available(); adapter._check(); general._remaining(deadline)
                    finally:
                        _zeroize_mutable(raw)
                        failed = False
                        for resource in (response,connection):
                            if resource is not None:
                                try: resource.close()
                                except Exception: failed = True
                        if failed: raise ValueError
                        self._available(); general._remaining(deadline)
                self._acks[(step,restore)] = receipt; return receipt
        except Exception: raise EmailAlertHttpError(_ERROR) from None
        finally: _zeroize_mutable(raw); _zeroize_mutable(expected)

    def close(self) -> None:
        with self._lock: self._closed = True
