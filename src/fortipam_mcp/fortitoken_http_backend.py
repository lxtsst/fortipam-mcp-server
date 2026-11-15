"""Fixed existing-User PUT candidate; native ACK/MFA remain unqualified.

Only a source-admitted plan, its private codec body and the original bound M4
dispatch guard reach I/O. Durable consumption belongs to the execution and
material ledgers; a local ACK alone never supplies restore or replay rights.
"""
from __future__ import annotations

from collections.abc import Callable
import hmac
from threading import RLock
from types import MethodType
from urllib.parse import quote

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as metadata
from .fortitoken_local_m4 import FortitokenBackendReceipt, FortitokenLocalM4Adapter
from .fortitoken_user_contract import FortitokenUserPlan, _encode_fortitoken_user_update
from .fortitoken_user_source import FortitokenUserSource
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

_ERROR = 'The private FortiToken HTTP candidate is unavailable.'


def _candidate_ack(raw: bytearray, serial: str, username: str) -> None:
    left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
    if _skip_json_space(raw,right) != len(raw): raise ValueError
    metadata._validate_json(raw,left,right,depth=0,budget=[256]); fields = _object_spans(raw,left,right)
    required = {'http_method','http_status','status','serial','version','build','path','name','mkey'}
    if not required <= set(fields) <= required | {'vdom','revision','revision_changed','error'}: raise ValueError
    for name,expected in dict(http_method='PUT',http_status=200,serial=serial,version='v7.0.0',build=29,
            path='system',name='admin',mkey=username).items():
        value = metadata._scalar(raw,fields[name])
        if type(value) is not type(expected) or value != expected: raise ValueError
    if metadata._scalar(raw,fields['status']) not in ('success','OK'): raise ValueError
    for name,expected in dict(vdom='root',revision_changed=True,error=0).items():
        if name in fields:
            value = metadata._scalar(raw,fields[name])
            if type(value) is not type(expected) or value != expected: raise ValueError
    if 'revision' in fields:
        value = metadata._scalar(raw,fields['revision'])
        if type(value) is not str or not 1 <= len(value) <= 256 or any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError


class FortitokenConfigurationHttpBackend(_OpaqueC3Object):
    def __init__(self, source: FortitokenUserSource, intent: FortitokenUserPlan, parameters_digest: str, *,
            execution_enabled: bool = False, source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(source) is not FortitokenUserSource or type(intent) is not FortitokenUserPlan
                    or type(execution_enabled) is not bool or source_guard is not None and not callable(source_guard)):
                raise ValueError
            require_digest(parameters_digest,'FortiToken HTTP parameters'); source.bind_plan(intent)
            self._source,self._intent,self._parameters = source,intent,parameters_digest
            self._detail = '/api/v2/cmdb/system/admin/'+quote(intent.current.binding.username,safe='')
            self._enabled,self._guard = execution_enabled,source_guard
            self._attempted: set[bool] = set(); self._acks: set[bool] = set()
            self._closed = False; self._lock = RLock()
        except Exception: raise ValueError(_ERROR) from None

    def _available(self) -> None:
        self._source._available()
        if self._closed or not self._enabled or self._guard is None or self._guard() is not True: raise ValueError

    def _dispatch_guard(self, before_send: Callable[[],int], restore: bool) -> FortitokenUserPlan:
        if (not isinstance(before_send,MethodType) or before_send.__func__ is not FortitokenLocalM4Adapter._before_send
                or type(before_send.__self__) is not FortitokenLocalM4Adapter): raise ValueError
        adapter = before_send.__self__
        base = adapter._original if restore else adapter
        if (adapter._backend is not self or adapter._source is not self._source
                or adapter._plan.parameters_digest != self._parameters
                or (adapter._original is not None) is not restore or base is None
                or base._intent is not self._intent or base._backend is not self
                or self._source._compiled_plan is not adapter._intent): raise ValueError
        return adapter._intent

    def _body(self, body: memoryview, intent: FortitokenUserPlan) -> bytearray:
        raw = bytearray(); expected = bytearray(); transferred = False
        try:
            if (type(body) is not memoryview or body.format != 'B' or body.ndim != 1 or not body.c_contiguous
                    or not body.readonly or not 0 < body.nbytes <= 1048576): raise ValueError
            raw = bytearray(body)
            marker = b',"fortitoken":"'; position = raw.rfind(marker)
            if position < 0 or raw[-2:] != b'"}': raise ValueError
            # Only the bounded ASCII selector view enters the private encoder.
            # No selector string, hash or decoded request object is produced.
            # The codec appends this member last. Full canonical comparison
            # below also rejects duplicate members, escapes and trailing data.
            with memoryview(raw)[position+len(marker):-2] as token:
                expected = _encode_fortitoken_user_update(intent,token)
            if not hmac.compare_digest(raw,expected): raise ValueError
            transferred = True
            return raw
        finally:
            _zeroize_mutable(expected)
            if not transferred: _zeroize_mutable(raw)

    def submit(self, body: memoryview, *, parameters_digest: str, restore: bool,
            before_send: Callable[[],int], timeout_seconds: int) -> FortitokenBackendReceipt:
        owned = bytearray()
        try:
            with self._lock, _private_http_logs():
                self._available()
                if (parameters_digest != self._parameters or type(restore) is not bool or restore in self._attempted
                        or restore and False not in self._acks or type(timeout_seconds) is not int or timeout_seconds <= 0):
                    raise ValueError
                intent = self._dispatch_guard(before_send,restore); owned = self._body(body,intent)
                self._attempted.add(restore)
                self._exchange(owned,before_send,timeout_seconds)
                self._acks.add(restore)
                return FortitokenBackendReceipt(self._source._source,self._parameters,restore)
        except Exception: raise ValueError(_ERROR) from None
        finally: _zeroize_mutable(owned)

    def _exchange(self, owned: bytearray, before_send: Callable[[],int], timeout_seconds: int) -> None:
        connection = None; raw = bytearray()
        try:
            source = self._source
            deadline = source._now()+min(timeout_seconds,source._config.timeout_seconds)
            connection = source._factory(source._host,source._port,context=source._tls,timeout=source._remaining(deadline))
            connection.set_debuglevel(0); connection.connect(); self._available()
            with source._bounded_by(deadline): budget = before_send()
            if type(budget) is not int or budget <= 0: raise ValueError
            deadline = min(deadline,source._now()+budget)
            self._available(); connection.sock.settimeout(source._remaining(deadline))
            connection.request('PUT',self._detail,body=owned,headers={'Authorization':'Bearer '+source._config.bearer_token,
                'Accept':'application/json','Content-Type':'application/json','Accept-Encoding':'identity',
                'Cache-Control':'no-cache,no-store','Connection':'close'})
            _zeroize_mutable(owned)
            raw = source._receive(connection,deadline,16384)
            _candidate_ack(raw,source._serial,self._intent.current.binding.username)
        finally:
            _zeroize_mutable(owned); _zeroize_mutable(raw)
            if connection is not None: connection.close()
        self._available(); self._source._remaining(deadline)

    def close(self) -> None:
        with self._lock: self._closed = True
