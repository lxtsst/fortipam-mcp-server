"""Fixed POST/owned DELETE candidate, without native ACK qualification.

Only an original source-issued absence snapshot and its exact inert-fixture
body are accepted. Gates default closed; normal startup never binds this.
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
from .local_user_reset_projection import _object_spans
from .saml_server_contract import build_saml_create_body
from .saml_server_local_m4 import SamlBackendReceipt, SamlLocalM4Adapter
from .saml_server_native_source import BASE_PATH, SamlNativeObservation, SamlNativeSource
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

_ERROR = 'The private SAML HTTP candidate is unavailable.'


def _candidate_ack(raw: bytearray, serial: str, name: str, restore: bool) -> None:
    left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
    if _skip_json_space(raw,right) != len(raw): raise ValueError
    metadata._validate_json(raw,left,right,depth=0,budget=[256]); fields = _object_spans(raw,left,right)
    required = {'http_method','http_status','status','serial','version','build','path','name','mkey'}
    if not required <= set(fields) <= required | {'vdom','revision','revision_changed','error'}: raise ValueError
    for key,expected in dict(http_method='DELETE' if restore else 'POST',http_status=200,serial=serial,
            version='v7.0.0',build=29,path='user',name='saml',mkey=name).items():
        value = metadata._scalar(raw,fields[key])
        if type(value) is not type(expected) or value != expected: raise ValueError
    if metadata._scalar(raw,fields['status']) not in ('success','OK'): raise ValueError
    for option,required_value in dict(vdom='root',revision_changed=True,error=0).items():
        if option in fields:
            attribute = metadata._scalar(raw,fields[option])
            if type(attribute) is not type(required_value) or attribute != required_value: raise ValueError
    if 'revision' in fields:
        revision = metadata._scalar(raw,fields['revision'])
        if type(revision) is not str or not 1 <= len(revision) <= 256 or any(ord(c)<32 or ord(c)==127 for c in revision): raise ValueError


class SamlConfigurationHttpBackend(_OpaqueC3Object):
    def __init__(self, source: SamlNativeSource, initial: SamlNativeObservation, parameters_digest: str, *,
            execution_enabled: bool = False, source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(source) is not SamlNativeSource or type(initial) is not SamlNativeObservation
                    or source._latest is not initial or initial._candidate is not None
                    or initial.plan.binding is not source._binding or type(execution_enabled) is not bool
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            require_digest(parameters_digest,'SAML HTTP parameters'); source._available()
            self._source,self._initial,self._parameters = source,initial,parameters_digest
            self._detail = BASE_PATH+'/'+quote(initial.plan.binding.name,safe='')
            self._enabled,self._guard = execution_enabled,source_guard
            self._attempted: set[bool] = set(); self._acks: set[bool] = set()
            self._closed = False; self._lock = RLock()
        except Exception: raise ValueError(_ERROR) from None

    def _available(self, *, write: bool = False) -> None:
        self._source._available()
        if self._closed or write and (not self._enabled or self._guard is None or self._guard() is not True): raise ValueError

    def inspect(self) -> SamlNativeObservation:
        try:
            with self._lock:
                self._available()
                return self._source.read()
        except Exception: raise ValueError(_ERROR) from None

    def _body(self, body: memoryview | None, restore: bool) -> bytearray:
        expected = bytearray()
        try:
            if restore:
                if body is not None: raise ValueError
                return bytearray()
            if (type(body) is not memoryview or body.format != 'B' or body.ndim != 1 or not body.c_contiguous
                    or not body.readonly or not 0 < body.nbytes <= 32768): raise ValueError
            plan = self._initial.plan
            expected = build_saml_create_body(plan,plan._source,plan._defaults,**plan._context)
            if not hmac.compare_digest(body,expected): raise ValueError
            return bytearray(expected)
        finally: _zeroize_mutable(expected)

    def _dispatch_guard(self, before_send: Callable[[],int], restore: bool) -> None:
        # The I/O boundary accepts the original bound M4 guard, never a
        # caller-supplied success callback or a copied adapter's guard.
        if (not isinstance(before_send,MethodType) or before_send.__func__ is not SamlLocalM4Adapter._before_send
                or type(before_send.__self__) is not SamlLocalM4Adapter): raise ValueError
        adapter = before_send.__self__
        if (adapter._backend is not self or adapter._plan.parameters_digest != self._parameters
                or (adapter._original is not None) is not restore): raise ValueError

    def submit(self, body: memoryview | None, *, parameters_digest: str, restore: bool,
            before_send: Callable[[],int], timeout_seconds: int) -> SamlBackendReceipt:
        owned = bytearray()
        try:
            with self._lock, _private_http_logs():
                self._available(write=True)
                if (parameters_digest != self._parameters or type(restore) is not bool or restore in self._attempted
                        or restore and False not in self._acks or type(timeout_seconds) is not int or timeout_seconds <= 0): raise ValueError
                self._dispatch_guard(before_send,restore)
                owned = self._body(body,restore)
                self._attempted.add(restore)
                self._exchange(owned,restore,before_send,timeout_seconds)
                self._acks.add(restore)
                return SamlBackendReceipt(self._source._source,self._parameters,restore)
        except Exception: raise ValueError(_ERROR) from None
        finally: _zeroize_mutable(owned)

    def _exchange(self, owned: bytearray, restore: bool, before_send: Callable[[],int], timeout_seconds: int) -> None:
        connection = None; raw = bytearray()
        try:
            source = self._source
            deadline = source._now()+min(timeout_seconds,source._config.timeout_seconds)
            connection = source._factory(source._host,source._port,context=source._tls,timeout=source._remaining(deadline))
            connection.set_debuglevel(0); connection.connect(); self._available(write=True)
            with source._bounded_by(deadline): budget = before_send()
            if type(budget) is not int or budget <= 0: raise ValueError
            deadline = min(deadline,source._now()+budget)
            self._available(write=True); connection.sock.settimeout(source._remaining(deadline))
            connection.request('DELETE' if restore else 'POST',self._detail if restore else BASE_PATH,
                body=None if restore else owned,headers={'Authorization':'Bearer '+source._config.bearer_token,
                    'Accept':'application/json','Content-Type':'application/json','Accept-Encoding':'identity',
                    'Cache-Control':'no-cache,no-store','Connection':'close'})
            _zeroize_mutable(owned)
            _,raw = source._receive(connection,deadline,16384)
            _candidate_ack(raw,source._serial,self._initial.plan.binding.name,restore)
        finally:
            _zeroize_mutable(owned); _zeroize_mutable(raw)
            if connection is not None: connection.close()
        self._available(write=True); self._source._remaining(deadline)

    def close(self) -> None:
        with self._lock: self._closed = True
