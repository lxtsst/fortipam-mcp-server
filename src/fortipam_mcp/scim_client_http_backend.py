"""Fixed singleton PUT candidate; no native ACK or credential qualification.

Only the source-bound proposed/original state and one pinned parameter domain
are accepted. Bodies and ACKs stay private, with no password hash in receipts.
M4 owns durable consumption; the local attempt set never supplies replay rights.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
from threading import RLock

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as metadata
from .local_user_reset_projection import _object_spans
from .scim_client_contract import NATIVE_NAME, NONMATERIAL_FIELDS, ScimClientTransition
from .scim_client_m4_adapter import ScimBackendReceipt, ScimConfigurationReadback
from .scim_client_native_source import ScimNativeSource, DETAIL_PATH
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

_ERROR = 'The private SCIM HTTP candidate is unavailable.'


def _candidate_ack(raw: bytearray, serial: str) -> None:
    left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
    if _skip_json_space(raw,right) != len(raw): raise ValueError
    metadata._validate_json(raw,left,right,depth=0,budget=[256]); fields = _object_spans(raw,left,right)
    required = {'http_method','http_status','status','serial','version','build','path','name','mkey'}
    if not required <= set(fields) <= required | {'vdom','revision','revision_changed','error'}: raise ValueError
    for name, expected in dict(http_method='PUT',http_status=200,serial=serial,version='v7.0.0',build=29,
            path='user',name='scim',mkey=NATIVE_NAME).items():
        value = metadata._scalar(raw,fields[name])
        if type(value) is not type(expected) or value != expected: raise ValueError
    if metadata._scalar(raw,fields['status']) not in ('success','OK'): raise ValueError
    for name, expected in dict(vdom='root',revision_changed=True,error=0).items():
        if name in fields:
            value = metadata._scalar(raw,fields[name])
            if type(value) is not type(expected) or value != expected: raise ValueError
    if 'revision' in fields:
        value = metadata._scalar(raw,fields['revision'])
        if type(value) is not str or not 1 <= len(value) <= 256 or any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError


class ScimConfigurationHttpBackend(_OpaqueC3Object):
    def __init__(self, source: ScimNativeSource, transition: ScimClientTransition, parameters_digest: str, *,
            execution_enabled: bool = False, source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(source) is not ScimNativeSource or type(transition) is not ScimClientTransition
                    or transition.operation == 'create' or type(execution_enabled) is not bool
                    or source_guard is not None and not callable(source_guard)
                    or source._latest is None or transition._original is not source._latest.state
                    or transition._context != source._latest.context
                    or json.loads(transition._context)['serial_digest'] != hashlib.sha256(source._serial.encode()).hexdigest()): raise ValueError
            require_digest(parameters_digest, 'SCIM HTTP parameters'); source._available()
            self._source, self._transition, self._parameters = source, transition, parameters_digest
            self._enabled, self._guard = execution_enabled, source_guard
            self._attempted: set[bool] = set(); self._acks: set[bool] = set()
            self._closed = False; self._lock = RLock()
        except Exception: raise ValueError(_ERROR) from None

    def _available(self, *, write: bool = False) -> None:
        self._source._available()
        if self._closed or write and (not self._enabled or self._guard is None or self._guard() is not True): raise ValueError

    def inspect(self) -> ScimConfigurationReadback:
        try:
            with self._lock:
                self._available()
                return self._source.read()
        except Exception: raise ValueError(_ERROR) from None

    def _body(self, body: memoryview, restore: bool) -> None:
        if (type(body) is not memoryview or body.format != 'B' or body.ndim != 1 or not body.c_contiguous
                or not 0 < body.nbytes <= 4096): raise ValueError
        # The provider/compiler validated material. Validate only its opaque
        # bounded JSON string and exact nonmaterial fields at this boundary.
        raw = bytearray(body)
        try:
            left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
            if _skip_json_space(raw,right) != len(raw): raise ValueError
            metadata._validate_json(raw,left,right,depth=0,budget=[128]); fields = _object_spans(raw,left,right)
            if set(fields) != NONMATERIAL_FIELDS-{'token-certificate'} | {'secret'}: raise ValueError
            start,end = fields['secret']
            if raw[start] != 34 or raw[end-1] != 34 or not 2 < end-start <= 356: raise ValueError
            expected = (self._transition._original if restore else self._transition._proposed)._values()
            for name in sorted(NONMATERIAL_FIELDS-{'token-certificate'}):
                value = metadata._scalar(raw,fields[name])
                if type(value) is not type(expected[name]) or value != expected[name]: raise ValueError
        finally: _zeroize_mutable(raw)

    def submit(self, body: memoryview, *, parameters_digest: str, restore: bool,
            before_send: Callable[[],int], timeout_seconds: int) -> ScimBackendReceipt:
        try:
            with self._lock, _private_http_logs():
                self._available(write=True)
                if (parameters_digest != self._parameters or type(restore) is not bool or restore in self._attempted
                        or restore and False not in self._acks or not callable(before_send)
                        or type(timeout_seconds) is not int or timeout_seconds <= 0): raise ValueError
                self._body(body,restore)
                self._attempted.add(restore)
                self._exchange(body,before_send,timeout_seconds)
                self._acks.add(restore)
                return ScimBackendReceipt(self._source._source,self._parameters,restore)
        except Exception: raise ValueError(_ERROR) from None

    def _exchange(self, body: memoryview, before_send: Callable[[],int], timeout_seconds: int) -> None:
        connection = None; raw = bytearray(); owned_body = bytearray()
        try:
            deadline = self._source._now()+min(timeout_seconds,self._source._config.timeout_seconds)
            connection = self._source._factory(self._source._host,self._source._port,context=self._source._context,
                timeout=self._source._remaining(deadline))
            connection.set_debuglevel(0); connection.connect()
            self._available(write=True)
            with self._source._bounded_by(deadline): budget = before_send()
            if type(budget) is not int or budget <= 0: raise ValueError
            deadline = min(deadline,self._source._now()+budget)
            self._available(write=True)
            connection.sock.settimeout(self._source._remaining(deadline))
            owned_body = bytearray(body)
            connection.request('PUT',DETAIL_PATH,body=owned_body,headers={'Authorization':'Bearer '+self._source._config.bearer_token,
                'Accept':'application/json','Content-Type':'application/json','Accept-Encoding':'identity',
                'Cache-Control':'no-cache,no-store','Connection':'close'})
            _zeroize_mutable(owned_body)
            raw = self._source._receive(connection,deadline,16384)
            _candidate_ack(raw,self._source._serial)
        finally:
            _zeroize_mutable(owned_body); _zeroize_mutable(raw)
            if connection is not None: connection.close()
        self._available(write=True); self._source._remaining(deadline)

    def close(self) -> None:
        with self._lock: self._closed = True
