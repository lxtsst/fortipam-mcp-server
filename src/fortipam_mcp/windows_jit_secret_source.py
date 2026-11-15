"""Fixed seven-read local JIT draft: Script pair plus complete supplied metadata.

No credential retrieval, configuration write, ownership or effect authority is
provided. The type-tree pin is a minimized projection, not native qualification.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hmac
from typing import Any

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as metadata
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .windows_jit_script_source import WindowsJitScriptObservation, WindowsJitScriptSource
from .windows_jit_secret_contract import (WindowsJitSecretBinding, WindowsJitSecretState, WindowsJitSecretPlan,
    _schema, _types, _encoded, project_windows_jit_secret)

CONTRACT = 'fortipam-build29-windows-jit-secret-fixed-source-local/v1'
SCHEMA_PATH = '/api/v2/cmdb/secret/database?action=schema&vdom=root'
_ERROR = 'The private Windows JIT Secret source is unavailable.'


@dataclass(frozen=True, slots=True, repr=False)
class WindowsJitSecretObservation(_OpaqueC3Object):
    source_digest: str
    scripts: WindowsJitScriptObservation
    secret: WindowsJitSecretState
    observed_at: int
    expires_at: int


class WindowsJitSecretSource(_OpaqueC3Object):
    def __init__(self, scripts: WindowsJitScriptSource, binding: WindowsJitSecretBinding, *,
            expected_schema_digest: str, source_digest: str, source_guard: Callable[[],bool] | None = None) -> None:
        if (type(scripts) is not WindowsJitScriptSource or type(binding) is not WindowsJitSecretBinding
                or scripts._nonce != binding.nonce or source_guard is not None and not callable(source_guard)): raise ValueError(_ERROR)
        for value in (expected_schema_digest,source_digest): require_digest(value,'Windows JIT Secret source')
        if source_digest == scripts._source: raise ValueError(_ERROR)
        self._scripts,self._binding = scripts,binding
        self._schema_pin,self._source,self._guard,self._guard_pin = expected_schema_digest,source_digest,source_guard,source_guard
        self._detail = '/api/v2/cmdb/secret/database/'+str(binding.secret_id)+'?with_meta=true&vdom=root'
        self._pins = (binding,expected_schema_digest,source_digest,self._detail)
        self._closed = False
        self._latest: WindowsJitSecretObservation | None = None
        self._plan: WindowsJitSecretPlan | None = None
        self._plan_origin: WindowsJitSecretObservation | None = None

    def _available(self) -> None:
        self._scripts._available()
        if (self._closed or self._scripts._nonce != self._binding.nonce or self._guard is None
                or self._guard is not self._guard_pin or self._guard() is not True
                or (self._binding,self._schema_pin,self._source,self._detail) != self._pins): raise ValueError

    def _fetch(self, path: str, deadline: float) -> bytearray:
        connection = None; raw = bytearray(); transferred = False
        try:
            source = self._scripts; self._available()
            if path not in (SCHEMA_PATH,self._detail): raise ValueError
            connection = source._factory(source._host,source._port,context=source._tls,timeout=source._remaining(deadline))
            connection.set_debuglevel(0); connection.connect(); self._available()
            connection.sock.settimeout(source._remaining(deadline))
            connection.request('GET',path,headers={'Authorization':'Bearer '+source._config.bearer_token,'Accept':'application/json',
                'Accept-Encoding':'identity','Cache-Control':'no-cache,no-store','Connection':'close'})
            _,raw = source._receive(connection,deadline,2097152); transferred = True; return raw
        finally:
            failed = False
            if connection is not None:
                try: connection.close()
                except Exception: failed = True
            if failed or not transferred: _zeroize_mutable(raw)
            if failed: raise ValueError

    def _schema(self, raw: bytearray) -> dict[str,Any]:
        left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
        if _skip_json_space(raw,right) != len(raw): raise ValueError
        metadata._validate_json(raw,left,right,depth=0,budget=[50000]); root = _object_spans(raw,left,right)
        if not root.keys() <= {'build','http_method','http_status','name','path','status','version','vdom','serial','results','action','revision','error'}:
            raise ValueError
        expected: dict[str,Any] = dict(build=29,http_method='GET',http_status=200,name='database',path='secret',status='success',
            version='v7.0.0',serial=self._scripts._serial,action='schema')
        for name,value in expected.items():
            with memoryview(raw)[slice(*root[name])] as actual:
                if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
        if 'vdom' in root and metadata._scalar(raw,root['vdom']) != 'root': raise ValueError
        if 'error' in root:
            error = metadata._scalar(raw,root['error'])
            if type(error) is not int or error != 0: raise ValueError
        def fields(span: tuple[int,int], depth: int = 0) -> dict[str,Any]:
            if depth>16: raise ValueError
            result = {}
            for name,descriptor_span in _object_spans(raw,*span).items():
                descriptor = _object_spans(raw,*descriptor_span); item: dict[str,Any] = {}
                if 'type' in descriptor:
                    kind = metadata._scalar(raw,descriptor['type'])
                    if type(kind) is not str or not 1 <= len(kind) <= 64: raise ValueError
                    item['type'] = kind
                if 'children' in descriptor: item['children'] = fields(descriptor['children'],depth+1)
                result[name] = item
            return result
        expected['results'] = {'children':fields(_object_spans(raw,*root['results'])['children'])}
        if canonical_digest(_types(_schema(expected,self._scripts._serial))) != self._schema_pin: raise ValueError
        return expected

    def read(self) -> WindowsJitSecretObservation:
        buffers: list[bytearray] = []
        try:
            with self._scripts._lock, _private_http_logs():
                source = self._scripts; self._available(); started = source._epoch(); deadline = source._now()+source._config.timeout_seconds
                with source._bounded_by(deadline):
                    scripts = source.read()
                    if scripts.present != (True,True): raise ValueError
                    raw = self._fetch(SCHEMA_PATH,deadline); buffers.append(raw); schema = self._schema(raw)
                    raw = self._fetch(self._detail,deadline); buffers.append(raw)
                    secret = project_windows_jit_secret(raw,schema,self._binding,expected_serial=source._serial)
                    observed = WindowsJitSecretObservation(self._source,scripts,secret,started,min(started+10,scripts.expires_at))
                    for buffer in buffers: _zeroize_mutable(buffer)
                    self._available(); source._remaining(deadline)
                    if source._latest is not scripts or not observed.observed_at <= source._epoch() < observed.expires_at: raise ValueError
                    self._latest = observed; return observed
        except Exception: raise ValueError(_ERROR) from None
        finally:
            for buffer in buffers: _zeroize_mutable(buffer)

    def prepare_plan(self) -> WindowsJitSecretPlan:
        try:
            with self._scripts._lock:
                observed = self.read(); self._plan = WindowsJitSecretPlan(observed.secret); self._plan_origin = observed
                return self._plan
        except Exception: raise ValueError(_ERROR) from None

    def compile_fragment(self, plan: WindowsJitSecretPlan) -> dict[str,object]:
        """Fresh metadata-only forward draft; no inverse ownership or wire body."""
        try:
            with self._scripts._lock:
                self._available(); origin = self._plan_origin
                if plan is not self._plan or origin is None or not origin.observed_at <= self._scripts._epoch() < origin.expires_at: raise ValueError
                deadline = self._scripts._now()+self._scripts._config.timeout_seconds
                with self._scripts._bounded_by(deadline):
                    observed = self.read()
                    if observed.scripts.state_digest != origin.scripts.state_digest or self._scripts._epoch() >= origin.expires_at: raise ValueError
                    fragment = plan.compile_metadata_patch(observed.secret)
                    self._available(); self._scripts._remaining(deadline)
                    if self._scripts._epoch() >= origin.expires_at: raise ValueError
                    return fragment
        except Exception: raise ValueError(_ERROR) from None

    def preview(self) -> dict[str,object]:
        try:
            with self._scripts._lock:
                plan = self.prepare_plan(); origin = self._plan_origin
                if origin is None: raise ValueError
                public = plan.preview(); public.update(read_source_contract=CONTRACT,observed_at=origin.observed_at,
                    expires_at=origin.expires_at,script_definitions_read_locally=True,nonmaterial_configuration_observed_locally=True)
                self._available()
                if self._scripts._epoch() >= origin.expires_at: raise ValueError
                return public
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._scripts._lock: self._closed = True
