"""Default-closed original-ACK Windows Secret removal through independent M4.

No Tool registration, retry, force or delegation is provided.
The fixed reader must establish complete state and original material before
the single bodyless DELETE. Existing creation outcomes are never rewritten.
"""
from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import http.client
import json
import math
import os
from pathlib import Path
import ssl
import stat
from threading import RLock
import time
from typing import Any
import httpx
from v4_planning import DenyAllM4AuthorizationVerifier, M4AuthorizationVerifier, M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, canonical_digest
from v4_planning.execution_kernel import M4AdapterAmbiguous, M4AdapterDenied, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from . import secret_bulk_import_metadata as parser
from .ldap_server_runtime import _key, _read
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _ssl_context, _zeroize_mutable
from .windows_execution_secret_ack import WindowsExecutionSecretAckCustody
from .windows_execution_secret_preservation import WindowsExecutionSecretPreservationReader
ACTION_ID = 'windows-execution-secret-remove'
ADAPTER_REF = 'fortipam-700-build29-windows-execution-secret-remove-v1'
TARGET_REF = 'bound-owned-windows-execution-secret'
_ERROR = 'The private Windows execution Secret recovery is unavailable.'
_SEND, _ACK = ('recovery.delete.attempt.json', 'recovery.delete.ack.json')
_DOMAIN = b'windows-execution-secret-remove/v1\x00'

class WindowsExecutionSecretRecoveryError(RuntimeError):
    """Categorical refusal; original effects and consumed records are retained."""

@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionSecretRecoveryPreview(_OpaqueC3Object):
    parameters_digest: str
    current_digest: str
    expected_digest: str
    requester_digest: str
    expires_at: int

class WindowsExecutionSecretRecovery(_OpaqueC3Object):

    def __init__(self, custody: WindowsExecutionSecretAckCustody, *, execution_store: PersistentM4ExecutionStateStore, witness_key_file: Path, authorization_verifier: M4AuthorizationVerifier | None=None, execution_enabled: bool=False, client_factory: Callable[..., httpx.Client]=httpx.Client, connection_factory: Callable[..., Any]=http.client.HTTPSConnection, clock: Callable[[], int]=lambda: int(time.time()), http_clock: Callable[[], float]=time.monotonic) -> None:
        try:
            if type(custody) is not WindowsExecutionSecretAckCustody or type(execution_store) is not PersistentM4ExecutionStateStore or (not execution_store.monotonic_checkpoint_protocol_bound) or (type(execution_enabled) is not bool) or (not all((callable(item) for item in (client_factory, connection_factory, clock, http_clock)))):
                raise ValueError
            self._custody, self._store, self._key_file = (custody, execution_store, Path(witness_key_file))
            self._key = _key(self._key_file)
            if execution_store._path in {custody._execution_store._path, custody._material_store._path} or execution_store._key_path in {custody._execution_store._key_path, custody._material_store._key_path, custody._key_file, self._key_file} or hmac.compare_digest(self._key, execution_store._key) or hmac.compare_digest(self._key, custody._key) or hmac.compare_digest(self._key, custody._execution_store._key) or custody._material_store.uses_key_material(self._key) or hmac.compare_digest(execution_store._key, custody._key) or hmac.compare_digest(execution_store._key, custody._execution_store._key) or custody._material_store.uses_key_material(execution_store._key):
                raise ValueError
            self._original = custody.inspect_original_creation()
            if self._original.original_outcome == 'in_progress' or self._original.native_uuid is None:
                raise ValueError
            self._verifier = authorization_verifier if authorization_verifier is not None else DenyAllM4AuthorizationVerifier()
            self._verifier_pin = self._verifier
            self._verifier_binding_guard = getattr(self._verifier, 'validate_recovery_binding', None)
            if self._verifier_binding_guard is not None and not callable(self._verifier_binding_guard):
                raise ValueError
            self._enabled, self._client_factory, self._connection_factory = (execution_enabled, client_factory, connection_factory)
            self._clock, self._http_clock = (clock, http_clock)
            self._epoch: int = -1
            self._monotonic: float = -1
            self._deadline: float | None = None
            self._preview: WindowsExecutionSecretRecoveryPreview | None = None
            self._plan: M4ExecutionPlan | None = None
            self._authorization: M4ExecutionAuthorization | None = None
            self._connection: Any = None
            self._socket: Any = None
            self._attempted = False
            self._authorized = False
            self._delete_started = self._absence_started = False
            self._preview_consumed = False
            self._lock = RLock()
            self._namespace = self._binding_digest()
            self._validate()
        except Exception:
            raise WindowsExecutionSecretRecoveryError(_ERROR) from None

    def _validate(self) -> None:
        self._custody._validate()
        self._store.verify_ready()
        if self._custody.inspect_original_creation() != self._original or self._verifier is not self._verifier_pin or self._binding_digest() != self._namespace or (not hmac.compare_digest(_key(self._key_file), self._key)):
            raise ValueError
        if getattr(self._verifier, 'validate_recovery_binding', None) != self._verifier_binding_guard:
            raise ValueError
        if self._verifier_binding_guard is not None:
            self._verifier_binding_guard(self)

    def _binding_digest(self) -> str:
        return canonical_digest({'original': self._original.custody_digest, 'source': self._custody._context, 'store': str(self._store._path), 'store_key_file': str(self._store._key_path), 'store_key': hashlib.sha256(self._store._key).hexdigest(), 'witness_file': str(self._key_file), 'witness_key': hashlib.sha256(self._key).hexdigest()})

    def _unconsumed(self) -> None:
        self._validate()
        if any((os.path.lexists(self._custody._directory / name) for name in (_SEND, _ACK))):
            raise ValueError

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value < self._epoch:
            raise ValueError
        self._epoch = value
        return value

    def _time(self) -> float:
        value = self._http_clock()
        if type(value) not in (int, float) or not math.isfinite(value) or value < self._monotonic or (value < 0):
            raise ValueError
        self._monotonic = float(value)
        return float(value)

    def _remaining(self) -> float:
        if self._deadline is None:
            raise ValueError
        remaining = self._deadline - self._time()
        if remaining <= 0:
            raise ValueError
        return min(10.0, remaining)

    def _signature(self, name: str, value: dict[str, object]) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + name.encode() + b'\x00' + raw, hashlib.sha256).hexdigest()

    def _write(self, name: str, value: dict[str, object]) -> None:
        self._validate()
        directory = os.open(self._custody._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if (info.st_dev, info.st_ino) != self._custody._directory_identity:
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=directory)
            with os.fdopen(descriptor, 'w') as stream:
                info = os.fstat(stream.fileno())
                if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 384 or (info.st_nlink != 1):
                    raise ValueError
                json.dump({**value, 'signature': self._signature(name, value)}, stream, sort_keys=True, separators=(',', ':'), allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str) -> dict[str, object]:
        raw = _read(self._custody._directory / name, 4096)
        try:
            self._validate()
            left = _skip_json_space(raw, 0)
            right = _json_value_end(raw, left)
            if _skip_json_space(raw, right) != len(raw):
                raise ValueError
            parser._validate_json(raw, left, right, depth=0, budget=[10000])
            _object_spans(raw, left, right)
            value = json.loads(raw)
            signature = value.pop('signature')
            expected = {'namespace', 'plan', 'authorization'} | ({'send_digest', 'ack_digest'} if name == _ACK else set())
            if set(value) != expected or type(signature) is not str or (not hmac.compare_digest(signature, self._signature(name, value))) or (value['namespace'] != self._namespace) or (self._plan is None) or (self._authorization is None) or (value['plan'] != self._plan.plan_digest) or (value['authorization'] != self._authorization.authorization_digest):
                raise ValueError
            if any((type(item) is not str or parser._DIGEST.fullmatch(item) is None for item in value.values())):
                raise ValueError
            return dict(value)
        finally:
            _zeroize_mutable(raw)

    def preview(self) -> WindowsExecutionSecretRecoveryPreview:
        try:
            with self._lock:
                if self._preview_consumed or not self._enabled:
                    raise ValueError
                self._preview_consumed = True
                self._unconsumed()
                reader = WindowsExecutionSecretPreservationReader(self._custody, phase='recovery', client_factory=self._client_factory, http_clock=self._time)
                observed = reader.read_once()
                baseline = reader._record('baseline')
                parameters = canonical_digest({'contract': ACTION_ID, 'original': self._namespace, 'baseline': canonical_digest(baseline)})
                current = canonical_digest({'original': self._original.custody_digest, 'preservation': observed.preservation_digest, 'state': 'present'})
                expected = canonical_digest({'original': self._original.custody_digest, 'state': 'absent'})
                now = self._now()
                self._deadline = observed.expires_at
                self._remaining()
                self._preview = WindowsExecutionSecretRecoveryPreview(parameters, current, expected, self._custody._plan.requester_digest, now + min(30, max(1, int(observed.expires_at - self._time()))))
                return self._preview
        except Exception:
            raise WindowsExecutionSecretRecoveryError(_ERROR) from None

    def _check_plan(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> None:
        self._validate()
        if self._preview is None or type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization:
            raise ValueError
        plan.__post_init__()
        authorization.__post_init__()
        v = self._preview
        if not self._enabled or plan.action_id != ACTION_ID or plan.action_version != '1.0.0' or (plan.adapter_ref != ADAPTER_REF) or (plan.target_ref != TARGET_REF) or (plan.compensation_ref is not None) or (plan.parameters_digest != v.parameters_digest) or (plan.expected_current_digest != v.current_digest) or (plan.expected_state_digest != v.expected_digest) or (plan.requester_digest != v.requester_digest) or (authorization.expires_at > plan.expires_at) or (plan.expires_at > v.expires_at) or (self._now() >= min(plan.expires_at, v.expires_at)):
            raise ValueError
        self._remaining()

    def _connect(self) -> None:
        from urllib.parse import urlsplit
        self._validate()
        config = self._custody._config
        origin = urlsplit(config.base_url)
        if origin.hostname is None or origin.username is not None or origin.password is not None:
            raise ValueError
        context = _ssl_context(config)
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._connection = self._connection_factory(origin.hostname, origin.port or 443, timeout=self._remaining(), context=context)
        self._connection.connect()
        self._socket = self._connection.sock
        if self._socket is None:
            raise ValueError

    def _close(self) -> None:
        try:
            if self._connection is not None:
                self._connection.close()
        finally:
            self._connection = self._socket = None

    def _request(self, method: str) -> str:
        raw, chunk = (bytearray(), bytearray(4096))
        response = None
        try:
            if method not in {'DELETE', 'GET'} or self._connection is None or self._connection.sock is not self._socket:
                raise ValueError
            if not self._authorized or self._plan is None or self._authorization is None:
                raise ValueError
            self._check_plan(self._plan, self._authorization)
            if method == 'DELETE':
                _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
                self._record(_SEND)
                if self._delete_started:
                    raise ValueError
                self._delete_started = True
            else:
                sent, ack = (self._record(_SEND), self._record(_ACK))
                if ack['send_digest'] != canonical_digest(sent):
                    raise ValueError
                if self._absence_started:
                    raise ValueError
                self._absence_started = True
            self._validate()
            self._remaining()
            self._socket.settimeout(self._remaining())
            path = '/api/v2/cmdb/secret/database/' + str(self._original.native_secret_id)
            path += '?format=id&vdom=root' if method == 'GET' else '?vdom=root'
            self._connection.request(method, path, headers={'Authorization': 'Bearer ' + self._custody._config.bearer_token, 'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Connection': 'close', 'Cache-Control': 'no-store'})
            response = self._connection.getresponse()
            content_type = response.getheader('Content-Type')
            if type(response.status) is not int or response.status != (404 if method == 'GET' else 200) or type(content_type) is not str or (content_type.split(';')[0].strip().lower() != 'application/json') or (response.getheader('Content-Encoding') not in (None, '', 'identity')) or (response.getheader('Transfer-Encoding') not in (None, '')):
                raise ValueError
            while True:
                self._socket.settimeout(self._remaining())
                with memoryview(chunk)[:min(len(chunk), 16385 - len(raw))] as view:
                    count = response.readinto1(view)
                    self._remaining()
                    if type(count) is not int or not 0 <= count <= len(view) or len(raw) + count > 16384:
                        raise ValueError
                    if count:
                        raw.extend(view[:count])
                for offset in range(len(chunk)):
                    chunk[offset] = 0
                if count == 0:
                    break
            start = _skip_json_space(raw, 0)
            end = _json_value_end(raw, start)
            if _skip_json_space(raw, end) != len(raw):
                raise ValueError
            parser._validate_json(raw, start, end, depth=0, budget=[10000])
            fields = _object_spans(raw, start, end)
            for name, wanted in {'version': 'v7.0.0', 'build': 29, 'http_method': method, 'http_status': 404 if method == 'GET' else 200, 'status': 'Not Found' if method == 'GET' else 'success', 'path': 'secret', 'name': 'database', 'vdom': 'root'}.items():
                value = parser._scalar(raw, fields[name])
                if type(value) is not type(wanted) or value != wanted:
                    raise ValueError
            serial = parser._text(parser._scalar(raw, fields['serial']), maximum=128)
            if hashlib.sha256(serial.encode()).hexdigest() != self._custody._profile.serial_digest or {'action', 'schema_errors'} & fields.keys():
                raise ValueError
            if method == 'GET':
                error = parser._scalar(raw, fields['error'])
                if {'results', 'mkey'} & fields.keys() or type(error) is not int or error != 2:
                    raise ValueError
            else:
                native_id = parser._scalar(raw, fields['mkey'])
                if type(native_id) is not int or native_id != self._original.native_secret_id:
                    raise ValueError
                if 'error' in fields and (type(parser._scalar(raw, fields['error'])) is not int or parser._scalar(raw, fields['error']) != 0):
                    raise ValueError
            return hashlib.sha256(raw).hexdigest()
        finally:
            _zeroize_mutable(raw)
            _zeroize_mutable(chunk)
            try:
                if response is not None:
                    response.close()
            finally:
                self._close()

    def execute(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> M4ExecutionResult:
        try:
            with self._lock:
                if self._attempted or type(self._verifier) is DenyAllM4AuthorizationVerifier:
                    raise ValueError
                self._attempted = True
                self._unconsumed()
                self._check_plan(plan, authorization)
                self._plan, self._authorization = (plan, authorization)
                return M4ExecutionKernel(_Adapter(self), _Verifier(self), self._store, clock=self._now).execute(plan, authorization)
        except Exception:
            raise WindowsExecutionSecretRecoveryError(_ERROR) from None
        finally:
            try:
                self._close()
            except Exception:
                raise WindowsExecutionSecretRecoveryError(_ERROR) from None

class _Verifier:

    def __init__(self, owner: WindowsExecutionSecretRecovery) -> None:
        self.owner = owner

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        self.owner._check_plan(plan, authorization)
        self.owner._verifier.verify(plan, authorization, now_epoch=now_epoch)
        self.owner._authorized = True

class _Adapter:

    def __init__(self, owner: WindowsExecutionSecretRecovery) -> None:
        self.owner = owner

    def read_current(self, plan: M4ExecutionPlan) -> str:
        o = self.owner
        try:
            if plan is not o._plan or o._preview is None:
                raise ValueError
            o._connect()
            observed = WindowsExecutionSecretPreservationReader(o._custody, phase='dispatch', client_factory=o._client_factory, http_clock=o._time).read_once(max_deadline=o._deadline)
            o._remaining()
            return canonical_digest({'original': o._original.custody_digest, 'preservation': observed.preservation_digest, 'state': 'present'})
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        o = self.owner
        try:
            if plan is not o._plan or o._authorization is None:
                raise ValueError
            o._check_plan(plan, o._authorization)
            _require_m4_dispatch_ownership(plan, o._authorization, o._store)
            o._unconsumed()
            o._write(_SEND, {'namespace': o._namespace, 'plan': plan.plan_digest, 'authorization': o._authorization.authorization_digest})
            digest = o._request('DELETE')
            sent = o._record(_SEND)
            o._write(_ACK, {'namespace': o._namespace, 'plan': plan.plan_digest, 'authorization': o._authorization.authorization_digest, 'send_digest': canonical_digest(sent), 'ack_digest': digest})
            o._remaining()
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        o = self.owner
        try:
            if plan is not o._plan or o._preview is None or (not os.path.lexists(o._custody._directory / _ACK)):
                raise ValueError
            o._connect()
            o._request('GET')
            o._remaining()
            return o._preview.expected_digest
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None
