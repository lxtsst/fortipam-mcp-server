"""Default-denied independent M4 recovery for one original acknowledged JWT key.

Private candidate only. No creation, retry, force, adoption, issuer or Tool is
provided. Native DELETE/success/full-row compatibility remains unqualified.
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
from threading import RLock, get_ident
import time
from typing import Any
from urllib.parse import quote

from v4_planning import (DenyAllM4AuthorizationVerifier, M4AuthorizationVerifier, M4ExecutionAuthorization,
    M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, canonical_digest)
from v4_planning.execution_kernel import M4AdapterAmbiguous, M4AdapterDenied, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as parser
from .jwt_manual_key_owned_state import JwtManualKeyOwnedState, consume_jwt_manual_key_owned_state
from .jwt_manual_key_contract import _digest
from .jwt_manual_key_preflight import _absence, _collection, _top
from .jwt_manual_key_preflight_reader import JwtManualKeyPreflightRead, JwtManualKeyPreflightReader
from .jwt_manual_key_response_custody import JwtManualKeyResponseCustody, _STATE
from .ldap_server_runtime import _key, _private_directory
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable
from .target_operation_records import _TargetOperationRecords

ACTION_ID = "manual-jwt-key-remove"
ADAPTER_REF = "fortipam-700-build29-manual-jwt-key-remove-v1"
TARGET_REF = "bound-owned-manual-jwt-key"
_ERROR = "The private manual JWT-key recovery is unavailable."
_DOMAIN = b"manual-jwt-key-remove/v1\x00"
_SEND, _RESPONSE, _SUMMARY, _ACK, _ABSENCE = (
    "delete.attempt.json", "delete.response.json", "delete.summary.json", "delete.ack.json", "absence.json")
_BASE = frozenset({"namespace", "plan_digest", "authorization_digest"})
_FIELDS = {
    _SEND: _BASE | {"claim_context_digest", "claimed_at"},
    _RESPONSE: _BASE | {"send_digest", "response_hmac", "http_status", "body_state", "content_kind", "source_valid", "clock_valid"},
    _SUMMARY: _BASE | {"response_record_digest", "native_context_matches", "native_status", "native_error", "mkey_observed", "mkey_matches"},
    _ACK: _BASE | {"response_record_digest", "summary_record_digest", "acknowledged_at"},
    _ABSENCE: _BASE | {"delete_ack_digest", "absence_digest", "expected_digest", "observed_at"},
}
_MAX_BYTES = 524288


class JwtManualKeyRecoveryError(RuntimeError):
    """Non-disclosing refusal; original records and outcomes stay unchanged."""


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualKeyRecoveryPreview(_OpaqueC3Object):
    parameters_digest: str
    current_digest: str
    expected_digest: str
    requester_digest: str
    created_at: int
    expires_at: int


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualKeyRecoveryObservation(_OpaqueC3Object):
    original_creation_outcome: str
    recovery_outcome: str
    recovery_verification: str
    http_status: int | None
    native_error: int | None
    delete_ack_observed: bool
    absence_observed: bool
    mkey_observed: bool
    mkey_matches: bool
    custody_digest: str


class JwtManualKeyRecovery(_TargetOperationRecords):
    """One source-bound independent grant; consumed ledgers cannot be reset here."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, custody: JwtManualKeyResponseCustody,
                 reader: JwtManualKeyPreflightReader, baseline: JwtManualKeyPreflightRead, *,
                 execution_store: PersistentM4ExecutionStateStore, witness_key_file: Path,
                 authorization_verifier: M4AuthorizationVerifier | None = None, execution_enabled: bool = False,
                 source_guard: Callable[[], bool] | None = None,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 clock: Callable[[], int] = lambda: int(time.time()), http_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(custody) is not JwtManualKeyResponseCustody
                    or type(reader) is not JwtManualKeyPreflightReader or type(baseline) is not JwtManualKeyPreflightRead
                    or type(execution_store) is not PersistentM4ExecutionStateStore or not execution_store.monotonic_checkpoint_protocol_bound
                    or type(execution_enabled) is not bool or config is not reader._config
                    or source_guard is not None and not callable(source_guard)
                    or not all(callable(value) for value in (connection_factory, clock, http_clock))):
                raise ValueError
            self._custody, self._config, self._reader, self._baseline = custody, config, reader, baseline
            self._original = custody.inspect_original_response()
            if (not self._original.success_ack_retained or self._original.original_outcome == "in_progress"
                    or baseline.state.state_digest != custody._state or baseline.source_digest != custody._source
                    or reader._source != baseline.source_digest or reader._name != custody._name
                    or baseline.actor.digest != custody._actor_digest):
                raise ValueError
            self._original_state = custody.inspect_original_owned_state() if os.path.lexists(custody._directory / _STATE) else None
            self._directory = custody._directory / "recovery"
            _private_directory(self._directory)
            info = self._directory.stat(); self._identity = (info.st_dev, info.st_ino)
            self._store, self._key_file = execution_store, Path(witness_key_file)
            self._store_pin = (execution_store._path, execution_store._key_path, execution_store._key)
            self._checkpoint_pin = (execution_store._monotonic_checkpoint, execution_store._checkpoint_store_ref)
            if (execution_store._monotonic_checkpoint is custody._store._monotonic_checkpoint
                    and execution_store._checkpoint_store_ref == custody._store._checkpoint_store_ref):
                raise ValueError
            if (execution_store._path != self._directory / "execution.sqlite"
                    or execution_store._key_path != self._directory / "execution.key"
                    or self._key_file != self._directory / "witness.key"):
                raise ValueError
            self._key = _key(self._key_file)
            paths = (custody._store._path, custody._store._key_path, custody._key_file,
                execution_store._path, execution_store._key_path, self._key_file)
            keys = (custody._store._key, custody._key, execution_store._key, self._key)
            if len({path.resolve() for path in paths}) != len(paths) or len(set(keys)) != len(keys):
                raise ValueError
            self._namespace = canonical_digest({"contract": ACTION_ID, "original": self._original.custody_digest,
                "creation_context": custody._context, "source": baseline.source_digest, "directory": str(self._directory),
                "ledger": str(execution_store._path), "ledger_key": hashlib.sha256(execution_store._key).hexdigest(),
                "witness": hashlib.sha256(self._key).hexdigest()})
            self._verifier = authorization_verifier if authorization_verifier is not None else DenyAllM4AuthorizationVerifier()
            self._verifier_pin, self._enabled, self._source_guard = self._verifier, execution_enabled, source_guard
            self._binding_guard = getattr(self._verifier, "validate_recovery_binding", None)
            if self._binding_guard is not None and not callable(self._binding_guard): raise ValueError
            self._source_guard_pin = source_guard
            self._factory, self._clock, self._http_clock = connection_factory, clock, http_clock
            self._last_clock: int | None = None; self._clock_failed = False
            self._last_http = -1.0; self._deadline: float | None = None
            self._preview: JwtManualKeyRecoveryPreview | None = None
            self._preview_started = self._attempted = self._executing = self._delete_started = self._delete_completed = False
            self._absence_started = False; self._owner_thread: int | None = None
            self._plan: M4ExecutionPlan | None = None; self._authorization: M4ExecutionAuthorization | None = None
            self._delete_connection: Any = None
            self._mutex = RLock()
            self._delete_path = custody._request.path + "/" + quote(custody._name, safe="")
            self._detail_path = self._delete_path + "?with_meta=true"
            self._absence_path = self._delete_path + "?format=name%7Ctype&with_meta=true"
            self._state_paths = (self._detail_path, reader._paths[6], reader._paths[7], self._detail_path)
            self._validate()
        except Exception:
            raise JwtManualKeyRecoveryError(_ERROR) from None

    def _validate(self) -> None:
        self._custody._integrity(); self._store.verify_ready(); _private_directory(self._directory)
        info = self._directory.stat()
        current = self._custody.inspect_original_response()
        state_present = os.path.lexists(self._custody._directory / _STATE)
        if (current != self._original or self._verifier is not self._verifier_pin
                or getattr(self._verifier, "validate_recovery_binding", None) != self._binding_guard
                or (self._store._path, self._store._key_path, self._store._key) != self._store_pin
                or self._store._monotonic_checkpoint is not self._checkpoint_pin[0]
                or self._store._checkpoint_store_ref != self._checkpoint_pin[1]
                or not hmac.compare_digest(_key(self._store._key_path), self._store._key)
                or (info.st_dev, info.st_ino) != self._identity or not hmac.compare_digest(_key(self._key_file), self._key)
                or state_present != (self._original_state is not None)
                or self._original_state is not None and self._custody.inspect_original_owned_state() != self._original_state
                or self._custody._request._request_digest() != self._custody._request_digest):
            raise ValueError
        if self._binding_guard is not None: self._binding_guard(self)

    def _source(self) -> None:
        self._validate()
        if (not self._enabled or self._source_guard is None or self._source_guard is not self._source_guard_pin
                or self._source_guard() is not True or self._reader._fingerprint() != self._baseline.source_digest):
            raise ValueError

    def _remaining(self) -> float:
        now = self._http_clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0 or now < self._last_http:
            raise ValueError
        self._last_http = float(now)
        if self._deadline is None or self._deadline <= now: raise ValueError
        return min(10.0, self._deadline - now)

    def _context(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> str:
        return canonical_digest({"plan_digest": plan.plan_digest, "authorization_digest": authorization.authorization_digest,
            "revision": plan.revision})

    def _active(self, *, post: bool = False) -> None:
        self._validate()
        p, a = self._plan, self._authorization
        if p is None or a is None: raise ValueError
        if post:
            if not self._executing or self._owner_thread != get_ident() or not self._delete_completed: raise ValueError
        else:
            _require_m4_dispatch_ownership(p, a, self._store)
        claim = self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest, context_digest=self._context(p, a))
        if claim.result is not None: raise ValueError

    def _signature(self, name: str, value: dict[str, Any]) -> str:
        return hmac.new(self._key, _DOMAIN + name.encode() + b"\x00" + json.dumps(value,
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()

    def _signed_write(self, name: str, values: dict[str, Any]) -> dict[str, Any]:
        self._active(post=name == _ABSENCE)
        if self._plan is None or self._authorization is None: raise ValueError
        record = dict(namespace=self._namespace, plan_digest=self._plan.plan_digest,
            authorization_digest=self._authorization.authorization_digest, **values)
        if record.keys() != _FIELDS[name]: raise ValueError
        with self._lock() as directory:
            self._write(directory, name, {**record, "signature": self._signature(name, record)})
        return record

    def _record(self, name: str) -> dict[str, Any]:
        self._validate()
        with self._lock() as directory: record = self._read(directory, name)
        signature = record.pop("signature")
        if (record.keys() != _FIELDS[name] or type(signature) is not str
                or not hmac.compare_digest(signature, self._signature(name, record))): raise ValueError
        for key, value in record.items():
            if key == "namespace" or key.endswith("_digest") or key.endswith("_hmac"):
                if type(value) is not str or parser._DIGEST.fullmatch(value) is None: raise ValueError
            elif key.endswith("_at"):
                if type(value) is not int or value < 0: raise ValueError
            elif key in {"clock_valid", "source_valid", "native_context_matches", "mkey_observed", "mkey_matches"}:
                if type(value) is not bool: raise ValueError
            elif key in {"http_status", "native_error"}:
                if value is not None and (type(value) is not int or not -(2 ** 31) <= value < 2 ** 31): raise ValueError
            elif key == "body_state":
                if value not in {"complete", "partial", "oversize", "encoded"}: raise ValueError
            elif key == "content_kind":
                if value not in {"json", "other", "unknown"}: raise ValueError
            elif key == "native_status":
                if value not in {"success", "error", "unknown"}: raise ValueError
            else: raise ValueError
        return record

    def _connect(self) -> Any:
        self._source()
        context = _ssl_context(self._config)
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED: raise ValueError
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = self._factory(self._reader._host, self._reader._port, timeout=self._remaining(), context=context)
        try:
            connection.connect(); self._source(); self._remaining(); return connection
        except BaseException:
            connection.close(); raise

    @staticmethod
    def _close(response: Any, connection: Any) -> None:
        failure: BaseException | None = None
        for resource in (response, connection):
            if resource is not None:
                try: resource.close()
                except BaseException as error: failure = failure or error
        if failure is not None: raise failure

    def _check_plan(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> None:
        self._source(); plan.__post_init__(); authorization.__post_init__()
        v = self._preview
        if (v is None or plan.action_id != ACTION_ID or plan.action_version != "1.0.0" or plan.adapter_ref != ADAPTER_REF
                or plan.target_ref != TARGET_REF or plan.compensation_ref is not None
                or plan.parameters_digest != v.parameters_digest or plan.expected_current_digest != v.current_digest
                or plan.expected_state_digest != v.expected_digest or plan.requester_digest != v.requester_digest
                or plan.expires_at > v.expires_at or authorization.expires_at > plan.expires_at
                or not authorization.issued_at <= self._now() < min(authorization.expires_at, plan.expires_at, v.expires_at)):
            raise ValueError
        self._remaining()

    def _read_present(self) -> JwtManualKeyOwnedState:
        self._source()
        actor = self._reader.observe_actor()
        if actor.digest != self._baseline.actor.digest: raise ValueError
        buffers: list[bytearray] = []
        try:
            for path in self._state_paths: buffers.append(self._http("GET", path))
            observed = consume_jwt_manual_key_owned_state(*buffers, request=self._custody._request,
                baseline=self._baseline.state, witness_key=self._custody._key,
                expected_full_row_hmac=self._original_state.state.full_row_hmac if self._original_state else None,
                require_original_body_digest=self._original_state is None)
            self._source(); self._remaining(); return observed
        finally:
            for raw in buffers: _zeroize_mutable(raw)

    def _current(self, observed: JwtManualKeyOwnedState) -> str:
        return canonical_digest({"original": self._original.custody_digest, "full_row": observed.full_row_hmac,
            "users": observed.api_users_digest, "keys": observed.key_namespace_digest, "state": "present"})

    def preview(self) -> JwtManualKeyRecoveryPreview:
        try:
            with self._mutex:
                self._source()
                if self._preview_started or self._store.claim_count or os.path.lexists(self._directory / _SEND): raise ValueError
                self._preview_started = True
                self._deadline = self._http_clock() + min(45.0, float(self._config.timeout_seconds))
                observed = self._read_present(); now = self._now()
                self._preview = JwtManualKeyRecoveryPreview(canonical_digest({"contract": ACTION_ID, "namespace": self._namespace}),
                    self._current(observed), canonical_digest({"original": self._namespace, "state": "absent",
                        "users": self._baseline.state.api_users_digest}), self._custody._plan.requester_digest, now, now + 60)
                return self._preview
        except Exception:
            raise JwtManualKeyRecoveryError(_ERROR) from None
        finally:
            self._deadline = None

    def execute(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> M4ExecutionResult:
        try:
            with self._mutex:
                if self._attempted or type(self._verifier) is DenyAllM4AuthorizationVerifier: raise ValueError
                self._attempted = True
                self._deadline = self._http_clock() + min(45.0, float(self._config.timeout_seconds))
                self._check_plan(plan, authorization)
                self._plan, self._authorization = plan, authorization
                self._owner_thread, self._executing = get_ident(), True
                return M4ExecutionKernel(_Adapter(self), _Verifier(self), self._store, clock=self._now).execute(plan, authorization)
        except Exception:
            raise JwtManualKeyRecoveryError(_ERROR) from None
        finally:
            self._executing = False; self._deadline = None
            try: self._close(None, self._delete_connection)
            except Exception: raise JwtManualKeyRecoveryError(_ERROR) from None
            finally: self._delete_connection = None

    def _http(self, method: str, path: str) -> bytearray:
        response = connection = None
        raw, chunk = bytearray(), bytearray(4096)
        transferred = sent = False; pending: BaseException | None = None
        status = None; content = None; body_state = "partial"
        try:
            if method == "DELETE":
                self._active()
                if path != self._delete_path or not self._delete_started or self._delete_connection is None: raise ValueError
                connection, self._delete_connection = self._delete_connection, None
            elif method == "GET" and path in {*self._state_paths, self._absence_path}:
                connection = self._connect()
            else: raise ValueError
            self._source(); self._remaining()
            if getattr(connection, "sock", None) is not None: connection.sock.settimeout(self._remaining())
            sent = True
            connection.request(method, path, headers={"Authorization": "Bearer " + self._config.bearer_token,
                "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close", "Cache-Control": "no-store"})
            response = connection.getresponse(); status = response.status; content = response.getheader("Content-Type")
            while True:
                self._remaining()
                count = response.readinto(chunk)
                if type(count) is not int or not 0 <= count <= len(chunk): raise ValueError
                if not count: body_state = "complete"; break
                size = min(count, _MAX_BYTES + 1 - len(raw))
                with memoryview(chunk)[:size] as part: raw.extend(part)
                chunk[:] = b"\x00" * len(chunk)
                if len(raw) > _MAX_BYTES: body_state = "oversize"; break
            encoding = response.getheader("Content-Encoding", "identity")
            if type(encoding) is not str or encoding.strip().lower() != "identity": body_state = "encoded"
            if method == "GET":
                expected = 404 if path == self._absence_path else 200
                if (type(status) is not int or status != expected or type(content) is not str
                        or content.split(";", 1)[0].strip().lower() != "application/json" or body_state != "complete"): raise ValueError
                self._source(); self._remaining(); transferred = True
        except BaseException as error:
            pending = error
        finally:
            try:
                if method == "DELETE" and sent: self._capture_delete(raw, status, content, body_state)
            except BaseException as error:
                pending = pending or error
            finally:
                _zeroize_mutable(chunk)
                if not transferred: _zeroize_mutable(raw)
                try: self._close(response, connection)
                except BaseException as error: pending = pending or error; _zeroize_mutable(raw)
        if pending is not None: raise pending
        return raw

    def _capture_delete(self, raw: bytearray, status: Any, content: Any, body_state: str) -> None:
        self._active()
        send = self._record(_SEND)
        source_valid = clock_valid = False
        try: self._source(); self._remaining(); source_valid = True
        except Exception: pass
        try:
            if self._plan is not None and self._authorization is not None:
                self._check_plan(self._plan, self._authorization); clock_valid = True
        except Exception: pass
        record = self._signed_write(_RESPONSE, dict(send_digest=canonical_digest(send),
            response_hmac=hmac.new(self._key, _DOMAIN + b"response\x00" + bytes(raw), hashlib.sha256).hexdigest(),
            http_status=status if type(status) is int and 100 <= status <= 599 else None, body_state=body_state,
            content_kind=("json" if content.split(";", 1)[0].strip().lower() == "application/json" else "other") if type(content) is str else "unknown",
            source_valid=source_valid, clock_valid=clock_valid))
        summary: dict[str, Any] = dict(native_context_matches=False, native_status="unknown", native_error=None,
            mkey_observed=False, mkey_matches=False)
        fields = None
        if body_state == "complete" and record["content_kind"] == "json":
            try:
                fields = _top(raw)
                selected = {key: parser._scalar(raw, fields[key]) for key in (
                    "version", "build", "serial", "http_method", "http_status", "status", "path", "name", "vdom")}
                expected = dict(version="v7.0.0", build=29, http_method="DELETE", http_status=200,
                    status="success", path="secret", name="jwt-key", vdom="root")
                matches = all(type(selected[key]) is type(value) and selected[key] == value for key, value in expected.items())
                serial = selected["serial"]
                matches = matches and type(serial) is str and hashlib.sha256(serial.encode()).hexdigest() == self._custody._serial_digest
                error = parser._scalar(raw, fields["error"]) if "error" in fields else None
                summary = dict(native_context_matches=matches,
                    native_status=selected["status"] if selected["status"] in {"success", "error"} else "unknown",
                    native_error=error if type(error) is int and -(2 ** 31) <= error < 2 ** 31 else None,
                    mkey_observed="mkey" in fields, mkey_matches="mkey" in fields and
                        type(parser._scalar(raw, fields["mkey"])) is str and parser._scalar(raw, fields["mkey"]) == self._custody._name)
            except Exception: pass
        sealed = self._signed_write(_SUMMARY, dict(response_record_digest=canonical_digest(record), **summary))
        if (not source_valid or not clock_valid or status != 200 or fields is None or not summary["native_context_matches"]
                or summary["native_error"] not in {None, 0} or "schema_errors" in fields
                or "action" in fields and parser._scalar(raw, fields["action"]) != ""
                or type(parser._scalar(raw, fields["mkey"])) is not str
                or parser._scalar(raw, fields["mkey"]) != self._custody._name): raise ValueError
        if "error" in fields:
            error = parser._scalar(raw, fields["error"])
            if type(error) is not int or error != 0: raise ValueError
        if self._plan is None or self._authorization is None: raise ValueError
        self._check_plan(self._plan, self._authorization)
        self._signed_write(_ACK, dict(response_record_digest=canonical_digest(record), summary_record_digest=canonical_digest(sealed),
            acknowledged_at=self._now()))
        self._delete_completed = True

    def inspect_result(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> JwtManualKeyRecoveryObservation:
        try:
            self._validate(); plan.__post_init__(); authorization.__post_init__()
            send = self._record(_SEND)
            if (send["plan_digest"] != plan.plan_digest or send["authorization_digest"] != authorization.authorization_digest
                    or send["claim_context_digest"] != self._context(plan, authorization)
                    or not authorization.issued_at <= send["claimed_at"] < authorization.expires_at): raise ValueError
            claim = self._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
                idempotency_digest=plan.idempotency_digest, authorization_digest=authorization.authorization_digest,
                context_digest=self._context(plan, authorization))
            records = {name: self._record(name) for name in (_RESPONSE, _SUMMARY, _ACK, _ABSENCE) if os.path.lexists(self._directory / name)}
            for value in records.values():
                if value["plan_digest"] != plan.plan_digest or value["authorization_digest"] != authorization.authorization_digest: raise ValueError
            response, summary, ack, absent = (records.get(name) for name in (_RESPONSE, _SUMMARY, _ACK, _ABSENCE))
            if response is not None and response["send_digest"] != canonical_digest(send): raise ValueError
            if summary is not None and (response is None or summary["response_record_digest"] != canonical_digest(response)): raise ValueError
            if ack is not None and (response is None or summary is None or ack["response_record_digest"] != canonical_digest(response)
                    or ack["summary_record_digest"] != canonical_digest(summary) or not response["source_valid"]
                    or not response["clock_valid"] or response["http_status"] != 200 or response["body_state"] != "complete"
                    or response["content_kind"] != "json" or not summary["native_context_matches"]
                    or summary["native_status"] != "success" or summary["native_error"] not in {None, 0} or not summary["mkey_matches"]
                    or not authorization.issued_at <= ack["acknowledged_at"] < authorization.expires_at
                    or ack["acknowledged_at"] < send["claimed_at"]): raise ValueError
            if absent is not None and (ack is None or absent["delete_ack_digest"] != canonical_digest(ack)
                    or absent["expected_digest"] != plan.expected_state_digest
                    or not ack["acknowledged_at"] <= absent["observed_at"] < authorization.expires_at): raise ValueError
            return JwtManualKeyRecoveryObservation(self._original.original_outcome,
                str(claim.result.outcome) if claim.result else "in_progress", str(claim.result.verification) if claim.result else "unknown",
                response["http_status"] if response else None, summary["native_error"] if summary else None,
                ack is not None, absent is not None, bool(summary and summary["mkey_observed"]),
                bool(summary and summary["mkey_matches"]), canonical_digest({"send": send, **records}))
        except Exception:
            raise JwtManualKeyRecoveryError(_ERROR) from None


class _Verifier:
    def __init__(self, owner: JwtManualKeyRecovery) -> None: self.owner = owner
    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        self.owner._check_plan(plan, authorization)
        self.owner._verifier.verify(plan, authorization, now_epoch=now_epoch)


class _Adapter:
    def __init__(self, owner: JwtManualKeyRecovery) -> None: self.owner = owner
    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            o = self.owner
            if plan is not o._plan: raise ValueError
            o._delete_connection = o._connect()
            return o._current(o._read_present())
        except Exception: raise M4AdapterDenied(_ERROR) from None
    def dispatch(self, plan: M4ExecutionPlan) -> None:
        try:
            o = self.owner
            if plan is not o._plan or o._authorization is None: raise ValueError
            o._active(); o._check_plan(plan, o._authorization)
            if o._delete_started or os.path.lexists(o._directory / _SEND) or o._current(o._read_present()) != plan.expected_current_digest: raise ValueError
            o._signed_write(_SEND, dict(claim_context_digest=o._context(plan, o._authorization), claimed_at=o._now()))
            o._delete_started = True
            o._check_plan(plan, o._authorization)
            o._http("DELETE", o._delete_path)
        except Exception: raise M4AdapterAmbiguous(_ERROR) from None
    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        buffers: list[bytearray] = []
        try:
            o = self.owner
            if plan is not o._plan or o._absence_started: raise ValueError
            o._active(post=True); o._absence_started = True
            raw = o._http("GET", o._absence_path); buffers.append(raw)
            _absence(raw, o._custody._name, o._custody._serial_digest)
            absence_digest = hmac.new(o._key, _DOMAIN + b"absence\x00" + bytes(raw), hashlib.sha256).hexdigest()
            for path in (o._reader._paths[6], o._reader._paths[7]): buffers.append(o._http("GET", path))
            keys, _ = _collection(buffers[1], "jwt-key", o._custody._serial_digest)
            users, _ = _collection(buffers[2], "api-user", o._custody._serial_digest)
            if keys or _digest(users) != o._baseline.state.api_users_digest: raise ValueError
            if o._authorization is None: raise ValueError
            o._check_plan(plan, o._authorization)
            ack = o._record(_ACK)
            o._signed_write(_ABSENCE, dict(delete_ack_digest=canonical_digest(ack), absence_digest=absence_digest,
                expected_digest=plan.expected_state_digest, observed_at=o._now()))
            return plan.expected_state_digest
        except Exception: raise M4AdapterAmbiguous(_ERROR) from None
        finally:
            for raw in buffers: _zeroize_mutable(raw)


__all__ = ["ACTION_ID", "ADAPTER_REF", "TARGET_REF", "JwtManualKeyRecoveryError", "JwtManualKeyRecoveryPreview",
           "JwtManualKeyRecoveryObservation", "JwtManualKeyRecovery"]
