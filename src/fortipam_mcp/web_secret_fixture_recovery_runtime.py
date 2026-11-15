"""Inactive fixed Web fixture recovery adapter through the existing M4 kernel.

This supplies no authorization issuer, Tool or startup activation. A separately
trusted verifier must authorize the exact recovery plan. Native DELETE status
and material-source qualification remain independent startup prerequisites.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import http.client
import math
import os
import ssl
import stat
import time
from threading import RLock
from typing import Any, Literal
from urllib.parse import urlsplit

from v4_planning import (DenyAllM4AuthorizationVerifier, M4AuthorizationVerifier,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, canonical_digest)
from v4_planning.execution_kernel import M4AdapterAmbiguous, M4AdapterDenied
from v4_planning.material_provider import _OpaqueC3Object
from . import secret_bulk_import_metadata as m
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _ssl_context, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .web_secret_fixture_recovery_guard import WebSecretFixtureRecoveryGuard, WebSecretFixtureRecoveryInspection

ACTION = "web-secret-fixture-recover"
ADAPTER = "fortipam-build29-web-fixture-recover-v1"
CONTRACT = "web-secret-fixture-recovery/v1"
SOURCE_ACTION = "web-secret-source-fixture-recover"
SOURCE_ADAPTER = "fortipam-build29-web-source-fixture-recover-v2"
SOURCE_CONTRACT = "web-secret-source-fixture-recovery/v2"
RECONCILED_ACTION = "web-secret-reconciled-fixture-recover"
RECONCILED_ADAPTER = "fortipam-build29-web-reconciled-fixture-recover-v1"
RECONCILED_CONTRACT = "web-secret-reconciled-fixture-recovery/v1"
_ERROR = "The private Web fixture recovery is unavailable."
_ATTEMPT = "recovery.delete.attempt"
_ACK = "recovery.delete.ack"
_FIELDS = frozenset({"version", "build", "http_method", "http_status", "status", "path", "name",
    "vdom", "serial", "mkey", "error", "action", "schema_errors", "results"})


class WebSecretFixtureRecoveryError(ValueError):
    """Categorical refusal; unknown or consumed effects are never replayed."""


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretFixtureRecoveryPreview(_OpaqueC3Object):
    """Value-free private C/P/E inputs for a separate trusted authorizer."""
    current_digest: str
    expected_digest: str
    parameters_digest: str
    requester_digest: str
    target_ref: str
    expires_at: int


class WebSecretFixtureRecoveryRuntime(_OpaqueC3Object):
    """One original fixture, one fresh pre-write read and one DELETE.

    Normal recovery retains one absence GET. Source v2 permits up to three
    identical absence GETs after a sealed ACK, retrying only RemoteDisconnected
    within the original deadline. No mutation, material phase or claim is replayed.
    Reconciled cleanup has its own action, parameter contract and durable files;
    it uses the qualified success status and the same bounded absence behavior.

    The DELETE TLS connection opens before the fresh complete Password/TOTP
    observation. Equality plus local custody/freshness is checked immediately
    before sending. This is bounded drift rejection, not backend atomic CAS.
    Original creation seals and consumed markers are never removed or adopted.
    """
    def __init__(self, guard: WebSecretFixtureRecoveryGuard, *,
            authorization_verifier: M4AuthorizationVerifier | None = None,
            delete_status: Literal["OK", "success"] | None = None,
            observe_delete_source: bool = False,
            execution_enabled: bool = False,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection) -> None:
        try:
            if (type(guard) is not WebSecretFixtureRecoveryGuard or type(execution_enabled) is not bool
                    or type(observe_delete_source) is not bool
                    or observe_delete_source and delete_status is not None
                    or delete_status is not None and (type(delete_status) is not str or delete_status not in {"OK", "success"})
                    or not callable(connection_factory)):
                raise ValueError
            guard._guard()
            self._guard_source, self._record = guard, guard._record
            self._original = self._record.read_acknowledged_creation()
            capture = self._record._ack_capture
            self._reconciled = guard._reconciled_source is not None
            if (capture is None or not self._reconciled and capture.observe_source != observe_delete_source
                    or self._reconciled and (observe_delete_source or delete_status != "success")):
                raise ValueError
            self._attempt_name = "reconciled-cleanup.delete.attempt" if self._reconciled else _ATTEMPT
            self._ack_name = "reconciled-cleanup.delete.ack" if self._reconciled else _ACK
            self._config, self._status = guard._config, delete_status
            self._observe_delete_source = observe_delete_source
            self._observed_status: Literal["OK", "success"] | None = None
            self._sealed_status: Literal["OK", "success"] | None = None
            self._source_completed = False
            self._verifier = authorization_verifier if authorization_verifier is not None else DenyAllM4AuthorizationVerifier()
            self._verifier_pin = self._verifier
            self._factory = self._factory_pin = connection_factory
            self._enabled = execution_enabled
            self._inspection: WebSecretFixtureRecoveryInspection | None = None
            self._preview: WebSecretFixtureRecoveryPreview | None = None
            self._plan: M4ExecutionPlan | None = None
            self._authorization: M4ExecutionAuthorization | None = None
            self._bound_context: tuple[str, str] | None = None
            self._authorized = False
            self._connection: Any = None
            self._socket: Any = None
            self._marker_identity: tuple[int, int] | None = None
            self._marker_payload: bytes | None = None
            self._ack_identity: tuple[int, int] | None = None
            self._ack_payload: bytes | None = None
            self._started = self._acknowledged = False
            self._last_http: float | None = None
            self._deadline: float | None = None
            self._parameters = self._parameters_digest()
            self._lock = RLock()
            self._unconsumed()
        except Exception:
            raise WebSecretFixtureRecoveryError(_ERROR) from None

    def _parameters_digest(self) -> str:
        return canonical_digest({"contract": RECONCILED_CONTRACT if self._reconciled else
            SOURCE_CONTRACT if self._observe_delete_source else CONTRACT,
            "namespace": self._record._namespace,
            "creation": self._original.creation.creation_digest, "source": self._guard_source._source,
            "delete_status": self._status})

    @property
    def action_contract(self) -> tuple[str, str, str]:
        if self._reconciled:
            return RECONCILED_ACTION, "1.0.0", RECONCILED_ADAPTER
        if self._observe_delete_source:
            return SOURCE_ACTION, "2.0.0", SOURCE_ADAPTER
        return ACTION, "1.0.0", ADAPTER

    def observed_delete_status(self) -> Literal["OK", "success"]:
        """Private source metadata only after ACK, exact absence and M4 success."""
        try:
            if not self._observe_delete_source or not self._source_completed or self._observed_status is None:
                raise ValueError
            self._guard()
            return self._observed_status
        except Exception:
            raise WebSecretFixtureRecoveryError(_ERROR) from None

    def _unconsumed(self) -> None:
        directory = self._record._directory_fd()
        try:
            for name in (self._attempt_name, self._ack_name):
                try:
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ValueError
        finally:
            os.close(directory)

    def preview(self) -> WebSecretFixtureRecoveryPreview:
        with self._lock:
            try:
                if (not self._enabled or self._status is None and not self._observe_delete_source
                        or self._preview is not None or self._started):
                    raise ValueError
                self._unconsumed()
                if self._guard_source._state == "new":
                    self._guard_source.capture_baseline_once()
                elif self._guard_source._state != "baseline":
                    raise ValueError
                inspection = self._guard_source.inspect_recovery_once()
                self._inspection = inspection
                preview = WebSecretFixtureRecoveryPreview(inspection.current_digest,
                    inspection.expected_absence_digest, self._parameters,
                    self._record._execution_binding.plan.requester_digest,
                    "web-fixture-" + inspection.creation_digest[:40], inspection.expires_at)
                self._preview = preview
                self._check_local()
                return preview
            except Exception:
                raise WebSecretFixtureRecoveryError(_ERROR) from None

    def _check_local(self) -> None:
        if (not self._enabled or self._status is None and not self._observe_delete_source
                or self._inspection is None or self._preview is None
                or self._record is not self._guard_source._record or self._config != self._guard_source._config
                or self._reconciled != (self._guard_source._reconciled_source is not None)
                or self._reconciled and (self._observe_delete_source or self._status != "success")
                or (self._attempt_name, self._ack_name) != (("reconciled-cleanup.delete.attempt",
                    "reconciled-cleanup.delete.ack") if self._reconciled else (_ATTEMPT, _ACK))
                or self._record.read_acknowledged_creation() != self._original
                or self._factory is not self._factory_pin or self._verifier is not self._verifier_pin
                or self._parameters_digest() != self._parameters):
            raise ValueError
        self._guard_source.check_current(self._inspection)
        expected = WebSecretFixtureRecoveryPreview(self._inspection.current_digest,
            self._inspection.expected_absence_digest, self._parameters,
            self._record._execution_binding.plan.requester_digest,
            "web-fixture-" + self._inspection.creation_digest[:40], self._inspection.expires_at)
        if self._preview != expected:
            raise ValueError

    def _check_plan(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> None:
        self._check_local()
        p = self._preview
        if p is None or type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization:
            raise ValueError
        plan.__post_init__()
        authorization.__post_init__()
        if ((plan.action_id, plan.action_version, plan.adapter_ref) != self.action_contract
                or (plan.expected_current_digest, plan.expected_state_digest, plan.parameters_digest,
                    plan.requester_digest, plan.target_ref, plan.expires_at) !=
                   (p.current_digest, p.expected_digest, p.parameters_digest, p.requester_digest, p.target_ref, p.expires_at)
                or plan.compensation_ref is not None):
            raise ValueError
        now = self._guard_source._now()
        if ((authorization.plan_ref, authorization.plan_digest, authorization.requester_digest,
                authorization.confirmation_digest, authorization.approval_digest) !=
                (plan.plan_ref, plan.plan_digest, plan.requester_digest, plan.confirmation_digest, plan.approval_digest)
                or not authorization.issued_at <= now < authorization.expires_at <= plan.expires_at):
            raise ValueError
        if self._bound_context is not None and ((plan, authorization) != (self._plan, self._authorization)
                or (plan.plan_digest, authorization.authorization_digest) != self._bound_context):
            raise ValueError

    def _guard(self) -> None:
        if self._plan is None or self._authorization is None or not self._authorized:
            raise ValueError
        self._check_plan(self._plan, self._authorization)
        self._check_marker()
        if self._acknowledged:
            self._check_file(self._ack_name, self._ack_identity, self._ack_payload)
            if self._observe_delete_source and self._observed_status != self._sealed_status:
                raise ValueError

    def _write(self, name: str, payload: bytes) -> tuple[int, int]:
        directory = self._record._directory_fd()
        try:
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                        or info.st_size != len(payload)):
                    raise ValueError
            os.fsync(directory)
            check = self._record._directory_fd()
            os.close(check)
            return info.st_dev, info.st_ino
        finally:
            os.close(directory)

    def _check_marker(self) -> None:
        self._check_file(self._attempt_name, self._marker_identity, self._marker_payload)

    def _check_file(self, name: str, identity: tuple[int, int] | None, payload: bytes | None) -> None:
        directory = self._record._directory_fd()
        descriptor: int | None = None
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            info = os.fstat(descriptor)
            if (payload is None or (info.st_dev, info.st_ino) != identity
                    or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size != len(payload)
                    or not hmac.compare_digest(os.read(descriptor, len(payload) + 1), payload)):
                raise ValueError
            after = os.fstat(descriptor)
            linked = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if ((after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_nlink,
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
                    (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                    or (linked.st_dev, linked.st_ino) != identity):
                raise ValueError
        finally:
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                os.close(directory)

    def _now_http(self) -> float:
        value = self._guard_source._http_clock()
        if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                or self._last_http is not None and value < self._last_http):
            raise ValueError
        self._last_http = value
        return value

    def _remaining(self) -> float:
        self._guard()
        if self._deadline is None:
            raise ValueError
        value = self._deadline - self._now_http()
        if value <= 0:
            raise ValueError
        return min(10., value)

    def _connect(self) -> None:
        origin = urlsplit(self._config.base_url)
        context = _ssl_context(self._config)
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._connection = self._factory(origin.hostname, origin.port or 443,
            context=context, timeout=self._remaining())
        self._connection.connect()
        self._socket = self._connection.sock
        if self._socket is None:
            raise ValueError
        self._remaining()

    def _close_connection(self) -> None:
        try:
            if self._connection is not None:
                self._connection.close()
        finally:
            self._connection = self._socket = None

    def _request(self, method: Literal["DELETE", "GET"]) -> str:
        response = None
        raw, chunk = bytearray(), bytearray(4096)
        try:
            if self._connection is None or self._connection.sock is not self._socket:
                raise ValueError
            self._socket.settimeout(self._remaining())
            path = "/api/v2/cmdb/secret/database/" + str(self._original.creation.native_secret_id)
            if method == "GET":
                path += "?format=id"
            with _private_http_logs():
                self._connection.request(method, path, headers={"Authorization": "Bearer " + self._config.bearer_token,
                    "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
                    "User-Agent": "fortipam-mcp-owned-web-fixture/1"})
                self._remaining()
                response = self._connection.getresponse()
                self._remaining()
                if (response.status != (404 if method == "GET" else 200)
                        or response.getheader("Content-Type", "").split(";")[0].strip().lower() != "application/json"
                        or response.getheader("Content-Encoding") not in (None, "", "identity")
                        or response.getheader("Transfer-Encoding") not in (None, "")):
                    raise ValueError
                for _ in range(4096):
                    if response.isclosed():
                        break
                    self._socket.settimeout(self._remaining())
                    with memoryview(chunk)[:min(len(chunk), 16385 - len(raw))] as view:
                        count = response.readinto1(view)
                        if type(count) is not int or not 0 <= count <= len(view):
                            raise ValueError
                        raw.extend(view[:count])
                    self._remaining()
                    if len(raw) > 16384:
                        raise ValueError
                    if count == 0:
                        break
                else:
                    raise ValueError
                digest = self._consume(raw, method)
        finally:
            _zeroize_mutable(raw)
            _zeroize_mutable(chunk)
            try:
                if response is not None:
                    response.close()
            finally:
                try:
                    self._close_connection()
                except Exception:
                    raise WebSecretFixtureRecoveryError(_ERROR) from None
        self._remaining()
        return digest

    def _consume(self, raw: bytearray, method: Literal["DELETE", "GET"]) -> str:
        left = _skip_json_space(raw, 0)
        right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            raise ValueError
        m._validate_json(raw, left, right, depth=0, budget=[50000])
        fields = m._object_spans(raw, left, right, _FIELDS)
        status = m._scalar(raw, fields["status"])
        expected_status = "Not Found" if method == "GET" else self._status
        if method == "DELETE" and self._observe_delete_source:
            if type(status) is not str or status not in {"OK", "success"}:
                raise ValueError
            expected_status = status
        for key, wanted in {"version": "v7.0.0", "build": 29, "http_method": method,
                "http_status": 404 if method == "GET" else 200,
                "status": expected_status,
                "path": "secret", "name": "database", "vdom": "root"}.items():
            value = m._scalar(raw, fields[key])
            if type(value) is not type(wanted) or value != wanted:
                raise ValueError
        serial = m._text(m._scalar(raw, fields["serial"]), maximum=128)
        if hashlib.sha256(serial.encode()).hexdigest() != self._original.creation.serial_digest:
            raise ValueError
        if {"action", "schema_errors"} & fields.keys():
            raise ValueError
        if method == "GET":
            if {"mkey", "results"} & fields.keys() or raw[slice(*fields["error"])] != b"2":
                raise ValueError
        else:
            identifier = m._scalar(raw, fields["mkey"])
            if type(identifier) is not int or identifier != self._original.creation.native_secret_id:
                raise ValueError
            if "error" in fields and raw[slice(*fields["error"])] != b"0":
                raise ValueError
            if self._observe_delete_source:
                self._observed_status = "OK" if status == "OK" else "success"
        return hashlib.sha256(raw).hexdigest()

    def execute(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> M4ExecutionResult:
        with self._lock:
            try:
                if self._started:
                    raise ValueError
                self._check_plan(plan, authorization)
                if type(self._verifier) is DenyAllM4AuthorizationVerifier:
                    raise ValueError
                self._unconsumed()
                self._started = True
                self._plan, self._authorization = plan, authorization
                self._bound_context = plan.plan_digest, authorization.authorization_digest
                self._marker_payload = hmac.new(self._record._key,
                    (b"web-fixture-reconciled-cleanup-delete-attempt/v1\0" if self._reconciled else
                     b"web-fixture-delete-attempt/v1\0")
                    + self._record._namespace.encode() + plan.plan_digest.encode()
                    + authorization.authorization_digest.encode(), hashlib.sha256).hexdigest().encode()
                self._marker_identity = self._write(self._attempt_name, self._marker_payload)
                self._deadline = self._now_http() + min(30., self._config.timeout_seconds)
                result = M4ExecutionKernel(_Adapter(self), _BoundVerifier(self), self._record._execution_store,
                    clock=self._guard_source._now).execute(plan, authorization)
                self._source_completed = (self._observe_delete_source and result.as_dict() == {
                    "outcome": "succeeded", "verification": "verified", "compensation": "not_requested",
                    "idempotent_replay": False})
                return result
            except Exception:
                raise WebSecretFixtureRecoveryError(_ERROR) from None
            finally:
                try:
                    self._close_connection()
                except Exception:
                    raise WebSecretFixtureRecoveryError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._authorized = False
            try:
                self._close_connection()
            except Exception:
                raise WebSecretFixtureRecoveryError(_ERROR) from None
            finally:
                self._guard_source.close()


class _BoundVerifier:
    """Delegate one-time authorization only after the kernel's durable claim."""
    def __init__(self, owner: WebSecretFixtureRecoveryRuntime) -> None:
        self._owner = owner

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        owner = self._owner
        if (owner._authorized or plan is not owner._plan or authorization is not owner._authorization
                or owner._verifier is not owner._verifier_pin):
            raise ValueError
        owner._check_plan(plan, authorization)
        owner._check_marker()
        owner._verifier.verify(plan, authorization, now_epoch=now_epoch)
        owner._check_plan(plan, authorization)
        owner._check_marker()
        owner._authorized = True


class _Adapter:
    def __init__(self, owner: WebSecretFixtureRecoveryRuntime) -> None:
        self._owner = owner

    def read_current(self, plan: M4ExecutionPlan) -> str:
        owner = self._owner
        try:
            if plan is not owner._plan or owner._inspection is None:
                raise ValueError
            owner._connect()
            owner._guard_source.check_pre_dispatch_once(owner._inspection, http_deadline=owner._deadline)
            owner._remaining()
            return owner._inspection.current_digest
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        owner = self._owner
        try:
            if plan is not owner._plan or not owner._guard_source._dispatch._started:
                raise ValueError
            digest = owner._request("DELETE")
            payload = hmac.new(owner._record._key,
                (b"web-fixture-reconciled-cleanup-delete-ack/v1\0" if owner._reconciled else
                 b"web-fixture-delete-ack/v1\0")
                + owner._marker_payload + digest.encode(), hashlib.sha256).hexdigest().encode() if owner._marker_payload else b""
            if not payload:
                raise ValueError
            owner._ack_payload = payload
            owner._ack_identity = owner._write(owner._ack_name, payload)
            owner._sealed_status = owner._observed_status
            owner._acknowledged = True
            owner._remaining()
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        owner = self._owner
        try:
            if plan is not owner._plan or not owner._acknowledged or owner._inspection is None:
                raise ValueError
            limit = 3 if owner._observe_delete_source or owner._reconciled else 1
            for attempt in range(limit):
                try:
                    owner._connect()
                    owner._request("GET")
                    return owner._inspection.expected_absence_digest
                except http.client.RemoteDisconnected:
                    if attempt == limit - 1:
                        raise
                    owner._close_connection()
                    time.sleep(min(.25, owner._remaining()))
                    owner._remaining()
            raise ValueError
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None
