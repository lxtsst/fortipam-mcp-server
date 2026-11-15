"""Default-off one-use initial Account material inside exact active M4 only."""
from __future__ import annotations

from collections.abc import Callable
from threading import RLock

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import MaterialAccessDenied, MaterialLease, _OpaqueC3Object

from .ems_tag_account_contract import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, TARGET_REF, _encode_create, _password_valid,
    current_digest, expected_digest,
)
from .ems_tag_account_enrollment import EmsAccountCentralEnrollment
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable
from .mutable_json_buffer import _clear_mutable_group

_ERROR = "The private initial EMS account material is unavailable."


class _EmsAccountInitialLease(MaterialLease):
    def __init__(self, source: EmsAccountInitialMaterialSource, username: bytearray, password: bytearray,
                 plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> None:
        self._source, self._username, self._password = source, username, password
        self._plan, self._authorization = plan, authorization
        self._consumed, self._closed = False, False

    def encode_once(self) -> bytearray:
        raw = bytearray()
        failure: BaseException | None = None
        try:
            if self._closed or self._consumed:raise ValueError
            self._consumed = True
            self._source._active(self._plan, self._authorization)
            with memoryview(self._username) as username, memoryview(self._password) as password:
                raw = _encode_create(self._source._enrollment._draft, username, password)
            self._source._active(self._plan, self._authorization)
        except BaseException as error:
            failure = error
        try:
            self.close()
        except BaseException as error:
            if failure is None or isinstance(failure, Exception) and not isinstance(error, Exception):
                failure = error
        if failure is None:
            return raw
        try:
            _zeroize_mutable(raw)
        except BaseException as error:
            if isinstance(failure, Exception) and not isinstance(error, Exception):
                failure = error
        if isinstance(failure, Exception):raise MaterialAccessDenied(_ERROR) from None
        raise failure

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            failure: BaseException | None = None
            for raw in (self._username, self._password):
                try:
                    _zeroize_mutable(raw)
                except BaseException as error:
                    if failure is None or isinstance(failure, Exception) and not isinstance(error, Exception):
                        failure = error
            if failure is not None:raise failure


class EmsAccountInitialMaterialSource(_OpaqueC3Object):
    def __init__(self, enrollment: EmsAccountCentralEnrollment, store: PersistentM4ExecutionStateStore, *,
                 execution_enabled: bool = False, clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(enrollment) is not EmsAccountCentralEnrollment or type(store) is not PersistentM4ExecutionStateStore
                    or type(execution_enabled) is not bool or clock is not None and not callable(clock)
                    or not store.monotonic_checkpoint_protocol_bound or store._read_only
                    or store._key in (enrollment._key, enrollment._sources._key, enrollment._parent._key, enrollment._parent._store._key)):
                raise ValueError
            enrollment.check_registered()
            self._enrollment, self._store = enrollment, store
            self._reference, self._parameters = enrollment.reference, enrollment.parameters_digest
            self._clock = clock or enrollment._clock
            self._enabled, self._closed, self._attempted, self._last = execution_enabled, False, False, -1
            self._lease: _EmsAccountInitialLease | None = None
            self._lock = RLock()
        except Exception:raise MaterialAccessDenied(_ERROR) from None

    @property
    def parameters_digest(self) -> str:
        if self._enrollment.reference != self._reference or self._enrollment.parameters_digest != self._parameters:
            raise MaterialAccessDenied(_ERROR)
        return self._parameters

    def _active(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> None:
        if self._closed or not self._enabled or type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization:
            raise MaterialAccessDenied(_ERROR)
        _require_m4_dispatch_ownership(plan, authorization, self._store)
        now = self._clock()
        if type(now) is not int or now < 0 or now < self._last:raise ValueError
        self._last = now
        plan.__post_init__();authorization.__post_init__()
        enrollment = self._enrollment
        enrollment.check_registered();enrollment._role_current()
        observed = enrollment._sources._current
        if observed is None:raise ValueError
        reference, parent = enrollment.reference, enrollment._owned.custody_digest
        scope, source = observed.full_scope.digest, observed.source_context_digest
        prepare = enrollment._prepare()
        if (plan.action_id != ACTION_ID or plan.action_version != ACTION_VERSION or plan.adapter_ref != ADAPTER_REF
                or plan.target_ref != TARGET_REF or plan.compensation_ref is not None
                or plan.parameters_digest != self.parameters_digest or plan.requester_digest != enrollment._requester
                or plan.expected_current_digest != current_digest(enrollment._draft, reference, parent, scope, source)
                or plan.expected_state_digest != expected_digest(enrollment._draft, reference, parent, scope, source)
                or authorization.plan_ref != plan.plan_ref or authorization.plan_digest != plan.plan_digest
                or authorization.requester_digest != plan.requester_digest
                or authorization.confirmation_digest != plan.confirmation_digest or authorization.approval_digest != plan.approval_digest
                or authorization.one_time is not True or authorization.execution_authorized is not True
                or not authorization.issued_at <= now < authorization.expires_at
                or authorization.expires_at > min(plan.expires_at, observed.expires_at, prepare["expires_at"])):
            raise ValueError
        self._store.verify_ready()
        claim = self._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest, authorization_digest=authorization.authorization_digest,
            context_digest=canonical_digest(dict(plan_digest=plan.plan_digest, authorization_digest=authorization.authorization_digest, revision=plan.revision)))
        if claim.result is not None:raise ValueError

    def acquire_original(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> _EmsAccountInitialLease:
        loaded: tuple[bytearray, bytearray] | None = None
        try:
            with self._lock:
                if self._attempted or (self._enrollment._directory / "material.used.json").exists():raise ValueError
                self._attempted = True;self._active(plan, authorization)
                writer = self._enrollment._take_writer(self._reference)
                try:
                    self._active(plan, authorization)
                    self._enrollment._write("material.used.json", dict(reference=self._reference, plan_digest=plan.plan_digest,
                        authorization_digest=authorization.authorization_digest, claimed_at=self._last))
                finally:self._enrollment._release_writer(writer)
                loaded = self._enrollment._loader.load_secret_create_material_once()
                if (type(loaded) is not tuple or len(loaded) != 2 or any(type(item) is not bytearray for item in loaded)
                        or loaded[0] is loaded[1] or loaded[0] != self._enrollment._draft._metadata_body["name"].encode("ascii")
                        or len(loaded[1]) != 44):raise ValueError
                with memoryview(loaded[1]) as password:
                    if not _password_valid(password):raise ValueError
                self._active(plan, authorization)
                lease = _EmsAccountInitialLease(self, *loaded, plan, authorization)
                self._lease = lease;loaded = None
                return lease
        except Exception:
            self.close();raise MaterialAccessDenied(_ERROR) from None
        finally:
            if loaded is not None:
                _clear_mutable_group(loaded, _zeroize_mutable)

    def close(self) -> None:
        with self._lock:
            self._enabled, self._closed = False, True
            if self._lease is not None:self._lease.close()
