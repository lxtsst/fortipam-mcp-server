"""Private license-file consumption within one original durable M4 dispatch.

This action-specific input is not an inventory/vault provider or a new generic
material purpose. It supplies no upload, ACK, entitlement, backup, maintenance,
restart, recovery or final send authorization.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hashlib
import hmac
from threading import RLock
import time

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import _ACTIVE_DISPATCH, _require_m4_dispatch_ownership, _reserve_m4_material_acquisition
from v4_planning.material_provider import MaterialAccessDenied, _OpaqueC3Object
from v4_planning.models import require_digest

from .license_artifact_source import LicenseArtifactSource
from .license_upload_contract import _compile_license_upload, REQUEST_SOURCE_SHA256
from .m4_execution_store import PersistentM4ExecutionStateStore

CONTRACT = "fortipam-build29-license-kernel-material-local/v1"
ADAPTER_CONTRACT = "fortipam_license_install_local_m4_candidate_v1"
ACTION = "license-install"
_ERROR = "The private license dispatch material is unavailable."


class LicenseUploadMaterialBinding(_OpaqueC3Object):
    def __init__(self, source: LicenseArtifactSource, *, target_serial_digest: str, requester_digest: str) -> None:
        try:
            if type(source) is not LicenseArtifactSource or source._used or source._closed: raise ValueError
            for value in (target_serial_digest, requester_digest): require_digest(value, "license material binding")
            self._source = source
            self._source_pin, self._guard_pin = source, source._guard_pin
            self._serial, self._requester = target_serial_digest, requester_digest
            self._path = source._path
            self._digest = canonical_digest(self._content())
            self._metadata()
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    def _content(self) -> dict[str, object]:
        source = self._source
        # The prebound artifact SHA is custody metadata, not a derived password
        # digest. No filename/path or artifact digest is exposed through MCP.
        return dict(contract=CONTRACT, request_source=REQUEST_SOURCE_SHA256,
            target=self._serial, requester=self._requester, scope=source._scope, audience=source._audience,
            artifact=source._sha, file_identity=[str(value) for value in source._identity],
            location=hashlib.sha256(str(source._path).encode()).hexdigest())

    def _metadata(self) -> None:
        source = self._source
        if (source is not self._source_pin or source._closed or source._path is not self._path
                or source._guard is not self._guard_pin or source._guard_pin is not self._guard_pin
                or source._file_identity() != source._identity
                or canonical_digest(self._content()) != self._digest): raise ValueError


def _parameters_snapshot(binding: LicenseUploadMaterialBinding, store: PersistentM4ExecutionStateStore) -> str:
    if type(binding) is not LicenseUploadMaterialBinding or type(store) is not PersistentM4ExecutionStateStore: raise ValueError
    binding._metadata()
    if not hmac.compare_digest(store._key, store._load_key()): raise ValueError
    return canonical_digest(dict(contract=CONTRACT, binding=binding._digest,
        database=hashlib.sha256(str(store._path.resolve()).encode()).hexdigest(),
        key_file=hashlib.sha256(str(store._key_path.resolve()).encode()).hexdigest(),
        key=hashlib.sha256(store._key).hexdigest(), checkpoint=store._checkpoint_store_ref,
        authority=getattr(store._monotonic_checkpoint, "authority_ref", None)))


def license_upload_material_parameters(binding: LicenseUploadMaterialBinding, store: PersistentM4ExecutionStateStore) -> str:
    if type(store) is not PersistentM4ExecutionStateStore: raise ValueError
    store.verify_ready()
    if not store.monotonic_checkpoint_protocol_bound: raise ValueError
    return _parameters_snapshot(binding, store)


class LicenseUploadDispatchMaterial(_OpaqueC3Object):
    def __init__(self, binding: LicenseUploadMaterialBinding, plan: M4ExecutionPlan,
            authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore, *,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(binding) is not LicenseUploadMaterialBinding or type(plan) is not M4ExecutionPlan
                    or type(authorization) is not M4ExecutionAuthorization or not callable(clock)): raise ValueError
            self._binding, self._plan, self._authorization, self._store = binding, plan, authorization, store
            self._pins = (binding, plan, authorization, store)
            self._checkpoint_pin, self._checkpoint_ref = store._monotonic_checkpoint, store._checkpoint_store_ref
            self._clock, self._last_now = clock, -1
            self._deadline: float | None = None
            self._closed = self._attempted = False
            self._lock = RLock()
            self._metadata()
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    def _pinned(self) -> None:
        if self._closed or any(current is not expected for current, expected in zip(
                (self._binding, self._plan, self._authorization, self._store), self._pins, strict=True)): raise ValueError
        if (self._store._monotonic_checkpoint is not self._checkpoint_pin
                or self._store._checkpoint_store_ref != self._checkpoint_ref): raise ValueError

    def _metadata(self) -> None:
        self._pinned()
        self._store.verify_ready()
        if not self._store.monotonic_checkpoint_protocol_bound: raise ValueError
        self._metadata_snapshot()

    def _metadata_snapshot(self) -> None:
        """Local metadata/file checks only; no guard, clock or checkpoint call."""
        self._pinned()
        binding, p, a = self._binding, self._plan, self._authorization
        p.__post_init__(); a.__post_init__()
        parameters = _parameters_snapshot(binding, self._store)
        if (self._closed or p.action_id != ACTION or p.action_version != "1.0.0" or p.adapter_ref != ADAPTER_CONTRACT
                or p.revision != 1 or p.compensation_ref is not None or p.parameters_digest != parameters
                or p.plan_ref != ACTION+"-"+parameters or p.target_ref != "license-appliance-"+binding._serial
                or p.requester_digest != binding._requester
                or p.idempotency_digest != canonical_digest(dict(action=ACTION, parameters=parameters))
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or a.confirmation_digest != p.confirmation_digest or a.approval_digest != p.approval_digest
                or not a.one_time or not a.execution_authorized
                or not 0 < min(p.expires_at, a.expires_at)-a.issued_at <= 60): raise ValueError

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or now < 0 or now < self._last_now:
            self._closed = True
            raise ValueError
        self._last_now = now
        return now

    def _owner(self) -> None:
        _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        scope = _ACTIVE_DISPATCH.get()
        if (scope is None or scope.plan is not self._plan or scope.authorization is not self._authorization
                or scope.store is not self._store): raise ValueError

    def _current(self) -> None:
        self._metadata()
        measured_at = time.monotonic()
        now = self._now()
        expires = min(self._plan.expires_at, self._authorization.expires_at)
        if self._deadline is None or not self._authorization.issued_at <= now < expires: raise ValueError
        self._deadline = min(self._deadline, measured_at+expires-now)
        source = self._binding._source
        # Source readiness is the last qualified callback. A later clock or
        # checkpoint callback must not revoke it before the private handoff.
        source._current()
        self._metadata_snapshot()
        if time.monotonic() >= self._deadline: raise ValueError
        self._owner()

    @contextmanager
    def _compile_once(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore) -> Iterator[memoryview]:
        """Only the original dispatch may reserve the one material slot.

        The future upload transport must independently recheck current authority,
        prerequisites and its final before-send guard. This view is not a permit.
        """
        try:
            with self._lock:
                if plan is not self._plan or authorization is not self._authorization or store is not self._store:
                    raise ValueError
                self._owner()
                if self._attempted: raise ValueError
                self._attempted = True
                self._deadline = time.monotonic() + min(plan.expires_at, authorization.expires_at)-authorization.issued_at
                # Claim before any file/clock/guard/checkpoint callback. New
                # helper/source objects cannot reset this original kernel slot.
                _reserve_m4_material_acquisition(plan, authorization, store)
                self._current()
                source = self._binding._source
                with _compile_license_upload(source, scope_digest=source._scope, audience_digest=source._audience) as body:
                    self._current()
                    yield body
                    self._current()
                # Include codec/source cleanup in the same deadline/context.
                self._current()
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    def close(self) -> None:
        self._closed = True
        with self._lock: self._pins[0]._source_pin.close()
