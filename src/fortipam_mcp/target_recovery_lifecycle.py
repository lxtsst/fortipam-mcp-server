"""Independent original-ACK Target recovery through the durable M4 kernel."""
from __future__ import annotations

import os
from threading import RLock

from v4_planning import M4ExecutionKernel, M4ExecutionPlan
from v4_planning.execution_kernel import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionResult
from v4_planning.material_provider import _OpaqueC3Object
from . import target_preservation_contract as c
from .target_creation_http_transport import TargetCreationHttpTransport
from .target_api_dependency_reader import TargetApiDependencyReader, TargetApiDependencyObservation
from .target_qualified_reference_reader import FortiPamTargetQualifiedReferenceReader
from .target_lifecycle_m4_authority import TargetLifecycleM4Authority, TargetLifecyclePreview, TargetLifecycleIssued
from .m4_execution_store import PersistentM4ExecutionStateStore
from .windows_target_owner_recovery import WindowsTargetOwnerRecovery

_ERROR = 'Protected Target recovery lifecycle unavailable.'


class TargetRecoveryLifecycleError(ValueError):
    """No original private material or partial result in failures."""


class TargetRecoveryLifecycle(_OpaqueC3Object):
    """A distinct recovery phase bound to original ownership and exact current state.

    The trusted runtime retains the original creator input/key and supplies the
    expected complete state. Coordinate changes may differ from the created
    baseline; every other original field and metadata fingerprint must match.
    No unknown or lost-ACK creation can be adopted by this composition.
    """

    def __init__(self, *, creator: TargetCreationHttpTransport, expected_current: c.TargetState,
                 reader: TargetApiDependencyReader, references: FortiPamTargetQualifiedReferenceReader,
                 store: PersistentM4ExecutionStateStore, authority_key: bytes,
                 environment_ref: str, scope_ref: str, audience_ref: str,
                 requester_digest: str, transport_digest: str, execution_enabled: bool = False,
                 owner_recovery: WindowsTargetOwnerRecovery | None = None) -> None:
        try:
            if (type(creator) is not TargetCreationHttpTransport
                or type(reader) is not TargetApiDependencyReader
                or type(references) is not FortiPamTargetQualifiedReferenceReader
                or type(store) is not PersistentM4ExecutionStateStore
                or type(execution_enabled) is not bool): raise ValueError
            c._checked_state(expected_current)
            self._creator, self._reader, self._references, self._store = creator, reader, references, store
            self._original = creator.load_creation_evidence()
            if creator._owner_read_source is not None:
                if (type(owner_recovery) is not WindowsTargetOwnerRecovery
                    or owner_recovery._namespace._api is reader):
                    raise ValueError
                owner_recovery.check_binding(creator, self._original, expected_current)
            elif owner_recovery is not None:
                raise ValueError
            self._owner_recovery = owner_recovery
            if (expected_current.name != self._original.created.name
                or expected_current.serial_digest != self._original.created.serial_digest
                or expected_current.preserved_digest != self._original.created.preserved_digest
                or creator._source_context_digest is None
                or creator._source_context_digest != reader._source
                or references._serial_digest != self._original.created.serial_digest): raise ValueError
            self._current = expected_current
            self._expected = (c._digest(('target-actor-visible-absence-v1',
                expected_current.name, expected_current.serial_digest)) if owner_recovery is None else owner_recovery.expected_digest)
            self._enabled, self._lock = execution_enabled, RLock()
            self._observation: TargetApiDependencyObservation | None = None
            self._preview: TargetLifecyclePreview | None = None
            self._issued: TargetLifecycleIssued | None = None
            self._expires_at: int | None = None
            self._identity = dict(requester_digest=requester_digest, transport_digest=transport_digest)
            with creator._lock() as directory:
                self._pending(directory)
            self._authority = TargetLifecycleM4Authority(phase='recover',
                input_digest=c._digest((creator._namespace, self._original.evidence_digest,
                    expected_current.state_digest, *(() if owner_recovery is None else (owner_recovery.binding_digest,)))),
                source_context_digest=creator._source_context_digest,
                original_creation_digest=self._original.evidence_digest, verified_update_digest=None,
                authority_key=authority_key, environment_ref=environment_ref, scope_ref=scope_ref,
                audience_ref=audience_ref, execution_enabled=execution_enabled,
                clock=creator._now, requester_digest=requester_digest,
                transport_digest=transport_digest)
        except Exception:
            raise TargetRecoveryLifecycleError(_ERROR) from None

    def _pending(self, directory: int) -> None:
        for suffix in ('coordinator.claim.json', 'claim.json', 'response.json', 'ack.json', 'verified.json'):
            try: os.stat('delete.'+suffix, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError: continue
            raise ValueError

    def _unconsumed(self) -> None:
        with self._creator._lock() as directory:
            self._pending(directory)

    def _source_guard(self) -> None:
        observed = self._observation
        if (observed is None or self._expires_at is None
            or self._creator._now() >= self._expires_at
            or self._references._serial_digest != self._original.created.serial_digest): raise ValueError
        self._reader.check_transport_source(observed, self._creator)
        if self._creator._now() >= self._expires_at: raise ValueError

    def _ownership_guard(self) -> None:
        self._source_guard()
        if self._creator.load_creation_evidence() != self._original: raise ValueError
        self._source_guard()

    def _reference_count(self, name: str) -> int:
        if name != self._original.created.name: raise ValueError
        self._source_guard()
        count = self._references.reference_count(name)
        self._source_guard()
        if type(count) is not int or count != 0: raise ValueError
        return count

    def _refresh(self, expires_at: int) -> c.TargetState:
        self._observation = None
        if type(expires_at) is not int or not 0 < expires_at-self._creator._now() <= 60: raise ValueError
        self._expires_at = expires_at
        self._observation = self._reader.observe((self._original.created.coordinates, self._current.coordinates))
        self._ownership_guard()
        current = self._creator.read_current(expires_at=expires_at, before_send=self._ownership_guard)
        if current != self._current: raise ValueError
        self._reference_count(current.name)
        if self._owner_recovery is not None:
            self._owner_recovery.inspect(expires_at=expires_at, before_send=self._ownership_guard)
        self._ownership_guard()
        return current

    def _values(self) -> dict[str, str]:
        if self._observation is None: raise ValueError
        return dict(current_digest=self._current.state_digest, expected_digest=self._expected,
            dependency_digest=c._digest((self._observation.dependencies.dependency_digest,
                self._original.evidence_digest, 'same-device-reference-count-zero',
                *(() if self._owner_recovery is None else (self._owner_recovery.binding_digest, self._owner_recovery.role_digest)))),
            source_context_digest=self._observation.source_context_digest)

    def preview(self) -> TargetLifecyclePreview:
        with self._lock:
            try:
                self._preview = self._issued = None
                self._unconsumed()
                self._refresh(self._creator._now()+60)
                self._unconsumed()
                values = self._values(); values.pop('source_context_digest')
                self._preview = self._authority.preview(**values, **self._identity)
                return self._preview
            except Exception:
                raise TargetRecoveryLifecycleError(_ERROR) from None

    def issue(self, preview: TargetLifecyclePreview) -> TargetLifecycleIssued:
        with self._lock:
            try:
                if preview is not self._preview or self._issued is not None: raise ValueError
                self._unconsumed()
                self._refresh(preview.expires_at)
                self._unconsumed()
                self._issued = self._authority.issue(preview, **self._values(), **self._identity)
                return self._issued
            except Exception:
                raise TargetRecoveryLifecycleError(_ERROR) from None

    def _guard(self) -> None:
        self._ownership_guard()
        self._dispatch_guard()

    def _dispatch_guard(self) -> None:
        # recover() holds the creator lock and checks the pinned evidence digest,
        # then revalidates that same seal internally around every network step.
        if self._issued is None: raise ValueError
        self._source_guard()
        self._authority.check_current(self._issued, **self._values())

    def execute(self, issued: TargetLifecycleIssued) -> M4ExecutionResult:
        with self._lock:
            try:
                if issued is not self._issued or not self._enabled or not self._creator._recovery_enabled:
                    raise ValueError
                if self._owner_recovery is not None and not self._owner_recovery._enabled:
                    raise ValueError
                self._unconsumed()
                self._refresh(issued.plan.expires_at)
                self._guard()
                with self._creator._lock() as directory:
                    self._pending(directory)
                    self._creator._write(directory, 'delete.coordinator.claim.json',
                        dict(namespace=self._creator._namespace, plan_digest=issued.plan.plan_digest,
                             authorization_digest=issued.authorization.authorization_digest))
                return M4ExecutionKernel(_KernelAdapter(self), self._authority, self._store,
                                         clock=self._creator._now).execute(issued.plan, issued.authorization)
            except Exception:
                raise TargetRecoveryLifecycleError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._authority.close()
            self._observation = self._preview = self._issued = None
            self._expires_at = None
            if self._owner_recovery is not None:
                self._owner_recovery.close()


class _KernelAdapter:
    def __init__(self, owner: TargetRecoveryLifecycle) -> None:
        self._owner = owner

    def _check(self, plan: M4ExecutionPlan) -> TargetLifecycleIssued:
        issued = self._owner._issued
        if issued is None or plan is not issued.plan: raise ValueError
        self._owner._guard()
        return issued

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self._check(plan)
            return self._owner._creator.read_current(expires_at=plan.expires_at,
                                                     before_send=self._owner._guard).state_digest
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        try:
            issued = self._check(plan); owner = self._owner
            owner._creator.recover(expected_current=owner._current, plan_digest=plan.plan_digest,
                authorization_digest=issued.authorization.authorization_digest, expires_at=plan.expires_at,
                before_send=owner._dispatch_guard, reference_count=owner._reference_count,
                creation_evidence_digest=owner._original.evidence_digest, owner_recovery=owner._owner_recovery)
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self._check(plan)
            if self._owner._owner_recovery is not None:
                raw, _ = self._owner._owner_recovery.observe_absence(expires_at=plan.expires_at,
                    before_send=self._owner._guard)
                from .secret_metadata_http_transport import _zeroize_mutable
                _zeroize_mutable(raw)
                return self._owner._owner_recovery.expected_digest
            return self._owner._creator.read_absence(expires_at=plan.expires_at,
                                                     before_send=self._owner._guard)
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None
