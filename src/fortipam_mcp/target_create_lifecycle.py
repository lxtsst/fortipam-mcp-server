"""Private one-shot Target creation through namespace preflight and durable M4."""
from __future__ import annotations

import os
from threading import RLock

from v4_planning import M4ExecutionKernel, M4ExecutionPlan
from v4_planning.execution_kernel import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionResult
from v4_planning.material_provider import _OpaqueC3Object
from . import target_preservation_contract as c
from .target_creation_evidence import _GENERATED
from .target_creation_http_transport import TargetCreationHttpTransport
from .target_namespace_preflight import TargetNamespacePreflight, TargetNamespacePreflightObservation
from .target_lifecycle_m4_authority import TargetLifecycleM4Authority, TargetLifecyclePreview, TargetLifecycleIssued
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_bulk_import_parent_graph import _OriginalImportTargetCreateBinding
from v4_planning import canonical_digest
from v4_planning.execution_kernel import M4ClaimState, M4Outcome, M4Verification, M4Compensation

_ERROR = 'Protected Target create lifecycle unavailable.'


def _configured_state_digest(state: c.TargetState) -> str:
    c._checked_state(state)
    return c._digest(('target-created-configuration-v1', state.name, state.serial_digest,
                     tuple((key, value) for key, value in state.field_digests if key not in _GENERATED)))


class TargetCreateLifecycleError(ValueError):
    """No partial result or protected input in failures."""


class TargetCreateLifecycle(_OpaqueC3Object):
    """Trusted runtime supplies pinned original creator, preflight and M4 store.

    This composition never adopts an existing object and cannot recover one.
    The creator's original input/key must remain available for a separately
    authorized recovery. Composition and transport gates are independently closed.
    """

    def __init__(self, *, creator: TargetCreationHttpTransport, preflight: TargetNamespacePreflight,
                 store: PersistentM4ExecutionStateStore, authority_key: bytes,
                 environment_ref: str, scope_ref: str, audience_ref: str,
                 requester_digest: str, transport_digest: str, execution_enabled: bool = False,
                 original_import: _OriginalImportTargetCreateBinding | None = None) -> None:
        try:
            if (type(creator) is not TargetCreationHttpTransport
                or type(preflight) is not TargetNamespacePreflight
                or type(store) is not PersistentM4ExecutionStateStore
                or type(execution_enabled) is not bool
                or creator._source_context_digest is None
                or creator._source_context_digest != preflight._source
                or creator._proposal.serial_digest != preflight._serial):
                raise ValueError
            if original_import is not None and (type(original_import) is not _OriginalImportTargetCreateBinding
                    or original_import.creator is not creator or original_import.execution is not store):
                raise ValueError
            self._creator, self._preflight, self._store = creator, preflight, store
            self._enabled, self._lock = execution_enabled, RLock()
            self._observation: TargetNamespacePreflightObservation | None = None
            self._preview: TargetLifecyclePreview | None = None
            self._issued: TargetLifecycleIssued | None = None
            self._expected = _configured_state_digest(creator._proposal)
            self._absence = c._digest(('target-actor-visible-absence-v1',
                                      creator._proposal.name, creator._proposal.serial_digest))
            self._identity = dict(requester_digest=requester_digest, transport_digest=transport_digest)
            with creator._lock() as directory:
                self._pending(directory)
            self._authority = TargetLifecycleM4Authority(phase='create',
                input_digest=c._digest((creator._namespace, creator._body_digest, creator._proposal.state_digest)),
                source_context_digest=creator._source_context_digest,
                original_creation_digest=None, verified_update_digest=None, authority_key=authority_key,
                environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref,
                execution_enabled=execution_enabled, clock=creator._now,
                original_import=original_import, **self._identity)
        except Exception:
            raise TargetCreateLifecycleError(_ERROR) from None

    def _pending(self, directory: int) -> None:
        for suffix in ('coordinator.claim.json', 'claim.json', 'absent.json', 'response.json', 'ack.json', 'verified.json'):
            try: os.stat('create.'+suffix, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError: continue
            raise ValueError

    def _unconsumed(self) -> None:
        binding = self._authority._original_import
        if binding is not None:
            binding.check(self._creator._now(), pending=True)
        with self._creator._lock() as directory:
            self._pending(directory)

    def _inspect_verified_import_target(self) -> c.TargetState:
        """Join original parent/M4/creation seal and a fresh full native read."""
        with self._lock:
            try:
                binding, issued = self._authority._original_import, self._issued
                if binding is None or issued is None:
                    raise ValueError
                binding.check(self._creator._now(), completed=True)
                claim = self._store.inspect_claim(plan_ref=issued.plan.plan_ref,
                    requester_digest=issued.plan.requester_digest, idempotency_digest=issued.plan.idempotency_digest,
                    context_digest=canonical_digest({'plan_digest': issued.plan.plan_digest,
                        'authorization_digest': issued.authorization.authorization_digest, 'revision': issued.plan.revision}),
                    authorization_digest=issued.authorization.authorization_digest)
                result = claim.result
                if (claim.state is not M4ClaimState.REPLAY or result is None
                        or result.outcome is not M4Outcome.SUCCEEDED
                        or result.verification is not M4Verification.VERIFIED
                        or result.compensation is not M4Compensation.NOT_REQUESTED):
                    raise ValueError
                evidence = self._creator.load_creation_evidence()
                current = self._creator.read_current(expires_at=issued.plan.expires_at, before_send=self._source_guard)
                if (current != evidence.created or _configured_state_digest(current) != issued.plan.expected_state_digest
                        or self._creator.load_creation_evidence() != evidence):
                    raise ValueError
                binding.check(self._creator._now(), completed=True)
                return current
            except Exception:
                raise TargetCreateLifecycleError(_ERROR) from None

    def _source_guard(self) -> None:
        observed = self._observation
        if observed is None or not observed.candidate_absent:
            raise ValueError
        self._preflight.check_transport_source(observed, candidate_name=self._creator._proposal.name,
                                               transport=self._creator)

    def _refresh(self, expires_at: int) -> str:
        self._observation = None
        observed = self._preflight.observe(self._creator._proposal.name, (self._creator._proposal.coordinates,))
        self._observation = observed
        self._source_guard()
        return self._creator.read_absence(expires_at=expires_at, before_send=self._source_guard)

    def _values(self) -> dict[str, str]:
        observed = self._observation
        if observed is None:
            raise ValueError
        return dict(current_digest=self._absence, expected_digest=self._expected,
            dependency_digest=c._digest((observed.dependency_digest, observed.namespace_digest,
                                         observed.api_witness_digest, observed.candidate_digest)),
            source_context_digest=observed.source_context_digest)

    def preview(self) -> TargetLifecyclePreview:
        with self._lock:
            try:
                self._preview = self._issued = None
                self._unconsumed()
                if self._refresh(self._creator._now()+60) != self._absence: raise ValueError
                self._unconsumed()
                values = self._values(); values.pop('source_context_digest')
                self._preview = self._authority.preview(**values, **self._identity)
                return self._preview
            except Exception:
                raise TargetCreateLifecycleError(_ERROR) from None

    def issue(self, preview: TargetLifecyclePreview) -> TargetLifecycleIssued:
        with self._lock:
            try:
                if preview is not self._preview or self._issued is not None: raise ValueError
                self._unconsumed()
                if self._refresh(preview.expires_at) != self._absence: raise ValueError
                self._unconsumed()
                self._issued = self._authority.issue(preview, **self._values(), **self._identity)
                return self._issued
            except Exception:
                raise TargetCreateLifecycleError(_ERROR) from None

    def _guard(self) -> None:
        if self._issued is None: raise ValueError
        self._source_guard()
        self._authority.check_current(self._issued, **self._values())

    def execute(self, issued: TargetLifecycleIssued) -> M4ExecutionResult:
        with self._lock:
            try:
                if issued is not self._issued or not self._enabled or not self._creator._enabled: raise ValueError
                self._unconsumed()
                if self._refresh(issued.plan.expires_at) != self._absence: raise ValueError
                self._guard()
                with self._creator._lock() as directory:
                    self._pending(directory)
                    self._creator._write(directory, 'create.coordinator.claim.json',
                        dict(namespace=self._creator._namespace, plan_digest=issued.plan.plan_digest,
                             authorization_digest=issued.authorization.authorization_digest))
                return M4ExecutionKernel(_KernelAdapter(self), self._authority, self._store,
                                         clock=self._creator._now).execute(issued.plan, issued.authorization)
            except Exception:
                raise TargetCreateLifecycleError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._authority.close()
            self._observation = self._preview = self._issued = None


class _KernelAdapter:
    def __init__(self, owner: TargetCreateLifecycle) -> None:
        self._owner = owner

    def _check(self, plan: M4ExecutionPlan) -> TargetLifecycleIssued:
        issued = self._owner._issued
        if issued is None or plan is not issued.plan: raise ValueError
        self._owner._guard()
        return issued

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self._check(plan)
            return self._owner._creator.read_absence(expires_at=plan.expires_at,
                                                     before_send=self._owner._guard)
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        try:
            issued = self._check(plan)
            self._owner._creator.create(plan_digest=plan.plan_digest,
                authorization_digest=issued.authorization.authorization_digest,
                expires_at=plan.expires_at, before_send=self._owner._guard)
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self._check(plan)
            owner = self._owner
            current = owner._creator.read_current(expires_at=plan.expires_at, before_send=owner._guard)
            # Full created identity and metadata are authenticated by the original
            # ACK seal; only generated fields are excluded from the planned result.
            if owner._creator.load_creation_evidence().created != current: raise ValueError
            owner._guard()
            return _configured_state_digest(current)
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None
