"""Private update/restore composition for a pinned Target.

No public Tool or live runtime wiring. Trusted runtime supplies pinned original
creator, coordinate adapter, dependency reader and durable M4 store. Create and
recovery remain separate independently authorized phases.
"""
from __future__ import annotations

import os
from threading import RLock
from typing import Literal

from v4_planning import M4ExecutionKernel, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import (M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionResult,
    M4ClaimState, M4Outcome, M4Verification, M4Compensation)
from v4_planning.material_provider import _OpaqueC3Object
from . import target_preservation_contract as c
from . import target_preservation_http_transport as t
from .m4_execution_store import PersistentM4ExecutionStateStore
from .target_api_dependency_reader import TargetApiDependencyObservation, TargetApiDependencyReader
from .target_creation_evidence import TargetCreationEvidence
from .target_creation_http_transport import TargetCreationHttpTransport
from .target_lifecycle_m4_authority import TargetLifecycleM4Authority, TargetLifecyclePreview, TargetLifecycleIssued
from .secret_bulk_import_parent_graph import _OriginalImportTargetUpdateBinding

_ERROR = 'Protected Target coordinate lifecycle unavailable.'


class TargetCoordinateLifecycleError(ValueError):
    """No protected input or partial response in failures."""


def _updated(change: c.TargetCoordinateChange) -> c.TargetState:
    c._checked_change(change)
    fields = tuple((key,c._digest(getattr(change.desired,key)) if key in c._COORDINATES else value)
                   for key,value in change.baseline.field_digests)
    state, preserved = c._state_digests(change.baseline.name,change.baseline.serial_digest,
                                      fields,change.baseline.metadata_digests)
    result = c.TargetState(change.baseline.name,change.baseline.serial_digest,change.desired,
                           fields,change.baseline.metadata_digests,state,preserved)
    c._checked_state(result)
    return result


class TargetCoordinateLifecycle(_OpaqueC3Object):
    """One bound phase; every execution attempt reserves it durably before M4."""

    _phase: Literal['update','restore']
    _creator: TargetCreationHttpTransport | None
    _transport: t.TargetCoordinateHttpTransport
    _reader: TargetApiDependencyReader
    _store: PersistentM4ExecutionStateStore
    _original: TargetCreationEvidence | None
    _import: _OriginalImportTargetUpdateBinding | None
    _baseline: c.TargetState
    _updated: c.TargetState
    _current: c.TargetState
    _expected: c.TargetState
    _enabled: bool
    _lock: RLock
    _identity: dict[str,str]
    _authority: TargetLifecycleM4Authority
    _update_digest: str | None

    def __init__(self, *, phase: Literal['update','restore'], creator: TargetCreationHttpTransport | None,
                 transport: t.TargetCoordinateHttpTransport, reader: TargetApiDependencyReader,
                 store: PersistentM4ExecutionStateStore, authority_key: bytes,
                 environment_ref: str, scope_ref: str, audience_ref: str,
                 requester_digest: str, transport_digest: str, execution_enabled: bool = False,
                 original_import: _OriginalImportTargetUpdateBinding | None = None) -> None:
        try:
            if (type(phase) is not str or phase not in ('update','restore')
                or type(transport) is not t.TargetCoordinateHttpTransport
                or type(reader) is not TargetApiDependencyReader
                or type(store) is not PersistentM4ExecutionStateStore
                or type(execution_enabled) is not bool):
                raise ValueError
            self._phase, self._creator, self._transport, self._reader, self._store = phase,creator,transport,reader,store
            self._import = original_import
            self._baseline = transport._change.baseline
            if original_import is None:
                if type(creator) is not TargetCreationHttpTransport or creator._identity == transport._identity:
                    raise ValueError
                self._original = creator.load_creation_evidence()
                if self._original.created != self._baseline: raise ValueError
                input_digest = c._digest((creator._namespace,transport._namespace,self._original.evidence_digest))
                creation_digest = self._original.evidence_digest
            else:
                if (type(original_import) is not _OriginalImportTargetUpdateBinding or creator is not None
                        or original_import.transport is not transport or original_import.execution is not store):
                    raise ValueError
                original_import.check(transport._now(), pending=phase=='update', restoring=phase=='restore')
                self._original = None
                input_digest, creation_digest = original_import.input_digest, None
            self._updated = _updated(transport._change)
            self._current = self._baseline if phase=='update' else self._updated
            self._expected = self._updated if phase=='update' else self._baseline
            self._enabled, self._lock = execution_enabled,RLock()
            self._observation: TargetApiDependencyObservation | None = None
            self._preview: TargetLifecyclePreview | None = None
            self._issued: TargetLifecycleIssued | None = None
            with transport._lock() as directory:
                self._pending(directory)
                update_digest = self._update_proof(directory) if phase=='restore' else None
            source = transport._source_context_digest
            if source is None or creator is not None and creator._source_context_digest != source: raise ValueError
            self._identity = dict(requester_digest=requester_digest,transport_digest=transport_digest)
            self._authority = TargetLifecycleM4Authority(phase=phase,
                input_digest=input_digest,
                source_context_digest=source, original_creation_digest=creation_digest,
                verified_update_digest=update_digest,authority_key=authority_key,
                environment_ref=environment_ref,scope_ref=scope_ref,audience_ref=audience_ref,
                execution_enabled=execution_enabled,clock=transport._now,
                original_import=original_import,**self._identity)
            self._update_digest = update_digest
        except Exception:
            raise TargetCoordinateLifecycleError(_ERROR) from None

    def _pending(self, directory: int) -> None:
        for suffix in ('coordinator.claim.json','claim.json','ack.json','verified.json'):
            try: os.stat(self._phase+'.'+suffix,dir_fd=directory,follow_symlinks=False)
            except FileNotFoundError: continue
            raise ValueError

    def _update_proof(self, directory: int) -> str:
        records = [self._transport._read(directory,'update.'+suffix)
                   for suffix in ('claim.json','ack.json','verified.json')]
        claim, ack, verified = records
        if (ack.get('claim_digest') != t._digest(claim)
            or verified.get('claim_digest') != t._digest(claim)
            or verified.get('ack_digest') != t._digest(ack)
            or verified.get('state_digest') != self._updated.state_digest): raise ValueError
        if self._import is not None:
            binding = self._import
            coordinator = self._transport._read(directory, 'update.coordinator.claim.json')
            plan_digest, authorization_digest = coordinator.get('plan_digest'), coordinator.get('authorization_digest')
            if (coordinator.get('namespace') != self._transport._namespace
                    or claim.get('plan_digest') != plan_digest
                    or claim.get('authorization_digest') != authorization_digest
                    or type(plan_digest) is not str or type(authorization_digest) is not str
                    or binding.line.idempotency_digest is None): raise ValueError
            original = self._store.inspect_claim(plan_ref=binding.parent.plan_ref,
                requester_digest=binding.parent.requester_digest, idempotency_digest=binding.line.idempotency_digest,
                context_digest=canonical_digest({'plan_digest': plan_digest,
                    'authorization_digest': authorization_digest, 'revision': 1}),
                authorization_digest=authorization_digest)
            result = original.result
            if (original.state is not M4ClaimState.REPLAY or result is None
                    or result.outcome is not M4Outcome.SUCCEEDED or result.verification is not M4Verification.VERIFIED
                    or result.compensation is not M4Compensation.NOT_REQUESTED): raise ValueError
            records.append(coordinator)
        return c._digest(tuple(records))

    def _unconsumed(self) -> None:
        if self._import is not None:
            self._import.check(self._transport._now(), pending=self._phase=='update', restoring=self._phase=='restore')
        with self._transport._lock() as directory:
            self._pending(directory)
            if self._phase=='restore' and self._update_proof(directory)!=self._update_digest:
                raise ValueError

    def _source_guard(self, *, completed: bool = False) -> None:
        observed = self._observation
        if observed is None: raise ValueError
        self._reader.check_transport_source(observed,self._transport)
        if self._import is not None:
            self._import.check(self._transport._now(), completed=completed, restoring=self._phase=='restore')
        else:
            if self._creator is None: raise ValueError
            self._reader.check_transport_source(observed,self._creator)
            if self._creator.load_creation_evidence() != self._original: raise ValueError
        self._reader.check_transport_source(observed,self._transport)

    def _refresh(self, expires_at: int, *, completed: bool = False) -> c.TargetState:
        self._observation = None
        coordinates = (self._baseline.coordinates,self._transport._change.desired)
        observed = self._reader.observe(coordinates)
        self._observation = observed
        guard = lambda: self._source_guard(completed=completed)
        guard()
        return self._transport.read_current(expires_at=expires_at,before_send=guard)

    def _inspect_verified_import_target(self) -> c.TargetState:
        """Require the original successful M4 update and a fresh unchanged full Target."""
        with self._lock:
            try:
                binding = self._import
                if binding is None or self._phase != 'update': raise ValueError
                binding.check(self._transport._now(), completed=True)
                with self._transport._lock() as directory:
                    self._update_proof(directory)
                    for suffix in ('coordinator.claim.json', 'claim.json', 'ack.json', 'verified.json'):
                        try: os.stat('restore.'+suffix, dir_fd=directory, follow_symlinks=False)
                        except FileNotFoundError: continue
                        raise ValueError
                current = self._refresh(binding.parent.expires_at, completed=True)
                if current != self._updated: raise ValueError
                binding.check(self._transport._now(), completed=True)
                return current
            except Exception:
                raise TargetCoordinateLifecycleError(_ERROR) from None

    def _values(self) -> dict[str,str]:
        if self._observation is None: raise ValueError
        return dict(current_digest=self._current.state_digest,expected_digest=self._expected.state_digest,
            dependency_digest=self._observation.dependencies.dependency_digest,
            source_context_digest=self._observation.source_context_digest)

    def preview(self) -> TargetLifecyclePreview:
        with self._lock:
            try:
                self._preview = self._issued = None
                self._unconsumed()
                current = self._refresh(self._transport._now()+60)
                if current != self._current: raise ValueError
                self._unconsumed()
                values = self._values();values.pop('source_context_digest')
                self._preview = self._authority.preview(**values,**self._identity)
                return self._preview
            except Exception:
                raise TargetCoordinateLifecycleError(_ERROR) from None

    def issue(self, preview: TargetLifecyclePreview) -> TargetLifecycleIssued:
        with self._lock:
            try:
                if preview is not self._preview or self._issued is not None: raise ValueError
                self._unconsumed()
                if self._refresh(preview.expires_at) != self._current: raise ValueError
                self._unconsumed()
                self._issued = self._authority.issue(preview,**self._values(),**self._identity)
                return self._issued
            except Exception:
                raise TargetCoordinateLifecycleError(_ERROR) from None

    def _guard(self) -> None:
        if self._issued is None: raise ValueError
        self._source_guard()
        self._authority.check_current(self._issued,**self._values())

    def execute(self, issued: TargetLifecycleIssued) -> M4ExecutionResult:
        with self._lock:
            try:
                if issued is not self._issued or not self._enabled or not self._transport._enabled:
                    raise ValueError
                self._unconsumed()
                if self._refresh(issued.plan.expires_at) != self._current: raise ValueError
                self._guard()
                with self._transport._lock() as directory:
                    self._pending(directory)
                    if self._phase=='restore' and self._update_proof(directory)!=self._update_digest: raise ValueError
                    self._transport._write(directory,self._phase+'.coordinator.claim.json',
                        dict(namespace=self._transport._namespace,plan_digest=issued.plan.plan_digest,
                             authorization_digest=issued.authorization.authorization_digest))
                return M4ExecutionKernel(_KernelAdapter(self),self._authority,self._store,
                    clock=self._transport._now).execute(issued.plan,issued.authorization)
            except Exception:
                raise TargetCoordinateLifecycleError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._authority.close()
            self._observation = self._preview = self._issued = None


class _KernelAdapter:
    def __init__(self, owner: TargetCoordinateLifecycle) -> None:
        self._owner = owner

    def _check(self, plan: M4ExecutionPlan) -> TargetLifecycleIssued:
        owner = self._owner
        issued = owner._issued
        if issued is None or plan is not issued.plan: raise ValueError
        owner._guard()
        return issued

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self._check(plan)
            return self._owner._transport.read_current(expires_at=plan.expires_at,
                before_send=self._owner._guard).state_digest
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        try:
            issued = self._check(plan)
            owner = self._owner
            owner._transport.dispatch(phase=owner._phase,plan_digest=plan.plan_digest,
                authorization_digest=issued.authorization.authorization_digest,expires_at=plan.expires_at,
                before_send=owner._guard,updated=owner._updated if owner._phase=='restore' else None)
        except Exception:
            # Transport failures can follow a PUT; never label them safe to retry.
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self._check(plan)
            return self._owner._transport.read_current(expires_at=plan.expires_at,
                before_send=self._owner._guard).state_digest
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None
