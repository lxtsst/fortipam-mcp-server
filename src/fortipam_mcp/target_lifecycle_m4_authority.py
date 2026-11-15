"""Default-closed lab-auto M4 authority for four fixed Target lifecycle phases.

Only trusted composition may supply pinned source/provenance digests and enable
this authority. It does not read sources, validate ownership seals or dispatch.
The adapter must recheck fresh observations, and use the durable M4 store plus
existing terminal HTTP claims. No public Tool or runtime wiring exists here.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
from threading import RLock
import time
from typing import Any

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_ref
from .target_creation_evidence import _require_digest
from .secret_bulk_import_parent_graph import _OriginalImportTargetCreateBinding, _OriginalImportTargetUpdateBinding

_CONTRACT = 'fortipam-build29-target-lifecycle-m4-v1'
_DOMAIN = b'fortipam-target-lifecycle-lab-auto-v1\0'
_ERROR = 'Protected Target lifecycle authority unavailable.'
_PHASES = frozenset({'create', 'update', 'restore', 'recover'})
_TTL = 60


@dataclass(frozen=True, slots=True, repr=False)
class TargetLifecyclePreview(_OpaqueC3Object):
    nonce: str
    current_digest: str
    expected_digest: str
    dependency_digest: str
    created_at: int
    expires_at: int
    preview_ref: str
    signature: str


@dataclass(frozen=True, slots=True, repr=False)
class TargetLifecycleIssued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class TargetLifecycleM4Authority(_OpaqueC3Object):
    """One bound phase and actor namespace; fresh preview invalidates prior issue."""
    __slots__ = ('_key', '_binding', '_enabled', '_clock', '_last_clock', '_clock_failed',
                 '_lock', '_preview', '_issued', '_original_import')

    def __init__(self, *, phase: str, input_digest: str, source_context_digest: str,
                 original_creation_digest: str | None, verified_update_digest: str | None,
                 authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
                 requester_digest: str, transport_digest: str, execution_enabled: bool = False,
                 clock: Callable[[], int] | None = None,
                 original_import: _OriginalImportTargetCreateBinding | _OriginalImportTargetUpdateBinding | None = None) -> None:
        try:
            if (type(phase) is not str or phase not in _PHASES
                or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                or type(execution_enabled) is not bool or clock is not None and not callable(clock)):
                raise ValueError
            for value in (input_digest, source_context_digest, requester_digest, transport_digest):
                _require_digest(value)
            for value in (environment_ref, scope_ref, audience_ref):
                if type(value) is not str: raise ValueError
                require_ref(value, 'namespace_ref')
            if phase == 'create':
                if original_creation_digest is not None or verified_update_digest is not None: raise ValueError
            else:
                if type(original_import) is _OriginalImportTargetUpdateBinding:
                    if phase not in ('update', 'restore') or original_creation_digest is not None: raise ValueError
                else:
                    _require_digest(original_creation_digest)
                if phase == 'restore': _require_digest(verified_update_digest)
                elif verified_update_digest is not None: raise ValueError
            self._key, self._enabled = authority_key, execution_enabled
            self._binding = dict(contract=_CONTRACT, phase=phase, input_digest=input_digest,
                source_context_digest=source_context_digest, original_creation_digest=original_creation_digest,
                verified_update_digest=verified_update_digest, environment_ref=environment_ref,
                scope_ref=scope_ref, audience_ref=audience_ref, requester_digest=requester_digest,
                transport_digest=transport_digest, policy_mode='lab_auto')
            self._original_import = original_import
            if original_import is not None:
                if type(original_import) not in (_OriginalImportTargetCreateBinding, _OriginalImportTargetUpdateBinding):
                    raise ValueError
                parent = original_import.parent
                phases = ('create',) if type(original_import) is _OriginalImportTargetCreateBinding else ('update', 'restore')
                if (phase not in phases or input_digest != original_import.input_digest
                        or source_context_digest != original_import._source_context
                        or requester_digest != parent.requester_digest
                        or environment_ref != 'owner-file-deployment-' + parent.environment_digest
                        or scope_ref != 'owner-file-scope-' + parent.scope_digest
                        or audience_ref != 'owner-file-audience-' + parent.audience_digest):
                    raise ValueError
                self._binding.update(original_parent_digest=parent.plan_digest,
                    original_line_ref=original_import.line.line_ref)
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._last_clock: int | None = None
            self._clock_failed = False
            self._lock = RLock()
            self._preview: TargetLifecyclePreview | None = None
            self._issued: TargetLifecycleIssued | None = None
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _now(self) -> int:
        try:
            now = self._clock()
            if (self._clock_failed or type(now) is not int or now < 0
                or self._last_clock is not None and now < self._last_clock): raise ValueError
            self._last_clock = now
            return now
        except Exception:
            self._clock_failed = True
            raise M4AuthorizationDenied(_ERROR) from None

    def _identity(self, requester: str, transport: str) -> None:
        _require_digest(requester); _require_digest(transport)
        if requester != self._binding['requester_digest'] or transport != self._binding['transport_digest']:
            raise ValueError

    def _mac(self, purpose: str, value: object) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b'\0' + raw, hashlib.sha256).hexdigest()

    def _context(self, preview: TargetLifecyclePreview) -> dict[str, object]:
        return {**self._binding, 'nonce': preview.nonce, 'current_digest': preview.current_digest,
                'expected_digest': preview.expected_digest, 'dependency_digest': preview.dependency_digest,
                'created_at': preview.created_at, 'expires_at': preview.expires_at, 'action_version': '1.0.0'}

    def preview(self, *, current_digest: str, expected_digest: str, dependency_digest: str,
                requester_digest: str, transport_digest: str) -> TargetLifecyclePreview:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                for value in (current_digest, expected_digest, dependency_digest): _require_digest(value)
                now, nonce = self._now(), secrets.token_hex(24)
                expires_at = now + _TTL
                if self._original_import is not None:
                    if type(self._original_import) is _OriginalImportTargetUpdateBinding and self._binding['phase'] == 'restore':
                        self._original_import.check(now, restoring=True)
                    else:
                        self._original_import.check(now, pending=True)
                    expires_at = min(expires_at, self._original_import.parent.expires_at)
                provisional = TargetLifecyclePreview(nonce, current_digest, expected_digest,
                                                     dependency_digest, now, expires_at, '', '')
                context = self._context(provisional)
                preview = TargetLifecyclePreview(nonce, current_digest, expected_digest, dependency_digest,
                    now, expires_at, 'target-preview-' + self._mac('preview-ref', context), self._mac('preview', context))
                self._preview, self._issued = preview, None
                return preview
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _check(self, preview: TargetLifecyclePreview, now: int) -> dict[str, object]:
        until = preview.created_at + _TTL
        if self._original_import is not None:
            if type(self._original_import) is _OriginalImportTargetUpdateBinding and self._binding['phase'] == 'restore':
                self._original_import.check(now, restoring=True)
            else:
                self._original_import.check(now)
            until = min(until, self._original_import.parent.expires_at)
        if (type(preview) is not TargetLifecyclePreview or preview is not self._preview
            or type(preview.created_at) is not int or type(preview.expires_at) is not int
            or not preview.created_at <= now < preview.expires_at
            or preview.expires_at != until): raise ValueError
        context = self._context(preview)
        if (not hmac.compare_digest(preview.signature, self._mac('preview', context))
            or not hmac.compare_digest(preview.preview_ref, 'target-preview-' + self._mac('preview-ref', context))):
            raise ValueError
        return context

    def _derive(self, preview: TargetLifecyclePreview) -> TargetLifecycleIssued:
        context = self._context(preview)
        action = 'target-lifecycle-' + str(self._binding['phase'])
        requester = str(self._binding['requester_digest'])
        confirmation, approval = self._mac('standing-intent', context), self._mac('lab-policy', context)
        values: dict[str, Any] = dict(plan_ref='target-plan-' + self._mac('plan-ref', context), revision=1,
            action_id=action, action_version='1.0.0', adapter_ref=action + '-build29-v1', target_ref=action,
            requester_digest=requester, summary_digest=self._mac('summary', context),
            confirmation_digest=confirmation, approval_digest=approval,
            parameters_digest=canonical_digest({**self._binding, 'dependency_digest': preview.dependency_digest}),
            expected_current_digest=preview.current_digest, expected_state_digest=preview.expected_digest,
            idempotency_digest=self._mac('idempotency', context), expires_at=preview.expires_at, compensation_ref=None)
        if self._original_import is not None and self._binding['phase'] != 'restore':
            parent, line = self._original_import.parent, self._original_import.line
            values.update(plan_ref=parent.plan_ref, idempotency_digest=line.idempotency_digest,
                parameters_digest=line.parameters_digest, summary_digest=parent.plan_digest,
                confirmation_digest=parent.intent_policy_digest)
            confirmation = parent.intent_policy_digest
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        signed = {**context, 'plan_digest': plan.plan_digest}
        auth: dict[str, Any] = dict(authorization_ref='target-auth-' + self._mac('authorization-ref', signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=requester,
            confirmation_ref='target-intent-' + self._mac('intent-ref', signed), confirmation_digest=confirmation,
            approval_ref='target-approval-' + self._mac('approval-ref', signed), approval_digest=approval,
            approver_digest=self._mac('lab-policy-authority', self._binding), issued_at=preview.created_at,
            expires_at=preview.expires_at, one_time=True, execution_authorized=True)
        return TargetLifecycleIssued(plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)))

    def issue(self, preview: TargetLifecyclePreview, *, current_digest: str, expected_digest: str,
              dependency_digest: str, source_context_digest: str,
              requester_digest: str, transport_digest: str) -> TargetLifecycleIssued:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._check(preview, self._now())
                if self._enabled is not True or self._issued is not None: raise ValueError
                self._observation(preview, current_digest, expected_digest, dependency_digest, source_context_digest)
                issued = self._derive(preview)
                self._check(preview, self._now())
                self._issued = issued
                return issued
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _observation(self, preview: TargetLifecyclePreview, current: str, expected: str,
                     dependencies: str, source: str) -> None:
        for value in (current, expected, dependencies, source): _require_digest(value)
        if ((current, expected, dependencies) != (preview.current_digest, preview.expected_digest, preview.dependency_digest)
            or source != self._binding['source_context_digest']): raise ValueError

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                preview, issued, now = self._preview, self._issued, self._now()
                if preview is None or issued is None or self._enabled is not True: raise ValueError
                self._check(preview, now)
                if type(now_epoch) is not int or not preview.created_at <= now_epoch <= now: raise ValueError
                expected = self._derive(preview)
                if (plan is not issued.plan or authorization is not issued.authorization
                    or plan != expected.plan or authorization != expected.authorization): raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def check_current(self, issued: TargetLifecycleIssued, *, current_digest: str, expected_digest: str,
                      dependency_digest: str, source_context_digest: str) -> None:
        """Adapter uses fresh observations before/after TLS; hashes alone are not source proof."""
        try:
            with self._lock:
                if type(issued) is not TargetLifecycleIssued or issued is not self._issued: raise ValueError
                self.verify(issued.plan, issued.authorization, now_epoch=self._now())
                if self._preview is None: raise ValueError
                self._observation(self._preview, current_digest, expected_digest, dependency_digest, source_context_digest)
                self._check(self._preview, self._now())
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._preview = self._issued = None
