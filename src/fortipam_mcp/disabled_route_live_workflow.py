"""Fixed standing-lab route policy and one-process create/recovery workflow."""
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

from v4_planning import (
    M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionKernel,
    M4ExecutionPlan, canonical_digest,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .disabled_route_contract import (
    CONTRACT, DisabledRouteBinding, DisabledRoutePreparation, prepare_disabled_route,
    qualify_schema, verify_disabled_route,
)
from .disabled_route_m4_adapter import DisabledRouteM4Adapter, _RouteHttpClient
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

_ERROR = 'The fixed disabled route workflow is unavailable.'


@dataclass(frozen=True, slots=True, repr=False)
class _Preview(_OpaqueC3Object):
    phase: str
    nonce: str
    current_digest: str
    expected_digest: str
    created_at: int
    expires_at: int
    preview_ref: str


class DisabledRouteLiveWorkflow(_OpaqueC3Object):
    """Bind lab intent to authenticated operator, exact source and original M4 tuples.

    The policy is the repository's standing disposable-lab authorization. No
    user-provided target, network setting or body enters this workflow.
    """

    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: DisabledRouteBinding,
                 execution_store: PersistentM4ExecutionStateStore, *, authority_key: bytes,
                 serial_digest: str, schema_digest: str, environment_ref: str, scope_ref: str,
                 audience_ref: str, allowed_requester_digest: str, allowed_transport_digest: str,
                 create_enabled: bool = False, recovery_enabled: bool = False,
                 clock: Callable[[], int] = lambda: int(time.time()),
                 client_factory: Callable[[], Any] | None = None) -> None:
        try:
            if (type(binding) is not DisabledRouteBinding or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or hmac.compare_digest(authority_key, execution_store._key)
                    or type(create_enabled) is not bool or type(recovery_enabled) is not bool):
                raise ValueError
            for value in (serial_digest, schema_digest, allowed_requester_digest, allowed_transport_digest):
                require_digest(value, 'binding_digest')
            for value in (environment_ref, scope_ref, audience_ref):
                require_ref(value, 'namespace_ref')
            self._binding, self._store, self._key = binding, execution_store, authority_key
            self._serial, self._schema = serial_digest, schema_digest
            self._namespace = dict(environment_ref=environment_ref, scope_ref=scope_ref,
                audience_ref=audience_ref, requester_digest=allowed_requester_digest,
                transport_digest=allowed_transport_digest)
            self._enabled = {'create': create_enabled, 'recover': recovery_enabled}
            self._clock, self._last_now, self._lock = clock, -1, RLock()
            self._http = _RouteHttpClient(config, client_factory)
            self._preparation: DisabledRoutePreparation | None = None
            self._previews: dict[str, _Preview] = {}
            self._issued: dict[str, tuple[M4ExecutionPlan, M4ExecutionAuthorization]] = {}
            self._adapters: dict[str, DisabledRouteM4Adapter] = {}
            self._closed = False
        except Exception:
            raise ValueError(_ERROR) from None

    def _now(self) -> int:
        try:
            now = self._clock()
            if type(now) is not int or now < 0 or now < self._last_now or self._closed:
                raise ValueError
            self._last_now = now
            return now
        except Exception:
            self._closed = True
            raise ValueError(_ERROR) from None

    def _identity(self, requester_digest: str, transport_digest: str) -> None:
        if (self._closed or requester_digest != self._namespace['requester_digest']
                or transport_digest != self._namespace['transport_digest']):
            raise ValueError(_ERROR)

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key, b'fortipam-disabled-route-lab-v1\0' + purpose.encode() + b'\0'
            + json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode(),
            hashlib.sha256).hexdigest()

    def _context(self, preview: _Preview) -> dict[str, object]:
        return {**self._namespace, 'contract': CONTRACT, 'policy_mode': 'lab_auto',
            'binding': self._binding.parameters_digest, 'serial': self._serial, 'schema': self._schema,
            'phase': preview.phase, 'nonce': preview.nonce, 'current': preview.current_digest,
            'expected': preview.expected_digest, 'created_at': preview.created_at, 'expires_at': preview.expires_at}

    def _unconsumed(self, phase: str) -> None:
        # This pinned, dedicated ledger has only create and recovery claims.
        # Existing M4 claim_count verifies its retained integrity/checkpoint.
        expected = 0 if phase == 'create' else 1
        if self._store.claim_count != expected:
            raise ValueError(_ERROR)

    def _observe(self, phase: str) -> tuple[str, str]:
        schema = self._http._request('GET', '?action=schema&with_meta=true')
        if qualify_schema(schema, serial_digest=self._serial) != self._schema:
            raise ValueError(_ERROR)
        if phase == 'create':
            prepared = prepare_disabled_route(schema,
                self._http._request('GET', '?action=default&with_meta=true'),
                self._http._request('GET', '?with_meta=true'), serial_digest=self._serial, binding=self._binding)
            if self._preparation is not None and prepared != self._preparation:
                raise ValueError(_ERROR)
            self._preparation = prepared
            return prepared.current_digest, prepared.expected_digest
        original, retained = self._adapters.get('create'), self._preparation
        if original is None or retained is None:
            raise ValueError(_ERROR)
        original._require_verified_create()
        if not verify_disabled_route(self._http._request('GET', '?with_meta=true'), retained,
                                     serial_digest=self._serial):
            raise ValueError(_ERROR)
        return retained.expected_digest, retained.current_digest

    def preview(self, phase: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                if phase not in self._enabled:
                    raise ValueError
                self._unconsumed(phase)
                self._issued.pop(phase, None)
                self._previews.pop(phase, None)
                if phase == 'create':
                    self._preparation = None
                created = self._now()
                current, expected = self._observe(phase)
                self._unconsumed(phase)
                nonce = secrets.token_hex(24)
                preview = _Preview(phase, nonce, current, expected, created, created + 60,
                    'route-preview-' + self._mac('preview', {'phase': phase, 'nonce': nonce,
                        'current': current, 'expected': expected, 'created_at': created}))
                if self._now() >= preview.expires_at:
                    raise ValueError
                self._previews[phase] = preview
                self._issued.pop(phase, None)
                return {'contract': CONTRACT, 'phase': phase, 'policy_mode': 'lab_auto',
                    'preview_ref': preview.preview_ref, 'expires_at': preview.expires_at,
                    'Current State': {'complete_route_table_verified': True,
                        'original_creation_verified': phase == 'recover'},
                    'Proposed Changes': {'operation': phase + '_disabled_route', 'route_remains_disabled': True},
                    'Expected State': {'other_routes_preserved': True, 'original_table_restored': phase == 'recover'},
                    'device_write_executed': False}
        except Exception:
            raise ValueError(_ERROR) from None

    def _derive(self, preview: _Preview) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        context = self._context(preview)
        phase, parameters = preview.phase, self._binding.parameters_digest
        intent, approval = self._mac('intent', context), self._mac('approval', context)
        fields: dict[str, Any] = dict(plan_ref='disabled-route-' + phase + '-' + parameters,
            revision=1, action_id='disabled-route-' + phase, action_version='1.0.0', adapter_ref=CONTRACT,
            target_ref='fixed-disabled-route-' + phase, requester_digest=self._namespace['requester_digest'],
            summary_digest=self._mac('summary', context), confirmation_digest=intent, approval_digest=approval,
            parameters_digest=parameters, expected_current_digest=preview.current_digest,
            expected_state_digest=preview.expected_digest,
            idempotency_digest=canonical_digest({'binding': parameters, 'phase': phase}),
            expires_at=preview.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        fields = dict(authorization_ref='route-auth-' + self._mac('authorization', dict(context, plan=plan.plan_digest)),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref='route-intent-' + intent, confirmation_digest=intent,
            approval_ref='route-approval-' + approval, approval_digest=approval,
            approver_digest=self._mac('lab-owner', self._namespace), issued_at=preview.created_at,
            expires_at=preview.expires_at, one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**fields, authorization_digest=canonical_digest(fields))

    def authorize(self, phase: str, preview_ref: str, *, requester_digest: str,
                  transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                preview = self._previews[phase]
                if (not self._enabled[phase] or preview.preview_ref != preview_ref
                        or phase in self._issued or not preview.created_at <= self._now() < preview.expires_at):
                    raise ValueError
                self._unconsumed(phase)
                if self._observe(phase) != (preview.current_digest, preview.expected_digest):
                    self._previews.pop(phase, None)
                    raise ValueError
                self._unconsumed(phase)
                issued = self._derive(preview)
                self._issued[phase] = issued
                self.verify(*issued, now_epoch=self._now())
                return {'contract': CONTRACT, 'phase': phase, 'policy_mode': 'lab_auto',
                        'authorization_ref': issued[1].authorization_ref, 'expires_at': preview.expires_at}
        except Exception:
            raise ValueError(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                phase = plan.action_id.removeprefix('disabled-route-')
                preview, issued, now = self._previews[phase], self._issued[phase], self._now()
                if (not self._enabled[phase] or type(now_epoch) is not int
                        or not preview.created_at <= now_epoch <= now < preview.expires_at
                        or plan is not issued[0] or authorization is not issued[1]
                        or self._derive(preview) != issued):
                    raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def execute(self, phase: str, authorization_ref: str, *, requester_digest: str,
                transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                plan, authorization = self._issued[phase]
                if authorization.authorization_ref != authorization_ref:
                    raise ValueError
                self.verify(plan, authorization, now_epoch=self._now())
                if phase not in self._adapters:
                    self._unconsumed(phase)
                    if self._preparation is None:
                        raise ValueError
                    if phase == 'create':
                        adapter = DisabledRouteM4Adapter(self._http._config, self._binding, self._preparation,
                            plan, authorization, self, self._store, serial_digest=self._serial,
                            execution_enabled=self._enabled[phase], clock=self._now, client_factory=self._http._factory)
                    else:
                        adapter = self._adapters['create'].bind_recovery(plan, authorization, self,
                            execution_enabled=self._enabled[phase])
                    self._adapters[phase] = adapter
                result = M4ExecutionKernel(self._adapters[phase], self, self._store,
                    clock=self._now).execute(plan, authorization)
                return {'contract': CONTRACT, 'phase': phase, **result.as_dict()}
        except Exception:
            raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            for adapter in self._adapters.values():
                adapter._enabled = False
