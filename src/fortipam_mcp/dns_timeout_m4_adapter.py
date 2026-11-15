"""Default-closed fixed DNS update/recovery adapter for the existing M4 kernel.

Trusted runtime composition must supply real server-issued authorization. This
module issues no authority and registers no public Tool. Recovery is available
only in the original process after its own acknowledged, M4-verified update;
a matching state, a new process or a consumed claim cannot establish ownership.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
from threading import RLock
import time
from typing import Any

import httpx
from v4_planning import (
    M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationVerifier,
    M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest,
)
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .dns_timeout_contract import (
    CONTRACT, PATH, DnsTimeoutBinding, DnsTimeoutPreparation,
    prepare_dns_timeout, qualify_schema, verify_dns_timeout, _envelope,
)
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context
from .target_api_dependency_reader import _private_http_logs

_ERROR = 'The fixed DNS timeout execution is unavailable.'


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class _DnsHttpClient(_OpaqueC3Object):
    """Shared private fixed-route I/O for preview and original dispatch."""

    def __init__(self, config: SecretMetadataHttpTransportConfig,
                 client_factory: Callable[[], Any] | None = None) -> None:
        if type(config) is not SecretMetadataHttpTransportConfig:
            raise M4AdapterDenied(_ERROR)
        self._config, self._factory = config, client_factory

    def _client(self) -> Any:
        if self._factory is not None:
            return self._factory()
        return httpx.Client(base_url=self._config.base_url, verify=_ssl_context(self._config),
            timeout=self._config.timeout_seconds, follow_redirects=False, trust_env=False,
            headers={'Authorization': 'Bearer ' + self._config.bearer_token})

    def _request(self, method: str, suffix: str = '', body: bytes | None = None) -> dict[str, Any]:
        # All callers below use fixed routes. No request selector crosses MCP.
        try:
            with _private_http_logs(), self._client() as client:
                with client.stream(method, PATH + suffix, content=body,
                    headers={'Content-Type': 'application/json'}) as response:
                    raw = bytearray()
                    try:
                        for chunk in response.iter_bytes():
                            raw.extend(chunk)
                            if len(raw) > 1048576:
                                raise ValueError
                        if response.status_code != 200:
                            raise ValueError
                        payload = json.loads(raw, object_pairs_hook=_pairs)
                        if type(payload) is not dict:
                            raise ValueError
                        return payload
                    finally:
                        raw[:] = b'\0' * len(raw)
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

class DnsTimeoutM4Adapter(_DnsHttpClient):
    """One exact PUT or owned restoration PUT, guarded by the original M4 dispatch."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: DnsTimeoutBinding,
                 preparation: DnsTimeoutPreparation, plan: M4ExecutionPlan,
                 authorization: M4ExecutionAuthorization, verifier: M4AuthorizationVerifier,
                 store: PersistentM4ExecutionStateStore, *, serial_digest: str,
                 execution_enabled: bool = False, clock: Callable[[], int] = lambda: int(time.time()),
                 client_factory: Callable[[], Any] | None = None) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(binding) is not DnsTimeoutBinding
                    or type(preparation) is not DnsTimeoutPreparation
                    or type(store) is not PersistentM4ExecutionStateStore
                    or type(execution_enabled) is not bool or not callable(clock)):
                raise ValueError
            require_digest(serial_digest, 'serial_digest')
            super().__init__(config, client_factory)
            self._binding, self._preparation = binding, preparation
            self._plan, self._authorization, self._verifier, self._store = plan, authorization, verifier, store
            self._serial, self._enabled, self._clock = serial_digest, execution_enabled, clock
            self._lock = RLock()
            self._last_now = -1
            self._dispatched = self._acknowledged = False
            self._original: DnsTimeoutM4Adapter | None = None
            self._check_plan()
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _check_plan(self) -> None:
        phase = 'update' if self._original is None else 'recover'
        p, a, prepared = self._plan, self._authorization, self._preparation
        if (type(p) is not M4ExecutionPlan or type(a) is not M4ExecutionAuthorization
                or p.action_id != 'dns-timeout-' + phase or p.action_version != '1.0.0'
                or p.adapter_ref != CONTRACT or p.compensation_ref is not None
                or p.parameters_digest != self._binding.parameters_digest
                or prepared.parameters_digest != self._binding.parameters_digest
                or prepared.current_digest != self._binding.baseline_digest
                or hashlib.sha256(prepared.original_bytes).hexdigest() != prepared.current_digest
                or hashlib.sha256(prepared.body_bytes).hexdigest() != prepared.expected_digest
                or json.loads(prepared.body_bytes) != dict(json.loads(prepared.original_bytes), timeout=6)
                or json.loads(prepared.original_bytes).get('timeout') != 5
                or p.plan_ref != 'dns-timeout-' + phase + '-' + p.parameters_digest
                or p.idempotency_digest != canonical_digest({'binding': p.parameters_digest, 'phase': phase})
                or p.expected_current_digest != (prepared.current_digest if phase == 'update' else prepared.expected_digest)
                or p.expected_state_digest != (prepared.expected_digest if phase == 'update' else prepared.current_digest)
                or a.plan_digest != p.plan_digest or a.plan_ref != p.plan_ref
                or a.requester_digest != p.requester_digest):
            raise ValueError
        p.__post_init__()
        a.__post_init__()

    def _check(self, plan: M4ExecutionPlan) -> None:
        try:
            if not self._enabled or plan is not self._plan:
                raise ValueError
            self._check_plan()
            now = self._clock()
            if (type(now) is not int or now < self._last_now
                    or not self._authorization.issued_at <= now < min(plan.expires_at, self._authorization.expires_at)):
                self._enabled = False
                raise ValueError
            self._last_now = now
            self._verifier.verify(plan, self._authorization, now_epoch=now)
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _original_verified(self) -> None:
        if self._original is None:
            raise ValueError
        self._original._require_verified_update()

    def _require_verified_update(self) -> None:
        if self._original is not None or not self._acknowledged:
            raise ValueError
        p, a = self._plan, self._authorization
        claim = self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest({'plan_digest': p.plan_digest,
                'authorization_digest': a.authorization_digest, 'revision': p.revision}))
        if (claim.result is None or claim.result.outcome != 'succeeded'
                or claim.result.verification != 'verified' or claim.result.compensation != 'not_requested'):
            raise ValueError

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            schema = self._request('GET', '?action=schema&with_meta=true')
            if qualify_schema(schema, serial_digest=self._serial) != self._preparation.schema_digest:
                raise ValueError
            if self._original is None:
                current = self._request('GET', '?with_meta=true')
                prepared = prepare_dns_timeout(schema, current,
                    serial_digest=self._serial, binding=self._binding)
                if prepared != self._preparation:
                    raise ValueError
                return prepared.current_digest
            self._original_verified()
            table = self._request('GET', '?with_meta=true')
            if not verify_dns_timeout(table, self._preparation, serial_digest=self._serial):
                raise ValueError
            return self._preparation.expected_digest
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        with self._lock:
            self._check(plan)
            _require_m4_dispatch_ownership(plan, self._authorization, self._store)
            if self._dispatched:
                raise M4AdapterDenied(_ERROR)
            # Check actual state again immediately before consuming the send.
            if self.read_current(plan) != plan.expected_current_digest:
                raise M4AdapterDenied(_ERROR)
            self._check(plan)
            _require_m4_dispatch_ownership(plan, self._authorization, self._store)
            self._dispatched = True
            body = self._preparation.body_bytes if self._original is None else self._preparation.original_bytes
            ack = self._request('PUT', body=body)
            try:
                _envelope(ack, self._serial, method='PUT')
                if ack.get('status') != 'success':
                    raise ValueError
                self._acknowledged = True
            except Exception:
                raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            if not self._acknowledged:
                raise ValueError
            table = self._request('GET', '?with_meta=true')
            if verify_dns_timeout(table, self._preparation, serial_digest=self._serial,
                                     restored=self._original is not None):
                return plan.expected_state_digest
            return canonical_digest({'contract': CONTRACT, 'postcondition': 'mismatch'})
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def bind_recovery(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                      verifier: M4AuthorizationVerifier, *, execution_enabled: bool = False) -> DnsTimeoutM4Adapter:
        """Bind a separately authorized recovery to the original verified update."""
        try:
            if self._original is not None or not self._acknowledged or type(execution_enabled) is not bool:
                raise ValueError
            recovery = object.__new__(DnsTimeoutM4Adapter)
            recovery.__dict__.update(self.__dict__)
            recovery._original = self
            recovery._plan, recovery._authorization, recovery._verifier = plan, authorization, verifier
            recovery._enabled = execution_enabled
            recovery._dispatched = recovery._acknowledged = False
            recovery._lock = self._lock
            recovery._check_plan()
            recovery._original_verified()
            return recovery
        except Exception:
            raise M4AdapterDenied(_ERROR) from None
