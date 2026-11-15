"""Private, default-closed M4 observation of one acknowledged RADIUS pair ordinal.

This separate lab-auto authority records one ordinal response for the unchanged,
zero-reference pair owned by the original HTTP journal. It has no material
provider, MCP Tool or startup registration. Consumed or uncertain native claims never become replayable.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets
from threading import RLock
import time
from typing import Any

from v4_planning import (
    M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationDenied, M4ClaimState,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.models import require_digest, require_ref

from .m4_execution_store import PersistentM4ExecutionStateStore
from .radius_server_pair_contract import RadiusServerPairBinding
from .radius_server_pair_owned_connect_contract import RadiusPairOwnedConnectObservation
from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport, _Connection
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

ACTION_ID = "radius-server-pair-owned-connect-observe"
ACTION_VERSION = "1.0.0"
ADAPTER_REF = "fortipam-700-build29-radius-pair-owned-connect-observe-v1"
CONTRACT = "fortipam-radius-pair-owned-connect-observation-private-v1"
_DOMAIN = b"fortipam-radius-pair-owned-connect-observation-lab-auto-v1\x00"
_ERROR = "The private paired RADIUS native observation workflow is unavailable."
_TTL = 60


class RadiusServerPairOwnedConnectError(RuntimeError):
    """Categorical refusal without private context or device output."""


@dataclass(frozen=True, slots=True, repr=False)
class _Preview(_OpaqueC3Object):
    owned_digest: str
    state_digest: str
    created_at: int
    expires_at: int
    nonce: str
    preview_ref: str
    signature: str


@dataclass(frozen=True, slots=True, repr=False)
class _Issued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class _Adapter:
    def __init__(self, workflow: RadiusServerPairOwnedConnectWorkflow) -> None:
        self._workflow = workflow

    def read_current(self, plan: M4ExecutionPlan) -> str:
        w = self._workflow
        w._check_plan(plan)
        try:
            owned, state = w._transport.inspect_owned_connect()
            return w._current_digest(owned, state)
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        w = self._workflow
        w._check_plan(plan)
        try:
            w._observation = w._transport.observe_owned_connect()
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        w = self._workflow
        w._check_plan(plan)
        try:
            observed = w._transport.inspect_owned_connect_observation()
            if w._observation is None or observed.as_dict() != w._observation.as_dict():
                raise ValueError
            return w._expected_digest()
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None


class RadiusServerPairOwnedConnectWorkflow(_OpaqueC3Object):
    """Separate authenticated lab scope, short-lived HMAC grant and durable M4 use."""

    __slots__ = ("_binding", "_parameters", "_key", "_namespace", "_store", "_enabled",
        "_clock", "_last_clock", "_clock_failed", "_lock", "_transport", "_preview", "_issued", "_started",
        "_composition", "_ordinal", "_pair_parameters", "_observation")
    _display_name = "RadiusServerPairOwnedConnectWorkflow"

    def __init__(self, binding: RadiusServerPairBinding, config: SecretMetadataHttpTransportConfig, *,
            ordinal: str, expected_serial: str, state_directory: Path, execution_store: PersistentM4ExecutionStateStore,
            authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
            allowed_requester_digest: str, allowed_transport_digest: str, execution_enabled: bool = False,
            clock: Callable[[], int] | None = None,
            connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(ordinal) is not str or ordinal not in {"primary", "secondary"}
                    or type(binding) is not RadiusServerPairBinding
                    or type(config) is not SecretMetadataHttpTransportConfig
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool or clock is not None and not callable(clock)):
                raise ValueError
            for value in (environment_ref, scope_ref, audience_ref): require_ref(value, "namespace_ref")
            for value in (allowed_requester_digest, allowed_transport_digest): require_digest(value, "identity_digest")
            self._binding, self._key, self._ordinal = binding, authority_key, ordinal
            self._pair_parameters = binding.parameters_digest
            self._parameters = canonical_digest({"contract": CONTRACT, "pair_parameters": self._pair_parameters, "ordinal": ordinal})
            self._namespace = {"contract": CONTRACT, "environment_ref": environment_ref,
                "scope_ref": scope_ref, "audience_ref": audience_ref,
                "requester_digest": allowed_requester_digest, "transport_digest": allowed_transport_digest,
                "policy_mode": "lab_auto", "parameters_digest": self._parameters, "ordinal": ordinal}
            self._store, self._enabled = execution_store, execution_enabled
            self._clock = clock or (lambda: int(time.time()))
            self._lock = RLock()
            self._last_clock: int | None = None
            self._clock_failed = False
            self._preview: _Preview | None = None
            self._issued: _Issued | None = None
            self._started = False
            self._observation: RadiusPairOwnedConnectObservation | None = None
            self._transport = FortiPamRadiusPairHttpTransport(config, binding, expected_serial=expected_serial,
                state_directory=state_directory, owned_connect_enabled=execution_enabled,
                owned_connect_ordinal=ordinal, owned_connect_authorizer=self._authorize_connect, clock=self._now,
                connection_factory=connection_factory)
            if authority_key == execution_store._key:
                raise ValueError
            self._composition = self._composition_digest()
            self._namespace["composition_digest"] = self._composition
        except Exception:
            raise RadiusServerPairOwnedConnectError(_ERROR) from None

    def _now(self) -> int:
        with self._lock:
            try:
                now = self._clock()
                if (self._clock_failed or type(now) is not int or now < 0
                        or self._last_clock is not None and now < self._last_clock):
                    raise ValueError
                self._last_clock = now
                return now
            except Exception:
                self._clock_failed = True
                raise RadiusServerPairOwnedConnectError(_ERROR) from None

    def _identity(self, requester: str, transport: str) -> None:
        require_digest(requester, "requester_digest")
        require_digest(transport, "transport_digest")
        if (not hmac.compare_digest(requester, self._namespace["requester_digest"])
                or not hmac.compare_digest(transport, self._namespace["transport_digest"])
                or self._binding.parameters_digest != self._pair_parameters):
            raise RadiusServerPairOwnedConnectError(_ERROR)

    def _composition_digest(self) -> str:
        t, store = self._transport, self._store
        if (t._binding is not self._binding or t._ordinal != self._ordinal
                or t._directory in store._path.parents or t._directory in store._key_path.parents
                or t._directory in {store._path, store._key_path}
                or getattr(t._authorize_owned_connect, "__self__", None) is not self
                or getattr(t._authorize_owned_connect, "__func__", None) is not RadiusServerPairOwnedConnectWorkflow._authorize_connect):
            raise ValueError
        return canonical_digest({"parameters": self._parameters, "ordinal": self._ordinal,
            "origin": t._config.base_url, "ca": t._config.ca_file,
            "actor": hashlib.sha256(t._config.bearer_token.encode()).hexdigest(), "serial": t._serial,
            "journal": str(t._directory), "store": str(store._path), "key_path": str(store._key_path),
            "key": hashlib.sha256(store._key).hexdigest()})

    def _gate(self) -> None:
        if (self._enabled is not True or self._transport._owned_connect_enabled is not True
                or self._transport._recovery_enabled is not False
                or self._transport._execution_enabled is not False
                or self._transport._binding is not self._binding
                or self._binding.parameters_digest != self._pair_parameters
                or self._composition_digest() != self._composition):
            raise RadiusServerPairOwnedConnectError(_ERROR)

    def _unconsumed(self) -> None:
        if self._store.claim_count != 0:
            raise RadiusServerPairOwnedConnectError(_ERROR)

    def _mac(self, purpose: str, content: object) -> str:
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode("ascii") + b"\x00" + encoded,
                        hashlib.sha256).hexdigest()

    def _context(self, p: _Preview) -> dict[str, Any]:
        return {**self._namespace, "owned_digest": p.owned_digest, "state_digest": p.state_digest,
            "created_at": p.created_at, "expires_at": p.expires_at, "nonce": p.nonce}

    def _check_preview(self, p: _Preview, now: int) -> None:
        if (type(p) is not _Preview or type(now) is not int or type(p.created_at) is not int
                or type(p.expires_at) is not int or not p.created_at <= now < p.expires_at
                or p.expires_at - p.created_at != _TTL):
            raise RadiusServerPairOwnedConnectError(_ERROR)
        require_digest(p.owned_digest, "owned_digest")
        require_digest(p.state_digest, "state_digest")
        context = self._context(p)
        if (not hmac.compare_digest(p.signature, self._mac("preview", context))
                or not hmac.compare_digest(p.preview_ref, "radius-pair-native-preview-" + self._mac("preview-ref", context))):
            raise RadiusServerPairOwnedConnectError(_ERROR)

    def _current_digest(self, owned: str, state: str) -> str:
        return canonical_digest({"contract": CONTRACT, "parameters_digest": self._parameters,
                                 "owned_digest": owned, "state_digest": state})

    def _expected_digest(self) -> str:
        p = self._preview
        if p is None: raise RadiusServerPairOwnedConnectError(_ERROR)
        return canonical_digest({"contract": CONTRACT, "owned_digest": p.owned_digest,
                                 "parameters_digest": self._parameters, "state": "native-observation-recorded-pair-unchanged", "connectivity_qualified": False})

    def _derive(self) -> _Issued:
        p = self._preview
        if p is None: raise RadiusServerPairOwnedConnectError(_ERROR)
        self._check_preview(p, self._now())
        context = self._context(p)
        confirmation, approval = self._mac("standing-intent", context), self._mac("lab-policy", context)
        values: dict[str, Any] = dict(plan_ref="radius-pair-native-plan-" + self._mac("plan-ref", context),
            revision=1, action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF,
            target_ref="radius-server-pair-original-owned-ordinal", requester_digest=self._namespace["requester_digest"],
            summary_digest=canonical_digest(self._summary(p)), confirmation_digest=confirmation, approval_digest=approval,
            parameters_digest=self._parameters, expected_current_digest=self._current_digest(p.owned_digest,p.state_digest),
            expected_state_digest=self._expected_digest(), idempotency_digest=self._mac("idempotency", context),
            expires_at=p.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        signed = {**context, "plan_digest": plan.plan_digest}
        auth: dict[str, Any] = dict(authorization_ref="radius-pair-native-auth-" + self._mac("authorization", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="radius-pair-native-intent-" + self._mac("intent-ref", signed),
            confirmation_digest=confirmation, approval_ref="radius-pair-native-policy-" + self._mac("policy-ref", signed),
            approval_digest=approval, approver_digest=self._mac("policy-authority", self._namespace),
            issued_at=p.created_at, expires_at=p.expires_at, one_time=True, execution_authorized=True)
        return _Issued(plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)))

    def _check_plan(self, plan: M4ExecutionPlan) -> None:
        self._gate()
        if self._issued is None or plan is not self._issued.plan or self._issued != self._derive():
            raise M4AdapterDenied(_ERROR)

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            self._check_plan(plan)
            if self._issued is None or self._preview is None or authorization is not self._issued.authorization:
                raise ValueError
            self._check_preview(self._preview, now_epoch)
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _authorize_connect(self, binding: RadiusServerPairBinding, ordinal: str, owned: str, state: str) -> bool:
        with self._lock:
            try:
                issued, p = self._issued, self._preview
                if (ordinal != self._ordinal or not self._started or issued is None or p is None or binding is not self._binding
                        or not hmac.compare_digest(owned, p.owned_digest)
                        or not hmac.compare_digest(state, p.state_digest)):
                    raise ValueError
                plan, auth = issued.plan, issued.authorization
                _require_m4_dispatch_ownership(plan, auth, self._store)
                self.verify(plan, auth, now_epoch=self._now())
                claim = self._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
                    idempotency_digest=plan.idempotency_digest, authorization_digest=auth.authorization_digest,
                    context_digest=canonical_digest({"authorization_digest": auth.authorization_digest,
                        "plan_digest": plan.plan_digest, "revision": plan.revision}))
                if claim.state is not M4ClaimState.IN_PROGRESS:
                    raise ValueError
                self._check_preview(p, self._now())
                self._gate()
                return True
            except Exception:
                return False

    def _summary(self, p: _Preview) -> dict[str, object]:
        return {"contract": CONTRACT, "policy_mode": "lab_auto", "summary_revision": 1,
            "preview_ref": p.preview_ref, "expires_at": p.expires_at,
            "requester_digest": self._namespace["requester_digest"],
            "environment": "privately_bound_disposable_lab",
            "unchanged_boundary": ["other_identity_servers", "users_groups_and_roles"],
            "Current State": {"original_creation_ack_verified": True, "full_state_unchanged": True,
                "zero_references": True, "observed_at": p.created_at},
            "Proposed Changes": {"operation": "observe_original_owned_radius_pair_ordinal", "ordinal": self._ordinal, "material_access": False},
            "Expected State": {"bounded_native_observation_recorded": True, "full_original_pair_unchanged": True,
                "connectivity_qualified": False},
            "dependencies": ["original_pair_creation_ack", "fresh_complete_unchanged_state", "independent_native_ordinal_ledger"],
            "risk_and_effects": {"effect": "one_native_probe_to_the_bound_ordinal"},
            "authorization_and_approval": {"mode": "standing_owner_lab_authority", "independent_human_approval": False},
            "facts": {"source": "original_pair_ack_and_fresh_full_cmdb_state", "freshness_seconds": 60},
            "assumptions": ["owner_authorized_disposable_lab_scope"],
            "unresolved_gaps": ["connectivity_qualification", "automatic_failover", "user_login"],
            "verification": ["claim_linked_minimized_observation", "complete_pair_state_preserved"],
            "compensation_and_stop": {"uncertain_result": "retain_claims_and_reconcile_without_replay"},
            "native_post_executed": False}

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                if self._issued is not None or self._composition_digest() != self._composition:
                    raise ValueError
                self._unconsumed()
                created = self._now()
                owned, state = self._transport.inspect_owned_connect()
                p = _Preview(owned,state,created,created+_TTL,secrets.token_hex(24),"","")
                context = self._context(p)
                p = _Preview(owned,state,created,p.expires_at,p.nonce,
                    "radius-pair-native-preview-"+self._mac("preview-ref",context),self._mac("preview",context))
                self._check_preview(p,self._now())
                self._preview, self._issued, self._started = p, None, False
                self._observation = None
                summary = self._summary(p)
                return {**summary, "summary_digest": canonical_digest(summary)}
        except Exception:
            raise RadiusServerPairOwnedConnectError(_ERROR) from None

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._gate()
                self._unconsumed()
                if self._issued is not None:
                    raise ValueError
                require_ref(preview_ref,"preview_ref")
                p = self._preview
                if p is None or not hmac.compare_digest(preview_ref,p.preview_ref): raise ValueError
                self._check_preview(p,self._now())
                if self._transport.inspect_owned_connect() != (p.owned_digest,p.state_digest): raise ValueError
                self._issued = self._derive()
                return {"contract": CONTRACT,"policy_mode": "lab_auto",
                    "authorization_ref": self._issued.authorization.authorization_ref,"expires_at":p.expires_at}
        except Exception:
            raise RadiusServerPairOwnedConnectError(_ERROR) from None

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._gate()
                require_ref(authorization_ref,"authorization_ref")
                issued = self._issued
                if issued is None or not hmac.compare_digest(authorization_ref,issued.authorization.authorization_ref):
                    raise ValueError
                self._check_plan(issued.plan)
                if not self._started: self._unconsumed()
                self._started = True
                result = M4ExecutionKernel(_Adapter(self), self, self._store, clock=self._now).execute(
                    issued.plan, issued.authorization)
                return {"contract":CONTRACT, **result.as_dict(), "ordinal": self._ordinal,
                    "execution_scope": "native_response_observation_only", "connectivity_qualified": False,
                    "observation": None if self._observation is None else self._observation.as_dict()}
        except Exception:
            raise RadiusServerPairOwnedConnectError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._transport.close_owned_connect()
            self._key = b""
