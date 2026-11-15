"""Read-only join of a Remote User target's original pair ACK and successful M4.

A snapshot or held lock grants no user-create authorization. Future dispatchers
must retain their own fresh C/P/E, active M4 and durable one-shot journal.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import hmac
import math
import time

from v4_planning import (
    M4ExecutionAuthorization, M4ExecutionPlan, M4Outcome, M4Verification,
    M4Compensation, canonical_digest,
)
from v4_planning.execution_kernel import M4ClaimState
from v4_planning.material_provider import MaterialLeaseRequest, _OpaqueC3Object
from v4_planning.models import require_digest

from .ldap_server_projection import _digest
from .m4_execution_store import PersistentM4ExecutionStateStore
from .radius_remote_user_contract import RadiusRemoteUserBinding, RadiusRemoteUserError
from .radius_server_pair_contract import ACTION_ID, ACTION_VERSION
from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport
from .radius_server_pair_m4_runtime import (
    ADAPTER_REF, TARGET_REF, RadiusPairM4ExecutionBinding, expected_state_digest,
)

_ERROR = "The private Remote User RADIUS target is unavailable."
_DOMAIN = "fortipam-700-build29-radius-remote-user-owned-target-private-v1"


@dataclass(frozen=True, slots=True, repr=False)
class RadiusRemoteUserTargetObservation(_OpaqueC3Object):
    """Private original provenance/current-state digest; never a capability."""

    provenance_digest: str
    state_digest: str
    binding_digest: str

    @property
    def observation_digest(self) -> str:
        return canonical_digest({"contract": _DOMAIN, **asdict(self)})


class RadiusRemoteUserOwnedTarget(_OpaqueC3Object):
    """Pin one original pair namespace/store; never create or recover a target."""

    def __init__(self, binding: RadiusRemoteUserBinding,
            target: FortiPamRadiusPairHttpTransport,
            execution_binding: RadiusPairM4ExecutionBinding,
            execution_store: PersistentM4ExecutionStateStore, *, recovery_only: bool = False,
            handoff_digest: str | None = None, preparation_digest: str | None = None) -> None:
        try:
            if (type(binding) is not RadiusRemoteUserBinding
                    or type(target) is not FortiPamRadiusPairHttpTransport
                    or type(execution_binding) is not RadiusPairM4ExecutionBinding
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(recovery_only) is not bool):
                raise ValueError
            self._binding, self._target = binding, target
            self._execution, self._store = execution_binding, execution_store
            self._recovery_only = recovery_only
            if handoff_digest is not None: require_digest(handoff_digest, "target_handoff")
            self._handoff_digest = handoff_digest
            if preparation_digest is not None: require_digest(preparation_digest, "target_preparation")
            if preparation_digest is not None and (not recovery_only or handoff_digest is not None): raise ValueError
            self._preparation_digest = preparation_digest
            self._pin = self._composition()
        except Exception:
            raise RadiusRemoteUserError(_ERROR) from None

    def _composition(self) -> tuple[object, ...]:
        t, e, store = self._target, self._execution, self._store
        if (t._binding is not self._binding.radius or e.material_binding is not self._binding.radius
                or any((t._execution_enabled, t._recovery_enabled, t._owned_connect_enabled))
                or type(e.plan) is not M4ExecutionPlan
                or type(e.authorization) is not M4ExecutionAuthorization
                or type(e.lease_request) is not MaterialLeaseRequest):
            raise ValueError
        e.plan.__post_init__()
        e.authorization.__post_init__()
        e.lease_request.__post_init__()
        return (id(t), id(t._config), t._config.base_url, t._serial, t._directory,
            t._directory_identity, id(t._factory), id(t._clock), id(e), e.plan.plan_digest,
            e.authorization.authorization_digest, _digest(asdict(e.lease_request)),
            self._binding.parameters_digest, store._path, store._key_path,
            hashlib.sha256(store._key).hexdigest(), self._recovery_only, self._handoff_digest, self._preparation_digest)

    def _original_execution(self) -> str:
        e = self._execution
        plan, auth, request = e.plan, e.authorization, e.lease_request
        if (plan.action_id != ACTION_ID or plan.action_version != ACTION_VERSION
                or plan.adapter_ref != ADAPTER_REF or plan.target_ref != TARGET_REF
                or plan.parameters_digest != self._binding.radius.parameters_digest
                or plan.expected_state_digest != expected_state_digest(self._binding.radius)
                or plan.compensation_ref is not None
                or auth.plan_ref != plan.plan_ref or auth.plan_digest != plan.plan_digest
                or auth.requester_digest != plan.requester_digest
                or auth.confirmation_digest != plan.confirmation_digest
                or auth.approval_digest != plan.approval_digest
                or request.action_id != ACTION_ID or request.action_version != ACTION_VERSION
                or request.plan_digest != plan.plan_digest
                or request.authorization_digest != auth.authorization_digest
                or request.policy_decision_digest != e.policy_decision_digest
                or request.scope_digest != e.scope_digest or request.audience_digest != e.audience_digest
                or request.requested_at < auth.issued_at
                or request.expires_at > min(auth.expires_at, plan.expires_at)):
            raise ValueError
        for digest in (e.policy_decision_digest, e.scope_digest, e.audience_digest):
            require_digest(digest, "original_pair_binding")
        context = canonical_digest({"authorization_digest": auth.authorization_digest,
            "plan_digest": plan.plan_digest, "revision": plan.revision})
        self._store.verify_ready()
        original = self._store.inspect_claim(plan_ref=plan.plan_ref,
            requester_digest=plan.requester_digest, idempotency_digest=plan.idempotency_digest,
            context_digest=context, authorization_digest=auth.authorization_digest)
        result = original.result
        if (original.state is not M4ClaimState.REPLAY or result is None
                or result.outcome is not M4Outcome.SUCCEEDED
                or result.verification is not M4Verification.VERIFIED
                or result.compensation is not M4Compensation.NOT_REQUESTED):
            raise ValueError
        events = [event for event in self._store.audit_events
            if hmac.compare_digest(event.digest_reference, canonical_digest(context + "verified"))]
        if (len(events) != 1 or events[0].authorization != "verified"
                or events[0].outcome is not result.outcome
                or events[0].verification is not result.verification
                or events[0].compensation is not result.compensation):
            raise ValueError
        return canonical_digest({"plan_digest": plan.plan_digest,
            "authorization_digest": auth.authorization_digest, "context_digest": context,
            "original_audit_digest": events[0].digest_reference})

    def _inspect_locked(self, stop: float | None = None) -> RadiusRemoteUserTargetObservation:
        if self._recovery_only:
            raise ValueError
        now = time.monotonic()
        if stop is not None and (type(stop) not in {int, float} or not math.isfinite(stop) or stop <= now):
            raise ValueError
        stop = min(now + 60, stop) if stop is not None else now + 60
        if self._composition() != self._pin:
            raise ValueError
        execution = self._original_execution()
        t = self._target
        # Do not manufacture a missing original full-readback record while
        # qualifying another workflow's dependency.
        if not t._exists("created.json"):
            raise ValueError
        owned = t._inspect_owned(stop)
        claim, ack = t._ownership_records()
        if (claim["request_digest"] != _digest(asdict(self._execution.lease_request))
                or claim["current_digest"] != self._execution.plan.expected_current_digest
                or claim["actor_digest"] != hashlib.sha256(t._config.bearer_token.encode()).hexdigest()):
            raise ValueError
        if (self._composition() != self._pin or self._original_execution() != execution
                or time.monotonic() >= stop):
            raise ValueError
        provenance = canonical_digest({"contract": _DOMAIN, "original_execution": execution,
            "claim_digest": _digest(claim), "ack_digest": _digest(ack),
            "owned_record_digest": _digest(owned), "serial": t._serial,
            "origin": t._config.base_url, "journal": str(t._directory),
            "journal_identity": list(t._directory_identity)})
        return RadiusRemoteUserTargetObservation(provenance, str(owned["state_digest"]),
            self._binding.parameters_digest)

    @contextmanager
    def hold(self, expected_digest: str | None = None, *, stop: float | None = None) -> Iterator[RadiusRemoteUserTargetObservation]:
        """Hold the original pair lock over a fresh check; confer no write grant.

        This prevents cooperating pair deletion while a future child performs its
        own authorized dispatch. Device-side races still require server readback.
        """
        try:
            if expected_digest is not None:
                require_digest(expected_digest, "target_observation")
            with self._target._locked(existing=True):
                observed = self._inspect_locked(stop)
                if expected_digest is not None and not hmac.compare_digest(expected_digest, observed.observation_digest):
                    raise ValueError
                yield observed
        except Exception:
            raise RadiusRemoteUserError(_ERROR) from None

    def inspect(self) -> RadiusRemoteUserTargetObservation:
        with self.hold() as observed:
            return observed
