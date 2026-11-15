"""Default-closed lab authority for one original acknowledged Web fixture.

Trusted composition supplies standing lab scope and authenticated identity.
This authority obtains C/P/E from the exact recovery runtime itself; callers
cannot provide a preservation witness or reuse the original creation grant.
It supplies no Tool, startup activation or live-source qualification.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
from threading import RLock
from typing import Any

from v4_planning import (M4AuthorizationDenied, M4ClaimState, M4ExecutionAuthorization,
    M4ExecutionPlan, canonical_digest)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref
from .web_secret_fixture_recovery_guard import WebSecretFixtureRecoveryGuard
from .web_secret_fixture_recovery_runtime import (ACTION, ADAPTER, CONTRACT,
    RECONCILED_CONTRACT,
    WebSecretFixtureRecoveryPreview, WebSecretFixtureRecoveryRuntime)

_DOMAIN = b"fortipam-web-fixture-recovery-lab-auto/v1\0"
_ERROR = "The private Web fixture recovery authorization is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretFixtureRecoveryIssued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class WebSecretFixtureRecoveryAuthority(_OpaqueC3Object):
    """Separate one-time delete authority, bound to original custody and actor.

    Construction alone grants nothing. Explicit lab enablement and trusted
    identity/scope inputs are required. Verification consumes this grant only
    after the original durable M4 store reports its recovery claim in progress.
    """
    def __init__(self, guard: WebSecretFixtureRecoveryGuard, *, authority_key: bytes,
            environment_ref: str, scope_ref: str, audience_ref: str,
            requester_digest: str, transport_digest: str,
            execution_enabled: bool = False) -> None:
        try:
            if (type(guard) is not WebSecretFixtureRecoveryGuard
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool):
                raise ValueError
            for value in (environment_ref, scope_ref, audience_ref):
                if type(value) is not str: raise ValueError
                require_ref(value, "namespace_ref")
            for value in (requester_digest, transport_digest):
                if type(value) is not str: raise ValueError
                require_digest(value, "identity_digest")
            guard._guard()
            original = guard._record.read_acknowledged_creation()
            if requester_digest != guard._record._execution_binding.plan.requester_digest:
                raise ValueError
            self._guard_source, self._original, self._key = guard, original, authority_key
            self._binding = dict(contract=RECONCILED_CONTRACT if guard._reconciled_source is not None else CONTRACT,
                environment_ref=environment_ref,
                scope_ref=scope_ref, audience_ref=audience_ref, requester_digest=requester_digest,
                transport_digest=transport_digest, policy_mode="lab_auto", source_digest=guard._source,
                namespace=guard._record._namespace, creation_digest=original.creation.creation_digest)
            self._enabled = execution_enabled
            self._runtime: WebSecretFixtureRecoveryRuntime | None = None
            self._preview: WebSecretFixtureRecoveryPreview | None = None
            self._issued: WebSecretFixtureRecoveryIssued | None = None
            self._context: dict[str, Any] | None = None
            self._started = self._consumed = False
            self._lock = RLock()
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _source(self) -> None:
        guard = self._guard_source
        guard._guard()
        if (not self._enabled or guard._record.read_acknowledged_creation() != self._original
                or guard._source != self._binding["source_digest"]
                or guard._record._namespace != self._binding["namespace"]
                or guard._record._execution_binding.plan.requester_digest != self._binding["requester_digest"]):
            raise ValueError
        if self._runtime is not None:
            runtime = self._runtime
            if (runtime._guard_source is not guard or runtime._verifier is not self
                    or runtime._verifier_pin is not self or runtime._original != self._original):
                raise ValueError
            runtime._check_local()

    def _mac(self, purpose: str, content: object) -> str:
        raw = json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\0" + raw, hashlib.sha256).hexdigest()

    def _derive(self) -> WebSecretFixtureRecoveryIssued:
        p, context = self._preview, self._context
        if p is None or context is None or self._runtime is None: raise ValueError
        action, version, adapter = self._runtime.action_contract
        confirmation, approval = self._mac("standing-intent", context), self._mac("lab-policy", context)
        values: dict[str, Any] = dict(plan_ref="web-recovery-plan-" + self._mac("plan-ref", context),
            revision=1, action_id=action, action_version=version, adapter_ref=adapter,
            target_ref=p.target_ref, requester_digest=p.requester_digest,
            summary_digest=self._mac("summary", context), confirmation_digest=confirmation,
            approval_digest=approval, parameters_digest=p.parameters_digest,
            expected_current_digest=p.current_digest, expected_state_digest=p.expected_digest,
            idempotency_digest=self._mac("idempotency", context), expires_at=p.expires_at,
            compensation_ref=None)
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        signed = {**context, "plan_digest": plan.plan_digest}
        auth: dict[str, Any] = dict(authorization_ref="web-recovery-auth-" + self._mac("authorization", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="web-recovery-intent-" + self._mac("intent-ref", signed),
            confirmation_digest=confirmation, approval_ref="web-recovery-policy-" + self._mac("policy-ref", signed),
            approval_digest=approval, approver_digest=self._mac("policy-authority", self._binding),
            issued_at=context["created_at"], expires_at=p.expires_at, one_time=True, execution_authorized=True)
        return WebSecretFixtureRecoveryIssued(plan,
            M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)))

    def issue(self, runtime: WebSecretFixtureRecoveryRuntime, *, requester_digest: str,
            transport_digest: str) -> WebSecretFixtureRecoveryIssued:
        """Obtain a new exact preview internally, then bind standing lab intent."""
        with self._lock:
            try:
                self._source()
                if (self._started or type(runtime) is not WebSecretFixtureRecoveryRuntime
                        or runtime._guard_source is not self._guard_source or runtime._verifier is not self
                        or runtime._verifier_pin is not self or runtime._preview is not None
                        or (requester_digest, transport_digest) !=
                           (self._binding["requester_digest"], self._binding["transport_digest"])):
                    raise ValueError
                self._started = True
                preview = runtime.preview()
                self._runtime, self._preview = runtime, preview
                now = self._guard_source._now()
                if not now < preview.expires_at <= now + 60: raise ValueError
                self._context = {**self._binding, "nonce": secrets.token_hex(24), "created_at": now,
                    "preview": {"current": preview.current_digest, "expected": preview.expected_digest,
                        "parameters": preview.parameters_digest, "target": preview.target_ref,
                        "expires_at": preview.expires_at}}
                self._issued = self._derive()
                self._source()
                runtime._check_plan(self._issued.plan, self._issued.authorization)
                return self._issued
            except Exception:
                raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        with self._lock:
            try:
                self._source()
                issued, runtime = self._issued, self._runtime
                now = self._guard_source._now()
                if (self._consumed or issued is None or runtime is None
                        or plan is not issued.plan or authorization is not issued.authorization
                        or issued != self._derive() or type(now_epoch) is not int
                        or not authorization.issued_at <= now_epoch <= now < authorization.expires_at):
                    raise ValueError
                runtime._check_plan(plan, authorization)
                runtime._check_marker()
                claim = self._guard_source._record._execution_store.inspect_claim(plan_ref=plan.plan_ref,
                    requester_digest=plan.requester_digest, idempotency_digest=plan.idempotency_digest,
                    authorization_digest=authorization.authorization_digest,
                    context_digest=canonical_digest({"authorization_digest": authorization.authorization_digest,
                        "plan_digest": plan.plan_digest, "revision": plan.revision}))
                if claim.state is not M4ClaimState.IN_PROGRESS: raise ValueError
                self._consumed = True
                self._source()
            except Exception:
                raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._key = b""
            runtime = self._runtime
        if runtime is not None: runtime.close()
