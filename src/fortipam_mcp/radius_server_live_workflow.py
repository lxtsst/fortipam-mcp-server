"""Fixed, default-closed lab-auto RADIUS workflow with private HMAC authority.

This is the named local-lab standing-intent policy, not a human or production
approval authority. M4 and C3 keep their existing independent durable claims.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets
from threading import RLock
import time

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import (
    MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose, _OpaqueC3Object,
)
from v4_planning.models import require_digest, require_ref

from .radius_server_contract import ACTION_ID, ACTION_VERSION, CONTRACT, RadiusServerCreateBinding
from .radius_server_http_transport import FortiPamRadiusServerHttpTransport, _Connection
from .radius_server_m4_runtime import (
    ADAPTER_REF, TARGET_REF, RadiusServerM4ExecutionBinding,
    ProtectedRadiusServerM4Runtime, expected_state_digest,
)
from .radius_server_material_provider import RadiusServerMaterialLoader, RadiusServerMaterialProvider
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

_AUTHORITY_REF = "fortipam-mcp-lab-auto-radius-create"
_DOMAIN = b"fortipam-radius-create-lab-auto-v1\x00"
_TTL = 60
_UNAVAILABLE = "The private RADIUS server live workflow is unavailable."


class RadiusServerLiveWorkflowError(RuntimeError):
    """Fixed non-disclosing workflow refusal."""


@dataclass(frozen=True, slots=True, repr=False)
class _Preview(_OpaqueC3Object):
    nonce: str
    current_digest: str
    created_at: int
    expires_at: int
    preview_ref: str
    signature: str


class _LabAutoAuthority(_OpaqueC3Object):
    """Re-derive and verify the exact signed lab context at the M4 boundary."""

    __slots__ = ("_key", "_binding", "_parameters", "_namespace", "_clock", "_preview", "_issued")

    def __init__(self, key: bytes, binding: RadiusServerCreateBinding,
                 namespace: dict[str, str], clock: Callable[[], int]) -> None:
        self._key, self._binding = key, binding
        self._parameters, self._namespace = binding.parameters_digest, namespace
        self._clock = clock
        self._preview: _Preview | None = None
        self._issued: RadiusServerM4ExecutionBinding | None = None

    def _mac(self, purpose: str, content: Mapping[str, object]) -> str:
        # Match the existing Secret lab-auto authority's domain separation.
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8")
        return hmac.new(self._key, _DOMAIN + purpose.encode("ascii") + b"\x00" + encoded,
                        hashlib.sha256).hexdigest()

    def _context(self, nonce: str, current: str, created: int, expires: int) -> dict[str, object]:
        return {**self._namespace, "authority_ref": _AUTHORITY_REF, "contract": CONTRACT,
                "action_id": ACTION_ID, "action_version": ACTION_VERSION, "policy_mode": "lab_auto",
                "parameters_digest": self._parameters, "nonce": nonce, "current_digest": current,
                "created_at": created, "expires_at": expires}

    def preview(self, current: str, created: int) -> _Preview:
        nonce, expires = secrets.token_hex(24), created + _TTL
        context = self._context(nonce, current, created, expires)
        return _Preview(nonce, current, created, expires,
                        "radius-preview-" + self._mac("preview-ref", context), self._mac("preview", context))

    def check_preview(self, preview: _Preview, now: int) -> dict[str, object]:
        if (type(preview) is not _Preview or type(now) is not int
            or type(preview.created_at) is not int or type(preview.expires_at) is not int
            or not preview.created_at <= now < preview.expires_at
            or preview.expires_at - preview.created_at != _TTL
            or self._binding.parameters_digest != self._parameters):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        require_digest(preview.current_digest, "current_digest")
        context = self._context(preview.nonce, preview.current_digest, preview.created_at, preview.expires_at)
        if (not hmac.compare_digest(preview.signature, self._mac("preview", context))
            or not hmac.compare_digest(preview.preview_ref, "radius-preview-" + self._mac("preview-ref", context))):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return context

    def _derive(self, preview: _Preview, now: int) -> RadiusServerM4ExecutionBinding:
        context = self.check_preview(preview, now)
        approval = self._mac("lab-approval", context)
        confirmation = self._mac("standing-intent", context)
        plan_ref = "radius-plan-" + self._mac("plan-ref", context)
        requester = self._namespace["requester_digest"]
        plan_values = {
            "plan_ref": plan_ref, "revision": 1, "action_id": ACTION_ID, "action_version": ACTION_VERSION,
            "adapter_ref": ADAPTER_REF, "target_ref": TARGET_REF, "requester_digest": requester,
            "summary_digest": self._mac("summary", context), "confirmation_digest": confirmation,
            "approval_digest": approval, "parameters_digest": self._parameters,
            "expected_current_digest": preview.current_digest,
            "expected_state_digest": expected_state_digest(self._binding),
            "idempotency_digest": self._mac("idempotency", context),
            "expires_at": preview.expires_at, "compensation_ref": None,
        }
        plan = M4ExecutionPlan(
            plan_ref, 1, ACTION_ID, ACTION_VERSION, ADAPTER_REF, TARGET_REF, requester,
            str(plan_values["summary_digest"]), confirmation, approval, self._parameters,
            preview.current_digest, str(plan_values["expected_state_digest"]),
            str(plan_values["idempotency_digest"]), preview.expires_at, None, canonical_digest(plan_values),
        )
        signed_plan = {"plan_digest": plan.plan_digest, **context}
        auth_ref = "radius-auth-" + self._mac("authorization-ref", signed_plan)
        confirmation_ref = "radius-lab-intent-" + self._mac("intent-ref", signed_plan)
        approval_ref = "radius-lab-approval-" + self._mac("approval-ref", signed_plan)
        # This distinct principal represents the configured lab policy authority.
        approver = self._mac("lab-policy-authority", {"authority_ref": _AUTHORITY_REF, **self._namespace})
        auth_values = {
            "authorization_ref": auth_ref, "plan_ref": plan_ref, "plan_digest": plan.plan_digest,
            "requester_digest": requester, "confirmation_ref": confirmation_ref,
            "confirmation_digest": confirmation, "approval_ref": approval_ref,
            "approval_digest": approval, "approver_digest": approver,
            "issued_at": preview.created_at, "expires_at": preview.expires_at,
            "one_time": True, "execution_authorized": True,
        }
        auth = M4ExecutionAuthorization(auth_ref, plan_ref, plan.plan_digest, requester,
            confirmation_ref, confirmation, approval_ref, approval, approver,
            preview.created_at, preview.expires_at, True, True, canonical_digest(auth_values))
        policy = self._mac("policy", context)
        scope = canonical_digest(self._namespace["scope_ref"])
        audience = canonical_digest(self._namespace["audience_ref"])
        request = MaterialLeaseRequest(ACTION_ID, ACTION_VERSION, plan.plan_digest, policy,
            auth.authorization_digest, scope, audience, MaterialProviderClass.OWNED_LAB_FIXTURE_REFERENCE,
            MaterialPurpose.INITIAL_ONBOARDING, preview.created_at, preview.expires_at)
        return RadiusServerM4ExecutionBinding(plan, auth, self._binding, request, policy, scope, audience)

    def issue(self, preview: _Preview) -> RadiusServerM4ExecutionBinding:
        issued = self._derive(preview, self._clock())
        self._preview, self._issued = preview, issued
        return issued

    def resolve_execution_binding(self, authorization_ref: str) -> RadiusServerM4ExecutionBinding:
        if self._issued is None or not hmac.compare_digest(authorization_ref, self._issued.authorization.authorization_ref):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        self.verify_binding(self._issued)
        return self._issued

    def verify_binding(self, binding: RadiusServerM4ExecutionBinding) -> None:
        if self._preview is None or self._issued is None or binding is not self._issued:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        expected = self._derive(self._preview, self._clock())
        if (binding.material_binding is not self._binding or binding.plan != expected.plan
            or binding.authorization != expected.authorization or binding.lease_request != expected.lease_request
            or binding.policy_decision_digest != expected.policy_decision_digest
            or binding.scope_digest != expected.scope_digest or binding.audience_digest != expected.audience_digest):
            raise M4AuthorizationDenied(_UNAVAILABLE)

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        if self._issued is None or self._preview is None:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        self.check_preview(self._preview, now_epoch)
        self.verify_binding(self._issued)
        if plan is not self._issued.plan or authorization is not self._issued.authorization:
            raise M4AuthorizationDenied(_UNAVAILABLE)


class RadiusServerLiveWorkflow(_OpaqueC3Object):
    """One protected lab fixture; public inputs contain identity digests and opaque refs only."""

    __slots__ = (
        "_binding", "_parameters", "_config", "_serial", "_directory", "_loader",
        "_execution_store", "_material_store", "_enabled", "_clock", "_factory", "_lock",
        "_last_clock", "_clock_failed", "_requester", "_transport_digest", "_authority",
        "_reader", "_preview", "_runtime", "_started",
    )
    _display_name = "RadiusServerLiveWorkflow"

    def __init__(self, binding: RadiusServerCreateBinding, transport_config: SecretMetadataHttpTransportConfig, *,
                 expected_serial: str, state_directory: Path, loader: RadiusServerMaterialLoader,
                 execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
                 authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
                 allowed_requester_digest: str, allowed_transport_digest: str, execution_enabled: bool = False,
                 clock: Callable[[], int] | None = None,
                 connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(binding) is not RadiusServerCreateBinding or type(transport_config) is not SecretMetadataHttpTransportConfig
                or type(execution_store) is not PersistentM4ExecutionStateStore
                or type(material_store) is not PersistentMaterialUseStateStore
                or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                or type(execution_enabled) is not bool or clock is not None and not callable(clock)
                or not callable(getattr(loader, "validate_prebound", None))
                or not callable(getattr(loader, "load_radius_material_once", None))):
                raise ValueError
            for ref in (environment_ref, scope_ref, audience_ref):
                require_ref(ref, "namespace_ref")
            for digest in (allowed_requester_digest, allowed_transport_digest):
                require_digest(digest, "identity_digest")
            self._binding, self._parameters, self._config = binding, binding.parameters_digest, transport_config
            self._serial, self._directory, self._loader = expected_serial, state_directory, loader
            self._execution_store, self._material_store = execution_store, material_store
            self._enabled, self._factory = execution_enabled, connection_factory
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._lock = RLock()
            self._last_clock: int | None = None
            self._clock_failed = False
            self._requester, self._transport_digest = allowed_requester_digest, allowed_transport_digest
            self._authority = _LabAutoAuthority(authority_key, binding, {
                "environment_ref": environment_ref, "scope_ref": scope_ref, "audience_ref": audience_ref,
                "requester_digest": allowed_requester_digest, "transport_digest": allowed_transport_digest,
            }, self._now)
            self._reader = self._transport()
            self._preview: _Preview | None = None
            self._runtime: ProtectedRadiusServerM4Runtime | None = None
            self._started = False
        except Exception:
            raise RadiusServerLiveWorkflowError(_UNAVAILABLE) from None

    def _now(self) -> int:
        with self._lock:
            try:
                now = self._clock()
                if (self._clock_failed or type(now) is not int or now < 0
                    or self._last_clock is not None and now < self._last_clock):
                    raise ValueError
            except Exception:
                self._clock_failed = True
                raise RadiusServerLiveWorkflowError(_UNAVAILABLE) from None
            self._last_clock = now
            return now

    def _identity(self, requester: str, transport: str) -> None:
        require_digest(requester, "requester_digest")
        require_digest(transport, "transport_digest")
        if (not hmac.compare_digest(requester, self._requester)
            or not hmac.compare_digest(transport, self._transport_digest)
            or self._binding.parameters_digest != self._parameters):
            raise RadiusServerLiveWorkflowError(_UNAVAILABLE)

    def _gate(self) -> None:
        if self._enabled is not True:
            raise RadiusServerLiveWorkflowError(_UNAVAILABLE)

    def _unconsumed(self) -> None:
        # Both properties verify their complete durable chain before counting.
        if self._execution_store.claim_count != 0 or self._material_store.claim_count != 0:
            raise RadiusServerLiveWorkflowError(_UNAVAILABLE)

    def _guard_material_source(self, binding: RadiusServerCreateBinding, request: MaterialLeaseRequest) -> None:
        """Trusted loader callback; a persisted in-progress claim cannot revive intake."""
        self._gate()
        issued = self._authority._issued
        if issued is None or binding is not self._binding or request != issued.lease_request:
            raise RadiusServerLiveWorkflowError(_UNAVAILABLE)
        _require_m4_dispatch_ownership(issued.plan, issued.authorization, self._execution_store)
        self._authority.verify(issued.plan, issued.authorization, now_epoch=self._now())
        self._gate()

    def _transport(self, issued: RadiusServerM4ExecutionBinding | None = None) -> FortiPamRadiusServerHttpTransport:
        def server_authorizer(binding: RadiusServerCreateBinding, request: MaterialLeaseRequest,
                              current_digest: str) -> bool:
            self._gate()
            if (issued is None or binding is not self._binding or request != issued.lease_request
                or not hmac.compare_digest(current_digest, issued.plan.expected_current_digest)):
                return False
            self._authority.verify(issued.plan, issued.authorization, now_epoch=self._now())
            _require_m4_dispatch_ownership(issued.plan, issued.authorization, self._execution_store)
            self._gate()
            return True

        return FortiPamRadiusServerHttpTransport(self._config, self._binding,
            expected_serial=self._serial, state_directory=self._directory,
            execution_request=None if issued is None else issued.lease_request,
            expected_current_digest=None if issued is None else issued.plan.expected_current_digest,
            execution_enabled=issued is not None and self._enabled,
            create_authorizer=None if issued is None else server_authorizer, clock=self._now,
            connection_factory=self._factory)

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                created = self._now()
                self._unconsumed()
                current = self._reader.inspect_create()
                preview = self._authority.preview(current.state_digest, created)
                self._authority.check_preview(preview, self._now())
                self._preview, self._runtime, self._started = preview, None, False
                return {
                    "contract": CONTRACT, "policy_mode": "lab_auto", "preview_ref": preview.preview_ref,
                    "expires_at": preview.expires_at,
                    "Current State": {"bound_entry_absent": True, "schema_defaults_qualified": True,
                        "dual_absence_verified": True},
                    "Proposed Changes": {"operation": "create_radius_server", "scope": "privately_bound_lab_fixture",
                        "primary_only": True, "user_group_associations": False},
                    "Expected State": {"exact_owned_entry_verified": True, "full_created_state_verified": True,
                        "original_ack_bound": True, "connectivity_qualified": False},
                    "device_write_executed": False,
                }
        except Exception:
            raise RadiusServerLiveWorkflowError(_UNAVAILABLE) from None

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._gate()
                require_ref(preview_ref, "preview_ref")
                preview = self._preview
                if preview is None or not hmac.compare_digest(preview_ref, preview.preview_ref):
                    raise ValueError
                self._authority.check_preview(preview, self._now())
                self._unconsumed()
                if self._reader.inspect_create().state_digest != preview.current_digest:
                    raise ValueError
                issued = self._authority.issue(preview)
                provider = RadiusServerMaterialProvider(self._loader, binding=self._binding,
                    request=issued.lease_request, clock=self._now)
                self._runtime = ProtectedRadiusServerM4Runtime(self._authority, self._authority,
                    self._execution_store, self._material_store, provider, self._transport(issued),
                    authenticated_requester_digest=self._requester, execution_enabled=self._enabled, clock=self._now)
                return {"contract": CONTRACT, "policy_mode": "lab_auto",
                        "authorization_ref": issued.authorization.authorization_ref, "expires_at": preview.expires_at}
        except Exception:
            raise RadiusServerLiveWorkflowError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._gate()
                require_ref(authorization_ref, "authorization_ref")
                if self._runtime is None:
                    raise ValueError
                self._authority.resolve_execution_binding(authorization_ref)
                if not self._started:
                    self._unconsumed()
                self._started = True
                result = self._runtime.execute_bound(authorization_ref)
                return {"contract": CONTRACT, **result.as_dict()}
        except Exception:
            raise RadiusServerLiveWorkflowError(_UNAVAILABLE) from None

    def close(self) -> None:
        """Close this workflow and its issued dispatcher without resetting use."""
        with self._lock:
            self._enabled = False
            if self._runtime is not None:
                self._runtime._enabled = False
                self._runtime._transport._execution_enabled = False
            self._authority._key = b""
            self._authority._issued = None
            self._authority._preview = None
            self._preview = None
