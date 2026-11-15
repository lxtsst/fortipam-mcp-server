"""Default-closed independent EMS authority for original-owned Tag recovery.

The original verified ledger is evidence only. Fresh recovery intent, issuer,
caller transport and actual owner session are separate; create approval never
authorizes deletion. No HTTP writer or normal MCP action is exposed here.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import secrets
from threading import RLock
import time
from typing import Any

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_ref

from .ems_tag_authority import EmsTagPreview, EmsTagIssued
from .ems_tag_contract import _canonical
from .ems_tag_recovery_contract import EmsTagOwnedRecoveryScope, EmsTagRecoveryObservation
from .ems_tag_fpa_sources import EmsTagFpaAdmission, binding_fields

ACTION_ID = "ems-disabled-process-tag-recover"
ADAPTER_REF = "ems-7.4.8.2245-original-owned-tag-recover-m4-v1"
TARGET_REF = "bound-original-disabled-ems-tag"
_DOMAIN = b"ems-original-owned-tag-recovery-authority/v1\x00"
_ERROR = "The private independent EMS recovery authority is unavailable."


class EmsTagRecoveryAuthority(_OpaqueC3Object):
    def __init__(self, scope: EmsTagOwnedRecoveryScope, *, authority_key: bytes,
                 environment_ref: str, scope_ref: str, audience_ref: str,
                 execution_enabled: bool = False, clock: Callable[[], int] | None = None,
                 fpa_admission: EmsTagFpaAdmission | None = None) -> None:
        try:
            if (type(scope) is not EmsTagOwnedRecoveryScope or type(authority_key) is not bytes
                    or not 32 <= len(authority_key) <= 4096 or type(execution_enabled) is not bool
                    or clock is not None and not callable(clock)):
                raise ValueError
            scope._pins()
            original = scope._original
            if (authority_key in {scope._sources._key, original._key, original._store._key}
                    or hashlib.sha256(authority_key).hexdigest() == scope._birth.actor_binding.issuer_key_digest):
                raise ValueError
            for ref in (environment_ref, scope_ref, audience_ref):
                require_ref(ref, "ems_recovery_scope")
            self._scope = scope
            self._binding: dict[str, Any] = {"contract": ADAPTER_REF, "recovery_context": scope._context,
                "source": scope._source, "original": scope._birth.custody_digest,
                "requester_digest": scope._requester, "transport_digest": scope._caller_transport,
                "owner_session": scope._session, "environment_ref": environment_ref,
                "scope_ref": scope_ref, "audience_ref": audience_ref, "policy_mode": "lab_auto"}
            self._key, self._enabled = authority_key, execution_enabled
            self._fpa_admission = fpa_admission
            self._fpa_pin = fpa_admission
            if fpa_admission is not None:
                if (type(fpa_admission) is not EmsTagFpaAdmission or fpa_admission.phase != "recover"
                        or fpa_admission.original is not original or fpa_admission.source._sources is not scope._sources
                        or hmac.compare_digest(authority_key, fpa_admission.source._key)):
                    raise ValueError
                fpa_admission.check()
                self._binding["fpa_admission"] = binding_fields(fpa_admission.binding)
            self._clock = clock or (lambda: int(time.time()))
            self._last, self._failed, self._lock = -1, False, RLock()
            self._preview: EmsTagPreview | None = None
            self._issued: EmsTagIssued | None = None
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _now(self) -> int:
        try:
            now = self._clock()
            if self._failed or type(now) is not int or now < 0 or now < self._last:
                raise ValueError
            self._last = now
            return now
        except Exception:
            self._failed = True
            raise ValueError from None

    def _pins(self) -> None:
        if self._fpa_admission is not self._fpa_pin:
            raise ValueError
        if self._fpa_admission is not None:
            self._fpa_admission.pins()
            if self._binding.get("fpa_admission") != binding_fields(self._fpa_admission.binding):
                raise ValueError
        self._scope._pins()
        if (self._scope._context != self._binding["recovery_context"]
                or self._scope._source != self._binding["source"]
                or self._scope._requester != self._binding["requester_digest"]
                or self._scope._caller_transport != self._binding["transport_digest"]
                or self._scope._session != self._binding["owner_session"]):
            raise ValueError

    def _identity(self, requester: str, transport: str) -> None:
        if (requester != self._binding["requester_digest"] or transport != self._binding["transport_digest"]):
            raise ValueError

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + _canonical(value), hashlib.sha256).hexdigest()

    def _observe(self, observed: EmsTagRecoveryObservation) -> None:
        self._pins()
        self._scope.check_current(observed)
        if self._fpa_admission is not None:
            self._fpa_admission.check()
        if (observed.expected_digest != self._scope._expected
                or observed.original_custody_digest != self._scope._birth.custody_digest):
            raise ValueError

    def _context(self, preview: EmsTagPreview) -> dict[str, object]:
        return {**self._binding, "nonce": preview.nonce, "current": preview.current_digest,
            "baseline": preview.baseline_digest, "expected": self._scope._expected,
            "created_at": preview.created_at, "expires_at": preview.expires_at}

    def preview(self, observed: EmsTagRecoveryObservation, *, requester_digest: str,
                transport_digest: str) -> EmsTagPreview:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._observe(observed)
                if self._issued is not None:
                    raise ValueError
                now = self._now()
                if not observed.observed_at <= now < observed.expires_at:
                    raise ValueError
                expires = min(now + 60, observed.expires_at)
                if self._fpa_admission is not None:
                    expires = min(expires, self._fpa_admission.check().expires_at)
                provisional = EmsTagPreview(secrets.token_hex(24), observed.current_digest,
                    self._scope._original._baseline, now, expires, "", "")
                context = self._context(provisional)
                result = EmsTagPreview(provisional.nonce, provisional.current_digest, provisional.baseline_digest,
                    now, expires, "ems-tag-recovery-preview-" + self._mac("preview-ref", context), self._mac("preview", context))
                self._preview = result
                return result
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _check(self, preview: EmsTagPreview, now: int) -> None:
        self._pins()
        if (type(preview) is not EmsTagPreview or preview is not self._preview
                or type(preview.created_at) is not int or type(preview.expires_at) is not int
                or not preview.created_at <= now < preview.expires_at
                or not preview.created_at < preview.expires_at <= preview.created_at + 60
                or preview.baseline_digest != self._scope._original._baseline):
            raise ValueError
        context = self._context(preview)
        if (not hmac.compare_digest(preview.signature, self._mac("preview", context))
                or preview.preview_ref != "ems-tag-recovery-preview-" + self._mac("preview-ref", context)):
            raise ValueError

    def _derive(self, preview: EmsTagPreview) -> EmsTagIssued:
        context = self._context(preview)
        confirmation, approval = self._mac("standing-recovery-intent", context), self._mac("ems-recovery-policy", context)
        fields: dict[str, Any] = dict(plan_ref="ems-tag-recovery-plan-" + self._mac("plan-ref", context), revision=1,
            action_id=ACTION_ID, action_version="1.0.0", adapter_ref=ADAPTER_REF, target_ref=TARGET_REF,
            requester_digest=self._scope._requester, summary_digest=self._mac("summary", context),
            confirmation_digest=confirmation, approval_digest=approval, parameters_digest=canonical_digest(self._binding),
            expected_current_digest=preview.current_digest, expected_state_digest=self._scope._expected,
            idempotency_digest=self._mac("idempotency", context), expires_at=preview.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        signed = {**context, "plan_digest": plan.plan_digest}
        auth: dict[str, Any] = dict(authorization_ref="ems-tag-recovery-auth-" + self._mac("authorization-ref", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="ems-tag-recovery-intent-" + self._mac("intent-ref", signed), confirmation_digest=confirmation,
            approval_ref="ems-tag-recovery-approval-" + self._mac("approval-ref", signed), approval_digest=approval,
            approver_digest=self._mac("independent-ems-recovery-authority", self._binding), issued_at=preview.created_at,
            expires_at=preview.expires_at, one_time=True, execution_authorized=True)
        return EmsTagIssued(plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)))

    def issue(self, preview: EmsTagPreview, observed: EmsTagRecoveryObservation, *,
              requester_digest: str, transport_digest: str) -> EmsTagIssued:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._check(preview, self._now())
                if not self._enabled or self._issued is not None:
                    raise ValueError
                self._observe(observed)
                if observed.current_digest != preview.current_digest:
                    raise ValueError
                issued = self._derive(preview)
                self._check(preview, self._now())
                self._issued = issued
                return issued
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                now, preview, issued = self._now(), self._preview, self._issued
                if not self._enabled or preview is None or issued is None:
                    raise ValueError
                self._check(preview, now)
                expected = self._derive(preview)
                if (type(now_epoch) is not int or not preview.created_at <= now_epoch <= now
                        or plan is not issued.plan or authorization is not issued.authorization
                        or plan != expected.plan or authorization != expected.authorization):
                    raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def check_current(self, issued: EmsTagIssued, observed: EmsTagRecoveryObservation) -> None:
        try:
            with self._lock:
                if issued is not self._issued or self._preview is None:
                    raise ValueError
                self.verify(issued.plan, issued.authorization, now_epoch=self._now())
                self._observe(observed)
                if observed.current_digest != self._preview.current_digest:
                    raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled, self._failed = False, True
