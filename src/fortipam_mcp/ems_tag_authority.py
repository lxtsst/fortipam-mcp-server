"""Default-closed EMS-specific lab-auto authority for one disabled tag create.

Live protected source composition remains mandatory. A FortiPAM authorization,
saved proof or SUPER label alone cannot issue this independent EMS authority.
No transport, recovery issuer, Tool or normal runtime activation is provided.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import secrets
from threading import RLock
import time
from typing import Any

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .ems_tag_contract import MAX_ORIGINAL_TAGS, _canonical, create_expected_digest
from .ems_tag_custody import ACTION_ID, ADAPTER_REF, TARGET_REF
from .ems_tag_sources import EmsTagSourceObservation, EmsTagSources
from .ems_tag_fpa_sources import EmsTagFpaAdmission, binding_fields

_ERROR = "The private EMS tag authority is unavailable."
_DOMAIN = b"ems-disabled-process-tag-lab-auto-authority-v1\x00"


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagPreview(_OpaqueC3Object):
    nonce: str
    current_digest: str
    baseline_digest: str
    created_at: int
    expires_at: int
    preview_ref: str
    signature: str


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagIssued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class EmsTagCreateAuthority(_OpaqueC3Object):
    def __init__(self, sources: EmsTagSources, *, authority_key: bytes,
                 environment_ref: str, scope_ref: str, audience_ref: str,
                 requester_digest: str, transport_digest: str,
                 execution_enabled: bool = False, clock: Callable[[], int] | None = None,
                 fpa_admission: EmsTagFpaAdmission | None = None) -> None:
        try:
            if (type(sources) is not EmsTagSources or type(authority_key) is not bytes
                    or not 32 <= len(authority_key) <= 4096 or type(execution_enabled) is not bool
                    or clock is not None and not callable(clock)
                    or hmac.compare_digest(authority_key, sources._key)):
                raise ValueError
            for ref in (environment_ref, scope_ref, audience_ref):
                require_ref(ref, "ems_authority_scope")
            for digest in (requester_digest, transport_digest):
                require_digest(digest, "ems_caller")
            self._sources, self._draft = sources, sources._draft
            sources.require_phase("create", requester_digest)
            self._source = sources.source_context_digest
            self._binding: dict[str, Any] = {"contract": ADAPTER_REF, "source_context": self._source,
                "instance_scope": sources._instance, "actor": sources._actor,
                "parameters": self._draft.parameters_digest, "environment_ref": environment_ref,
                "scope_ref": scope_ref, "audience_ref": audience_ref,
                "requester_digest": requester_digest, "transport_digest": transport_digest,
                "phase": "create", "policy_mode": "lab_auto"}
            self._key, self._enabled = authority_key, execution_enabled
            self._fpa_admission = fpa_admission
            self._fpa_pin = fpa_admission
            if fpa_admission is not None:
                if (type(fpa_admission) is not EmsTagFpaAdmission or fpa_admission.phase != "create"
                        or fpa_admission.source._sources is not sources
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

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + _canonical(value),
                        hashlib.sha256).hexdigest()

    def _identity(self, requester: str, transport: str) -> None:
        if (requester != self._binding["requester_digest"]
                or transport != self._binding["transport_digest"]):
            raise ValueError

    def _pins(self) -> None:
        self._sources.require_phase("create", self._binding["requester_digest"])
        if self._fpa_admission is not self._fpa_pin:
            raise ValueError
        if self._fpa_admission is not None:
            self._fpa_admission.pins()
            if self._binding.get("fpa_admission") != binding_fields(self._fpa_admission.binding):
                raise ValueError
        if (self._sources.source_context_digest != self._source
                or self._draft.parameters_digest != self._binding["parameters"]
                or self._sources._draft is not self._draft):
            raise ValueError

    def _observe(self, observed: EmsTagSourceObservation) -> None:
        self._pins()
        self._sources.check_current(observed)
        if self._fpa_admission is not None:
            self._fpa_admission.check()
        if (observed.source_context_digest != self._source
                or observed.actor_digest != self._binding["actor"]
                or observed.full_scope.catalog.count > MAX_ORIGINAL_TAGS
                or observed.full_scope.catalog.contains_draft(self._draft)):
            raise ValueError

    def _context(self, preview: EmsTagPreview) -> dict[str, object]:
        return {**self._binding, "nonce": preview.nonce, "current": preview.current_digest,
                "baseline": preview.baseline_digest, "created_at": preview.created_at,
                "expires_at": preview.expires_at,
                "expected": create_expected_digest(self._draft, preview.baseline_digest, self._source)}

    def preview(self, observed: EmsTagSourceObservation, *, requester_digest: str,
                transport_digest: str) -> EmsTagPreview:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._observe(observed)
                if self._issued is not None:
                    raise ValueError
                now = self._now()
                expires = min(now + 60, observed.expires_at)
                if self._fpa_admission is not None:
                    expires = min(expires, self._fpa_admission.check().expires_at)
                provisional = EmsTagPreview(secrets.token_hex(24), self._sources.current_digest(observed),
                    observed.full_scope.digest, now, expires, "", "")
                context = self._context(provisional)
                preview = EmsTagPreview(provisional.nonce, provisional.current_digest,
                    provisional.baseline_digest, now, expires,
                    "ems-tag-preview-" + self._mac("preview-ref", context), self._mac("preview", context))
                self._preview = preview
                return preview
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _check(self, preview: EmsTagPreview, now: int) -> None:
        self._pins()
        if (type(preview) is not EmsTagPreview or preview is not self._preview
                or type(preview.created_at) is not int or type(preview.expires_at) is not int
                or not preview.created_at <= now < preview.expires_at
                or not preview.created_at < preview.expires_at <= preview.created_at + 60):
            raise ValueError
        context = self._context(preview)
        if (not hmac.compare_digest(preview.signature, self._mac("preview", context))
                or preview.preview_ref != "ems-tag-preview-" + self._mac("preview-ref", context)):
            raise ValueError

    def _derive(self, preview: EmsTagPreview) -> EmsTagIssued:
        context = self._context(preview)
        confirmation, approval = self._mac("standing-intent", context), self._mac("ems-policy", context)
        fields: dict[str, Any] = dict(plan_ref="ems-tag-plan-" + self._mac("plan-ref", context),
            revision=1, action_id=ACTION_ID, action_version="1.0.0", adapter_ref=ADAPTER_REF,
            target_ref=TARGET_REF, requester_digest=self._binding["requester_digest"],
            summary_digest=self._mac("summary", context), confirmation_digest=confirmation,
            approval_digest=approval, parameters_digest=self._draft.parameters_digest,
            expected_current_digest=preview.current_digest, expected_state_digest=context["expected"],
            idempotency_digest=self._mac("idempotency", context), expires_at=preview.expires_at,
            compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        signed = {**context, "plan_digest": plan.plan_digest}
        auth: dict[str, Any] = dict(authorization_ref="ems-tag-auth-" + self._mac("authorization-ref", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="ems-tag-intent-" + self._mac("intent-ref", signed),
            confirmation_digest=confirmation, approval_ref="ems-tag-approval-" + self._mac("approval-ref", signed),
            approval_digest=approval, approver_digest=self._mac("independent-ems-authority", self._binding),
            issued_at=preview.created_at, expires_at=preview.expires_at, one_time=True, execution_authorized=True)
        return EmsTagIssued(plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)))

    def issue(self, preview: EmsTagPreview, observed: EmsTagSourceObservation, *,
              requester_digest: str, transport_digest: str) -> EmsTagIssued:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._check(preview, self._now())
                if not self._enabled or self._issued is not None:
                    raise ValueError
                self._observe(observed)
                if (self._sources.current_digest(observed) != preview.current_digest
                        or observed.full_scope.digest != preview.baseline_digest):
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
                preview, issued, now = self._preview, self._issued, self._now()
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

    def check_current(self, issued: EmsTagIssued, observed: EmsTagSourceObservation) -> None:
        try:
            with self._lock:
                if issued is not self._issued or self._preview is None:
                    raise ValueError
                self.verify(issued.plan, issued.authorization, now_epoch=self._now())
                self._observe(observed)
                if (self._sources.current_digest(observed) != self._preview.current_digest
                        or observed.full_scope.digest != self._preview.baseline_digest):
                    raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled, self._failed = False, True
