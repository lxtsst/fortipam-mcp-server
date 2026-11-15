"""Default-closed lab authority for one original EMS account creation."""
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
from v4_planning.models import require_digest, require_ref

from .ems_tag_account_contract import ACTION_ID, ACTION_VERSION, ADAPTER_REF, TARGET_REF, current_digest, expected_digest
from .ems_tag_account_enrollment import EmsAccountCentralEnrollment
from .ems_tag_contract import _canonical
from .ems_tag_identity_contract import MAX_ADMINS
from .ems_tag_identity_sources import EmsTagIdentityObservation

LAB_SCOPE = {"environment_ref": "ems-home-lab", "scope_ref": "ems-tag-account-fixture-lab", "audience_ref": "local-account-fixture"}
_ERROR = "The private EMS account fixture authority is unavailable."
_DOMAIN = b"ems-original-account-fixture-authority/v1\x00"


@dataclass(frozen=True, slots=True, repr=False)
class EmsAccountFixturePreview(_OpaqueC3Object):
    nonce: str
    current_digest: str
    scope_digest: str
    created_at: int
    expires_at: int
    signature: str


@dataclass(frozen=True, slots=True, repr=False)
class EmsAccountFixtureIssued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    source_digest: str
    scope_digest: str
    parent_digest: str


class EmsAccountFixtureAuthority(_OpaqueC3Object):
    def __init__(self, enrollment: EmsAccountCentralEnrollment, *, authority_key: bytes,
                 environment_ref: str, scope_ref: str, audience_ref: str,
                 requester_digest: str, transport_digest: str, execution_enabled: bool = False,
                 clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(enrollment) is not EmsAccountCentralEnrollment or type(authority_key) is not bytes
                    or not 32 <= len(authority_key) <= 4096 or type(execution_enabled) is not bool
                    or clock is not None and not callable(clock)
                    or authority_key in (enrollment._key, enrollment._sources._key,
                                         enrollment._parent._key, enrollment._parent._store._key)):
                raise ValueError
            for value in (environment_ref, scope_ref, audience_ref):require_ref(value, "account_lab_scope")
            if dict(environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref) != LAB_SCOPE:
                raise ValueError
            for value in (requester_digest, transport_digest):require_digest(value, "account_caller")
            if requester_digest != enrollment._requester:raise ValueError
            enrollment.check_registered();enrollment._role_current()
            if (enrollment._directory / "material.used.json").exists():raise ValueError
            self._enrollment, self._sources, self._key = enrollment, enrollment._sources, authority_key
            self._source, self._instance, self._session = self._sources.source_context_digest, self._sources._binding, self._sources._session
            self._reference, self._parameters, self._parent = enrollment.reference, enrollment.parameters_digest, enrollment._owned
            self._binding = dict(source=self._source, instance=self._instance, session=self._session,
                parameters=self._parameters, parent=self._parent.custody_digest, material=self._reference,
                environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref,
                requester_digest=requester_digest, transport_digest=transport_digest, policy_mode="lab_auto")
            self._clock = clock or (lambda: int(time.time()))
            self._enabled, self._closed, self._last = execution_enabled, False, -1
            self._preview: EmsAccountFixturePreview | None = None
            self._issued: EmsAccountFixtureIssued | None = None
            self._lock = RLock()
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def _now(self) -> int:
        value = self._clock()
        if self._closed or type(value) is not int or value < 0 or value < self._last:raise ValueError
        self._last = value
        return value

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + _canonical(value), hashlib.sha256).hexdigest()

    def _pins(self) -> None:
        enrollment = self._enrollment
        if (enrollment._sources is not self._sources or self._sources.source_context_digest != self._source
                or self._sources._binding != self._instance or self._sources._session != self._session
                or enrollment._owned != self._parent or enrollment._parent.inspect_verified_original() != self._parent
                or enrollment.reference != self._reference or enrollment.parameters_digest != self._parameters):raise ValueError
        enrollment.check_registered()

    def _observe(self, observed: EmsTagIdentityObservation) -> None:
        self._pins();self._sources.check_current(observed);self._enrollment._role_current()
        if ((self._enrollment._directory / "material.used.json").exists()
                or len(observed.full_scope._admin_rows) >= MAX_ADMINS
                or any(json.loads(raw)["name"].casefold() == self._enrollment._draft._metadata_body["name"].casefold()
                       for raw in observed.full_scope._admin_rows)):
            raise ValueError

    def _caller(self, requester_digest: str, transport_digest: str) -> None:
        if requester_digest != self._binding["requester_digest"] or transport_digest != self._binding["transport_digest"]:
            raise ValueError

    def _context(self, preview: EmsAccountFixturePreview) -> dict[str, Any]:
        return dict(binding=self._binding, nonce=preview.nonce, current=preview.current_digest,
                    scope=preview.scope_digest, created_at=preview.created_at, expires_at=preview.expires_at)

    def preview(self, observed: EmsTagIdentityObservation, *, requester_digest: str,
                transport_digest: str) -> EmsAccountFixturePreview:
        try:
            with self._lock:
                self._caller(requester_digest, transport_digest);self._observe(observed)
                if self._issued is not None:raise ValueError
                now = self._now();prepare = self._enrollment._prepare()
                value = EmsAccountFixturePreview(secrets.token_hex(24), current_digest(self._enrollment._draft,
                    self._reference, self._parent.custody_digest, observed.full_scope.digest, self._source),
                    observed.full_scope.digest, now, min(now + 60, observed.expires_at, prepare["expires_at"]), "")
                if value.expires_at <= now:raise ValueError
                self._preview = EmsAccountFixturePreview(value.nonce, value.current_digest, value.scope_digest,
                    value.created_at, value.expires_at, self._mac("preview", self._context(value)))
                return self._preview
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def _check(self, preview: EmsAccountFixturePreview) -> None:
        self._pins();now = self._now()
        if (preview is not self._preview or not preview.created_at <= now < preview.expires_at
                or not preview.created_at < preview.expires_at <= preview.created_at + 60
                or not hmac.compare_digest(preview.signature, self._mac("preview", self._context(preview)))):raise ValueError

    def _derive(self, preview: EmsAccountFixturePreview) -> EmsAccountFixtureIssued:
        context = self._context(preview)
        confirmation, approval = self._mac("standing-intent", context), self._mac("fixed-lab-policy", context)
        fields: dict[str, Any] = dict(plan_ref="ems-account-plan-" + self._mac("plan-ref", context), revision=1,
            action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF, target_ref=TARGET_REF,
            requester_digest=self._binding["requester_digest"], summary_digest=self._mac("summary", context),
            confirmation_digest=confirmation, approval_digest=approval, parameters_digest=self._parameters,
            expected_current_digest=preview.current_digest, expected_state_digest=expected_digest(self._enrollment._draft,
                self._reference, self._parent.custody_digest, preview.scope_digest, self._source),
            idempotency_digest=self._mac("idempotency", context), expires_at=preview.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        signed = dict(context, plan_digest=plan.plan_digest)
        auth: dict[str, Any] = dict(authorization_ref="ems-account-auth-" + self._mac("authorization-ref", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="ems-account-intent-" + self._mac("intent-ref", signed), confirmation_digest=confirmation,
            approval_ref="ems-account-policy-" + self._mac("approval-ref", signed), approval_digest=approval,
            approver_digest=self._mac("independent-account-policy", self._binding), issued_at=preview.created_at,
            expires_at=preview.expires_at, one_time=True, execution_authorized=True)
        return EmsAccountFixtureIssued(plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)),
                                       self._source, preview.scope_digest, self._parent.custody_digest)

    def issue(self, preview: EmsAccountFixturePreview, observed: EmsTagIdentityObservation, *, requester_digest: str,
              transport_digest: str) -> EmsAccountFixtureIssued:
        try:
            with self._lock:
                self._caller(requester_digest, transport_digest);self._check(preview)
                if not self._enabled or self._issued is not None:raise ValueError
                self._observe(observed)
                if observed.full_scope.digest != preview.scope_digest:raise ValueError
                self._issued = self._derive(preview);self._check(preview)
                return self._issued
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                if not self._enabled or self._preview is None or self._issued is None:raise ValueError
                self._check(self._preview)
                if (type(now_epoch) is not int or not self._preview.created_at <= now_epoch <= self._last
                        or plan is not self._issued.plan or authorization is not self._issued.authorization
                        or self._derive(self._preview) != self._issued):raise ValueError
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def check_current(self, observed: EmsTagIdentityObservation) -> None:
        if self._issued is None or self._preview is None:raise M4AuthorizationDenied(_ERROR)
        self.verify(self._issued.plan, self._issued.authorization, now_epoch=self._now())
        try:
            self._observe(observed)
            if observed.full_scope.digest != self._preview.scope_digest:raise ValueError
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:self._enabled, self._closed = False, True
