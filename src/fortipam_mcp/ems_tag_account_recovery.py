"""Default-closed authority for one exact originally verified Account recovery."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
from threading import RLock
import time
from typing import Any, TYPE_CHECKING

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .ems_tag_account_authority import EmsAccountFixturePreview, LAB_SCOPE
from .ems_tag_account_contract import CONTRACT, ACTION_VERSION, TARGET_REF
from .ems_tag_contract import _canonical
from .ems_tag_identity_sources import EmsTagIdentityObservation, EmsTagIdentitySources

if TYPE_CHECKING:
    from .ems_tag_account_custody import EmsAccountCustody, EmsAccountOriginal

ACTION_ID = "ems-tag-account-recover"
ADAPTER_REF = CONTRACT + "-recover-m4"
_ERROR = "The private original EMS account recovery authority is unavailable."
_DOMAIN = b"ems-original-account-recovery-authority/v1\x00"


def recovery_parameters(original: EmsAccountOriginal) -> str:
    original.__post_init__()
    return canonical_digest(dict(contract=CONTRACT, phase="recover", original=original.custody_digest,
        context=original.context_digest, account=original.account_digest, parent=original.parent_digest))


def recovery_current(original: EmsAccountOriginal, source: str) -> str:
    require_digest(source, "account_recovery_source")
    return canonical_digest(dict(parameters=recovery_parameters(original), source=source, scope=original.created_scope_digest))


def recovery_expected(original: EmsAccountOriginal, source: str) -> str:
    return canonical_digest(dict(current=recovery_current(original, source), restored_scope=original.baseline_digest))


@dataclass(frozen=True, slots=True, repr=False)
class EmsAccountRecoveryIssued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    source_digest: str
    scope_digest: str
    parent_digest: str
    original_digest: str
    baseline_digest: str


class EmsAccountRecoveryAuthority(_OpaqueC3Object):
    def __init__(self, sources: EmsTagIdentitySources, original: EmsAccountCustody, *, authority_key: bytes,
                 environment_ref: str, scope_ref: str, audience_ref: str, requester_digest: str, transport_digest: str,
                 execution_enabled: bool = False, clock: Callable[[], int] | None = None) -> None:
        try:
            from .ems_tag_account_custody import EmsAccountCustody
            if (type(sources) is not EmsTagIdentitySources or type(original) is not EmsAccountCustody
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool or clock is not None and not callable(clock)
                    or authority_key in (sources._key, original._key, original._store._key)):raise ValueError
            for value in (environment_ref, scope_ref, audience_ref):require_ref(value, "account_lab_scope")
            if dict(environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref) != LAB_SCOPE:raise ValueError
            for value in (requester_digest, transport_digest):require_digest(value, "account_caller")
            self._owned = original.require_recovery_source(sources, requester_digest)
            if transport_digest == original._binding["caller_transport"]:raise ValueError
            self._sources, self._original, self._key = sources, original, authority_key
            self._source, self._instance, self._session = sources.source_context_digest, sources._binding, sources._session
            self._draft, self._reference = original._draft, original._reference
            self._parameters = recovery_parameters(self._owned)
            self._binding = dict(source=self._source, instance=self._instance, session=self._session, original=self._owned.custody_digest,
                parameters=self._parameters, requester_digest=requester_digest, transport_digest=transport_digest,
                environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref, policy_mode="lab_auto")
            self._clock = clock or (lambda: int(time.time()))
            self._enabled, self._closed, self._last = execution_enabled, False, -1
            self._preview: EmsAccountFixturePreview | None = None
            self._issued: EmsAccountRecoveryIssued | None = None
            self._lock = RLock()
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def _now(self) -> int:
        value = self._clock()
        if self._closed or type(value) is not int or value < 0 or value < self._last:raise ValueError
        self._last = value;return value

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + _canonical(value), hashlib.sha256).hexdigest()

    def _pins(self) -> None:
        if (self._sources.source_context_digest != self._source or self._sources._binding != self._instance
                or self._sources._session != self._session or self._original.require_recovery_source(
                    self._sources, str(self._binding["requester_digest"])) != self._owned
                or self._original._draft != self._draft or self._original._reference != self._reference):raise ValueError

    def _observe(self, observed: EmsTagIdentityObservation) -> None:
        self._pins();self._sources.check_current(observed)
        if observed.full_scope.digest != self._owned.created_scope_digest:raise ValueError
        selected = [raw for raw in observed.full_scope._admin_details if json.loads(raw)["id"] == self._owned.account_numeric_id
                    and json.loads(raw)["vdom"] is None]
        if len(selected) != 1 or hashlib.sha256(selected[0]).hexdigest() != self._owned.account_digest:raise ValueError

    def _caller(self, requester_digest: str, transport_digest: str) -> None:
        if requester_digest != self._binding["requester_digest"] or transport_digest != self._binding["transport_digest"]:raise ValueError

    def _context(self, value: EmsAccountFixturePreview) -> dict[str, Any]:
        return dict(binding=self._binding, nonce=value.nonce, current=value.current_digest,
                    scope=value.scope_digest, created_at=value.created_at, expires_at=value.expires_at)

    def preview(self, observed: EmsTagIdentityObservation, *, requester_digest: str, transport_digest: str) -> EmsAccountFixturePreview:
        try:
            with self._lock:
                self._caller(requester_digest, transport_digest);self._observe(observed)
                if self._issued is not None:raise ValueError
                now = self._now()
                value = EmsAccountFixturePreview(secrets.token_hex(24), recovery_current(self._owned, self._source),
                    observed.full_scope.digest, now, min(now + 60, observed.expires_at), "")
                if value.expires_at <= now:raise ValueError
                self._preview = EmsAccountFixturePreview(value.nonce, value.current_digest, value.scope_digest,
                    value.created_at, value.expires_at, self._mac("preview", self._context(value)))
                return self._preview
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def _check(self, value: EmsAccountFixturePreview) -> None:
        self._pins();now = self._now()
        if (value is not self._preview or not value.created_at <= now < value.expires_at
                or not value.created_at < value.expires_at <= value.created_at + 60
                or not hmac.compare_digest(value.signature, self._mac("preview", self._context(value)))):raise ValueError

    def _derive(self, value: EmsAccountFixturePreview) -> EmsAccountRecoveryIssued:
        context = self._context(value);confirmation, approval = self._mac("standing-intent", context), self._mac("fixed-lab-policy", context)
        fields: dict[str, Any] = dict(plan_ref="ems-account-recover-plan-" + self._mac("plan-ref", context), revision=1,
            action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF, target_ref=TARGET_REF,
            requester_digest=self._binding["requester_digest"], summary_digest=self._mac("summary", context),
            confirmation_digest=confirmation, approval_digest=approval, parameters_digest=self._parameters,
            expected_current_digest=value.current_digest, expected_state_digest=recovery_expected(self._owned, self._source),
            idempotency_digest=self._mac("idempotency", context), expires_at=value.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields));signed = dict(context, plan_digest=plan.plan_digest)
        auth: dict[str, Any] = dict(authorization_ref="ems-account-recover-auth-" + self._mac("authorization-ref", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="ems-account-recover-intent-" + self._mac("intent-ref", signed), confirmation_digest=confirmation,
            approval_ref="ems-account-recover-policy-" + self._mac("approval-ref", signed), approval_digest=approval,
            approver_digest=self._mac("independent-account-policy", self._binding), issued_at=value.created_at,
            expires_at=value.expires_at, one_time=True, execution_authorized=True)
        return EmsAccountRecoveryIssued(plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)),
            self._source, value.scope_digest, self._owned.parent_digest, self._owned.custody_digest, self._owned.baseline_digest)

    def issue(self, value: EmsAccountFixturePreview, observed: EmsTagIdentityObservation, *, requester_digest: str,
              transport_digest: str) -> EmsAccountRecoveryIssued:
        try:
            with self._lock:
                self._caller(requester_digest, transport_digest);self._check(value)
                if not self._enabled or self._issued is not None:raise ValueError
                self._observe(observed)
                if observed.full_scope.digest != value.scope_digest:raise ValueError
                self._issued = self._derive(value);self._check(value);return self._issued
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
