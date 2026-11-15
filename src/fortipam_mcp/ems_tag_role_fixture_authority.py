"""Default-closed authority for original Role creation or exact owned recovery."""
from __future__ import annotations

from collections.abc import Callable
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

from .ems_tag_contract import _canonical
from .ems_tag_identity_contract import MAX_ROLES
from .ems_tag_identity_sources import EmsTagIdentitySources, EmsTagIdentityObservation
from .ems_tag_role_contract import ProspectiveEmsTagManagerRole
from .ems_tag_role_fixture_contract import (
    VERSION, TARGET_REF, LAB_SCOPE, action, current_digest, expected_digest,
    EmsRoleFixturePreview, EmsRoleFixtureIssued, EmsRoleFixtureOriginal,
)

if TYPE_CHECKING:
    from .ems_tag_role_fixture_custody import EmsRoleFixtureCustody

_ERROR = "The private EMS role fixture authority is unavailable."
_DOMAIN = b"ems-original-role-fixture-authority/v1\x00"


class EmsRoleFixtureAuthority(_OpaqueC3Object):
    def __init__(self, sources: EmsTagIdentitySources, draft: ProspectiveEmsTagManagerRole, *,
                 authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
                 requester_digest: str, transport_digest: str, execution_enabled: bool = False,
                 original: EmsRoleFixtureCustody | None = None, clock: Callable[[], int] | None = None) -> None:
        try:
            from .ems_tag_role_fixture_custody import EmsRoleFixtureCustody
            if (type(sources) is not EmsTagIdentitySources or type(draft) is not ProspectiveEmsTagManagerRole
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool or clock is not None and not callable(clock)
                    or authority_key == sources._key):raise ValueError
            for value in (environment_ref, scope_ref, audience_ref):require_ref(value, "role_lab_scope")
            if dict(environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref) != LAB_SCOPE:raise ValueError
            for value in (requester_digest, transport_digest):require_digest(value, "role_caller")
            draft.__post_init__()
            self._sources, self._draft, self._key = sources, draft, authority_key
            self._source, self._instance, self._session = sources.source_context_digest, sources._binding, sources._session
            self._original, self._original_pin = original, original
            self._owned: EmsRoleFixtureOriginal | None = None
            if original is not None:
                if (type(original) is not EmsRoleFixtureCustody or authority_key == original._key
                        or transport_digest == original._binding["caller_transport"]):raise ValueError
                self._owned = original.require_recovery_source(sources, requester_digest)
                if original._draft.parameters_digest != draft.parameters_digest:raise ValueError
            self._phase = "recover" if original is not None else "create"
            self._binding = dict(phase=self._phase, source=self._source, instance=self._instance, session=self._session,
                parameters=draft.parameters_digest, environment_ref=environment_ref, scope_ref=scope_ref,
                audience_ref=audience_ref, requester_digest=requester_digest, transport_digest=transport_digest,
                original=self._owned.custody_digest if self._owned else None, policy_mode="lab_auto")
            self._enabled, self._closed, self._last = execution_enabled, False, -1
            self._clock = clock or (lambda: int(time.time()))
            self._preview: EmsRoleFixturePreview | None = None
            self._issued: EmsRoleFixtureIssued | None = None
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
        if (self._original is not self._original_pin or self._sources.source_context_digest != self._source
                or self._sources._binding != self._instance or self._sources._session != self._session
                or self._draft.parameters_digest != self._binding["parameters"]):raise ValueError
        if self._original is not None and self._original.require_recovery_source(
                self._sources, str(self._binding["requester_digest"])) != self._owned:raise ValueError

    def _observe(self, observed: EmsTagIdentityObservation) -> None:
        self._pins();self._sources.check_current(observed)
        scope = observed.full_scope
        if scope.schema.digest != self._draft.schema.digest:raise ValueError
        if self._owned is None:
            if (len(scope._role_rows) >= MAX_ROLES or any(json.loads(raw)["name"].casefold()
                    == self._draft._body["name"].casefold() for raw in scope._role_rows)):raise ValueError
        else:
            roles = [detail for detail in scope._role_details if detail._uid == self._owned.role_uid]
            if (scope.digest != self._owned.created_scope_digest or len(roles) != 1
                    or roles[0].digest != self._owned.role_digest or not roles[0].matches_proposal(self._draft)
                    or scope.role_is_referenced(self._owned.role_uid)):raise ValueError

    def _caller(self, requester_digest: str, transport_digest: str) -> None:
        if (requester_digest != self._binding["requester_digest"] or transport_digest != self._binding["transport_digest"]):raise ValueError

    def _context(self, preview: EmsRoleFixturePreview) -> dict[str, Any]:
        baseline = self._owned.baseline_digest if self._owned else preview.scope_digest
        return dict(binding=self._binding, nonce=preview.nonce, current=preview.current_digest,
            scope=preview.scope_digest, baseline=baseline, created_at=preview.created_at, expires_at=preview.expires_at)

    def preview(self, observed: EmsTagIdentityObservation, *, requester_digest: str,
                transport_digest: str) -> EmsRoleFixturePreview:
        try:
            with self._lock:
                self._caller(requester_digest, transport_digest);self._observe(observed)
                if self._issued is not None:raise ValueError
                now = self._now()
                value = EmsRoleFixturePreview(secrets.token_hex(24), current_digest(self._draft,
                    observed.full_scope.digest, self._source, self._phase, self._binding["original"]),
                    observed.full_scope.digest, now, min(now + 60, observed.expires_at), "")
                self._preview = EmsRoleFixturePreview(value.nonce, value.current_digest, value.scope_digest,
                    value.created_at, value.expires_at, self._mac("preview", self._context(value)))
                return self._preview
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def _check(self, preview: EmsRoleFixturePreview) -> None:
        self._pins();now = self._now()
        if (preview is not self._preview or not preview.created_at <= now < preview.expires_at
                or not preview.created_at < preview.expires_at <= preview.created_at + 60
                or preview.signature != self._mac("preview", self._context(preview))):raise ValueError

    def _derive(self, preview: EmsRoleFixturePreview) -> EmsRoleFixtureIssued:
        context = self._context(preview)
        confirmation, approval = self._mac("standing-intent", context), self._mac("fixed-lab-policy", context)
        action_id, adapter_ref = action(self._phase)
        fields: dict[str, Any] = dict(plan_ref="ems-role-plan-" + self._mac("plan-ref", context), revision=1,
            action_id=action_id, action_version=VERSION, adapter_ref=adapter_ref, target_ref=TARGET_REF,
            requester_digest=self._binding["requester_digest"], summary_digest=self._mac("summary", context),
            confirmation_digest=confirmation, approval_digest=approval, parameters_digest=self._draft.parameters_digest,
            expected_current_digest=preview.current_digest, expected_state_digest=expected_digest(self._draft,
                context["baseline"], self._source, self._phase, self._binding["original"]),
            idempotency_digest=self._mac("idempotency", context), expires_at=preview.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        signed = dict(context, plan_digest=plan.plan_digest)
        auth: dict[str, Any] = dict(authorization_ref="ems-role-auth-" + self._mac("authorization-ref", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="ems-role-intent-" + self._mac("intent-ref", signed), confirmation_digest=confirmation,
            approval_ref="ems-role-policy-" + self._mac("approval-ref", signed), approval_digest=approval,
            approver_digest=self._mac("independent-role-policy", self._binding), issued_at=preview.created_at,
            expires_at=preview.expires_at, one_time=True, execution_authorized=True)
        return EmsRoleFixtureIssued(self._phase, plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)),
            self._source, preview.scope_digest, context["baseline"], self._binding["original"])

    def issue(self, preview: EmsRoleFixturePreview, observed: EmsTagIdentityObservation, *, requester_digest: str,
              transport_digest: str) -> EmsRoleFixtureIssued:
        try:
            with self._lock:
                self._caller(requester_digest, transport_digest);self._check(preview)
                if not self._enabled or self._issued is not None:raise ValueError
                self._observe(observed)
                if observed.full_scope.digest != preview.scope_digest:raise ValueError
                self._issued = self._derive(preview)
                self._check(preview)
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
