"""Default-off lab-auto M4 authority for one source-bound local reset fixture.

Trusted composition supplies this server key and exact lab scope. Neither an
offline proof nor a caller-supplied digest can stand in for the live source join.
The separately gated adapter still owns dispatch claims and fixed readback.
"""
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

from v4_planning import M4AuthorizationDenied, M4ExecutionPlan, M4ExecutionAuthorization, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .local_user_reset_fixture_sources import LocalResetFixtureSources, LocalResetSourceObservation
from .local_user_reset_fixture_custody import LocalResetFixtureAckCustody, ACTION_ID, ADAPTER_REF, ACTION_VERSION
from .local_user_reset_fixture_material import LocalResetInitialMaterialSource

RECOVER_ACTION = "local-reset-fixture-recover"
RECOVER_ADAPTER = "fortipam-build29-local-reset-fixture-recover-m4-v1"
_CONTRACT = "fortipam-build29-local-reset-fixture-authority-v1"
_DOMAIN = b"fortipam-local-reset-fixture-lab-auto-v1\x00"
_ERROR = "The private local reset fixture authority is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class LocalResetFixturePreview(_OpaqueC3Object):
    nonce: str
    current_digest: str
    dependency_digest: str
    created_at: int
    expires_at: int
    preview_ref: str
    signature: str


@dataclass(frozen=True, slots=True, repr=False)
class LocalResetFixtureIssued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class LocalResetFixtureM4Authority(_OpaqueC3Object):
    def __init__(self, sources: LocalResetFixtureSources, *, phase: str,
            authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
            requester_digest: str, transport_digest: str, original: LocalResetFixtureAckCustody | None = None,
            material: LocalResetInitialMaterialSource | None = None,
            execution_enabled: bool = False, clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(sources) is not LocalResetFixtureSources or phase not in ("create", "recover")
                    or type(phase) is not str or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool or clock is not None and not callable(clock)):
                raise ValueError
            for value in (environment_ref, scope_ref, audience_ref): require_ref(value, "fixture_scope")
            for value in (requester_digest, transport_digest): require_digest(value, "fixture_identity")
            self._sources, self._body_digest = sources, sources._state._draft.nonmaterial_request_digest
            self._source = sources.source_context_digest
            self._original, self._material = original, material
            creation = None
            state = None
            baseline = None
            namespace = None
            material_ref = None
            if phase == "create":
                if (original is not None or type(material) is not LocalResetInitialMaterialSource
                        or material._sources is not sources or hmac.compare_digest(authority_key, material._key)
                        or hmac.compare_digest(authority_key, material._store._key)): raise ValueError
                material.check_staged()
                material_ref = material.reference
            else:
                if (material is not None or type(original) is not LocalResetFixtureAckCustody
                        or original._pins.body_digest != self._body_digest
                        or original._pins.username != sources._state._draft.username
                        or original._pins.serial_digest != sources._state._serial
                        or original._pins.actor_context_digest != sources._state._actor
                        or hmac.compare_digest(authority_key, original._key)
                        or hmac.compare_digest(authority_key, original._store._key)):
                    raise ValueError
                absence = original.inspect_original_absence()
                observed = original.inspect_original_full_state()
                if (absence.source_context_digest != self._source or absence.state_source_digest != sources._state._context()
                        or observed.source_context_digest != absence.state_source_digest or observed.state_digest is None
                        or original._plan.requester_digest != requester_digest
                        or (observed.original_ack.original_outcome, observed.original_ack.original_verification) not in
                            (("succeeded", "verified"), ("reconciliation_required", "unknown"))):
                    raise ValueError
                creation, state = observed.custody_digest, observed.state_digest
                baseline, namespace = absence.custody_digest, absence.presence_namespace_digest
            self._binding = dict(contract=_CONTRACT, phase=phase, body_digest=self._body_digest,
                source_context_digest=self._source, original_creation_digest=creation, original_state_digest=state,
                original_absence_digest=baseline, original_namespace_digest=namespace, initial_material_ref=material_ref,
                environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref,
                requester_digest=requester_digest, transport_digest=transport_digest, policy_mode="lab_auto")
            self._key, self._enabled = authority_key, execution_enabled
            self._clock = clock if clock is not None else lambda:int(time.time())
            self._last = -1
            self._failed = self._closed = False
            self._lock = RLock()
            self._preview: LocalResetFixturePreview | None = None
            self._issued: LocalResetFixtureIssued | None = None
            self.expected_digest = canonical_digest({**self._binding,
                "postcondition":"original-full-state-and-exact-global-presence" if phase == "create"
                    else "qualified-original-global-absence"})
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _now(self) -> int:
        try:
            value = self._clock()
            if self._failed or self._closed or type(value) is not int or value < 0 or value < self._last:
                raise ValueError
            self._last = value
            return value
        except Exception:
            self._failed = True
            raise M4AuthorizationDenied(_ERROR) from None

    def _pins(self) -> None:
        if self._sources.source_context_digest != self._source:
            raise ValueError
        if self._sources._state._draft.nonmaterial_request_digest != self._body_digest:
            raise ValueError
        if self._material is not None:
            if self._material.reference != self._binding["initial_material_ref"]: raise ValueError
            self._material.check_staged()
        if self._original is not None:
            absence = self._original.inspect_original_absence()
            observed = self._original.inspect_original_full_state()
            if (observed.custody_digest != self._binding["original_creation_digest"]
                    or observed.state_digest != self._binding["original_state_digest"]
                    or absence.custody_digest != self._binding["original_absence_digest"]
                    or absence.source_context_digest != self._source
                    or observed.source_context_digest != self._sources._state._context()):
                raise ValueError

    def _identity(self, requester: str, transport: str) -> None:
        if requester != self._binding["requester_digest"] or transport != self._binding["transport_digest"]:
            raise ValueError

    def _observe(self, observed: LocalResetSourceObservation) -> None:
        self._pins()
        self._sources.check_current(observed)
        if self._binding["phase"] == "create":
            if not observed.absent or observed.state_digest is not None or observed.admin_count >= 128: raise ValueError
        elif (observed.absent or observed.state_digest != self._binding["original_state_digest"]
                or observed.namespace_digest != self._binding["original_namespace_digest"]):
            raise ValueError

    def _mac(self, purpose: str, value: object) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + raw, hashlib.sha256).hexdigest()

    def _context(self, preview: LocalResetFixturePreview) -> dict[str, object]:
        return {**self._binding, "nonce":preview.nonce, "current_digest":preview.current_digest,
            "dependency_digest":preview.dependency_digest, "expected_digest":self.expected_digest,
            "created_at":preview.created_at, "expires_at":preview.expires_at}

    def preview(self, observed: LocalResetSourceObservation, *, requester_digest: str,
            transport_digest: str) -> LocalResetFixturePreview:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest); self._observe(observed)
                now = self._now()
                provisional = LocalResetFixturePreview(secrets.token_hex(24), observed.current_digest,
                    observed.dependency_digest, now, now+60, "", "")
                context = self._context(provisional)
                preview = LocalResetFixturePreview(provisional.nonce, provisional.current_digest, provisional.dependency_digest,
                    now, now+60, "reset-fixture-preview-"+self._mac("preview-ref",context), self._mac("preview",context))
                self._preview, self._issued = preview, None
                return preview
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _check(self, preview: LocalResetFixturePreview, now: int) -> None:
        self._pins()
        if (type(preview) is not LocalResetFixturePreview or preview is not self._preview
                or type(preview.created_at) is not int or type(preview.expires_at) is not int
                or not preview.created_at <= now < preview.expires_at or preview.expires_at != preview.created_at+60):
            raise ValueError
        context = self._context(preview)
        if (not hmac.compare_digest(preview.signature,self._mac("preview",context))
                or preview.preview_ref != "reset-fixture-preview-"+self._mac("preview-ref",context)):
            raise ValueError

    def _derive(self, preview: LocalResetFixturePreview) -> LocalResetFixtureIssued:
        context = self._context(preview)
        creation = self._binding["phase"] == "create"
        parameters = self._material.parameters_digest if creation and self._material is not None else canonical_digest(self._binding)
        confirmation = self._mac("standing-intent",context)
        approval = self._mac("lab-policy",context)
        values: dict[str,Any] = dict(plan_ref="reset-fixture-plan-"+self._mac("plan-ref",context), revision=1,
            action_id=ACTION_ID if creation else RECOVER_ACTION, action_version=ACTION_VERSION if creation else "1.0.0",
            adapter_ref=ADAPTER_REF if creation else RECOVER_ADAPTER, target_ref="bound-local-reset-fixture",
            requester_digest=self._binding["requester_digest"], summary_digest=self._mac("summary",context),
            confirmation_digest=confirmation, approval_digest=approval, parameters_digest=parameters,
            expected_current_digest=preview.current_digest, expected_state_digest=self.expected_digest,
            idempotency_digest=self._mac("idempotency",context), expires_at=preview.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**values,plan_digest=canonical_digest(values))
        signed = {**context,"plan_digest":plan.plan_digest}
        auth: dict[str,Any] = dict(authorization_ref="reset-fixture-auth-"+self._mac("authorization-ref",signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="reset-fixture-intent-"+self._mac("intent-ref",signed), confirmation_digest=confirmation,
            approval_ref="reset-fixture-approval-"+self._mac("approval-ref",signed), approval_digest=approval,
            approver_digest=self._mac("lab-policy-authority",self._binding), issued_at=preview.created_at,
            expires_at=preview.expires_at, one_time=True, execution_authorized=True)
        return LocalResetFixtureIssued(plan,M4ExecutionAuthorization(**auth,authorization_digest=canonical_digest(auth)))

    def issue(self, preview: LocalResetFixturePreview, observed: LocalResetSourceObservation, *,
            requester_digest: str, transport_digest: str) -> LocalResetFixtureIssued:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest); self._check(preview,self._now())
                if not self._enabled or self._issued is not None: raise ValueError
                self._observe(observed)
                if (observed.current_digest,observed.dependency_digest) != (preview.current_digest,preview.dependency_digest):
                    raise ValueError
                issued = self._derive(preview)
                self._check(preview,self._now())
                self._issued = issued
                return issued
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                preview,issued,now = self._preview,self._issued,self._now()
                if not self._enabled or preview is None or issued is None: raise ValueError
                self._check(preview,now)
                expected = self._derive(preview)
                if (type(now_epoch) is not int or not preview.created_at <= now_epoch <= now
                        or plan is not issued.plan or authorization is not issued.authorization
                        or plan != expected.plan or authorization != expected.authorization):
                    raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def check_current(self, issued: LocalResetFixtureIssued, observed: LocalResetSourceObservation) -> None:
        try:
            with self._lock:
                if issued is not self._issued or self._preview is None: raise ValueError
                self.verify(issued.plan,issued.authorization,now_epoch=self._now())
                self._observe(observed)
                if (observed.current_digest,observed.dependency_digest) != (self._preview.current_digest,self._preview.dependency_digest):
                    raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._closed = True
            self._preview = self._issued = None
