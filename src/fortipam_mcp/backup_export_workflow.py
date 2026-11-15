"""Default-closed fixed native encrypted backup phases using the existing durable M4 kernel."""
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

from v4_planning import (M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationDenied,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest)
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .backup_export_transport import CONTRACT, BackupExportTransport
from .m4_execution_store import PersistentM4ExecutionStateStore

_ERROR = "The fixed encrypted backup workflow is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class _Preview(_OpaqueC3Object):
    phase: str
    nonce: str
    current_digest: str
    expected_digest: str
    created_at: int
    expires_at: int
    preview_ref: str


class _BackupExportAdapter(_OpaqueC3Object):
    def __init__(self, workflow: BackupExportWorkflow, phase: str,
                 plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> None:
        self._workflow, self._phase, self._plan, self._authorization = workflow, phase, plan, authorization
        self._acknowledged = False

    def _check(self, plan: M4ExecutionPlan) -> None:
        if plan is not self._plan:
            raise M4AdapterDenied(_ERROR)
        self._workflow.verify(plan, self._authorization, now_epoch=self._workflow._now())

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            current, expected = self._workflow._transport.inspect(self._phase)
            if expected != plan.expected_state_digest:
                raise ValueError
            return current
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._check(plan)
        _require_m4_dispatch_ownership(plan, self._authorization, self._workflow._store)
        try:
            self._workflow._transport.dispatch(self._phase, current_digest=plan.expected_current_digest,
                plan=plan, authorization=self._authorization, store=self._workflow._store,
                guard=lambda: self._check(plan))
            self._acknowledged = True
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            if not self._acknowledged:
                raise ValueError
            return self._workflow._transport.postcondition(self._phase)
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None


class BackupExportWorkflow(_OpaqueC3Object):
    """One authenticated lab export; retained artifacts are not automatic cleanup.

    Standing lab policy grants one export, never restore or device configuration.
    """

    def __init__(self, transport: BackupExportTransport, store: PersistentM4ExecutionStateStore, *,
                 authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
                 allowed_requester_digest: str, allowed_transport_digest: str,
                 create_enabled: bool = False,
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(transport) is not BackupExportTransport or type(store) is not PersistentM4ExecutionStateStore
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or hmac.compare_digest(authority_key, store._key)
                    or type(create_enabled) is not bool or not callable(clock)):
                raise ValueError
            for value in (allowed_requester_digest, allowed_transport_digest):
                require_digest(value, "operator_binding")
            for value in (environment_ref, scope_ref, audience_ref):
                require_ref(value, "namespace_ref")
            self._transport, self._store, self._key, self._clock = transport, store, authority_key, clock
            self._namespace = dict(environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref,
                requester_digest=allowed_requester_digest, transport_digest=allowed_transport_digest)
            self._enabled = {"create": create_enabled}
            self._previews: dict[str, _Preview] = {}
            self._issued: dict[str, tuple[M4ExecutionPlan, M4ExecutionAuthorization]] = {}
            self._adapters: dict[str, _BackupExportAdapter] = {}
            self._last_now, self._closed, self._lock = -1, False, RLock()
        except Exception:
            raise ValueError(_ERROR) from None

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or now < 0 or now < self._last_now or self._closed:
            self.close()
            raise ValueError(_ERROR)
        self._last_now = now
        return now

    def _identity(self, requester_digest: str, transport_digest: str) -> None:
        if (self._closed or requester_digest != self._namespace["requester_digest"]
                or transport_digest != self._namespace["transport_digest"]):
            raise ValueError(_ERROR)

    def _unconsumed(self, phase: str) -> None:
        if phase not in self._enabled or self._store.claim_count != 0:
            raise ValueError(_ERROR)

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key, b"fortipam-native-backup-export-lab-v1\0" + purpose.encode() + b"\0"
            + json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(),
            hashlib.sha256).hexdigest()

    def _context(self, preview: _Preview) -> dict[str, object]:
        return {**self._namespace, "contract": CONTRACT, "binding": self._transport.parameters_digest,
            "policy_mode": "lab_auto", "phase": preview.phase, "nonce": preview.nonce,
            "current": preview.current_digest, "expected": preview.expected_digest,
            "created_at": preview.created_at, "expires_at": preview.expires_at}

    def _derive(self, preview: _Preview) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        context = self._context(preview)
        phase, parameters = preview.phase, self._transport.parameters_digest
        intent, approval = self._mac("intent", context), self._mac("approval", context)
        fields: dict[str, Any] = dict(plan_ref="backup-export-native-" + phase + "-" + parameters,
            revision=1, action_id="backup-export-native-" + phase, action_version="1.0.0", adapter_ref=CONTRACT,
            target_ref="fixed-encrypted-global-backup", requester_digest=self._namespace["requester_digest"],
            summary_digest=self._mac("summary", context), confirmation_digest=intent, approval_digest=approval,
            parameters_digest=parameters, expected_current_digest=preview.current_digest,
            expected_state_digest=preview.expected_digest,
            idempotency_digest=canonical_digest({"binding": parameters, "phase": phase}),
            expires_at=preview.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        fields = dict(authorization_ref="backup_export-auth-" + self._mac("authorization", dict(context, plan=plan.plan_digest)),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="backup_export-intent-" + intent, confirmation_digest=intent,
            approval_ref="backup_export-approval-" + approval, approval_digest=approval,
            approver_digest=self._mac("lab-owner", self._namespace), issued_at=preview.created_at,
            expires_at=preview.expires_at, one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**fields, authorization_digest=canonical_digest(fields))

    def preview(self, phase: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._unconsumed(phase)
                self._previews.pop(phase, None)
                self._issued.pop(phase, None)
                created = self._now()
                current, expected = self._transport.inspect(phase)
                nonce = secrets.token_hex(24)
                preview = _Preview(phase, nonce, current, expected, created, created + 60,
                    "backup_export-preview-" + self._mac("preview", {"phase": phase, "nonce": nonce,
                        "current": current, "expected": expected, "created_at": created}))
                if self._now() >= preview.expires_at:
                    raise ValueError
                self._unconsumed(phase)
                self._previews[phase] = preview
                return {"contract": CONTRACT, "phase": phase, "policy_mode": "lab_auto",
                    "preview_ref": preview.preview_ref, "expires_at": preview.expires_at,
                    "Current State": {"bound_global_owner_verified": True, "private_destination_empty": True},
                    "Proposed Changes": {"create_configuration_backup": True, "native_encryption_requested": True,
                        "scope": "global", "configuration_write": False},
                    "Expected State": {"artifact_and_password_retained_privately": True,
                        "saved_bytes_integrity_verified": True, "minimum_retention_days": 2, "restore_tested": False},
                    "device_write_executed": False}
        except Exception:
            raise ValueError(_ERROR) from None

    def authorize(self, phase: str, preview_ref: str, *, requester_digest: str,
                  transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                preview = self._previews[phase]
                if (not self._enabled[phase] or preview_ref != preview.preview_ref
                        or phase in self._issued or not preview.created_at <= self._now() < preview.expires_at):
                    raise ValueError
                self._unconsumed(phase)
                try:
                    observed = self._transport.inspect(phase)
                except Exception:
                    self._previews.pop(phase, None)
                    raise
                if observed != (preview.current_digest, preview.expected_digest):
                    self._previews.pop(phase, None)
                    raise ValueError
                self._unconsumed(phase)
                issued = self._derive(preview)
                self._issued[phase] = issued
                return {"contract": CONTRACT, "phase": phase, "policy_mode": "lab_auto",
                    "authorization_ref": issued[1].authorization_ref, "execution_authorized": True,
                    "expires_at": preview.expires_at, "device_write_executed": False}
        except Exception:
            raise ValueError(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                phase = plan.action_id.removeprefix("backup-export-native-")
                preview, issued, now = self._previews[phase], self._issued[phase], self._now()
                if (not self._enabled[phase] or type(now_epoch) is not int
                        or not preview.created_at <= now_epoch <= now < preview.expires_at
                        or plan is not issued[0] or authorization is not issued[1]
                        or self._derive(preview) != issued):
                    raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def execute(self, phase: str, authorization_ref: str, *, requester_digest: str,
                transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                plan, authorization = self._issued[phase]
                if authorization.authorization_ref != authorization_ref:
                    raise ValueError
                self.verify(plan, authorization, now_epoch=self._now())
                if phase not in self._adapters:
                    self._unconsumed(phase)
                    self._adapters[phase] = _BackupExportAdapter(self, phase, plan, authorization)
                result = M4ExecutionKernel(self._adapters[phase], self, self._store,
                    clock=self._now).execute(plan, authorization)
                return {"contract": CONTRACT, "phase": phase, **result.as_dict(),
                    "native_encryption_requested": self._transport._export_requested,
                    "restore_tested": False, "configuration_write_executed": False}
        except Exception:
            raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._enabled = {"create": False}
