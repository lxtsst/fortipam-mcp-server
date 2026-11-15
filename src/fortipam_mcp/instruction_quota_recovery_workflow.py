"""Default-closed owner-incident policy and durable M4 correction candidate.

An external trusted owner-policy provisioner is required. This module reads one
canonical protected policy record; it cannot create/admit it, infer authority
from target selection, or transplant old lab-auto approval. No startup or Tool
registration and no live incident authority are supplied here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import logging
import os
import secrets
from typing import Any, Callable

from v4_planning import (
    M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationDenied, M4Claim, M4ClaimState,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .instruction_quota_http_transport import _members
from .instruction_quota_recovery_contract import (
    ACTION, ADAPTER, REQUIRED_POLICY, VERSION, prepare_instruction_quota_baseline_recovery,
)
from .instruction_quota_recovery_transport import (
    FortiPamInstructionQuotaRecoveryTransport, InstructionQuotaRecoveryTransportError, _STAGES,
)
from .ldap_server_runtime import _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "fortipam-700-build29-instruction-quota-incident-m4-v1"
POLICY_CONTRACT = "fortipam-700-build29-instruction-quota-owner-incident-policy-v1"
_PREFIX = "instruction-quota-incident-baseline-correction"
_POLICY_DOMAIN = b"fortipam-instruction-quota-owner-incident-policy/v1\0"
_AUTH_DOMAIN = b"fortipam-instruction-quota-incident-execution/v1\0"
_ERROR = "The private Instruction quota incident workflow is unavailable."
_LOGGER = logging.getLogger(__name__)


class InstructionQuotaRecoveryWorkflowError(RuntimeError):
    """Value-free failure without private records, identities or partial plans."""


@dataclass(frozen=True, slots=True, repr=False)
class _Issued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class InstructionQuotaRecoveryWorkflow(_OpaqueC3Object):
    """One canonically bound M4 correction, gated by explicit signed incident policy."""

    def __init__(self, writer: FortiPamInstructionQuotaRecoveryTransport, *,
            execution_store: PersistentM4ExecutionStateStore, policy_key: bytes,
            authority_key: bytes, original_key_digests: frozenset[str],
            environment_ref: str, scope_ref: str, audience_ref: str,
            execution_enabled: bool = False, bootstrap_guard: Callable[[], None] | None = None) -> None:
        try:
            if (type(writer) is not FortiPamInstructionQuotaRecoveryTransport
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or execution_store._read_only or type(execution_enabled) is not bool
                    or bootstrap_guard is not None and not callable(bootstrap_guard)
                    or type(original_key_digests) is not frozenset or len(original_key_digests) != 5
                    or any(type(key) is not bytes or not 32 <= len(key) <= 4096 for key in (policy_key, authority_key))):
                raise ValueError
            for value in original_key_digests:
                require_digest(value, "original_key_digest")
            for value in (environment_ref, scope_ref, audience_ref):
                require_ref(value, "namespace_ref")
            original = writer._candidate._reconciler._workflow
            if any(original._authority._namespace[name] != value for name, value in (
                    ("environment_ref", environment_ref), ("scope_ref", scope_ref), ("audience_ref", audience_ref))):
                raise ValueError
            held = (original._transport._key, original._authority._key,
                original._execution_store._key, original._original_store._key if original._original_store else b"")
            fresh_keys = (writer._key, execution_store._key, policy_key, authority_key)
            if (not {hashlib.sha256(key).hexdigest() for key in held} <= original_key_digests
                    or len(set(fresh_keys)) != 4
                    or any(hashlib.sha256(key).hexdigest() in original_key_digests for key in fresh_keys)):
                raise ValueError
            root = writer._original._directory
            if (execution_store._path != root / (_PREFIX + ".m4.sqlite")
                    or execution_store._key_path != root / (_PREFIX + ".m4.key")):
                raise ValueError
            self._writer, self._store = writer, execution_store
            self._policy_key, self._authority_key = policy_key, authority_key
            self._key_cohort = original_key_digests
            self._namespace = {"environment_ref": environment_ref, "scope_ref": scope_ref,
                "audience_ref": audience_ref, "requester_digest": writer._candidate._requester,
                "transport_digest": writer._candidate._transport}
            self._enabled, self._started, self._authorized = execution_enabled, False, False
            self._bootstrap_guard = bootstrap_guard
            self._lock = original._lock
            self._ledger_pin = self._ledger_binding()
            self._preview: dict[str, Any] | None = None
            self._issued: _Issued | None = None
            self._issue_context: dict[str, Any] | None = None
            self._policy_pin: str | None = None
            self._attempt_pin: tuple[int, int] | None = None
            self._verifier = _Verifier(self)
            with writer.operation_lock():
                self._local()
        except Exception:
            raise InstructionQuotaRecoveryWorkflowError(_ERROR) from None

    def _ledger_binding(self) -> str:
        raw = _read(self._store._key_path, 4096)
        try:
            if not hmac.compare_digest(raw, self._store._key):
                raise ValueError
            values: dict[str, object] = {"key_digest": hashlib.sha256(raw).hexdigest()}
            for name, path in (("database", self._store._path), ("key", self._store._key_path)):
                info = path.lstat()
                values[name] = {"path_digest": hashlib.sha256(str(path).encode()).hexdigest(),
                    "device": str(info.st_dev), "inode": str(info.st_ino)}
            self._store.verify_ready()
            return canonical_digest(values)
        finally:
            _zeroize_mutable(raw)

    def _local(self) -> int:
        now = self._writer._check()
        if (self._ledger_binding() != self._ledger_pin
                or self._store._read_only or self._writer._candidate._requester != self._namespace["requester_digest"]
                or self._writer._candidate._transport != self._namespace["transport_digest"]):
            raise ValueError
        if self._bootstrap_guard is not None:
            self._bootstrap_guard()
        return self._writer._check()

    def _identity(self, requester: str, transport: str) -> None:
        self._writer._candidate._reconciler._workflow._identity(requester, transport)
        if (requester, transport) != (self._namespace["requester_digest"], self._namespace["transport_digest"]):
            raise ValueError

    def _unconsumed(self) -> None:
        self._local()
        self._writer._unconsumed()
        if self._store.claim_count:
            raise ValueError
        if self._writer._original._exists(_PREFIX + ".m4.attempt.json"):
            raise ValueError

    def _policy(self, *, require_active: bool = True) -> tuple[dict[str, Any], str]:
        now = self._local()
        path = self._writer._original._directory / (_PREFIX + ".policy.json")
        raw = _read(path, 16384)
        try:
            value = json.loads(raw, object_pairs_hook=_members)
            if type(value) is not dict or set(value) != {"payload", "seal"}:
                raise ValueError
            p = value["payload"]
            if type(p) is not dict or type(value["seal"]) is not str:
                raise ValueError
            expected = self._policy_content()
            if set(p) != set(expected) | {"owner_decision_digest", "issued_at", "expires_at"}:
                raise ValueError
            if any(type(p[k]) is not type(v) or p[k] != v for k, v in expected.items()):
                raise ValueError
            require_digest(p["owner_decision_digest"], "owner_decision_digest")
            if (type(p["issued_at"]) is not int or type(p["expires_at"]) is not int
                    or not 0 <= p["issued_at"] <= now
                    or not p["issued_at"] < p["expires_at"] <= p["issued_at"] + 3600
                    or require_active and now >= p["expires_at"]):
                raise ValueError
            seal = hmac.new(self._policy_key, _POLICY_DOMAIN + canonical_digest(p).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(value["seal"], seal):
                raise ValueError
            self._local()
            return p, canonical_digest(value)
        finally:
            _zeroize_mutable(raw)

    def _policy_content(self) -> dict[str, Any]:
        """The exact external provisioner's schema, without an admission/sign method."""
        candidate, draft = self._writer._candidate, self._writer._candidate._draft
        return {"contract": POLICY_CONTRACT, "policy": REQUIRED_POLICY, "policy_mode": "pre_approved_policy",
            **self._namespace, "original_namespace": self._writer._original._namespace,
            "original_plan": draft._original, "original_witness": draft._witness,
            "current": draft._current, "expected": draft._expected,
            "native_namespace": self._writer._namespace, "ledger_binding": self._ledger_pin,
            "original_key_cohort": canonical_digest(sorted(self._key_cohort)),
            "authority_key_digest": hashlib.sha256(self._authority_key).hexdigest(),
            "accepts_unresolved_original": True, "accepts_late_original_effect": True,
            "preserves_original_unknown": True, "forward_resource_work_allowed": False,
            "automatic_retry_allowed": False, "automatic_compensation_allowed": False,
            "max_dispatches": 1}

    def _mac(self, purpose: str, content: object) -> str:
        return hmac.new(self._authority_key, _AUTH_DOMAIN + purpose.encode() + b"\0"
            + canonical_digest({"namespace": self._namespace, "value": content}).encode(), hashlib.sha256).hexdigest()

    def _check_preview(self) -> None:
        p, c = self._preview, self._writer._candidate
        if (p is None or set(p) != {"candidate", "expires_at", "nonce", "created_at", "reference"}
                or p["candidate"] != c.digest or type(p["nonce"]) is not str or len(p["nonce"]) != 48
                or any(char not in "0123456789abcdef" for char in p["nonce"])
                or type(p["created_at"]) is not int or type(p["expires_at"]) is not int
                or p["expires_at"] != c._draft._expires
                or not c._draft._observed <= p["created_at"] <= self._local() < p["expires_at"]
                or p["reference"] != "instruction-quota-incident-preview-" + self._mac("preview",
                    {k: v for k, v in p.items() if k != "reference"})):
            raise ValueError

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                with self._writer.operation_lock():
                    self._unconsumed()
                candidate = prepare_instruction_quota_baseline_recovery(self._writer._candidate._reconciler,
                    requester_digest=requester_digest, transport_digest=transport_digest)
                self._writer = FortiPamInstructionQuotaRecoveryTransport(candidate,
                    state_key=self._writer._key, execution_enabled=self._writer._enabled)
                return self._preview_prepared()
        except Exception:
            raise InstructionQuotaRecoveryWorkflowError(_ERROR) from None

    def _preview_prepared(self) -> dict[str, object]:
        """Reuse the already authenticated fresh candidate; never extend its expiry."""
        with self._lock:
            with self._writer.operation_lock():
                candidate = self._writer._candidate
                self._unconsumed()
                now = self._local()
                if not candidate._draft._observed <= now < candidate._draft._expires:
                    raise ValueError
                self._issued = self._issue_context = self._policy_pin = None
                self._authorized = False
                self._preview = {"candidate": candidate.digest, "expires_at": candidate._draft._expires,
                    "nonce": secrets.token_hex(24), "created_at": now}
                reference = "instruction-quota-incident-preview-" + self._mac("preview", self._preview)
                self._preview["reference"] = reference
                self._check_preview()
                return {"contract": CONTRACT, "preview_ref": reference, "expires_at": candidate._draft._expires,
                    "policy_mode": "pre_approved_policy", "required_policy": REQUIRED_POLICY,
                    "policy_status": "requires_protected_record", "execution_admissible": False,
                    "Current State": {"instruction_quota_percent": 1, "original_restore": "unknown",
                        "complete_setting_and_zero_resource_usage_verified": True},
                    "Proposed Changes": {"instruction_delta_percent": -1, "file_storage_delta_percent": 1,
                        "other_setting_fields_preserved": True, "operation": ACTION},
                    "Expected State": {"instruction_quota_percent": 0, "complete_original_baseline": True},
                    "original_terminal_proof_preserved_as_unknown": True, "incident_closed": False,
                    "forward_resource_work_authorized": False, "device_write_executed": False}

    def _derive(self) -> _Issued:
        context = self._issue_context
        if context is None:
            raise ValueError
        c = self._writer._candidate
        confirmation, approval = self._mac("intent", context), self._mac("policy", context)
        values: dict[str, Any] = {"plan_ref": "instruction-quota-incident-plan-" + self._mac("plan", context),
            "revision": 1, "action_id": ACTION, "action_version": VERSION, "adapter_ref": ADAPTER,
            "target_ref": "instruction-quota-" + self._writer._original._baseline._serial,
            "requester_digest": c._requester, "summary_digest": self._mac("summary", context),
            "confirmation_digest": confirmation, "approval_digest": approval, "parameters_digest": c.digest,
            "expected_current_digest": c._draft._current, "expected_state_digest": c._draft._expected,
            "idempotency_digest": self._mac("idempotency", context), "expires_at": context["expires_at"],
            "compensation_ref": None}
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        signed = {"plan_digest": plan.plan_digest, "context": canonical_digest(context)}
        auth: dict[str, Any] = {"authorization_ref": "instruction-quota-incident-auth-" + self._mac("auth", signed),
            "plan_ref": plan.plan_ref, "plan_digest": plan.plan_digest, "requester_digest": plan.requester_digest,
            "confirmation_ref": "instruction-quota-incident-intent-" + self._mac("intent-ref", signed),
            "confirmation_digest": confirmation, "approval_ref": "instruction-quota-incident-policy-" + self._mac("policy-ref", signed),
            "approval_digest": approval, "approver_digest": self._mac("policy-authority", self._policy_pin),
            "issued_at": context["issued_at"], "expires_at": plan.expires_at, "one_time": True,
            "execution_authorized": True}
        return _Issued(plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)))

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock, self._writer.operation_lock():
                self._identity(requester_digest, transport_digest)
                self._unconsumed()
                if (self._enabled is not True or self._writer._enabled is not True or self._preview is None
                        or preview_ref != self._preview["reference"]):
                    raise ValueError
                self._check_preview()
                self._policy_pin = None
                policy, pin = self._policy()
                self._writer.inspect_precondition()
                now = self._local()
                expires = min(policy["expires_at"], self._preview["expires_at"])
                if not self._preview["created_at"] <= now < expires:
                    raise ValueError
                self._policy_pin = pin
                self._issue_context = {"contract": CONTRACT, "namespace": self._namespace,
                    "preview": self._preview, "policy": pin, "owner_decision": policy["owner_decision_digest"],
                    "ledger": self._ledger_pin, "native": self._writer._namespace,
                    "issued_at": now, "expires_at": expires}
                self._issued = self._derive()
                self._check_issued(self._issued.plan, self._issued.authorization, require_fresh=True)
                return {"contract": CONTRACT, "authorization_ref": self._issued.authorization.authorization_ref,
                    "expires_at": expires, "policy_mode": "pre_approved_policy",
                    "owner_incident_policy_bound": True, "independent_human_approver": False}
        except Exception:
            raise InstructionQuotaRecoveryWorkflowError(_ERROR) from None

    def _check_issued(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, require_fresh: bool) -> None:
        if (self._enabled is not True or self._writer._enabled is not True or self._issued is None
                or plan is not self._issued.plan or authorization is not self._issued.authorization
                or self._issued != self._derive()
                or self._policy(require_active=require_fresh)[1] != self._policy_pin):
            raise ValueError
        self._writer._authorization(plan, authorization, require_fresh=require_fresh)
        if self._started:
            self._check_attempt()

    def _attempt_value(self) -> dict[str, Any]:
        if self._issued is None or self._policy_pin is None:
            raise ValueError
        payload = {"contract": CONTRACT, "ledger": self._ledger_pin, "policy": self._policy_pin,
            "native": self._writer._namespace, "candidate": self._writer._candidate.digest,
            "plan": self._issued.plan.plan_digest, "authorization": self._issued.authorization.authorization_digest}
        return {"payload": payload, "seal": self._mac("m4-attempt", payload)}

    def _write_attempt(self) -> None:
        value = self._attempt_value()
        raw = bytearray(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
        directory = self._writer._original._directory_fd()
        try:
            fd = os.open(_PREFIX + ".m4.attempt.json", os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                0o600, dir_fd=directory)
            with os.fdopen(fd, "wb") as output:
                info = os.fstat(output.fileno())
                self._attempt_pin = (info.st_dev, info.st_ino)
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(directory)
        finally:
            _zeroize_mutable(raw)
            os.close(directory)
        self._check_attempt()

    def _check_attempt(self) -> None:
        path = self._writer._original._directory / (_PREFIX + ".m4.attempt.json")
        raw = _read(path, 16384)
        try:
            info = path.lstat()
            if ((info.st_dev, info.st_ino) != self._attempt_pin
                    or json.loads(raw, object_pairs_hook=_members) != self._attempt_value()):
                raise ValueError
            self._local()
        finally:
            _zeroize_mutable(raw)

    def _claim(self, issued: _Issued) -> M4Claim:
        plan, auth = issued.plan, issued.authorization
        return self._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest, authorization_digest=auth.authorization_digest,
            context_digest=canonical_digest({"authorization_digest": auth.authorization_digest,
                "plan_digest": plan.plan_digest, "revision": plan.revision}))

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock, self._writer.operation_lock():
                self._identity(requester_digest, transport_digest)
                issued = self._issued
                if issued is None or authorization_ref != issued.authorization.authorization_ref:
                    raise ValueError
                self._check_issued(issued.plan, issued.authorization, require_fresh=True)
                if not self._started:
                    self._unconsumed()
                    self._write_attempt()
                else:
                    # An attempt without a durable claim cannot enter the kernel again.
                    self._claim(issued)
                self._started = True
                result = M4ExecutionKernel(_Adapter(self), self._verifier, self._store,
                    clock=self._writer._candidate._reconciler._workflow._now).execute(issued.plan, issued.authorization)
                return {"contract": CONTRACT, **result.as_dict(), "original_restore_unknown_preserved": True,
                    "original_request_terminal_proven": False, "incident_closed": False,
                    "forward_resource_work_authorized": False}
        except Exception:
            raise InstructionQuotaRecoveryWorkflowError(_ERROR) from None


class _Verifier:
    def __init__(self, workflow: InstructionQuotaRecoveryWorkflow) -> None:
        self._workflow = workflow

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            w = self._workflow
            w._check_issued(plan, authorization, require_fresh=True)
            if (w._authorized or w._issued is None or type(now_epoch) is not int
                    or not authorization.issued_at <= now_epoch <= w._local() < authorization.expires_at
                    or w._claim(w._issued).state is not M4ClaimState.IN_PROGRESS):
                raise ValueError
            w._authorized = True
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None


class _Adapter:
    def __init__(self, workflow: InstructionQuotaRecoveryWorkflow) -> None:
        self._workflow = workflow

    def _log_failure(self, operation: str, error: Exception) -> None:
        stage = error.stage if type(error) is InstructionQuotaRecoveryTransportError else None
        stage = stage if type(stage) is str and stage in _STAGES else "unavailable"
        operation = operation if operation in {"current_read", "dispatch", "postcondition_read"} else "unavailable"
        # Fixed categories only; never exception text, references or traceback.
        try:
            _LOGGER.warning("Instruction quota incident adapter failure: operation=%s stage=%s", operation, stage)
        except Exception:
            # Diagnostic failure must not interrupt durable UNKNOWN finalization.
            pass

    def _check(self, plan: M4ExecutionPlan, *, require_fresh: bool = True) -> _Issued:
        w, issued = self._workflow, self._workflow._issued
        if issued is None or not w._authorized or w._claim(issued).state is not M4ClaimState.IN_PROGRESS:
            raise ValueError
        w._check_issued(plan, issued.authorization, require_fresh=require_fresh)
        return issued

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self._check(plan)
        except Exception:
            raise M4AdapterDenied(_ERROR) from None
        try:
            return self._workflow._writer.inspect_precondition()
        except Exception as error:
            self._log_failure("current_read", error)
            raise M4AdapterAmbiguous(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        try:
            issued = self._check(plan)
            def before_send() -> None:
                self._check(plan)
            self._workflow._writer.dispatch(plan, issued.authorization, before_send=before_send)
        except Exception as error:
            self._log_failure("dispatch", error)
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            issued = self._check(plan, require_fresh=False)
            started = self._workflow._local()
            actual = self._workflow._writer.inspect_postcondition(plan, issued.authorization)
            self._check(plan, require_fresh=False)
            if not started <= self._workflow._writer._check() < started + 30:
                raise ValueError
            return actual
        except Exception as error:
            self._log_failure("postcondition_read", error)
            raise M4AdapterAmbiguous(_ERROR) from None
