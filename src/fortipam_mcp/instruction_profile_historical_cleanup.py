"""Independent, default-closed disposal of an audited historical Profile.

This does not reconstruct a lost creation nonce or restore normal lifecycle
admission. Frozen native evidence, the original successful M4 digest reservation,
the original API namespace, and fresh full state support a new cleanup grant.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import secrets
import stat
from threading import RLock
import time
from typing import Any, Callable, Mapping

from v4_planning import (
    M4AdapterAmbiguous, M4AdapterDenied, M4ClaimState, M4ExecutionAuthorization,
    M4ExecutionKernel, M4ExecutionPlan, canonical_digest,
)
from v4_planning.material_provider import _OpaqueC3Object
from .instruction_profile_contract import InstructionProfileCreatePlan, _require_digest
from .instruction_profile_http_transport import (
    CONTRACT as NATIVE_CONTRACT, FortiPamInstructionProfileHttpTransport, _digest,
)
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

CONTRACT = "fortipam-build29-historical-instruction-profile-cleanup/v1"
_ERROR = "The private historical Instruction Profile cleanup is unavailable."
_FILES = ("creation.plan.json", "create.claim.json", "create-ack.json",
          "created.json", "create-response.json")
_CONSUMED = "historical-cleanup.consumed.json"
_SUCCESS = {"outcome": "succeeded", "verification": "verified",
            "compensation": "not_requested", "idempotent_replay": False}


class InstructionProfileHistoricalCleanupError(ValueError):
    """A fixed error without retained content or identity values."""


class InstructionProfileHistoricalCleanup(_OpaqueC3Object):
    """Trusted composition only; one fresh grant and at most one DELETE.

    The historical ledger proves an exact successful digest reservation, not a
    reconstructed original plan. The new binding compiles the expected body;
    its digest is never substituted into original creation records.
    """

    def __init__(self, binding: InstructionProfileCreatePlan, config: SecretMetadataHttpTransportConfig, *,
            original_directory: Path, original_hashes: Mapping[str, str],
            original_store: PersistentM4ExecutionStateStore, state_directory: Path,
            execution_store: PersistentM4ExecutionStateStore, authority_key: bytes,
            requester_digest: str, transport_digest: str, execution_enabled: bool = False,
            clock: Callable[[], int] = lambda: int(time.time()),
            connection_factory: Callable[..., Any] | None = None) -> None:
        try:
            if (type(binding) is not InstructionProfileCreatePlan
                    or type(config) is not SecretMetadataHttpTransportConfig
                    or type(original_store) is not PersistentM4ExecutionStateStore
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(authority_key) is not bytes or len(authority_key) < 32
                    or type(execution_enabled) is not bool or not callable(clock)
                    or set(original_hashes) != set(_FILES)
                    or original_directory == state_directory
                    or original_store._path == execution_store._path
                    or original_store._key == execution_store._key):
                raise ValueError
            for value in (*original_hashes.values(), requester_digest, transport_digest):
                _require_digest(value)
            self._binding, self._config = binding, config
            self._original_store, self._store = original_store, execution_store
            self._key, self._requester, self._caller_transport = authority_key, requester_digest, transport_digest
            self._enabled, self._clock, self._lock = execution_enabled, clock, RLock()
            self._last_time: int | None = None
            self._started = False
            self._source_marker: dict[str, str] | None = None
            self._hashes = dict(original_hashes)
            self._reader = FortiPamInstructionProfileHttpTransport(config, binding,
                serial_digest=binding._serial, schema_digest=binding._schema,
                state_directory=original_directory, phase="delete", execution_enabled=False,
                clock=self._now, connection_factory=connection_factory)
            self._transport = FortiPamInstructionProfileHttpTransport(config, binding,
                serial_digest=binding._serial, schema_digest=binding._schema,
                state_directory=state_directory, phase="delete", execution_enabled=execution_enabled,
                clock=self._now, connection_factory=connection_factory)
            self._parameters = canonical_digest({"contract": CONTRACT, "files": self._hashes,
                "original_directory": str(original_directory), "binding": binding.digest,
                "cleanup_namespace": self._transport._namespace, "requester": requester_digest,
                "transport": transport_digest})
            self._record = self._custody()
            self._phase: _CleanupPhase | None = None
        except Exception:
            raise InstructionProfileHistoricalCleanupError(_ERROR) from None

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0 or self._last_time is not None and value < self._last_time:
            raise ValueError
        self._last_time = value
        return value

    def _custody(self) -> dict[str, Any]:
        """Verify frozen historical evidence without issuing or renewing a grant."""
        if any(self._reader._exists(name) for name in (
                "delete.claim.json", "delete-response.json", "delete-ack.json", "deleted.json")):
            raise ValueError
        values: dict[str, dict[str, Any]] = {}
        for name in _FILES:
            values[name] = self._reader._read(name, expected_digest=self._hashes[name])
        plan, claim, ack, created, response = (values[name] for name in _FILES)
        directory = self._reader._directory
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode)
                or (info.st_dev, info.st_ino) != self._reader._directory_identity):
            raise ValueError
        namespace = _digest({"contract": NATIVE_CONTRACT, "binding": plan["binding"],
            "directory": str(directory), "directory_identity": (info.st_dev, info.st_ino),
            "serial": self._binding._serial, "schema": self._binding._schema,
            "api_base_url": self._config.base_url,
            "api_identity": hashlib.sha256(self._config.bearer_token.encode()).hexdigest(),
            "api_ca": hashlib.sha256(Path(self._config.ca_file).read_bytes()).hexdigest()
                if self._config.ca_file else None})
        if (plan != {"contract": NATIVE_CONTRACT, "namespace": namespace,
                "binding": plan["binding"], "schema": self._binding._schema, "serial": self._binding._serial}
                or claim["context"] != plan or claim["phase"] != "create"
                or ack["context"] != plan or created["context"] != plan
                or ack["claim_digest"] != _digest(claim) or created["claim_digest"] != _digest(claim)
                or created["ack_digest"] != _digest(ack)
                or response != {"namespace": namespace, "binding": plan["binding"],
                    "http_status": 200, "payload": ack["response"]}):
            raise ValueError
        self._reader._ack(ack["response"], "create")
        record = self._reader._record(created["record"])
        with self._original_store._connect() as connection:
            connection.execute("BEGIN")
            state = self._original_store._read_state(connection)
            rows = connection.execute("SELECT * FROM execution_ledger WHERE event_type = 'claim'").fetchall()
            context = canonical_digest({"authorization_digest": claim["authorization_digest"],
                "plan_digest": claim["plan_digest"], "revision": 1})
            if (len(rows) != 1 or len(state.claims) != 1
                    or rows[0]["authorization_key"] != self._original_store._digest_key(
                        "execution-authorization", claim["authorization_digest"])
                    or rows[0]["context_key"] != self._original_store._digest_key("context", context)
                    or rows[0]["requester_key"] != self._original_store._digest_key("requester", self._requester)):
                raise ValueError
            result = next(iter(state.claims.values())).result
            if result is None or result.as_dict() != _SUCCESS:
                raise ValueError
            connection.commit()
        return record

    def _fresh(self) -> str:
        if self._custody() != self._record or self._transport._snapshot(exists=True) != self._record:
            raise ValueError
        return canonical_digest({"parameters": self._parameters, "record_digest": _digest(self._record)})

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._transport.close()
            self._reader.close()

    def execute_once(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock, self._transport.operation_lock():
                if (not self._enabled or self._started or self._store.claim_count != 0
                        or self._reader._exists(_CONSUMED)
                        or requester_digest != self._requester or transport_digest != self._caller_transport):
                    raise ValueError
                self._started = True
                self._store.verify_ready()
                current = self._fresh()
                with self._reader.operation_lock():
                    marker = {"contract": CONTRACT, "parameters": self._parameters,
                        "cleanup_namespace": self._transport._namespace,
                        "cleanup_store": str(self._store._path)}
                    self._reader._write_once(_CONSUMED, marker)
                    self._source_marker = marker
                phase = _CleanupPhase(self, current, self._now())
                self._phase = phase
                self._transport._write_once("historical-preview.json", {
                    "contract": CONTRACT, "current": current, "parameters": self._parameters,
                    "proposed": "delete_exact_unreferenced_historical_profile",
                    "expected": "owned_absence", "created_at": phase.created,
                    "expires_at": phase.expires, "original_plan_reconstructed": False})
                return M4ExecutionKernel(phase, phase, self._store, clock=self._now).execute(
                    phase.plan, phase.authorization).as_dict()
        except Exception:
            raise InstructionProfileHistoricalCleanupError(_ERROR) from None
        finally:
            self.close()


class _CleanupPhase:
    def __init__(self, owner: InstructionProfileHistoricalCleanup, current: str, created: int) -> None:
        self.owner, self.current, self.created = owner, current, created
        self.expires, self.nonce = created + 60, secrets.token_hex(24)
        self.authorized = self.acknowledged = False
        self.plan, self.authorization = self._derive()

    def _derive(self) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        owner = self.owner
        context = {"contract": CONTRACT, "parameters": owner._parameters,
            "current": self.current, "created": self.created, "expires": self.expires, "nonce": self.nonce}
        def mac(purpose: str, value: object) -> str:
            return hmac.new(owner._key, CONTRACT.encode() + b"\0" + purpose.encode() + b"\0" +
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        values: dict[str, Any] = dict(plan_ref="historical-profile-plan-" + mac("plan", context), revision=1,
            action_id="instruction-profile-historical-cleanup", action_version="1.0.0",
            adapter_ref="fortipam-build29-historical-profile-cleanup-v1",
            target_ref="historical-profile-" + owner._parameters[:40], requester_digest=owner._requester,
            summary_digest=mac("summary", context), confirmation_digest=mac("standing-intent", context),
            approval_digest=mac("lab-policy", context), parameters_digest=canonical_digest(context),
            expected_current_digest=self.current,
            expected_state_digest=canonical_digest({"parameters": owner._parameters, "absent": True}),
            idempotency_digest=mac("idempotency", context), expires_at=self.expires, compensation_ref=None)
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        signed = {**context, "plan": plan.plan_digest}
        auth: dict[str, Any] = dict(authorization_ref="historical-profile-auth-" + mac("authorization", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="historical-profile-intent-" + mac("intent", signed),
            confirmation_digest=plan.confirmation_digest, approval_ref="historical-profile-policy-" + mac("policy", signed),
            approval_digest=plan.approval_digest, approver_digest=mac("authority", owner._parameters),
            issued_at=self.created, expires_at=self.expires, one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth))

    def _check(self, plan: M4ExecutionPlan) -> None:
        if (self.owner._phase is not self or not self.owner._enabled or not self.owner._transport._enabled
                or plan is not self.plan or (self.plan, self.authorization) != self._derive()
                or not self.created <= self.owner._now() < self.expires
                or self.owner._source_marker is None
                or self.owner._reader._read(_CONSUMED) != self.owner._source_marker
                or self.owner._custody() != self.owner._record):
            raise ValueError
        if self.authorized:
            claim = self.owner._store.inspect_claim(plan_ref=plan.plan_ref,
                requester_digest=plan.requester_digest, idempotency_digest=plan.idempotency_digest,
                authorization_digest=self.authorization.authorization_digest,
                context_digest=canonical_digest({"authorization_digest": self.authorization.authorization_digest,
                    "plan_digest": plan.plan_digest, "revision": plan.revision}))
            if claim.state is not M4ClaimState.IN_PROGRESS or claim.result is not None:
                raise ValueError

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        self._check(plan)
        if (self.authorized or authorization is not self.authorization or type(now_epoch) is not int
                or not self.created <= now_epoch <= self.owner._now() < self.expires):
            raise ValueError
        self.authorized = True

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self._check(plan)
            if not self.authorized:
                raise ValueError
            return self.owner._fresh()
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        try:
            self._check(plan)
            if not self.authorized or self.owner._fresh() != plan.expected_current_digest:
                raise ValueError
            transport = self.owner._transport
            marker = {"contract": CONTRACT, "parameters": self.owner._parameters,
                "plan_digest": plan.plan_digest, "authorization_digest": self.authorization.authorization_digest,
                "expires_at": self.expires}
            transport._write_once("historical-delete.attempt.json", marker)
            def guard() -> None:
                self._check(plan)
                if (transport._read("historical-delete.attempt.json") != marker
                        or self.owner._fresh() != plan.expected_current_digest):
                    raise ValueError
                self._check(plan)
            payload = transport._request("DELETE", transport._delete_path(), guard=guard,
                deadline=self.expires, capture_name="delete-response.json")
            transport._ack(payload, "delete")
            self._check(plan)
            transport._write_once("historical-delete-ack.json", {"attempt": _digest(marker), "response": payload})
            self.acknowledged = True
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self._check(plan)
            if not self.acknowledged or self.owner._transport._snapshot(exists=False) is not None:
                raise ValueError
            transport = self.owner._transport
            marker = transport._read("historical-delete.attempt.json")
            ack = transport._read("historical-delete-ack.json")
            native = transport._read("delete-response.json")
            if (marker["plan_digest"] != plan.plan_digest
                    or marker["authorization_digest"] != self.authorization.authorization_digest
                    or ack != {"attempt": _digest(marker), "response": native["payload"]}
                    or native["namespace"] != transport._namespace
                    or native["binding"] != self.owner._binding.digest or native["http_status"] != 200):
                raise ValueError
            transport._ack(native["payload"], "delete")
            self._check(plan)
            self.owner._transport._write_once("historical-deleted.json", {
                "parameters": self.owner._parameters, "absent": True,
                "plan_digest": plan.plan_digest, "authorization_digest": self.authorization.authorization_digest})
            return plan.expected_state_digest
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None
