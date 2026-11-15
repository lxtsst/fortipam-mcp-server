"""Private original-M4 custody for one prospective inactive Policy creation.

No HTTP client, authorization issuer, callable Tool or recovery dispatch exists
here. Signed write-once records never retain native bodies, selectors or login
material. Original UNKNOWN results remain untouched even when an ACK exists.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
from threading import RLock
import time
from typing import cast

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import M4Claim, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as m
from .ldap_server_runtime import _key, _private_directory, _read
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .windows_execution_policy_contract import (
    WindowsExecutionPolicyRequest, consume_windows_policy_response, consume_windows_policy_state,
)

ACTION_ID = "inactive-windows-policy-create"
ADAPTER_REF = "fortipam-build29-inactive-windows-policy-create-m4-v1"
_DOMAIN = b"inactive-windows-policy-original-custody/v1\x00"
_SEND, _ACK, _STATE = "send.claim.json", "create-ack.json", "created-state.json"
_ERROR = "The private original inactive Policy custody is unavailable."


class WindowsExecutionPolicyCustodyError(RuntimeError):
    """Non-disclosing refusal without retry or deletion authority."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsPolicyOriginalObservation(_OpaqueC3Object):
    context_digest: str
    custody_digest: str
    original_outcome: str
    original_verification: str
    created_state_digest: str | None
    source_context_digest: str


class WindowsExecutionPolicyCustody(_OpaqueC3Object):
    """Bind the actual original absence, ACK and full state to one active M4."""

    def __init__(self, directory: Path, witness_key_file: Path,
            request: WindowsExecutionPolicyRequest, preflight_digest: str,
            plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore, *, source_context_digest: str,
            clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(request) is not WindowsExecutionPolicyRequest or type(plan) is not M4ExecutionPlan
                    or type(authorization) is not M4ExecutionAuthorization
                    or type(store) is not PersistentM4ExecutionStateStore
                    or store.monotonic_checkpoint_protocol_bound is not True
                    or clock is not None and not callable(clock)):
                raise ValueError
            request.validate()
            require_digest(preflight_digest, "policy_preflight")
            require_digest(source_context_digest, "policy_source_context")
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            _private_directory(self._directory)
            info = self._directory.stat()
            self._identity = (info.st_dev, info.st_ino)
            if self._key_file in (store._path, store._key_path, *(self._directory / name for name in (_SEND, _ACK, _STATE))):
                raise ValueError
            self._key = _key(self._key_file)
            if hmac.compare_digest(self._key, store._key):
                raise ValueError
            self._request, self._preflight = request, preflight_digest
            self._source_context = source_context_digest
            self._plan, self._authorization, self._store = plan, authorization, store
            self._context = canonical_digest({"request":request.request_digest, "preflight":preflight_digest,
                "source_context":source_context_digest,
                "plan":plan.plan_digest, "authorization":authorization.authorization_digest,
                "store_key":hashlib.sha256(store._key).hexdigest()})
            self._clock = clock or (lambda: int(time.time()))
            self._last_now = -1
            self._send_started = self._ack_consumed = self._state_consumed = self._closed = False
            self._lock = RLock()
            self._validate()
        except Exception:
            raise WindowsExecutionPolicyCustodyError(_ERROR) from None

    def _validate(self) -> None:
        self._request.validate()
        p, a = self._plan, self._authorization
        p.__post_init__()
        a.__post_init__()
        if (p.action_id != ACTION_ID or p.action_version != "1.0.0" or p.adapter_ref != ADAPTER_REF
                or p.target_ref != "bound-inactive-windows-policy" or p.compensation_ref is not None
                or p.parameters_digest != self._request.request_digest
                or p.expected_current_digest != self._preflight
                or p.expected_state_digest != self._request.expected_state_digest
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest
                or a.requester_digest != p.requester_digest or a.confirmation_digest != p.confirmation_digest
                or a.approval_digest != p.approval_digest or a.expires_at > p.expires_at
                or self._context != canonical_digest({"request":self._request.request_digest,
                    "preflight":self._preflight, "plan":p.plan_digest, "authorization":a.authorization_digest,
                    "source_context":self._source_context,
                    "store_key":hashlib.sha256(self._store._key).hexdigest()})):
            raise ValueError
        _private_directory(self._directory)
        info = self._directory.stat()
        if ((info.st_dev, info.st_ino) != self._identity
                or not hmac.compare_digest(_key(self._key_file), self._key)):
            raise ValueError

    def _original_claim(self) -> M4Claim:
        self._validate()
        p, a = self._plan, self._authorization
        return self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest({"plan_digest":p.plan_digest,
                "authorization_digest":a.authorization_digest, "revision":p.revision}))

    def _writing_now(self) -> int:
        if self._closed:
            raise ValueError
        self._validate()
        _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        if self._original_claim().result is not None:
            raise ValueError
        now = self._clock()
        if (type(now) is not int or now < self._last_now
                or not self._authorization.issued_at <= now < self._authorization.expires_at):
            raise ValueError
        self._last_now = now
        return now

    def _signature(self, phase: str, record: dict[str, object]) -> str:
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + phase.encode() + b"\x00" + encoded, hashlib.sha256).hexdigest()

    def _write(self, name: str, record: dict[str, object]) -> None:
        self._validate()
        directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != self._identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError
                json.dump({**record, "signature":self._signature(name, record)}, stream,
                          sort_keys=True, separators=(",", ":"), allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str, fields: frozenset[str]) -> dict[str, object]:
        self._validate()
        raw = _read(self._directory / name, 4096)
        try:
            self._validate()
            start = _skip_json_space(raw, 0)
            end = _json_value_end(raw, start)
            if _skip_json_space(raw, end) != len(raw):
                raise ValueError
            m._validate_json(raw, start, end, depth=0, budget=[10000])
            spans = _object_spans(raw, start, end)
            if set(spans) != fields | {"signature"}:
                raise ValueError
            record = {key:m._scalar(raw, span) for key, span in spans.items()}
            signature = record.pop("signature")
            for key, value in record.items():
                if key.endswith("_at"):
                    if type(value) is not int or not self._authorization.issued_at <= value < self._authorization.expires_at:
                        raise ValueError
                else:
                    if type(value) is not str:
                        raise ValueError
                    require_digest(value, "policy_custody_record")
            if (record["context_digest"] != self._context or type(signature) is not str
                    or not hmac.compare_digest(signature, self._signature(name, record))):
                raise ValueError
            return record
        finally:
            _zeroize_mutable(raw)

    def begin_original_send(self, absence: bytearray, *, http_status: int) -> None:
        """Reserve one send within the real M4, after its exact original absence."""
        try:
            with self._lock:
                now = self._writing_now()
                if self._send_started:
                    raise ValueError
                self._send_started = True
                digest = consume_windows_policy_response(absence, binding=self._request.binding,
                    phase="absent", http_status=http_status)
                self._writing_now()
                self._write(_SEND, {"context_digest":self._context, "absence_digest":digest, "claimed_at":now})
        except Exception:
            self._closed = True
            raise WindowsExecutionPolicyCustodyError(_ERROR) from None
        finally:
            if type(absence) is bytearray:
                _zeroize_mutable(absence)

    def capture_original_ack(self, raw: bytearray, *, http_status: int, content_type: str) -> None:
        """Consume only the original response; a rejected response stays consumed."""
        try:
            with self._lock:
                now = self._writing_now()
                if not self._send_started or self._ack_consumed or content_type.split(";")[0] != "application/json":
                    raise ValueError
                self._ack_consumed = True
                claim = self._record(_SEND, frozenset({"context_digest", "absence_digest", "claimed_at"}))
                if now < cast(int, claim["claimed_at"]):
                    raise ValueError
                digest = consume_windows_policy_response(raw, binding=self._request.binding,
                    phase="create", http_status=http_status)
                self._writing_now()
                self._write(_ACK, {"context_digest":self._context, "claim_digest":canonical_digest(claim),
                    "acknowledgement_digest":digest, "acknowledged_at":now})
        except Exception:
            self._closed = True
            raise WindowsExecutionPolicyCustodyError(_ERROR) from None
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)

    def inspect_original_ack(self) -> WindowsPolicyOriginalObservation:
        """Read original signed provenance without replay or outcome promotion."""
        try:
            with self._lock:
                original = self._original_claim()
                claim = self._record(_SEND, frozenset({"context_digest", "absence_digest", "claimed_at"}))
                ack = self._record(_ACK, frozenset({"context_digest", "claim_digest", "acknowledgement_digest", "acknowledged_at"}))
                if (ack["claim_digest"] != canonical_digest(claim)
                        or cast(int, ack["acknowledged_at"]) < cast(int, claim["claimed_at"])):
                    raise ValueError
                return WindowsPolicyOriginalObservation(self._context, canonical_digest(ack),
                    str(original.result.outcome) if original.result is not None else "in_progress",
                    str(original.result.verification) if original.result is not None else "unknown", None,
                    self._source_context)
        except Exception:
            raise WindowsExecutionPolicyCustodyError(_ERROR) from None

    def capture_created_state(self, raw: bytearray) -> None:
        """Seal complete state only during the original active dispatch/readback."""
        try:
            with self._lock:
                now = self._writing_now()
                if self._state_consumed:
                    raise ValueError
                self._state_consumed = True
                ack = self.inspect_original_ack()
                state = consume_windows_policy_state(raw, request=self._request)
                self._writing_now()
                self._write(_STATE, {"context_digest":self._context, "ack_custody_digest":ack.custody_digest,
                    "state_digest":state, "verified_at":now})
        except Exception:
            self._closed = True
            raise WindowsExecutionPolicyCustodyError(_ERROR) from None
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)

    def inspect_created_state(self) -> WindowsPolicyOriginalObservation:
        """Require the original state seal; never supply a late replacement."""
        try:
            with self._lock:
                ack = self.inspect_original_ack()
                state = self._record(_STATE, frozenset({"context_digest", "ack_custody_digest", "state_digest", "verified_at"}))
                original = self._record(_ACK, frozenset({"context_digest", "claim_digest", "acknowledgement_digest", "acknowledged_at"}))
                if (state["ack_custody_digest"] != ack.custody_digest
                        or cast(int, state["verified_at"]) < cast(int, original["acknowledged_at"])):
                    raise ValueError
                return WindowsPolicyOriginalObservation(ack.context_digest, canonical_digest(state),
                    ack.original_outcome, ack.original_verification, cast(str, state["state_digest"]),
                    self._source_context)
        except Exception:
            raise WindowsExecutionPolicyCustodyError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
