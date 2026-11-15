"""Private original-response custody for a prospective manual JWT-key POST.

No HTTP producer, authority issuer, Tool or recovery operation is implemented
here. A signed bounded response observation precedes all native parsing. Error,
partial and late responses remain observations, never creation receipts.
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
from typing import Any

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import M4Claim, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as parser
from .jwt_manual_key_actor_evidence import JwtManualKeyActorEvidence
from .jwt_manual_key_request_contract import JwtManualCreateRequest, consume_jwt_manual_create_ack
from .jwt_manual_key_preflight import JwtManualKeyPreflight
from .jwt_manual_key_owned_state import (JwtManualKeyOwnedState, consume_jwt_manual_key_owned_state,
    expected_jwt_manual_key_created_state)
from .ldap_server_runtime import _key, _private_directory, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

ACTION_ID = "manual-jwt-key-create"
ADAPTER_REF = "fortipam-700-build29-manual-jwt-key-m4-v1"
_CONTRACT = "manual-jwt-key-response-custody-build29/v1"
_DOMAIN = _CONTRACT.encode() + b"\x00"
_ERROR = "The private original JWT-key response is unavailable."
_MAX_BYTES = 524288
_SEND, _RESPONSE, _METADATA, _ACK = "send.claim.json", "response.json", "response-metadata.json", "create-ack.json"
_STATE = "original-state.json"
_FIELDS = {
    _SEND: frozenset({"context_digest", "claimed_at", "request_digest", "actor_digest"}),
    _RESPONSE: frozenset({"context_digest", "send_digest", "response_hmac", "captured_at", "http_status",
        "content_kind", "body_state", "body_bytes", "clock_valid"}),
    _METADATA: frozenset({"context_digest", "response_record_digest", "native_context_matches", "native_status",
        "native_http_status", "native_error", "source_valid", "clock_valid"}),
    _ACK: frozenset({"context_digest", "response_record_digest", "metadata_digest", "request_digest",
        "response_digest", "acknowledged_at"}),
    _STATE: frozenset({"context_digest", "ack_custody_digest", "full_row_hmac", "postcondition_digest",
        "api_users_digest", "key_namespace_digest", "observed_at"}),
}


class JwtManualKeyResponseCustodyError(RuntimeError):
    """Fixed non-disclosing refusal; no retry, ownership or recovery authority."""


def jwt_manual_create_current_digest(request: JwtManualCreateRequest, actor: JwtManualKeyActorEvidence,
                                    source_digest: str, state_digest: str) -> str:
    """Bind the native request/actor to a separately qualified complete preflight."""
    try:
        if type(request) is not JwtManualCreateRequest or type(actor) is not JwtManualKeyActorEvidence:
            raise ValueError
        for value in (source_digest, state_digest, request.digest, actor.digest):
            require_digest(value, "jwt_current")
        request.validate()
        if actor.serial_digest != request.serial_digest:
            raise ValueError
        return canonical_digest({"contract": _CONTRACT, "request": request.digest, "actor": actor.digest,
            "source": source_digest, "state": state_digest})
    except Exception:
        raise JwtManualKeyResponseCustodyError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualOriginalResponse(_OpaqueC3Object):
    """Minimal original-wire observation; terminal M4 status is never repaired."""

    context_digest: str
    custody_digest: str
    http_status: int | None
    body_state: str
    native_status: str
    native_http_status: int | None
    native_error: int | None
    native_context_matches: bool
    success_ack_retained: bool
    original_outcome: str
    original_verification: str


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualOriginalOwnedState(_OpaqueC3Object):
    response: JwtManualOriginalResponse
    state: JwtManualKeyOwnedState
    custody_digest: str


class JwtManualKeyResponseCustody(_OpaqueC3Object):
    """Write once in the original active M4; inspect after closure or expiry.

    Execution/source/fresh-actor callbacks default to denial. They are private
    producer inputs, not authority. Full state, backend compatibility and an
    independent recovery remain prerequisites for any native dispatch.
    """

    def __init__(self, directory: Path, witness_key_file: Path, request: JwtManualCreateRequest,
                 actor: JwtManualKeyActorEvidence, source_digest: str, state_digest: str,
                 plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                 store: PersistentM4ExecutionStateStore, *,
                 execution_enabled: Callable[[], bool] | None = None,
                 source_guard: Callable[[], bool] | None = None,
                 actor_reader: Callable[[], JwtManualKeyActorEvidence] | None = None,
                 clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                    or type(store) is not PersistentM4ExecutionStateStore
                    or store.monotonic_checkpoint_protocol_bound is not True
                    or any(value is not None and not callable(value)
                           for value in (execution_enabled, source_guard, actor_reader, clock))):
                raise ValueError
            self._current = jwt_manual_create_current_digest(request, actor, source_digest, state_digest)
            self._request, self._actor = request, actor
            self._request_digest, self._actor_digest = request.digest, actor.digest
            self._name, self._serial_digest = request._name, request.serial_digest
            self._source, self._state = source_digest, state_digest
            self._plan, self._authorization, self._store = plan, authorization, store
            self._plan_digest, self._authorization_digest = plan.plan_digest, authorization.authorization_digest
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            _private_directory(self._directory)
            info = self._directory.stat()
            self._directory_identity = (info.st_dev, info.st_ino)
            if self._key_file in (store._path, store._key_path, *(self._directory / name for name in _FIELDS)):
                raise ValueError
            self._key = _key(self._key_file)
            if hmac.compare_digest(self._key, store._key):
                raise ValueError
            self._context = canonical_digest({"contract": _CONTRACT, "plan": self._plan_digest,
                "authorization": self._authorization_digest, "current": self._current,
                "request": self._request_digest, "actor": self._actor_digest})
            self._execution_enabled, self._source_guard, self._actor_reader = execution_enabled, source_guard, actor_reader
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._last_now = -1
            self._begin_consumed = self._send_started = self._capture_consumed = self._closed = False
            self._state_consumed = False
            self._lock = RLock()
            self._integrity()
        except Exception:
            raise JwtManualKeyResponseCustodyError(_ERROR) from None

    def _integrity(self) -> None:
        p, a = self._plan, self._authorization
        p.__post_init__(); a.__post_init__()
        if (p.plan_digest != self._plan_digest or a.authorization_digest != self._authorization_digest
                or p.action_id != ACTION_ID or p.action_version != "1.0.0" or p.adapter_ref != ADAPTER_REF
                or p.target_ref != "bound-manual-jwt-public-key" or p.parameters_digest != self._request_digest
                or p.expected_current_digest != self._current or p.compensation_ref is not None
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest
                or a.requester_digest != p.requester_digest or a.confirmation_digest != p.confirmation_digest
                or a.approval_digest != p.approval_digest or a.expires_at > p.expires_at):
            raise ValueError
        _private_directory(self._directory)
        info = self._directory.stat()
        if ((info.st_dev, info.st_ino) != self._directory_identity
                or not hmac.compare_digest(_key(self._key_file), self._key)):
            raise ValueError

    def _original_claim(self) -> M4Claim:
        self._integrity()
        p, a = self._plan, self._authorization
        return self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest({"plan_digest": p.plan_digest,
                "authorization_digest": a.authorization_digest, "revision": p.revision}))

    def _active(self) -> None:
        self._integrity()
        _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        if self._original_claim().result is not None:
            raise ValueError

    def _observed_clock(self) -> tuple[int | None, bool]:
        try:
            now = self._clock()
            if type(now) is not int or not 0 <= now < 2 ** 63:
                return None, False
            valid = self._last_now <= now and self._authorization.issued_at <= now < self._authorization.expires_at
            self._last_now = max(self._last_now, now)
            return now, valid
        except Exception:
            return None, False

    def _source_valid(self) -> bool:
        try:
            return (self._execution_enabled is not None and self._execution_enabled() is True
                    and self._source_guard is not None and self._source_guard() is True)
        except Exception:
            return False

    def _request_valid(self) -> bool:
        try:
            return jwt_manual_create_current_digest(self._request, self._actor, self._source, self._state) == self._current
        except Exception:
            return False

    def _signature(self, phase: str, record: dict[str, Any]) -> str:
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + phase.encode() + b"\x00" + encoded, hashlib.sha256).hexdigest()

    def _write(self, name: str, record: dict[str, Any]) -> None:
        self._active()
        payload = {**record, "signature": self._signature(name, record)}
        directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != self._directory_identity
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                    raise ValueError
                json.dump(payload, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str) -> dict[str, Any]:
        self._integrity()
        raw = _read(self._directory / name, 8192)
        try:
            self._integrity()
            start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
            if _skip_json_space(raw, end) != len(raw):
                raise ValueError
            parser._validate_json(raw, start, end, depth=0, budget=[10000])
            fields = parser._object_spans(raw, start, end, _FIELDS[name] | {"signature"})
            if fields.keys() != _FIELDS[name] | {"signature"}:
                raise ValueError
            record = {key: parser._scalar(raw, span) for key, span in fields.items()}
            signature = record.pop("signature")
            if (type(signature) is not str or record["context_digest"] != self._context
                    or not hmac.compare_digest(signature, self._signature(name, record))):
                raise ValueError
            for key, value in record.items():
                if key.endswith("_digest") or key.endswith("_hmac"):
                    if type(value) is not str: raise ValueError
                    require_digest(value, "jwt_response")
                elif key in {"clock_valid", "source_valid", "native_context_matches"}:
                    if type(value) is not bool: raise ValueError
                elif key in {"http_status", "native_http_status"}:
                    if value is not None and (type(value) is not int or not 100 <= value <= 599): raise ValueError
                elif key == "native_error":
                    if value is not None and (type(value) is not int or not -(2 ** 31) <= value < 2 ** 31): raise ValueError
                elif key == "body_bytes":
                    if type(value) is not int or not 0 <= value <= _MAX_BYTES + 1: raise ValueError
                elif key.endswith("_at"):
                    if key == "captured_at" and value is None: continue
                    if type(value) is not int or not 0 <= value < 2 ** 63: raise ValueError
                    if key != "captured_at" and not self._authorization.issued_at <= value < self._authorization.expires_at:
                        raise ValueError
                elif key == "content_kind":
                    if value not in {"json", "other", "unknown"}: raise ValueError
                elif key == "body_state":
                    if value not in {"complete", "partial", "oversize", "encoded"}: raise ValueError
                elif key == "native_status":
                    if value not in {"success", "error", "unknown"}: raise ValueError
                else:
                    raise ValueError
            return record
        finally:
            _zeroize_mutable(raw)

    def begin_original_send(self) -> None:
        """Fsync once before the producer's single POST; never send here."""
        try:
            with self._lock:
                self._active()
                if self._closed or self._begin_consumed:
                    raise ValueError
                self._begin_consumed = True
                if not self._source_valid() or not self._request_valid() or self._actor_reader is None:
                    raise ValueError
                fresh = self._actor_reader()
                if type(fresh) is not JwtManualKeyActorEvidence or fresh.digest != self._actor_digest:
                    raise ValueError
                now, valid = self._observed_clock()
                if not valid or not self._source_valid() or not self._request_valid():
                    raise ValueError
                self._write(_SEND, {"context_digest": self._context, "claimed_at": now,
                    "request_digest": self._request_digest, "actor_digest": self._actor_digest})
                self._send_started = True
        except Exception:
            self._closed = True
            raise JwtManualKeyResponseCustodyError(_ERROR) from None

    def capture_original_response(self, raw: bytearray, *, http_status: int | None,
                                  content_type: str | None, body_state: str = "complete",
                                  producer_context_valid: bool = False) -> JwtManualOriginalResponse:
        """Save minimal wire evidence before parsing; late failures cannot be ACKs.

        For an interrupted or oversized transport the producer supplies its
        bounded prefix and partial/oversize state. It must not fetch/replay the
        response. Observation is allowed after in-flight expiry or Gate/source
        drift only while this original instance and M4 dispatch remain active.
        """
        try:
            with self._lock:
                self._active()
                if (self._closed or not self._send_started or self._capture_consumed
                        or type(raw) is not bytearray or body_state not in {"complete", "partial", "oversize", "encoded"}):
                    raise ValueError
                self._capture_consumed = True
                send = self._record(_SEND)
                now, valid = self._observed_clock()
                status = http_status if type(http_status) is int and 100 <= http_status <= 599 else None
                content = ("json" if content_type.split(";", 1)[0].strip().lower() == "application/json" else "other"
                           ) if type(content_type) is str and len(content_type) <= 255 else "unknown"
                size = min(len(raw), _MAX_BYTES + 1)
                state = "oversize" if len(raw) > _MAX_BYTES else body_state
                with memoryview(raw)[:size] as prefix:
                    fingerprint = hmac.new(self._key, _DOMAIN + b"wire\x00" + self._context.encode(), hashlib.sha256)
                    fingerprint.update(prefix)
                response = {"context_digest": self._context, "send_digest": canonical_digest(send),
                    "response_hmac": fingerprint.hexdigest(), "captured_at": now, "http_status": status,
                    "content_kind": content, "body_state": state, "body_bytes": size, "clock_valid": valid}
                self._write(_RESPONSE, response)
                # No native JSON or ACK interpretation occurs before this durable record.
                summary = self._native_summary(raw) if state == "complete" and content == "json" else self._unknown_summary()
                summary.update(context_digest=self._context, response_record_digest=canonical_digest(response),
                    source_valid=producer_context_valid is True and self._source_valid() and self._request_valid(), clock_valid=valid)
                self._write(_METADATA, summary)
                _, still_valid = self._observed_clock()
                if (valid and still_valid and summary["source_valid"] and self._source_valid()
                        and self._request_valid() and state == "complete" and content == "json"
                        and status == 200 and summary["native_context_matches"]):
                    try:
                        ack = consume_jwt_manual_create_ack(raw, self._request, http_status=status)
                    except Exception:
                        ack = None
                    if ack is not None:
                        ack_now, ack_valid = self._observed_clock()
                        if ack_valid and self._source_valid() and self._request_valid():
                            self._write(_ACK, {"context_digest": self._context, "response_record_digest": canonical_digest(response),
                                "metadata_digest": canonical_digest(summary), "request_digest": self._request_digest,
                                "response_digest": ack.response_digest, "acknowledged_at": ack_now})
                return self.inspect_original_response()
        except Exception:
            raise JwtManualKeyResponseCustodyError(_ERROR) from None
        finally:
            self._closed = True
            if type(raw) is bytearray:
                _zeroize_mutable(raw)

    @staticmethod
    def _unknown_summary() -> dict[str, Any]:
        return dict(native_context_matches=False, native_status="unknown", native_http_status=None, native_error=None)

    def _native_summary(self, raw: bytearray) -> dict[str, Any]:
        try:
            start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
            if _skip_json_space(raw, end) != len(raw): raise ValueError
            parser._validate_json(raw, start, end, depth=0, budget=[50000])
            fields = parser._object_spans(raw, start, end, frozenset({"version", "build", "serial", "http_method",
                "http_status", "status", "path", "name", "vdom", "mkey", "error"}))
            selected = {key: parser._scalar(raw, span) for key, span in fields.items()}
            expected = dict(version="v7.0.0", build=29, http_method="POST", path="secret", name="jwt-key", vdom="root")
            matches = all(type(selected.get(key)) is type(value) and selected[key] == value for key, value in expected.items())
            serial = selected.get("serial")
            matches = matches and type(serial) is str and hashlib.sha256(serial.encode()).hexdigest() == self._serial_digest
            if "mkey" in selected:
                matches = matches and type(selected["mkey"]) is str and selected["mkey"] == self._name
            status, error, http_status = selected.get("status"), selected.get("error"), selected.get("http_status")
            return dict(native_context_matches=matches, native_status=status if status in {"success", "error"} else "unknown",
                native_http_status=http_status if type(http_status) is int and 100 <= http_status <= 599 else None,
                native_error=error if type(error) is int and -(2 ** 31) <= error < 2 ** 31 else None)
        except Exception:
            return self._unknown_summary()

    def inspect_original_response(self) -> JwtManualOriginalResponse:
        """Read original seals/claim only; never promote UNKNOWN or authorize removal."""
        try:
            with self._lock:
                original = self._original_claim()
                send, response = self._record(_SEND), self._record(_RESPONSE)
                if (send["request_digest"] != self._request_digest or send["actor_digest"] != self._actor_digest
                        or response["send_digest"] != canonical_digest(send)):
                    raise ValueError
                if response["clock_valid"] and (type(response["captured_at"]) is not int
                        or not send["claimed_at"] <= response["captured_at"] < self._authorization.expires_at):
                    raise ValueError
                metadata = self._record(_METADATA) if os.path.lexists(self._directory / _METADATA) else None
                if metadata is not None and (metadata["response_record_digest"] != canonical_digest(response)
                        or metadata["clock_valid"] != response["clock_valid"]):
                    raise ValueError
                ack = self._record(_ACK) if os.path.lexists(self._directory / _ACK) else None
                if ack is not None and (metadata is None or metadata["native_context_matches"] is not True
                        or not metadata["clock_valid"] or not metadata["source_valid"]
                        or response["http_status"] != 200 or response["body_state"] != "complete"
                        or response["content_kind"] != "json" or metadata["native_status"] != "success"
                        or metadata["native_http_status"] != 200 or metadata["native_error"] not in {0, None}
                        or ack["response_record_digest"] != canonical_digest(response)
                        or ack["metadata_digest"] != canonical_digest(metadata) or ack["request_digest"] != self._request_digest
                        or ack["acknowledged_at"] < response["captured_at"]):
                    raise ValueError
                summary = metadata if metadata is not None else self._unknown_summary()
                return JwtManualOriginalResponse(self._context, canonical_digest({"send": send, "response": response,
                    "metadata": metadata, "ack": ack}), response["http_status"], response["body_state"], summary["native_status"],
                    summary["native_http_status"], summary["native_error"], summary["native_context_matches"], ack is not None,
                    str(original.result.outcome) if original.result is not None else "in_progress",
                    str(original.result.verification) if original.result is not None else "unknown")
        except Exception:
            raise JwtManualKeyResponseCustodyError(_ERROR) from None

    def capture_original_owned_state(self, detail_before: bytearray, keys: bytearray, users: bytearray,
                                     detail_after: bytearray, *, baseline: JwtManualKeyPreflight) -> None:
        """Seal one complete state only after the original ACK in active dispatch."""
        buffers = (detail_before, keys, users, detail_after)
        try:
            with self._lock:
                self._active()
                if not self._send_started or not self._capture_consumed or self._state_consumed:
                    raise ValueError
                self._state_consumed = True
                original = self.inspect_original_response()
                if (not original.success_ack_retained or type(baseline) is not JwtManualKeyPreflight
                        or baseline.state_digest != self._state
                        or expected_jwt_manual_key_created_state(self._request, baseline) != self._plan.expected_state_digest
                        or not self._source_valid() or not self._request_valid()):
                    raise ValueError
                _, valid = self._observed_clock()
                if not valid: raise ValueError
                observed = consume_jwt_manual_key_owned_state(*buffers, request=self._request, baseline=baseline,
                    witness_key=self._key)
                now, valid = self._observed_clock()
                if (not valid or not self._source_valid() or not self._request_valid()
                        or self.inspect_original_response() != original):
                    raise ValueError
                self._write(_STATE, {"context_digest": self._context, "ack_custody_digest": original.custody_digest,
                    "full_row_hmac": observed.full_row_hmac, "postcondition_digest": observed.postcondition_digest,
                    "api_users_digest": observed.api_users_digest, "key_namespace_digest": observed.key_namespace_digest,
                    "observed_at": now})
        except Exception:
            raise JwtManualKeyResponseCustodyError(_ERROR) from None
        finally:
            for raw in buffers:
                if type(raw) is bytearray: _zeroize_mutable(raw)

    def inspect_original_owned_state(self) -> JwtManualOriginalOwnedState:
        """Read original ACK/state seals without repairing a terminal M4 result."""
        try:
            with self._lock:
                original = self.inspect_original_response()
                state = self._record(_STATE)
                if (not original.success_ack_retained or state["ack_custody_digest"] != original.custody_digest
                        or state["postcondition_digest"] != self._plan.expected_state_digest):
                    raise ValueError
                observed = JwtManualKeyOwnedState(self._request_digest, state["full_row_hmac"], state["api_users_digest"],
                    state["key_namespace_digest"], state["postcondition_digest"])
                return JwtManualOriginalOwnedState(original, observed, canonical_digest(state))
        except Exception:
            raise JwtManualKeyResponseCustodyError(_ERROR) from None


__all__ = ["ACTION_ID", "ADAPTER_REF", "JwtManualKeyResponseCustodyError", "JwtManualOriginalResponse", "JwtManualOriginalOwnedState",
           "JwtManualKeyResponseCustody", "jwt_manual_create_current_digest"]
