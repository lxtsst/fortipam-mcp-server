"""Original independent-recovery custody; the create ledger stays readonly.

One reservation is keyed by the original create plan across recovery stores,
directories and regenerated plans. ACK and full API restoration are sealed only
inside the active recovery M4. Static inspection does not need a live cookie.
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

from .ems_tag_contract import _canonical
from .ems_tag_custody import EmsTagOriginalActorBinding, EmsTagOriginalCustody, _ack_data, _decode
from .ems_tag_recovery_authority import ACTION_ID, ADAPTER_REF, TARGET_REF
from .ems_tag_recovery_contract import EmsTagOwnedRecoveryScope, EmsTagRecoveryObservation
from .ldap_server_runtime import _key, _private_directory, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

_SEND, _ATTEMPT, _ACK = "recover.claim.json", "recover.ack.attempt.json", "recover.ack.json"
_RESTORED, _FAILURE = "recover.restored.json", "recover.failure.json"
_NAMES = frozenset({_SEND, _ATTEMPT, _ACK, _RESTORED, _FAILURE})
_DOMAIN = b"ems-original-owned-tag-recovery-custody/v1\x00"
_ERROR = "The private original EMS tag recovery custody is unavailable."


class EmsTagRecoveryCustodyError(RuntimeError):
    """No new dispatch, late seal or ownership on refusal."""


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagRecoverySeal(_OpaqueC3Object):
    context_digest: str
    custody_digest: str
    original_custody_digest: str
    restored_api_scope_digest: str
    outcome: str
    verification: str


class EmsTagRecoveryCustody(_OpaqueC3Object):
    def __init__(self, directory: Path, witness_key_file: Path, original: EmsTagOriginalCustody,
                 recovery_context_digest: str, actor_binding: EmsTagOriginalActorBinding,
                 plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                 store: PersistentM4ExecutionStateStore, *, clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(original) is not EmsTagOriginalCustody or original._store._read_only is not True
                    or type(actor_binding) is not EmsTagOriginalActorBinding or type(plan) is not M4ExecutionPlan
                    or type(authorization) is not M4ExecutionAuthorization
                    or type(store) is not PersistentM4ExecutionStateStore or store.monotonic_checkpoint_protocol_bound is not True
                    or clock is not None and not callable(clock)):
                raise ValueError
            require_digest(recovery_context_digest, "ems_recovery_context")
            actor_binding.__post_init__()
            self._original, self._birth = original, original.inspect_created_scope()
            self._binding, self._actor = recovery_context_digest, actor_binding
            self._plan, self._authorization, self._store = plan, authorization, store
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            _private_directory(self._directory)
            info = self._directory.stat();self._identity = (info.st_dev, info.st_ino)
            self._key = _key(self._key_file)
            self._origin_parent = original._store._path.parent
            _private_directory(self._origin_parent)
            info = self._origin_parent.stat();self._origin_identity = (info.st_dev, info.st_ino)
            self._reservation = original._store._path.name + ".ems-recover." + original._plan.plan_digest + ".json"
            self._context = canonical_digest(self._context_fields())
            self._clock = clock or (lambda: int(time.time()))
            self._last, self._closed, self._lock = -1, False, RLock()
            self._postcondition_open = False
            self._validate()
        except Exception:
            raise EmsTagRecoveryCustodyError(_ERROR) from None

    def _context_fields(self) -> dict[str, object]:
        return {"contract": ADAPTER_REF, "original": self._birth.custody_digest,
            "original_context": self._original._context, "recovery_context": self._binding,
            "actor": self._actor.digest, "plan": self._plan.plan_digest,
            "authorization": self._authorization.authorization_digest,
            "store_path": str(self._store._path.absolute()), "store_key_path": str(self._store._key_path.absolute()),
            "store_key": hashlib.sha256(self._store._key).hexdigest(),
            "directory": str(self._directory.absolute()), "identity": self._identity,
            "witness_key_path": str(self._key_file.absolute()), "origin_identity": self._origin_identity}

    def _validate(self) -> None:
        p, a, original = self._plan, self._authorization, self._original
        p.__post_init__();a.__post_init__();self._actor.__post_init__()
        forbidden = {original._key, original._store._key}
        issuer = self._birth.actor_binding.issuer_key_digest
        if (original._store._read_only is not True or original.inspect_created_scope() != self._birth
                or self._actor.owner_session_digest == self._birth.actor_binding.owner_session_digest
                or self._actor.caller_transport_digest == self._birth.actor_binding.caller_transport_digest
                or self._actor.issuer_key_digest == issuer
                or len({self._key, self._store._key}) != 2 or self._key in forbidden or self._store._key in forbidden
                or any(hashlib.sha256(key).hexdigest() in {issuer, self._actor.issuer_key_digest}
                       for key in (self._key, self._store._key))
                or self._store._path == original._store._path or self._store._key_path == original._store._key_path
                or self._directory == original._directory
                or self._key_file in {self._store._path, self._store._key_path, original._key_file,
                    original._store._path, original._store._key_path, self._origin_parent / self._reservation}
                or self._key_file in {self._directory / name for name in _NAMES}
                or p.action_id != ACTION_ID or p.action_version != "1.0.0" or p.adapter_ref != ADAPTER_REF
                or p.target_ref != TARGET_REF or p.requester_digest != original._plan.requester_digest
                or p.compensation_ref is not None
                or p.expected_state_digest != canonical_digest({"context": self._binding,
                    "postcondition": "original-native-tag-catalog-and-full-prior-states-restored"})
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or a.confirmation_digest != p.confirmation_digest or a.approval_digest != p.approval_digest
                or a.execution_authorized is not True or a.one_time is not True or a.expires_at > p.expires_at
                or self._context != canonical_digest(self._context_fields())):
            raise ValueError
        _private_directory(self._directory);_private_directory(self._origin_parent)
        info, origin = self._directory.stat(), self._origin_parent.stat()
        if ((info.st_dev, info.st_ino) != self._identity or (origin.st_dev, origin.st_ino) != self._origin_identity
                or set(os.listdir(self._directory)) - _NAMES or not hmac.compare_digest(_key(self._key_file), self._key)):
            raise ValueError

    def _claim(self) -> M4Claim:
        self._validate()
        p, a = self._plan, self._authorization
        return self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest({"plan_digest": p.plan_digest,
                "authorization_digest": a.authorization_digest, "revision": p.revision}))

    def _writing_now(self) -> int:
        self._validate()
        _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        now = self._clock()
        if (self._closed or self._store._read_only or self._claim().result is not None
                or type(now) is not int or now < self._last
                or not self._authorization.issued_at <= now < self._authorization.expires_at):
            raise ValueError
        self._last = now
        return now

    def _signature(self, name: str, record: object) -> str:
        return hmac.new(self._key, _DOMAIN + name.encode() + b"\x00" + _canonical(record), hashlib.sha256).hexdigest()

    def _write(self, name: str, record: dict[str, object]) -> None:
        self._validate()
        if name not in _NAMES | {self._reservation} or record.get("context_digest") != self._context:
            raise ValueError
        parent = self._origin_parent if name == self._reservation else self._directory
        identity = self._origin_identity if name == self._reservation else self._identity
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if (info.st_dev, info.st_ino) != identity:
                raise ValueError
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "w") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                    raise ValueError
                json.dump({**record, "signature": self._signature(name, record)}, stream, sort_keys=True, separators=(",", ":"))
                stream.flush();os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str, fields: set[str]) -> dict[str, Any]:
        self._validate()
        if name not in _NAMES | {self._reservation}:
            raise ValueError
        parent = self._origin_parent if name == self._reservation else self._directory
        raw = _read(parent / name, 16384)
        try:
            record = _decode(raw)
            if type(record) is not dict or set(record) != fields | {"signature"}:
                raise ValueError
            signature = record.pop("signature")
            if (record.get("context_digest") != self._context or type(signature) is not str
                    or not hmac.compare_digest(signature, self._signature(name, record))):
                raise ValueError
            return record
        finally:
            _zeroize_mutable(raw)

    def _send(self) -> dict[str, Any]:
        origin = self._record(self._reservation, {"context_digest", "original_custody_digest", "claimed_at"})
        send = self._record(_SEND, {"context_digest", "reservation_digest", "current_digest", "claimed_at"})
        if (origin["original_custody_digest"] != self._birth.custody_digest
                or send["reservation_digest"] != canonical_digest(origin)
                or send["current_digest"] != self._plan.expected_current_digest
                or type(send["claimed_at"]) is not int or type(origin["claimed_at"]) is not int
                or not self._authorization.issued_at <= origin["claimed_at"] <= send["claimed_at"] < self._authorization.expires_at):
            raise ValueError
        return send

    def _scope(self, scope: EmsTagOwnedRecoveryScope) -> None:
        if (type(scope) is not EmsTagOwnedRecoveryScope or scope._original is not self._original
                or scope._context != self._binding or scope._session != self._actor.owner_session_digest
                or scope._caller_transport != self._actor.caller_transport_digest):
            raise ValueError
        scope._pins()

    def reserve(self, scope: EmsTagOwnedRecoveryScope, observed: EmsTagRecoveryObservation) -> None:
        try:
            with self._lock:
                now = self._writing_now();self._scope(scope);scope.check_current(observed)
                if observed.current_digest != self._plan.expected_current_digest:
                    raise ValueError
                self._write(self._reservation, {"context_digest": self._context,
                    "original_custody_digest": self._birth.custody_digest, "claimed_at": now})
                origin = self._record(self._reservation, {"context_digest", "original_custody_digest", "claimed_at"})
                self._write(_SEND, {"context_digest": self._context, "reservation_digest": canonical_digest(origin),
                    "current_digest": observed.current_digest, "claimed_at": now})
        except Exception:
            self._closed = True
            raise EmsTagRecoveryCustodyError(_ERROR) from None

    def capture_ack(self, raw: bytearray, *, http_status: int, content_type: str, complete: bool) -> None:
        try:
            with self._lock:
                now = self._writing_now();send = self._send()
                root = valid = data_present = False
                try:
                    decoded = _decode(raw);root = type(decoded) is dict
                    data_present = root and "data" in decoded
                    _ack_data(decoded);valid = True
                except Exception:
                    pass
                digest = hmac.new(self._key, b"ems-original-delete-first-ack/v1\x00", hashlib.sha256)
                if type(raw) is bytearray and len(raw) <= 65536:
                    digest.update(raw)
                witness = {"context_digest": self._context, "send_digest": canonical_digest(send),
                    "http_status": http_status if type(http_status) is int and 0 <= http_status <= 599 else 0,
                    "reply_complete": complete is True, "json_content_type": type(content_type) is str
                        and content_type.split(";", 1)[0].strip().lower() == "application/json",
                    "json_object_complete": root, "native_envelope_valid": valid,
                    "data_field_present": data_present, "reply_digest": digest.hexdigest(), "attempted_at": now}
                self._write(_ATTEMPT, witness)
                if (witness["http_status"] != 200 or not all(witness[key] for key in (
                        "reply_complete", "json_content_type", "json_object_complete", "native_envelope_valid"))):
                    raise ValueError
                self._writing_now()
                self._write(_ACK, {"context_digest": self._context, "attempt_digest": canonical_digest(witness),
                    "ack_digest": digest.hexdigest(), "acknowledged_at": now})
        except Exception:
            self._closed = True
            raise EmsTagRecoveryCustodyError(_ERROR) from None
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)

    def inspect_ack_attempt(self) -> dict[str, Any]:
        try:
            record = self._record(_ATTEMPT, {"context_digest", "send_digest", "http_status", "reply_complete",
                "json_content_type", "json_object_complete", "native_envelope_valid", "data_field_present",
                "reply_digest", "attempted_at"})
            send = self._send()
            if (record["send_digest"] != canonical_digest(send) or type(record["attempted_at"]) is not int
                    or not send["claimed_at"] <= record["attempted_at"] < self._authorization.expires_at):
                raise ValueError
            return record
        except Exception:
            raise EmsTagRecoveryCustodyError(_ERROR) from None

    def _ack(self) -> dict[str, Any]:
        attempt = self.inspect_ack_attempt()
        ack = self._record(_ACK, {"context_digest", "attempt_digest", "ack_digest", "acknowledged_at"})
        if (attempt["http_status"] != 200 or any(attempt[key] is not True for key in (
                "reply_complete", "json_content_type", "json_object_complete", "native_envelope_valid"))
                or ack["attempt_digest"] != canonical_digest(attempt) or ack["ack_digest"] != attempt["reply_digest"]
                or type(ack["acknowledged_at"]) is not int
                or not attempt["attempted_at"] <= ack["acknowledged_at"] < self._authorization.expires_at):
            raise ValueError
        return ack

    def capture_restored(self, scope: EmsTagOwnedRecoveryScope) -> None:
        try:
            with self._lock:
                now = self._writing_now();self._scope(scope);ack = self._ack()
                observed = scope._sources._current
                if observed is None:
                    raise ValueError
                scope._sources.check_current(observed)
                if (observed.full_scope.digest != self._original._baseline
                        or observed.full_scope.catalog.contains_draft(scope._sources._draft)
                        or scope._expected != self._plan.expected_state_digest):
                    raise ValueError
                self._writing_now()
                self._write(_RESTORED, {"context_digest": self._context, "ack_custody_digest": canonical_digest(ack),
                    "restored_api_scope_digest": observed.full_scope.digest,
                    "expected_digest": scope._expected, "verified_at": now})
                self._postcondition_open = True
        except Exception:
            self._closed = True
            raise EmsTagRecoveryCustodyError(_ERROR) from None

    def capture_failure(self, *, stage: str, error_type: str, response_error_type: str | None) -> None:
        """Retain bounded original diagnostics without granting a late seal."""
        with self._lock:
            self._validate()
            _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
            self._capture_failure_record(stage, error_type, response_error_type)

    def capture_postcondition_failure(self, *, stage: str, error_type: str) -> None:
        """Diagnostic only, after the original active dispatch sealed restoration."""
        with self._lock:
            self._validate()
            if (not self._postcondition_open or stage not in {"postcondition", "fpa_postcondition", "fpa_sync_pending"}
                    or self.inspect_restored(require_verified_recovery=False).outcome != "in_progress"):
                raise EmsTagRecoveryCustodyError(_ERROR)
            self._postcondition_open = False
            self._capture_failure_record(stage, error_type, None)

    def _capture_failure_record(self, stage: str, error_type: str, response_error_type: str | None) -> None:
        if self._claim().result is not None or not stage.isascii() or not stage.replace("_", "").isalnum() or len(stage) > 64:
            raise EmsTagRecoveryCustodyError(_ERROR)
        safe = {"ValueError", "EmsTagRecoveryError", "EmsTagRecoveryCustodyError", "M4AuthorizationDenied",
                "RemoteDisconnected", "IncompleteRead", "TimeoutError", "OSError", "EmsTagHttpError"}
        attempt = None
        try:
            record = self.inspect_ack_attempt()
            attempt = {key: record[key] for key in ("http_status", "reply_complete", "json_content_type",
                "json_object_complete", "native_envelope_valid", "data_field_present")}
        except Exception:
            pass
        self._write(_FAILURE, {"context_digest": self._context, "stage": stage,
            "error_type": error_type if error_type in safe else "unavailable",
            "response_error_type": response_error_type if response_error_type in safe else None,
            "original_ack_attempt": attempt, "request_replayable": False})

    def inspect_restored(self, *, require_verified_recovery: bool = True) -> EmsTagRecoverySeal:
        try:
            with self._lock:
                if type(require_verified_recovery) is not bool:
                    raise ValueError
                claim, ack = self._claim(), self._ack()
                restored = self._record(_RESTORED, {"context_digest", "ack_custody_digest",
                    "restored_api_scope_digest", "expected_digest", "verified_at"})
                if (restored["ack_custody_digest"] != canonical_digest(ack)
                        or restored["restored_api_scope_digest"] != self._original._baseline
                        or restored["expected_digest"] != self._plan.expected_state_digest
                        or type(restored["verified_at"]) is not int
                        or not ack["acknowledged_at"] <= restored["verified_at"] < self._authorization.expires_at):
                    raise ValueError
                result = claim.result
                if require_verified_recovery and (result is None or result.outcome != "succeeded"
                        or result.verification != "verified" or result.compensation != "not_requested"):
                    raise ValueError
                return EmsTagRecoverySeal(self._context, canonical_digest(restored), self._birth.custody_digest,
                    self._original._baseline, str(result.outcome) if result else "in_progress",
                    str(result.verification) if result else "unknown")
        except Exception:
            raise EmsTagRecoveryCustodyError(_ERROR) from None
