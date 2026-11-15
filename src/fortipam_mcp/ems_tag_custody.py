"""Original active-M4 custody for one prospective disabled EMS tag.

No transport, authorization issuer, Tool or recovery dispatch is exposed. The
first complete ACK and complete same-dispatch birth graph are sealed separately.
An ACK without a selector never authorizes later name-based adoption.
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
from typing import Any, NoReturn, cast

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import M4Claim, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .ems_tag_contract import (
    CONTRACT, MAX_ORIGINAL_TAGS, DisabledLinuxProcessTag, EmsTagFullScope, _envelope,
    create_current_digest, create_expected_digest, full_single_addition_matches,
)
from .ldap_server_runtime import _key, _private_directory, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

ACTION_ID = "ems-disabled-process-tag-create"
ADAPTER_REF = CONTRACT + "-m4"
TARGET_REF = "bound-new-disabled-ems-tag"
ACK_CONTRACT = "ems-tag-create-success-envelope-v2"
_DOMAIN = b"ems-disabled-process-tag-original-custody/v1\x00"
_ERROR = "The original disabled EMS tag custody is unavailable."
_SEND, _ACK_ATTEMPT, _ACK = "send.claim.json", "ack.attempt.json", "create-ack.json"
_BIRTH_ATTEMPT, _BIRTH = "birth.attempt.json", "created-scope.json"
_NAMES = frozenset({_SEND, _ACK_ATTEMPT, _ACK, _BIRTH_ATTEMPT, _BIRTH})
_ACK_ATTEMPT_FIELDS = frozenset({
    "context_digest", "claim_digest", "reply_digest", "attempted_at", "http_status",
    "reply_complete", "json_content_type", "json_object_complete", "native_envelope_valid",
    "data_field_present",
})


class EmsTagCustodyError(RuntimeError):
    """Value-free refusal without retry, adoption or deletion authority."""


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in items:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _nonfinite(_: str) -> NoReturn:
    raise ValueError


def _decode(raw: bytearray) -> Any:
    if type(raw) is not bytearray or not 0 < len(raw) <= 65536:
        raise ValueError
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)


def _ack_data(payload: object) -> Any:
    """Void success has no selector; complete original birth remains mandatory."""
    if type(payload) is dict and set(payload) == {"result"}:
        return _envelope({"data": None, "result": payload["result"]})
    return _envelope(payload)


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagOriginalActorBinding(_OpaqueC3Object):
    owner_session_digest: str
    caller_transport_digest: str
    issuer_key_digest: str

    def __post_init__(self) -> None:
        for value in (self.owner_session_digest, self.caller_transport_digest, self.issuer_key_digest):
            require_digest(value, "ems_original_actor")

    @property
    def digest(self) -> str:
        self.__post_init__()
        return canonical_digest({"session": self.owner_session_digest, "transport": self.caller_transport_digest,
                                 "issuer_key": self.issuer_key_digest})


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagOriginalObservation(_OpaqueC3Object):
    context_digest: str
    custody_digest: str
    original_outcome: str
    original_verification: str
    created_state_digest: str | None
    created_scope_digest: str | None
    source_context_digest: str
    actor_binding: EmsTagOriginalActorBinding


class EmsTagOriginalCustody(_OpaqueC3Object):
    """Capture only during the actual original claim; reopen as read-only evidence."""

    def __init__(self, directory: Path, witness_key_file: Path,
                 draft: DisabledLinuxProcessTag, baseline_digest: str,
                 plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                 store: PersistentM4ExecutionStateStore, *, source_context_digest: str,
                 actor_binding: EmsTagOriginalActorBinding,
                 clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(draft) is not DisabledLinuxProcessTag or type(plan) is not M4ExecutionPlan
                    or type(authorization) is not M4ExecutionAuthorization
                    or type(store) is not PersistentM4ExecutionStateStore
                    or type(actor_binding) is not EmsTagOriginalActorBinding
                    or store.monotonic_checkpoint_protocol_bound is not True
                    or clock is not None and not callable(clock)):
                raise ValueError
            require_digest(baseline_digest, "ems_baseline")
            require_digest(source_context_digest, "ems_source")
            actor_binding.__post_init__()
            plan.__post_init__()
            authorization.__post_init__()
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            _private_directory(self._directory)
            info = self._directory.stat()
            self._identity = (info.st_dev, info.st_ino)
            self._reservation_name = store._path.name + ".ems-send." + plan.plan_digest + ".json"
            _private_directory(store._path.parent)
            info = store._path.parent.stat()
            self._store_parent_identity = (info.st_dev, info.st_ino)
            if self._key_file in (store._path, store._key_path,
                                  store._path.parent / self._reservation_name,
                                  *(self._directory / name for name in _NAMES)):
                raise ValueError
            self._key = _key(self._key_file)
            if hmac.compare_digest(self._key, store._key):
                raise ValueError
            self._draft, self._baseline, self._source = draft, baseline_digest, source_context_digest
            self._actor_binding = actor_binding
            self._plan, self._authorization, self._store = plan, authorization, store
            self._context = canonical_digest(self._context_fields())
            self._clock = clock or (lambda: int(time.time()))
            self._last_now, self._closed, self._lock = -1, False, RLock()
            self._validate()
        except Exception:
            raise EmsTagCustodyError(_ERROR) from None

    def _context_fields(self) -> dict[str, object]:
        return {"contract": CONTRACT, "ack_contract": ACK_CONTRACT, "parameters": self._draft.parameters_digest,
                "baseline": self._baseline, "source": self._source,
                "actor_binding": self._actor_binding.digest,
                "plan": self._plan.plan_digest, "authorization": self._authorization.authorization_digest,
                "store_key": hashlib.sha256(self._store._key).hexdigest(),
                "store_path": str(self._store._path.absolute()),
                "store_key_path": str(self._store._key_path.absolute()),
                "directory": str(self._directory.absolute()), "identity": self._identity,
                "store_parent_identity": self._store_parent_identity,
                "witness_key_path": str(self._key_file.absolute())}

    def _validate(self) -> None:
        p, a = self._plan, self._authorization
        p.__post_init__()
        a.__post_init__()
        if (p.action_id != ACTION_ID or p.action_version != "1.0.0" or p.adapter_ref != ADAPTER_REF
                or p.target_ref != TARGET_REF or p.compensation_ref is not None
                or p.parameters_digest != self._draft.parameters_digest
                or p.expected_current_digest != create_current_digest(self._draft, self._baseline, self._source)
                or p.expected_state_digest != create_expected_digest(self._draft, self._baseline, self._source)
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest
                or a.requester_digest != p.requester_digest
                or a.confirmation_digest != p.confirmation_digest or a.approval_digest != p.approval_digest
                or a.expires_at > p.expires_at or a.one_time is not True or a.execution_authorized is not True
                or self._context != canonical_digest(self._context_fields())):
            raise ValueError
        _private_directory(self._directory)
        info = self._directory.stat()
        _private_directory(self._store._path.parent)
        store_parent = self._store._path.parent.stat()
        if ((info.st_dev, info.st_ino) != self._identity
                or (store_parent.st_dev, store_parent.st_ino) != self._store_parent_identity
                or set(os.listdir(self._directory)) - _NAMES
                or not hmac.compare_digest(_key(self._key_file), self._key)):
            raise ValueError

    def _claim(self) -> M4Claim:
        self._validate()
        p, a = self._plan, self._authorization
        return self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest({"plan_digest": p.plan_digest,
                "authorization_digest": a.authorization_digest, "revision": p.revision}))

    def _writing_now(self) -> int:
        if self._closed:
            raise ValueError
        self._validate()
        _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        if self._claim().result is not None:
            raise ValueError
        now = self._clock()
        if (type(now) is not int or now < self._last_now
                or not self._authorization.issued_at <= now < self._authorization.expires_at):
            raise ValueError
        self._last_now = now
        return now

    def _mac(self, purpose: str, value: bytes | bytearray) -> str:
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + value,
                        hashlib.sha256).hexdigest()

    def _signature(self, name: str, record: dict[str, object]) -> str:
        return self._mac(name, json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())

    def _write(self, name: str, record: dict[str, object]) -> None:
        self._validate()
        if name not in _NAMES | {self._reservation_name}:
            raise ValueError
        parent = self._store._path.parent if name == self._reservation_name else self._directory
        identity = self._store_parent_identity if name == self._reservation_name else self._identity
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_nlink != 1):
                    raise ValueError
                json.dump({**record, "signature": self._signature(name, record)}, stream,
                          sort_keys=True, separators=(",", ":"), allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str, fields: frozenset[str]) -> dict[str, object]:
        self._validate()
        if name not in _NAMES | {self._reservation_name}:
            raise ValueError
        parent = self._store._path.parent if name == self._reservation_name else self._directory
        raw = _read(parent / name, 8192)
        try:
            record = _decode(raw)
            if type(record) is not dict or set(record) != fields | {"signature"}:
                raise ValueError
            signature = record.pop("signature")
            for field, value in record.items():
                if name == _ACK_ATTEMPT and field == "http_status":
                    if type(value) is not int or not 0 <= value <= 599:
                        raise ValueError
                elif name == _ACK_ATTEMPT and field in {
                        "reply_complete", "json_content_type", "json_object_complete", "native_envelope_valid", "data_field_present"}:
                    if type(value) is not bool:
                        raise ValueError
                elif field.endswith("_at"):
                    if (type(value) is not int
                            or not self._authorization.issued_at <= value < self._authorization.expires_at):
                        raise ValueError
                else:
                    if type(value) is not str:
                        raise ValueError
                    require_digest(value, "ems_custody")
            if (record["context_digest"] != self._context or type(signature) is not str
                    or not hmac.compare_digest(signature, self._signature(name, record))):
                raise ValueError
            return cast(dict[str, object], record)
        finally:
            _zeroize_mutable(raw)

    def _send_record(self) -> dict[str, object]:
        claim = self._record(_SEND, frozenset({"context_digest", "baseline_digest", "reservation_digest", "claimed_at"}))
        reservation = self._record(self._reservation_name, frozenset({"context_digest", "reserved_at"}))
        if (claim["baseline_digest"] != self._baseline or claim["reservation_digest"] != canonical_digest(reservation)
                or cast(int, claim["claimed_at"]) < cast(int, reservation["reserved_at"])):
            raise ValueError
        return claim

    def begin_original_send(self, baseline: EmsTagFullScope) -> None:
        try:
            with self._lock:
                now = self._writing_now()
                if (type(baseline) is not EmsTagFullScope or baseline.digest != self._baseline
                        or baseline.catalog.count > MAX_ORIGINAL_TAGS
                        or baseline.catalog.contains_draft(self._draft)):
                    raise ValueError
                self._write(self._reservation_name, {"context_digest": self._context, "reserved_at": now})
                reservation = self._record(self._reservation_name, frozenset({"context_digest", "reserved_at"}))
                self._write(_SEND, {"context_digest": self._context, "baseline_digest": baseline.digest,
                                    "reservation_digest": canonical_digest(reservation), "claimed_at": now})
        except Exception:
            self._closed = True
            raise EmsTagCustodyError(_ERROR) from None

    def capture_original_ack(self, raw: bytearray, *, http_status: int,
                              content_type: str, complete: bool) -> None:
        """Consume the first response, including incomplete or malformed replies."""
        try:
            with self._lock:
                now = self._writing_now()
                claim = self._send_record()
                root_complete = envelope_valid = data_present = False
                if type(raw) is bytearray and 0 < len(raw) <= 65536:
                    try:
                        decoded = _decode(raw)
                        root_complete = type(decoded) is dict
                        data_present = root_complete and "data" in decoded
                        _ack_data(decoded)
                        envelope_valid = True
                    except Exception:
                        pass
                    reply_digest = self._mac("first-response", raw)
                else:
                    reply_digest = self._mac("first-response-unavailable", b"unavailable")
                self._write(_ACK_ATTEMPT, {"context_digest": self._context,
                    "claim_digest": canonical_digest(claim), "attempted_at": now,
                    "reply_digest": reply_digest,
                    "http_status": http_status if type(http_status) is int and 0 <= http_status <= 599 else 0,
                    "reply_complete": complete is True,
                    "json_content_type": type(content_type) is str and content_type.split(";")[0].strip().lower() == "application/json",
                    "json_object_complete": root_complete, "native_envelope_valid": envelope_valid,
                    "data_field_present": data_present})
                if (type(http_status) is not int or http_status != 200 or type(content_type) is not str
                        or content_type.split(";")[0].strip().lower() != "application/json" or complete is not True):
                    raise ValueError
                data = _ack_data(_decode(raw))
                selector: int | None = None
                if type(data) is int:
                    if not 0 < data <= 2**31 - 1:
                        raise ValueError
                    selector = data
                elif type(data) is dict and ("tag_id" in data or set(data) == {"id"}):
                    value = data["tag_id"] if "tag_id" in data else data["id"]
                    if type(value) is not int or not 0 < value <= 2**31 - 1:
                        raise ValueError
                    if "tag_id" in data and "id" in data and data["id"] != value:
                        raise ValueError
                    selector = value
                selector_digest = (self._mac("ack-selector", str(selector).encode()) if selector is not None
                                   else self._mac("ack-selector-unavailable", b"none"))
                self._writing_now()
                self._write(_ACK, {"context_digest": self._context, "claim_digest": canonical_digest(claim),
                    "acknowledgement_digest": self._mac("original-ack", raw),
                    "selector_digest": selector_digest, "acknowledged_at": now})
        except Exception:
            self._closed = True
            raise EmsTagCustodyError(_ERROR) from None
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)

    def inspect_original_ack(self) -> EmsTagOriginalObservation:
        try:
            with self._lock:
                original = self._claim()
                claim = self._send_record()
                attempt = self._record(_ACK_ATTEMPT, _ACK_ATTEMPT_FIELDS)
                ack = self._record(_ACK, frozenset({"context_digest", "claim_digest", "acknowledgement_digest",
                                                   "selector_digest", "acknowledged_at"}))
                if (attempt["claim_digest"] != canonical_digest(claim) or ack["claim_digest"] != canonical_digest(claim)
                        or attempt["http_status"] != 200 or attempt["reply_complete"] is not True
                        or attempt["json_content_type"] is not True or attempt["native_envelope_valid"] is not True
                        or cast(int, ack["acknowledged_at"]) < cast(int, attempt["attempted_at"])
                        or cast(int, attempt["attempted_at"]) < cast(int, claim["claimed_at"])):
                    raise ValueError
                return EmsTagOriginalObservation(self._context, canonical_digest(ack),
                    str(original.result.outcome) if original.result else "in_progress",
                    str(original.result.verification) if original.result else "unknown", None, None, self._source,
                    self._actor_binding)
        except Exception:
            raise EmsTagCustodyError(_ERROR) from None

    def inspect_ack_attempt(self) -> dict[str, object]:
        """Expose only the original bounded framing witness, never an ACK seal."""
        try:
            with self._lock:
                self._claim()
                claim = self._send_record()
                attempt = self._record(_ACK_ATTEMPT, _ACK_ATTEMPT_FIELDS)
                if (attempt["claim_digest"] != canonical_digest(claim)
                        or cast(int, attempt["attempted_at"]) < cast(int, claim["claimed_at"])):
                    raise ValueError
                return {field: attempt[field] for field in (
                    "http_status", "reply_complete", "json_content_type", "json_object_complete", "native_envelope_valid", "data_field_present")}
        except Exception:
            raise EmsTagCustodyError(_ERROR) from None

    def capture_created_scope(self, baseline: EmsTagFullScope, created: EmsTagFullScope) -> None:
        """Seal the same-dispatch delta before the original M4 becomes terminal."""
        try:
            with self._lock:
                now = self._writing_now()
                ack = self.inspect_original_ack()
                self._write(_BIRTH_ATTEMPT, {"context_digest": self._context,
                    "ack_custody_digest": ack.custody_digest, "attempted_at": now})
                if (type(baseline) is not EmsTagFullScope or baseline.digest != self._baseline
                        or not full_single_addition_matches(baseline, created, self._draft)):
                    raise ValueError
                detail = created._candidate(self._draft)
                record = self._record(_ACK, frozenset({"context_digest", "claim_digest", "acknowledgement_digest",
                                                      "selector_digest", "acknowledged_at"}))
                if record["selector_digest"] not in (self._mac("ack-selector-unavailable", b"none"),
                                                      self._mac("ack-selector", str(detail._id).encode())):
                    raise ValueError
                self._writing_now()
                self._write(_BIRTH, {"context_digest": self._context, "ack_custody_digest": ack.custody_digest,
                    "baseline_digest": baseline.digest, "created_scope_digest": created.digest,
                    "created_state_digest": detail.digest, "verified_at": now})
        except Exception:
            self._closed = True
            raise EmsTagCustodyError(_ERROR) from None

    def inspect_created_scope(self, *, require_verified_original: bool = True) -> EmsTagOriginalObservation:
        try:
            with self._lock:
                if type(require_verified_original) is not bool:
                    raise ValueError
                ack = self.inspect_original_ack()
                state = self._record(_BIRTH, frozenset({"context_digest", "ack_custody_digest", "baseline_digest",
                                                        "created_scope_digest", "created_state_digest", "verified_at"}))
                attempt = self._record(_BIRTH_ATTEMPT, frozenset({"context_digest", "ack_custody_digest", "attempted_at"}))
                original_ack = self._record(_ACK, frozenset({"context_digest", "claim_digest", "acknowledgement_digest",
                                                            "selector_digest", "acknowledged_at"}))
                if (attempt["ack_custody_digest"] != ack.custody_digest or state["ack_custody_digest"] != ack.custody_digest
                        or state["baseline_digest"] != self._baseline
                        or cast(int, attempt["attempted_at"]) < cast(int, original_ack["acknowledged_at"])
                        or cast(int, state["verified_at"]) < cast(int, attempt["attempted_at"])):
                    raise ValueError
                if require_verified_original:
                    result = self._claim().result
                    if (result is None or result.outcome != "succeeded" or result.verification != "verified"
                            or result.compensation != "not_requested"):
                        raise ValueError
                return EmsTagOriginalObservation(ack.context_digest, canonical_digest(state), ack.original_outcome,
                    ack.original_verification, cast(str, state["created_state_digest"]),
                    cast(str, state["created_scope_digest"]), ack.source_context_digest, self._actor_binding)
        except Exception:
            raise EmsTagCustodyError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
