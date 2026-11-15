"""Original-response custody for a prospective build-29 reset fixture.

No HTTP, issuer, User adoption, reset or recovery operation is exposed. A future
producer must supply real fresh C/P/E and the actual original response inside
M4 dispatch. This component alone does not qualify complete fixture provenance.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
from threading import RLock
import time
from typing import Any, TYPE_CHECKING

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import M4Claim, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from . import secret_bulk_import_metadata as metadata
from .ldap_server_runtime import _key, _private_directory, _read
from .local_user_reset_fixture_create import _fixture_envelope
from .local_user_reset_http_transport import _NAME
from .local_user_reset_fixture_state import LocalResetFixtureStateReader
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

if TYPE_CHECKING:
    from .local_user_reset_fixture_sources import LocalResetFixtureSources

ACTION_ID = "local-reset-fixture-create"
ADAPTER_REF = "fortipam-build29-local-reset-fixture-m4-v2"
ACTION_VERSION = "2.0.0"
_ERROR = "The private original reset-fixture acknowledgement is unavailable."
_DOMAIN = b"local-reset-fixture-original-custody/v2\x00"
_SEND, _ACK, _STATE = "original-send.json", "original-ack.json", "original-full-state.json"
_ABSENCE = "original-absence.json"


def initial_create_parameters_digest(body_digest: str, material_ref: str) -> str:
    require_digest(body_digest, "fixture_body")
    require_ref(material_ref, "initial_material")
    return canonical_digest(dict(contract="local-reset-fixture-create-parameters/v2",
        body_digest=body_digest, initial_material_ref=material_ref))


@dataclass(frozen=True, slots=True, repr=False)
class LocalResetFixtureAckPins(_OpaqueC3Object):
    username: str
    serial_digest: str
    requester_digest: str
    actor_context_digest: str
    preflight_digest: str
    body_digest: str
    material_ref: str
    plan_digest: str
    authorization_digest: str
    private_nonce: str

    def __post_init__(self) -> None:
        if type(self.username) is not str or len(self.username) > 64 or _NAME.fullmatch(self.username) is None:
            raise ValueError(_ERROR)
        for name, value in asdict(self).items():
            if name == "material_ref": require_ref(value, "initial_material")
            elif name != "username": require_digest(value, "reset_fixture_pin")

    @property
    def request_digest(self) -> str:
        return initial_create_parameters_digest(self.body_digest, self.material_ref)

    @property
    def context_digest(self) -> str:
        self.__post_init__()
        return canonical_digest({"contract": "build29-local-reset-original-ack/v2", **asdict(self)})


@dataclass(frozen=True, slots=True, repr=False)
class LocalResetFixtureOriginalAck(_OpaqueC3Object):
    context_digest: str
    custody_digest: str
    original_outcome: str
    original_verification: str


@dataclass(frozen=True, slots=True, repr=False)
class LocalResetFixtureOriginalState(_OpaqueC3Object):
    original_ack: LocalResetFixtureOriginalAck
    custody_digest: str
    source_context_digest: str
    state_digest: str
    nonmaterial_state_digest: str
    definition_digest: str
    user_id: int


@dataclass(frozen=True, slots=True, repr=False)
class LocalResetFixtureOriginalAbsence(_OpaqueC3Object):
    custody_digest: str
    source_context_digest: str
    state_source_digest: str
    before_namespace_digest: str
    presence_namespace_digest: str
    admin_count: int
    api_user_count: int


class LocalResetFixtureAckCustody(_OpaqueC3Object):
    """One original send/ACK with a persisted execution packet and separate key."""

    def __init__(self, *, directory: Path, packet_file: Path, witness_key_file: Path,
            plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore, expected_vdom: str,
            execution_enabled: bool = False, clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                    or type(store) is not PersistentM4ExecutionStateStore
                    or store.monotonic_checkpoint_protocol_bound is not True
                    or type(execution_enabled) is not bool or clock is not None and not callable(clock)
                    or type(expected_vdom) is not str or expected_vdom != "root"):
                raise ValueError
            self._directory, self._packet_file, self._key_file = Path(directory), Path(packet_file), Path(witness_key_file)
            _private_directory(self._directory)
            info = self._directory.stat(); self._identity = (info.st_dev, info.st_ino)
            paths = (self._packet_file, self._key_file, store._path, store._key_path,
                self._directory / _SEND, self._directory / _ACK, self._directory / _STATE, self._directory / _ABSENCE)
            if len(set(paths)) != len(paths): raise ValueError
            self._plan, self._authorization, self._store = plan, authorization, store
            self._pins, self._packet_digest = self._load_packet()
            self._key = _key(self._key_file)
            if hmac.compare_digest(self._key, store._key): raise ValueError
            self._context, self._vdom = self._pins.context_digest, expected_vdom
            self._enabled, self._closed = execution_enabled, False
            self._send_consumed = self._send_started = self._capture_consumed = False
            self._state_capture_consumed = False
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._last = -1
            self._lock = RLock()
            self._validate()
            if execution_enabled:
                if store.claim_count != 0: raise ValueError
                self._durable_packet()
        except Exception:
            raise ValueError(_ERROR) from None

    def _load_packet(self) -> tuple[LocalResetFixtureAckPins, str]:
        _private_directory(self._packet_file.parent)
        raw = _read(self._packet_file, 8192)
        try:
            left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
            if _skip_json_space(raw, right) != len(raw): raise ValueError
            metadata._validate_json(raw, left, right, depth=0, budget=[10000])
            packet = _object_spans(raw, left, right)
            if set(packet) != {"pins", "plan", "authorization", "vdom"} or metadata._scalar(raw, packet["vdom"]) != "root":
                raise ValueError
            for label, expected in (("plan", self._plan), ("authorization", self._authorization)):
                fields = _object_spans(raw, *packet[label])
                if set(fields) != set(expected.__dataclass_fields__): raise ValueError
                values = {key: metadata._scalar(raw, span) for key, span in fields.items()}
                actual = asdict(expected)
                if any(type(values[key]) is not type(actual[key]) or values[key] != actual[key] for key in fields):
                    raise ValueError
            fields = _object_spans(raw, *packet["pins"])
            if set(fields) != set(LocalResetFixtureAckPins.__dataclass_fields__): raise ValueError
            values = {key: metadata._scalar(raw, span) for key, span in fields.items()}
            if any(type(value) is not str for value in values.values()): raise ValueError
            pins = LocalResetFixtureAckPins(**{key: str(value) for key, value in values.items()})
            return pins, hashlib.sha256(raw).hexdigest()
        finally:
            _zeroize_mutable(raw)

    def _durable_packet(self) -> None:
        directory = os.open(self._packet_file.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(self._packet_file.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1): raise ValueError
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
        finally:
            os.close(directory)
        self._validate()

    def _validate(self) -> None:
        _private_directory(self._directory)
        info = self._directory.stat()
        pins, digest = self._load_packet()
        p, a = self._plan, self._authorization
        p.__post_init__(); a.__post_init__()
        if ((info.st_dev, info.st_ino) != self._identity or digest != self._packet_digest or pins != self._pins
                or not hmac.compare_digest(_key(self._key_file), self._key)
                or not hmac.compare_digest(_key(self._store._key_path), self._store._key)
                or p.action_id != ACTION_ID or p.adapter_ref != ADAPTER_REF or p.action_version != ACTION_VERSION
                or p.target_ref != "bound-local-reset-fixture" or p.compensation_ref is not None
                or p.parameters_digest != pins.request_digest or p.expected_current_digest != pins.preflight_digest
                or p.requester_digest != pins.requester_digest or p.plan_digest != pins.plan_digest
                or a.authorization_digest != pins.authorization_digest or a.plan_digest != p.plan_digest
                or a.plan_ref != p.plan_ref or a.requester_digest != p.requester_digest
                or a.confirmation_digest != p.confirmation_digest or a.approval_digest != p.approval_digest
                or a.expires_at > p.expires_at):
            raise ValueError

    def _claim(self) -> M4Claim:
        self._validate()
        p, a = self._plan, self._authorization
        return self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest({"plan_digest": p.plan_digest,
                "authorization_digest": a.authorization_digest, "revision": p.revision}))

    def _writing_now(self) -> int:
        if not self._enabled or self._closed: raise ValueError
        _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        if self._claim().result is not None: raise ValueError
        now = self._clock()
        if (type(now) is not int or now < self._last
                or not self._authorization.issued_at <= now < self._authorization.expires_at):
            raise ValueError
        self._last = now
        return now

    def _signature(self, name: str, record: dict[str, Any]) -> str:
        return hmac.new(self._key, _DOMAIN + name.encode() + b"\x00" +
            json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()

    def _write(self, name: str, record: dict[str, Any]) -> None:
        self._validate()
        directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != self._identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700): raise ValueError
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "w") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                    raise ValueError
                json.dump({**record, "signature": self._signature(name, record)}, stream,
                    sort_keys=True, separators=(",", ":"), allow_nan=False)
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str, keys: frozenset[str]) -> dict[str, Any]:
        self._validate()
        raw = _read(self._directory / name, 8192)
        try:
            left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
            if _skip_json_space(raw, right) != len(raw): raise ValueError
            metadata._validate_json(raw, left, right, depth=0, budget=[10000])
            spans = _object_spans(raw, left, right)
            if set(spans) != keys | {"signature"}: raise ValueError
            record = {key: metadata._scalar(raw, span) for key, span in spans.items()}
            signature = record.pop("signature")
            if (record["context_digest"] != self._context or type(signature) is not str
                    or not hmac.compare_digest(signature, self._signature(name, record))): raise ValueError
            return record
        finally:
            _zeroize_mutable(raw)

    def capture_original_absence(self, sources: LocalResetFixtureSources) -> None:
        """Seal the actual global baseline only in this original dispatch."""
        from .local_user_reset_fixture_sources import LocalResetFixtureSources, _NAMESPACE_CONTRACT
        try:
            with self._lock:
                now = self._writing_now()
                observed = sources._current
                if (type(sources) is not LocalResetFixtureSources or self._send_consumed
                        or observed is None or not observed.absent or observed.admin_count >= 128
                        or observed.current_digest != self._pins.preflight_digest
                        or sources._state._draft.nonmaterial_request_digest != self._pins.body_digest
                        or sources._state._draft.username != self._pins.username
                        or sources._state._serial != self._pins.serial_digest
                        or sources._state._actor != self._pins.actor_context_digest): raise ValueError
                sources.check_current(observed)
                presence = canonical_digest(dict(contract=_NAMESPACE_CONTRACT,
                    admin_names=sorted((*sources._admin_names,self._pins.username)),api_names=sorted(sources._api_names)))
                self._write(_ABSENCE,dict(context_digest=self._context,source_context_digest=sources.source_context_digest,
                    state_source_digest=sources._state._context(),before_namespace_digest=observed.namespace_digest,
                    presence_namespace_digest=presence,admin_count=observed.admin_count,api_user_count=observed.api_user_count,
                    captured_at=now))
                self._writing_now()
        except Exception:
            self.close();raise ValueError(_ERROR) from None

    def inspect_original_absence(self) -> LocalResetFixtureOriginalAbsence:
        try:
            with self._lock:
                record=self._record(_ABSENCE,frozenset({"context_digest","source_context_digest","state_source_digest",
                    "before_namespace_digest","presence_namespace_digest","admin_count","api_user_count","captured_at"}))
                for name in ("source_context_digest","state_source_digest","before_namespace_digest","presence_namespace_digest"):
                    require_digest(record[name],"original_absence")
                if (any(type(record[name]) is not int or not 1 <= record[name] <= 128 for name in ("admin_count","api_user_count"))
                        or type(record["captured_at"]) is not int
                        or not self._authorization.issued_at <= record["captured_at"] < self._authorization.expires_at): raise ValueError
                return LocalResetFixtureOriginalAbsence(canonical_digest(record),record["source_context_digest"],
                    record["state_source_digest"],record["before_namespace_digest"],record["presence_namespace_digest"],
                    record["admin_count"],record["api_user_count"])
        except Exception:raise ValueError(_ERROR) from None

    def begin_original_send(self) -> None:
        try:
            with self._lock:
                if self._send_consumed: raise ValueError
                self._send_consumed = True
                now = self._writing_now()
                if any(os.path.lexists(self._directory / name) for name in (_SEND, _ACK, _STATE)): raise ValueError
                self._write(_SEND, dict(context_digest=self._context, packet_file_digest=self._packet_digest,
                    current_digest=self._pins.preflight_digest, claimed_at=now))
                self._writing_now(); self._send_started = True
        except Exception:
            self.close()
            raise ValueError(_ERROR) from None

    def capture_original_ack(self, raw: bytearray, *, http_status: int, content_type: str) -> None:
        try:
            with self._lock:
                if not self._send_started or self._capture_consumed: raise ValueError
                self._capture_consumed = True
                now = self._writing_now()
                if (type(raw) is not bytearray or not 0 < len(raw) <= 16384
                        or type(http_status) is not int or http_status != 200 or type(content_type) is not str
                        or len(content_type) > 128 or content_type.split(";", 1)[0].strip().lower() != "application/json"):
                    raise ValueError
                root = _fixture_envelope(raw, method="POST", expected_name=self._pins.username, expected_vdom=self._vdom)
                if {"results", "action"} & root.keys(): raise ValueError
                serial = metadata._scalar(raw, root["serial"])
                if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != self._pins.serial_digest:
                    raise ValueError
                digest = hmac.new(self._key, _DOMAIN + b"original-response\x00" + self._context.encode() + b"\x00", hashlib.sha256)
                digest.update(raw)
                claim = self._record(_SEND, frozenset({"context_digest", "packet_file_digest", "current_digest", "claimed_at"}))
                self._writing_now()
                self._write(_ACK, dict(context_digest=self._context, claim_digest=canonical_digest(claim),
                    acknowledgement_digest=digest.hexdigest(), acknowledged_at=now))
                self._writing_now()
        except Exception:
            self.close()
            raise ValueError(_ERROR) from None
        finally:
            if type(raw) is bytearray: _zeroize_mutable(raw)

    def inspect_original_ack(self) -> LocalResetFixtureOriginalAck:
        """No product reads, expiry renewal, receipt repair or UNKNOWN promotion."""
        try:
            with self._lock:
                claim = self._claim()
                send = self._record(_SEND, frozenset({"context_digest", "packet_file_digest", "current_digest", "claimed_at"}))
                ack = self._record(_ACK, frozenset({"context_digest", "claim_digest", "acknowledgement_digest", "acknowledged_at"}))
                if (send["packet_file_digest"] != self._packet_digest or send["current_digest"] != self._plan.expected_current_digest
                        or ack["claim_digest"] != canonical_digest(send)
                        or type(send["claimed_at"]) is not int or type(ack["acknowledged_at"]) is not int
                        or not self._authorization.issued_at <= send["claimed_at"] <= ack["acknowledged_at"] < self._authorization.expires_at):
                    raise ValueError
                require_digest(ack["acknowledgement_digest"], "original_ack")
                result = claim.result
                return LocalResetFixtureOriginalAck(self._context, canonical_digest(ack),
                    "in_progress" if result is None else str(result.outcome),
                    "unknown" if result is None else str(result.verification))
        except Exception:
            raise ValueError(_ERROR) from None

    def capture_original_full_state(self, source: LocalResetFixtureStateReader) -> None:
        """Only the original active dispatch may join its ACK to this fixed read."""
        try:
            with self._lock:
                if (not self._send_started or not self._capture_consumed or self._state_capture_consumed
                        or type(source) is not LocalResetFixtureStateReader): raise ValueError
                self._state_capture_consumed = True
                self._writing_now()
                if (source._draft.username != self._pins.username or source._serial != self._pins.serial_digest
                        or source._actor != self._pins.actor_context_digest
                        or source._draft.nonmaterial_request_digest != self._pins.body_digest): raise ValueError
                original = self.inspect_original_ack()
                observed = source.read_created(); source.check_current(observed)
                now = self._writing_now()
                self._write(_STATE, dict(context_digest=self._context, ack_custody_digest=original.custody_digest,
                    source_context_digest=observed.source_context_digest, state_digest=observed.state_digest,
                    nonmaterial_state_digest=observed.nonmaterial_state_digest, definition_digest=observed.definition_digest,
                    user_id=observed.user_id, state_contract_digest=self._plan.expected_state_digest, verified_at=now))
                self._writing_now()
        except Exception:
            self.close()
            raise ValueError(_ERROR) from None

    def inspect_original_full_state(self) -> LocalResetFixtureOriginalState:
        """Return original full custody without a new source read or authority."""
        try:
            with self._lock:
                original = self.inspect_original_ack()
                ack = self._record(_ACK, frozenset({"context_digest", "claim_digest", "acknowledgement_digest", "acknowledged_at"}))
                state = self._record(_STATE, frozenset({"context_digest", "ack_custody_digest", "source_context_digest",
                    "state_digest", "nonmaterial_state_digest", "definition_digest", "user_id", "state_contract_digest", "verified_at"}))
                if (state["ack_custody_digest"] != original.custody_digest
                        or state["state_contract_digest"] != self._plan.expected_state_digest
                        or type(state["user_id"]) is not int or state["user_id"] <= 0
                        or type(state["verified_at"]) is not int
                        or not ack["acknowledged_at"] <= state["verified_at"] < self._authorization.expires_at): raise ValueError
                for name in ("source_context_digest", "state_digest", "nonmaterial_state_digest", "definition_digest"):
                    require_digest(state[name], "original_fixture_state")
                return LocalResetFixtureOriginalState(original, canonical_digest(state), state["source_context_digest"],
                    state["state_digest"], state["nonmaterial_state_digest"], state["definition_digest"], state["user_id"])
        except Exception:
            raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled, self._closed = False, True
