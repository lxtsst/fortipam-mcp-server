"""Private original-dispatch custody for one prospective disabled Job POST.

This component has no HTTP client, authority issuer, Tool, or cleanup operation.
It reuses the existing M4 ledger; signed write-once records preserve original
ACK evidence without retaining response bytes, scripts, credentials or selectors.
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

from .job_definition_create_contract import DisabledJobCreateAckPins, consume_disabled_job_create_ack
from .job_definition_detail_reader import JobDefinitionDetailReader
from .ldap_server_runtime import _key, _private_directory, _read
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

ACTION_ID = "disabled-job-create"
ADAPTER_REF = "fortipam-700-build29-disabled-job-m4-v1"
_ERROR = "The private original Job acknowledgement is unavailable."
_DOMAIN = b"disabled-job-create-custody-build29/v1\x00"
_SEND = "send.claim.json"
_ACK = "create-ack.json"
_SOURCE_ABSENCE = "source-absence.json"
_STATE = "created-full-state.json"


class JobDefinitionAckCustodyError(RuntimeError):
    """A fixed non-disclosing refusal; no retry or recovery authority."""


@dataclass(frozen=True, slots=True, repr=False)
class JobDefinitionOriginalAckObservation(_OpaqueC3Object):
    """Read-only provenance evidence; original terminal status stays unchanged."""

    context_digest: str
    custody_digest: str
    original_outcome: str
    original_verification: str


@dataclass(frozen=True, slots=True, repr=False)
class JobDefinitionAcknowledgedPristineObservation(_OpaqueC3Object):
    """One original ACK joined to current state; never a cleanup authorization."""

    original_ack: JobDefinitionOriginalAckObservation
    state_digest: str


@dataclass(frozen=True, slots=True, repr=False)
class JobDefinitionOriginalStateObservation(_OpaqueC3Object):
    """Original dispatch's full-state seal; not independent recovery authority."""

    original_ack: JobDefinitionOriginalAckObservation
    custody_digest: str
    state_digest: str
    source_context_digest: str


class JobDefinitionAckCustody(_OpaqueC3Object):
    """Persist only within the original active M4; inspect without expiry renewal."""

    def __init__(self, directory: Path, witness_key_file: Path,
                 pins: DisabledJobCreateAckPins, plan: M4ExecutionPlan,
                 authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore,
                 *, clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(pins) is not DisabledJobCreateAckPins or type(plan) is not M4ExecutionPlan
                    or type(authorization) is not M4ExecutionAuthorization
                    or type(store) is not PersistentM4ExecutionStateStore
                    or store.monotonic_checkpoint_protocol_bound is not True
                    or clock is not None and not callable(clock)):
                raise ValueError
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            _private_directory(self._directory)
            info = self._directory.stat()
            self._directory_identity = (info.st_dev, info.st_ino)
            if self._key_file in (store._path, store._key_path,
                                  *(self._directory / name for name in (_SEND, _ACK, _SOURCE_ABSENCE, _STATE))):
                raise ValueError
            self._key = _key(self._key_file)
            if hmac.compare_digest(self._key, store._key):
                raise ValueError
            self._pins, self._plan, self._authorization, self._store = pins, plan, authorization, store
            self._context = pins.context_digest
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._last_now = -1
            self._begin_consumed = self._send_started = self._capture_consumed = self._closed = False
            self._source_begin_consumed = self._state_capture_consumed = False
            self._lock = RLock()
            self._validate()
        except Exception:
            raise JobDefinitionAckCustodyError(_ERROR) from None

    def _validate(self) -> None:
        p, a, pins = self._plan, self._authorization, self._pins
        p.__post_init__()
        a.__post_init__()
        if (pins.context_digest != self._context or pins.plan_digest != p.plan_digest
                or pins.authorization_digest != a.authorization_digest
                or p.action_id != ACTION_ID or p.action_version != "1.0.0"
                or p.adapter_ref != ADAPTER_REF or p.target_ref != "bound-disabled-job"
                or p.parameters_digest != pins.body_digest or p.compensation_ref is not None
                or p.requester_digest != pins.requester_digest
                or a.requester_digest != p.requester_digest or a.plan_ref != p.plan_ref
                or a.plan_digest != p.plan_digest or a.confirmation_digest != p.confirmation_digest
                or a.approval_digest != p.approval_digest
                or a.expires_at > p.expires_at):
            raise ValueError
        _private_directory(self._directory)
        info = self._directory.stat()
        if ((info.st_dev, info.st_ino) != self._directory_identity
                or not hmac.compare_digest(_key(self._key_file), self._key)):
            raise ValueError

    def _original_claim(self) -> M4Claim:
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
        return hmac.new(self._key, _DOMAIN + phase.encode("ascii") + b"\x00" + encoded,
                        hashlib.sha256).hexdigest()

    def _write(self, name: str, record: dict[str, object]) -> None:
        self._validate()
        payload = {**record, "signature": self._signature(name, record)}
        directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != self._directory_identity
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError
                json.dump(payload, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str, fields: frozenset[str]) -> dict[str, object]:
        from . import secret_bulk_import_metadata as metadata
        self._validate()
        raw = _read(self._directory / name, 4096)
        try:
            self._validate()
            start = _skip_json_space(raw, 0)
            end = _json_value_end(raw, start)
            if _skip_json_space(raw, end) != len(raw):
                raise ValueError
            metadata._validate_json(raw, start, end, depth=0, budget=[10_000])
            spans = _object_spans(raw, start, end)
            if set(spans) != fields | {"signature"}:
                raise ValueError
            record = {key: metadata._scalar(raw, spans[key]) for key in spans}
            signature = record.pop("signature")
            for key, value in record.items():
                if key.endswith("_at"):
                    if type(value) is not int or not self._authorization.issued_at <= value < self._authorization.expires_at:
                        raise ValueError
                else:
                    if type(value) is not str:
                        raise ValueError
                    require_digest(value, "job_ack_record")
            if (type(signature) is not str or record["context_digest"] != self._context
                    or not hmac.compare_digest(signature, self._signature(name, record))):
                raise ValueError
            return record
        finally:
            _zeroize_mutable(raw)

    def begin_original_send(self) -> None:
        """Reserve/fsync once before the producer's one POST; never send it here."""
        try:
            with self._lock:
                now = self._writing_now()
                if self._begin_consumed:
                    raise ValueError
                self._begin_consumed = True
                self._write(_SEND, {"context_digest": self._context, "claimed_at": now})
                self._send_started = True
        except Exception:
            self._closed = True
            raise JobDefinitionAckCustodyError(_ERROR) from None

    def capture_original_ack(self, raw: bytearray, *, http_status: int, content_type: str) -> None:
        """Consume the original response once, before post-read; failures remain consumed."""
        try:
            with self._lock:
                now = self._writing_now()
                if not self._send_started or self._capture_consumed:
                    raise ValueError
                self._capture_consumed = True
                claim = self._record(_SEND, frozenset({"context_digest", "claimed_at"}))
                if now < cast(int, claim["claimed_at"]):
                    raise ValueError
                ack = consume_disabled_job_create_ack(raw, pins=self._pins, http_status=http_status,
                    content_type=content_type, witness_key=self._key)
                self._writing_now()
                self._write(_ACK, {"context_digest": self._context, "claim_digest": canonical_digest(claim),
                    "acknowledgement_digest": ack.acknowledgement_digest, "acknowledged_at": now})
        except Exception:
            self._closed = True
            raise JobDefinitionAckCustodyError(_ERROR) from None
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)

    def _bound_source(self, sources: object) -> None:
        from .job_definition_sources import JobDefinitionSources
        if type(sources) is not JobDefinitionSources:
            raise ValueError
        binding = sources._candidate._bound_definition_digests()
        if (sources._candidate._name != self._pins.job_name or binding[:2] != (
                self._pins.body_digest, self._pins.serial_digest)
                or sources._body_digest != self._pins.body_digest
                or self._plan.expected_state_digest != canonical_digest({
                    "contract": "disabled-job-pristine-state-build29/v1", "body_digest": binding[0],
                    "serial_digest": binding[1], "timeout_digest": binding[2]})):
            raise ValueError

    def begin_original_send_from_sources(self, sources: object) -> None:
        """Seal actual fresh global absence, then reserve the original send once."""
        from dataclasses import asdict
        from .job_definition_sources import JobDefinitionSources
        from .target_preservation_contract import _digest
        try:
            with self._lock:
                now = self._writing_now()
                if self._source_begin_consumed or self._begin_consumed or type(sources) is not JobDefinitionSources:
                    raise ValueError
                self._source_begin_consumed = True
                self._bound_source(sources)
                observed = sources._current
                if observed is None:
                    raise ValueError
                sources.check_current(observed)
                if (not observed.absent or observed.state_digest is not None
                        or observed.current_digest != self._plan.expected_current_digest):
                    raise ValueError
                self._write(_SOURCE_ABSENCE, {"context_digest": self._context,
                    "source_context_digest": sources.source_context_digest,
                    "current_digest": observed.current_digest, "namespace_digest": observed.namespace_digest,
                    "observation_digest": _digest(asdict(observed)), "claimed_at": now})
                self.begin_original_send()
        except Exception:
            self._closed = True
            raise JobDefinitionAckCustodyError(_ERROR) from None

    def capture_original_full_state(self, sources: object) -> None:
        """Seal only the same actual source inside the original ACK dispatch."""
        from .job_definition_sources import JobDefinitionSources
        from .job_namespace_ssh_reader import CONTRACT as namespace_contract
        try:
            with self._lock:
                now = self._writing_now()
                if (not self._send_started or not self._capture_consumed or self._state_capture_consumed
                        or type(sources) is not JobDefinitionSources):
                    raise ValueError
                self._state_capture_consumed = True
                self._bound_source(sources)
                absence = self._record(_SOURCE_ABSENCE, frozenset({"context_digest", "source_context_digest",
                    "current_digest", "namespace_digest", "observation_digest", "claimed_at"}))
                ack = self.inspect_original_ack()
                observed = sources._current
                if observed is None:
                    raise ValueError
                sources.check_current(observed)
                if (observed.absent or observed.state_digest is None
                        or absence["source_context_digest"] != sources.source_context_digest
                        or absence["current_digest"] != self._plan.expected_current_digest
                        or sources._names.count(self._pins.job_name) != 1
                        or canonical_digest({"contract": namespace_contract,
                            "names": sorted(name for name in sources._names if name != self._pins.job_name)}) != absence["namespace_digest"]):
                    raise ValueError
                self._writing_now()
                self._write(_STATE, {"context_digest": self._context, "ack_custody_digest": ack.custody_digest,
                    "absence_digest": canonical_digest(absence), "source_context_digest": sources.source_context_digest,
                    "state_contract_digest": self._plan.expected_state_digest,
                    "state_digest": observed.state_digest, "verified_at": now})
        except Exception:
            self._closed = True
            raise JobDefinitionAckCustodyError(_ERROR) from None

    def inspect_original_full_state(self) -> JobDefinitionOriginalStateObservation:
        """Read stable original records after expiry without source IO or repair."""
        try:
            with self._lock:
                original = self.inspect_original_ack()
                absence = self._record(_SOURCE_ABSENCE, frozenset({"context_digest", "source_context_digest",
                    "current_digest", "namespace_digest", "observation_digest", "claimed_at"}))
                state = self._record(_STATE, frozenset({"context_digest", "ack_custody_digest", "absence_digest",
                    "source_context_digest", "state_contract_digest", "state_digest", "verified_at"}))
                ack = self._record(_ACK, frozenset({"context_digest", "claim_digest", "acknowledgement_digest", "acknowledged_at"}))
                if (state["ack_custody_digest"] != original.custody_digest
                        or state["absence_digest"] != canonical_digest(absence)
                        or state["state_contract_digest"] != self._plan.expected_state_digest
                        or absence["current_digest"] != self._plan.expected_current_digest
                        or state["source_context_digest"] != absence["source_context_digest"]
                        or not cast(int, absence["claimed_at"]) <= cast(int, ack["acknowledged_at"]) <= cast(int, state["verified_at"])):
                    raise ValueError
                return JobDefinitionOriginalStateObservation(original, canonical_digest(state),
                    cast(str, state["state_digest"]), cast(str, state["source_context_digest"]))
        except Exception:
            raise JobDefinitionAckCustodyError(_ERROR) from None

    def inspect_original_ack(self) -> JobDefinitionOriginalAckObservation:
        """Read exact custody and the original claim; never repair/promote its result."""
        try:
            with self._lock:
                original = self._original_claim()
                claim = self._record(_SEND, frozenset({"context_digest", "claimed_at"}))
                ack = self._record(_ACK, frozenset({"context_digest", "claim_digest",
                    "acknowledgement_digest", "acknowledged_at"}))
                if (ack["claim_digest"] != canonical_digest(claim)
                        or cast(int, ack["acknowledged_at"]) < cast(int, claim["claimed_at"])):
                    raise ValueError
                return JobDefinitionOriginalAckObservation(self._context, canonical_digest(ack),
                    str(original.result.outcome) if original.result is not None else "in_progress",
                    str(original.result.verification) if original.result is not None else "unknown")
        except Exception:
            raise JobDefinitionAckCustodyError(_ERROR) from None

    def inspect_acknowledged_pristine(self, reader: JobDefinitionDetailReader
                                     ) -> JobDefinitionAcknowledgedPristineObservation:
        """Join exact original custody and a fresh full/pristine read, without writes.

        The original plan must bind the complete expected body/device/timeout
        state. Matching a different existing Job, changing expected defaults,
        or changing ACK/ledger context across the read cannot qualify this join.
        Original UNKNOWN/IN_PROGRESS remains unchanged; a separate authorized
        recovery still requires its own exact action and fixed absence readback.
        """
        try:
            with self._lock:
                if type(reader) is not JobDefinitionDetailReader:
                    raise ValueError
                before = self.inspect_original_ack()
                binding = reader._bound_definition_digests()
                if (reader._name != self._pins.job_name
                        or binding[:2] != (self._pins.body_digest, self._pins.serial_digest)):
                    raise ValueError
                expected = canonical_digest({"contract": "disabled-job-pristine-state-build29/v1",
                    "body_digest": binding[0], "serial_digest": binding[1], "timeout_digest": binding[2]})
                if expected != self._plan.expected_state_digest:
                    raise ValueError
                state = reader.read_pristine()
                if (state.verified is not True or reader._bound_definition_digests() != binding
                        or self.inspect_original_ack() != before):
                    raise ValueError
                return JobDefinitionAcknowledgedPristineObservation(before, expected)
        except Exception:
            raise JobDefinitionAckCustodyError(_ERROR) from None
