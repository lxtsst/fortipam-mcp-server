"""Inactive original-ACK/full-state recovery inspection, never delete authority.

Both full observations are produced here, not imported from opaque witnesses.
Durable reader phases prevent restart adoption/replay; baseline custody is kept
in this process only. The explicit retained-cleanup mode authenticates a sealed
independent reconciliation, then uses distinct fresh reader phases. It cannot
enter Instruction transitions or replay ordinary/source recovery. Separately
authorized fixed DELETE/ACK/absence remains required, with no default wiring.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import math
import re
from threading import RLock
import time

import httpx

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from .secret_instruction_build29_api_preservation import SecretInstructionBuild29ApiPreservationWitness
from .web_secret_fixture_api_preservation_reader import WebSecretFixtureApiPreservationReader
from .web_secret_fixture_creation_record import WebSecretFixtureCreationRecord
from .web_secret_fixture_reconciled_source import WebSecretFixtureReconciledSource

_ERROR = "The private Web fixture recovery inspection is unavailable."
_TTL = 60


class WebSecretFixtureRecoveryGuardError(ValueError):
    """Categorical refusal with no source, identity or material values."""


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretFixtureRecoveryInspection(_OpaqueC3Object):
    """Private same-instance eligibility evidence, never an execution grant."""

    creation_digest: str
    source_digest: str
    current_digest: str
    expected_absence_digest: str
    checked_at: int
    expires_at: int
    _display_name = "WebSecretFixtureRecoveryInspection"


class WebSecretFixtureRecoveryGuard(_OpaqueC3Object):
    """Join original creation custody to baseline and recovery observations.

    Each observation uses the existing seven-request producer and original key.
    Complete row bytes and independent Password/TOTP evidence must match, with
    the original empty Instruction reference explicitly required in both phases.
    Inspection freshness begins before the recovery read. Repeated, failed or
    restarted observations cannot adopt an earlier witness or repeat a phase.
    """
    _display_name = "WebSecretFixtureRecoveryGuard"

    def __init__(self, record: WebSecretFixtureCreationRecord, *,
            credential_envelope: Mapping[str, str | int], totp_envelope: Mapping[str, str | int],
            source_observer: WebSecretFixtureApiPreservationReader | None = None,
            reconciled_source: WebSecretFixtureReconciledSource | None = None,
            client_factory: Callable[..., httpx.Client] = httpx.Client,
            http_clock: Callable[[], float] = time.monotonic,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if type(record) is not WebSecretFixtureCreationRecord:
                raise ValueError
            timeout = record._config.timeout_seconds
            if (type(timeout) not in (int, float) or not math.isfinite(timeout) or not 1 <= timeout <= 60
                    or not callable(client_factory) or not callable(http_clock) or not callable(clock)):
                raise ValueError
            self._record = record
            self._original = record.read_acknowledged_creation()
            self._reconciled_source = reconciled_source
            capture = record._ack_capture
            if (capture is None
                    or reconciled_source is None and capture.observe_source != (source_observer is not None)
                    or reconciled_source is not None and source_observer is not None):
                raise ValueError
            self._source_observer = source_observer
            self._source_witness: SecretInstructionBuild29ApiPreservationWitness | None = None
            if source_observer is not None:
                if (type(source_observer) is not WebSecretFixtureApiPreservationReader
                        or source_observer._phase != "source"
                        or source_observer._record is not record or source_observer._config != record._config
                        or source_observer._factory is not client_factory or source_observer._clock is not http_clock
                        or source_observer.observed_envelopes() != (dict(credential_envelope), dict(totp_envelope))):
                    raise ValueError
                self._checked_witness(source_observer._source_result)
                self._source_witness = source_observer._source_result
            if reconciled_source is not None:
                if (type(reconciled_source) is not WebSecretFixtureReconciledSource
                        or reconciled_source._record is not record):
                    raise ValueError
                reconciled_source._guard()
                values = reconciled_source._value
                if ((values["credential"], values["totp"]) != (dict(credential_envelope), dict(totp_envelope))
                        or values["completed_at"] > clock()):
                    raise ValueError
                self._source_witness = SecretInstructionBuild29ApiPreservationWitness(values["preservation_digest"])
            self._config = record._config
            self._factory, self._http_clock, self._clock = client_factory, http_clock, clock
            self._last_clock: int | None = None
            self._clock_failed = False
            self._baseline = WebSecretFixtureApiPreservationReader(record, instruction_profile_name="",
                credential_envelope=credential_envelope, totp_envelope=totp_envelope,
                phase="reconciled-cleanup-baseline" if reconciled_source is not None else "baseline",
                client_factory=client_factory, clock=http_clock)
            self._recovery = WebSecretFixtureApiPreservationReader(record, instruction_profile_name="",
                credential_envelope=credential_envelope, totp_envelope=totp_envelope,
                phase="reconciled-cleanup-current" if reconciled_source is not None else "recovery",
                client_factory=client_factory, clock=http_clock)
            self._dispatch = WebSecretFixtureApiPreservationReader(record, instruction_profile_name="",
                credential_envelope=credential_envelope, totp_envelope=totp_envelope,
                phase="reconciled-cleanup-dispatch" if reconciled_source is not None else "recovery-dispatch",
                client_factory=client_factory, clock=http_clock)
            self._applied: WebSecretFixtureApiPreservationReader | None = None
            self._restored: WebSecretFixtureApiPreservationReader | None = None
            self._transition_reference: str | None = None
            self._transition_source: str | None = None
            self._source = self._source_digest()
            self._state = "new"
            self._witness: SecretInstructionBuild29ApiPreservationWitness | None = None
            self._inspection: WebSecretFixtureRecoveryInspection | None = None
            self._inspection_clock: tuple[int, int] | None = None
            self._lock = RLock()
            self._guard()
        except Exception:
            raise WebSecretFixtureRecoveryGuardError(_ERROR) from None

    def _now(self) -> int:
        try:
            value = self._clock()
            if (self._clock_failed or type(value) is not int or value < 0
                    or self._last_clock is not None and value < self._last_clock):
                raise ValueError
            self._last_clock = value
            return value
        except Exception:
            self._clock_failed = True
            raise ValueError from None

    def _source_digest(self) -> str:
        reconciled = self._reconciled_source
        if reconciled is not None:
            if (type(reconciled) is not WebSecretFixtureReconciledSource or reconciled._record is not self._record
                    or self._source_observer is not None or self._source_witness is None):
                raise ValueError
            reconciled._guard()
            if (reconciled._value["preservation_digest"] != self._source_witness.preservation_digest
                    or (reconciled._value["credential"], reconciled._value["totp"]) !=
                       (self._baseline._credential_envelope, self._baseline._totp_envelope)):
                raise ValueError
        if self._source_observer is not None:
            observer = self._source_observer
            if (observer._phase != "source" or observer._record is not self._record or observer._config != self._config
                    or observer._factory is not self._factory or observer._clock is not self._http_clock
                    or observer._source_result is not self._source_witness
                    or observer.observed_envelopes() != (
                        self._baseline._credential_envelope, self._baseline._totp_envelope)):
                raise ValueError
        phases = (("reconciled-cleanup-baseline", "reconciled-cleanup-current", "reconciled-cleanup-dispatch")
                  if reconciled is not None else ("baseline", "recovery", "recovery-dispatch"))
        for reader, phase in zip((self._baseline, self._recovery, self._dispatch), phases, strict=True):
            if (type(reader) is not WebSecretFixtureApiPreservationReader or reader._record is not self._record
                    or reader._original != self._original.creation or reader._config != self._config
                    or reader._phase != phase or reader._reference != ""
                    or reader._factory is not self._factory or reader._clock is not self._http_clock):
                raise ValueError
        if (self._baseline._credential_envelope != self._recovery._credential_envelope
                or self._baseline._totp_envelope != self._recovery._totp_envelope
                or self._baseline._credential_envelope != self._dispatch._credential_envelope
                or self._baseline._totp_envelope != self._dispatch._totp_envelope):
            raise ValueError
        values = {"contract": "web-fixture-reconciled-cleanup-source/v1" if reconciled is not None else
            "web-fixture-recovery-source/v1", "namespace": self._record._namespace,
            "origin": self._config.base_url, "bearer": hashlib.sha256(self._config.bearer_token.encode()).hexdigest(),
            "ack_source": self._record._ack_source, "password": self._baseline._credential_envelope,
            "totp": self._baseline._totp_envelope}
        if self._source_observer is not None:
            if self._source_witness is None:
                raise ValueError
            values["observed_source"] = self._source_witness.preservation_digest
        if reconciled is not None:
            if self._source_witness is None:
                raise ValueError
            values["reconciliation_capsule"] = reconciled._digest
            values["observed_source"] = self._source_witness.preservation_digest
        return canonical_digest(values)

    def _guard(self) -> None:
        self._now()
        if (self._record._config != self._config or self._record._transport._config != self._config
                or self._record.read_acknowledged_creation() != self._original
                or self._source_digest() != self._source
                or self._transition_digest() != self._transition_source):
            raise ValueError
        for reader in (self._baseline, self._recovery, self._dispatch, self._applied, self._restored):
            if reader is None:
                continue
            if reader._started:
                if reader._attempt_identity is None:
                    raise ValueError
                reader._check_attempt()
        self._now()

    def _transition_digest(self) -> str | None:
        if (self._applied is None and self._restored is None
                and self._transition_reference is None):
            return None
        if not self._transition_reference or self._applied is None or self._restored is None:
            raise ValueError
        for reader, phase, reference in ((self._applied, "applied", self._transition_reference),
                                         (self._restored, "restored", "")):
            if (type(reader) is not WebSecretFixtureApiPreservationReader
                    or reader._record is not self._record or reader._original != self._original.creation
                    or reader._config != self._config or reader._phase != phase or reader._reference != reference
                    or reader._factory is not self._factory or reader._clock is not self._http_clock
                    or reader._credential_envelope != self._baseline._credential_envelope
                    or reader._totp_envelope != self._baseline._totp_envelope):
                raise ValueError
        return canonical_digest({"contract": "web-fixture-instruction-preservation/v1",
            "source": self._source, "reference": self._transition_reference})

    def bind_instruction_profile(self, reference: str) -> None:
        """Constrain later reads to one name; this grants no Profile/write rights."""
        with self._lock:
            try:
                if (self._reconciled_source is not None or self._state != "baseline"
                        or self._witness is None or self._transition_source is not None):
                    raise ValueError
                self._guard()
                applied = WebSecretFixtureApiPreservationReader(self._record, instruction_profile_name=reference,
                    credential_envelope=self._baseline._credential_envelope, totp_envelope=self._baseline._totp_envelope,
                    phase="applied", client_factory=self._factory, clock=self._http_clock)
                restored = WebSecretFixtureApiPreservationReader(self._record, instruction_profile_name="",
                    credential_envelope=self._baseline._credential_envelope, totp_envelope=self._baseline._totp_envelope,
                    phase="restored", client_factory=self._factory, clock=self._http_clock)
                self._applied, self._restored, self._transition_reference = applied, restored, reference
                self._transition_source = self._transition_digest()
                self._guard()
            except Exception:
                raise WebSecretFixtureRecoveryGuardError(_ERROR) from None

    def check_instruction_applied_once(self) -> None:
        """Compare the actual applied frame and independent material to baseline."""
        self._check_instruction_phase_once(restored=False)

    def check_instruction_restored_once(self) -> None:
        """Require original empty reference and complete baseline before recovery."""
        self._check_instruction_phase_once(restored=True)

    def _check_instruction_phase_once(self, *, restored: bool) -> None:
        with self._lock:
            reader = self._restored if restored else self._applied
            expected_state = "applied" if restored else "baseline"
            if self._state != expected_state or reader is None or reader._started or self._witness is None:
                raise WebSecretFixtureRecoveryGuardError(_ERROR) from None
            self._state = "restored-reading" if restored else "applied-reading"
            try:
                self._guard()
                witness = reader.read_once()
                self._checked_witness(witness)
                if not hmac.compare_digest(witness.preservation_digest, self._witness.preservation_digest):
                    raise ValueError
                self._guard()
                self._state = "baseline" if restored else "applied"
            except Exception:
                self._state, self._witness, self._inspection = "failed", None, None
                raise WebSecretFixtureRecoveryGuardError(_ERROR) from None

    @staticmethod
    def _checked_witness(witness: SecretInstructionBuild29ApiPreservationWitness | None) -> None:
        if (type(witness) is not SecretInstructionBuild29ApiPreservationWitness
                or type(witness.preservation_digest) is not str
                or re.fullmatch(r"[a-f0-9]{64}", witness.preservation_digest) is None):
            raise ValueError

    def capture_baseline_once(self) -> None:
        """Capture privately from the actual fixed producer; never import a digest."""
        with self._lock:
            try:
                if self._state != "new":
                    raise ValueError
                self._state = "baseline-reading"
                self._guard()
                witness = self._baseline.read_once()
                self._checked_witness(witness)
                if (self._source_witness is not None and not hmac.compare_digest(
                        witness.preservation_digest, self._source_witness.preservation_digest)):
                    raise ValueError
                self._guard()
                self._witness, self._state = witness, "baseline"
            except Exception:
                self._state, self._witness, self._inspection = "failed", None, None
                raise WebSecretFixtureRecoveryGuardError(_ERROR) from None

    def inspect_recovery_once(self) -> WebSecretFixtureRecoveryInspection:
        """Require complete baseline equality; no write or permission is issued."""
        with self._lock:
            try:
                if self._state != "baseline" or self._witness is None:
                    raise ValueError
                self._state = "recovery-reading"
                self._guard()
                started = self._now()
                witness = self._recovery.read_once()
                self._checked_witness(witness)
                if not hmac.compare_digest(witness.preservation_digest, self._witness.preservation_digest):
                    raise ValueError
                self._guard()
                checked = self._now()
                if checked >= started + _TTL:
                    raise ValueError
                inspection = self._inspection_value(checked, started + _TTL)
                self._inspection_clock = checked, started + _TTL
                self._inspection, self._state = inspection, "ready"
                return inspection
            except Exception:
                self._state, self._witness, self._inspection = "failed", None, None
                raise WebSecretFixtureRecoveryGuardError(_ERROR) from None

    def _inspection_value(self, checked: int, expires: int) -> WebSecretFixtureRecoveryInspection:
        if self._witness is None:
            raise ValueError
        self._checked_witness(self._witness)
        creation = self._original.creation.creation_digest
        current = canonical_digest({"creation": creation, "source": self._source,
            "preservation": self._witness.preservation_digest, "instruction_empty": True})
        expected = canonical_digest({"creation": creation, "source": self._source,
            "ack": self._original.acknowledgement.acknowledgement_digest,
            "state": "actor-visible-absence-required-v1"})
        return WebSecretFixtureRecoveryInspection(creation, self._source, current, expected, checked, expires)

    def check_current(self, inspection: WebSecretFixtureRecoveryInspection) -> None:
        """Check local custody/freshness only; this does not reread device state."""
        with self._lock:
            try:
                if (self._state != "ready" or type(inspection) is not WebSecretFixtureRecoveryInspection
                        or inspection is not self._inspection or self._inspection_clock is None
                        or (inspection.checked_at, inspection.expires_at) != self._inspection_clock
                        or inspection != self._inspection_value(*self._inspection_clock)):
                    raise ValueError
                self._guard()
                if not inspection.checked_at <= self._now() < inspection.expires_at:
                    raise ValueError
            except Exception:
                self._state, self._witness, self._inspection = "failed", None, None
                raise WebSecretFixtureRecoveryGuardError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._state, self._witness, self._inspection = "closed", None, None

    def check_pre_dispatch_once(self, inspection: WebSecretFixtureRecoveryInspection, *,
                                http_deadline: float | None = None) -> None:
        """Perform one fresh complete read after the DELETE TLS connection opens."""
        with self._lock:
            try:
                self.check_current(inspection)
                if self._dispatch._started or self._witness is None:
                    raise ValueError
                witness = self._dispatch.read_once(max_deadline=http_deadline)
                self._checked_witness(witness)
                if not hmac.compare_digest(witness.preservation_digest, self._witness.preservation_digest):
                    raise ValueError
                self.check_current(inspection)
            except Exception:
                self._state, self._witness, self._inspection = "failed", None, None
                raise WebSecretFixtureRecoveryGuardError(_ERROR) from None
