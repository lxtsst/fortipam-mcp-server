"""Principal-scoped immutable diagnostic baselines with local audit integrity.

This module is intentionally local-only.  It persists only already-validated
C1/C2 projection envelopes and never provides enumeration, update, deletion,
or export operations.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from types import MappingProxyType
from typing import Callable, Final

from .baseline_drift import (
    BaselineDriftError,
    BaselineRecord,
    ProjectionContract,
    ProjectionContractRegistry,
    ProjectionEnvelope,
    parse_projection_envelope,
)


_BASELINE_ID = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_NAMESPACE_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EVENT_TYPES: Final = frozenset(
    {
        "baseline_create",
        "baseline_load",
        "baseline_compare",
        "evidence_correlate",
        "ha_reconcile",
        "store_verify",
    }
)
_BASELINE_EVENT_TYPES: Final = frozenset(
    {"baseline_create", "baseline_load", "baseline_compare", "store_verify"}
)
_DRIFT_OUTCOMES: Final = frozenset(
    {"unchanged", "changed", "missing", "new", "stale", "contradictory", "not_assessed"}
)
_CORRELATION_OUTCOMES: Final = frozenset(
    {"temporally_aligned", "operationally_consistent", "contradictory", "not_assessed"}
)
_HA_RECONCILIATION_OUTCOMES: Final = frozenset(
    {
        "contradictory",
        "degraded",
        "out_of_sync",
        "not_assessed",
        "eligible_for_operator_review",
        "rejected",
    }
)
_EVENT_OUTCOMES: Final = MappingProxyType(
    {
        "baseline_create": frozenset({"accepted", "rejected"}),
        "baseline_load": frozenset({"accepted", "rejected"}),
        "baseline_compare": _DRIFT_OUTCOMES,
        "evidence_correlate": _CORRELATION_OUTCOMES,
        "ha_reconcile": _HA_RECONCILIATION_OUTCOMES,
        "store_verify": frozenset({"accepted", "rejected"}),
    }
)


class DiagnosticStoreError(ValueError):
    """Raised when local diagnostic persistence cannot safely proceed."""


@dataclass(frozen=True, slots=True)
class AuditProfile:
    """Immutable audit authorization for one service-defined diagnostic profile."""

    profile_id: str
    contract_id: str
    contract_version: str
    event_types: frozenset[str]

    def __post_init__(self) -> None:
        if (
            type(self.profile_id) is not str
            or type(self.contract_id) is not str
            or type(self.contract_version) is not str
            or type(self.event_types) is not frozenset
            or not _IDENTIFIER.fullmatch(self.profile_id)
            or not _IDENTIFIER.fullmatch(self.contract_id)
            or not _bounded_text(self.contract_version)
            or not self.event_types
            or not self.event_types <= _EVENT_TYPES
        ):
            raise DiagnosticStoreError("The diagnostic audit profile is invalid.")


class DiagnosticBaselineStore:
    """Owner-only SQLite store with immutable principal-scoped baseline records."""

    def __init__(
        self,
        database_path: Path,
        contracts: ProjectionContractRegistry,
        principal_namespace: str,
        audit_hmac_key: bytes,
        audit_profiles: tuple[AuditProfile, ...] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(contracts, ProjectionContractRegistry):
            raise DiagnosticStoreError("The diagnostic contract registry is invalid.")
        if (
            type(principal_namespace) is not str
            or not _NAMESPACE_DIGEST.fullmatch(principal_namespace)
        ):
            raise DiagnosticStoreError("The diagnostic principal is invalid.")
        if type(audit_hmac_key) is not bytes or len(audit_hmac_key) < 32:
            raise DiagnosticStoreError("The audit key is invalid.")
        if clock is not None and not callable(clock):
            raise DiagnosticStoreError("The diagnostic clock is invalid.")
        self._path = Path(database_path)
        self._contracts = contracts
        self._audit_key = audit_hmac_key
        self._clock = clock or (lambda: datetime.now(UTC))
        self._principal_key = _hmac_hex(audit_hmac_key, b"principal\x00" + principal_namespace.encode("utf-8"))
        self._audit_profiles = _audit_profile_index(
            _default_audit_profiles(contracts) if audit_profiles is None else audit_profiles
        )
        self._prepare_path()
        try:
            with self._connect() as connection:
                self._initialize_schema(connection)
                self._verify_audit_chain(connection)
        except (sqlite3.Error, OSError, BaselineDriftError, KeyError, TypeError) as exc:
            raise DiagnosticStoreError("The diagnostic store integrity check failed.") from exc

    def create(self, baseline_id: str, record: BaselineRecord) -> None:
        """Create one baseline and its audit event in a single transaction."""

        baseline_key = self._baseline_key(baseline_id)
        parsed = self._validated_record(record)
        self._resolve_audit_profile(
            "baseline_create",
            parsed.contract.contract_id,
            parsed.contract.contract_id,
            parsed.contract.version,
        )
        envelope_json = _canonical_json(parsed.canonical)
        occurred_at = self._now()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT 1 FROM baselines WHERE principal_key = ? AND baseline_key = ?",
                    (self._principal_key, baseline_key),
                ).fetchone()
                if existing is not None:
                    connection.rollback()
                    raise DiagnosticStoreError("The diagnostic baseline already exists.")
                connection.execute(
                    """
                    INSERT INTO baselines(
                        principal_key, baseline_key, contract_id, contract_version,
                        envelope_json, comparison_digest, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self._principal_key,
                        baseline_key,
                        parsed.contract.contract_id,
                        parsed.contract.version,
                        envelope_json,
                        parsed.comparison_digest,
                        _utc_timestamp(occurred_at),
                    ),
                )
                self._append_audit(
                    connection,
                    event_type="baseline_create",
                    profile=parsed.contract.contract_id,
                    contract_id=parsed.contract.contract_id,
                    contract_version=parsed.contract.version,
                    outcome="accepted",
                    occurred_at=occurred_at,
                    baseline_key=baseline_key,
                    record_reference=_record_reference(self._audit_key, parsed.comparison_digest),
                )
                connection.commit()
        except DiagnosticStoreError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise DiagnosticStoreError("The diagnostic baseline could not be created.") from exc

    def load(self, baseline_id: str) -> BaselineRecord | None:
        """Load only the current principal's baseline after contract revalidation."""

        baseline_key = self._baseline_key(baseline_id)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT envelope_json, comparison_digest
                    FROM baselines
                    WHERE principal_key = ? AND baseline_key = ?
                    """,
                    (self._principal_key, baseline_key),
                ).fetchone()
                if row is None:
                    return None
                parsed = self._parse_stored_envelope(row["envelope_json"], row["comparison_digest"])
                self._verify_audit_chain(connection)
                return BaselineRecord(envelope=parsed, digest=parsed.comparison_digest)
        except DiagnosticStoreError:
            raise
        except (sqlite3.Error, OSError, BaselineDriftError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise DiagnosticStoreError("The diagnostic baseline could not be loaded.") from exc

    def append_event(
        self,
        event_type: str,
        profile: str,
        contract: str,
        version: str,
        outcome: str,
        occurred_at: datetime,
    ) -> None:
        """Append a bounded operational event without accepting arbitrary metadata."""

        audit_profile = self._resolve_audit_profile(
            event_type, profile, contract, version
        )
        _validate_event(event_type, outcome, occurred_at)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._append_audit(
                    connection,
                    event_type=event_type,
                    profile=profile,
                    contract_id=audit_profile.contract_id,
                    contract_version=audit_profile.contract_version,
                    outcome=outcome,
                    occurred_at=occurred_at,
                    baseline_key=None,
                    record_reference=None,
                )
                connection.commit()
        except DiagnosticStoreError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise DiagnosticStoreError("The diagnostic audit event could not be appended.") from exc

    def _validated_record(self, record: BaselineRecord) -> ProjectionEnvelope:
        if not isinstance(record, BaselineRecord):
            raise DiagnosticStoreError("The diagnostic baseline record is invalid.")
        try:
            parsed = parse_projection_envelope(
                record.envelope.canonical, self._contracts, require_required_paths=True
            )
        except (AttributeError, BaselineDriftError) as exc:
            raise DiagnosticStoreError("The diagnostic baseline record is invalid.") from exc
        if record.digest != parsed.comparison_digest:
            raise DiagnosticStoreError("The diagnostic baseline record is invalid.")
        return parsed

    def _now(self) -> datetime:
        try:
            value = self._clock()
            _utc_timestamp(value)
        except Exception as exc:
            raise DiagnosticStoreError("The diagnostic clock is invalid.") from exc
        return value

    def _parse_stored_envelope(
        self, envelope_json: object, comparison_digest: object
    ) -> ProjectionEnvelope:
        if type(envelope_json) is not str or type(comparison_digest) is not str:
            raise DiagnosticStoreError("The stored diagnostic baseline is invalid.")
        parsed = parse_projection_envelope(
            json.loads(envelope_json), self._contracts, require_required_paths=True
        )
        if not hmac.compare_digest(parsed.comparison_digest, comparison_digest):
            raise DiagnosticStoreError("The stored diagnostic baseline is invalid.")
        return parsed

    def _resolve_audit_profile(
        self, event_type: str, profile: str, contract: str, version: str
    ) -> AuditProfile:
        if (
            type(profile) is not str
            or type(contract) is not str
            or type(version) is not str
            or not _IDENTIFIER.fullmatch(profile)
            or not _IDENTIFIER.fullmatch(contract)
            or not _bounded_text(version)
        ):
            raise DiagnosticStoreError("The diagnostic audit event is invalid.")
        audit_profile = self._audit_profiles.get(profile)
        if (
            audit_profile is None
            or event_type not in audit_profile.event_types
            or contract != audit_profile.contract_id
            or version != audit_profile.contract_version
        ):
            raise DiagnosticStoreError("The diagnostic audit event is invalid.")
        return audit_profile

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        profile: str,
        contract_id: str,
        contract_version: str,
        outcome: str,
        occurred_at: datetime,
        baseline_key: str | None,
        record_reference: str | None,
    ) -> None:
        _validate_event(event_type, outcome, occurred_at)
        previous = connection.execute(
            "SELECT sequence, chain_hmac FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_hmac = "" if previous is None else str(previous["chain_hmac"])
        payload = _audit_payload(
            sequence=sequence,
            occurred_at=_utc_timestamp(occurred_at),
            event_type=event_type,
            profile=profile,
            contract_id=contract_id,
            contract_version=contract_version,
            outcome=outcome,
            principal_key=self._principal_key,
            baseline_key=baseline_key,
            record_reference=record_reference,
            previous_hmac=previous_hmac,
        )
        chain_hmac = _hmac_hex(self._audit_key, payload)
        connection.execute(
            """
            INSERT INTO audit_events(
                sequence, occurred_at, event_type, profile, contract_id, contract_version,
                outcome, principal_key, baseline_key, record_reference, previous_hmac, chain_hmac
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                _utc_timestamp(occurred_at),
                event_type,
                profile,
                contract_id,
                contract_version,
                outcome,
                self._principal_key,
                baseline_key,
                record_reference,
                previous_hmac,
                chain_hmac,
            ),
        )

    def _verify_audit_chain(self, connection: sqlite3.Connection) -> None:
        expected_previous = ""
        expected_sequence = 1
        for row in connection.execute("SELECT * FROM audit_events ORDER BY sequence"):
            if (
                int(row["sequence"]) != expected_sequence
                or row["previous_hmac"] != expected_previous
                or row["event_type"] not in _EVENT_TYPES
                or row["outcome"]
                not in _EVENT_OUTCOMES.get(str(row["event_type"]), frozenset())
            ):
                raise DiagnosticStoreError("The diagnostic audit chain is invalid.")
            payload = _audit_payload(
                sequence=expected_sequence,
                occurred_at=str(row["occurred_at"]),
                event_type=str(row["event_type"]),
                profile=str(row["profile"]),
                contract_id=str(row["contract_id"]),
                contract_version=str(row["contract_version"]),
                outcome=str(row["outcome"]),
                principal_key=str(row["principal_key"]),
                baseline_key=row["baseline_key"],
                record_reference=row["record_reference"],
                previous_hmac=expected_previous,
            )
            expected = _hmac_hex(self._audit_key, payload)
            actual = row["chain_hmac"]
            if type(actual) is not str or not hmac.compare_digest(expected, actual):
                raise DiagnosticStoreError("The diagnostic audit chain is invalid.")
            expected_previous = actual
            expected_sequence += 1

    def _baseline_key(self, baseline_id: str) -> str:
        if type(baseline_id) is not str or not _BASELINE_ID.fullmatch(baseline_id):
            raise DiagnosticStoreError("The diagnostic baseline identifier is invalid.")
        return _hmac_hex(
            self._audit_key,
            b"baseline\x00" + bytes.fromhex(self._principal_key) + baseline_id.encode("utf-8"),
        )

    def _prepare_path(self) -> None:
        parent = self._path.parent
        try:
            if not self._path.is_absolute():
                raise DiagnosticStoreError("The diagnostic store path is unsafe.")
            _assert_no_symlink_components(parent)
            parent_existed = parent.exists()
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if parent.is_symlink():
                raise DiagnosticStoreError("The diagnostic store path is unsafe.")
            if not parent_existed:
                os.chmod(parent, 0o700)
            _assert_owner_only(parent, directory=True)
            if self._path.exists() or self._path.is_symlink():
                if self._path.is_symlink():
                    raise DiagnosticStoreError("The diagnostic store path is unsafe.")
                _assert_owner_only(self._path, directory=False)
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self._path, flags, 0o600)
            except FileExistsError:
                if self._path.is_symlink():
                    raise DiagnosticStoreError("The diagnostic store path is unsafe.")
                _assert_owner_only(self._path, directory=False)
                return
            os.close(descriptor)
            os.chmod(self._path, 0o600)
            _assert_owner_only(self._path, directory=False)
        except DiagnosticStoreError:
            raise
        except OSError as exc:
            raise DiagnosticStoreError("The diagnostic store path is unsafe.") from exc

    def _connect(self) -> sqlite3.Connection:
        _assert_owner_only(self._path.parent, directory=True)
        _assert_owner_only(self._path, directory=False)
        connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @staticmethod
    def _initialize_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS baselines(
                principal_key TEXT NOT NULL,
                baseline_key TEXT NOT NULL,
                contract_id TEXT NOT NULL,
                contract_version TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                comparison_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(principal_key, baseline_key)
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events(
                sequence INTEGER PRIMARY KEY,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                profile TEXT NOT NULL,
                contract_id TEXT NOT NULL,
                contract_version TEXT NOT NULL,
                outcome TEXT NOT NULL,
                principal_key TEXT NOT NULL,
                baseline_key TEXT,
                record_reference TEXT,
                previous_hmac TEXT NOT NULL,
                chain_hmac TEXT NOT NULL
            )
            """
        )


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
        raise DiagnosticStoreError("The diagnostic store path is unsafe.")
    required_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not required_type(info.st_mode) or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise DiagnosticStoreError("The diagnostic store path is unsafe.")


def _assert_no_symlink_components(path: Path) -> None:
    """Reject a symlink at any already-existing directory component."""

    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if not current.exists():
            return
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise DiagnosticStoreError("The diagnostic store path is unsafe.")


def _validate_event(event_type: str, outcome: str, occurred_at: datetime) -> None:
    if (
        type(event_type) is not str
        or type(outcome) is not str
        or outcome not in _EVENT_OUTCOMES.get(event_type, frozenset())
    ):
        raise DiagnosticStoreError("The diagnostic audit event is invalid.")
    _utc_timestamp(occurred_at)


def _bounded_text(value: str) -> bool:
    return bool(value) and len(value) <= 256 and "\n" not in value and "\r" not in value


def _utc_timestamp(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise DiagnosticStoreError("The diagnostic audit time is invalid.")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _hmac_hex(key: bytes, value: bytes) -> str:
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def _record_reference(key: bytes, comparison_digest: str) -> str:
    """Bind an audit event to a record without persisting its raw digest there."""

    return _hmac_hex(key, b"record-reference\x00" + comparison_digest.encode("ascii"))


def _default_audit_profiles(
    contracts: ProjectionContractRegistry,
) -> tuple[AuditProfile, ...]:
    """Derive safe baseline profiles without fabricating correlation contracts."""

    items = getattr(contracts, "_items", None)
    if not isinstance(items, Mapping):
        raise DiagnosticStoreError("The diagnostic contract registry is invalid.")
    profiles: list[AuditProfile] = []
    for contract in items.values():
        if not isinstance(contract, ProjectionContract):
            raise DiagnosticStoreError("The diagnostic contract registry is invalid.")
        profiles.append(
            AuditProfile(
                contract.contract_id,
                contract.contract_id,
                contract.version,
                _BASELINE_EVENT_TYPES,
            )
        )
    return tuple(profiles)


def _audit_profile_index(
    profiles: tuple[AuditProfile, ...],
) -> Mapping[str, AuditProfile]:
    if type(profiles) is not tuple or not profiles:
        raise DiagnosticStoreError("The diagnostic audit profiles are invalid.")
    indexed: dict[str, AuditProfile] = {}
    for profile in profiles:
        if not isinstance(profile, AuditProfile) or profile.profile_id in indexed:
            raise DiagnosticStoreError("The diagnostic audit profiles are invalid.")
        indexed[profile.profile_id] = profile
    return MappingProxyType(indexed)


def _canonical_json(value: Mapping[str, object]) -> str:
    return json.dumps(_plain_value(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _plain_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_value(item) for item in value]
    return value


def _audit_payload(**fields: object) -> bytes:
    return json.dumps(fields, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
