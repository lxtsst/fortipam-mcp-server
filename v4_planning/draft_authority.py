"""Owner-only persistent Scheme Draft issuance for the V4 planning host.

This authority is a trusted local composition boundary, never an MCP Tool. It
stores only validated C0-C2 planning values, binds every opaque draft reference
to one authenticated requester, and has no product client or execution path.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from typing import Protocol, cast

from .canonical import CanonicalValue, canonical_digest, canonical_json
from .models import (
    AuthenticatedRequester,
    DesiredObject,
    MaterialReferenceMetadata,
    ObjectClass,
    PlanningContractError,
    SchemeDraft,
    SchemeId,
    require_digest,
    require_ref,
)


_SCHEMA_VERSION = 1
_CHAIN_ROOT = "scheme-draft-authority-chain-root"
_ISSUE = "issue"
_REVOKE = "revoke"
_MAX_EVENTS = 10_000


class SchemeDraftAuthorityError(PlanningContractError):
    """Stable failure for unavailable or invalid Scheme Draft authority state."""


class SchemeDraftAuthorityCheckpointError(RuntimeError):
    """Raised when an external Scheme Draft checkpoint is untrusted."""


@dataclass(frozen=True, slots=True)
class SchemeDraftAuthorityStoreTail:
    """Value-free Scheme Draft ledger and time-watermark position."""

    store_ref: str
    sequence: int
    chain_mac: str
    last_seen_at: int

    @classmethod
    def empty(cls, store_ref: str) -> SchemeDraftAuthorityStoreTail:
        return cls(store_ref, 0, _CHAIN_ROOT, 0)

    def __post_init__(self) -> None:
        try:
            require_ref(self.store_ref, "Scheme Draft checkpoint store_ref")
            if self.sequence > 0:
                require_digest(self.chain_mac, "Scheme Draft checkpoint chain_mac")
        except PlanningContractError as exc:
            raise SchemeDraftAuthorityError(
                "Scheme Draft checkpoint position is invalid."
            ) from exc
        if (
            type(self.sequence) is not int
            or self.sequence < 0
            or type(self.last_seen_at) is not int
            or self.last_seen_at < 0
            or (self.sequence == 0 and self.chain_mac != _CHAIN_ROOT)
        ):
            raise SchemeDraftAuthorityError(
                "Scheme Draft checkpoint position is invalid."
            )


class MonotonicSchemeDraftAuthorityCheckpoint(Protocol):
    """External compare-and-swap Authority for Scheme Draft state and time."""

    authority_ref: str

    def verify(self, tail: SchemeDraftAuthorityStoreTail) -> None: ...

    def advance(
        self,
        previous: SchemeDraftAuthorityStoreTail,
        current: SchemeDraftAuthorityStoreTail,
    ) -> None: ...


class PersistentSchemeDraftAuthority:
    """Issue, resolve, and revoke requester-bound Scheme Draft references."""

    def __init__(
        self,
        database_path: Path,
        hmac_key_path: Path,
        *,
        authority_ref: str,
        monotonic_checkpoint: MonotonicSchemeDraftAuthorityCheckpoint | None = None,
        checkpoint_store_ref: str | None = None,
        clock: Callable[[], int] | None = None,
        max_draft_ttl_seconds: int = 3600,
    ) -> None:
        try:
            self.authority_ref = require_ref(
                authority_ref,
                "scheme draft authority_ref",
            )
        except PlanningContractError as exc:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority configuration is invalid."
            ) from exc
        if (
            type(max_draft_ttl_seconds) is not int
            or not 60 <= max_draft_ttl_seconds <= 86_400
        ):
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority lifetime is invalid."
            )
        if (monotonic_checkpoint is None) is not (checkpoint_store_ref is None):
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority checkpoint binding is incomplete."
            )
        self._monotonic_checkpoint = monotonic_checkpoint
        self._checkpoint_store_ref = checkpoint_store_ref
        if monotonic_checkpoint is not None and checkpoint_store_ref is not None:
            try:
                checkpoint_authority_ref = require_ref(
                    monotonic_checkpoint.authority_ref,
                    "Scheme Draft checkpoint authority_ref",
                )
                require_ref(checkpoint_store_ref, "Scheme Draft checkpoint store_ref")
                if checkpoint_authority_ref == self.authority_ref:
                    raise PlanningContractError(
                        "Scheme Draft and checkpoint authorities must be distinct."
                    )
            except (AttributeError, PlanningContractError) as exc:
                raise SchemeDraftAuthorityError(
                    "Scheme Draft authority checkpoint binding is invalid."
                ) from exc
        self._path = Path(database_path)
        self._key_path = Path(hmac_key_path)
        if (
            not self._path.is_absolute()
            or not self._key_path.is_absolute()
            or self._path == self._key_path
        ):
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority protected paths are invalid."
            )
        self._clock = clock or (lambda: int(time.time()))
        self._max_draft_ttl_seconds = max_draft_ttl_seconds
        self._key = self._load_key()
        checkpoint_key_matcher = getattr(monotonic_checkpoint, "uses_key_material", None)
        if callable(checkpoint_key_matcher) and checkpoint_key_matcher(self._key) is True:
            raise SchemeDraftAuthorityError(
                "Scheme Draft and checkpoint Authority HMAC keys must be independent."
            )
        self._prepare_database_file()
        with self._connect() as connection:
            self._initialize(connection)
            self._verify(connection)

    @property
    def monotonic_checkpoint_protocol_bound(self) -> bool:
        """Report whether rollback protection is external to this database."""

        return self._monotonic_checkpoint is not None

    def issue(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        expires_at: int,
        now_epoch: int | None = None,
    ) -> str:
        """Issue one opaque reference for an exact validated draft/requester pair."""

        if not isinstance(draft, SchemeDraft) or not isinstance(
            requester, AuthenticatedRequester
        ):
            raise SchemeDraftAuthorityError("Scheme Draft issuance input is invalid.")
        return self._issue(
            draft,
            requester.digest,
            expires_at=expires_at,
            now_epoch=now_epoch,
        )

    def issue_for_requester_digest(
        self,
        draft: SchemeDraft,
        requester_digest: str,
        *,
        expires_at: int,
        now_epoch: int | None = None,
    ) -> str:
        """Issue from a digest produced by an already trusted identity boundary."""

        if not isinstance(draft, SchemeDraft):
            raise SchemeDraftAuthorityError("Scheme Draft issuance input is invalid.")
        try:
            validated_digest = require_digest(
                requester_digest,
                "Scheme Draft requester_digest",
            )
        except PlanningContractError as exc:
            raise SchemeDraftAuthorityError(
                "Scheme Draft issuance input is invalid."
            ) from exc
        return self._issue(
            draft,
            validated_digest,
            expires_at=expires_at,
            now_epoch=now_epoch,
        )

    def _issue(
        self,
        draft: SchemeDraft,
        requester_digest: str,
        *,
        expires_at: int,
        now_epoch: int | None,
    ) -> str:
        now = self._time(now_epoch)
        if (
            type(expires_at) is not int
            or expires_at <= now
            or expires_at > now + self._max_draft_ttl_seconds
        ):
            raise SchemeDraftAuthorityError("Scheme Draft lifetime is invalid.")
        draft_json = canonical_json(_draft_payload(draft))
        draft_ref = f"scheme-draft-{secrets.token_hex(16)}"
        draft_ref_digest = canonical_digest(draft_ref)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            events = self._verify(connection)
            previous_tail = self._checkpoint_tail(connection)
            self._observe_time(connection, now)
            if len(events) >= _MAX_EVENTS:
                raise SchemeDraftAuthorityError(
                    "Scheme Draft authority event bound exceeded."
                )
            if draft_ref_digest in self._latest(events):
                raise SchemeDraftAuthorityError("Scheme Draft generation failed.")
            self._append_event(
                connection,
                event_kind=_ISSUE,
                draft_ref_digest=draft_ref_digest,
                requester_digest=requester_digest,
                draft_json=draft_json,
                event_at=now,
                expires_at=expires_at,
            )
            current_tail = self._checkpoint_tail(connection)
            connection.commit()
            self._advance_monotonic_checkpoint(previous_tail, current_tail)
        return draft_ref

    def resolve(
        self,
        scheme_draft_ref: str,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int | None = None,
    ) -> SchemeDraft:
        """Resolve only an active reference issued to the exact requester."""

        try:
            draft_ref_digest = canonical_digest(
                require_ref(scheme_draft_ref, "scheme_draft_ref")
            )
        except PlanningContractError as exc:
            raise SchemeDraftAuthorityError("Scheme Draft is unavailable.") from exc
        if not isinstance(requester, AuthenticatedRequester):
            raise SchemeDraftAuthorityError("Scheme Draft is unavailable.")
        now = self._time(now_epoch)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            events = self._verify(connection)
            previous_tail = self._checkpoint_tail(connection)
            self._observe_time(connection, now)
            event = self._latest(events).get(draft_ref_digest)
            if (
                event is None
                or event["event_kind"] != _ISSUE
                or int(event["expires_at"]) <= now
                or not hmac.compare_digest(
                    str(event["requester_digest"]), requester.digest
                )
            ):
                raise SchemeDraftAuthorityError("Scheme Draft is unavailable.")
            try:
                draft = _draft_from_payload(_mapping_json(str(event["draft_json"])))
            except (KeyError, TypeError, ValueError, PlanningContractError) as exc:
                raise SchemeDraftAuthorityError(
                    "Scheme Draft authority integrity failed."
                ) from exc
            current_tail = self._checkpoint_tail(connection)
            connection.commit()
            self._advance_monotonic_checkpoint(previous_tail, current_tail)
        return draft

    def revoke(
        self,
        scheme_draft_ref: str,
        *,
        now_epoch: int | None = None,
    ) -> None:
        """Revoke one active reference through the private host boundary."""

        try:
            draft_ref_digest = canonical_digest(
                require_ref(scheme_draft_ref, "scheme_draft_ref")
            )
        except PlanningContractError as exc:
            raise SchemeDraftAuthorityError("Scheme Draft is unavailable.") from exc
        now = self._time(now_epoch)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            events = self._verify(connection)
            previous_tail = self._checkpoint_tail(connection)
            self._observe_time(connection, now)
            event = self._latest(events).get(draft_ref_digest)
            if (
                event is None
                or event["event_kind"] != _ISSUE
                or int(event["expires_at"]) <= now
            ):
                raise SchemeDraftAuthorityError("Scheme Draft is unavailable.")
            self._append_event(
                connection,
                event_kind=_REVOKE,
                draft_ref_digest=draft_ref_digest,
                requester_digest=str(event["requester_digest"]),
                draft_json=str(event["draft_json"]),
                event_at=now,
                expires_at=int(event["expires_at"]),
            )
            current_tail = self._checkpoint_tail(connection)
            connection.commit()
            self._advance_monotonic_checkpoint(previous_tail, current_tail)

    def uses_key_material(self, candidate: bytes) -> bool:
        """Return only whether trusted composition reused this exact key."""

        return type(candidate) is bytes and hmac.compare_digest(self._key, candidate)

    def shares_key_material_with(self, candidate: object) -> bool:
        """Compare protected keys without exposing either key."""

        matcher = getattr(candidate, "uses_key_material", None)
        return callable(matcher) and matcher(self._key) is True

    def verify_ready(self) -> None:
        """Revalidate protected state before binding it to a Host."""

        self._assert_owner_only(self._path.parent, directory=True)
        self._assert_owner_only(self._path, directory=False)
        self._assert_owner_only(self._key_path.parent, directory=True)
        self._assert_owner_only(self._key_path, directory=False)
        with self._connect() as connection:
            self._verify(connection)

    def _time(self, value: int | None) -> int:
        now = self._clock() if value is None else value
        if type(now) is not int or now < 0:
            raise SchemeDraftAuthorityError("Scheme Draft authority time is invalid.")
        return now

    def _load_key(self) -> bytes:
        self._assert_owner_only(self._key_path.parent, directory=True)
        self._assert_owner_only(self._key_path, directory=False)
        try:
            key = self._key_path.read_bytes()
        except OSError as exc:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority key is unavailable."
            ) from exc
        if not 32 <= len(key) <= 4096:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority key is invalid."
            )
        return key

    def _prepare_database_file(self) -> None:
        self._assert_owner_only(self._path.parent, directory=True)
        if self._path.exists():
            self._assert_owner_only(self._path, directory=False)
            return
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
        except OSError as exc:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority state is unavailable."
            ) from exc
        os.chmod(self._path, 0o600)

    @staticmethod
    def _assert_owner_only(path: Path, *, directory: bool) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority protected path is unavailable."
            ) from exc
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if (
            path.is_symlink()
            or not expected_type(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority protected path must be owner-only."
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    def _initialize(self, connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, _SCHEMA_VERSION}:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority schema is unavailable."
            )
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scheme_draft_events (
                sequence INTEGER PRIMARY KEY,
                event_kind TEXT NOT NULL,
                draft_ref_digest TEXT NOT NULL,
                requester_digest TEXT NOT NULL,
                draft_json TEXT NOT NULL,
                event_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                previous_mac TEXT NOT NULL,
                event_mac TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scheme_draft_anchor (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_sequence INTEGER NOT NULL,
                last_mac TEXT NOT NULL,
                last_seen_at INTEGER NOT NULL,
                anchor_mac TEXT NOT NULL
            );
            """
        )
        connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        if connection.execute(
            "SELECT COUNT(*) FROM scheme_draft_anchor"
        ).fetchone()[0] == 0:
            connection.execute(
                "INSERT INTO scheme_draft_anchor VALUES(1, 0, ?, 0, ?)",
                (_CHAIN_ROOT, self._anchor_mac(0, _CHAIN_ROOT, 0)),
            )
        connection.commit()

    def _verify(self, connection: sqlite3.Connection) -> list[sqlite3.Row]:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at, anchor_mac "
            "FROM scheme_draft_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None or not hmac.compare_digest(
            str(anchor["anchor_mac"]),
            self._anchor_mac(
                int(anchor["last_sequence"]),
                str(anchor["last_mac"]),
                int(anchor["last_seen_at"]),
            ),
        ):
            raise SchemeDraftAuthorityError("Scheme Draft authority integrity failed.")
        events = connection.execute(
            "SELECT * FROM scheme_draft_events ORDER BY sequence"
        ).fetchall()
        if len(events) > _MAX_EVENTS:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority event bound exceeded."
            )
        previous_mac = _CHAIN_ROOT
        for expected_sequence, event in enumerate(events, start=1):
            if (
                int(event["sequence"]) != expected_sequence
                or str(event["previous_mac"]) != previous_mac
                or str(event["event_kind"]) not in {_ISSUE, _REVOKE}
                or not hmac.compare_digest(
                    str(event["event_mac"]), self._event_mac(self._event_fields(event))
                )
            ):
                raise SchemeDraftAuthorityError(
                    "Scheme Draft authority integrity failed."
                )
            previous_mac = str(event["event_mac"])
        if (
            int(anchor["last_sequence"]) != len(events)
            or str(anchor["last_mac"]) != previous_mac
        ):
            raise SchemeDraftAuthorityError("Scheme Draft authority integrity failed.")
        self._verify_monotonic_checkpoint(
            self._checkpoint_tail_values(
                int(anchor["last_sequence"]),
                str(anchor["last_mac"]),
                int(anchor["last_seen_at"]),
            )
        )
        return events

    def _checkpoint_tail(
        self,
        connection: sqlite3.Connection,
    ) -> SchemeDraftAuthorityStoreTail | None:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at FROM scheme_draft_anchor "
            "WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise SchemeDraftAuthorityError("Scheme Draft authority integrity failed.")
        return self._checkpoint_tail_values(
            int(anchor["last_sequence"]),
            str(anchor["last_mac"]),
            int(anchor["last_seen_at"]),
        )

    def _checkpoint_tail_values(
        self,
        sequence: int,
        chain_mac: str,
        last_seen_at: int,
    ) -> SchemeDraftAuthorityStoreTail | None:
        if self._monotonic_checkpoint is None:
            return None
        if self._checkpoint_store_ref is None:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority checkpoint store binding is unavailable."
            )
        return SchemeDraftAuthorityStoreTail(
            self._checkpoint_store_ref,
            sequence,
            chain_mac,
            last_seen_at,
        )

    def _verify_monotonic_checkpoint(
        self,
        tail: SchemeDraftAuthorityStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if tail is None:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority checkpoint state is unavailable."
            )
        try:
            checkpoint.verify(tail)
        except SchemeDraftAuthorityCheckpointError as exc:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority checkpoint verification failed."
            ) from exc

    def _advance_monotonic_checkpoint(
        self,
        previous: SchemeDraftAuthorityStoreTail | None,
        current: SchemeDraftAuthorityStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if previous is None or current is None:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority checkpoint state is unavailable."
            )
        if previous == current:
            return
        try:
            checkpoint.advance(previous, current)
        except SchemeDraftAuthorityCheckpointError as exc:
            raise SchemeDraftAuthorityError(
                "Scheme Draft authority checkpoint advance failed."
            ) from exc

    def _observe_time(self, connection: sqlite3.Connection, now: int) -> None:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at FROM scheme_draft_anchor "
            "WHERE singleton = 1"
        ).fetchone()
        if anchor is None or now < int(anchor["last_seen_at"]):
            raise SchemeDraftAuthorityError("Scheme Draft authority time moved backwards.")
        connection.execute(
            "UPDATE scheme_draft_anchor SET last_seen_at = ?, anchor_mac = ? "
            "WHERE singleton = 1",
            (
                now,
                self._anchor_mac(
                    int(anchor["last_sequence"]), str(anchor["last_mac"]), now
                ),
            ),
        )

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        event_kind: str,
        draft_ref_digest: str,
        requester_digest: str,
        draft_json: str,
        event_at: int,
        expires_at: int,
    ) -> None:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at FROM scheme_draft_anchor "
            "WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise SchemeDraftAuthorityError("Scheme Draft authority integrity failed.")
        sequence = int(anchor["last_sequence"]) + 1
        previous_mac = str(anchor["last_mac"])
        fields: dict[str, CanonicalValue] = {
            "draft_json": draft_json,
            "draft_ref_digest": require_digest(
                draft_ref_digest, "scheme draft_ref digest"
            ),
            "event_at": event_at,
            "event_kind": event_kind,
            "expires_at": expires_at,
            "previous_mac": previous_mac,
            "requester_digest": require_digest(
                requester_digest, "scheme draft requester digest"
            ),
            "sequence": sequence,
        }
        event_mac = self._event_mac(fields)
        connection.execute(
            "INSERT INTO scheme_draft_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                event_kind,
                draft_ref_digest,
                requester_digest,
                draft_json,
                event_at,
                expires_at,
                previous_mac,
                event_mac,
            ),
        )
        connection.execute(
            "UPDATE scheme_draft_anchor SET last_sequence = ?, last_mac = ?, "
            "anchor_mac = ? WHERE singleton = 1",
            (
                sequence,
                event_mac,
                self._anchor_mac(sequence, event_mac, int(anchor["last_seen_at"])),
            ),
        )

    @staticmethod
    def _latest(events: list[sqlite3.Row]) -> dict[str, sqlite3.Row]:
        latest: dict[str, sqlite3.Row] = {}
        for event in events:
            latest[str(event["draft_ref_digest"])] = event
        return latest

    @staticmethod
    def _event_fields(event: sqlite3.Row) -> dict[str, CanonicalValue]:
        return {
            "draft_json": str(event["draft_json"]),
            "draft_ref_digest": str(event["draft_ref_digest"]),
            "event_at": int(event["event_at"]),
            "event_kind": str(event["event_kind"]),
            "expires_at": int(event["expires_at"]),
            "previous_mac": str(event["previous_mac"]),
            "requester_digest": str(event["requester_digest"]),
            "sequence": int(event["sequence"]),
        }

    def _event_mac(self, fields: Mapping[str, object]) -> str:
        return hmac.new(
            self._key,
            b"scheme-draft-event\x00"
            + json.dumps(
                fields,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _anchor_mac(self, sequence: int, last_mac: str, last_seen_at: int) -> str:
        return hmac.new(
            self._key,
            b"scheme-draft-anchor\x00"
            + canonical_json(
                {
                    "last_mac": last_mac,
                    "last_seen_at": last_seen_at,
                    "last_sequence": sequence,
                }
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


def _draft_payload(draft: SchemeDraft) -> dict[str, object]:
    payload: dict[str, object] = {
        "approval_class": draft.approval_class,
        "assumption_codes": list(draft.assumption_codes),
        "audience_ref": draft.audience_ref,
        "blueprint_ref": draft.blueprint_ref,
        "desired_objects": [
            {
                "desired_exists": item.desired_exists,
                "desired_fields": dict(item.desired_fields),
                "object_class": item.object_class.value,
                "object_ref": item.object_ref,
            }
            for item in draft.desired_objects
        ],
        "environment_ref": draft.environment_ref,
        "evidence_policy": draft.evidence_policy,
        "evidence_refs": list(draft.evidence_refs),
        "excluded_scope_codes": list(draft.excluded_scope_codes),
        "external_effects": list(draft.external_effects),
        "maintenance_class": draft.maintenance_class,
        "outcome_code": draft.outcome_code,
        "owner_ref": draft.owner_ref,
        "reconciliation_strategy": draft.reconciliation_strategy,
        "registry_schema_version": draft.registry_schema_version,
        "reversibility_class": draft.reversibility_class,
        "risk_class": draft.risk_class,
        "scheme_id": draft.scheme_id.value,
        "scheme_version": draft.scheme_version,
        "scope_ref": draft.scope_ref,
        "separation_required": draft.separation_required,
        "stop_codes": list(draft.stop_codes),
        "summary_ttl_seconds": draft.summary_ttl_seconds,
        "unresolved_gap_codes": list(draft.unresolved_gap_codes),
        "verification_codes": list(draft.verification_codes),
    }
    if draft.material_reference_metadata is not None:
        payload["material_reference_metadata"] = (
            draft.material_reference_metadata.as_dict()
        )
    return payload


def scheme_draft_as_mapping(draft: SchemeDraft) -> dict[str, object]:
    """Return the exact bounded C0-C2 persistence representation."""

    if not isinstance(draft, SchemeDraft):
        raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
    return _draft_payload(draft)


def _draft_from_payload(payload: Mapping[str, object]) -> SchemeDraft:
    allowed = {
        "approval_class",
        "assumption_codes",
        "audience_ref",
        "blueprint_ref",
        "desired_objects",
        "environment_ref",
        "evidence_policy",
        "evidence_refs",
        "excluded_scope_codes",
        "external_effects",
        "maintenance_class",
        "material_reference_metadata",
        "outcome_code",
        "owner_ref",
        "reconciliation_strategy",
        "registry_schema_version",
        "reversibility_class",
        "risk_class",
        "scheme_id",
        "scheme_version",
        "scope_ref",
        "separation_required",
        "stop_codes",
        "summary_ttl_seconds",
        "unresolved_gap_codes",
        "verification_codes",
    }
    required = allowed - {"material_reference_metadata"}
    payload_keys = set(payload)
    if payload_keys != required and payload_keys != allowed:
        raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
    desired_values = _list(payload["desired_objects"])
    desired_objects: list[DesiredObject] = []
    for value in desired_values:
        item = _mapping(value)
        if set(item) != {
            "desired_exists",
            "desired_fields",
            "object_class",
            "object_ref",
        }:
            raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
        fields = _mapping(item["desired_fields"])
        desired_objects.append(
            DesiredObject(
                object_ref=_str(item["object_ref"]),
                object_class=ObjectClass(_str(item["object_class"])),
                desired_exists=_bool(item["desired_exists"]),
                desired_fields=tuple(
                    (name, _bool_or_str(fields[name])) for name in sorted(fields)
                ),
            )
        )
    material = None
    if "material_reference_metadata" in payload:
        material_value = _mapping(payload["material_reference_metadata"])
        if set(material_value) != {"lifecycle", "provider_class", "purpose"}:
            raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
        material = MaterialReferenceMetadata(
            provider_class=_str(material_value["provider_class"]),
            purpose=_str(material_value["purpose"]),
            lifecycle=_str(material_value["lifecycle"]),
        )
    return SchemeDraft(
        scheme_id=SchemeId(_str(payload["scheme_id"])),
        scheme_version=_str(payload["scheme_version"]),
        registry_schema_version=_str(payload["registry_schema_version"]),
        blueprint_ref=_str(payload["blueprint_ref"]),
        environment_ref=_str(payload["environment_ref"]),
        scope_ref=_str(payload["scope_ref"]),
        owner_ref=_str(payload["owner_ref"]),
        audience_ref=_str(payload["audience_ref"]),
        outcome_code=_str(payload["outcome_code"]),
        desired_objects=tuple(desired_objects),
        approval_class=_str(payload["approval_class"]),
        separation_required=_bool(payload["separation_required"]),
        risk_class=_str(payload["risk_class"]),
        external_effects=_strings(payload["external_effects"]),
        assumption_codes=_strings(payload["assumption_codes"]),
        excluded_scope_codes=_strings(payload["excluded_scope_codes"]),
        verification_codes=_strings(payload["verification_codes"]),
        stop_codes=_strings(payload["stop_codes"]),
        evidence_policy=_str(payload["evidence_policy"]),
        maintenance_class=_str(payload["maintenance_class"]),
        reversibility_class=_str(payload["reversibility_class"]),
        evidence_refs=_strings(payload["evidence_refs"]),
        unresolved_gap_codes=_strings(payload["unresolved_gap_codes"]),
        reconciliation_strategy=_str(payload["reconciliation_strategy"]),
        summary_ttl_seconds=_int(payload["summary_ttl_seconds"]),
        material_reference_metadata=material,
    )


def scheme_draft_from_mapping(payload: Mapping[str, object]) -> SchemeDraft:
    """Validate and construct one exact bounded C0-C2 Scheme Draft."""

    if not isinstance(payload, Mapping):
        raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
    return _draft_from_payload(payload)


def _mapping_json(value: str) -> dict[str, object]:
    parsed = json.loads(value)
    if type(parsed) is not dict:
        raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
    return cast(dict[str, object], parsed)


def _mapping(value: object) -> dict[str, object]:
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
    return cast(dict[str, object], value)


def _list(value: object) -> list[object]:
    if type(value) is not list:
        raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
    return cast(list[object], value)


def _str(value: object) -> str:
    if type(value) is not str:
        raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
    return value


def _bool(value: object) -> bool:
    if type(value) is not bool:
        raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
    return value


def _int(value: object) -> int:
    if type(value) is not int:
        raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")
    return value


def _bool_or_str(value: object) -> bool | str | int:
    if type(value) is bool or type(value) is str or type(value) is int:
        return value
    raise SchemeDraftAuthorityError("Scheme Draft payload is invalid.")


def _strings(value: object) -> tuple[str, ...]:
    return tuple(_str(item) for item in _list(value))


__all__ = [
    "MonotonicSchemeDraftAuthorityCheckpoint",
    "PersistentSchemeDraftAuthority",
    "SchemeDraftAuthorityCheckpointError",
    "SchemeDraftAuthorityError",
    "SchemeDraftAuthorityStoreTail",
    "scheme_draft_as_mapping",
    "scheme_draft_from_mapping",
]
