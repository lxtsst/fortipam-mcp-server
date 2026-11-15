"""Owner-protected C2 reference authority for the V4 planning boundary.

The authority is deliberately not an MCP Tool and has no product adapter,
credential loader, network client, or execution transition.  It stores only
digests of bounded opaque references and their exact authorization context.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from typing import Protocol

from .canonical import CanonicalValue, canonical_digest, canonical_json
from .models import (
    PlanningContractError,
    VerifiedReferenceDecision,
    require_code,
    require_digest,
    require_ref,
)


_SCHEMA_VERSION = 1
_CHAIN_ROOT = "reference-authority-chain-root"
_ISSUE = "issue"
_REVOKE = "revoke"
_MAX_EVENTS = 10_000


class ReferenceAuthorityError(PlanningContractError):
    """Stable failure for an unavailable or invalid authority transition."""


class ReferenceAuthorityCheckpointError(RuntimeError):
    """Raised when the external Reference Authority checkpoint is untrusted."""


@dataclass(frozen=True, slots=True)
class ReferenceAuthorityStoreTail:
    """Value-free reference-ledger and time-watermark position."""

    store_ref: str
    sequence: int
    chain_mac: str
    last_seen_at: int

    @classmethod
    def empty(cls, store_ref: str) -> ReferenceAuthorityStoreTail:
        return cls(store_ref, 0, _CHAIN_ROOT, 0)

    def __post_init__(self) -> None:
        try:
            require_ref(self.store_ref, "reference checkpoint store_ref")
            if self.sequence > 0:
                require_digest(self.chain_mac, "reference checkpoint chain_mac")
        except PlanningContractError as exc:
            raise ReferenceAuthorityError(
                "Reference authority checkpoint position is invalid."
            ) from exc
        if (
            type(self.sequence) is not int
            or self.sequence < 0
            or type(self.last_seen_at) is not int
            or self.last_seen_at < 0
            or (self.sequence == 0 and self.chain_mac != _CHAIN_ROOT)
        ):
            raise ReferenceAuthorityError(
                "Reference authority checkpoint position is invalid."
            )


class MonotonicReferenceAuthorityCheckpoint(Protocol):
    """External compare-and-swap authority for reference state and time."""

    authority_ref: str

    def verify(self, tail: ReferenceAuthorityStoreTail) -> None: ...

    def advance(
        self,
        previous: ReferenceAuthorityStoreTail,
        current: ReferenceAuthorityStoreTail,
    ) -> None: ...


class PersistentReferenceAuthority:
    """Issue and revoke exact, time-bounded C2 reference decisions.

    Registration methods are private-host operations.  The only planning-facing
    method is :meth:`authorize`, which implements ``ReferenceAuthorizer`` and
    returns value-free decision metadata.
    """

    def __init__(
        self,
        database_path: Path,
        hmac_key_path: Path,
        *,
        authority_ref: str,
        monotonic_checkpoint: MonotonicReferenceAuthorityCheckpoint | None = None,
        checkpoint_store_ref: str | None = None,
        clock: Callable[[], int] | None = None,
        max_grant_ttl_seconds: int = 3600,
        decision_ttl_seconds: int = 60,
    ) -> None:
        try:
            self.authority_ref = require_ref(authority_ref, "reference authority_ref")
        except PlanningContractError as exc:
            raise ReferenceAuthorityError("Reference authority configuration is invalid.") from exc
        if (
            type(max_grant_ttl_seconds) is not int
            or not 1 <= max_grant_ttl_seconds <= 86_400
            or type(decision_ttl_seconds) is not int
            or not 1 <= decision_ttl_seconds <= max_grant_ttl_seconds
        ):
            raise ReferenceAuthorityError("Reference authority lifetime is invalid.")
        if (monotonic_checkpoint is None) is not (checkpoint_store_ref is None):
            raise ReferenceAuthorityError(
                "Reference authority checkpoint binding is incomplete."
            )
        self._monotonic_checkpoint = monotonic_checkpoint
        self._checkpoint_store_ref = checkpoint_store_ref
        if monotonic_checkpoint is not None and checkpoint_store_ref is not None:
            try:
                checkpoint_authority_ref = require_ref(
                    monotonic_checkpoint.authority_ref,
                    "reference checkpoint authority_ref",
                )
                require_ref(checkpoint_store_ref, "reference checkpoint store_ref")
                if checkpoint_authority_ref == self.authority_ref:
                    raise PlanningContractError(
                        "Reference and checkpoint authorities must be distinct."
                    )
            except (AttributeError, PlanningContractError) as exc:
                raise ReferenceAuthorityError(
                    "Reference authority checkpoint binding is invalid."
                ) from exc
        self._path = Path(database_path)
        self._key_path = Path(hmac_key_path)
        self._clock = clock or (lambda: int(time.time()))
        self._max_grant_ttl_seconds = max_grant_ttl_seconds
        self._decision_ttl_seconds = decision_ttl_seconds
        self._key = self._load_key()
        checkpoint_key_matcher = getattr(monotonic_checkpoint, "uses_key_material", None)
        if callable(checkpoint_key_matcher) and checkpoint_key_matcher(self._key) is True:
            raise ReferenceAuthorityError(
                "Reference and checkpoint Authority HMAC keys must be independent."
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
        reference: str,
        *,
        reference_kind: str,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
        expires_at: int,
        now_epoch: int | None = None,
    ) -> str:
        """Create one private revocation handle for an exact authorization."""

        return self.issue_many(
            ((reference, reference_kind),),
            requester_digest=requester_digest,
            environment_ref=environment_ref,
            scope_ref=scope_ref,
            expires_at=expires_at,
            now_epoch=now_epoch,
        )[0]

    def issue_many(
        self,
        references: Sequence[tuple[str, str]],
        *,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
        expires_at: int,
        now_epoch: int | None = None,
    ) -> tuple[str, ...]:
        """Atomically create private handles for one bounded reference set."""

        now = self._time(now_epoch)
        if (
            isinstance(references, (str, bytes, bytearray))
            or not isinstance(references, Sequence)
            or not 1 <= len(references) <= 64
            or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not str
                for item in references
            )
        ):
            raise ReferenceAuthorityError("Reference authorization set is invalid.")
        bindings = tuple(
            self._binding(
                reference,
                reference_kind=reference_kind,
                requester_digest=requester_digest,
                environment_ref=environment_ref,
                scope_ref=scope_ref,
            )
            for reference, reference_kind in references
        )
        binding_keys = tuple(self._binding_key(binding) for binding in bindings)
        if len(set(binding_keys)) != len(binding_keys):
            raise ReferenceAuthorityError("Reference authorization set is invalid.")
        if (
            type(expires_at) is not int
            or expires_at <= now
            or expires_at > now + self._max_grant_ttl_seconds
        ):
            raise ReferenceAuthorityError("Reference grant lifetime is invalid.")

        grant_refs = tuple(
            f"reference-grant-{secrets.token_hex(16)}" for _binding in bindings
        )
        grant_ref_digests = tuple(canonical_digest(value) for value in grant_refs)
        if len(set(grant_ref_digests)) != len(grant_ref_digests):
            raise ReferenceAuthorityError("Reference grant generation failed.")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            events = self._verify(connection)
            previous_tail = self._checkpoint_tail(connection)
            self._observe_time(connection, now)
            latest = self._latest(events)
            if len(events) + len(bindings) > _MAX_EVENTS:
                raise ReferenceAuthorityError("Reference authority event bound exceeded.")
            active_bindings = {
                self._binding_key(self._event_binding(event))
                for event in latest.values()
                if event["event_kind"] == _ISSUE and int(event["expires_at"]) > now
            }
            if any(
                binding_key in active_bindings for binding_key in binding_keys
            ):
                raise ReferenceAuthorityError(
                    "An active reference authorization already exists."
                )
            for grant_ref_digest, binding in zip(
                grant_ref_digests,
                bindings,
                strict=True,
            ):
                self._append_event(
                    connection,
                    event_kind=_ISSUE,
                    grant_ref_digest=grant_ref_digest,
                    binding=binding,
                    event_at=now,
                    expires_at=expires_at,
                )
            current_tail = self._checkpoint_tail(connection)
            connection.commit()
            self._advance_monotonic_checkpoint(previous_tail, current_tail)
        return grant_refs

    def revoke(self, grant_ref: str, *, now_epoch: int | None = None) -> None:
        """Revoke one private grant handle without accepting a reference value."""

        self.revoke_many((grant_ref,), now_epoch=now_epoch)

    def revoke_many(
        self,
        grant_refs: Sequence[str],
        *,
        now_epoch: int | None = None,
    ) -> None:
        """Atomically revoke one bounded set of private grant handles."""

        try:
            if (
                isinstance(grant_refs, (str, bytes, bytearray))
                or not isinstance(grant_refs, Sequence)
                or not 1 <= len(grant_refs) <= 64
            ):
                raise PlanningContractError("Reference grant set is invalid.")
            grant_ref_digests = tuple(
                canonical_digest(require_ref(value, "reference grant_ref"))
                for value in grant_refs
            )
            if len(set(grant_ref_digests)) != len(grant_ref_digests):
                raise PlanningContractError("Reference grant set is invalid.")
        except PlanningContractError as exc:
            raise ReferenceAuthorityError("Reference grant is unavailable.") from exc
        now = self._time(now_epoch)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            events = self._verify(connection)
            previous_tail = self._checkpoint_tail(connection)
            self._observe_time(connection, now)
            latest = self._latest(events)
            selected = tuple(latest.get(digest) for digest in grant_ref_digests)
            if any(
                event is None or event["event_kind"] != _ISSUE
                for event in selected
            ):
                raise ReferenceAuthorityError("Reference grant is unavailable.")
            if len(events) + len(selected) > _MAX_EVENTS:
                raise ReferenceAuthorityError("Reference authority event bound exceeded.")
            for grant_ref_digest, event in zip(
                grant_ref_digests,
                selected,
                strict=True,
            ):
                assert event is not None
                self._append_event(
                    connection,
                    event_kind=_REVOKE,
                    grant_ref_digest=grant_ref_digest,
                    binding=self._event_binding(event),
                    event_at=now,
                    expires_at=int(event["expires_at"]),
                )
            current_tail = self._checkpoint_tail(connection)
            connection.commit()
            self._advance_monotonic_checkpoint(previous_tail, current_tail)

    def authorize(
        self,
        reference: str,
        *,
        reference_kind: str,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
        now_epoch: int,
    ) -> VerifiedReferenceDecision:
        """Return one exact value-free decision and never reveal stored state."""

        now = self._time(now_epoch)
        binding = self._binding(
            reference,
            reference_kind=reference_kind,
            requester_digest=requester_digest,
            environment_ref=environment_ref,
            scope_ref=scope_ref,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            events = self._verify(connection)
            previous_tail = self._checkpoint_tail(connection)
            self._observe_time(connection, now)
            matches = [
                event
                for event in self._latest(events).values()
                if event["event_kind"] == _ISSUE
                and int(event["expires_at"]) > now
                and self._event_binding(event) == binding
            ]
            if len(matches) > 1:
                raise ReferenceAuthorityError("Reference authority state is ambiguous.")
            authorized = len(matches) == 1
            expires_at = now + self._decision_ttl_seconds
            if authorized:
                expires_at = min(expires_at, int(matches[0]["expires_at"]))
            current_tail = self._checkpoint_tail(connection)
            connection.commit()
            self._advance_monotonic_checkpoint(previous_tail, current_tail)

        return VerifiedReferenceDecision(
            reference_digest=binding["reference_digest"],
            reference_kind=binding["reference_kind"],
            authority_ref=self.authority_ref,
            requester_digest=binding["requester_digest"],
            environment_digest=binding["environment_digest"],
            scope_digest=binding["scope_digest"],
            authorized=authorized,
            checked_at=now,
            expires_at=expires_at,
        )

    def verify_ready(self) -> None:
        """Revalidate protected state before binding it to a Host."""

        self._assert_owner_only(self._path.parent, directory=True)
        self._assert_owner_only(self._path, directory=False)
        self._assert_owner_only(self._key_path.parent, directory=True)
        self._assert_owner_only(self._key_path, directory=False)
        with self._connect() as connection:
            self._verify(connection)

    def uses_key_material(self, candidate: bytes) -> bool:
        """Return only whether trusted composition reused this exact key."""

        return type(candidate) is bytes and hmac.compare_digest(self._key, candidate)

    def shares_key_material_with(self, candidate: object) -> bool:
        """Compare protected keys without exposing either key."""

        matcher = getattr(candidate, "uses_key_material", None)
        return callable(matcher) and matcher(self._key) is True

    def _binding(
        self,
        reference: str,
        *,
        reference_kind: str,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
    ) -> dict[str, str]:
        try:
            return {
                "reference_digest": canonical_digest(
                    require_ref(reference, "reference")
                ),
                "reference_kind": require_code(reference_kind, "reference_kind"),
                "requester_digest": require_digest(
                    requester_digest, "reference requester_digest"
                ),
                "environment_digest": canonical_digest(
                    require_ref(environment_ref, "environment_ref")
                ),
                "scope_digest": canonical_digest(require_ref(scope_ref, "scope_ref")),
            }
        except PlanningContractError as exc:
            raise ReferenceAuthorityError("Reference authorization input is invalid.") from exc

    def _time(self, value: int | None) -> int:
        now = self._clock() if value is None else value
        if type(now) is not int or now < 0:
            raise ReferenceAuthorityError("Reference authority time is invalid.")
        return now

    def _load_key(self) -> bytes:
        self._assert_owner_only(self._key_path.parent, directory=True)
        self._assert_owner_only(self._key_path, directory=False)
        try:
            key = self._key_path.read_bytes()
        except OSError as exc:
            raise ReferenceAuthorityError("Reference authority key is unavailable.") from exc
        if not 32 <= len(key) <= 4096:
            raise ReferenceAuthorityError("Reference authority key is invalid.")
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
            raise ReferenceAuthorityError(
                "Reference authority state is unavailable."
            ) from exc
        os.chmod(self._path, 0o600)

    @staticmethod
    def _assert_owner_only(path: Path, *, directory: bool) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ReferenceAuthorityError(
                "Reference authority protected path is unavailable."
            ) from exc
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if (
            path.is_symlink()
            or not expected_type(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ReferenceAuthorityError(
                "Reference authority protected path must be owner-only."
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self, connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, _SCHEMA_VERSION}:
            raise ReferenceAuthorityError("Reference authority schema is unavailable.")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS reference_events (
                sequence INTEGER PRIMARY KEY,
                event_kind TEXT NOT NULL,
                grant_ref_digest TEXT NOT NULL,
                reference_digest TEXT NOT NULL,
                reference_kind TEXT NOT NULL,
                requester_digest TEXT NOT NULL,
                environment_digest TEXT NOT NULL,
                scope_digest TEXT NOT NULL,
                event_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                previous_mac TEXT NOT NULL,
                event_mac TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reference_anchor (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_sequence INTEGER NOT NULL,
                last_mac TEXT NOT NULL,
                last_seen_at INTEGER NOT NULL,
                anchor_mac TEXT NOT NULL
            );
            """
        )
        connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        if connection.execute("SELECT COUNT(*) FROM reference_anchor").fetchone()[0] == 0:
            connection.execute(
                "INSERT INTO reference_anchor VALUES(1, 0, ?, 0, ?)",
                (_CHAIN_ROOT, self._anchor_mac(0, _CHAIN_ROOT, 0)),
            )
        connection.commit()

    def _verify(self, connection: sqlite3.Connection) -> list[sqlite3.Row]:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at, anchor_mac "
            "FROM reference_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None or not hmac.compare_digest(
            str(anchor["anchor_mac"]),
            self._anchor_mac(
                int(anchor["last_sequence"]),
                str(anchor["last_mac"]),
                int(anchor["last_seen_at"]),
            ),
        ):
            raise ReferenceAuthorityError("Reference authority integrity failed.")
        events = connection.execute(
            "SELECT * FROM reference_events ORDER BY sequence"
        ).fetchall()
        if len(events) > _MAX_EVENTS:
            raise ReferenceAuthorityError("Reference authority event bound exceeded.")
        previous_mac = _CHAIN_ROOT
        for expected_sequence, event in enumerate(events, start=1):
            fields = self._event_fields(event)
            if (
                int(event["sequence"]) != expected_sequence
                or str(event["previous_mac"]) != previous_mac
                or not hmac.compare_digest(
                    str(event["event_mac"]), self._event_mac(fields)
                )
            ):
                raise ReferenceAuthorityError("Reference authority integrity failed.")
            previous_mac = str(event["event_mac"])
        if (
            int(anchor["last_sequence"]) != len(events)
            or str(anchor["last_mac"]) != previous_mac
        ):
            raise ReferenceAuthorityError("Reference authority integrity failed.")
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
    ) -> ReferenceAuthorityStoreTail | None:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at FROM reference_anchor "
            "WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise ReferenceAuthorityError("Reference authority integrity failed.")
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
    ) -> ReferenceAuthorityStoreTail | None:
        if self._monotonic_checkpoint is None:
            return None
        if self._checkpoint_store_ref is None:
            raise ReferenceAuthorityError(
                "Reference authority checkpoint store binding is unavailable."
            )
        return ReferenceAuthorityStoreTail(
            self._checkpoint_store_ref,
            sequence,
            chain_mac,
            last_seen_at,
        )

    def _verify_monotonic_checkpoint(
        self,
        tail: ReferenceAuthorityStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if tail is None:
            raise ReferenceAuthorityError(
                "Reference authority checkpoint state is unavailable."
            )
        try:
            checkpoint.verify(tail)
        except ReferenceAuthorityCheckpointError as exc:
            raise ReferenceAuthorityError(
                "Reference authority checkpoint verification failed."
            ) from exc

    def _advance_monotonic_checkpoint(
        self,
        previous: ReferenceAuthorityStoreTail | None,
        current: ReferenceAuthorityStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if previous is None or current is None:
            raise ReferenceAuthorityError(
                "Reference authority checkpoint state is unavailable."
            )
        if previous == current:
            return
        try:
            checkpoint.advance(previous, current)
        except ReferenceAuthorityCheckpointError as exc:
            raise ReferenceAuthorityError(
                "Reference authority checkpoint advance failed."
            ) from exc

    def _observe_time(self, connection: sqlite3.Connection, now: int) -> None:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at FROM reference_anchor "
            "WHERE singleton = 1"
        ).fetchone()
        if anchor is None or now < int(anchor["last_seen_at"]):
            raise ReferenceAuthorityError("Reference authority time moved backwards.")
        connection.execute(
            "UPDATE reference_anchor SET last_seen_at = ?, anchor_mac = ? "
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
        grant_ref_digest: str,
        binding: dict[str, str],
        event_at: int,
        expires_at: int,
    ) -> None:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at FROM reference_anchor "
            "WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise ReferenceAuthorityError("Reference authority integrity failed.")
        sequence = int(anchor["last_sequence"]) + 1
        previous_mac = str(anchor["last_mac"])
        fields: dict[str, CanonicalValue] = {
            "environment_digest": binding["environment_digest"],
            "event_at": event_at,
            "event_kind": event_kind,
            "expires_at": expires_at,
            "grant_ref_digest": grant_ref_digest,
            "previous_mac": previous_mac,
            "reference_digest": binding["reference_digest"],
            "reference_kind": binding["reference_kind"],
            "requester_digest": binding["requester_digest"],
            "scope_digest": binding["scope_digest"],
            "sequence": sequence,
        }
        event_mac = self._event_mac(fields)
        connection.execute(
            "INSERT INTO reference_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                event_kind,
                grant_ref_digest,
                binding["reference_digest"],
                binding["reference_kind"],
                binding["requester_digest"],
                binding["environment_digest"],
                binding["scope_digest"],
                event_at,
                expires_at,
                previous_mac,
                event_mac,
            ),
        )
        connection.execute(
            "UPDATE reference_anchor SET last_sequence = ?, last_mac = ?, "
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
            latest[str(event["grant_ref_digest"])] = event
        return latest

    @staticmethod
    def _event_binding(event: sqlite3.Row) -> dict[str, str]:
        return {
            "reference_digest": str(event["reference_digest"]),
            "reference_kind": str(event["reference_kind"]),
            "requester_digest": str(event["requester_digest"]),
            "environment_digest": str(event["environment_digest"]),
            "scope_digest": str(event["scope_digest"]),
        }

    @staticmethod
    def _binding_key(binding: dict[str, str]) -> tuple[str, ...]:
        return (
            binding["reference_digest"],
            binding["reference_kind"],
            binding["requester_digest"],
            binding["environment_digest"],
            binding["scope_digest"],
        )

    @staticmethod
    def _event_fields(event: sqlite3.Row) -> dict[str, CanonicalValue]:
        return {
            "environment_digest": str(event["environment_digest"]),
            "event_at": int(event["event_at"]),
            "event_kind": str(event["event_kind"]),
            "expires_at": int(event["expires_at"]),
            "grant_ref_digest": str(event["grant_ref_digest"]),
            "previous_mac": str(event["previous_mac"]),
            "reference_digest": str(event["reference_digest"]),
            "reference_kind": str(event["reference_kind"]),
            "requester_digest": str(event["requester_digest"]),
            "scope_digest": str(event["scope_digest"]),
            "sequence": int(event["sequence"]),
        }

    def _event_mac(self, fields: dict[str, CanonicalValue]) -> str:
        return hmac.new(
            self._key,
            b"reference-event\x00" + canonical_json(fields).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _anchor_mac(self, sequence: int, last_mac: str, last_seen_at: int) -> str:
        return hmac.new(
            self._key,
            b"reference-anchor\x00"
            + canonical_json(
                {
                    "last_mac": last_mac,
                    "last_seen_at": last_seen_at,
                    "last_sequence": sequence,
                }
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


__all__ = [
    "MonotonicReferenceAuthorityCheckpoint",
    "PersistentReferenceAuthority",
    "ReferenceAuthorityCheckpointError",
    "ReferenceAuthorityError",
    "ReferenceAuthorityStoreTail",
]
