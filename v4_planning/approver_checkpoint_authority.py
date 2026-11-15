"""Owner-only compare-and-swap Authority for approver-ledger tails."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
import stat

from .approver_authority import (
    ApproverAuthorityCheckpointError,
    ApproverAuthorityStoreTail,
)
from .canonical import CanonicalValue, canonical_json
from .models import PlanningContractError, require_ref


_SCHEMA_VERSION = 1
_AUTHORITY_CHAIN_ROOT = "approver-checkpoint-authority-chain-root"
_MAX_EVENTS = 100_000


class PersistentApproverCheckpointAuthority:
    """Persist exact approver Authority tails with atomic compare-and-swap."""

    def __init__(
        self,
        database_path: Path,
        hmac_key_path: Path,
        *,
        authority_ref: str,
    ) -> None:
        try:
            self.authority_ref = require_ref(
                authority_ref,
                "approver checkpoint authority_ref",
            )
        except PlanningContractError as exc:
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority configuration is invalid."
            ) from exc
        self._path = Path(database_path)
        self._key_path = Path(hmac_key_path)
        if (
            not self._path.is_absolute()
            or not self._key_path.is_absolute()
            or self._path == self._key_path
        ):
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority paths are invalid."
            )
        self._key = self._load_key()
        self._prepare_database_file()
        try:
            with self._connect() as connection:
                self._initialize(connection)
                self._verify_integrity(connection)
        except ApproverAuthorityCheckpointError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority integrity failed."
            ) from exc

    def verify(self, tail: ApproverAuthorityStoreTail) -> None:
        """Require the supplied tail to equal this Authority's current tail."""

        self._require_tail(tail)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                events = self._verify_integrity(connection)
                expected = self._current_tail(events, tail.store_ref)
                if not _tails_equal(expected, tail):
                    raise ApproverAuthorityCheckpointError(
                        "Approver checkpoint position does not match."
                    )
                connection.commit()
        except ApproverAuthorityCheckpointError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority is unavailable."
            ) from exc

    def advance(
        self,
        previous: ApproverAuthorityStoreTail,
        current: ApproverAuthorityStoreTail,
    ) -> None:
        """Atomically advance one exact event or time-watermark position."""

        self._require_tail(previous)
        self._require_tail(current)
        if not _valid_advance(previous, current):
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint compare-and-swap is invalid."
            )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                events = self._verify_integrity(connection)
                expected = self._current_tail(events, previous.store_ref)
                if not _tails_equal(expected, previous):
                    raise ApproverAuthorityCheckpointError(
                        "Approver checkpoint compare-and-swap failed."
                    )
                if len(events) >= _MAX_EVENTS:
                    raise ApproverAuthorityCheckpointError(
                        "Approver checkpoint Authority event bound exceeded."
                    )
                self._append_event(connection, previous, current)
                connection.commit()
        except ApproverAuthorityCheckpointError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority is unavailable."
            ) from exc

    def verify_ready(self) -> None:
        """Revalidate protected state before trusted composition."""

        self._assert_owner_only(self._path.parent, directory=True)
        self._assert_owner_only(self._path, directory=False)
        self._assert_owner_only(self._key_path.parent, directory=True)
        self._assert_owner_only(self._key_path, directory=False)
        with self._connect() as connection:
            self._verify_integrity(connection)

    def uses_key_material(self, candidate: bytes) -> bool:
        """Return only whether trusted composition reused this exact key."""

        return type(candidate) is bytes and hmac.compare_digest(self._key, candidate)

    def shares_key_material_with(self, candidate: object) -> bool:
        """Compare protected keys without exposing either key."""

        matcher = getattr(candidate, "uses_key_material", None)
        return callable(matcher) and matcher(self._key) is True

    @staticmethod
    def _require_tail(tail: object) -> None:
        if not isinstance(tail, ApproverAuthorityStoreTail):
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint position is invalid."
            )

    def _load_key(self) -> bytes:
        self._assert_owner_only(self._key_path.parent, directory=True)
        self._assert_owner_only(self._key_path, directory=False)
        try:
            key = self._key_path.read_bytes()
        except OSError as exc:
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority key is unavailable."
            ) from exc
        if not 32 <= len(key) <= 4096:
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority key is invalid."
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
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority state is unavailable."
            ) from exc
        os.chmod(self._path, 0o600)

    @staticmethod
    def _assert_owner_only(path: Path, *, directory: bool) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority path is unavailable."
            ) from exc
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if (
            path.is_symlink()
            or not expected_type(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority path must be owner-only."
            )

    def _connect(self) -> sqlite3.Connection:
        self._assert_owner_only(self._path.parent, directory=True)
        self._assert_owner_only(self._path, directory=False)
        connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    def _initialize(self, connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, _SCHEMA_VERSION}:
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority schema is unavailable."
            )
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS approver_checkpoint_events (
                event_sequence INTEGER PRIMARY KEY,
                store_ref TEXT NOT NULL,
                previous_sequence INTEGER NOT NULL,
                previous_chain_mac TEXT NOT NULL,
                previous_last_seen_at INTEGER NOT NULL,
                current_sequence INTEGER NOT NULL,
                current_chain_mac TEXT NOT NULL,
                current_last_seen_at INTEGER NOT NULL,
                previous_event_mac TEXT NOT NULL,
                event_mac TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approver_checkpoint_anchor (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_event_sequence INTEGER NOT NULL,
                last_event_mac TEXT NOT NULL,
                anchor_mac TEXT NOT NULL
            );
            """
        )
        connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        if connection.execute(
            "SELECT COUNT(*) FROM approver_checkpoint_anchor"
        ).fetchone()[0] == 0:
            connection.execute(
                "INSERT INTO approver_checkpoint_anchor VALUES(1, 0, ?, ?)",
                (
                    _AUTHORITY_CHAIN_ROOT,
                    self._anchor_mac(0, _AUTHORITY_CHAIN_ROOT),
                ),
            )
        connection.commit()

    def _verify_integrity(self, connection: sqlite3.Connection) -> list[sqlite3.Row]:
        anchor = connection.execute(
            "SELECT last_event_sequence, last_event_mac, anchor_mac "
            "FROM approver_checkpoint_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None or not hmac.compare_digest(
            str(anchor["anchor_mac"]),
            self._anchor_mac(
                int(anchor["last_event_sequence"]),
                str(anchor["last_event_mac"]),
            ),
        ):
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority integrity failed."
            )
        events = connection.execute(
            "SELECT * FROM approver_checkpoint_events ORDER BY event_sequence"
        ).fetchall()
        if len(events) > _MAX_EVENTS:
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority event bound exceeded."
            )
        previous_event_mac = _AUTHORITY_CHAIN_ROOT
        current_by_store: dict[str, ApproverAuthorityStoreTail] = {}
        for expected_sequence, event in enumerate(events, start=1):
            fields = self._event_fields(event)
            store_ref = str(event["store_ref"])
            previous = ApproverAuthorityStoreTail(
                store_ref,
                int(event["previous_sequence"]),
                str(event["previous_chain_mac"]),
                int(event["previous_last_seen_at"]),
            )
            current = ApproverAuthorityStoreTail(
                store_ref,
                int(event["current_sequence"]),
                str(event["current_chain_mac"]),
                int(event["current_last_seen_at"]),
            )
            expected_previous = current_by_store.get(
                store_ref,
                ApproverAuthorityStoreTail.empty(store_ref),
            )
            if (
                int(event["event_sequence"]) != expected_sequence
                or str(event["previous_event_mac"]) != previous_event_mac
                or not _tails_equal(previous, expected_previous)
                or not _valid_advance(previous, current)
                or not hmac.compare_digest(
                    str(event["event_mac"]),
                    self._event_mac(fields),
                )
            ):
                raise ApproverAuthorityCheckpointError(
                    "Approver checkpoint Authority integrity failed."
                )
            current_by_store[store_ref] = current
            previous_event_mac = str(event["event_mac"])
        if (
            int(anchor["last_event_sequence"]) != len(events)
            or str(anchor["last_event_mac"]) != previous_event_mac
        ):
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority integrity failed."
            )
        return events

    def _append_event(
        self,
        connection: sqlite3.Connection,
        previous: ApproverAuthorityStoreTail,
        current: ApproverAuthorityStoreTail,
    ) -> None:
        anchor = connection.execute(
            "SELECT last_event_sequence, last_event_mac "
            "FROM approver_checkpoint_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise ApproverAuthorityCheckpointError(
                "Approver checkpoint Authority integrity failed."
            )
        event_sequence = int(anchor["last_event_sequence"]) + 1
        previous_event_mac = str(anchor["last_event_mac"])
        fields: dict[str, CanonicalValue] = {
            "current_chain_mac": current.chain_mac,
            "current_last_seen_at": current.last_seen_at,
            "current_sequence": current.sequence,
            "event_sequence": event_sequence,
            "previous_chain_mac": previous.chain_mac,
            "previous_event_mac": previous_event_mac,
            "previous_last_seen_at": previous.last_seen_at,
            "previous_sequence": previous.sequence,
            "store_ref": current.store_ref,
        }
        event_mac = self._event_mac(fields)
        connection.execute(
            "INSERT INTO approver_checkpoint_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_sequence,
                current.store_ref,
                previous.sequence,
                previous.chain_mac,
                previous.last_seen_at,
                current.sequence,
                current.chain_mac,
                current.last_seen_at,
                previous_event_mac,
                event_mac,
            ),
        )
        connection.execute(
            "UPDATE approver_checkpoint_anchor SET last_event_sequence = ?, "
            "last_event_mac = ?, anchor_mac = ? WHERE singleton = 1",
            (
                event_sequence,
                event_mac,
                self._anchor_mac(event_sequence, event_mac),
            ),
        )

    @staticmethod
    def _current_tail(
        events: list[sqlite3.Row],
        store_ref: str,
    ) -> ApproverAuthorityStoreTail:
        require_ref(store_ref, "approver checkpoint store_ref")
        for event in reversed(events):
            if str(event["store_ref"]) == store_ref:
                return ApproverAuthorityStoreTail(
                    store_ref,
                    int(event["current_sequence"]),
                    str(event["current_chain_mac"]),
                    int(event["current_last_seen_at"]),
                )
        return ApproverAuthorityStoreTail.empty(store_ref)

    @staticmethod
    def _event_fields(event: sqlite3.Row) -> dict[str, CanonicalValue]:
        return {
            "current_chain_mac": str(event["current_chain_mac"]),
            "current_last_seen_at": int(event["current_last_seen_at"]),
            "current_sequence": int(event["current_sequence"]),
            "event_sequence": int(event["event_sequence"]),
            "previous_chain_mac": str(event["previous_chain_mac"]),
            "previous_event_mac": str(event["previous_event_mac"]),
            "previous_last_seen_at": int(event["previous_last_seen_at"]),
            "previous_sequence": int(event["previous_sequence"]),
            "store_ref": str(event["store_ref"]),
        }

    def _event_mac(self, fields: dict[str, CanonicalValue]) -> str:
        return hmac.new(
            self._key,
            b"approver-checkpoint-event\x00"
            + canonical_json(fields).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _anchor_mac(self, event_sequence: int, last_event_mac: str) -> str:
        return hmac.new(
            self._key,
            b"approver-checkpoint-anchor\x00"
            + canonical_json(
                {
                    "last_event_mac": last_event_mac,
                    "last_event_sequence": event_sequence,
                }
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


def _valid_advance(
    previous: ApproverAuthorityStoreTail,
    current: ApproverAuthorityStoreTail,
) -> bool:
    if previous.store_ref != current.store_ref:
        return False
    event_advance = (
        current.sequence == previous.sequence + 1
        and current.last_seen_at >= previous.last_seen_at
        and not hmac.compare_digest(current.chain_mac, previous.chain_mac)
    )
    time_advance = (
        current.sequence == previous.sequence
        and hmac.compare_digest(current.chain_mac, previous.chain_mac)
        and current.last_seen_at > previous.last_seen_at
    )
    return event_advance or time_advance


def _tails_equal(
    left: ApproverAuthorityStoreTail,
    right: ApproverAuthorityStoreTail,
) -> bool:
    return (
        left.store_ref == right.store_ref
        and left.sequence == right.sequence
        and left.last_seen_at == right.last_seen_at
        and hmac.compare_digest(left.chain_mac, right.chain_mac)
    )


__all__ = ["PersistentApproverCheckpointAuthority"]
