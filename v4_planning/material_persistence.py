"""Owner-only persistent replay ledger for private C3 material use.

The append-only SQLite ledger stores only keyed digests and closed outcomes.
It never receives a material binding, lease, locator, value, product response,
or provider detail. A matching unfinished claim survives restart as
``IN_PROGRESS`` so the coordinator cannot acquire or consume the lease again.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3
import stat
from typing import Mapping, Protocol

from .material_runtime import (
    MaterialRuntimeError,
    MaterialRuntimeOutcome,
    MaterialUseClaim,
    MaterialUseClaimState,
)


_SCHEMA_VERSION = 1
_CHAIN_ROOT = "material-use-ledger-chain-root-v1"
_MAX_EVENTS = 10_000
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class PersistentMaterialUseStateStoreError(MaterialRuntimeError):
    """Raised when the private material-use ledger cannot be trusted."""


class MaterialUseMonotonicCheckpointError(RuntimeError):
    """Raised when the external material-use checkpoint cannot be trusted."""


@dataclass(frozen=True, slots=True)
class MaterialUseStoreTail:
    """Value-free material-use ledger position bound to one opaque store ref."""

    store_ref: str
    sequence: int
    chain_hmac: str

    @classmethod
    def empty(cls, store_ref: str) -> MaterialUseStoreTail:
        """Construct the only valid initial position for one material store."""

        return cls(store_ref, 0, _CHAIN_ROOT)

    def __post_init__(self) -> None:
        _require_ref(self.store_ref)
        if type(self.sequence) is not int or self.sequence < 0:
            raise PersistentMaterialUseStateStoreError(
                "Material-use checkpoint sequence is invalid."
            )
        if self.sequence == 0:
            if self.chain_hmac != _CHAIN_ROOT:
                raise PersistentMaterialUseStateStoreError(
                    "Empty material-use checkpoint tail is invalid."
                )
            return
        if _DIGEST.fullmatch(self.chain_hmac) is None:
            raise PersistentMaterialUseStateStoreError(
                "Material-use checkpoint chain digest is invalid."
            )


class MonotonicMaterialUseCheckpoint(Protocol):
    """Compare-and-swap authority owned outside the material-use database."""

    authority_ref: str

    def verify(self, tail: MaterialUseStoreTail) -> None: ...

    def advance(
        self,
        previous: MaterialUseStoreTail,
        current: MaterialUseStoreTail,
    ) -> None: ...


class PersistentMaterialUseStateStore:
    """Append-only SQLite/HMAC implementation of MaterialUseStateStore."""

    def __init__(
        self,
        database_path: Path,
        hmac_key_path: Path,
        *,
        monotonic_checkpoint: MonotonicMaterialUseCheckpoint | None = None,
        checkpoint_store_ref: str | None = None,
    ) -> None:
        self._path = Path(database_path)
        self._key_path = Path(hmac_key_path)
        if (monotonic_checkpoint is None) is not (checkpoint_store_ref is None):
            raise PersistentMaterialUseStateStoreError(
                "Material-use checkpoint binding is incomplete."
            )
        self._monotonic_checkpoint = monotonic_checkpoint
        self._checkpoint_store_ref = checkpoint_store_ref
        if monotonic_checkpoint is not None and checkpoint_store_ref is not None:
            try:
                _require_ref(monotonic_checkpoint.authority_ref)
                _require_ref(checkpoint_store_ref)
            except (AttributeError, PersistentMaterialUseStateStoreError) as exc:
                raise PersistentMaterialUseStateStoreError(
                    "Material-use checkpoint binding is invalid."
                ) from exc
        if (
            not self._path.is_absolute()
            or not self._key_path.is_absolute()
            or self._path == self._key_path
        ):
            raise PersistentMaterialUseStateStoreError(
                "Material-use protected paths are invalid."
            )
        created = self._prepare_database_path()
        self._key = self._load_key()
        checkpoint_key_matcher = getattr(
            self._monotonic_checkpoint,
            "uses_key_material",
            None,
        )
        if callable(checkpoint_key_matcher) and checkpoint_key_matcher(self._key) is True:
            raise PersistentMaterialUseStateStoreError(
                "Material-use store and checkpoint keys must be independent."
            )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._initialize(connection, allow_create=created)
                self._read_state(connection)
                connection.commit()
        except PersistentMaterialUseStateStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentMaterialUseStateStoreError(
                "Material-use state integrity validation failed."
            ) from exc

    @property
    def monotonic_checkpoint_protocol_bound(self) -> bool:
        """Report whether rollback protection is bound outside this store."""

        return self._monotonic_checkpoint is not None

    def verify_ready(self) -> None:
        """Revalidate protected state and its external checkpoint."""

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._read_state(connection)
                connection.commit()
        except PersistentMaterialUseStateStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentMaterialUseStateStoreError(
                "Material-use state readiness validation failed."
            ) from exc

    @property
    def claim_count(self) -> int:
        """Count verified reservations, including unfinished claims after restart."""
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._read_state(connection)
                connection.commit()
                return len(state.claims)
        except PersistentMaterialUseStateStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentMaterialUseStateStoreError(
                "Material-use reservation state could not be read safely."
            ) from exc

    def _inspect_claim(self, *, request_digest: str, authorization_digest: str) -> MaterialUseClaim:
        """Inspect the exact existing claim without reserving a missing request."""
        request_key = self._digest_key("request", request_digest)
        authorization_key = self._digest_key("authorization", authorization_digest)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                state = self._read_state(connection)
                existing = state.claims.get(request_key)
                if existing is None or not hmac.compare_digest(existing.authorization_key, authorization_key):
                    raise PersistentMaterialUseStateStoreError("Material-use claim is unavailable.")
                connection.commit()
                return MaterialUseClaim(MaterialUseClaimState.IN_PROGRESS) if existing.outcome is None else (
                    MaterialUseClaim(MaterialUseClaimState.REPLAY, existing.outcome))
        except PersistentMaterialUseStateStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError):
            raise PersistentMaterialUseStateStoreError("Material-use claim cannot be inspected safely.") from None

    def claim(
        self,
        *,
        request_digest: str,
        authorization_digest: str,
    ) -> MaterialUseClaim:
        request_key = self._digest_key("request", request_digest)
        authorization_key = self._digest_key(
            "authorization", authorization_digest
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._read_state(connection)
                existing = state.claims.get(request_key)
                if existing is not None:
                    if not hmac.compare_digest(
                        existing.authorization_key, authorization_key
                    ):
                        raise PersistentMaterialUseStateStoreError(
                            "Material-use claim is unavailable."
                        )
                    connection.commit()
                    if existing.outcome is None:
                        return MaterialUseClaim(MaterialUseClaimState.IN_PROGRESS)
                    return MaterialUseClaim(
                        MaterialUseClaimState.REPLAY,
                        existing.outcome,
                    )
                if authorization_key in state.authorizations:
                    raise PersistentMaterialUseStateStoreError(
                        "Material-use claim is unavailable."
                    )
                self._require_capacity(state.sequence)
                previous_tail = self._checkpoint_tail(state)
                current_tail = self._append(
                    connection,
                    state,
                    event_kind="claim",
                    request_key=request_key,
                    authorization_key=authorization_key,
                    outcome=None,
                )
                connection.commit()
                self._advance_monotonic_checkpoint(previous_tail, current_tail)
                return MaterialUseClaim(MaterialUseClaimState.NEW)
        except PersistentMaterialUseStateStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentMaterialUseStateStoreError(
                "Material-use state could not be claimed safely."
            ) from exc

    def finalize(
        self,
        *,
        request_digest: str,
        authorization_digest: str,
        outcome: MaterialRuntimeOutcome,
    ) -> None:
        if not isinstance(outcome, MaterialRuntimeOutcome):
            raise PersistentMaterialUseStateStoreError(
                "Material-use outcome is invalid."
            )
        request_key = self._digest_key("request", request_digest)
        authorization_key = self._digest_key(
            "authorization", authorization_digest
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._read_state(connection)
                existing = state.claims.get(request_key)
                if (
                    existing is None
                    or existing.outcome is not None
                    or not hmac.compare_digest(
                        existing.authorization_key, authorization_key
                    )
                ):
                    raise PersistentMaterialUseStateStoreError(
                        "Material-use finalization is unavailable."
                    )
                self._require_capacity(state.sequence)
                previous_tail = self._checkpoint_tail(state)
                current_tail = self._append(
                    connection,
                    state,
                    event_kind="finalize",
                    request_key=request_key,
                    authorization_key=authorization_key,
                    outcome=outcome,
                )
                connection.commit()
                self._advance_monotonic_checkpoint(previous_tail, current_tail)
        except PersistentMaterialUseStateStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentMaterialUseStateStoreError(
                "Material-use state could not be finalized safely."
            ) from exc

    def shares_key_material_with(self, other: object) -> bool:
        """Compare private keys without exposing them."""

        other_key = getattr(other, "_key", None)
        return isinstance(other_key, bytes) and hmac.compare_digest(
            self._key, other_key
        )

    def uses_key_material(self, candidate: bytes) -> bool:
        """Return only whether trusted composition reused this exact key."""

        return type(candidate) is bytes and hmac.compare_digest(self._key, candidate)

    def _read_state(self, connection: sqlite3.Connection) -> _State:
        anchor = connection.execute(
            "SELECT last_sequence, last_hmac, anchor_hmac "
            "FROM material_use_integrity_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise PersistentMaterialUseStateStoreError(
                "Material-use integrity anchor is unavailable."
            )
        anchor_sequence = int(anchor["last_sequence"])
        anchor_hmac = str(anchor["last_hmac"])
        if not hmac.compare_digest(
            str(anchor["anchor_hmac"]),
            self._anchor_hmac(anchor_sequence, anchor_hmac),
        ):
            raise PersistentMaterialUseStateStoreError(
                "Material-use integrity anchor is invalid."
            )

        claims: dict[str, _ClaimState] = {}
        authorizations: set[str] = set()
        previous = _CHAIN_ROOT
        sequence = 0
        rows = connection.execute(
            "SELECT sequence, event_kind, request_key, authorization_key, "
            "outcome, previous_hmac, chain_hmac "
            "FROM material_use_ledger ORDER BY sequence"
        ).fetchall()
        if len(rows) > _MAX_EVENTS:
            raise PersistentMaterialUseStateStoreError(
                "Material-use event bound is exceeded."
            )
        for row in rows:
            sequence += 1
            event_kind = str(row["event_kind"])
            request_key = str(row["request_key"])
            authorization_key = str(row["authorization_key"])
            raw_outcome = row["outcome"]
            outcome = (
                None
                if raw_outcome is None
                else MaterialRuntimeOutcome(str(raw_outcome))
            )
            fields = {
                "authorization_key": authorization_key,
                "event_kind": event_kind,
                "outcome": None if outcome is None else outcome.value,
                "previous_hmac": str(row["previous_hmac"]),
                "request_key": request_key,
                "sequence": int(row["sequence"]),
            }
            if (
                int(row["sequence"]) != sequence
                or event_kind not in {"claim", "finalize"}
                or _DIGEST.fullmatch(request_key) is None
                or _DIGEST.fullmatch(authorization_key) is None
                or not hmac.compare_digest(str(row["previous_hmac"]), previous)
                or not hmac.compare_digest(
                    str(row["chain_hmac"]), self._record_hmac(fields)
                )
            ):
                raise PersistentMaterialUseStateStoreError(
                    "Material-use ledger is invalid."
                )
            if event_kind == "claim":
                if (
                    outcome is not None
                    or request_key in claims
                    or authorization_key in authorizations
                ):
                    raise PersistentMaterialUseStateStoreError(
                        "Material-use claim ledger is inconsistent."
                    )
                claims[request_key] = _ClaimState(authorization_key, None)
                authorizations.add(authorization_key)
            else:
                existing = claims.get(request_key)
                if (
                    outcome is None
                    or existing is None
                    or existing.outcome is not None
                    or not hmac.compare_digest(
                        existing.authorization_key, authorization_key
                    )
                ):
                    raise PersistentMaterialUseStateStoreError(
                        "Material-use final ledger is inconsistent."
                    )
                claims[request_key] = _ClaimState(authorization_key, outcome)
            previous = str(row["chain_hmac"])
        if anchor_sequence != sequence or not hmac.compare_digest(
            anchor_hmac, previous
        ):
            raise PersistentMaterialUseStateStoreError(
                "Material-use integrity anchor does not match the ledger."
            )
        state = _State(claims, authorizations, sequence, previous)
        self._verify_monotonic_checkpoint(self._checkpoint_tail(state))
        return state

    def _append(
        self,
        connection: sqlite3.Connection,
        state: _State,
        *,
        event_kind: str,
        request_key: str,
        authorization_key: str,
        outcome: MaterialRuntimeOutcome | None,
    ) -> MaterialUseStoreTail | None:
        sequence = state.sequence + 1
        fields: dict[str, object] = {
            "authorization_key": authorization_key,
            "event_kind": event_kind,
            "outcome": None if outcome is None else outcome.value,
            "previous_hmac": state.last_hmac,
            "request_key": request_key,
            "sequence": sequence,
        }
        chain_hmac = self._record_hmac(fields)
        connection.execute(
            "INSERT INTO material_use_ledger("
            "sequence, event_kind, request_key, authorization_key, outcome, "
            "previous_hmac, chain_hmac) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                event_kind,
                request_key,
                authorization_key,
                fields["outcome"],
                state.last_hmac,
                chain_hmac,
            ),
        )
        connection.execute(
            "UPDATE material_use_integrity_anchor "
            "SET last_sequence = ?, last_hmac = ?, anchor_hmac = ? "
            "WHERE singleton = 1",
            (sequence, chain_hmac, self._anchor_hmac(sequence, chain_hmac)),
        )
        return self._checkpoint_tail_values(sequence, chain_hmac)

    def _checkpoint_tail(
        self,
        state: _State,
    ) -> MaterialUseStoreTail | None:
        return self._checkpoint_tail_values(state.sequence, state.last_hmac)

    def _checkpoint_tail_values(
        self,
        sequence: int,
        chain_hmac: str,
    ) -> MaterialUseStoreTail | None:
        if self._monotonic_checkpoint is None:
            return None
        if self._checkpoint_store_ref is None:
            raise PersistentMaterialUseStateStoreError(
                "Material-use checkpoint store binding is unavailable."
            )
        return MaterialUseStoreTail(
            self._checkpoint_store_ref,
            sequence,
            chain_hmac,
        )

    def _verify_monotonic_checkpoint(
        self,
        tail: MaterialUseStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if tail is None:
            raise PersistentMaterialUseStateStoreError(
                "Material-use checkpoint state is unavailable."
            )
        try:
            checkpoint.verify(tail)
        except MaterialUseMonotonicCheckpointError as exc:
            raise PersistentMaterialUseStateStoreError(
                "Material-use checkpoint verification failed."
            ) from exc

    def _advance_monotonic_checkpoint(
        self,
        previous: MaterialUseStoreTail | None,
        current: MaterialUseStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if previous is None or current is None:
            raise PersistentMaterialUseStateStoreError(
                "Material-use checkpoint state is unavailable."
            )
        try:
            checkpoint.advance(previous, current)
        except MaterialUseMonotonicCheckpointError as exc:
            raise PersistentMaterialUseStateStoreError(
                "Material-use checkpoint advance failed."
            ) from exc

    def _prepare_database_path(self) -> bool:
        try:
            _assert_no_symlink_components(self._path.parent)
            existed = self._path.parent.exists()
            self._path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if not existed:
                os.chmod(self._path.parent, 0o700)
            _assert_owner_only(self._path.parent, directory=True)
            if self._path.exists() or self._path.is_symlink():
                _assert_owner_only(self._path, directory=False)
                return False
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
            os.chmod(self._path, 0o600)
            _assert_owner_only(self._path, directory=False)
            return True
        except PersistentMaterialUseStateStoreError:
            raise
        except OSError as exc:
            raise PersistentMaterialUseStateStoreError(
                "Material-use database path is unsafe."
            ) from exc

    def _load_key(self) -> bytes:
        try:
            _assert_no_symlink_components(self._key_path.parent)
            _assert_owner_only(self._key_path.parent, directory=True)
            _assert_owner_only(self._key_path, directory=False)
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._key_path, flags)
            try:
                value = os.read(descriptor, 129)
            finally:
                os.close(descriptor)
            if not 32 <= len(value) <= 128:
                raise PersistentMaterialUseStateStoreError(
                    "Material-use HMAC key is invalid."
                )
            return value
        except PersistentMaterialUseStateStoreError:
            raise
        except OSError as exc:
            raise PersistentMaterialUseStateStoreError(
                "Material-use HMAC key is invalid."
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        _assert_owner_only(self._path.parent, directory=True)
        _assert_owner_only(self._path, directory=False)
        connection = sqlite3.connect(
            self._path, timeout=5.0, isolation_level=None
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA temp_store=MEMORY")
        return connection

    def _initialize(
        self, connection: sqlite3.Connection, *, allow_create: bool
    ) -> None:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current == 0 and not allow_create:
            raise PersistentMaterialUseStateStoreError(
                "Existing material-use database has no trusted schema."
            )
        if current not in {0, _SCHEMA_VERSION}:
            raise PersistentMaterialUseStateStoreError(
                "Material-use state schema is unsupported."
            )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS material_use_ledger("
            "sequence INTEGER PRIMARY KEY, "
            "event_kind TEXT NOT NULL CHECK(event_kind IN ('claim','finalize')), "
            "request_key TEXT NOT NULL, authorization_key TEXT NOT NULL, "
            "outcome TEXT, previous_hmac TEXT NOT NULL, chain_hmac TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS material_use_integrity_anchor("
            "singleton INTEGER PRIMARY KEY CHECK(singleton = 1), "
            "last_sequence INTEGER NOT NULL, last_hmac TEXT NOT NULL, "
            "anchor_hmac TEXT NOT NULL) WITHOUT ROWID"
        )
        anchor = connection.execute(
            "SELECT singleton FROM material_use_integrity_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            if current != 0 or not allow_create:
                raise PersistentMaterialUseStateStoreError(
                    "Material-use integrity anchor is missing."
                )
            connection.execute(
                "INSERT INTO material_use_integrity_anchor("
                "singleton, last_sequence, last_hmac, anchor_hmac) "
                "VALUES (1, 0, ?, ?)",
                (_CHAIN_ROOT, self._anchor_hmac(0, _CHAIN_ROOT)),
            )
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def _digest_key(self, domain: str, value: str) -> str:
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise PersistentMaterialUseStateStoreError(
                "Material-use digest is invalid."
            )
        return hmac.new(
            self._key,
            domain.encode("ascii") + b"\x00" + value.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _record_hmac(self, fields: Mapping[str, object]) -> str:
        return hmac.new(
            self._key,
            _canonical_bytes(fields),
            hashlib.sha256,
        ).hexdigest()

    def _anchor_hmac(self, sequence: int, chain_hmac: str) -> str:
        return hmac.new(
            self._key,
            _canonical_bytes(
                {
                    "domain": "material-use-tail-anchor-v1",
                    "last_hmac": chain_hmac,
                    "last_sequence": sequence,
                }
            ),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _require_capacity(sequence: int) -> None:
        if sequence >= _MAX_EVENTS:
            raise PersistentMaterialUseStateStoreError(
                "Material-use event bound is exceeded."
            )


class _ClaimState:
    __slots__ = ("authorization_key", "outcome")

    def __init__(
        self,
        authorization_key: str,
        outcome: MaterialRuntimeOutcome | None,
    ) -> None:
        self.authorization_key = authorization_key
        self.outcome = outcome


class _State:
    __slots__ = ("claims", "authorizations", "sequence", "last_hmac")

    def __init__(
        self,
        claims: dict[str, _ClaimState],
        authorizations: set[str],
        sequence: int,
        last_hmac: str,
    ) -> None:
        self.claims = claims
        self.authorizations = authorizations
        self.sequence = sequence
        self.last_hmac = last_hmac


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _require_ref(value: str) -> None:
    if not isinstance(value, str) or _REF.fullmatch(value) is None:
        raise PersistentMaterialUseStateStoreError(
            "Material-use checkpoint reference is invalid."
        )


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PersistentMaterialUseStateStoreError(
            "Material-use protected path is unavailable."
        ) from exc
    expected_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(
        info.st_mode
    )
    if (
        not expected_type
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise PersistentMaterialUseStateStoreError(
            "Material-use protected path is unsafe."
        )


def _assert_no_symlink_components(path: Path) -> None:
    current = path
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise PersistentMaterialUseStateStoreError(
                "Material-use protected path is unsafe."
            )
        current = current.parent


__all__ = [
    "MaterialUseMonotonicCheckpointError",
    "MaterialUseStoreTail",
    "MonotonicMaterialUseCheckpoint",
    "PersistentMaterialUseStateStore",
    "PersistentMaterialUseStateStoreError",
]
