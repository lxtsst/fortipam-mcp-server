"""Owner-protected exact approver-delegation authority for V4 planning.

The authority is a trusted local composition boundary, never an MCP Tool. It
stores only digests and bounded policy metadata, has no OAuth credential,
product client, adapter, or execution transition, and returns only an exact
authorization decision for an already authenticated requester and approver.
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

from .approval import (
    ApproverAuthorizationDecision,
    AuthenticatedApprover,
    approval_action_bindings_digest,
    approval_action_set_digest,
    approval_delegation_digest,
)
from .canonical import CanonicalValue, canonical_digest, canonical_json
from .models import (
    AuthenticatedRequester,
    PlanningContractError,
    PreparedPlan,
    require_code,
    require_digest,
    require_ref,
    require_version,
)
from .policy import PlanPolicyDecision


_SCHEMA_VERSION = 1
_CHAIN_ROOT = "approver-authority-chain-root"
_ISSUE = "issue"
_REVOKE = "revoke"
_MAX_EVENTS = 10_000


class ApproverAuthorityError(PlanningContractError):
    """Stable failure for invalid or unavailable delegation authority state."""


class ApproverAuthorityCheckpointError(RuntimeError):
    """Raised when the external Authority checkpoint cannot be trusted."""


@dataclass(frozen=True, slots=True)
class ApproverAuthorityStoreTail:
    """Value-free delegation-ledger and time-watermark position."""

    store_ref: str
    sequence: int
    chain_mac: str
    last_seen_at: int

    @classmethod
    def empty(cls, store_ref: str) -> ApproverAuthorityStoreTail:
        """Construct the only initial checkpoint for one Authority store."""

        return cls(store_ref, 0, _CHAIN_ROOT, 0)

    def __post_init__(self) -> None:
        try:
            require_ref(self.store_ref, "approver checkpoint store_ref")
            if self.sequence > 0:
                require_digest(self.chain_mac, "approver checkpoint chain_mac")
        except PlanningContractError as exc:
            raise ApproverAuthorityError(
                "Approver authority checkpoint position is invalid."
            ) from exc
        if (
            type(self.sequence) is not int
            or self.sequence < 0
            or type(self.last_seen_at) is not int
            or self.last_seen_at < 0
            or (self.sequence == 0 and self.chain_mac != _CHAIN_ROOT)
        ):
            raise ApproverAuthorityError(
                "Approver authority checkpoint position is invalid."
            )


class MonotonicApproverAuthorityCheckpoint(Protocol):
    """External compare-and-swap authority for delegation state and time."""

    authority_ref: str

    def verify(self, tail: ApproverAuthorityStoreTail) -> None: ...

    def advance(
        self,
        previous: ApproverAuthorityStoreTail,
        current: ApproverAuthorityStoreTail,
    ) -> None: ...


class PersistentApproverAuthorizationAuthority:
    """Authorize exact, time-bounded approver delegations from digest state."""

    def __init__(
        self,
        database_path: Path,
        hmac_key_path: Path,
        *,
        authority_ref: str,
        monotonic_checkpoint: MonotonicApproverAuthorityCheckpoint | None = None,
        checkpoint_store_ref: str | None = None,
        clock: Callable[[], int] | None = None,
        max_grant_ttl_seconds: int = 3600,
        decision_ttl_seconds: int = 60,
    ) -> None:
        try:
            self.authority_ref = require_ref(
                authority_ref,
                "approver authority_ref",
            )
        except PlanningContractError as exc:
            raise ApproverAuthorityError(
                "Approver authority configuration is invalid."
            ) from exc
        if (
            type(max_grant_ttl_seconds) is not int
            or not 1 <= max_grant_ttl_seconds <= 86_400
            or type(decision_ttl_seconds) is not int
            or not 1 <= decision_ttl_seconds <= max_grant_ttl_seconds
        ):
            raise ApproverAuthorityError("Approver authority lifetime is invalid.")
        if (monotonic_checkpoint is None) is not (checkpoint_store_ref is None):
            raise ApproverAuthorityError(
                "Approver authority checkpoint binding is incomplete."
            )
        self._monotonic_checkpoint = monotonic_checkpoint
        self._checkpoint_store_ref = checkpoint_store_ref
        if monotonic_checkpoint is not None and checkpoint_store_ref is not None:
            try:
                checkpoint_authority_ref = require_ref(
                    monotonic_checkpoint.authority_ref,
                    "approver checkpoint authority_ref",
                )
                require_ref(checkpoint_store_ref, "approver checkpoint store_ref")
                if checkpoint_authority_ref == self.authority_ref:
                    raise PlanningContractError(
                        "Approver and checkpoint authorities must be distinct."
                    )
            except (AttributeError, PlanningContractError) as exc:
                raise ApproverAuthorityError(
                    "Approver authority checkpoint binding is invalid."
                ) from exc
        self._path = Path(database_path)
        self._key_path = Path(hmac_key_path)
        if (
            not self._path.is_absolute()
            or not self._key_path.is_absolute()
            or self._path == self._key_path
        ):
            raise ApproverAuthorityError(
                "Approver authority protected paths are invalid."
            )
        self._clock = clock or (lambda: int(time.time()))
        self._max_grant_ttl_seconds = max_grant_ttl_seconds
        self._decision_ttl_seconds = decision_ttl_seconds
        self._key = self._load_key()
        checkpoint_key_matcher = getattr(
            self._monotonic_checkpoint,
            "uses_key_material",
            None,
        )
        if callable(checkpoint_key_matcher) and checkpoint_key_matcher(self._key) is True:
            raise ApproverAuthorityError(
                "Approver and checkpoint Authority HMAC keys must be independent."
            )
        self._prepare_database_file()
        with self._connect() as connection:
            self._initialize(connection)
            self._verify(connection)

    @property
    def monotonic_checkpoint_protocol_bound(self) -> bool:
        """Report whether rollback protection is bound outside this database."""

        return self._monotonic_checkpoint is not None

    def verify_ready(self) -> None:
        """Revalidate protected state and its external tail before host use."""

        self._assert_owner_only(self._path.parent, directory=True)
        self._assert_owner_only(self._path, directory=False)
        self._assert_owner_only(self._key_path.parent, directory=True)
        self._assert_owner_only(self._key_path, directory=False)
        with self._connect() as connection:
            self._verify(connection)

    def issue(
        self,
        approver: AuthenticatedApprover,
        *,
        environment_ref: str,
        scope_ref: str,
        action_bindings: Sequence[tuple[str, str]],
        policy_version: str,
        expires_at: int,
        now_epoch: int | None = None,
    ) -> str:
        """Create one private revocation handle for an exact delegation."""

        now = self._time(now_epoch)
        try:
            action_set_digest = approval_action_bindings_digest(action_bindings)
        except PlanningContractError as exc:
            raise ApproverAuthorityError(
                "Approver delegation input is invalid."
            ) from exc
        binding = self._binding(
            approver,
            environment_ref=environment_ref,
            scope_ref=scope_ref,
            action_set_digest=action_set_digest,
            policy_version=policy_version,
        )
        if (
            type(expires_at) is not int
            or expires_at <= now
            or expires_at > now + self._max_grant_ttl_seconds
        ):
            raise ApproverAuthorityError("Approver delegation lifetime is invalid.")
        grant_ref = f"approver-delegation-{secrets.token_hex(16)}"
        grant_ref_digest = canonical_digest(grant_ref)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            events = self._verify(connection)
            previous_tail = self._checkpoint_tail(connection)
            self._observe_time(connection, now)
            if len(events) >= _MAX_EVENTS:
                raise ApproverAuthorityError(
                    "Approver authority event bound exceeded."
                )
            if any(
                self._event_binding(event) == binding
                and event["event_kind"] == _ISSUE
                and int(event["expires_at"]) > now
                for event in self._latest(events).values()
            ):
                raise ApproverAuthorityError(
                    "An active approver delegation already exists."
                )
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
        return grant_ref

    def revoke(self, grant_ref: str, *, now_epoch: int | None = None) -> None:
        """Revoke one exact private handle without accepting identity data."""

        try:
            grant_ref_digest = canonical_digest(
                require_ref(grant_ref, "approver delegation_ref")
            )
        except PlanningContractError as exc:
            raise ApproverAuthorityError(
                "Approver delegation is unavailable."
            ) from exc
        now = self._time(now_epoch)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            events = self._verify(connection)
            previous_tail = self._checkpoint_tail(connection)
            self._observe_time(connection, now)
            event = self._latest(events).get(grant_ref_digest)
            if (
                event is None
                or event["event_kind"] != _ISSUE
                or int(event["expires_at"]) <= now
            ):
                raise ApproverAuthorityError("Approver delegation is unavailable.")
            if len(events) >= _MAX_EVENTS:
                raise ApproverAuthorityError(
                    "Approver authority event bound exceeded."
                )
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
        plan: PreparedPlan,
        decision: PlanPolicyDecision,
        requester: AuthenticatedRequester,
        approver: AuthenticatedApprover,
        *,
        now_epoch: int,
    ) -> ApproverAuthorizationDecision:
        """Return one exact authorized decision or fail closed."""

        now = self._time(now_epoch)
        requester_identity_digest = requester.identity_digest
        approver_identity_digest = approver.identity_digest
        if (
            requester_identity_digest is None
            or approver_identity_digest is None
            or requester.identity_authority_ref != approver.identity_authority_ref
            or requester.subject_namespace != approver.subject_namespace
            or requester_identity_digest == approver_identity_digest
            or requester.digest == approver.digest
            or plan.plan_ref != decision.plan_ref
            or plan.plan_digest != decision.plan_digest
            or plan.requester_digest != requester.digest
            or decision.requester_digest != requester.digest
            or now < decision.issued_at
            or now >= decision.expires_at
            or now < plan.created_at
            or now >= plan.expires_at
        ):
            raise ApproverAuthorityError(
                "Approver authorization context is unavailable."
            )
        assert approver.identity_authority_ref is not None
        assert approver.subject_namespace is not None
        binding = self._binding(
            approver,
            environment_ref=plan.environment_ref,
            scope_ref=plan.scope_ref,
            action_set_digest=approval_action_set_digest(plan),
            policy_version=decision.policy_version,
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
            if len(matches) != 1:
                raise ApproverAuthorityError("Approver delegation is unavailable.")
            expires_at = min(
                int(matches[0]["expires_at"]),
                decision.expires_at,
                plan.expires_at,
                now + self._decision_ttl_seconds,
            )
            current_tail = self._checkpoint_tail(connection)
            connection.commit()
            self._advance_monotonic_checkpoint(previous_tail, current_tail)

        authorization_ref = f"approver-authorization-{secrets.token_hex(16)}"
        values: dict[str, CanonicalValue] = {
            "action_set_digest": binding["action_set_digest"],
            "approval_class": binding["approval_class"],
            "approver_digest": approver.digest,
            "approver_identity_digest": approver_identity_digest,
            "authority_ref": self.authority_ref,
            "authorization_ref": authorization_ref,
            "authorized": True,
            "checked_at": now,
            "delegated_role": binding["delegated_role"],
            "delegation_digest": approval_delegation_digest(
                plan,
                decision,
                approver,
            ),
            "environment_digest": binding["environment_digest"],
            "execution_authorized": False,
            "executor_separation_required": True,
            "expires_at": expires_at,
            "identity_authority_ref": approver.identity_authority_ref,
            "plan_digest": plan.plan_digest,
            "plan_ref": plan.plan_ref,
            "policy_decision_digest": decision.decision_digest,
            "policy_decision_ref": decision.decision_ref,
            "policy_version": decision.policy_version,
            "requester_digest": requester.digest,
            "requester_identity_digest": requester_identity_digest,
            "scope_digest": binding["scope_digest"],
            "separation_required": True,
            "subject_namespace": approver.subject_namespace,
        }
        return ApproverAuthorizationDecision(
            authorization_ref=authorization_ref,
            authority_ref=self.authority_ref,
            plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest,
            policy_decision_ref=decision.decision_ref,
            policy_decision_digest=decision.decision_digest,
            policy_version=decision.policy_version,
            requester_digest=requester.digest,
            requester_identity_digest=requester_identity_digest,
            approver_digest=approver.digest,
            approver_identity_digest=approver_identity_digest,
            identity_authority_ref=approver.identity_authority_ref,
            subject_namespace=approver.subject_namespace,
            environment_digest=binding["environment_digest"],
            scope_digest=binding["scope_digest"],
            action_set_digest=binding["action_set_digest"],
            delegation_digest=approval_delegation_digest(
                plan,
                decision,
                approver,
            ),
            delegated_role=binding["delegated_role"],
            approval_class=binding["approval_class"],
            separation_required=True,
            executor_separation_required=True,
            authorized=True,
            execution_authorized=False,
            checked_at=now,
            expires_at=expires_at,
            authorization_digest=canonical_digest(values),
        )

    def uses_key_material(self, candidate: bytes) -> bool:
        """Return only whether trusted composition reused this exact key."""

        return type(candidate) is bytes and hmac.compare_digest(self._key, candidate)

    def shares_key_material_with(self, candidate: object) -> bool:
        """Compare keys without returning this Authority's protected material."""

        matcher = getattr(candidate, "uses_key_material", None)
        if not callable(matcher):
            return True
        try:
            return matcher(self._key) is not False
        except Exception:
            return True

    def _binding(
        self,
        approver: AuthenticatedApprover,
        *,
        environment_ref: str,
        scope_ref: str,
        action_set_digest: str,
        policy_version: str,
    ) -> dict[str, str]:
        if not isinstance(approver, AuthenticatedApprover):
            raise ApproverAuthorityError("Approver delegation input is invalid.")
        identity_digest = approver.identity_digest
        if (
            identity_digest is None
            or approver.identity_authority_ref is None
            or approver.subject_namespace is None
        ):
            raise ApproverAuthorityError("Approver identity binding is unavailable.")
        try:
            return {
                "action_set_digest": require_digest(
                    action_set_digest,
                    "approver action_set_digest",
                ),
                "approval_class": require_code(
                    "independent_approval",
                    "approval_class",
                ),
                "approver_digest": require_digest(
                    approver.digest,
                    "approver_digest",
                ),
                "approver_identity_digest": require_digest(
                    identity_digest,
                    "approver_identity_digest",
                ),
                "delegated_role": require_code(
                    "independent_approver",
                    "delegated_role",
                ),
                "environment_digest": canonical_digest(
                    require_ref(environment_ref, "environment_ref")
                ),
                "identity_authority_digest": canonical_digest(
                    require_ref(
                        approver.identity_authority_ref,
                        "identity_authority_ref",
                    )
                ),
                "policy_version": require_version(
                    policy_version,
                    "policy_version",
                ),
                "scope_digest": canonical_digest(
                    require_ref(scope_ref, "scope_ref")
                ),
                "subject_namespace_digest": canonical_digest(
                    require_ref(
                        approver.subject_namespace,
                        "subject_namespace",
                    )
                ),
            }
        except PlanningContractError as exc:
            raise ApproverAuthorityError(
                "Approver delegation input is invalid."
            ) from exc

    def _time(self, value: int | None) -> int:
        now = self._clock() if value is None else value
        if type(now) is not int or now < 0:
            raise ApproverAuthorityError("Approver authority time is invalid.")
        return now

    def _load_key(self) -> bytes:
        self._assert_owner_only(self._key_path.parent, directory=True)
        self._assert_owner_only(self._key_path, directory=False)
        try:
            key = self._key_path.read_bytes()
        except OSError as exc:
            raise ApproverAuthorityError(
                "Approver authority key is unavailable."
            ) from exc
        if not 32 <= len(key) <= 4096:
            raise ApproverAuthorityError("Approver authority key is invalid.")
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
            raise ApproverAuthorityError(
                "Approver authority state is unavailable."
            ) from exc
        os.chmod(self._path, 0o600)

    @staticmethod
    def _assert_owner_only(path: Path, *, directory: bool) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ApproverAuthorityError(
                "Approver authority protected path is unavailable."
            ) from exc
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if (
            path.is_symlink()
            or not expected_type(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ApproverAuthorityError(
                "Approver authority protected path must be owner-only."
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self, connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, _SCHEMA_VERSION}:
            raise ApproverAuthorityError("Approver authority schema is unavailable.")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS approver_delegation_events (
                sequence INTEGER PRIMARY KEY,
                event_kind TEXT NOT NULL,
                grant_ref_digest TEXT NOT NULL,
                approver_digest TEXT NOT NULL,
                approver_identity_digest TEXT NOT NULL,
                identity_authority_digest TEXT NOT NULL,
                subject_namespace_digest TEXT NOT NULL,
                environment_digest TEXT NOT NULL,
                scope_digest TEXT NOT NULL,
                action_set_digest TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                approval_class TEXT NOT NULL,
                delegated_role TEXT NOT NULL,
                event_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                previous_mac TEXT NOT NULL,
                event_mac TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approver_delegation_anchor (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_sequence INTEGER NOT NULL,
                last_mac TEXT NOT NULL,
                last_seen_at INTEGER NOT NULL,
                anchor_mac TEXT NOT NULL
            );
            """
        )
        connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        count = connection.execute(
            "SELECT COUNT(*) FROM approver_delegation_anchor"
        ).fetchone()[0]
        if count == 0:
            connection.execute(
                "INSERT INTO approver_delegation_anchor VALUES(1, 0, ?, 0, ?)",
                (_CHAIN_ROOT, self._anchor_mac(0, _CHAIN_ROOT, 0)),
            )
        connection.commit()

    def _verify(self, connection: sqlite3.Connection) -> list[sqlite3.Row]:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at, anchor_mac "
            "FROM approver_delegation_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None or not hmac.compare_digest(
            str(anchor["anchor_mac"]),
            self._anchor_mac(
                int(anchor["last_sequence"]),
                str(anchor["last_mac"]),
                int(anchor["last_seen_at"]),
            ),
        ):
            raise ApproverAuthorityError("Approver authority integrity failed.")
        events = connection.execute(
            "SELECT * FROM approver_delegation_events ORDER BY sequence"
        ).fetchall()
        if len(events) > _MAX_EVENTS:
            raise ApproverAuthorityError("Approver authority event bound exceeded.")
        previous_mac = _CHAIN_ROOT
        for expected_sequence, event in enumerate(events, start=1):
            fields = self._event_fields(event)
            if (
                int(event["sequence"]) != expected_sequence
                or str(event["event_kind"]) not in {_ISSUE, _REVOKE}
                or int(event["expires_at"]) <= int(event["event_at"])
                or str(event["previous_mac"]) != previous_mac
                or not hmac.compare_digest(
                    str(event["event_mac"]),
                    self._event_mac(fields),
                )
            ):
                raise ApproverAuthorityError("Approver authority integrity failed.")
            previous_mac = str(event["event_mac"])
        if (
            int(anchor["last_sequence"]) != len(events)
            or str(anchor["last_mac"]) != previous_mac
        ):
            raise ApproverAuthorityError("Approver authority integrity failed.")
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
    ) -> ApproverAuthorityStoreTail | None:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at "
            "FROM approver_delegation_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise ApproverAuthorityError("Approver authority integrity failed.")
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
    ) -> ApproverAuthorityStoreTail | None:
        if self._monotonic_checkpoint is None:
            return None
        if self._checkpoint_store_ref is None:
            raise ApproverAuthorityError(
                "Approver authority checkpoint store binding is unavailable."
            )
        return ApproverAuthorityStoreTail(
            self._checkpoint_store_ref,
            sequence,
            chain_mac,
            last_seen_at,
        )

    def _verify_monotonic_checkpoint(
        self,
        tail: ApproverAuthorityStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if tail is None:
            raise ApproverAuthorityError(
                "Approver authority checkpoint state is unavailable."
            )
        try:
            checkpoint.verify(tail)
        except ApproverAuthorityCheckpointError as exc:
            raise ApproverAuthorityError(
                "Approver authority checkpoint verification failed."
            ) from exc

    def _advance_monotonic_checkpoint(
        self,
        previous: ApproverAuthorityStoreTail | None,
        current: ApproverAuthorityStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if previous is None or current is None:
            raise ApproverAuthorityError(
                "Approver authority checkpoint state is unavailable."
            )
        if previous == current:
            return
        try:
            checkpoint.advance(previous, current)
        except ApproverAuthorityCheckpointError as exc:
            raise ApproverAuthorityError(
                "Approver authority checkpoint advance failed."
            ) from exc

    def _observe_time(self, connection: sqlite3.Connection, now: int) -> None:
        anchor = connection.execute(
            "SELECT last_sequence, last_mac, last_seen_at "
            "FROM approver_delegation_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None or now < int(anchor["last_seen_at"]):
            raise ApproverAuthorityError("Approver authority time moved backwards.")
        connection.execute(
            "UPDATE approver_delegation_anchor SET last_seen_at = ?, "
            "anchor_mac = ? WHERE singleton = 1",
            (
                now,
                self._anchor_mac(
                    int(anchor["last_sequence"]),
                    str(anchor["last_mac"]),
                    now,
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
            "SELECT last_sequence, last_mac, last_seen_at "
            "FROM approver_delegation_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise ApproverAuthorityError("Approver authority integrity failed.")
        sequence = int(anchor["last_sequence"]) + 1
        previous_mac = str(anchor["last_mac"])
        fields: dict[str, CanonicalValue] = {
            **binding,
            "event_at": event_at,
            "event_kind": event_kind,
            "expires_at": expires_at,
            "grant_ref_digest": grant_ref_digest,
            "previous_mac": previous_mac,
            "sequence": sequence,
        }
        event_mac = self._event_mac(fields)
        connection.execute(
            "INSERT INTO approver_delegation_events VALUES(?, ?, ?, ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                event_kind,
                grant_ref_digest,
                binding["approver_digest"],
                binding["approver_identity_digest"],
                binding["identity_authority_digest"],
                binding["subject_namespace_digest"],
                binding["environment_digest"],
                binding["scope_digest"],
                binding["action_set_digest"],
                binding["policy_version"],
                binding["approval_class"],
                binding["delegated_role"],
                event_at,
                expires_at,
                previous_mac,
                event_mac,
            ),
        )
        connection.execute(
            "UPDATE approver_delegation_anchor SET last_sequence = ?, "
            "last_mac = ?, anchor_mac = ? WHERE singleton = 1",
            (
                sequence,
                event_mac,
                self._anchor_mac(
                    sequence,
                    event_mac,
                    int(anchor["last_seen_at"]),
                ),
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
            "action_set_digest": str(event["action_set_digest"]),
            "approval_class": str(event["approval_class"]),
            "approver_digest": str(event["approver_digest"]),
            "approver_identity_digest": str(event["approver_identity_digest"]),
            "delegated_role": str(event["delegated_role"]),
            "environment_digest": str(event["environment_digest"]),
            "identity_authority_digest": str(event["identity_authority_digest"]),
            "policy_version": str(event["policy_version"]),
            "scope_digest": str(event["scope_digest"]),
            "subject_namespace_digest": str(event["subject_namespace_digest"]),
        }

    @classmethod
    def _event_fields(cls, event: sqlite3.Row) -> dict[str, CanonicalValue]:
        return {
            **cls._event_binding(event),
            "event_at": int(event["event_at"]),
            "event_kind": str(event["event_kind"]),
            "expires_at": int(event["expires_at"]),
            "grant_ref_digest": str(event["grant_ref_digest"]),
            "previous_mac": str(event["previous_mac"]),
            "sequence": int(event["sequence"]),
        }

    def _event_mac(self, fields: dict[str, CanonicalValue]) -> str:
        return hmac.new(
            self._key,
            b"approver-delegation-event\x00"
            + canonical_json(fields).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _anchor_mac(self, sequence: int, last_mac: str, last_seen_at: int) -> str:
        return hmac.new(
            self._key,
            b"approver-delegation-anchor\x00"
            + canonical_json(
                {
                    "authority_ref_digest": canonical_digest(self.authority_ref),
                    "last_mac": last_mac,
                    "last_seen_at": last_seen_at,
                    "last_sequence": sequence,
                }
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


__all__ = [
    "ApproverAuthorityError",
    "ApproverAuthorityCheckpointError",
    "ApproverAuthorityStoreTail",
    "MonotonicApproverAuthorityCheckpoint",
    "PersistentApproverAuthorizationAuthority",
]
