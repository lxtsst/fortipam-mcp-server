"""One real FortiPAM child-Folder workflow for the V4 controlled profile.

This deliberately small workflow is the usable Beta 7 path.  It reads the
actual Folder collection, renders one bounded Current/Proposed/Expected
preview, records one explicit confirmation, creates exactly that child Folder,
and reads the collection again to verify the result.  It has no generic CRUD
surface, no secret inputs, and no bulk behaviour.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Any, Protocol

from .folder_create_contract import FolderCreateRequest
from .folder_m4_adapter import (
    ChildFolderCreateM4Adapter,
    ChildFolderLogicalState,
    PreparedChildFolderCreate,
)


WORKFLOW_CONTRACT = "fortipam_v4_child_folder_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 child Folder workflow is unavailable."
_TTL_SECONDS = 600


class ChildFolderWorkflowError(RuntimeError):
    """Stable, non-disclosing error for the bounded live workflow."""


class ChildFolderWorkflowTransport(Protocol):
    """The only two product operations needed by this exact workflow."""

    def read_collection(self) -> Mapping[str, object]: ...

    def create_child(self, body: Mapping[str, object]) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class _WorkflowRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    name: str
    parent_folder_id: int
    current_digest: str
    expected_digest: str
    state: str
    expires_at: int


class ChildFolderLiveWorkflow:
    """Persistent, single-confirmation workflow for one inherited child Folder."""

    def __init__(
        self,
        database: Path,
        hmac_key_path: Path,
        transport: ChildFolderWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._database = database
        self._key = _load_key(hmac_key_path)
        self._transport = transport
        self._clock = clock or _now
        self._prepare_database()

    def preview(
        self,
        *,
        folder_name: str,
        parent_folder_id: int,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current FortiPAM state and create one expiring preview."""

        request = FolderCreateRequest.child(folder_name, parent_folder_id)
        _require_requester(requester_digest)
        current = self._read_state(request, require_parent=True)
        if current.exists:
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)
        now_epoch = self._clock()
        record = _WorkflowRecord(
            preview_ref="folder-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            name=request.name,
            parent_folder_id=parent_folder_id,
            current_digest=current.digest(),
            expected_digest=ChildFolderLogicalState.expected(request).digest(),
            state="previewed",
            expires_at=now_epoch + _TTL_SECONDS,
        )
        self._insert(record)
        return self._preview_projection(record)

    def confirm(
        self,
        preview_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        """Re-read Current State and issue one exact execution reference."""

        record = self._get_by_preview(preview_ref)
        self._validate_record(record, requester_digest, expected_state="previewed")
        request = FolderCreateRequest.child(record.name, record.parent_folder_id)
        if self._read_state(request, require_parent=True).digest() != record.current_digest:
            self._set_state(record.preview_ref, "invalidated")
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)
        authorization_ref = "folder-authorized-" + secrets.token_urlsafe(24)
        self._authorize(record.preview_ref, authorization_ref)
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": record.expires_at,
            "device_write_executed": False,
        }

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        """Run exactly one authorized create with pre-write and readback checks."""

        record = self._get_by_authorization(authorization_ref)
        if record.state == "completed":
            self._validate_requester(record, requester_digest)
            return self._result(record, idempotent_replay=True)
        self._validate_record(record, requester_digest, expected_state="authorized")
        if not self._reserve(record.preview_ref):
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)
        request = FolderCreateRequest.child(record.name, record.parent_folder_id)
        try:
            current = self._read_state(request, require_parent=True)
            if current.digest() != record.current_digest:
                self._set_state(record.preview_ref, "invalidated")
                raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)
            response = self._transport.create_child(request.body())
            if response.get("http_status") != 200 or not _valid_mkey(response.get("mkey")):
                self._set_state(record.preview_ref, "reconciliation_required")
                return self._result(record, idempotent_replay=False)
            if self._read_state(request, require_parent=True).digest() != record.expected_digest:
                self._set_state(record.preview_ref, "reconciliation_required")
                return self._result(record, idempotent_replay=False)
        except ChildFolderWorkflowError:
            raise
        except Exception:
            self._set_state(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        self._set_state(record.preview_ref, "completed")
        return self._result(record, idempotent_replay=False)

    def _read_state(
        self,
        request: FolderCreateRequest,
        *,
        require_parent: bool,
    ) -> ChildFolderLogicalState:
        try:
            payload = self._transport.read_collection()
        except Exception as exc:
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if require_parent and not _has_parent(payload, request.parent_folder_id):
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)
        try:
            prepared = PreparedChildFolderCreate.build(
                plan_ref="folder-workflow-preview",
                target_ref="folder-workflow-target",
                request=request,
            )
            return ChildFolderCreateM4Adapter._state(prepared, payload)
        except Exception as exc:
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE) from exc

    def _insert(self, record: _WorkflowRecord) -> None:
        self._write_record(record, insert=True)

    def _get_by_preview(self, preview_ref: str) -> _WorkflowRecord:
        if not _valid_ref(preview_ref, "folder-preview-"):
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)
        return self._select("preview_ref", preview_ref)

    def _get_by_authorization(self, authorization_ref: str) -> _WorkflowRecord:
        if not _valid_ref(authorization_ref, "folder-authorized-"):
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)
        return self._select("authorization_ref", authorization_ref)

    def _select(self, field: str, value: str) -> _WorkflowRecord:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM v4_child_folder_workflows WHERE " + field + " = ?",
                    (value,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if row is None:
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _record_from_row(row)
        if not hmac.compare_digest(str(row["record_mac"]), self._mac(record)):
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _authorize(self, preview_ref: str, authorization_ref: str) -> None:
        record = self._get_by_preview(preview_ref)
        if record.state != "previewed" or not self._transition(
            record, replace(record, state="authorized", authorization_ref=authorization_ref)
        ):
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)

    def _reserve(self, preview_ref: str) -> bool:
        record = self._get_by_preview(preview_ref)
        return record.state == "authorized" and self._transition(
            record, replace(record, state="executing")
        )

    def _transition(self, current: _WorkflowRecord, updated: _WorkflowRecord) -> bool:
        """Atomically consume the exact signed state observed by this caller."""
        try:
            with self._connect() as connection:
                result = connection.execute(
                    "UPDATE v4_child_folder_workflows SET authorization_ref = ?, state = ?, record_mac = ? "
                    "WHERE preview_ref = ? AND state = ? AND record_mac = ?",
                    (updated.authorization_ref, updated.state, self._mac(updated),
                     current.preview_ref, current.state, self._mac(current)),
                )
                connection.commit()
                return result.rowcount == 1
        except sqlite3.Error as exc:
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE) from exc

    def _set_state(self, preview_ref: str, state: str) -> None:
        record = self._get_by_preview(preview_ref)
        updated = _WorkflowRecord(
            preview_ref=record.preview_ref,
            authorization_ref=record.authorization_ref,
            requester_digest=record.requester_digest,
            name=record.name,
            parent_folder_id=record.parent_folder_id,
            current_digest=record.current_digest,
            expected_digest=record.expected_digest,
            state=state,
            expires_at=record.expires_at,
        )
        self._write_record(updated, insert=False)

    def _write_record(self, record: _WorkflowRecord, *, insert: bool) -> None:
        values = (*_record_values(record), self._mac(record))
        try:
            with self._connect() as connection:
                if insert:
                    connection.execute(
                        "INSERT INTO v4_child_folder_workflows "
                        "(preview_ref, authorization_ref, requester_digest, name, "
                        "parent_folder_id, current_digest, expected_digest, state, "
                        "expires_at, record_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        values,
                    )
                else:
                    connection.execute(
                        "UPDATE v4_child_folder_workflows SET authorization_ref = ?, "
                        "requester_digest = ?, name = ?, parent_folder_id = ?, "
                        "current_digest = ?, expected_digest = ?, state = ?, expires_at = ?, "
                        "record_mac = ? WHERE preview_ref = ?",
                        (*values[1:], record.preview_ref),
                    )
                connection.commit()
        except sqlite3.Error as exc:
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE) from exc

    def _validate_record(
        self,
        record: _WorkflowRecord,
        requester_digest: str,
        *,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _WorkflowRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)

    def _preview_projection(self, record: _WorkflowRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "selected_parent_folder_id": record.parent_folder_id,
                "requested_child_folder_name": record.name,
                "parent_exists": True,
                "matching_child_exists": False,
            },
            "Proposed Changes": {
                "operation": "create_inherited_public_child_folder",
                "parent_folder_id": record.parent_folder_id,
                "folder_name": record.name,
            },
            "Expected State": {
                "child_folder_name_matches": True,
                "matching_child_exists": True,
                "inherit_policy": "enable",
                "inherit_permission": "enable",
                "inherit_folder_ztna": "enable",
            },
            "device_write_executed": False,
        }

    def _result(self, record: _WorkflowRecord, *, idempotent_replay: bool) -> dict[str, object]:
        latest = self._get_by_preview(record.preview_ref)
        if latest.state == "completed":
            outcome, verification = "succeeded", "verified"
        else:
            outcome, verification = "reconciliation_required", "unknown"
        return {
            "contract": "fortipam_v4_child_folder_execution_v1",
            "outcome": outcome,
            "verification": verification,
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "credentials_returned": False,
            "raw_response_returned": False,
        }

    def _prepare_database(self) -> None:
        self._database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS v4_child_folder_workflows "
                    "(preview_ref TEXT PRIMARY KEY, authorization_ref TEXT UNIQUE, "
                    "requester_digest TEXT NOT NULL, name TEXT NOT NULL, "
                    "parent_folder_id INTEGER NOT NULL, current_digest TEXT NOT NULL, "
                    "expected_digest TEXT NOT NULL, state TEXT NOT NULL, "
                    "expires_at INTEGER NOT NULL, record_mac TEXT NOT NULL)"
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database)
        connection.row_factory = sqlite3.Row
        return connection

    def _mac(self, record: _WorkflowRecord) -> str:
        payload = json.dumps(_record_values(record), separators=(",", ":"), ensure_ascii=True)
        return hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).hexdigest()


def _record_values(record: _WorkflowRecord) -> tuple[object, ...]:
    return (
        record.preview_ref,
        record.authorization_ref,
        record.requester_digest,
        record.name,
        record.parent_folder_id,
        record.current_digest,
        record.expected_digest,
        record.state,
        record.expires_at,
    )


def _record_from_row(row: sqlite3.Row) -> _WorkflowRecord:
    return _WorkflowRecord(
        preview_ref=str(row["preview_ref"]),
        authorization_ref=(str(row["authorization_ref"]) if row["authorization_ref"] else None),
        requester_digest=str(row["requester_digest"]),
        name=str(row["name"]),
        parent_folder_id=int(row["parent_folder_id"]),
        current_digest=str(row["current_digest"]),
        expected_digest=str(row["expected_digest"]),
        state=str(row["state"]),
        expires_at=int(row["expires_at"]),
    )


def _has_parent(payload: Mapping[str, object], parent_folder_id: int | None) -> bool:
    if type(parent_folder_id) is not int or parent_folder_id <= 0:
        return False
    raw = payload.get("results")
    if payload.get("http_status") != 200 or not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return False
    return any(isinstance(item, Mapping) and item.get("id") == parent_folder_id for item in raw)


def _valid_mkey(value: object) -> bool:
    return type(value) is int and value > 0


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and len(value) <= 128 and value.isascii()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)


def _load_key(path: Path) -> bytes:
    try:
        value = path.read_bytes()
    except OSError as exc:
        raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE) from exc
    if len(value) < 32:
        raise ChildFolderWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _now() -> int:
    return int(time.time())


__all__ = [
    "ChildFolderLiveWorkflow",
    "ChildFolderWorkflowError",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
