"""One confirmation-gated FortiPAM empty Public Folder archive workflow.

FortiPAM 1.9.1 documents Folder removal as deletion and permits it only for an
empty Folder.  The V4 ``folder.archive`` family therefore has no invented
``status`` transition: this narrowly scoped action permanently removes one
isolated V4 Public child Folder only after an exact C/P/E confirmation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Literal, Protocol


WORKFLOW_CONTRACT = "fortipam_v4_empty_public_child_folder_archive_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 empty Public Folder archive action is unavailable."
_TTL_SECONDS = 600
_MAX_FOLDER_ID = 2_147_483_647
_ARCHIVE_NAME = re.compile(r"mcp-v4-archive-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")


class FolderArchiveLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the destructive Folder action."""


class FolderArchiveTransport(Protocol):
    """Fixed collection-read and exact-ID delete contract for this action."""

    def read_collection(self) -> Mapping[str, object]: ...

    def delete_empty_folder(self, folder_id: int) -> Mapping[str, object]: ...


class FolderArchiveReferenceReader(Protocol):
    """Private CLI child absence and calibrated CMDB check; no caller assertions."""

    def verify_no_references(self, folder_id: int, parent_folder_id: int, device_serial: str) -> bool: ...


class FolderArchiveActorReader(Protocol):
    """Require the API authentication identity to match the private ACL owner."""

    def inspect(self, expected_requester: str) -> None: ...


@dataclass(frozen=True, slots=True)
class _FolderArchiveState:
    folder_id: int
    name: str
    parent_folder_id: int
    child_folder_count: int
    device_serial: str
    permission_digest: str

    def digest(self) -> str:
        payload = json.dumps(
            {
                "folder_id": self.folder_id,
                "name": self.name,
                "parent_folder_id": self.parent_folder_id,
                "child_folder_count": self.child_folder_count,
                "device_serial": self.device_serial,
                "permission_digest": self.permission_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class _FolderArchiveRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    folder_id: int
    current_digest: str
    device_serial: str
    state: str
    expires_at: int


class FolderArchiveLiveWorkflow:
    """One-confirmation API workflow for a disposable empty V4 Folder."""

    def __init__(
        self,
        transport: FolderArchiveTransport,
        *,
        clock: Callable[[], int] | None = None,
        claim_path: Path | None = None,
        reference_reader: FolderArchiveReferenceReader | None = None,
        actor_reader: FolderArchiveActorReader | None = None,
        bound_folder_name: str | None = None,
        delete_authentication: Literal["api_bearer", "owner_session"] = "api_bearer",
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._reference_reader = reference_reader
        self._actor_reader = actor_reader
        if bound_folder_name is not None and _ARCHIVE_NAME.fullmatch(bound_folder_name) is None:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if delete_authentication not in ("api_bearer", "owner_session") or (
            delete_authentication == "owner_session" and bound_folder_name is None
        ):
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._bound_folder_name = bound_folder_name
        self._delete_authentication = delete_authentication
        self._claim_path = Path(claim_path) if claim_path is not None else None
        if self._claim_path is not None and not self._claim_path.is_absolute():
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records: dict[str, _FolderArchiveRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        folder_id: int,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read one exact disposable Folder and render a destructive C/P/E preview."""

        safe_id = _folder_id(folder_id)
        _require_requester(requester_digest)
        if self._claim_path is not None:
            self._require_unconsumed()
        current = self._prepare(safe_id)
        record = _FolderArchiveRecord(
            preview_ref="folder-archive-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            folder_id=safe_id,
            current_digest=current.digest(),
            device_serial=current.device_serial,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Re-read the exact empty-Folder baseline before authorizing delete."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            if self._claim_path is not None:
                self._require_unconsumed()
            if not hmac.compare_digest(
                self._prepare(record.folder_id).digest(), record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "previewed")
            authorization_ref = "folder-archive-authorized-" + secrets.token_urlsafe(24)
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Delete exactly the confirmed Folder and prove absence by collection readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            self._require_unconsumed()
            if not hmac.compare_digest(
                self._prepare(record.folder_id).digest(), record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "authorized")
            self._reserve_claim(record.current_digest)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            response = self._transport.delete_empty_folder(record.folder_id)
            if (
                not _successful_delete(response)
                or response.get("serial") != record.device_serial
                or not self._folder_absent(record.folder_id, record.device_serial)
            ):
                raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(record.preview_ref, "completed")
        return self._result(record, idempotent_replay=False)

    def _require_unconsumed(self) -> None:
        """Refuse a missing durable binding or any prior attempt before dispatch."""
        path = self._claim_path
        if path is None:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        try:
            if not path.parent.is_dir():
                path.parent.mkdir(parents=True, mode=0o700)
            info = path.parent.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or os.path.lexists(path)
            ):
                raise OSError
        except OSError:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE) from None

    def _reserve_claim(self, current_digest: str) -> None:
        """Persist one owner-only attempt before the irreversible DELETE."""
        self._require_unconsumed()
        path = self._claim_path
        assert path is not None
        try:
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(parent)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise OSError
                fd = os.open(
                    path.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent,
                )
                with os.fdopen(fd, "w") as stream:
                    json.dump(
                        {
                            "contract": WORKFLOW_CONTRACT,
                            "current_digest": current_digest,
                            "state": "delete_attempt_reserved",
                            "reserved_at": self._clock(),
                        },
                        stream,
                        sort_keys=True,
                    )
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(parent)
            finally:
                os.close(parent)
        except OSError:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE) from None

    def _prepare(self, folder_id: int) -> _FolderArchiveState:
        if self._reference_reader is None or self._actor_reader is None:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        records, device_serial = self._read_records()
        matching = [record for record in records if _record_id(record) == folder_id]
        if len(matching) != 1:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = matching[0]
        name = record.get("name")
        parent_folder_id = _positive_int(record.get("parent-folder"))
        if (
            not isinstance(name, str)
            or _ARCHIVE_NAME.fullmatch(name) is None
            or (self._bound_folder_name is not None and name != self._bound_folder_name)
            or record.get("folder-type") != "public"
            or parent_folder_id is None
        ):
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        child_folder_count = sum(
            1
            for candidate in records
            if _positive_int(candidate.get("parent-folder")) == folder_id
        )
        if child_folder_count != 0:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        permission_digest, owner_name = _isolated_permissions(record)
        try:
            self._actor_reader.inspect(owner_name)
            references_zero = self._reference_reader.verify_no_references(
                folder_id, parent_folder_id, device_serial
            )
        except Exception:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE) from None
        if references_zero is not True:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return _FolderArchiveState(
            folder_id=folder_id,
            name=name,
            parent_folder_id=parent_folder_id,
            child_folder_count=child_folder_count,
            device_serial=device_serial,
            permission_digest=permission_digest,
        )

    def _folder_absent(self, folder_id: int, expected_serial: str) -> bool:
        records, device_serial = self._read_records()
        if not hmac.compare_digest(device_serial, expected_serial):
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return all(_record_id(record) != folder_id for record in records)

    def _read_records(self) -> tuple[tuple[Mapping[str, object], ...], str]:
        try:
            payload = self._transport.read_collection()
        except Exception as exc:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not _successful_response(payload):
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        # The reference diagnostic is qualified only on this exact release.
        if payload.get("version") != "v7.0.0" or type(payload.get("build")) is not int or payload["build"] != 29:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        device_serial = payload.get("serial")
        if not isinstance(device_serial, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", device_serial) is None:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        # A truncated collection cannot establish either child absence or
        # post-delete absence. Do not interpret truthy/non-boolean markers.
        if "limit_reached" in payload and payload["limit_reached"] is not False:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        results = payload.get("results") if isinstance(payload, Mapping) else None
        if not isinstance(results, Sequence) or isinstance(
            results, (str, bytes, bytearray)
        ):
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        records: list[Mapping[str, object]] = []
        identifiers: set[int] = set()
        for item in results:
            if not isinstance(item, Mapping):
                raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            identifier = _record_id(item)
            parent = item.get("parent-folder")
            if (
                identifier is None or identifier in identifiers
                or type(parent) is not int or not 0 <= parent <= _MAX_FOLDER_ID
            ):
                raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            identifiers.add(identifier)
            records.append({str(key): value for key, value in item.items()})
        if type(payload.get("matched_count")) is not int or payload["matched_count"] != len(records):
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return tuple(records), device_serial

    def _record_for_preview_locked(self, preview_ref: str) -> _FolderArchiveRecord:
        if not _valid_ref(preview_ref, "folder-archive-preview-"):
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _FolderArchiveRecord:
        if not _valid_ref(authorization_ref, "folder-archive-authorized-"):
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _FolderArchiveRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _FolderArchiveRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        now_epoch = self._clock()
        expired = [
            ref
            for ref, record in self._records.items()
            if record.expires_at <= now_epoch and record.state != "completed"
        ]
        for preview_ref in expired:
            record = self._records.pop(preview_ref)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    def _preview_projection(self, record: _FolderArchiveRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "selected_folder_id": record.folder_id,
                "folder_exists": True,
                "folder_scope": "isolated_v4_public_child",
                "folder_has_no_child_folders": True,
                "folder_hierarchy_checked_by_cli": True,
                "folder_has_no_cmdb_references": True,
                "folder_has_owner_only_permissions": True,
                "delete_actor_matches_folder_owner": True,
                "folder_name_returned": False,
                "write_transport": "rest_api",
                "delete_authentication": self._delete_authentication,
            },
            "Proposed Changes": {
                "operation": "archive_by_deleting_empty_v4_public_child_folder_via_api",
                "folder_id": record.folder_id,
                "folder_name_returned": False,
                "product_requires_empty_folder": True,
                "irreversible_after_execution": True,
                "secret_or_child_relocation_attempted": False,
            },
            "Expected State": {
                "folder_id_absent": True,
                "folder_exists": False,
                "folder_deletion_verified_by_collection_readback": True,
                "other_folder_configuration_modified": False,
                "secret_or_child_relocation_attempted": False,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _FolderArchiveRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_empty_public_child_folder_archive_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "manual_recreation_or_backup_restore_required",
            "irreversible_after_execution": True,
            "folder_id_returned": False,
            "folder_name_returned": False,
            "raw_api_response_returned": False,
        }


def _isolated_permissions(record: Mapping[str, object]) -> tuple[str, str]:
    """Require the established owner-only fixture shape and bind its full ACL.

    This checks isolation, not the transport actor's effective delete permission.
    Principal names and permission data stay inside the private state digest.
    """
    from .folder_acl_live_workflow import _relations

    try:
        if record.get("inherit-permission") != "disable" or record.get("group-permission") != []:
            raise ValueError
        relations = _relations(record, principal_key="user-name")
        if len(relations) != 1:
            raise ValueError
        relation = relations[0]
        if (
            relation.relation_id <= 0 or len(relation.names) != 1
            or relation.folder_permission != "owner" or relation.secret_permission != "owner"
        ):
            raise ValueError
        payload = json.dumps(
            {key: record[key] for key in ("inherit-permission", "user-permission", "group-permission")},
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest(), relation.names[0]
    except Exception:
        raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE) from None


def _record_id(record: Mapping[str, object]) -> int | None:
    return _positive_int(record.get("id"))


def _positive_int(value: object) -> int | None:
    if type(value) is not int or not 0 < value <= _MAX_FOLDER_ID:
        return None
    return value


def _folder_id(value: object) -> int:
    result = _positive_int(value)
    if result is None:
        raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return result


def _successful_delete(response: Mapping[str, object]) -> bool:
    return _successful_response(response)


def _successful_response(response: Mapping[str, object]) -> bool:
    status = response.get("http_status") if isinstance(response, Mapping) else None
    return (
        type(status) is int
        and status == 200
        and response.get("status") in ("success", "OK")
    )


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise FolderArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and value.isascii()
        and len(value) <= 128
    )


def _now() -> int:
    return int(time.time())


__all__ = [
    "FolderArchiveLiveWorkflow",
    "FolderArchiveLiveWorkflowError",
    "FolderArchiveTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
