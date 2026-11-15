"""One API-first, confirmation-gated Public Folder direct user-ACL revoke workflow."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import re
import secrets
import threading

from .folder_acl_live_workflow import (
    FolderAclLiveWorkflowTransport,
    _AclRelation,
    _folder_record,
    _folder_update_body,
    _inherit_permission,
    _now,
    _positive_int,
    _relations,
    _relations_from_body,
    _relation_semantics,
    _require_requester,
    _valid_ref,
    _ztna_control_semantics,
)
from .folder_rename_live_workflow import _canonical_acl_projection


WORKFLOW_CONTRACT = "fortipam_v4_folder_user_acl_revoke_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Folder ACL revoke workflow is unavailable."
_TTL_SECONDS = 600
_MAX_FOLDER_ID = 2_147_483_647
_USER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}\Z")


class FolderAclRevokeLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Folder ACL revoke workflow."""


@dataclass(frozen=True, slots=True)
class _FolderAclRevokeRequest:
    folder_id: int
    username: str

    @classmethod
    def create(cls, *, folder_id: int, username: str) -> "_FolderAclRevokeRequest":
        if type(folder_id) is not int or not 0 < folder_id <= _MAX_FOLDER_ID:
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if not isinstance(username, str) or _USER_NAME.fullmatch(username) is None:
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(folder_id=folder_id, username=username)


@dataclass(frozen=True, slots=True)
class _PreparedFolderAclRevoke:
    request: _FolderAclRevokeRequest
    current_user_relation_count: int
    current_group_relation_count: int
    body: dict[str, object]

    def digest(self) -> str:
        payload = {
            "folder_id": self.request.folder_id,
            "current_user_relation_count": self.current_user_relation_count,
            "current_group_relation_count": self.current_group_relation_count,
            "body": self.body,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class _FolderAclRevokeRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    prepared: _PreparedFolderAclRevoke
    current_digest: str
    state: str
    expires_at: int


class FolderAclRevokeLiveWorkflow:
    """Volatile one-confirmation workflow for one direct Public Folder user revoke."""

    def __init__(
        self,
        transport: FolderAclLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _FolderAclRevokeRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        folder_id: int,
        username: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read live state and render a minimized Current/Proposed/Expected preview."""

        request = _FolderAclRevokeRequest.create(folder_id=folder_id, username=username)
        _require_requester(requester_digest)
        prepared = self._prepare(request)
        record = _FolderAclRevokeRecord(
            preview_ref="folder-acl-revoke-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            prepared=prepared,
            current_digest=prepared.digest(),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(
        self,
        preview_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        """Confirm an unchanged preview and issue one short-lived execution ref."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._prepare(record.prepared.request)
            if not hmac.compare_digest(current.digest(), record.current_digest):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "folder-acl-revoke-authorized-" + secrets.token_urlsafe(24)
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

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        """Write one confirmed projection and verify the precise resulting ACL state."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._prepare(record.prepared.request)
            if not hmac.compare_digest(current.digest(), record.current_digest):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            response = self._transport.update_folder(
                record.prepared.request.folder_id,
                record.prepared.body,
            )
            if not isinstance(response, Mapping) or not response:
                raise TypeError("Folder update response is unavailable")
            verified = self._verify_readback(record.prepared)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _prepare(self, request: _FolderAclRevokeRequest) -> _PreparedFolderAclRevoke:
        try:
            child = _canonical_folder_acl_record(self._read_folder(request.folder_id))
            if _positive_int(child.get("id")) != request.folder_id:
                raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            if child.get("folder-type") != "public":
                raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            _positive_int(child.get("parent-folder"))
            if _inherit_permission(child) != "disable":
                raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            users = _relations(child, principal_key="user-name")
            groups = _relations(child, principal_key="group-name")
            remaining_users = _revoke_direct_user(users, request.username)
            body = _folder_update_body(child, remaining_users, groups)
        except FolderAclRevokeLiveWorkflowError:
            raise
        except Exception as exc:
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        return _PreparedFolderAclRevoke(
            request=request,
            current_user_relation_count=len(users),
            current_group_relation_count=len(groups),
            body=body,
        )

    def _verify_readback(self, prepared: _PreparedFolderAclRevoke) -> bool:
        try:
            actual = _canonical_folder_acl_record(
                self._read_folder(prepared.request.folder_id)
            )
            if _positive_int(actual.get("id")) != prepared.request.folder_id:
                return False
            if actual.get("folder-type") != "public":
                return False
            _positive_int(actual.get("parent-folder"))
            if _inherit_permission(actual) != "disable":
                return False
            expected_users = _relations_from_body(
                prepared.body["user-permission"], principal_key="user-name"
            )
            expected_groups = _relations_from_body(
                prepared.body["group-permission"], principal_key="group-name"
            )
            actual_users = _relations(actual, principal_key="user-name")
            actual_groups = _relations(actual, principal_key="group-name")
            return (
                _relation_semantics(actual_users) == _relation_semantics(expected_users)
                and _relation_semantics(actual_groups) == _relation_semantics(expected_groups)
                and _ztna_control_semantics(actual)
                == _ztna_control_semantics(prepared.body)
            )
        except Exception:
            return False

    def _read_folder(self, folder_id: int) -> Mapping[str, object]:
        try:
            response = self._transport.read_folder(folder_id)
            return _folder_record(response)
        except FolderAclRevokeLiveWorkflowError:
            raise
        except Exception as exc:
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc

    def _record_for_preview_locked(self, preview_ref: str) -> _FolderAclRevokeRecord:
        if not _valid_ref(preview_ref, "folder-acl-revoke-preview-"):
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _FolderAclRevokeRecord:
        if not _valid_ref(authorization_ref, "folder-acl-revoke-authorized-"):
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _FolderAclRevokeRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _FolderAclRevokeRecord,
        requester_digest: str,
    ) -> None:
        try:
            _require_requester(requester_digest)
        except Exception as exc:
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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

    @staticmethod
    def _preview_projection(record: _FolderAclRevokeRecord) -> dict[str, object]:
        prepared = record.prepared
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "selected_folder_id": prepared.request.folder_id,
                "requested_username": prepared.request.username,
                "folder_exists": True,
                "folder_scope": "public_child",
                "permission_inheritance": "disable",
                "direct_user_relation_count": prepared.current_user_relation_count,
                "direct_group_relation_count": prepared.current_group_relation_count,
                "requested_direct_user_relation_present": True,
            },
            "Proposed Changes": {
                "operation": "revoke_public_folder_direct_user_acl",
                "folder_id": prepared.request.folder_id,
                "username": prepared.request.username,
                "direct_user_relation_count_delta": -1,
                "permission_inheritance_preserved": True,
            },
            "Expected State": {
                "folder_exists": True,
                "folder_scope": "public_child",
                "permission_inheritance": "disable",
                "requested_username_direct_relation_present": False,
                "other_direct_user_relations_preserved": True,
                "direct_group_relations_preserved": True,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _FolderAclRevokeRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_folder_user_acl_revoke_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "grant_new_direct_relation_required",
            "credentials_returned": False,
            "raw_response_returned": False,
        }


def _revoke_direct_user(
    users: tuple[_AclRelation, ...],
    username: str,
) -> tuple[_AclRelation, ...]:
    result: list[_AclRelation] = []
    removed = 0
    for relation in users:
        if username not in relation.names:
            result.append(relation)
            continue
        if relation.names != (username,):
            raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        removed += 1
    if removed != 1:
        raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return tuple(result)


def _canonical_folder_acl_record(
    record: Mapping[str, object],
) -> dict[str, object]:
    """Drop only the 1.9.1 read-only ACL metadata proven by b61."""

    try:
        normalized = dict(record)
        normalized["user-permission"] = _canonical_acl_projection(
            record.get("user-permission"), principal_key="user-name"
        )
        normalized["group-permission"] = _canonical_acl_projection(
            record.get("group-permission"), principal_key="group-name"
        )
        return normalized
    except Exception as exc:
        raise FolderAclRevokeLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc


__all__ = [
    "FolderAclRevokeLiveWorkflow",
    "FolderAclRevokeLiveWorkflowError",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
