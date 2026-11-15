"""One live, confirmation-gated FortiPAM Public child-Folder rename workflow."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from typing import Protocol


WORKFLOW_CONTRACT = "fortipam_v4_public_child_folder_rename_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Public child Folder rename is unavailable."
_TTL_SECONDS = 600
_MAX_FOLDER_ID = 2_147_483_647
_NAME = re.compile(r"[^/\\\x00-\x1f\x7f]{1,64}\Z")
_UPDATE_FIELDS = (
    "id",
    "name",
    "parent-folder",
    "folder-type",
    "secret-policy",
    "inherit-policy",
    "inherit-permission",
    "inherit-folder-ztna",
    "ztna-ems-tag",
    "ztna-tags-match-logic",
    "user-permission",
    "group-permission",
)
_READ_ONLY_RELATION_FIELDS = frozenset({"allowed-launcher-type", "q_origin_key"})
_READ_ONLY_PRINCIPAL_FIELDS = frozenset({"q_origin_key"})


class FolderRenameLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Folder rename workflow."""


class FolderRenameTransport(Protocol):
    """The exact Folder detail and update contract used by this workflow."""

    def read_folder(self, folder_id: int) -> Mapping[str, object]: ...

    def update_folder(
        self,
        folder_id: int,
        body: Mapping[str, object],
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class _FolderRenameRequest:
    folder_id: int
    new_name: str

    @classmethod
    def create(cls, *, folder_id: int, new_name: str) -> "_FolderRenameRequest":
        if type(folder_id) is not int or not 0 < folder_id <= _MAX_FOLDER_ID:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if not isinstance(new_name, str) or _NAME.fullmatch(new_name) is None:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(folder_id=folder_id, new_name=new_name)


@dataclass(frozen=True, slots=True)
class _PreparedFolderRename:
    request: _FolderRenameRequest
    current_digest: str
    desired_body: dict[str, object]


@dataclass(frozen=True, slots=True)
class _FolderRenameRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    prepared: _PreparedFolderRename
    state: str
    expires_at: int


class FolderRenameLiveWorkflow:
    """Volatile one-confirmation REST workflow for one Public child-Folder rename."""

    def __init__(
        self,
        transport: FolderRenameTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _FolderRenameRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        folder_id: int,
        new_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current state and render one redacted C/P/E rename preview."""

        request = _FolderRenameRequest.create(folder_id=folder_id, new_name=new_name)
        _require_requester(requester_digest)
        prepared = self._prepare(request)
        record = _FolderRenameRecord(
            preview_ref="folder-rename-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            prepared=prepared,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm an unchanged preview and issue one short-lived execution ref."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._prepare(record.prepared.request)
            if not hmac.compare_digest(current.current_digest, record.prepared.current_digest):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "folder-rename-authorized-" + secrets.token_urlsafe(24)
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
        """Write one previously confirmed Folder update and verify readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._prepare(record.prepared.request)
            if not hmac.compare_digest(current.current_digest, record.prepared.current_digest):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            response = self._transport.update_folder(
                record.prepared.request.folder_id,
                record.prepared.desired_body,
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

    def _prepare(self, request: _FolderRenameRequest) -> _PreparedFolderRename:
        current = self._read_folder(request.folder_id)
        body = _update_projection(current, folder_id=request.folder_id)
        if body["name"] == request.new_name:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        current_digest = _state_digest(body)
        desired_body = dict(body)
        desired_body["name"] = request.new_name
        return _PreparedFolderRename(
            request=request,
            current_digest=current_digest,
            desired_body=desired_body,
        )

    def _verify_readback(self, prepared: _PreparedFolderRename) -> bool:
        actual = _update_projection(
            self._read_folder(prepared.request.folder_id),
            folder_id=prepared.request.folder_id,
        )
        if actual["name"] != prepared.request.new_name:
            return False
        expected = dict(prepared.desired_body)
        return hmac.compare_digest(_state_digest(actual), _state_digest(expected))

    def _read_folder(self, folder_id: int) -> Mapping[str, object]:
        try:
            response = self._transport.read_folder(folder_id)
            return _folder_record(response)
        except FolderRenameLiveWorkflowError:
            raise
        except Exception as exc:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc

    def _record_for_preview_locked(self, preview_ref: str) -> _FolderRenameRecord:
        if not _valid_ref(preview_ref, "folder-rename-preview-"):
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _FolderRenameRecord:
        if not _valid_ref(authorization_ref, "folder-rename-authorized-"):
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _FolderRenameRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _FolderRenameRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _FolderRenameRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "selected_folder_id": record.prepared.request.folder_id,
                "requested_new_name": record.prepared.request.new_name,
                "folder_exists": True,
                "folder_scope": "public_child",
                "permission_inheritance": "disable",
                "requested_name_already_matches": False,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "rename_public_child_folder_via_api",
                "folder_id": record.prepared.request.folder_id,
                "current_name_returned": False,
                "new_name": record.prepared.request.new_name,
                "acl_and_policy_projection_preserved": True,
                "ztna_projection_preserved": True,
            },
            "Expected State": {
                "folder_id_matches": True,
                "folder_exists": True,
                "folder_scope": "public_child",
                "requested_name_matches": True,
                "parent_relation_preserved": True,
                "acl_and_policy_projection_preserved": True,
                "ztna_projection_preserved": True,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _FolderRenameRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_public_child_folder_rename_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "folder_id_returned": False,
            "folder_name_returned": False,
            "raw_api_response_returned": False,
        }


def _update_projection(record: Mapping[str, object], *, folder_id: int) -> dict[str, object]:
    if set(_UPDATE_FIELDS) - set(record):
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    body = {field: record[field] for field in _UPDATE_FIELDS}
    if _positive_int(body["id"]) != folder_id:
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    if body["folder-type"] != "public" or _positive_int(body["parent-folder"]) is None:
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    if body["inherit-permission"] != "disable":
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    if not isinstance(body["name"], str) or _NAME.fullmatch(body["name"]) is None:
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    if not isinstance(body["secret-policy"], str) or not body["secret-policy"]:
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    for field in ("inherit-policy", "inherit-folder-ztna"):
        if body[field] not in {"enable", "disable"}:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    if not isinstance(body["ztna-ems-tag"], list) or body["ztna-ems-tag"]:
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    if body["ztna-tags-match-logic"] not in {"and", "or"}:
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    body["user-permission"] = _canonical_acl_projection(
        body["user-permission"], principal_key="user-name"
    )
    body["group-permission"] = _canonical_acl_projection(
        body["group-permission"], principal_key="group-name"
    )
    return body


def _canonical_acl_projection(
    value: object,
    *,
    principal_key: str,
) -> list[dict[str, object]]:
    """Drop only proven read-only response metadata from fixed PUT relations."""

    if not isinstance(value, list) or len(value) > 128:
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    expected_fields = {
        "id",
        principal_key,
        "folder-permission",
        "secret-permission",
    }
    allowed_fields = expected_fields | _READ_ONLY_RELATION_FIELDS
    result: list[dict[str, object]] = []
    for relation in value:
        if (
            not isinstance(relation, Mapping)
            or not expected_fields <= set(relation)
            or not set(relation) <= allowed_fields
        ):
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        relation_id = relation.get("id")
        if type(relation_id) is not int or relation_id < 0 or relation_id > _MAX_FOLDER_ID:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        allowed_launcher_type = relation.get("allowed-launcher-type")
        if allowed_launcher_type is not None and allowed_launcher_type != "all":
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        names_value = relation.get(principal_key)
        if not isinstance(names_value, list) or not names_value or len(names_value) > 64:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        names: list[str] = []
        for item in names_value:
            if isinstance(item, Mapping):
                if (
                    "name" not in item
                    or not set(item) <= ({"name"} | _READ_ONLY_PRINCIPAL_FIELDS)
                ):
                    raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
                name = item.get("name")
            else:
                name = item
            if not isinstance(name, str) or not name or len(name) > 128:
                raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            names.append(name)
        if len(set(names)) != len(names):
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        folder_permission = relation.get("folder-permission")
        secret_permission = relation.get("secret-permission")
        if (
            not isinstance(folder_permission, str)
            or not folder_permission
            or len(folder_permission) > 64
            or not isinstance(secret_permission, str)
            or not secret_permission
            or len(secret_permission) > 64
        ):
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        result.append(
            {
                "id": relation_id,
                principal_key: [{"name": name} for name in names],
                "folder-permission": folder_permission,
                "secret-permission": secret_permission,
            }
        )
    return result


def _state_digest(body: Mapping[str, object]) -> str:
    normalized = {
        "id": body["id"],
        "name": body["name"],
        "parent-folder": body["parent-folder"],
        "folder-type": body["folder-type"],
        "secret-policy": body["secret-policy"],
        "inherit-policy": body["inherit-policy"],
        "inherit-permission": body["inherit-permission"],
        "inherit-folder-ztna": body["inherit-folder-ztna"],
        "ztna-ems-tag": body["ztna-ems-tag"],
        "ztna-tags-match-logic": body["ztna-tags-match-logic"],
        "user-permission": _acl_semantics(
            body["user-permission"], principal_key="user-name"
        ),
        "group-permission": _acl_semantics(
            body["group-permission"], principal_key="group-name"
        ),
    }
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
    return hashlib.sha256(encoded).hexdigest()


def _acl_semantics(value: object, *, principal_key: str) -> tuple[tuple[tuple[str, ...], str, str], ...]:
    if not isinstance(value, list) or len(value) > 128:
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    relations: list[tuple[tuple[str, ...], str, str]] = []
    for relation in value:
        expected_fields = {
            "id",
            principal_key,
            "folder-permission",
            "secret-permission",
        }
        if not isinstance(relation, Mapping) or set(relation) != expected_fields:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        relation_id = relation.get("id")
        if type(relation_id) is not int or relation_id < 0 or relation_id > _MAX_FOLDER_ID:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        names_value = relation.get(principal_key)
        if not isinstance(names_value, list) or not names_value or len(names_value) > 64:
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        names: list[str] = []
        for item in names_value:
            name = item.get("name") if isinstance(item, Mapping) else item
            if not isinstance(name, str) or not name or len(name) > 128:
                raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            names.append(name)
        if len(set(names)) != len(names):
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        folder_permission = relation.get("folder-permission")
        secret_permission = relation.get("secret-permission")
        if (
            not isinstance(folder_permission, str)
            or not folder_permission
            or len(folder_permission) > 64
            or not isinstance(secret_permission, str)
            or not secret_permission
            or len(secret_permission) > 64
        ):
            raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        relations.append((tuple(sorted(names)), folder_permission, secret_permission))
    return tuple(sorted(relations))


def _folder_record(value: Mapping[str, object]) -> Mapping[str, object]:
    queue: list[object] = [value]
    visited: set[int] = set()
    while queue:
        candidate = queue.pop(0)
        if isinstance(candidate, Mapping):
            if id(candidate) in visited:
                continue
            visited.add(id(candidate))
            record = {str(key): item for key, item in candidate.items()}
            if set(_UPDATE_FIELDS) <= set(record):
                return record
            queue.extend(record.values())
        elif isinstance(candidate, Sequence) and not isinstance(
            candidate, (str, bytes, bytearray)
        ):
            queue.extend(candidate)
    raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _positive_int(value: object) -> int | None:
    if type(value) is int and 0 < value <= _MAX_FOLDER_ID:
        return value
    return None


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise FolderRenameLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "FolderRenameLiveWorkflow",
    "FolderRenameLiveWorkflowError",
    "FolderRenameTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
