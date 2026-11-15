"""One API-first, confirmation-gated Public Folder user-ACL workflow."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from typing import Protocol


WORKFLOW_CONTRACT = "fortipam_v4_folder_user_acl_grant_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Folder ACL grant workflow is unavailable."
_TTL_SECONDS = 600
_MAX_FOLDER_ID = 2_147_483_647
_MAX_ACL_DEPTH = 8
_USER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}\Z")
_FOLDER_PERMISSIONS = frozenset({"view", "edit", "owner", "add-secret"})
_SECRET_PERMISSIONS = frozenset({"none", "view", "edit", "owner"})
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


class FolderAclLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Folder ACL workflow."""


class FolderAclLiveWorkflowTransport(Protocol):
    """The exact Folder detail and update contract used by this workflow."""

    def read_folder(self, folder_id: int) -> Mapping[str, object]: ...

    def update_folder(
        self,
        folder_id: int,
        body: Mapping[str, object],
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class _FolderAclRequest:
    folder_id: int
    principal_name: str
    subject_class: str
    folder_permission: str
    secret_permission: str

    @classmethod
    def create(
        cls,
        *,
        folder_id: int,
        username: str,
        folder_permission: str,
        secret_permission: str,
    ) -> "_FolderAclRequest":
        if type(folder_id) is not int or not 0 < folder_id <= _MAX_FOLDER_ID:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if not isinstance(username, str) or _USER_NAME.fullmatch(username) is None:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if folder_permission not in _FOLDER_PERMISSIONS:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if secret_permission not in _SECRET_PERMISSIONS:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(folder_id, username, "user", folder_permission, secret_permission)

    @classmethod
    def create_group(
        cls,
        *,
        folder_id: int,
        group_name: str,
        folder_permission: str,
        secret_permission: str,
    ) -> "_FolderAclRequest":
        if type(folder_id) is not int or not 0 < folder_id <= _MAX_FOLDER_ID:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        _nonempty_text(group_name, maximum=128)
        if folder_permission not in _FOLDER_PERMISSIONS:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if secret_permission not in _SECRET_PERMISSIONS:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(folder_id, group_name, "group", folder_permission, secret_permission)


@dataclass(frozen=True, slots=True)
class _AclRelation:
    relation_id: int
    names: tuple[str, ...]
    folder_permission: str
    secret_permission: str

    def body(self, *, principal_key: str) -> dict[str, object]:
        return {
            "id": self.relation_id,
            principal_key: [{"name": name} for name in self.names],
            "folder-permission": self.folder_permission,
            "secret-permission": self.secret_permission,
        }

    def semantic(self) -> tuple[int, tuple[str, ...], str, str]:
        return (
            self.relation_id,
            self.names,
            self.folder_permission,
            self.secret_permission,
        )


@dataclass(frozen=True, slots=True)
class _PreparedFolderAcl:
    request: _FolderAclRequest
    current_inherit_permission: str
    current_user_relation_count: int
    current_group_relation_count: int
    requested_relation_present: bool
    body: dict[str, object]

    def digest(self) -> str:
        payload = {
            "folder_id": self.request.folder_id,
            "current_inherit_permission": self.current_inherit_permission,
            "current_user_relation_count": self.current_user_relation_count,
            "current_group_relation_count": self.current_group_relation_count,
            "requested_relation_present": self.requested_relation_present,
            "body": self.body,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class _FolderAclRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    prepared: _PreparedFolderAcl
    current_digest: str
    state: str
    expires_at: int


class FolderAclGrantLiveWorkflow:
    """Volatile one-confirmation API workflow for one Public Folder user grant."""

    def __init__(
        self,
        transport: FolderAclLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _FolderAclRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        folder_id: int,
        username: str,
        folder_permission: str,
        secret_permission: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read live state and render a Current/Proposed/Expected ACL preview."""

        request = _FolderAclRequest.create(
            folder_id=folder_id,
            username=username,
            folder_permission=folder_permission,
            secret_permission=secret_permission,
        )
        _require_requester(requester_digest)
        prepared = self._prepare(request)
        record = _FolderAclRecord(
            preview_ref="folder-acl-preview-" + secrets.token_urlsafe(24),
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

    def preview_group(
        self,
        *,
        folder_id: int,
        group_name: str,
        folder_permission: str,
        secret_permission: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Render the same bounded projection for internal Scheme composition."""

        request = _FolderAclRequest.create_group(
            folder_id=folder_id,
            group_name=group_name,
            folder_permission=folder_permission,
            secret_permission=secret_permission,
        )
        _require_requester(requester_digest)
        prepared = self._prepare(request)
        record = _FolderAclRecord(
            preview_ref="folder-acl-preview-" + secrets.token_urlsafe(24),
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

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm an unchanged preview and issue one short-lived execution ref."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._prepare(record.prepared.request)
            if current.digest() != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "folder-acl-authorized-" + secrets.token_urlsafe(24)
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": (
                "fortipam_v4_folder_group_acl_grant_workflow_v1"
                if updated.prepared.request.subject_class == "group"
                else WORKFLOW_CONTRACT
            ),
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
        """Write one previously confirmed API projection and verify readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._prepare(record.prepared.request)
            if current.digest() != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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

    def _prepare(self, request: _FolderAclRequest) -> _PreparedFolderAcl:
        child = self._read_folder(request.folder_id)
        child_id = _positive_int(child.get("id"))
        if child_id != request.folder_id:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if child.get("folder-type") != "public":
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        _positive_int(child.get("parent-folder"))
        current_inherit_permission = _inherit_permission(child)
        source = self._effective_acl_source(child)
        users = _relations(source, principal_key="user-name")
        groups = _relations(source, principal_key="group-name")
        relations = users if request.subject_class == "user" else groups
        requested_relation_present = any(
            relation.names == (request.principal_name,) for relation in relations
        )
        updated_relations = _grant_relation(relations, request)
        updated_users = updated_relations if request.subject_class == "user" else users
        updated_groups = updated_relations if request.subject_class == "group" else groups
        body = _folder_update_body(child, updated_users, updated_groups)
        return _PreparedFolderAcl(
            request=request,
            current_inherit_permission=current_inherit_permission,
            current_user_relation_count=len(users),
            current_group_relation_count=len(groups),
            requested_relation_present=requested_relation_present,
            body=body,
        )

    def _effective_acl_source(self, child: Mapping[str, object]) -> Mapping[str, object]:
        current = child
        seen = {_positive_int(child.get("id"))}
        for _ in range(_MAX_ACL_DEPTH):
            if _inherit_permission(current) == "disable":
                return current
            current_parent = _positive_int(current.get("parent-folder"))
            if current_parent in seen:
                break
            seen.add(current_parent)
            current = self._read_folder(current_parent)
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _verify_readback(self, prepared: _PreparedFolderAcl) -> bool:
        actual = self._read_folder(prepared.request.folder_id)
        if _positive_int(actual.get("id")) != prepared.request.folder_id:
            return False
        if _inherit_permission(actual) != "disable":
            return False
        actual_users = _relations(actual, principal_key="user-name")
        actual_groups = _relations(actual, principal_key="group-name")
        requested_names = (prepared.request.principal_name,)
        selected = (
            actual_users if prepared.request.subject_class == "user" else actual_groups
        )
        if sum(relation.names == requested_names for relation in selected) != 1:
            return False
        # FortiPAM assigns a relation ID when the submitted relation has id=0.
        # Normalize only that requested relation; keep every other ID and field.
        if prepared.request.subject_class == "user":
            actual_users = tuple(
                replace(relation, relation_id=0)
                if relation.names == requested_names else relation
                for relation in actual_users
            )
        else:
            actual_groups = tuple(
                replace(relation, relation_id=0)
                if relation.names == requested_names else relation
                for relation in actual_groups
            )
        actual_body = _folder_update_body(actual, actual_users, actual_groups)
        return _folder_projection_semantics(actual_body) == _folder_projection_semantics(
            prepared.body
        )

    def _read_folder(self, folder_id: int) -> Mapping[str, object]:
        try:
            response = self._transport.read_folder(folder_id)
            return _folder_record(response)
        except FolderAclLiveWorkflowError:
            raise
        except Exception as exc:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc

    def _record_for_preview_locked(self, preview_ref: str) -> _FolderAclRecord:
        if not _valid_ref(preview_ref, "folder-acl-preview-"):
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _FolderAclRecord:
        if not _valid_ref(authorization_ref, "folder-acl-authorized-"):
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _FolderAclRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _FolderAclRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _FolderAclRecord) -> dict[str, object]:
        prepared = record.prepared
        if prepared.request.subject_class == "group":
            return _group_preview_projection(record)
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "selected_folder_id": prepared.request.folder_id,
                "requested_username": prepared.request.principal_name,
                "requested_folder_permission": prepared.request.folder_permission,
                "requested_secret_permission": prepared.request.secret_permission,
                "folder_exists": True,
                "folder_scope": "public_child",
                "permission_inheritance": prepared.current_inherit_permission,
                "effective_user_relation_count": prepared.current_user_relation_count,
                "effective_group_relation_count": prepared.current_group_relation_count,
                "requested_user_relation_present": prepared.requested_relation_present,
            },
            "Proposed Changes": {
                "operation": "grant_public_folder_user_acl",
                "folder_id": prepared.request.folder_id,
                "username": prepared.request.principal_name,
                "folder_permission": prepared.request.folder_permission,
                "secret_permission": prepared.request.secret_permission,
                "permission_inheritance_after_change": "disable",
            },
            "Expected State": {
                "folder_exists": True,
                "folder_scope": "public_child",
                "permission_inheritance": "disable",
                "requested_username_relation_present": True,
                "requested_folder_permission_matches": True,
                "requested_secret_permission_matches": True,
                "effective_user_relations_preserved": True,
                "effective_group_relations_preserved": True,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _FolderAclRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": (
                "fortipam_v4_folder_group_acl_grant_execution_v1"
                if record.prepared.request.subject_class == "group"
                else "fortipam_v4_folder_user_acl_grant_execution_v1"
            ),
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "credentials_returned": False,
            "raw_response_returned": False,
        }


def _folder_record(value: Mapping[str, object]) -> Mapping[str, object]:
    required = {"id", "user-permission", "group-permission"}
    queue: list[object] = [value]
    visited: set[int] = set()
    while queue:
        candidate = queue.pop(0)
        if isinstance(candidate, Mapping):
            if id(candidate) in visited:
                continue
            visited.add(id(candidate))
            record = {str(key): item for key, item in candidate.items()}
            if required <= set(record):
                return record
            queue.extend(record.values())
        elif isinstance(candidate, list):
            queue.extend(candidate)
    raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _folder_update_body(
    child: Mapping[str, object],
    users: tuple[_AclRelation, ...],
    groups: tuple[_AclRelation, ...],
) -> dict[str, object]:
    if set(_UPDATE_FIELDS) - set(child):
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    body = {field: child[field] for field in _UPDATE_FIELDS}
    if body["folder-type"] != "public":
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    _positive_int(body["id"])
    _positive_int(body["parent-folder"])
    for field in ("name", "secret-policy"):
        _nonempty_text(body[field], maximum=128)
    for field in ("inherit-policy", "inherit-folder-ztna"):
        if body[field] not in {"enable", "disable"}:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    _ztna_control_semantics(body)
    body["inherit-permission"] = "disable"
    body["user-permission"] = [
        relation.body(principal_key="user-name") for relation in users
    ]
    body["group-permission"] = [
        relation.body(principal_key="group-name") for relation in groups
    ]
    return body


def _relations(
    record: Mapping[str, object],
    *,
    principal_key: str,
) -> tuple[_AclRelation, ...]:
    relation_key = (
        "user-permission" if principal_key == "user-name" else "group-permission"
    )
    return _relations_from_body(record.get(relation_key), principal_key=principal_key)


def _relations_from_body(value: object, *, principal_key: str) -> tuple[_AclRelation, ...]:
    if not isinstance(value, list) or len(value) > 128:
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    result: list[_AclRelation] = []
    for relation in value:
        if not isinstance(relation, Mapping):
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        relation_id = relation.get("id")
        if type(relation_id) is not int or not 0 <= relation_id <= _MAX_FOLDER_ID:
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        names = _principal_names(relation.get(principal_key))
        folder_permission = _nonempty_text(
            relation.get("folder-permission"), maximum=64
        )
        secret_permission = _nonempty_text(
            relation.get("secret-permission"), maximum=64
        )
        result.append(
            _AclRelation(relation_id, names, folder_permission, secret_permission)
        )
    return tuple(result)


def _principal_names(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    names: list[str] = []
    for item in value:
        name = item.get("name") if isinstance(item, Mapping) else item
        names.append(_nonempty_text(name, maximum=128))
    if len(set(names)) != len(names):
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return tuple(names)


def _grant_relation(
    relations: tuple[_AclRelation, ...],
    request: _FolderAclRequest,
) -> tuple[_AclRelation, ...]:
    result: list[_AclRelation] = []
    for relation in relations:
        if request.principal_name not in relation.names:
            result.append(relation)
            continue
        if relation.names != (request.principal_name,):
            raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    result.append(
        _AclRelation(
            0,
            (request.principal_name,),
            request.folder_permission,
            request.secret_permission,
        )
    )
    return tuple(result)


def _relation_semantics(
    relations: tuple[_AclRelation, ...],
) -> tuple[tuple[int, tuple[str, ...], str, str], ...]:
    return tuple(sorted(relation.semantic() for relation in relations))


def _folder_projection_semantics(record: Mapping[str, object]) -> dict[str, object]:
    """Return the exact fixed Folder projection used for drift/readback checks."""

    if set(_UPDATE_FIELDS) - set(record):
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    ztna_tags = record.get("ztna-ems-tag")
    if not isinstance(ztna_tags, list):
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return {
        "id": _positive_int(record.get("id")),
        "name": _nonempty_text(record.get("name"), maximum=128),
        "parent-folder": _positive_int(record.get("parent-folder")),
        "folder-type": record.get("folder-type"),
        "secret-policy": _nonempty_text(record.get("secret-policy"), maximum=128),
        "inherit-policy": record.get("inherit-policy"),
        "inherit-permission": _inherit_permission(record),
        "inherit-folder-ztna": _ztna_control_semantics(record)[0],
        "ztna-ems-tag": tuple(ztna_tags),
        "ztna-tags-match-logic": _ztna_control_semantics(record)[1],
        "user-permission": _relation_semantics(
            _relations(record, principal_key="user-name")
        ),
        "group-permission": _relation_semantics(
            _relations(record, principal_key="group-name")
        ),
    }


def _group_preview_projection(record: _FolderAclRecord) -> dict[str, object]:
    prepared = record.prepared
    return {
        "contract": "fortipam_v4_folder_group_acl_grant_workflow_v1",
        "preview_ref": record.preview_ref,
        "expires_at": record.expires_at,
        "Current State": {
            "selected_folder_id": prepared.request.folder_id,
            "requested_group_name": prepared.request.principal_name,
            "requested_folder_permission": prepared.request.folder_permission,
            "requested_secret_permission": prepared.request.secret_permission,
            "folder_exists": True,
            "folder_scope": "public_child",
            "permission_inheritance": prepared.current_inherit_permission,
            "effective_user_relation_count": prepared.current_user_relation_count,
            "effective_group_relation_count": prepared.current_group_relation_count,
            "requested_group_relation_present": prepared.requested_relation_present,
        },
        "Proposed Changes": {
            "operation": "grant_public_folder_group_acl",
            "folder_id": prepared.request.folder_id,
            "group_name": prepared.request.principal_name,
            "folder_permission": prepared.request.folder_permission,
            "secret_permission": prepared.request.secret_permission,
            "permission_inheritance_after_change": "disable",
        },
        "Expected State": {
            "folder_exists": True,
            "folder_scope": "public_child",
            "permission_inheritance": "disable",
            "requested_group_relation_present": True,
            "requested_folder_permission_matches": True,
            "requested_secret_permission_matches": True,
            "effective_user_relations_preserved": True,
            "effective_group_relations_preserved": True,
        },
        "device_write_executed": False,
    }


def _inherit_permission(record: Mapping[str, object]) -> str:
    value = record.get("inherit-permission")
    if value not in {"enable", "disable"}:
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _ztna_control_semantics(record: Mapping[str, object]) -> tuple[str, str]:
    """Validate the observed empty-tag Folder ZTNA projection without disclosure."""

    inherit = record.get("inherit-folder-ztna")
    tags = record.get("ztna-ems-tag")
    logic = record.get("ztna-tags-match-logic")
    if inherit not in {"enable", "disable"}:
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    if not isinstance(tags, list) or tags:
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    if logic not in {"and", "or"}:
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return inherit, logic


def _positive_int(value: object) -> int:
    if type(value) is not int or not 0 < value <= _MAX_FOLDER_ID:
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _nonempty_text(value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "FolderAclGrantLiveWorkflow",
    "FolderAclLiveWorkflowError",
    "FolderAclLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
