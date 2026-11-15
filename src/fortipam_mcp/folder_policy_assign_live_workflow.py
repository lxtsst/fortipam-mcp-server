"""One API-first, confirmation-gated Public child-Folder policy assignment."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import re
import secrets
import threading

from .folder_acl_live_workflow import (
    FolderAclLiveWorkflowTransport,
    _folder_record,
    _folder_update_body,
    _inherit_permission,
    _now,
    _positive_int,
    _relations,
    _require_requester,
    _valid_ref,
)


WORKFLOW_CONTRACT = "fortipam_v4_public_child_folder_policy_assign_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Public child Folder policy assignment is unavailable."
_TTL_SECONDS = 600
_MAX_FOLDER_ID = 2_147_483_647
_POLICY_NAME = re.compile(r"[^/\\\x00-\x1f\x7f]{1,64}\Z")


class FolderPolicyAssignLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded policy-assignment workflow."""


@dataclass(frozen=True, slots=True)
class _FolderPolicyAssignRequest:
    folder_id: int
    policy_name: str

    @classmethod
    def create(
        cls,
        *,
        folder_id: int,
        policy_name: str,
    ) -> "_FolderPolicyAssignRequest":
        if type(folder_id) is not int or not 0 < folder_id <= _MAX_FOLDER_ID:
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(folder_id=folder_id, policy_name=_policy_name(policy_name))


@dataclass(frozen=True, slots=True)
class _PreparedFolderPolicyAssign:
    request: _FolderPolicyAssignRequest
    current_body: dict[str, object]
    body: dict[str, object]

    def digest(self) -> str:
        return _state_digest(
            {
                "folder_id": self.request.folder_id,
                "current_body": self.current_body,
                "body": self.body,
            }
        )


@dataclass(frozen=True, slots=True)
class _FolderPolicyAssignRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    prepared: _PreparedFolderPolicyAssign
    current_digest: str
    state: str
    expires_at: int


class FolderPolicyAssignLiveWorkflow:
    """Volatile one-confirmation workflow for an explicit Folder Secret Policy."""

    def __init__(
        self,
        transport: FolderAclLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _FolderPolicyAssignRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        folder_id: int,
        policy_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current state and render one redacted Current/Proposed/Expected preview."""

        request = _FolderPolicyAssignRequest.create(
            folder_id=folder_id,
            policy_name=policy_name,
        )
        try:
            _require_requester(requester_digest)
        except Exception as exc:
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        prepared = self._prepare(request)
        record = _FolderPolicyAssignRecord(
            preview_ref="folder-policy-assign-preview-" + secrets.token_urlsafe(24),
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
                raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "folder-policy-assign-authorized-" + secrets.token_urlsafe(24)
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
        """Write one confirmed full projection and verify the policy assignment."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._prepare(record.prepared.request)
            if not hmac.compare_digest(current.digest(), record.current_digest):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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

    def _prepare(
        self,
        request: _FolderPolicyAssignRequest,
    ) -> _PreparedFolderPolicyAssign:
        try:
            current = deepcopy(self._current_body(request.folder_id))
            if _policy_name(current["secret-policy"]) == request.policy_name:
                raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            desired_body = deepcopy(current)
            desired_body["secret-policy"] = request.policy_name
        except FolderPolicyAssignLiveWorkflowError:
            raise
        except Exception as exc:
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        return _PreparedFolderPolicyAssign(
            request=request, current_body=current, body=desired_body,
        )

    def _verify_readback(self, prepared: _PreparedFolderPolicyAssign) -> bool:
        try:
            actual = self._current_body(prepared.request.folder_id)
            return hmac.compare_digest(
                _state_digest(actual),
                _state_digest(prepared.body),
            )
        except Exception:
            return False

    def _current_body(self, folder_id: int) -> dict[str, object]:
        child = self._read_folder(folder_id)
        if _positive_int(child.get("id")) != folder_id:
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if child.get("folder-type") != "public":
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        _positive_int(child.get("parent-folder"))
        if child.get("inherit-policy") != "disable":
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if _inherit_permission(child) != "disable":
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        users = _relations(child, principal_key="user-name")
        groups = _relations(child, principal_key="group-name")
        body = _folder_update_body(child, users, groups)
        _policy_name(body["secret-policy"])
        return body

    def _read_folder(self, folder_id: int) -> Mapping[str, object]:
        try:
            response = self._transport.read_folder(folder_id)
            return _folder_record(response)
        except FolderPolicyAssignLiveWorkflowError:
            raise
        except Exception as exc:
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc

    def _record_for_preview_locked(self, preview_ref: str) -> _FolderPolicyAssignRecord:
        if not _valid_ref(preview_ref, "folder-policy-assign-preview-"):
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _FolderPolicyAssignRecord:
        if not _valid_ref(authorization_ref, "folder-policy-assign-authorized-"):
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _FolderPolicyAssignRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _FolderPolicyAssignRecord,
        requester_digest: str,
    ) -> None:
        try:
            _require_requester(requester_digest)
        except Exception as exc:
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _FolderPolicyAssignRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "selected_folder_id": record.prepared.request.folder_id,
                "requested_policy_name": record.prepared.request.policy_name,
                "folder_exists": True,
                "folder_scope": "public_child",
                "policy_inheritance": "disable",
                "permission_inheritance": "disable",
                "explicit_policy_binding_present": True,
                "requested_policy_already_matches": False,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "assign_public_child_folder_secret_policy_via_api",
                "folder_id": record.prepared.request.folder_id,
                "current_policy_identifier_returned": False,
                "secret_policy": record.prepared.request.policy_name,
                "policy_inheritance_preserved": True,
                "non_policy_projection_preserved": True,
            },
            "Expected State": {
                "folder_id_matches": True,
                "folder_exists": True,
                "folder_scope": "public_child",
                "policy_inheritance": "disable",
                "requested_explicit_policy_matches": True,
                "parent_relation_preserved": True,
                "permission_and_ztna_projection_preserved": True,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _FolderPolicyAssignRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_public_child_folder_policy_assign_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "assign_prior_explicit_policy_after_new_confirmation",
            "folder_id_returned": False,
            "policy_identifier_returned": False,
            "raw_api_response_returned": False,
        }


def _policy_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or _POLICY_NAME.fullmatch(value) is None
    ):
        raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _state_digest(value: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FolderPolicyAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "FolderPolicyAssignLiveWorkflow",
    "FolderPolicyAssignLiveWorkflowError",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
