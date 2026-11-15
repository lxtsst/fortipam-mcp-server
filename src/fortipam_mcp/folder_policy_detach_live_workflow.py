"""One API-first, confirmation-gated Public child-Folder policy detach."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
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


WORKFLOW_CONTRACT = "fortipam_v4_public_child_folder_policy_detach_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Public child Folder policy detach is unavailable."
_TTL_SECONDS = 600
_MAX_FOLDER_ID = 2_147_483_647


class FolderPolicyDetachLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded policy-detach workflow."""


@dataclass(frozen=True, slots=True)
class _FolderPolicyDetachRequest:
    folder_id: int

    @classmethod
    def create(cls, *, folder_id: int) -> "_FolderPolicyDetachRequest":
        if type(folder_id) is not int or not 0 < folder_id <= _MAX_FOLDER_ID:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(folder_id=folder_id)


@dataclass(frozen=True, slots=True)
class _PreparedFolderPolicyDetach:
    request: _FolderPolicyDetachRequest
    body: dict[str, object]

    def digest(self) -> str:
        return _state_digest(
            {
                "folder_id": self.request.folder_id,
                "body": self.body,
            }
        )


@dataclass(frozen=True, slots=True)
class _FolderPolicyDetachRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    prepared: _PreparedFolderPolicyDetach
    current_digest: str
    state: str
    expires_at: int


class FolderPolicyDetachLiveWorkflow:
    """One-confirmation detach of an explicit policy from a Public child Folder."""

    def __init__(
        self,
        transport: FolderAclLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _FolderPolicyDetachRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        folder_id: int,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read one explicit-policy Folder and render C/P/E without mutation."""

        request = _FolderPolicyDetachRequest.create(folder_id=folder_id)
        try:
            _require_requester(requester_digest)
        except Exception as exc:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        prepared = self._prepare(request)
        record = _FolderPolicyDetachRecord(
            preview_ref="folder-policy-detach-preview-" + secrets.token_urlsafe(24),
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
        """Confirm the exact explicit-policy baseline before one detach."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._prepare(record.prepared.request)
            if not hmac.compare_digest(current.digest(), record.current_digest):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "folder-policy-detach-authorized-" + secrets.token_urlsafe(24)
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
        """Enable policy inheritance and verify the preserved Folder projection."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._prepare(record.prepared.request)
            if not hmac.compare_digest(current.digest(), record.current_digest):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        request: _FolderPolicyDetachRequest,
    ) -> _PreparedFolderPolicyDetach:
        try:
            current = self._explicit_policy_body(request.folder_id)
            desired_body = dict(current)
            desired_body["inherit-policy"] = "enable"
        except FolderPolicyDetachLiveWorkflowError:
            raise
        except Exception as exc:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        return _PreparedFolderPolicyDetach(request=request, body=desired_body)

    def _verify_readback(self, prepared: _PreparedFolderPolicyDetach) -> bool:
        try:
            actual = self._inherited_policy_body(prepared.request.folder_id)
            expected_projection = _projection_without_policy_state(prepared.body)
            actual_projection = _projection_without_policy_state(actual)
            return hmac.compare_digest(
                _state_digest(actual_projection),
                _state_digest(expected_projection),
            )
        except Exception:
            return False

    def _explicit_policy_body(self, folder_id: int) -> dict[str, object]:
        child = self._read_folder(folder_id)
        return self._folder_body(
            child,
            folder_id=folder_id,
            expected_inherit_policy="disable",
        )

    def _inherited_policy_body(self, folder_id: int) -> dict[str, object]:
        child = self._read_folder(folder_id)
        return self._folder_body(
            child,
            folder_id=folder_id,
            expected_inherit_policy="enable",
        )

    @staticmethod
    def _folder_body(
        child: Mapping[str, object],
        *,
        folder_id: int,
        expected_inherit_policy: str,
    ) -> dict[str, object]:
        if _positive_int(child.get("id")) != folder_id:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if child.get("folder-type") != "public":
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        _positive_int(child.get("parent-folder"))
        if child.get("inherit-policy") != expected_inherit_policy:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if _inherit_permission(child) != "disable":
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        users = _relations(child, principal_key="user-name")
        groups = _relations(child, principal_key="group-name")
        return _folder_update_body(child, users, groups)

    def _read_folder(self, folder_id: int) -> Mapping[str, object]:
        try:
            response = self._transport.read_folder(folder_id)
            return _folder_record(response)
        except FolderPolicyDetachLiveWorkflowError:
            raise
        except Exception as exc:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc

    def _record_for_preview_locked(self, preview_ref: str) -> _FolderPolicyDetachRecord:
        if not _valid_ref(preview_ref, "folder-policy-detach-preview-"):
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _FolderPolicyDetachRecord:
        if not _valid_ref(authorization_ref, "folder-policy-detach-authorized-"):
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _FolderPolicyDetachRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _FolderPolicyDetachRecord,
        requester_digest: str,
    ) -> None:
        try:
            _require_requester(requester_digest)
        except Exception as exc:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _FolderPolicyDetachRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "selected_folder_id": record.prepared.request.folder_id,
                "folder_exists": True,
                "folder_scope": "public_child",
                "policy_inheritance": "disable",
                "permission_inheritance": "disable",
                "explicit_policy_binding_present": True,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "detach_public_child_folder_explicit_secret_policy_via_api",
                "folder_id": record.prepared.request.folder_id,
                "current_policy_identifier_returned": False,
                "policy_inheritance_enabled": True,
                "non_policy_projection_preserved": True,
            },
            "Expected State": {
                "folder_id_matches": True,
                "folder_exists": True,
                "folder_scope": "public_child",
                "policy_inheritance": "enable",
                "explicit_policy_binding_removed": True,
                "parent_relation_preserved": True,
                "permission_and_ztna_projection_preserved": True,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _FolderPolicyDetachRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_public_child_folder_policy_detach_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "restore_explicit_policy_requires_new_assignment_confirmation",
            "folder_id_returned": False,
            "policy_identifier_returned": False,
            "raw_api_response_returned": False,
        }


def _projection_without_policy_state(body: Mapping[str, object]) -> dict[str, object]:
    """Compare all stable Folder fields while excluding inherited policy identity."""

    return {
        key: value
        for key, value in body.items()
        if key not in {"inherit-policy", "secret-policy"}
    }


def _state_digest(value: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FolderPolicyDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "FolderPolicyDetachLiveWorkflow",
    "FolderPolicyDetachLiveWorkflowError",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
