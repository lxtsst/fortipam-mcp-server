"""One confirmation-gated FortiPAM remote LDAP User Group create workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from typing import Protocol

from .user_group_ssh_transport import (
    USER_GROUP_CONFIGURATION,
    UserGroupInspection,
    UserGroupReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_user_group_create_cli_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 User Group create action is unavailable."
_TTL_SECONDS = 600
_USER_GROUP_NAME = re.compile(
    r"mcp-v4-user-group-[A-Za-z0-9][A-Za-z0-9._-]{0,43}\Z"
)
_LDAP_SERVER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_LDAP_GROUP_DN = re.compile(r"[A-Za-z0-9][A-Za-z0-9=,._@+:-]{0,253}\Z")


class UserGroupLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded User Group workflow."""


class UserGroupLiveWorkflowTransport(Protocol):
    """Exact User Group preflight and create/readback contract."""

    def inspect(self, user_group_name: str) -> UserGroupInspection: ...

    def create_and_readback(
        self,
        user_group_name: str,
        ldap_server_name: str,
        ldap_group_dn: str,
    ) -> UserGroupReadback: ...


@dataclass(frozen=True, slots=True)
class _UserGroupRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    user_group_name: str
    ldap_server_name: str
    ldap_group_dn: str
    current_digest: str
    state: str
    expires_at: int


class UserGroupCreateLiveWorkflow:
    """Volatile one-confirmation flow for one remote LDAP User Group."""

    def __init__(
        self,
        transport: UserGroupLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _UserGroupRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        user_group_name: str,
        ldap_server_name: str,
        ldap_group_dn: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current state and render C/P/E without device mutation."""

        safe_group = _user_group_name(user_group_name)
        safe_server = _ldap_server_name(ldap_server_name)
        safe_dn = _ldap_group_dn(ldap_group_dn)
        _require_requester(requester_digest)
        current = self._inspect(safe_group)
        if current.user_group_exists:
            raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _UserGroupRecord(
            preview_ref="user-group-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            user_group_name=safe_group,
            ldap_server_name=safe_server,
            ldap_group_dn=safe_dn,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the absent User Group remains absent."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(record.user_group_name)
            if current.user_group_exists or _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "user-group-authorized-" + secrets.token_urlsafe(24)
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
        """Create only the confirmed unattached User Group and verify it."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.user_group_name)
            if current.user_group_exists or _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(
                record.user_group_name,
                record.ldap_server_name,
                record.ldap_group_dn,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, UserGroupReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, user_group_name: str) -> UserGroupInspection:
        try:
            result = self._transport.inspect(user_group_name)
        except Exception as exc:
            raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, UserGroupInspection):
            raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _UserGroupRecord:
        if not _valid_ref(preview_ref, "user-group-preview-"):
            raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _UserGroupRecord:
        if not _valid_ref(authorization_ref, "user-group-authorized-"):
            raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _UserGroupRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _UserGroupRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(
        record: _UserGroupRecord,
        current: UserGroupInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_user_group_name": record.user_group_name,
                "requested_ldap_server_name": record.ldap_server_name,
                "requested_ldap_group_dn": record.ldap_group_dn,
                "user_group_name_exists": current.user_group_exists,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "create_remote_ldap_user_group_via_cli_fallback",
                "user_group_name": record.user_group_name,
                "ldap_server_name": record.ldap_server_name,
                "ldap_group_dn": record.ldap_group_dn,
                "configuration_profile": USER_GROUP_CONFIGURATION,
                "one_ldap_server_member_created": True,
                "one_remote_group_match_created": True,
                "role_assignment": False,
                "auto_provision_rule_created": False,
                "folder_or_secret_acl_change": False,
                "user_import_or_session_change": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "user_group_name_matches": True,
                "user_group_name_exists": True,
                "ldap_server_member_matches": True,
                "remote_group_match_matches": True,
                "role_assignment": False,
                "auto_provision_rule_created": False,
                "folder_or_secret_acl_change": False,
                "user_import_or_session_change": False,
                "readback_transport": "ssh_cli_fallback",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _UserGroupRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_user_group_create_cli_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_user_group_delete_action_required",
            "user_group_name_returned": False,
            "ldap_server_identifier_returned": False,
            "ldap_group_identifier_returned": False,
            "role_assignment": False,
            "auto_provision_rule_created": False,
            "folder_or_secret_acl_change": False,
            "user_import_or_session_change": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: UserGroupInspection) -> str:
    payload = json.dumps(
        {"user_group_exists": inspection.user_group_exists},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _user_group_name(value: str) -> str:
    if not isinstance(value, str) or _USER_GROUP_NAME.fullmatch(value) is None:
        raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _ldap_server_name(value: str) -> str:
    if not isinstance(value, str) or _LDAP_SERVER_NAME.fullmatch(value) is None:
        raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _ldap_group_dn(value: str) -> str:
    if not isinstance(value, str) or _LDAP_GROUP_DN.fullmatch(value) is None:
        raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise UserGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)


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
    "UserGroupCreateLiveWorkflow",
    "UserGroupLiveWorkflowError",
    "UserGroupLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
