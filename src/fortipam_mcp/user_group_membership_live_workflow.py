"""One confirmation-gated FortiPAM remote LDAP User Group match change."""

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
    USER_GROUP_MEMBERSHIP_CONFIGURATION,
    UserGroupMembershipInspection,
    UserGroupMembershipReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_user_group_membership_change_cli_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 User Group membership action is unavailable."
_TTL_SECONDS = 600
_USER_GROUP_NAME = re.compile(
    r"mcp-v4-user-group-[A-Za-z0-9][A-Za-z0-9._-]{0,43}\Z"
)
_LDAP_SERVER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_LDAP_GROUP_DN = re.compile(r"[A-Za-z0-9][A-Za-z0-9=,._@+:-]{0,253}\Z")


class UserGroupMembershipLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded membership workflow."""


class UserGroupMembershipLiveWorkflowTransport(Protocol):
    """Exact baseline, match-add, and categorical readback contract."""

    def inspect_membership(
        self,
        user_group_name: str,
        ldap_server_name: str,
        primary_ldap_group_dn: str,
        additional_ldap_group_dn: str,
    ) -> UserGroupMembershipInspection: ...

    def add_remote_ldap_match_and_readback(
        self,
        user_group_name: str,
        ldap_server_name: str,
        primary_ldap_group_dn: str,
        additional_ldap_group_dn: str,
    ) -> UserGroupMembershipReadback: ...


@dataclass(frozen=True, slots=True)
class _UserGroupMembershipRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    user_group_name: str
    ldap_server_name: str
    primary_ldap_group_dn: str
    additional_ldap_group_dn: str
    current_digest: str
    state: str
    expires_at: int


class UserGroupMembershipChangeLiveWorkflow:
    """Volatile one-confirmation flow that adds only match ID 2."""

    def __init__(
        self,
        transport: UserGroupMembershipLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _UserGroupMembershipRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        user_group_name: str,
        ldap_server_name: str,
        primary_ldap_group_dn: str,
        additional_ldap_group_dn: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read the exact V4 create baseline and render C/P/E without a write."""

        safe_group = _user_group_name(user_group_name)
        safe_server = _ldap_server_name(ldap_server_name)
        safe_primary = _ldap_group_dn(primary_ldap_group_dn)
        safe_additional = _ldap_group_dn(additional_ldap_group_dn)
        _require_distinct_dns(safe_primary, safe_additional)
        _require_requester(requester_digest)
        current = self._inspect(
            safe_group,
            safe_server,
            safe_primary,
            safe_additional,
        )
        if not current.baseline_verified:
            raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _UserGroupMembershipRecord(
            preview_ref="user-group-membership-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            user_group_name=safe_group,
            ldap_server_name=safe_server,
            primary_ldap_group_dn=safe_primary,
            additional_ldap_group_dn=safe_additional,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the full one-match baseline remains unchanged."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect_for_record(record)
            if (
                not current.baseline_verified
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "user-group-membership-authorized-" + secrets.token_urlsafe(24)
            )
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
        """Add only the confirmed second match and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect_for_record(record)
            if (
                not current.baseline_verified
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.add_remote_ldap_match_and_readback(
                record.user_group_name,
                record.ldap_server_name,
                record.primary_ldap_group_dn,
                record.additional_ldap_group_dn,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, UserGroupMembershipReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(
        self,
        user_group_name: str,
        ldap_server_name: str,
        primary_ldap_group_dn: str,
        additional_ldap_group_dn: str,
    ) -> UserGroupMembershipInspection:
        try:
            result = self._transport.inspect_membership(
                user_group_name,
                ldap_server_name,
                primary_ldap_group_dn,
                additional_ldap_group_dn,
            )
        except Exception as exc:
            raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, UserGroupMembershipInspection):
            raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _inspect_for_record(
        self,
        record: _UserGroupMembershipRecord,
    ) -> UserGroupMembershipInspection:
        return self._inspect(
            record.user_group_name,
            record.ldap_server_name,
            record.primary_ldap_group_dn,
            record.additional_ldap_group_dn,
        )

    def _record_for_preview_locked(
        self,
        preview_ref: str,
    ) -> _UserGroupMembershipRecord:
        if not _valid_ref(preview_ref, "user-group-membership-preview-"):
            raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _UserGroupMembershipRecord:
        if not _valid_ref(authorization_ref, "user-group-membership-authorized-"):
            raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _UserGroupMembershipRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _UserGroupMembershipRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is not None:
            self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        now = self._clock()
        expired = [
            key
            for key, record in self._records.items()
            if now >= record.expires_at and record.state != "completed"
        ]
        for key in expired:
            record = self._records.pop(key)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    @staticmethod
    def _preview_projection(
        record: _UserGroupMembershipRecord,
        current: UserGroupMembershipInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "Current State": {
                "requested_user_group_name": record.user_group_name,
                "requested_ldap_server_name": record.ldap_server_name,
                "requested_primary_ldap_group_dn": record.primary_ldap_group_dn,
                "requested_additional_ldap_group_dn": record.additional_ldap_group_dn,
                "user_group_exists": current.user_group_exists,
                "known_single_match_baseline_verified": current.baseline_verified,
                "additional_remote_group_match_present": current.additional_match_present,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "add_second_remote_ldap_group_match_via_cli_fallback",
                "user_group_name": record.user_group_name,
                "ldap_server_name": record.ldap_server_name,
                "primary_ldap_group_dn": record.primary_ldap_group_dn,
                "additional_ldap_group_dn": record.additional_ldap_group_dn,
                "configuration_profile": USER_GROUP_MEMBERSHIP_CONFIGURATION,
                "existing_remote_group_match_preserved": True,
                "additional_remote_group_match_added": True,
                "role_assignment": False,
                "auto_provision_rule_created": False,
                "folder_or_secret_acl_change": False,
                "user_import_or_session_change": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "user_group_name_matches": True,
                "user_group_exists": True,
                "ldap_server_member_present": True,
                "primary_remote_group_match_preserved": True,
                "additional_remote_group_match_present": True,
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
        record: _UserGroupMembershipRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_user_group_membership_change_cli_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_user_group_membership_remove_action_required",
            "user_group_name_returned": False,
            "ldap_server_identifier_returned": False,
            "primary_ldap_group_identifier_returned": False,
            "additional_ldap_group_identifier_returned": False,
            "existing_remote_group_match_preserved": True,
            "additional_remote_group_match_added": succeeded,
            "role_assignment": False,
            "auto_provision_rule_created": False,
            "folder_or_secret_acl_change": False,
            "user_import_or_session_change": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: UserGroupMembershipInspection) -> str:
    payload = json.dumps(
        {
            "user_group_exists": inspection.user_group_exists,
            "ldap_server_member_present": inspection.ldap_server_member_present,
            "primary_match_server_present": inspection.primary_match_server_present,
            "primary_match_group_dn_present": inspection.primary_match_group_dn_present,
            "additional_match_present": inspection.additional_match_present,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _user_group_name(value: str) -> str:
    if not isinstance(value, str) or _USER_GROUP_NAME.fullmatch(value) is None:
        raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _ldap_server_name(value: str) -> str:
    if not isinstance(value, str) or _LDAP_SERVER_NAME.fullmatch(value) is None:
        raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _ldap_group_dn(value: str) -> str:
    if not isinstance(value, str) or _LDAP_GROUP_DN.fullmatch(value) is None:
        raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_distinct_dns(primary: str, additional: str) -> None:
    if primary == additional:
        raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise UserGroupMembershipLiveWorkflowError(WORKFLOW_UNAVAILABLE)


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
    "UserGroupMembershipChangeLiveWorkflow",
    "UserGroupMembershipLiveWorkflowError",
    "UserGroupMembershipLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
