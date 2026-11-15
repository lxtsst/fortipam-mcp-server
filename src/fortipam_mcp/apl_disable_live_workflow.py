"""One confirmation-gated FortiPAM Auto-Provision Rule disable workflow."""

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
from typing import Literal, Protocol

from .apl_ssh_transport import (
    APL_DISABLE_CONFIGURATION,
    AplDisableInspection,
    AplReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_auto_provision_rule_disable_cli_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Auto-Provision Rule disable action is unavailable."
_TTL_SECONDS = 600
_APL_NAME = re.compile(r"mcp-v4-apl-[A-Za-z0-9][A-Za-z0-9._-]{0,51}\Z")
_USER_GROUP_NAME = re.compile(
    r"mcp-v4-user-group-[A-Za-z0-9][A-Za-z0-9._-]{0,43}\Z"
)
_ROLE_NAME = re.compile(r"mcp-v4-role-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")


class AplDisableLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded APL-disable workflow."""


class AplDisableLiveWorkflowTransport(Protocol):
    """Exact enabled-APL preflight and disable/readback contract."""

    def inspect_disable(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplDisableInspection: ...

    def disable_and_readback(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplReadback: ...


@dataclass(frozen=True, slots=True)
class _AplDisableRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    auto_provision_rule_name: str
    remote_user_group_name: str
    role_name: str
    current_digest: str
    state: str
    expires_at: int


class AplDisableLiveWorkflow:
    """Volatile one-confirmation flow that only disables an exact V4 APL."""

    def __init__(
        self,
        transport: AplDisableLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
        write_transport: Literal["ssh_cli_fallback", "rest_700"] = "ssh_cli_fallback",
    ) -> None:
        if write_transport not in ("ssh_cli_fallback", "rest_700"):
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._write_transport = write_transport
        self._contract = (WORKFLOW_CONTRACT if write_transport == "ssh_cli_fallback"
                          else "fortipam_v4_auto_provision_rule_disable_rest_700_workflow_v1")
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _AplDisableRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read the exact enabled baseline and render C/P/E without mutation."""

        safe_rule = _apl_name(auto_provision_rule_name)
        safe_group = _user_group_name(remote_user_group_name)
        safe_role = _role_name(role_name)
        _require_requester(requester_digest)
        current = self._inspect(safe_rule, safe_group, safe_role)
        if not current.disable_baseline_verified:
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _AplDisableRecord(
            preview_ref="apl-disable-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            auto_provision_rule_name=safe_rule,
            remote_user_group_name=safe_group,
            role_name=safe_role,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the exact enabled APL baseline remains unchanged."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(
                record.auto_provision_rule_name,
                record.remote_user_group_name,
                record.role_name,
            )
            if (
                not current.disable_baseline_verified
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "apl-disable-authorized-" + secrets.token_urlsafe(24)
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": self._contract,
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Disable only the confirmed exact APL baseline and verify it."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(
                record.auto_provision_rule_name,
                record.remote_user_group_name,
                record.role_name,
            )
            if (
                not current.disable_baseline_verified
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.disable_and_readback(
                record.auto_provision_rule_name,
                record.remote_user_group_name,
                record.role_name,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, AplReadback):
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
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplDisableInspection:
        try:
            result = self._transport.inspect_disable(
                auto_provision_rule_name,
                remote_user_group_name,
                role_name,
            )
        except Exception as exc:
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, AplDisableInspection):
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _AplDisableRecord:
        if not _valid_ref(preview_ref, "apl-disable-preview-"):
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _AplDisableRecord:
        if not _valid_ref(authorization_ref, "apl-disable-authorized-"):
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _AplDisableRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _AplDisableRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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

    def _preview_projection(
        self,
        record: _AplDisableRecord,
        current: AplDisableInspection,
    ) -> dict[str, object]:
        return {
            "contract": self._contract,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_auto_provision_rule_name": record.auto_provision_rule_name,
                "requested_remote_user_group_name": record.remote_user_group_name,
                "requested_role_name": record.role_name,
                "auto_provision_rule_exists": current.auto_provision_rule_exists,
                "status_enabled": current.status_enabled,
                "remote_user_group_matches": current.remote_user_group_matches,
                "role_matches": current.role_matches,
                "existing_v4_remote_user_group_exists": (
                    current.remote_user_group_exists
                ),
                "existing_v4_role_exists": current.role_exists,
                "write_transport": self._write_transport,
            },
            "Proposed Changes": {
                "operation": ("disable_existing_auto_provision_rule_via_cli_fallback"
                              if self._write_transport == "ssh_cli_fallback"
                              else "disable_existing_auto_provision_rule_via_rest_700"),
                "auto_provision_rule_name": record.auto_provision_rule_name,
                "remote_user_group_name": record.remote_user_group_name,
                "role_name": record.role_name,
                "configuration_profile": APL_DISABLE_CONFIGURATION,
                "status": "disabled",
                "remote_user_group_reference_preserved": True,
                "role_reference_preserved": True,
                "auto_provisioning_disabled": True,
                "existing_rule_fields_other_than_status_modified": False,
                "user_group_or_role_created": False,
                "identity_server_or_login_flow_changed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "auto_provision_rule_name_matches": True,
                "auto_provision_rule_exists": True,
                "status_disabled": True,
                "remote_user_group_matches": True,
                "role_matches": True,
                "auto_provisioning_disabled": True,
                "existing_rule_fields_other_than_status_modified": False,
                "user_group_or_role_created": False,
                "identity_server_or_login_flow_changed": False,
                "readback_transport": self._write_transport,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _AplDisableRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": ("fortipam_v4_auto_provision_rule_disable_cli_execution_v1"
                         if self._write_transport == "ssh_cli_fallback"
                         else "fortipam_v4_auto_provision_rule_disable_rest_700_execution_v1"),
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_auto_provision_rule_enable_action_required",
            "auto_provision_rule_name_returned": False,
            "remote_user_group_identifier_returned": False,
            "role_identifier_returned": False,
            "status": "disabled",
            "auto_provisioning_disabled": True,
            "existing_rule_fields_other_than_status_modified": False,
            "user_group_or_role_created": False,
            "identity_server_or_login_flow_changed": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: AplDisableInspection) -> str:
    payload = json.dumps(
        {
            "auto_provision_rule_exists": inspection.auto_provision_rule_exists,
            "status_enabled": inspection.status_enabled,
            "remote_user_group_matches": inspection.remote_user_group_matches,
            "role_matches": inspection.role_matches,
            "remote_user_group_exists": inspection.remote_user_group_exists,
            "role_exists": inspection.role_exists,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _apl_name(value: str) -> str:
    if not isinstance(value, str) or _APL_NAME.fullmatch(value) is None:
        raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _user_group_name(value: str) -> str:
    if not isinstance(value, str) or _USER_GROUP_NAME.fullmatch(value) is None:
        raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _role_name(value: str) -> str:
    if not isinstance(value, str) or _ROLE_NAME.fullmatch(value) is None:
        raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AplDisableLiveWorkflowError(WORKFLOW_UNAVAILABLE)


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
    "AplDisableLiveWorkflow",
    "AplDisableLiveWorkflowError",
    "AplDisableLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
