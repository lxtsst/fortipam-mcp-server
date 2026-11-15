"""One confirmation-gated recovery for the accepted FortiPAM Character Set."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Protocol

from .character_set_http_transport import (
    CharacterSetDeleteInspection,
    CharacterSetDeleteReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_character_set_delete_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Character Set recovery is unavailable."
_TTL_SECONDS = 600


class CharacterSetDeleteLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the fixed recovery workflow."""


class CharacterSetDeleteLiveWorkflowTransport(Protocol):
    """Exact accepted-target preflight and DELETE/absence contract."""

    def inspect_delete_target(self) -> CharacterSetDeleteInspection: ...

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> CharacterSetDeleteReadback: ...


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    target_digest: str
    state: str
    expires_at: int


class CharacterSetDeleteLiveWorkflow:
    """Volatile one-confirmation flow for the exact unreferenced b25 target."""

    def __init__(
        self,
        transport: CharacterSetDeleteLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _Record] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        _require_requester(requester_digest)
        current = self._inspect()
        if (
            not current.exists
            or not current.eligible_fixed_character_set
            or current.password_policy_reference_count != 0
        ):
            raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _Record(
            preview_ref="character-set-delete-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
            target_digest=current.target_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect()
            if not hmac.compare_digest(
                _inspection_digest(current),
                record.current_digest,
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "character-set-delete-authorized-" + secrets.token_urlsafe(24)
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
        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if not hmac.compare_digest(
                _inspection_digest(current),
                record.current_digest,
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.delete_and_readback(record.target_digest)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, CharacterSetDeleteReadback)
                and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> CharacterSetDeleteInspection:
        try:
            result = self._transport.inspect_delete_target()
        except Exception as exc:
            raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, CharacterSetDeleteInspection):
            raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _Record:
        if not _valid_ref(preview_ref, "character-set-delete-preview-"):
            raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _Record:
        if not _valid_ref(authorization_ref, "character-set-delete-authorized-"):
            raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _Record,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _Record, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _Record) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "accepted_character_set_exists": True,
                "exact_fixed_character_set_observed": True,
                "password_policy_reference_count": 0,
                "read_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "delete_exact_unreferenced_character_set_via_api",
                "character_set_count_affected": 1,
                "irreversible_after_execution": True,
                "password_policy_association_changes": False,
                "password_values_generated_or_handled": False,
            },
            "Expected State": {
                "accepted_character_set_absent": True,
                "password_policy_association_changes": False,
                "password_values_generated_or_handled": False,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        }

    def _result(self, record: _Record, *, idempotent_replay: bool) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_character_set_delete_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_character_set_create_action_required",
            "irreversible_after_execution": True,
            "character_set_name_returned": False,
            "character_set_value_returned": False,
            "password_policy_association_changes": False,
            "password_values_generated_or_handled": False,
            "raw_api_response_returned": False,
        }


def _inspection_digest(inspection: CharacterSetDeleteInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "exists": inspection.exists,
                "eligible_fixed_character_set": inspection.eligible_fixed_character_set,
                "password_policy_reference_count": (
                    inspection.password_policy_reference_count
                ),
                "target_digest": inspection.target_digest,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CharacterSetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "CharacterSetDeleteLiveWorkflow",
    "CharacterSetDeleteLiveWorkflowError",
    "CharacterSetDeleteLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
