"""One confirmation-gated FortiPAM Character Set create workflow."""

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

from .character_set_http_transport import (
    CHARACTER_SET_NAME_PREFIX,
    CHARACTER_SET_VALUE,
    CharacterSetInspection,
    CharacterSetReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_character_set_create_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Character Set action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-char-set-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")


class CharacterSetLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded workflow."""


class CharacterSetLiveWorkflowTransport(Protocol):
    """Exact Character Set preflight and create/readback contract."""

    def inspect(self, name: str) -> CharacterSetInspection: ...

    def create_and_readback(self, name: str) -> CharacterSetReadback: ...


@dataclass(frozen=True, slots=True)
class _CharacterSetRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    name: str
    current_digest: str
    state: str
    expires_at: int


class CharacterSetCreateLiveWorkflow:
    """Volatile one-confirmation flow for one unattached symbol Character Set."""

    def __init__(
        self,
        transport: CharacterSetLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _CharacterSetRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, name: str, requester_digest: str) -> dict[str, object]:
        """Read current state and render the fixed C/P/E without a write."""

        safe_name = _name(name)
        _require_requester(requester_digest)
        current = self._inspect(safe_name)
        if current.exists:
            raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _CharacterSetRecord(
            preview_ref="character-set-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            name=safe_name,
            current_digest=_inspection_digest(safe_name, current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm unchanged absence and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(record.name)
            if not hmac.compare_digest(
                _inspection_digest(record.name, current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "character-set-authorized-" + secrets.token_urlsafe(24)
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
        """Create only the confirmed Character Set and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.name)
            if not hmac.compare_digest(
                _inspection_digest(record.name, current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(record.name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, CharacterSetReadback) and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, name: str) -> CharacterSetInspection:
        try:
            result = self._transport.inspect(name)
        except Exception as exc:
            raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, CharacterSetInspection):
            raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _CharacterSetRecord:
        if not _valid_ref(preview_ref, "character-set-preview-"):
            raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _CharacterSetRecord:
        if not _valid_ref(authorization_ref, "character-set-authorized-"):
            raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _CharacterSetRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _CharacterSetRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _CharacterSetRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_character_set_name": record.name,
                "character_set_exists": False,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "create_documented_symbol_character_set_via_api",
                "character_set_name": record.name,
                "character_set_value": CHARACTER_SET_VALUE,
                "configuration_profile": "documented-symbol-set-v1",
                "password_policy_or_template_association_changes": False,
            },
            "Expected State": {
                "character_set_exists": True,
                "character_set_name_matches": True,
                "character_set_value_matches": True,
                "password_policy_or_template_association_changes": False,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _CharacterSetRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_character_set_create_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_character_set_delete_action_required",
            "character_set_name_returned": False,
            "character_set_value_returned": False,
            "password_policy_or_template_association_changes": False,
            "raw_api_response_returned": False,
        }


def _inspection_digest(name: str, inspection: CharacterSetInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {"name": name, "exists": inspection.exists},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CharacterSetLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "CHARACTER_SET_NAME_PREFIX",
    "CharacterSetCreateLiveWorkflow",
    "CharacterSetLiveWorkflowError",
    "CharacterSetLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
