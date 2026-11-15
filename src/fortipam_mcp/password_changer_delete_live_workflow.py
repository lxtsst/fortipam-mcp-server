"""One-shot C/P/E recovery for one exact unreferenced Unix changer clone."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from typing import Callable

from .password_changer_delete_http_transport import (
    FortiPamUnixPasswordChangerDeleteHttpTransport,
    PasswordChangerDeleteInspection,
    PasswordChangerDeleteReadback,
)


CONTRACT = "fortipam_v4_unix_password_changer_delete_700_candidate_v1"
_UNAVAILABLE = "FortiPAM V4 Unix Password Changer recovery is unavailable."
_TTL = 600


class PasswordChangerDeleteLiveWorkflowError(RuntimeError):
    """Non-disclosing recovery workflow failure."""


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    target_digest: str
    source_digest: str
    expires_at: int
    state: str


class PasswordChangerDeleteLiveWorkflow:
    """Keep previews volatile and the one DELETE claim durable."""

    def __init__(
        self,
        transport: FortiPamUnixPasswordChangerDeleteHttpTransport,
        claim_path: Path,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(transport, FortiPamUnixPasswordChangerDeleteHttpTransport):
            raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
        self._transport = transport
        self._claim_path = Path(claim_path)
        if not self._claim_path.is_absolute():
            raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
        self._clock = clock or (lambda: int(time.time()))
        self._records: dict[str, _Record] = {}
        self._authorizations: dict[str, str] = {}
        self._results: dict[str, dict[str, object]] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        _requester(requester_digest)
        with self._lock:
            self._require_unconsumed()
            current = self._inspect()
            if not current.eligible:
                raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
            record = _Record(
                "password-changer-delete-preview-" + secrets.token_urlsafe(24),
                None, requester_digest, current.target_digest,
                current.source_digest, self._clock() + _TTL, "previewed",
            )
            self._records[record.preview_ref] = record
        return {
            "contract": CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "bound_exact_unix_clone_exists": True,
                "source_and_clone_projection_match": True,
                "template_secret_target_references_known_zero": True,
                "procedure_values_returned": False,
            },
            "Proposed Changes": {
                "operation": "delete_bound_unreferenced_unix_password_changer",
                "password_changer_count_affected": 1,
                "irreversible_after_execution": True,
                "template_or_secret_association_changes": False,
                "procedure_execution": False,
                "credential_change": False,
            },
            "Expected State": {
                "clone_detail_absent": True,
                "clone_collection_absent": True,
                "built_in_source_preserved": True,
            },
            "device_write_executed": False,
        }

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._get_preview(preview_ref, requester_digest, "previewed")
            self._require_unconsumed()
            if not _matches(record, self._inspect()):
                self._records[preview_ref] = replace(record, state="invalidated")
                raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
            auth = "password-changer-delete-authorized-" + secrets.token_urlsafe(24)
            self._records[preview_ref] = replace(record, authorization_ref=auth, state="authorized")
            self._authorizations[auth] = preview_ref
        return {
            "contract": CONTRACT,
            "authorization_ref": auth,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            if not isinstance(authorization_ref, str) or not authorization_ref.startswith(
                "password-changer-delete-authorized-"
            ):
                raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
            preview_ref = self._authorizations.get(authorization_ref)
            if preview_ref is None:
                raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
            prior = self._records.get(preview_ref)
            _requester(requester_digest)
            if prior is None or not hmac.compare_digest(prior.requester_digest, requester_digest):
                raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
            if prior.state in {"completed", "reconciliation_required"}:
                prior_result = self._results.get(preview_ref)
                if prior_result is None:
                    raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
                return {**prior_result, "idempotent_replay": True}
            record = self._get_preview(preview_ref, requester_digest, "authorized")
            if record.authorization_ref != authorization_ref:
                raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
            self._require_unconsumed()
            current = self._inspect()
            if not _matches(record, current):
                self._records[preview_ref] = replace(record, state="invalidated")
                raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
            self._reserve_claim(record.target_digest)
            self._records[preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.delete_and_readback(current)
            success = isinstance(readback, PasswordChangerDeleteReadback) and readback.verified
        except Exception:
            success = False
        result: dict[str, object] = {
            "contract": CONTRACT,
            "outcome": "succeeded" if success else "reconciliation_required",
            "verification": "absence_and_source_preserved" if success else "unknown",
            "idempotent_replay": False,
            "one_shot_claim_consumed": True,
            "credential_values_returned": False,
            "procedure_values_returned": False,
            "raw_api_or_cli_returned": False,
        }
        with self._lock:
            self._results[preview_ref] = result
            self._records[preview_ref] = replace(
                self._records[preview_ref],
                state="completed" if success else "reconciliation_required",
            )
        return result

    def _get_preview(self, ref: str, requester_digest: str, state: str) -> _Record:
        _requester(requester_digest)
        record = self._records.get(ref)
        if (
            record is None or record.state != state or self._clock() >= record.expires_at
            or not hmac.compare_digest(record.requester_digest, requester_digest)
        ):
            raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)
        return record

    def _inspect(self) -> PasswordChangerDeleteInspection:
        try:
            result = self._transport.inspect()
            if not isinstance(result, PasswordChangerDeleteInspection):
                raise ValueError
            return result
        except Exception:
            raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE) from None

    def _require_unconsumed(self) -> None:
        parent = self._claim_path.parent
        if not parent.is_dir():
            parent.mkdir(parents=True, mode=0o700)
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or self._claim_path.exists()):
            raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)

    def _reserve_claim(self, target_digest: str) -> None:
        self._require_unconsumed()
        try:
            fd = os.open(
                self._claim_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "w") as stream:
                json.dump({
                    "contract": CONTRACT,
                    "target_digest": target_digest,
                    "state": "delete_attempt_reserved",
                    "reserved_at": self._clock(),
                }, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE) from None


def _matches(record: _Record, current: PasswordChangerDeleteInspection) -> bool:
    return (
        current.eligible
        and hmac.compare_digest(record.target_digest, current.target_digest)
        and hmac.compare_digest(record.source_digest, current.source_digest)
    )


def _requester(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise PasswordChangerDeleteLiveWorkflowError(_UNAVAILABLE)


__all__ = ["PasswordChangerDeleteLiveWorkflow", "PasswordChangerDeleteLiveWorkflowError"]
