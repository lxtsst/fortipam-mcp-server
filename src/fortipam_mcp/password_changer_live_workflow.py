"""One-shot C/P/E workflow for the fixed FortiPAM 7.0 Unix changer clone."""

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

from .password_changer_http_transport import (
    FortiPamUnixPasswordChangerHttpTransport,
    PasswordChangerInspection,
    PasswordChangerReadback,
)


CONTRACT = "fortipam_v4_unix_password_changer_700_candidate_v1"
_UNAVAILABLE = "FortiPAM V4 Unix Password Changer workflow is unavailable."
_TTL = 600


class PasswordChangerLiveWorkflowError(RuntimeError):
    """Non-disclosing workflow failure."""


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    source_digest: str
    expires_at: int
    state: str


class PasswordChangerCreateLiveWorkflow:
    """Keep previews volatile and the once-only dispatch marker durable."""

    def __init__(
        self,
        transport: FortiPamUnixPasswordChangerHttpTransport,
        claim_path: Path,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(transport, FortiPamUnixPasswordChangerHttpTransport):
            raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
        self._transport = transport
        self._claim_path = Path(claim_path)
        if not self._claim_path.is_absolute():
            raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
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
            if current.target_exists:
                raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
            record = _Record(
                "password-changer-preview-" + secrets.token_urlsafe(24),
                None, requester_digest, current.source_digest,
                self._clock() + _TTL, "previewed",
            )
            self._records[record.preview_ref] = record
        return {
            "contract": CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "built_in_unix_source_matched": True,
                "bound_clone_absent": True,
                "source_procedure_returned": False,
            },
            "Proposed Changes": {
                "operation": "clone_built_in_unix_password_changer",
                "change_step_count": 9,
                "target_name_privately_bound": True,
                "template_or_secret_association": False,
                "procedure_execution": False,
                "credential_change": False,
            },
            "Expected State": {
                "clone_detail_matches_source": True,
                "clone_collection_unique": True,
                "reference_count_requires_independent_ui_check_if_api_omits_it": True,
            },
            "device_write_executed": False,
        }

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._get_preview(preview_ref, requester_digest, "previewed")
            self._require_unconsumed()
            current = self._inspect()
            if current.target_exists or not hmac.compare_digest(
                current.source_digest, record.source_digest,
            ):
                self._records[preview_ref] = replace(record, state="invalidated")
                raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
            auth = "password-changer-authorized-" + secrets.token_urlsafe(24)
            self._records[preview_ref] = replace(
                record, authorization_ref=auth, state="authorized",
            )
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
                "password-changer-authorized-"
            ):
                raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
            preview_ref = self._authorizations.get(authorization_ref)
            if preview_ref is None:
                raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
            prior = self._records.get(preview_ref)
            _requester(requester_digest)
            if prior is None or not hmac.compare_digest(
                prior.requester_digest, requester_digest,
            ):
                raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
            if prior.state in {"completed", "reconciliation_required"}:
                prior_result = self._results.get(preview_ref)
                if prior_result is None:
                    raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
                return {**prior_result, "idempotent_replay": True}
            record = self._get_preview(preview_ref, requester_digest, "authorized")
            if record.authorization_ref != authorization_ref:
                raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
            self._require_unconsumed()
            current = self._inspect()
            if current.target_exists or not hmac.compare_digest(
                current.source_digest, record.source_digest,
            ):
                self._records[preview_ref] = replace(record, state="invalidated")
                raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
            self._reserve_claim(record.source_digest)
            self._records[preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(current)
            success = isinstance(readback, PasswordChangerReadback) and readback.verified
            references_zero = readback.reference_count_known_zero if success else False
        except Exception:
            success = False
            references_zero = False
        result: dict[str, object] = {
            "contract": CONTRACT,
            "outcome": "succeeded" if success else "reconciliation_required",
            "verification": "api_projection_verified" if success else "unknown",
            "idempotent_replay": False,
            "reference_count_known_zero": references_zero,
            "independent_ui_reference_check_required": not references_zero,
            "one_shot_claim_consumed": True,
            "credential_values_returned": False,
            "procedure_values_returned": False,
            "raw_api_response_returned": False,
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
            raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)
        return record

    def _inspect(self) -> PasswordChangerInspection:
        try:
            result = self._transport.inspect()
            if not isinstance(result, PasswordChangerInspection):
                raise ValueError
            return result
        except Exception:
            raise PasswordChangerLiveWorkflowError(_UNAVAILABLE) from None

    def _require_unconsumed(self) -> None:
        parent = self._claim_path.parent
        if not parent.is_dir():
            parent.mkdir(parents=True, mode=0o700)
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or os.path.lexists(self._claim_path)):
            raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)

    def _reserve_claim(self, source_digest: str) -> None:
        self._require_unconsumed()
        try:
            parent = os.open(self._claim_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(parent)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise OSError
                fd = os.open(
                    self._claim_path.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=parent,
                )
                with os.fdopen(fd, "w") as stream:
                    json.dump({
                        "contract": CONTRACT,
                        "source_digest": source_digest,
                        "state": "post_attempt_reserved",
                        "reserved_at": self._clock(),
                    }, stream, sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(parent)
            finally:
                os.close(parent)
        except OSError:
            raise PasswordChangerLiveWorkflowError(_UNAVAILABLE) from None


def _requester(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise PasswordChangerLiveWorkflowError(_UNAVAILABLE)


__all__ = ["PasswordChangerCreateLiveWorkflow", "PasswordChangerLiveWorkflowError"]
