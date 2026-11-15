"""Default-off C/P/E for one fixed FortiPAM 7.0 scheduled Job run."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from typing import Callable

from .job_definition_http_transport import (
    FortiPamDisabledJobHttpTransport,
    JobActivationInspection,
)


CONTRACT = "fortipam_v4_fixed_job_activation_700_candidate_v1"
_UNAVAILABLE = "The fixed Job activation workflow is unavailable."
_TTL = 60


class JobActivationLiveWorkflowError(RuntimeError):
    """The exact one-use activation cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    inspection: JobActivationInspection
    expires_at: int
    state: str


class JobActivationLiveWorkflow:
    """Bind a five-minute schedule to one requester and one durable PUT claim."""

    def __init__(
        self,
        transport: FortiPamDisabledJobHttpTransport,
        claim_path: Path,
        *,
        clock: Callable[[], int] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if (
            not isinstance(transport, FortiPamDisabledJobHttpTransport)
            or not Path(claim_path).is_absolute()
        ):
            raise JobActivationLiveWorkflowError(_UNAVAILABLE)
        self._transport = transport
        self._claim_path = Path(claim_path)
        self._clock = clock or (lambda: int(time.time()))
        self._sleep = sleep or time.sleep
        self._records: dict[str, _Record] = {}
        self._authorizations: dict[str, str] = {}
        self._results: dict[str, dict[str, object]] = {}
        self._lock = threading.RLock()

    def observe(self, *, requester_digest: str) -> dict[str, object]:
        _requester(requester_digest)
        try:
            state = self._transport.observe_execution()
            return {
                "contract": CONTRACT,
                "execution_state": state.state,
                "job_enabled": state.job_enabled,
                "approved": state.approved,
                "result_text_present": state.result_text_present,
                "fixed_result_marker_present": state.fixed_result_marker_present,
                "device_write_executed": False,
                "script_or_secret_returned": False,
            }
        except Exception:
            raise JobActivationLiveWorkflowError(_UNAVAILABLE) from None

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        _requester(requester_digest)
        with self._lock:
            self._require_unconsumed()
            now = self._now()
            inspection = self._transport.inspect_activation(
                scheduled_at=now + timedelta(minutes=5), now=now,
            )
            record = _Record(
                "job-activation-preview-" + secrets.token_urlsafe(24), None,
                requester_digest, inspection, self._clock() + _TTL, "previewed",
            )
            self._records[record.preview_ref] = record
        return {
            "contract": CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "fixed_job_disabled_approved_unrun": True,
                "script_or_secret_returned": False,
            },
            "Proposed Changes": {
                "operation": "activate_one_fixed_harmless_one_shot_ssh_script_job",
                "scheduled_minutes_after_preview": 5,
                "job_request_or_approval": False,
            },
            "Expected State": {
                "job_enabled": True,
                "actual_script_execution_observed_separately": True,
            },
            "device_write_executed": False,
        }

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._get(preview_ref, requester_digest, "previewed")
            self._require_unconsumed()
            self._reinspect(record)
            authorization_ref = "job-activation-authorized-" + secrets.token_urlsafe(24)
            self._records[preview_ref] = replace(
                record, authorization_ref=authorization_ref, state="authorized",
            )
            self._authorizations[authorization_ref] = preview_ref
        return {
            "contract": CONTRACT,
            "authorization_ref": authorization_ref,
            "technical_confirmation": "recorded",
            "execution": "authorized_once",
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            _requester(requester_digest)
            if not isinstance(authorization_ref, str):
                raise JobActivationLiveWorkflowError(_UNAVAILABLE)
            preview_ref = self._authorizations.get(authorization_ref)
            record = self._records.get(preview_ref or "")
            if record is None or not hmac.compare_digest(
                record.requester_digest, requester_digest,
            ) or record.authorization_ref != authorization_ref:
                raise JobActivationLiveWorkflowError(_UNAVAILABLE)
            if record.state in {"completed", "reconciliation_required"}:
                prior = self._results.get(record.preview_ref)
                if prior is None:
                    raise JobActivationLiveWorkflowError(_UNAVAILABLE)
                return {**prior, "idempotent_replay": True}
            record = self._get(record.preview_ref, requester_digest, "authorized")
            self._require_unconsumed()
            self._reinspect(record)
            self._reserve_claim(record.inspection.body_digest)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            put_accepted = self._transport.put_activation_once(
                record.inspection, now=self._now(),
            )
        except Exception:
            put_accepted = False
        enabled = False
        for delay in (0, 1, 2, 3):
            if delay:
                self._sleep(delay)
            try:
                enabled = self._transport.observe_execution().job_enabled
            except Exception:
                enabled = False
            if enabled:
                break
        success = put_accepted and enabled
        result: dict[str, object] = {
            "contract": CONTRACT,
            "outcome": "scheduled" if success else "reconciliation_required",
            "put_accepted": put_accepted,
            "job_enabled_observed": enabled,
            "script_execution_verified": False,
            "one_shot_claim_consumed": True,
            "idempotent_replay": False,
            "script_or_secret_returned": False,
        }
        with self._lock:
            self._results[record.preview_ref] = result
            self._records[record.preview_ref] = replace(
                self._records[record.preview_ref],
                state="completed" if success else "reconciliation_required",
            )
        return result

    def _now(self) -> datetime:
        return datetime.fromtimestamp(self._clock(), tz=timezone.utc)

    def _get(self, ref: str, requester_digest: str, state: str) -> _Record:
        _requester(requester_digest)
        record = self._records.get(ref)
        if (
            record is None or record.state != state
            or self._clock() >= record.expires_at
            or not hmac.compare_digest(record.requester_digest, requester_digest)
        ):
            raise JobActivationLiveWorkflowError(_UNAVAILABLE)
        return record

    def _reinspect(self, record: _Record) -> None:
        try:
            current = self._transport.inspect_activation(
                scheduled_at=record.inspection.scheduled_at, now=self._now(),
            )
            if not hmac.compare_digest(
                current.body_digest, record.inspection.body_digest,
            ):
                raise ValueError
        except Exception:
            self._records[record.preview_ref] = replace(record, state="invalidated")
            raise JobActivationLiveWorkflowError(_UNAVAILABLE) from None

    def _require_unconsumed(self) -> None:
        parent = self._claim_path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or self._claim_path.exists()
        ):
            raise JobActivationLiveWorkflowError(_UNAVAILABLE)

    def _reserve_claim(self, body_digest: str) -> None:
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
                    "body_digest": body_digest,
                    "state": "put_attempt_reserved",
                    "reserved_at": self._clock(),
                }, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            raise JobActivationLiveWorkflowError(_UNAVAILABLE) from None


def _requester(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise JobActivationLiveWorkflowError(_UNAVAILABLE)
    try:
        int(value, 16)
    except ValueError:
        raise JobActivationLiveWorkflowError(_UNAVAILABLE) from None
