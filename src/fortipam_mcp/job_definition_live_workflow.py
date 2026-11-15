"""One-use C/P/E workflow for one disabled FortiPAM 7.0 Job definition."""

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

from .job_definition_http_transport import (
    FortiPamDisabledJobHttpTransport,
    JobCreateInspection,
)


CONTRACT = "fortipam_v4_disabled_job_create_700_candidate_v1"
_UNAVAILABLE = "The fixed disabled Job workflow is unavailable."
_TTL = 600


class JobDefinitionLiveWorkflowError(RuntimeError):
    """A private Job preview or dispatch cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    body_digest: str
    expires_at: int
    state: str


class JobDefinitionCreateLiveWorkflow:
    """Keep previews volatile and the one-use POST claim durable."""

    def __init__(
        self,
        transport: FortiPamDisabledJobHttpTransport,
        claim_path: Path,
        *, clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(transport, FortiPamDisabledJobHttpTransport):
            raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
        self._transport = transport
        self._claim_path = Path(claim_path)
        if not self._claim_path.is_absolute():
            raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
        self._clock = clock or (lambda: int(time.time()))
        self._records: dict[str, _Record] = {}
        self._authorizations: dict[str, str] = {}
        self._results: dict[str, dict[str, object]] = {}
        self._lock = threading.RLock()

    def observe(self, *, requester_digest: str) -> dict[str, object]:
        """Read the fixed Job after a consumed or ambiguous dispatch."""

        _requester(requester_digest)
        try:
            execution = self._transport.observe_execution()
            return {
                "contract": CONTRACT,
                "definition_verified": not execution.job_enabled and execution.approved,
                "disabled": not execution.job_enabled,
                "one_shot_ssh_script": True,
                "approved": execution.approved,
                "execution_state": execution.state,
                "result_text_present": execution.result_text_present,
                "job_enabled": execution.job_enabled,
                "device_write_executed": False,
                "script_or_secret_returned": False,
            }
        except Exception:
            raise JobDefinitionLiveWorkflowError(_UNAVAILABLE) from None

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        _requester(requester_digest)
        with self._lock:
            self._require_unconsumed()
            current = self._inspect()
            if current.target_exists:
                raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
            record = _Record(
                "job-create-preview-" + secrets.token_urlsafe(24), None,
                requester_digest, current.body_digest,
                self._clock() + _TTL, "previewed",
            )
            self._records[record.preview_ref] = record
        return {
            "contract": CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "fixed_source_definition_matched": True,
                "bound_job_absent": True,
                "script_or_secret_returned": False,
            },
            "Proposed Changes": {
                "operation": "create_one_disabled_one_shot_ssh_script_job",
                "job_name_and_requester_privately_bound": True,
                "same_existing_secret": True,
                "job_execution": False,
                "automatic_activation": False,
            },
            "Expected State": {
                "collection_definition_verified": True,
                "disabled_and_not_scheduled_to_run": True,
                "script_output_returned": False,
            },
            "device_write_executed": False,
        }

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._get_preview(preview_ref, requester_digest, "previewed")
            self._require_unconsumed()
            current = self._inspect()
            if current.target_exists or not hmac.compare_digest(
                current.body_digest, record.body_digest,
            ):
                self._records[preview_ref] = replace(record, state="invalidated")
                raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
            authorization_ref = "job-create-authorized-" + secrets.token_urlsafe(24)
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
            if (
                not isinstance(authorization_ref, str)
                or not authorization_ref.startswith("job-create-authorized-")
            ):
                raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
            preview_ref = self._authorizations.get(authorization_ref)
            if preview_ref is None:
                raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
            prior = self._records.get(preview_ref)
            _requester(requester_digest)
            if prior is None or not hmac.compare_digest(
                prior.requester_digest, requester_digest,
            ):
                raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
            if prior.state in {"completed", "reconciliation_required"}:
                prior_result = self._results.get(preview_ref)
                if prior_result is None:
                    raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
                return {**prior_result, "idempotent_replay": True}
            record = self._get_preview(preview_ref, requester_digest, "authorized")
            if record.authorization_ref != authorization_ref:
                raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
            self._require_unconsumed()
            current = self._inspect()
            if current.target_exists or not hmac.compare_digest(
                current.body_digest, record.body_digest,
            ):
                self._records[preview_ref] = replace(record, state="invalidated")
                raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
            self._reserve_claim(record.body_digest)
            self._records[preview_ref] = replace(record, state="executing")
        try:
            post_accepted = self._transport.post_disabled_once(current)
        except Exception:
            post_accepted = False
        definition_verified = False
        for delay in (0, 1, 2, 3):
            if delay:
                time.sleep(delay)
            try:
                definition_verified = self._transport.readback(expected=current).definition_verified
            except Exception:
                definition_verified = False
            if definition_verified:
                break
        success = post_accepted and definition_verified
        result: dict[str, object] = {
            "contract": CONTRACT,
            "outcome": "succeeded" if success else "reconciliation_required",
            "verification": "collection_projection_verified" if success else "unknown",
            "post_accepted": post_accepted,
            "definition_observed": definition_verified,
            "job_executed": False,
            "one_shot_claim_consumed": True,
            "idempotent_replay": False,
            "script_or_secret_returned": False,
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
            raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)
        return record

    def _inspect(self) -> JobCreateInspection:
        try:
            result = self._transport.inspect()
            if not isinstance(result, JobCreateInspection):
                raise ValueError
            return result
        except Exception:
            raise JobDefinitionLiveWorkflowError(_UNAVAILABLE) from None

    def _require_unconsumed(self) -> None:
        parent = self._claim_path.parent
        if not parent.is_dir():
            parent.mkdir(parents=True, mode=0o700)
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or self._claim_path.exists()
        ):
            raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)

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
                    "state": "post_attempt_reserved",
                    "reserved_at": self._clock(),
                }, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            parent = os.open(self._claim_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except OSError:
            raise JobDefinitionLiveWorkflowError(_UNAVAILABLE) from None


def _requester(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise JobDefinitionLiveWorkflowError(_UNAVAILABLE)


__all__ = ["JobDefinitionCreateLiveWorkflow", "JobDefinitionLiveWorkflowError"]
