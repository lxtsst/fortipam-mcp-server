"""Minimized FortiPAM 7.0 Job definition readback for a private binding.

This projector has no transport or execution path. The caller keeps the Job,
Secret, requester, and script expectations inside its protected process.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal


class JobDefinitionProjectionError(ValueError):
    """A Job read response cannot be safely classified."""


@dataclass(frozen=True, slots=True, repr=False)
class JobDefinitionExpectation:
    name: str
    requester: str
    secret_id: int
    script: str

    def __repr__(self) -> str:
        return "<JobDefinitionExpectation redacted>"


@dataclass(frozen=True, slots=True)
class JobDefinitionReadback:
    product_matches: bool
    identity_matches: bool
    requester_matches: bool
    secret_matches: bool
    disabled: bool
    one_shot_ssh_script: bool
    script_matches: bool
    approved: bool

    @property
    def definition_verified(self) -> bool:
        return all((
            self.product_matches,
            self.identity_matches,
            self.requester_matches,
            self.secret_matches,
            self.disabled,
            self.one_shot_ssh_script,
            self.script_matches,
            self.approved,
        ))


@dataclass(frozen=True, slots=True)
class JobExecutionReadback:
    """Categorical execution timing, never script output or result text."""

    state: Literal[
        "not_started", "started_outcome_unverified", "ended_outcome_unverified",
    ]
    result_text_present: bool
    job_enabled: bool
    approved: bool
    fixed_result_marker_present: bool = False


def project_job_definition(
    payload: object, expected: JobDefinitionExpectation,
) -> JobDefinitionReadback:
    """Classify one exact detail GET without returning its script or selectors."""

    if not isinstance(payload, Mapping) or not isinstance(expected, JobDefinitionExpectation):
        raise JobDefinitionProjectionError("Job detail is unavailable.")
    if payload.get("status") != "success":
        raise JobDefinitionProjectionError("Job detail is unavailable.")
    results = payload.get("results")
    if isinstance(results, list):
        if len(results) != 1 or not isinstance(results[0], Mapping):
            raise JobDefinitionProjectionError("Job detail is unavailable.")
        record = results[0]
    elif isinstance(results, Mapping):
        record = results
    else:
        raise JobDefinitionProjectionError("Job detail is unavailable.")
    return _project_record(payload, record, expected)


def project_job_collection_definition(
    payload: object, expected: JobDefinitionExpectation,
) -> JobDefinitionReadback:
    """Classify one exact Job from the 7.0 GET-override collection envelope.

    The frontend route returns ``status=OK``, unlike the exact-detail GET's
    ``status=success``. Duplicate names or malformed rows fail closed.
    """

    if (
        not isinstance(payload, Mapping)
        or not isinstance(expected, JobDefinitionExpectation)
        or payload.get("status") != "OK"
    ):
        raise JobDefinitionProjectionError("Job collection is unavailable.")
    results = payload.get("results")
    if not isinstance(results, list) or not all(isinstance(row, Mapping) for row in results):
        raise JobDefinitionProjectionError("Job collection is unavailable.")
    matches = [row for row in results if row.get("name") == expected.name]
    if len(matches) != 1:
        raise JobDefinitionProjectionError("Job collection is unavailable.")
    return _project_record(payload, matches[0], expected)


def project_job_collection_execution(
    payload: object, expected: JobDefinitionExpectation,
) -> JobExecutionReadback:
    """Classify exact build-29 execution timestamps without inferring success."""

    if (
        not isinstance(payload, Mapping)
        or not isinstance(expected, JobDefinitionExpectation)
        or payload.get("status") != "OK"
    ):
        raise JobDefinitionProjectionError("Job execution state is unavailable.")
    rows = payload.get("results")
    if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
        raise JobDefinitionProjectionError("Job execution state is unavailable.")
    matches = [row for row in rows if row.get("name") == expected.name]
    if len(matches) != 1:
        raise JobDefinitionProjectionError("Job execution state is unavailable.")
    record = matches[0]
    definition = _project_record(payload, record, expected)
    if not all((
        definition.product_matches, definition.identity_matches,
        definition.requester_matches, definition.secret_matches,
        definition.one_shot_ssh_script, definition.script_matches,
    )):
        raise JobDefinitionProjectionError("Job execution state is unavailable.")
    start = record.get("execution-time-start")
    end = record.get("execution-time-end")
    result_text = record.get("result-txt")
    if (
        type(start) is not int or type(end) is not int
        or start < 0 or end < 0 or not isinstance(result_text, str)
        or record.get("status") not in {"disable", "enable"}
    ):
        raise JobDefinitionProjectionError("Job execution state is unavailable.")
    state: Literal[
        "not_started", "started_outcome_unverified", "ended_outcome_unverified",
    ]
    if start == end == 0 and not result_text:
        state = "not_started"
    elif start > 0 and end == 0:
        state = "started_outcome_unverified"
    elif start > 0 and end >= start:
        state = "ended_outcome_unverified"
    else:
        raise JobDefinitionProjectionError("Job execution state is unavailable.")
    return JobExecutionReadback(
        state, bool(result_text), record.get("status") == "enable",
        definition.approved,
        (
            state == "ended_outcome_unverified"
            and expected.script == "echo BP008_JOB_OK"
            and "BP008_JOB_OK" in result_text
            and "echo BP008_JOB_OK" not in result_text
        ),
    )


def _project_record(
    payload: Mapping[object, object], record: Mapping[object, object],
    expected: JobDefinitionExpectation,
) -> JobDefinitionReadback:
    return JobDefinitionReadback(
        product_matches=(
            payload.get("version") in {"v7.0.0", "7.0.0"}
            and type(payload.get("build")) is int
            and payload.get("build") == 29
        ),
        identity_matches=record.get("name") == expected.name,
        requester_matches=record.get("user") == expected.requester,
        secret_matches=(
            type(record.get("secret")) is int
            and record.get("secret") == expected.secret_id
        ),
        disabled=record.get("status") == "disable",
        one_shot_ssh_script=(
            record.get("schedule") == "one-shot"
            and record.get("type") == "ssh-script"
        ),
        script_matches=record.get("script") == expected.script,
        approved=record.get("approval-status") == "approved",
    )
