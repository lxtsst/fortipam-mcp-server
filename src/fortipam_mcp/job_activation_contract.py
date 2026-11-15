"""Compile one fixed, future one-shot activation without dispatching it."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from .job_definition_create_contract import compile_disabled_job_create_body
from .job_definition_projection import (
    JobDefinitionExpectation,
    project_job_collection_definition,
    project_job_collection_execution,
)


_SOURCE = "mcp-v4-bp008-job-20260930-r3"
_SCRIPT = "echo BP008_JOB_OK"
_UTC8 = timezone(timedelta(hours=8))
_UNAVAILABLE = "The fixed Job activation is unavailable."


class JobActivationContractError(ValueError):
    """The exact disabled fixture cannot be safely activated."""


def compile_fixed_job_activation_body(
    source_detail: object,
    target_collection: object,
    *,
    target_name: str,
    target_requester: str,
    expected_secret_id: int,
    scheduled_at: datetime,
    now: datetime,
) -> dict[str, object]:
    """Return the observed 23-field GUI update shape for one bounded run.

    Both times are aware instants. The caller must durably reserve a separate
    one-use activation claim before sending the body and reconcile afterwards.
    """

    try:
        if (
            not isinstance(target_collection, Mapping)
            or not isinstance(scheduled_at, datetime)
            or not isinstance(now, datetime)
            or scheduled_at.tzinfo is None or now.tzinfo is None
            or scheduled_at.utcoffset() is None or now.utcoffset() is None
        ):
            raise ValueError
        lead = scheduled_at - now
        if not timedelta(minutes=2) <= lead <= timedelta(minutes=15):
            raise ValueError
        expectation = JobDefinitionExpectation(
            target_name, target_requester, expected_secret_id, _SCRIPT,
        )
        if not project_job_collection_definition(
            target_collection, expectation,
        ).definition_verified:
            raise ValueError
        execution = project_job_collection_execution(target_collection, expectation)
        if execution.state != "not_started" or execution.job_enabled or not execution.approved:
            raise ValueError
        body = compile_disabled_job_create_body(
            source_detail, source_name=_SOURCE, target_name=target_name,
            target_requester=target_requester,
            expected_secret_id=expected_secret_id,
        )
        timestamp = scheduled_at.astimezone(_UTC8).strftime("%Y-%m-%d %H:%M:%S")
        body["status"] = "enable"
        body["scheduled-time"] = timestamp
        body["job-sch-start-date"] = timestamp
        body["$originalName"] = target_name
        return body
    except Exception:
        raise JobActivationContractError(_UNAVAILABLE) from None
