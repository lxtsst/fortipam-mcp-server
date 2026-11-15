"""Regression checks for the single bounded Job activation body."""

from datetime import datetime, timedelta, timezone

import pytest

from fortipam_mcp.job_activation_contract import (
    JobActivationContractError,
    compile_fixed_job_activation_body,
)
from test_job_definition_create_contract import _source


_NAME = "mcp-v4-bp008-job-20260930-r8"
_NOW = datetime(2026, 9, 30, 3, 0, tzinfo=timezone.utc)


def _collection() -> dict[str, object]:
    row = dict(_source()["results"])
    row.update({
        "name": _NAME, "user": "adminapi", "scheduled-time": 1,
        "execution-time-start": 0, "execution-time-end": 0, "result-txt": "",
    })
    return {
        "status": "OK", "version": "v7.0.0", "build": 29,
        "results": [row],
    }


def _compile(collection: object, *, minutes: int = 5) -> dict[str, object]:
    return compile_fixed_job_activation_body(
        _source(), collection, target_name=_NAME,
        target_requester="adminapi", expected_secret_id=999,
        scheduled_at=_NOW + timedelta(minutes=minutes), now=_NOW,
    )


def test_compiles_only_enable_and_future_schedule_for_exact_unrun_job() -> None:
    body = _compile(_collection())
    assert body["status"] == "enable"
    assert body["$originalName"] == _NAME
    assert body["scheduled-time"] == "2026-09-30 11:05:00"
    assert body["job-sch-start-date"] == body["scheduled-time"]
    assert body["script"] == "echo BP008_JOB_OK"
    assert len(body) == 23


@pytest.mark.parametrize("change", [
    {"status": "enable"},
    {"execution-time-start": 1, "execution-time-end": 0},
    {"script": "id"},
    {"approval-status": "pending"},
    {"secret": 1000},
])
def test_rejects_changed_or_started_target(change: dict[str, object]) -> None:
    collection = _collection()
    collection["results"][0].update(change)
    with pytest.raises(JobActivationContractError, match="unavailable"):
        _compile(collection)


@pytest.mark.parametrize("minutes", [0, 1, 16])
def test_rejects_unbounded_schedule(minutes: int) -> None:
    with pytest.raises(JobActivationContractError, match="unavailable"):
        _compile(_collection(), minutes=minutes)
