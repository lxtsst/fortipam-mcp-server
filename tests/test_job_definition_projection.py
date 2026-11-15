"""Focused checks for the fixed, non-disclosing Job readback."""

import pytest

from fortipam_mcp.job_definition_projection import (
    JobDefinitionExpectation,
    JobDefinitionProjectionError,
    project_job_collection_definition,
    project_job_collection_execution,
    project_job_definition,
)


def _payload() -> dict[str, object]:
    return {
        "status": "success",
        "version": "v7.0.0",
        "build": 29,
        "results": {
            "name": "mcp-v4-bp008-job-synthetic",
            "user": "admin",
            "secret": 999,
            "status": "disable",
            "schedule": "one-shot",
            "type": "ssh-script",
            "script": "echo TEST_JOB_OK",
            "approval-status": "approved",
        },
    }


def _expected() -> JobDefinitionExpectation:
    return JobDefinitionExpectation(
        "mcp-v4-bp008-job-synthetic", "admin", 999, "echo TEST_JOB_OK",
    )


def test_exact_disabled_definition_is_verified_without_exposing_script() -> None:
    readback = project_job_definition(_payload(), _expected())
    assert readback.definition_verified
    assert "TEST_JOB_OK" not in repr(readback)
    assert "TEST_JOB_OK" not in repr(_expected())


def test_enabled_or_changed_script_fails_definition_readback() -> None:
    payload = _payload()
    record = payload["results"]
    assert isinstance(record, dict)
    record["status"] = "enable"
    record["script"] = "unexpected"
    readback = project_job_definition(payload, _expected())
    assert not readback.definition_verified
    assert not readback.disabled
    assert not readback.script_matches


def test_ambiguous_detail_fails_closed() -> None:
    payload = _payload()
    payload["results"] = [payload["results"], payload["results"]]
    with pytest.raises(JobDefinitionProjectionError, match="unavailable"):
        project_job_definition(payload, _expected())


def test_get_override_collection_selects_one_exact_disabled_job() -> None:
    payload = _payload()
    payload["status"] = "OK"
    record = payload["results"]
    assert isinstance(record, dict)
    payload["results"] = [{"name": "another-job"}, record]
    assert project_job_collection_definition(payload, _expected()).definition_verified


def test_get_override_collection_rejects_duplicates_and_wrong_envelope() -> None:
    payload = _payload()
    record = payload["results"]
    payload["results"] = [record, record]
    payload["status"] = "OK"
    with pytest.raises(JobDefinitionProjectionError, match="unavailable"):
        project_job_collection_definition(payload, _expected())
    payload["results"] = [record]
    payload["status"] = "success"
    with pytest.raises(JobDefinitionProjectionError, match="unavailable"):
        project_job_collection_definition(payload, _expected())


def test_execution_zero_timestamps_are_not_a_run() -> None:
    payload = _payload()
    payload["status"] = "OK"
    record = payload["results"]
    assert isinstance(record, dict)
    record.update({
        "execution-time-start": 0,
        "execution-time-end": 0,
        "result-txt": "",
    })
    payload["results"] = [record]

    initial = project_job_collection_execution(payload, _expected())
    assert initial.state == "not_started"
    assert initial.result_text_present is False
    record["execution-time-start"] = 100
    assert project_job_collection_execution(payload, _expected()).state == "started_outcome_unverified"
    record["execution-time-end"] = 101
    assert project_job_collection_execution(payload, _expected()).state == "ended_outcome_unverified"
    record["execution-time-start"] = 0
    with pytest.raises(JobDefinitionProjectionError, match="unavailable"):
        project_job_collection_execution(payload, _expected())


def test_fixed_result_marker_is_categorical_and_not_the_command_line() -> None:
    payload = _payload()
    payload["status"] = "OK"
    record = payload["results"]
    assert isinstance(record, dict)
    record.update({
        "script": "echo BP008_JOB_OK",
        "status": "enable",
        "execution-time-start": 100,
        "execution-time-end": 101,
        "result-txt": "result: BP008_JOB_OK",
    })
    payload["results"] = [record]
    expected = JobDefinitionExpectation(
        "mcp-v4-bp008-job-synthetic", "admin", 999, "echo BP008_JOB_OK",
    )
    result = project_job_collection_execution(payload, expected)
    assert result.fixed_result_marker_present is True
    assert "BP008_JOB_OK" not in repr(result)
    record["result-txt"] = "command: echo BP008_JOB_OK"
    assert project_job_collection_execution(payload, expected).fixed_result_marker_present is False
