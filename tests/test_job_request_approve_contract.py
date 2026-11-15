from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from fortipam_mcp.job_request_approve_contract import (
    JobRequestApproveContractError,
    compile_job_request_approve_body,
    job_request_approved_readback,
)


NOW = int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp())
SCHEDULE = NOW + 1200
ZONE = timezone(timedelta(hours=8))
START = datetime.fromtimestamp(SCHEDULE, ZONE).strftime("%Y-%m-%d %H:%M:%S")
EXPIRY = datetime.fromtimestamp(SCHEDULE + 300, ZONE).strftime("%Y-%m-%d %H:%M:%S")
BINDING = {"request_id": 19, "secret_id": 7,
           "job_name": "mcp-v4-bp008-job-20261001-r17",
           "requester": "synthetic-requester", "authenticated_reviewer": "synthetic-reviewer"}
REQUEST = {"id": 19, "secret-id": 7, "request-type": "job",
           "job-name": BINDING["job_name"], "user": BINDING["requester"],
           "final-status": "pending", "tier1-status": "pending",
           "start-after-approve": "disable", "duration": 0,
           "start-time": "0000-00-00 00:00:00", "expiration-time": EXPIRY}
JOB = {"name": BINDING["job_name"], "secret": 7, "user": BINDING["requester"],
       "status": "enable", "approval-status": "pending", "type": "ssh-script",
       "schedule": "one-shot", "script": "echo BP008_JOB_OK", "script-type": "custom-script",
       "script-name": "", "associated-secret": 0, "ssh-procedure": [], "web-api-procedure": [],
       "scheduled-time": SCHEDULE, "job-sch-start-date": 0,
       "execution-time-start": 0, "execution-time-end": 0, "result-txt": ""}

DETAIL = {**JOB, "scheduled-time": START, "job-sch-start-date":"0000-00-00 00:00:00"}


def envelope(row, *, name="request", method="GET", status="OK"):
    return {"version": "v7.0.0", "build": 29, "status": status, "http_status": 200,
            "http_method": method, "path": "secret", "name": name, "results": row}


@pytest.mark.parametrize("failure", [None, "self", "queue_missing", "queue_duplicate",
                                    "queue_method", "request_identity", "terminal", "window",
                                    "start_drift", "job_method", "job_build", "job_secret",
                                    "job_duplicate", "job_disabled", "job_approved", "job_script",
                                    "job_started", "job_associated", "schedule_drift", "schedule_boolean",
                                    "deadline", "boolean_clock", "detail_secret", "detail_procedure", "detail_schedule"])
def test_approval_pins_pending_relation_future_unrun_job_and_five_minute_window(failure):
    queue = envelope([deepcopy(REQUEST)], method="POST")
    before = envelope([deepcopy(REQUEST)])
    jobs = envelope([deepcopy(JOB)], name="job", method="POST")
    detail = envelope(deepcopy(DETAIL),name="job",status="success")
    binding, now = dict(BINDING), NOW
    if failure == "self": binding["authenticated_reviewer"] = binding["requester"]
    if failure == "queue_missing": queue["results"] = []
    if failure == "queue_duplicate": queue["results"].append(deepcopy(REQUEST))
    if failure == "queue_method": queue["http_method"] = "GET"
    if failure == "request_identity": before["results"][0]["secret-id"] = 8
    if failure == "terminal": before["results"][0]["final-status"] = "denied"
    if failure == "window": before["results"][0]["expiration-time"] = START
    if failure == "start_drift": before["results"][0]["start-time"] = EXPIRY
    if failure == "job_method": jobs["http_method"] = "GET"
    if failure == "job_build": jobs["build"] = 30
    if failure == "job_secret": jobs["results"][0]["secret"] = 8
    if failure == "job_duplicate": jobs["results"].append(deepcopy(JOB))
    if failure == "job_disabled": jobs["results"][0]["status"] = "disable"
    if failure == "job_approved": jobs["results"][0]["approval-status"] = "approved"
    if failure == "job_script": jobs["results"][0]["script"] = "echo different"
    if failure == "job_started": jobs["results"][0]["execution-time-start"] = NOW
    if failure == "job_associated": jobs["results"][0]["associated-secret"] = 8
    if failure == "schedule_drift": jobs["results"][0]["job-sch-start-date"] += 1
    if failure == "schedule_boolean": jobs["results"][0]["scheduled-time"] = True
    if failure == "deadline": now = SCHEDULE - 60
    if failure == "boolean_clock": now = True
    if failure == "detail_secret": detail["results"]["secret"] = 8
    if failure == "detail_procedure": detail["results"]["ssh-procedure"] = ["unbounded"]
    if failure == "detail_schedule": detail["results"]["scheduled-time"] = EXPIRY
    snapshot = deepcopy((queue, before, jobs, detail))
    if failure:
        with pytest.raises(JobRequestApproveContractError,
                           match="^The fixed scheduled Job Request approval is unavailable.$"):
            compile_job_request_approve_body(queue, before, jobs, detail, **binding, now_epoch=now)
        return
    body = compile_job_request_approve_body(queue, before, jobs, detail, **binding, now_epoch=now)
    assert body == {"request-id": 19, "tier": 1, "approval-status": "approved",
                    "comments": "MCP V4 BP008 independent Job approval",
                    "start-after-approve": "disable", "start-time": START, "expiration-time": EXPIRY}
    assert "duration" not in body
    assert (queue, before, jobs, detail) == snapshot
    after = envelope({**REQUEST, "final-status": "approved", "tier1-status": "approved"})
    approved_job = envelope([{**JOB,"approval-status":"approved"}],name="job",method="POST")
    identity = {key: value for key, value in binding.items() if key != "authenticated_reviewer"}
    assert job_request_approved_readback(before, after, approved_job, **identity, scheduled_epoch=SCHEDULE)
    # An approved enum alone cannot qualify the scheduled approval.
    after["results"]["start-time"] = ""
    assert not job_request_approved_readback(before, after, approved_job, **identity, scheduled_epoch=SCHEDULE)
    after["results"]["start-time"] = REQUEST["start-time"]
    approved_job["results"][0]["scheduled-time"] += 1
    assert not job_request_approved_readback(before, after, approved_job, **identity, scheduled_epoch=SCHEDULE)
    approved_job["results"][0]["scheduled-time"] = SCHEDULE
    after["results"]["duration"] = True
    assert not job_request_approved_readback(before, after, approved_job, **identity, scheduled_epoch=SCHEDULE)
    assert not job_request_approved_readback(before, before, approved_job, **identity, scheduled_epoch=SCHEDULE)
