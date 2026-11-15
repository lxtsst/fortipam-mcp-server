"""Private build-29 scheduled Job approval compiler; no dispatch or MCP Tool.

The retained successful scheduled-review serializer supplies seven fields,
including the fixed Job start and the Request expiry, without duration.
Private selectors and scheduling values must stay inside the adapter.
"""

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from .job_definition_projection import (
    JobDefinitionExpectation,
    project_job_collection_execution,
)
from .job_request_deny_contract import _detail, _identity, _pending_job_request

_UNAVAILABLE = "The fixed scheduled Job Request approval is unavailable."
_COMMENT = "MCP V4 BP008 independent Job approval"
_ZONE = timezone(timedelta(hours=8))


class JobRequestApproveContractError(ValueError):
    """Stable rejection without private selectors or upstream data."""


def _schedule(
    job_collection: object, job_detail: object, *, job_name: str, secret_id: int, requester: str,
) -> tuple[Mapping[str, Any], int]:
    if (not isinstance(job_collection, Mapping)
            or type(job_collection.get("build")) is not int
            or type(job_collection.get("http_status")) is not int
            or any(job_collection.get(key) != value for key, value in {
                "version": "v7.0.0", "build": 29, "http_status": 200,
                "http_method": "POST", "path": "secret", "name": "job",
                "status": "OK",
            }.items())):
        raise ValueError
    execution = project_job_collection_execution(
        job_collection,
        JobDefinitionExpectation(job_name, requester, secret_id, "echo BP008_JOB_OK"),
    )
    if (not execution.job_enabled or execution.approved
            or execution.state != "not_started" or execution.result_text_present):
        raise ValueError
    rows = job_collection["results"]
    row = next(row for row in rows if row["name"] == job_name)
    scheduled = row.get("scheduled-time")
    if (row.get("approval-status") != "pending"
            or type(row.get("associated-secret")) is not int
            or row["associated-secret"] != 0
            or row.get("script-type") != "custom-script"
            or row.get("script-name") != ""
            or type(scheduled) is not int or scheduled <= 0
            or type(row.get("job-sch-start-date")) is not int
            or row["job-sch-start-date"] != 0):
        raise ValueError
    if (not isinstance(job_detail, Mapping)
            or any(type(job_detail.get(key)) is not type(value) or job_detail.get(key) != value
                   for key, value in {"version":"v7.0.0", "build":29, "http_status":200,
                                      "http_method":"GET", "path":"secret", "name":"job",
                                      "status":"success"}.items())):
        raise ValueError
    detail = job_detail.get("results")
    if isinstance(detail, list) and len(detail)==1:
        detail=detail[0]
    if not isinstance(detail, Mapping):
        raise ValueError
    start = datetime.fromtimestamp(scheduled, _ZONE).strftime("%Y-%m-%d %H:%M:%S")
    expected = {"name":job_name, "secret":secret_id, "user":requester,
                "status":"enable", "approval-status":"pending", "type":"ssh-script",
                "schedule":"one-shot", "script":"echo BP008_JOB_OK", "script-type":"custom-script",
                "script-name":"", "associated-secret":0, "ssh-procedure":[], "web-api-procedure":[],
                "scheduled-time":start, "job-sch-start-date":"0000-00-00 00:00:00"}
    if any(type(detail.get(key)) is not type(value) or detail.get(key)!=value for key,value in expected.items()):
        raise ValueError
    return row, scheduled


def compile_job_request_approve_body(
    reviewer_queue: object, pending_detail: object, job_collection: object, job_detail: object, *,
    request_id: int, secret_id: int, job_name: str, requester: str,
    authenticated_reviewer: str, now_epoch: int,
) -> dict[str, object]:
    """Approve only a future, unrun fixed script with a five-minute window.

    The transport must repeat this check immediately before claiming dispatch.
    Approval does not prove that the Job ran or that access subsequently expired.
    """
    try:
        row = _pending_job_request(
            reviewer_queue, pending_detail, request_id=request_id,
            secret_id=secret_id, job_name=job_name, requester=requester,
            authenticated_reviewer=authenticated_reviewer,
        )
        _, scheduled = _schedule(
            job_collection, job_detail, job_name=job_name, secret_id=secret_id, requester=requester,
        )
        if type(now_epoch) is not int or now_epoch <= 0 or scheduled <= now_epoch + 60:
            raise ValueError
        start = datetime.fromtimestamp(scheduled, _ZONE).strftime("%Y-%m-%d %H:%M:%S")
        expiry = datetime.fromtimestamp(scheduled + 300, _ZONE).strftime("%Y-%m-%d %H:%M:%S")
        if (row["expiration-time"] != expiry
                or row["start-time"] not in {"", "0000-00-00 00:00:00", start}):
            raise ValueError
        return {"request-id": request_id, "tier": 1, "approval-status": "approved",
                "comments": _COMMENT, "start-after-approve": "disable",
                "start-time": start, "expiration-time": expiry}
    except Exception:
        raise JobRequestApproveContractError(_UNAVAILABLE) from None


def job_request_approved_readback(
    before: object, after: object, job_collection: object, *, request_id: int, secret_id: int,
    job_name: str, requester: str, scheduled_epoch: int,
) -> bool:
    """Prove exact Request approval/expiry and unchanged Job start, not execution."""
    try:
        if (type(scheduled_epoch) is not int or scheduled_epoch <= 0
                or any(type(value) is not int or not 0 < value <= 2_147_483_647
                       for value in (request_id, secret_id))):
            return False
        original, current = _detail(before), _detail(after)
        if (not isinstance(job_collection, Mapping)
                or any(type(job_collection.get(key)) is not type(value) or job_collection.get(key)!=value
                       for key,value in {"version":"v7.0.0", "build":29, "http_status":200,
                                         "http_method":"POST", "path":"secret", "name":"job",
                                         "status":"OK"}.items())):
            return False
        execution = project_job_collection_execution(
            job_collection, JobDefinitionExpectation(job_name,requester,secret_id,"echo BP008_JOB_OK"),
        )
        if not execution.job_enabled or not execution.approved or execution.state!="not_started":
            return False
        job=next(row for row in job_collection["results"] if row.get("name")==job_name)
        if type(job.get("scheduled-time")) is not int or job["scheduled-time"]!=scheduled_epoch:
            return False
        _identity(original, request_id, secret_id, job_name, requester)
        _identity(current, request_id, secret_id, job_name, requester)
        start = datetime.fromtimestamp(scheduled_epoch, _ZONE).strftime("%Y-%m-%d %H:%M:%S")
        expiry = datetime.fromtimestamp(scheduled_epoch + 300, _ZONE).strftime("%Y-%m-%d %H:%M:%S")
        return (
            original.get("final-status") == original.get("tier1-status") == "pending"
            and original.get("start-after-approve") == "disable"
            and type(original.get("duration")) is int and original["duration"] == 0
            and original.get("start-time") in {"", "0000-00-00 00:00:00", start}
            and original.get("expiration-time") == expiry
            and current.get("final-status") == current.get("tier1-status") == "approved"
            and current.get("start-after-approve") == "disable"
            and type(current.get("duration")) is int and current["duration"] == 0
            and type(current.get("start-time")) is str
            and current.get("start-time") == original.get("start-time")
            and current.get("expiration-time") == expiry
        )
    except Exception:
        return False
