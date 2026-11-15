"""Private build-29 Job Request denial body; no login, claim or dispatch.

Source: the retained frontend request-review serializer and denied enum. A
qualified authenticated reviewer queue and exact pending detail are required.
Returned identifiers remain inside the private adapter, never MCP output.
"""

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_UNAVAILABLE = "The fixed Job Request denial is unavailable."
_JOB = re.compile(r"mcp-v4-bp008-job-[0-9]{8}-r[1-9][0-9]*\Z")
_COMMENT = "MCP V4 BP008 independent Job denial"


class JobRequestDenyContractError(ValueError):
    """Stable rejection without private state in error messages."""


def _qualified(payload: object, *, method: str = "GET") -> Mapping[str, Any]:
    if (not isinstance(payload, Mapping)
            or type(payload.get("build")) is not int
            or type(payload.get("http_status")) is not int
            or any(payload.get(key) != value for key, value in {
                "version": "v7.0.0", "build": 29, "http_method": method,
                "http_status": 200, "path": "secret", "name": "request",
            }.items()) or payload.get("status") not in {"OK", "success"}):
        raise ValueError
    return payload


def _detail(payload: object) -> Mapping[str, Any]:
    row = _qualified(payload).get("results")
    if isinstance(row, list) and len(row) == 1:
        row = row[0]
    if not isinstance(row, Mapping):
        raise ValueError
    return row


def _identity(row: Mapping[str, Any], request_id: int, secret_id: int,
              job_name: str, requester: str) -> None:
    for key, value in {"id": request_id, "secret-id": secret_id,
                       "request-type": "job", "job-name": job_name,
                       "user": requester}.items():
        if type(row.get(key)) is not type(value) or row[key] != value:
            raise ValueError


def _pending_job_request(
    reviewer_queue: object, pending_detail: object, *,
    request_id: int, secret_id: int, job_name: str,
    requester: str, authenticated_reviewer: str,
) -> Mapping[str, Any]:
    """Qualify the exact fixed pending reviewer relation without a review delta."""
    if any(type(value) is not int or not 0 < value <= 2_147_483_647
           for value in (request_id, secret_id)):
        raise ValueError
    if not isinstance(job_name, str) or _JOB.fullmatch(job_name) is None:
        raise ValueError
    for value in (requester, authenticated_reviewer):
        if (not isinstance(value, str) or not value
                or len(value.encode("utf-8")) > 255
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError
    if requester == authenticated_reviewer:
        raise ValueError
    # Build 29 reports the wire POST for the frontend reviewer query,
    # even with its fixed X-Http-Method-Override: GET read header.
    rows = _qualified(reviewer_queue, method="POST").get("results")
    if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
        raise ValueError
    matches = [row for row in rows if row.get("id") == request_id]
    if len(matches) != 1:
        raise ValueError
    _identity(matches[0], request_id, secret_id, job_name, requester)
    row = _detail(pending_detail)
    _identity(row, request_id, secret_id, job_name, requester)
    if (row.get("final-status") != "pending" or row.get("tier1-status") != "pending"
            or row.get("start-after-approve") != "disable"
            or type(row.get("duration")) is not int or row["duration"] != 0):
        raise ValueError
    schedule = {key: row.get(key) for key in ("start-time", "expiration-time")}
    for schedule_value in schedule.values():
        if not isinstance(schedule_value, str):
            raise ValueError
        if schedule_value not in {"", "0000-00-00 00:00:00"}:
            parsed = datetime.strptime(schedule_value, "%Y-%m-%d %H:%M:%S")
            if parsed.strftime("%Y-%m-%d %H:%M:%S") != schedule_value:
                raise ValueError
    return row


def compile_job_request_deny_body(
    reviewer_queue: object, pending_detail: object, *,
    request_id: int, secret_id: int, job_name: str,
    requester: str, authenticated_reviewer: str,
) -> dict[str, object]:
    """Deny tier one only; preserve scheduling fields without granting access.

    An elapsed deadline is not converted into an expired lifecycle state. The
    caller must authenticate the exact independent reviewer, reserve a durable
    one-use claim, dispatch once and independently verify denial and Job effects.
    """
    try:
        row = _pending_job_request(
            reviewer_queue, pending_detail, request_id=request_id,
            secret_id=secret_id, job_name=job_name, requester=requester,
            authenticated_reviewer=authenticated_reviewer,
        )
        schedule = {key: row[key] for key in ("start-time", "expiration-time")}
        return {"request-id": request_id, "tier": 1, "approval-status": "denied",
                "comments": _COMMENT, "start-after-approve": "disable", "duration": 0,
                **schedule}
    except Exception:
        raise JobRequestDenyContractError(_UNAVAILABLE) from None


def job_request_denied_readback(
    before: object, after: object, *, request_id: int, secret_id: int,
    job_name: str, requester: str,
) -> bool:
    """Return only denial/preservation evidence, never Job execution proof."""
    try:
        original, current = _detail(before), _detail(after)
        _identity(original, request_id, secret_id, job_name, requester)
        _identity(current, request_id, secret_id, job_name, requester)
        if original.get("final-status") != "pending" or original.get("tier1-status") != "pending":
            return False
        return (current.get("final-status") == "denied"
                and current.get("tier1-status") == "denied"
                and all(type(current.get(key)) is type(original.get(key))
                        and current.get(key) == original.get(key) for key in (
                            "start-after-approve", "duration", "start-time", "expiration-time",
                        )))
    except Exception:
        return False
