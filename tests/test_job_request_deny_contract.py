from copy import deepcopy

import pytest

from fortipam_mcp.job_request_deny_contract import (
    JobRequestDenyContractError, compile_job_request_deny_body,
    job_request_denied_readback,
)


def envelope(row, *, method="GET"):
    return {"version": "v7.0.0", "build": 29, "status": "OK", "http_method": method,
            "http_status": 200, "path": "secret", "name": "request", "results": row}


ROW = {"id": 19, "secret-id": 7, "request-type": "job",
       "job-name": "mcp-v4-bp008-job-20261001-r14", "user": "synthetic-requester",
       "final-status": "pending", "tier1-status": "pending",
       "start-after-approve": "disable", "duration": 0, "start-time": "",
       "expiration-time": "2026-09-30 01:00:00"}
BINDING = {"request_id": 19, "secret_id": 7, "job_name": ROW["job-name"],
           "requester": ROW["user"], "authenticated_reviewer": "synthetic-reviewer"}


@pytest.mark.parametrize("failure", [None, "self", "queue_absent", "queue_duplicate",
                                    "version", "identity", "terminal", "time", "boolean_id", "queue_method"])
def test_denial_requires_exact_independent_reviewer_queue_and_pending_state(failure):
    queue, before, binding = envelope([deepcopy(ROW)], method="POST"), envelope([deepcopy(ROW)]), dict(BINDING)
    snapshot = deepcopy((queue, before, binding))
    if failure == "self": binding["authenticated_reviewer"] = binding["requester"]
    if failure == "queue_absent": queue["results"] = []
    if failure == "queue_duplicate": queue["results"].append(deepcopy(ROW))
    if failure == "queue_method": queue["http_method"] = "GET"
    if failure == "version": before["build"] = 30
    if failure == "identity": before["results"][0]["secret-id"] = 8
    if failure == "terminal": before["results"][0]["final-status"] = "approved"
    if failure == "time": before["results"][0]["expiration-time"] = "not-a-date"
    if failure == "boolean_id": binding["request_id"] = True
    if failure:
        with pytest.raises(JobRequestDenyContractError, match="^The fixed Job Request denial is unavailable.$"):
            compile_job_request_deny_body(queue, before, **binding)
        return
    body = compile_job_request_deny_body(queue, before, **binding)
    assert body == {"request-id": 19, "tier": 1, "approval-status": "denied",
                    "comments": "MCP V4 BP008 independent Job denial", "start-after-approve": "disable",
                    "duration": 0, "start-time": "", "expiration-time": ROW["expiration-time"]}
    assert (queue, before, binding) == snapshot
    after = envelope({**ROW, "final-status": "denied", "tier1-status": "denied"})
    projected = {key: value for key, value in binding.items() if key != "authenticated_reviewer"}
    assert job_request_denied_readback(before, after, **projected)
    after["results"]["expiration-time"] = "2026-10-01 01:00:00"
    assert not job_request_denied_readback(before, after, **projected)
    # Pending past its deadline is still pending; terminal state cannot be inferred.
    assert not job_request_denied_readback(before, before, **projected)
