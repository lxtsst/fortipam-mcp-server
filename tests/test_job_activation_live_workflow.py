"""One-use activation, stale-preflight and uncertain-result checks."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from fortipam_mcp.job_activation_live_workflow import (
    JobActivationLiveWorkflow,
    JobActivationLiveWorkflowError,
)
from fortipam_mcp.job_activation_mcp_action import (
    JobActivationMcpAction, PREFIX, build_fixed_job_activation_candidate,
)
from fortipam_mcp.job_definition_http_transport import (
    FortiPamDisabledJobHttpTransport,
    JobActivationInspection,
)
from fortipam_mcp.job_definition_projection import JobExecutionReadback
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


REQUESTER = "a" * 64


def _transport() -> FortiPamDisabledJobHttpTransport:
    return FortiPamDisabledJobHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example.test", "synthetic-token", 10, None,
        ),
        target_name="mcp-v4-bp008-job-20260930-r9",
        target_requester="adminapi", expected_secret_id=999,
    )


def test_one_claim_one_put_and_idempotent_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _transport()
    clock = [int(datetime(2026, 9, 30, tzinfo=timezone.utc).timestamp())]
    writes: list[JobActivationInspection] = []
    observations = [False, True]

    def inspect(*, scheduled_at: datetime, now: datetime) -> JobActivationInspection:
        assert scheduled_at - now == timedelta(minutes=5)
        return JobActivationInspection("f" * 64, scheduled_at)

    def put(expected: JobActivationInspection, *, now: datetime) -> bool:
        writes.append(expected)
        return True

    def observe() -> JobExecutionReadback:
        enabled = observations.pop(0) if observations else True
        return JobExecutionReadback("not_started", False, enabled, True)

    monkeypatch.setattr(transport, "inspect_activation", inspect)
    monkeypatch.setattr(transport, "put_activation_once", put)
    monkeypatch.setattr(transport, "observe_execution", observe)
    workflow = JobActivationLiveWorkflow(
        transport, tmp_path / "private" / "claim.json",
        clock=lambda: clock[0], sleep=lambda _: None,
    )
    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["device_write_executed"] is False
    auth = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    result = workflow.execute(auth["authorization_ref"], requester_digest=REQUESTER)
    assert result["outcome"] == "scheduled"
    assert result["script_execution_verified"] is False
    assert len(writes) == 1
    assert (tmp_path / "private" / "claim.json").exists()
    replay = workflow.execute(auth["authorization_ref"], requester_digest=REQUESTER)
    assert replay["idempotent_replay"] is True
    assert len(writes) == 1


def test_changed_preflight_blocks_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _transport()
    inspections = 0
    writes = 0

    def inspect(*, scheduled_at: datetime, now: datetime) -> JobActivationInspection:
        nonlocal inspections
        inspections += 1
        return JobActivationInspection(str(inspections), scheduled_at)

    def put(expected: JobActivationInspection, *, now: datetime) -> bool:
        nonlocal writes
        writes += 1
        return True

    monkeypatch.setattr(transport, "inspect_activation", inspect)
    monkeypatch.setattr(transport, "put_activation_once", put)
    workflow = JobActivationLiveWorkflow(
        transport, tmp_path / "private" / "claim.json",
        clock=lambda: 1_800_000_000,
    )
    preview = workflow.preview(requester_digest=REQUESTER)
    with pytest.raises(JobActivationLiveWorkflowError, match="unavailable"):
        workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    assert writes == 0
    assert not (tmp_path / "private" / "claim.json").exists()


def test_ambiguous_put_is_claimed_and_never_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _transport()
    writes = 0

    def inspect(*, scheduled_at: datetime, now: datetime) -> JobActivationInspection:
        return JobActivationInspection("f" * 64, scheduled_at)

    def put(expected: JobActivationInspection, *, now: datetime) -> bool:
        nonlocal writes
        writes += 1
        raise RuntimeError("ambiguous")

    monkeypatch.setattr(transport, "inspect_activation", inspect)
    monkeypatch.setattr(transport, "put_activation_once", put)
    monkeypatch.setattr(
        transport, "observe_execution",
        lambda: JobExecutionReadback("not_started", False, False, True),
    )
    workflow = JobActivationLiveWorkflow(
        transport, tmp_path / "private" / "claim.json",
        clock=lambda: 1_800_000_000, sleep=lambda _: None,
    )
    preview = workflow.preview(requester_digest=REQUESTER)
    auth = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    result = workflow.execute(auth["authorization_ref"], requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required"
    assert writes == 1
    assert workflow.execute(auth["authorization_ref"], requester_digest=REQUESTER)[
        "idempotent_replay"
    ] is True
    assert writes == 1


def test_candidate_defaults_off_and_rejects_gate_without_feature() -> None:
    assert build_fixed_job_activation_candidate({}) is None
    with pytest.raises(ValueError):
        build_fixed_job_activation_candidate({PREFIX + "EXECUTION_ENABLED": "true"})


def test_observe_returns_fixed_marker_boolean_without_result_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _transport()
    monkeypatch.setattr(
        transport, "observe_execution",
        lambda: JobExecutionReadback(
            "ended_outcome_unverified", True, True, True, True,
        ),
    )
    workflow = JobActivationLiveWorkflow(
        transport, tmp_path / "private" / "claim.json",
    )
    observation = workflow.observe(requester_digest=REQUESTER)
    assert observation["fixed_result_marker_present"] is True
    assert observation["execution_state"] == "ended_outcome_unverified"
    assert "BP008_JOB_OK" not in json.dumps(observation)


@pytest.mark.parametrize("operate,gate", [(False, True), (True, False), (True, True)])
def test_oauth_mcp_activation_scope_and_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operate: bool, gate: bool,
) -> None:
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import (
        _v4_environment, _register_public_client, _authorize_and_login, _request_headers,
    )

    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    transport = _transport()
    writes = 0

    def inspect(*, scheduled_at: datetime, now: datetime) -> JobActivationInspection:
        return JobActivationInspection("f" * 64, scheduled_at)

    def put(expected: JobActivationInspection, *, now: datetime) -> bool:
        nonlocal writes
        writes += 1
        return True

    monkeypatch.setattr(transport, "inspect_activation", inspect)
    monkeypatch.setattr(transport, "put_activation_once", put)
    monkeypatch.setattr(
        transport, "observe_execution",
        lambda: JobExecutionReadback("not_started", False, writes > 0, True),
    )
    workflow = JobActivationLiveWorkflow(
        transport, tmp_path / "private" / "claim.json",
        clock=lambda: 1_800_000_000, sleep=lambda _: None,
    )
    action = JobActivationMcpAction(workflow, execution_enabled=gate)
    app = create_http_app(
        HttpServerSettings.from_environment(environment),
        v4_fixed_job_activation_candidate_action=action,
    )
    scope = "fortipam:read fortipam:plan" + (" fortipam:operate" if operate else "")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token = client.post("/fpamcp/oauth/token", data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
            "resource": "https://mcp.example.com/fpamcp",
        })
        assert token.status_code == 200
        headers = _request_headers(token.json()["access_token"])
        headers["host"] = "mcp.example.com"

        def call(name: str, arguments: dict[str, object]) -> dict[str, object]:
            response = client.post("/fpamcp", headers=headers, json={
                "jsonrpc": "2.0", "id": name, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            })
            assert response.status_code == 200
            return response.json()["result"]

        preview = call("preview_v4_fixed_job_activation_700", {})
        assert not preview["isError"]
        assert "BP008_JOB_OK" not in json.dumps(preview)
        confirmation = call("confirm_v4_fixed_job_activation_700", {
            "preview_ref": preview["structuredContent"]["preview_ref"],
        })
        if not operate:
            assert confirmation["isError"] and writes == 0
            return
        assert not confirmation["isError"]
        args = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_fixed_job_activation_700", args)
        if not gate:
            assert result["isError"] and writes == 0
            return
        assert result["structuredContent"]["outcome"] == "scheduled"
        assert result["structuredContent"]["script_execution_verified"] is False
        observation = call("observe_v4_fixed_job_activation_700", {})
        assert observation["structuredContent"]["job_enabled"] is True
        replay = call("execute_confirmed_v4_fixed_job_activation_700", args)
        assert replay["structuredContent"]["idempotent_replay"] is True
        assert writes == 1
