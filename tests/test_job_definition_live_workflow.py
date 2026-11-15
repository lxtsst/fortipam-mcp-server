"""One-use workflow checks for the fixed disabled Job candidate."""

from __future__ import annotations

from pathlib import Path
import json
import os
import stat

import pytest

from fortipam_mcp.job_definition_http_transport import (
    FortiPamDisabledJobHttpTransport,
    JobCreateInspection,
)
from fortipam_mcp.job_definition_live_workflow import (
    JobDefinitionCreateLiveWorkflow,
    JobDefinitionLiveWorkflowError,
)
from fortipam_mcp.job_definition_mcp_action import (
    BINDING_CONTRACT,
    PREFIX,
    JobDefinitionMcpAction,
    _load_binding,
    build_disabled_job_candidate,
)
from fortipam_mcp.job_definition_projection import (
    JobDefinitionReadback, JobExecutionReadback,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


REQUESTER = "a" * 64


def _workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> tuple[JobDefinitionCreateLiveWorkflow, list[JobCreateInspection], list[JobCreateInspection]]:
    transport = FortiPamDisabledJobHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example.test", "synthetic", 10, None,
        ),
        target_name="mcp-v4-bp008-job-20260930-r6",
        target_requester="adminapi", expected_secret_id=999,
    )
    current = [JobCreateInspection("b" * 64, False)]
    writes: list[JobCreateInspection] = []
    monkeypatch.setattr(transport, "inspect", lambda: current[0])

    def post(expected: JobCreateInspection) -> bool:
        writes.append(expected)
        return True

    monkeypatch.setattr(transport, "post_disabled_once", post)
    monkeypatch.setattr(transport, "readback", lambda **kwargs: JobDefinitionReadback(*([True] * 8)))
    monkeypatch.setattr(
        transport, "observe_execution",
        lambda: JobExecutionReadback("not_started", False, False, True),
    )
    return JobDefinitionCreateLiveWorkflow(transport, tmp_path / "claim"), current, writes


def test_preview_confirm_execute_claim_and_idempotent_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["Proposed Changes"]["job_execution"] is False
    authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    first = workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    replay = workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)

    assert first["outcome"] == "succeeded"
    assert first["verification"] == "collection_projection_verified"
    observation = workflow.observe(requester_digest=REQUESTER)
    assert observation["definition_verified"] is True
    assert observation["execution_state"] == "not_started"
    assert replay["idempotent_replay"] is True
    assert len(writes) == 1
    assert (tmp_path / "claim").is_file()
    with pytest.raises(JobDefinitionLiveWorkflowError):
        workflow.preview(requester_digest=REQUESTER)


def test_claim_directory_sync_failure_stops_post_and_preserves_non_replay_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    original = os.fsync

    def sync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("synthetic directory sync failure")
        original(fd)

    monkeypatch.setattr(os, "fsync", sync)
    with pytest.raises(JobDefinitionLiveWorkflowError):
        workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    assert writes == [] and workflow._claim_path.is_file()
    with pytest.raises(JobDefinitionLiveWorkflowError): workflow.preview(requester_digest=REQUESTER)


def test_drift_blocks_claim_and_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, current, writes = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    current[0] = JobCreateInspection("c" * 64, False)

    with pytest.raises(JobDefinitionLiveWorkflowError):
        workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    assert writes == []
    assert not (tmp_path / "claim").exists()


def test_ambiguous_post_reconciles_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)

    def ambiguous(expected: JobCreateInspection) -> bool:
        writes.append(expected)
        raise TimeoutError("synthetic POST timeout")

    monkeypatch.setattr(workflow._transport, "post_disabled_once", ambiguous)
    first = workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    again = workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    restarted = JobDefinitionCreateLiveWorkflow(workflow._transport, tmp_path / "claim")

    assert first["outcome"] == "reconciliation_required"
    assert first["definition_observed"] is True
    assert again["idempotent_replay"] is True
    assert len(writes) == 1
    with pytest.raises(JobDefinitionLiveWorkflowError):
        restarted.preview(requester_digest=REQUESTER)


def test_delayed_collection_visibility_retries_only_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    attempts = 0
    delays: list[int] = []

    def readback(**kwargs: object) -> JobDefinitionReadback:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise TimeoutError("synthetic collection lag")
        return JobDefinitionReadback(*([True] * 8))

    monkeypatch.setattr(workflow._transport, "readback", readback)
    monkeypatch.setattr("fortipam_mcp.job_definition_live_workflow.time.sleep", delays.append)
    result = workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)

    assert result["outcome"] == "succeeded"
    assert len(writes) == 1
    assert attempts == 3
    assert delays == [1, 2]


def test_candidate_defaults_off_and_binding_is_owner_only(tmp_path: Path) -> None:
    assert build_disabled_job_candidate({}) is None
    with pytest.raises(ValueError):
        build_disabled_job_candidate({PREFIX + "EXECUTION_ENABLED": "true"})
    path = tmp_path / "binding.json"
    path.write_text(json.dumps({
        "contract": BINDING_CONTRACT,
        "target_name": "mcp-v4-bp008-job-20260930-r6",
        "target_requester": "adminapi",
        "expected_secret_id": 999,
    }))
    path.chmod(0o600)
    assert _load_binding(path)["target_requester"] == "adminapi"
    path.chmod(0o644)
    with pytest.raises(ValueError):
        _load_binding(path)


def test_closed_execution_gate_does_not_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    action = JobDefinitionMcpAction(workflow, execution_enabled=False)
    with pytest.raises(RuntimeError):
        action.execute("job-create-authorized-synthetic", object())
    assert writes == []


@pytest.mark.parametrize("operate,gate", [(False, True), (True, False), (True, True)])
def test_oauth_mcp_candidate_scope_and_gate(
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
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    action = JobDefinitionMcpAction(workflow, execution_enabled=gate)
    app = create_http_app(
        HttpServerSettings.from_environment(environment),
        v4_disabled_job_candidate_action=action,
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

        preview = call("preview_v4_disabled_job_create_700", {})
        assert not preview["isError"]
        assert "BP008_JOB_OK" not in json.dumps(preview)
        confirmation = call("confirm_v4_disabled_job_create_700", {
            "preview_ref": preview["structuredContent"]["preview_ref"],
        })
        if not operate:
            assert confirmation["isError"] and not writes
            return
        assert not confirmation["isError"]
        args = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_disabled_job_create_700", args)
        if not gate:
            assert result["isError"] and not writes
            return
        assert result["structuredContent"]["outcome"] == "succeeded"
        observation = call("observe_v4_disabled_job_create_700", {})
        assert observation["structuredContent"]["definition_verified"] is True
        replay = call("execute_confirmed_v4_disabled_job_create_700", args)
        assert replay["structuredContent"]["idempotent_replay"]
        assert len(writes) == 1
