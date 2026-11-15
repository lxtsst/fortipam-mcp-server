"""Real authenticated MCP registration over source-qualified synthetic snapshots."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import HttpConfigurationError, HttpServerSettings, create_http_app
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV, RuntimeProfile
from fortipam_mcp.server import FortiPamMcpServer
from fortipam_mcp.secret_dlp_association_live_workflow import SecretDlpAssociationLiveWorkflow
from fortipam_mcp.secret_dlp_association_mcp_action import (
    ASSOCIATION_TOOLS, RESTORE_TOOLS, SecretDlpAssociationMcpAction, SecretDlpAssociationMcpActionError,
    validate_secret_dlp_preview, validate_secret_dlp_confirmation, validate_secret_dlp_result,
)
from test_secret_dlp_association_live_workflow import Clock, Transport, IDENTITY, SENSOR
from test_http_server import (
    _v4_environment, _register_public_client, _authorize_and_login, _request_headers, _initialize_payload,
)

TOOLS = ASSOCIATION_TOOLS | RESTORE_TOOLS


def _settings(tmp_path: Path) -> HttpServerSettings:
    environment = _v4_environment(tmp_path)
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    return HttpServerSettings.from_environment(environment)


def _candidate(*, gate: bool = True, workflow_gate: bool = True) -> tuple[SecretDlpAssociationMcpAction, Transport]:
    clock = Clock()
    transport = Transport(clock)
    action = SecretDlpAssociationMcpAction(SecretDlpAssociationLiveWorkflow(
        transport, execution_enabled=workflow_gate, clock=clock), execution_enabled=gate)
    return action, transport


def _login(client: TestClient, *, scope: str = "fortipam:read fortipam:plan fortipam:operate",
           client_id: str | None = None) -> tuple[dict[str, str], str, str]:
    client_id = client_id or _register_public_client(client, scope)
    code, verifier = _authorize_and_login(client, client_id, scope)
    response = client.post("/fpamcp/oauth/token", data={"grant_type": "authorization_code",
        "client_id": client_id, "code": code, "code_verifier": verifier,
        "redirect_uri": "https://client.example/callback", "resource": "https://mcp.example.com/fpamcp"})
    assert response.status_code == 200
    token = response.json()["access_token"]
    headers = _request_headers(token)
    headers["host"] = "mcp.example.com"
    return headers, client_id, token


def _rpc(client: TestClient, headers: dict[str, str], method: str, params: dict[str, Any]) -> dict[str, Any]:
    response = client.post("/fpamcp", headers=headers, json={"jsonrpc": "2.0", "id": "test",
                                                          "method": method, "params": params})
    assert response.status_code == 200
    result = response.json()["result"]
    assert isinstance(result, dict)
    return result


def _call(client: TestClient, headers: dict[str, str], name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return _rpc(client, headers, "tools/call", {"name": name, "arguments": arguments})


def test_default_server_and_http_listing_have_no_candidate_tools(tmp_path: Path) -> None:
    server = FortiPamMcpServer()
    assert not TOOLS & {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    with TestClient(create_http_app(_settings(tmp_path)), base_url="https://mcp.example.com") as client:
        headers, _, _ = _login(client)
        listing = _rpc(client, headers, "tools/list", {})
        assert not TOOLS & {tool["name"] for tool in listing["tools"]}
        denied = _call(client, headers, "preview_v4_secret_dlp_association_700", {})
        assert denied["isError"]


@pytest.mark.parametrize("defect", ["profile", "auth_mode", "authority"])
def test_http_injection_requires_exact_controlled_local_authority(tmp_path: Path, defect: str) -> None:
    settings = _settings(tmp_path)
    if defect == "profile":
        settings = replace(settings, runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif defect == "auth_mode":
        settings = replace(settings, auth_mode="token")
    else:
        settings = replace(settings, v4_planning_authorization=None)
    action, transport = _candidate()
    with pytest.raises(HttpConfigurationError, match="controlled OAuth operation authority"):
        create_http_app(settings, v4_secret_dlp_association_candidate_action=action)
    assert transport.inspections == 0


@pytest.mark.parametrize("defect", ["profile", "oauth", "authority", "action_type"])
def test_direct_server_injection_cannot_bypass_candidate_guard(tmp_path: Path, defect: str) -> None:
    settings = _settings(tmp_path)
    action, _ = _candidate()
    kwargs: dict[str, Any] = {"runtime_profile": "v4-controlled", "v4_http_oauth": True,
        "v4_planning_authorization": settings.v4_planning_authorization,
        "v4_secret_dlp_association_candidate_action": action}
    if defect == "profile":
        kwargs["runtime_profile"] = "v4-plan-only"
    elif defect == "oauth":
        kwargs["v4_http_oauth"] = False
    elif defect == "authority":
        kwargs["v4_planning_authorization"] = None
    else:
        kwargs["v4_secret_dlp_association_candidate_action"] = object()
    with pytest.raises(RuntimeError):
        FortiPamMcpServer(**kwargs)


@pytest.mark.parametrize("scope,gate,workflow_gate", [
    ("fortipam:read", True, True), ("fortipam:read fortipam:plan", True, True),
    ("fortipam:read fortipam:plan fortipam:operate", False, True),
    ("fortipam:read fortipam:plan fortipam:operate", True, False),
    ("fortipam:read fortipam:plan fortipam:operate", True, True),
])
def test_real_oauth_principal_and_both_gates_control_the_six_fixed_tools(
    tmp_path: Path, scope: str, gate: bool, workflow_gate: bool,
) -> None:
    action, transport = _candidate(gate=gate, workflow_gate=workflow_gate)
    app = create_http_app(_settings(tmp_path), v4_secret_dlp_association_candidate_action=action)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        headers, _, _ = _login(client, scope=scope)
        listing = _rpc(client, headers, "tools/list", {})
        candidates = {tool["name"]: tool for tool in listing["tools"] if tool["name"] in TOOLS}
        assert set(candidates) == TOOLS
        for name, tool in candidates.items():
            expected = {} if name.startswith("preview") else {"preview_ref": "string"} if name.startswith("confirm") else {"authorization_ref": "string"}
            schema = tool["inputSchema"]
            assert set(schema.get("properties", {})) == set(expected)
            assert schema["additionalProperties"] is False
        preview = _call(client, headers, "preview_v4_secret_dlp_association_700", {})
        if "fortipam:plan" not in scope:
            assert preview["isError"] and transport.inspections == 0
            return
        assert not preview["isError"]
        assert _call(client, headers, "preview_v4_secret_dlp_association_restore_700", {})["isError"]
        private = (IDENTITY.name, IDENTITY.target, SENSOR, "projected_secret_json", "opaque_field_digest")
        assert all(value not in json.dumps(preview) for value in private)
        ref = preview["structuredContent"]["preview_ref"]
        assert _call(client, headers, "confirm_v4_secret_dlp_association_restore_700", {"preview_ref": ref})["isError"]
        confirmation = _call(client, headers, "confirm_v4_secret_dlp_association_700", {"preview_ref": ref})
        if "fortipam:operate" not in scope:
            assert confirmation["isError"] and transport.associations == 0
            return
        assert not confirmation["isError"]
        args = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
        assert _call(client, headers, "execute_confirmed_v4_secret_dlp_association_restore_700", args)["isError"]
        result = _call(client, headers, "execute_confirmed_v4_secret_dlp_association_700", args)
        if not gate or not workflow_gate:
            assert result["isError"] and transport.associations == 0
            return
        assert not result["isError"] and result["structuredContent"]["outcome"] == "succeeded"
        assert result["structuredContent"]["file_audit_effect"] == "unproven"
        assert _call(client, headers, "execute_confirmed_v4_secret_dlp_association_700", args)["structuredContent"]["idempotent_replay"] is True
        restore = _call(client, headers, "preview_v4_secret_dlp_association_restore_700", {})
        restore_confirmation = _call(client, headers, "confirm_v4_secret_dlp_association_restore_700",
            {"preview_ref": restore["structuredContent"]["preview_ref"]})
        restored = _call(client, headers, "execute_confirmed_v4_secret_dlp_association_restore_700",
            {"authorization_ref": restore_confirmation["structuredContent"]["authorization_ref"]})
        assert restored["structuredContent"]["outcome"] == "succeeded"
        assert transport.associations == transport.restorations == 1
        assert all(value not in json.dumps(restored) for value in private)


@pytest.mark.parametrize("name,args", [
    ("preview_v4_secret_dlp_association_700", {"secret_id": 17}),
    ("preview_v4_secret_dlp_association_restore_700", {"sensor_name": SENSOR}),
    ("confirm_v4_secret_dlp_association_700", {"preview_ref": "secret-dlp-associate-preview-x", "field": []}),
    ("execute_confirmed_v4_secret_dlp_association_700", {"authorization_ref": "secret-dlp-associate-authorized-x", "password": "synthetic-material-sentinel"}),
])
def test_mcp_schemas_reject_payload_or_selector_expansion_before_source_reads(
    tmp_path: Path, name: str, args: dict[str, Any],
) -> None:
    action, transport = _candidate()
    with TestClient(create_http_app(_settings(tmp_path), v4_secret_dlp_association_candidate_action=action),
                    base_url="https://mcp.example.com") as client:
        headers, _, _ = _login(client)
        result = _call(client, headers, name, args)
        assert result["isError"] and transport.inspections == 0 and transport.associations == 0
        assert "synthetic-material-sentinel" not in json.dumps(result)


def test_principal_must_be_validated_planning_identity() -> None:
    action, transport = _candidate()
    with pytest.raises(SecretDlpAssociationMcpActionError):
        action.preview_association(SimpleNamespace(requester=SimpleNamespace(digest="b" * 64)))
    assert transport.inspections == 0


@pytest.mark.parametrize("phase", ["preview", "confirmation", "result"])
def test_closed_output_projection_rejects_private_payload_expansion(phase: str) -> None:
    clock = Clock()
    workflow = SecretDlpAssociationLiveWorkflow(Transport(clock), execution_enabled=True, clock=clock)
    preview = workflow.preview_association(requester_digest="b" * 64)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest="b" * 64)
    result = workflow.execute(str(confirmation["authorization_ref"]), requester_digest="b" * 64)
    value = {"preview": preview, "confirmation": confirmation, "result": result}[phase]
    value["field"] = "synthetic-material-sentinel"
    with pytest.raises(SecretDlpAssociationMcpActionError) as error:
        if phase == "preview":
            validate_secret_dlp_preview(value, "associate")
        elif phase == "confirmation":
            validate_secret_dlp_confirmation(value, "associate", str(preview["preview_ref"]))
        else:
            validate_secret_dlp_result(value, "associate")
    assert "sentinel" not in str(error.value)
