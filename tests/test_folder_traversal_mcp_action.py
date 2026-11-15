import asyncio
from dataclasses import asdict
import json
import os
from types import SimpleNamespace
import pytest
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from fortipam_mcp.folder_traversal_mcp_action import (
    CONTRACT, PREFIX, FolderTraversalMcpAction, _private_binding,
    build_folder_traversal_candidate, register_folder_traversal_tools,
)
from fortipam_mcp.folder_traversal_live_workflow import FolderTraversalLiveWorkflow
from fortipam_mcp.folder_traversal_m4_adapter import FolderTraversalBinding
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_v4_m3 import _requester
from test_folder_traversal_live_workflow import Transport
from test_folder_traversal_candidate import record
from fortipam_mcp.folder_traversal_candidate import prepare_folder_traversal

def binding_fixture():
    candidate = prepare_folder_traversal(record(), folder_id=12, parent_id=0, username="gui-user", version="7.0.0", build=29)
    return FolderTraversalBinding(12, 0, "gui-user", candidate.current_digest, candidate.proposed_digest)


def test_owner_only_http_environment_composes_traversal_with_gate_closed(tmp_path, monkeypatch):
    from fortipam_mcp.http_server import HTTP_ENV_FILE_VARIABLE, load_http_runtime_environment
    from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX as metadata_prefix

    binding_path = tmp_path / "binding.json"
    binding_path.write_text(json.dumps({
        "contract": CONTRACT, "parent_path": "Public", **asdict(binding_fixture()),
    }))
    binding_path.chmod(0o600)
    key = tmp_path / "workflow.key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    values = {
        PREFIX + "ENABLED": "true",
        PREFIX + "EXECUTION_ENABLED": "false",
        PREFIX + "BINDING_FILE": str(binding_path),
        PREFIX + "AUTHORIZATION_DB": str(tmp_path / "workflow.sqlite3"),
        PREFIX + "AUTHORIZATION_HMAC_KEY_FILE": str(key),
        metadata_prefix + "ENABLED": "true",
        metadata_prefix + "BASE_URL": "https://fortipam.example.test",
        metadata_prefix + "API_TOKEN": "synthetic-test-token",
    }
    environment_file = tmp_path / "http.env"
    environment_file.write_text("".join(f"{name}={value}\n" for name, value in values.items()))
    environment_file.chmod(0o600)
    for name in tuple(os.environ):
        if name.startswith((PREFIX, metadata_prefix)):
            monkeypatch.delenv(name)
    # Track loader-created variables so this test cannot configure later tests.
    for name in values:
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    monkeypatch.setenv(HTTP_ENV_FILE_VARIABLE, str(environment_file))

    assert load_http_runtime_environment()
    action = build_folder_traversal_candidate(os.environ)
    assert action is not None
    assert action._action._execution_enabled is False


def test_candidate_disabled_default_and_strict_private_binding(tmp_path):
    assert build_folder_traversal_candidate({}) is None
    with pytest.raises(ValueError):
        build_folder_traversal_candidate({PREFIX + "EXECUTION_ENABLED": "true"})
    path = tmp_path / "binding.json"
    value = dict(contract=CONTRACT, folder_id=12, parent_id=0,
        username="gui-user", current_digest="a" * 64, expected_digest="b" * 64, parent_path="Public")
    path.write_text(json.dumps(value)); path.chmod(0o600)
    binding, parent = _private_binding(path)
    assert binding.username == "gui-user" and parent == "Public"
    value["extra"] = "not-allowed"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError): _private_binding(path)
    path.write_text(json.dumps({k:v for k,v in value.items() if k != "extra"}))
    path.chmod(0o644)
    with pytest.raises(ValueError): _private_binding(path)


@pytest.mark.parametrize("execution_enabled", [False, True])
def test_sdk_candidate_tools_keep_selectors_private_and_enforce_execution_gate(tmp_path, execution_enabled):
    async def scenario():
        key = tmp_path / "key"; key.write_bytes(b"a" * 32); key.chmod(0o600)
        binding = binding_fixture()
        transport = Transport(None)
        workflow = FolderTraversalLiveWorkflow(tmp_path / "state.sqlite3", key, transport, binding=binding, clock=lambda:1000)
        principal = V4PlanningPrincipal(_requester(), "b" * 64)
        checks = []
        def operator():
            checks.append("operate")
            return principal
        host = SimpleNamespace(mcp=MCPServer("candidate-test"), _v4_planning_principal=lambda:principal,
            _v4_folder_action_principal=operator)
        register_folder_traversal_tools(host, FolderTraversalMcpAction(workflow, binding, execution_enabled=execution_enabled))
        listed = await host.mcp.list_tools()
        assert len(listed) == 3
        preview = await host.mcp.call_tool("preview_v4_folder_traversal_grant", {})
        assert not preview.is_error
        summary = preview.structured_content
        assert "gui-user" not in json.dumps(summary)
        confirmation = await host.mcp.call_tool("confirm_v4_folder_traversal_grant", {"preview_ref": summary["preview_ref"]})
        assert not confirmation.is_error
        arguments = {"authorization_ref": confirmation.structured_content["authorization_ref"]}
        if execution_enabled:
            result = await host.mcp.call_tool("execute_confirmed_v4_folder_traversal", arguments)
            assert not result.is_error and result.structured_content["outcome"] == "succeeded"
        else:
            with pytest.raises(ToolError):
                await host.mcp.call_tool("execute_confirmed_v4_folder_traversal", arguments)
        assert transport.writes == int(execution_enabled)
        assert checks == ["operate", "operate"]
    asyncio.run(scenario())


def test_http_host_rejects_candidate_outside_controlled_oauth_profile(tmp_path):
    from fortipam_mcp.http_server import HttpServerSettings, HttpConfigurationError, create_http_app
    from test_http_server import _v4_environment
    settings = HttpServerSettings.from_environment(_v4_environment(tmp_path))
    with pytest.raises(HttpConfigurationError, match="Folder traversal candidate requires"):
        create_http_app(settings, v4_folder_traversal_action=object())


@pytest.mark.parametrize("operate", [False, True])
def test_real_http_oauth_isolated_candidate_authorizes_one_private_bound_write(tmp_path, operate):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers
    env = _v4_environment(tmp_path / "oauth")
    env[RUNTIME_PROFILE_ENV] = "v4-controlled"
    settings = HttpServerSettings.from_environment(env)
    key = tmp_path / "candidate-key"; key.write_bytes(b"a" * 32); key.chmod(0o600)
    binding = binding_fixture()
    transport = Transport(None)
    workflow = FolderTraversalLiveWorkflow(tmp_path / "candidate.sqlite3", key, transport, binding=binding)
    action = FolderTraversalMcpAction(workflow, binding, execution_enabled=True)
    app = create_http_app(settings, v4_folder_traversal_action=action)
    scope = "fortipam:read fortipam:plan" + (" fortipam:operate" if operate else "")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token = client.post("/fpamcp/oauth/token", data={
            "grant_type":"authorization_code", "client_id":client_id, "code":code,
            "code_verifier":verifier, "redirect_uri":"https://client.example/callback",
            "resource":"https://mcp.example.com/fpamcp"})
        assert token.status_code == 200
        headers = _request_headers(token.json()["access_token"])
        headers["host"] = "mcp.example.com"
        def call(name, arguments):
            response = client.post("/fpamcp", headers=headers, json={"jsonrpc":"2.0", "id":name,
                "method":"tools/call", "params":{"name":name,"arguments":arguments}})
            assert response.status_code == 200
            return response.json()["result"]
        preview = call("preview_v4_folder_traversal_grant", {})
        assert not preview["isError"]
        assert "gui-user" not in json.dumps(preview)
        confirmed = call("confirm_v4_folder_traversal_grant", {"preview_ref":preview["structuredContent"]["preview_ref"]})
        if not operate:
            assert confirmed["isError"] and transport.writes == 0
            return
        assert not confirmed["isError"]
        arguments = {"authorization_ref":confirmed["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_folder_traversal", arguments)
        assert not result["isError"] and result["structuredContent"]["outcome"] == "succeeded"
        replay = call("execute_confirmed_v4_folder_traversal", arguments)
        assert replay["structuredContent"]["idempotent_replay"] is True
        assert transport.writes == 1
