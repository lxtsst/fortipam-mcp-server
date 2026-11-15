"""Actual OAuth/MCP context enforces plan/operate on the private recovery DI."""
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import create_http_app, HttpConfigurationError, HttpServerSettings
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_http_server import (
    _authorize_and_login, _bearer_environment, _register_public_client, _request_headers,
    _v4_controlled_environment, V4_FOLDER_ACTION_FEATURE_ENV,
)


class _BoundaryAction:
    def __init__(self):
        self.calls = []

    def preview(self, principal):
        assert type(principal) is V4PlanningPrincipal
        self.calls.append(("preview", principal))
        return {"preview_ref": "scanned-recovery-preview-test01", "device_write_executed": False}

    def confirm(self, preview_ref, principal):
        assert preview_ref == "scanned-recovery-preview-test01" and type(principal) is V4PlanningPrincipal
        self.calls.append(("confirm", principal))
        return {"authorization_ref": "scanned-recovery-authorization-test01", "device_write_executed": False}

    def execute(self, authorization_ref, principal):
        assert authorization_ref == "scanned-recovery-authorization-test01" and type(principal) is V4PlanningPrincipal
        self.calls.append(("execute", principal))
        return {"outcome": "succeeded", "verification": "verified"}


def test_scanned_recovery_di_rejects_uncontrolled_auth():
    settings = HttpServerSettings.from_environment(_bearer_environment())
    with pytest.raises(HttpConfigurationError, match="Scanned Source recovery requires"):
        create_http_app(settings, v4_unix_scanned_source_recovery_action=_BoundaryAction())


def test_default_has_no_candidate_and_oauth_scopes_bind_all_three_tools(tmp_path: Path):
    environment = _v4_controlled_environment(tmp_path)
    environment[V4_FOLDER_ACTION_FEATURE_ENV] = "false"
    settings = HttpServerSettings.from_environment(environment)
    action = _BoundaryAction()
    names = ("preview_v4_unix_scanned_source_recovery_700", "confirm_v4_unix_scanned_source_recovery_700",
        "execute_confirmed_v4_unix_scanned_source_recovery_700")
    def headers(client, scope):
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        response = client.post("/fpamcp/oauth/token", data={"grant_type": "authorization_code", "client_id": client_id,
            "code": code, "code_verifier": verifier, "redirect_uri": "https://client.example/callback", "resource": "https://mcp.example.com/fpamcp"})
        assert response.status_code == 200
        return {**_request_headers(response.json()["access_token"]), "host": "mcp.example.com"}
    def rpc(client, token, method, params=None):
        response = client.post("/fpamcp", headers=token, json={"jsonrpc": "2.0", "id": "scanned-recovery-test01",
            "method": method, **({"params": params} if params is not None else {})})
        assert response.status_code == 200
        return response.json()["result"]
    with TestClient(create_http_app(settings), base_url="https://mcp.example.com") as client:
        plan = headers(client, "fortipam:read fortipam:plan")
        ordinary = rpc(client, plan, "tools/list")["tools"]
        assert not set(names).intersection(tool["name"] for tool in ordinary)
    with TestClient(create_http_app(settings, v4_unix_scanned_source_recovery_action=action), base_url="https://mcp.example.com") as client:
        plan = headers(client, "fortipam:read fortipam:plan")
        operate = headers(client, "fortipam:read fortipam:plan fortipam:operate")
        tools = {tool["name"]: tool for tool in rpc(client, plan, "tools/list")["tools"]}
        assert set(names).issubset(tools) and len(tools) == len(ordinary) + 3
        assert all(tools[name]["inputSchema"]["additionalProperties"] is False for name in names)
        arguments = ({}, {"preview_ref": "scanned-recovery-preview-test01"}, {"authorization_ref": "scanned-recovery-authorization-test01"})
        assert tools[names[0]]["annotations"]["readOnlyHint"] is True
        assert tools[names[2]]["annotations"]["destructiveHint"] is True
        assert tools[names[0]]["inputSchema"].get("properties", {}) == {}
        for name, argument in zip(names[1:], arguments[1:]):
            assert set(tools[name]["inputSchema"]["properties"]) == set(argument)
        for index, name in enumerate(names):
            result = rpc(client, plan, "tools/call", {"name": name, "arguments": arguments[index]})
            assert result["isError"] is (index != 0)
        assert [kind for kind, _ in action.calls] == ["preview"]
        for index, name in enumerate(names):
            result = rpc(client, operate, "tools/call", {"name": name, "arguments": {**arguments[index], "source_name": "caller-selected-source"}})
            assert result["isError"]
        assert [kind for kind, _ in action.calls] == ["preview"]
        for index, name in enumerate(names):
            result = rpc(client, operate, "tools/call", {"name": name, "arguments": arguments[index]})
            assert not result["isError"]
        assert [kind for kind, _ in action.calls] == ["preview", "preview", "confirm", "execute"]
        principals = [principal for _, principal in action.calls[1:]]
        assert principals[0] == principals[1] == principals[2]
