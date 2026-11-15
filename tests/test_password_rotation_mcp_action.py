"""OAuth and default-off checks for the bounded rotation Tool surface."""

from dataclasses import asdict
import json

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import HttpServerSettings, create_http_app
from fortipam_mcp.password_rotation_mcp_action import (
    BINDING_CONTRACT,
    PREFIX,
    PasswordRotationMcpAction,
    _load_binding,
    build_password_rotation_candidate,
)
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
from test_http_server import (
    _authorize_and_login,
    _register_public_client,
    _request_headers,
    _v4_environment,
)
from test_password_rotation_live_workflow import BINDING, FakeTransport, factory


def test_binding_is_private_and_candidate_defaults_off(tmp_path):
    assert build_password_rotation_candidate({}) is None
    with pytest.raises(ValueError):
        build_password_rotation_candidate({PREFIX + "EXECUTION_ENABLED": "true"})
    path = tmp_path / "binding.json"
    path.write_text(json.dumps({"contract": BINDING_CONTRACT, **asdict(BINDING)}))
    path.chmod(0o600)
    assert _load_binding(path) == BINDING
    path.chmod(0o644)
    with pytest.raises(ValueError):
        _load_binding(path)


@pytest.mark.parametrize("operate,gate", [(False, True), (True, False), (True, True)])
def test_oauth_scope_gate_and_single_rotation_dispatch(tmp_path, operate, gate):
    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    transport = FakeTransport()
    action = PasswordRotationMcpAction(factory(tmp_path, transport)(), execution_enabled=gate)
    app = create_http_app(
        HttpServerSettings.from_environment(environment),
        v4_password_rotation_candidate_action=action,
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

        def call(name, arguments):
            response = client.post("/fpamcp", headers=headers, json={
                "jsonrpc": "2.0", "id": name, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            })
            assert response.status_code == 200
            return response.json()["result"]

        preview = call("preview_v4_password_rotation_700", {})
        assert not preview["isError"]
        assert BINDING.secret_name not in json.dumps(preview)
        confirmation = call("confirm_v4_password_rotation_700", {
            "preview_ref": preview["structuredContent"]["preview_ref"],
        })
        if not operate:
            assert confirmation["isError"] and transport.writes == 0
            return
        assert not confirmation["isError"]
        args = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_password_rotation_700", args)
        if not gate:
            assert result["isError"] and transport.writes == 0
            return
        assert not result["isError"]
        assert result["structuredContent"]["outcome"] == "succeeded"
        assert result["structuredContent"]["target_login_verified"] is False
        assert call("execute_confirmed_v4_password_rotation_700", args)["structuredContent"]["idempotent_replay"]
        assert transport.writes == 1
