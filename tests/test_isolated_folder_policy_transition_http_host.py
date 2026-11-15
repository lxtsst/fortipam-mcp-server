"""Actual OAuth/MCP host scope and opt-in boundaries with synthetic device evidence."""
from __future__ import annotations

import json
import pytest
from starlette.testclient import TestClient

from fortipam_mcp import isolated_folder_policy_transition_mcp_action as action_module
from fortipam_mcp.http_server import HttpConfigurationError, HttpServerSettings, create_http_app
from fortipam_mcp.isolated_folder_policy_transition_contract import IsolatedFolderPolicyTransitionReadback
from fortipam_mcp.isolated_folder_policy_transition_live_workflow import IsolatedFolderPolicyTransitionLiveWorkflow
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers
from test_isolated_folder_policy_transition_live_workflow import inspection


def test_explicit_transition_requires_controlled_profile_and_exact_action(tmp_path):
    env = _v4_environment(tmp_path)
    with pytest.raises(HttpConfigurationError, match="controlled OAuth"):
        create_http_app(HttpServerSettings.from_environment(env), v4_isolated_folder_policy_transition_candidate_action=object())
    env[RUNTIME_PROFILE_ENV] = "v4-controlled"
    with pytest.raises(action_module.IsolatedFolderPolicyTransitionMcpActionError):
        create_http_app(HttpServerSettings.from_environment(env), v4_isolated_folder_policy_transition_candidate_action=object())


@pytest.mark.parametrize("operate,gate", ((False, True), (True, False), (True, True)))
def test_actual_http_oauth_operation_scope_gate_same_creator_and_separate_restore(tmp_path, monkeypatch, operate, gate):
    env = _v4_environment(tmp_path / "oauth")
    env[RUNTIME_PROFILE_ENV] = "v4-controlled"
    creator = []
    requester = action_module._requester
    def bound_requester(principal):
        value = requester(principal)
        if not creator: creator.append(value)
        return value
    monkeypatch.setattr(action_module, "_requester", bound_requester)

    class Transport:
        phase = "inherited"
        writes = 0
        def inspect_transition(self): return inspection(self.phase, creator=creator[0])
        def inspect_owned_restore(self): return self.inspect_transition()
        def transition_and_readback(self, digest, *, expires_at, clock): return self.dispatch(digest, "explicit")
        def restore_and_readback(self, digest, *, expires_at, clock): return self.dispatch(digest, "inherited")
        def dispatch(self, digest, phase):
            assert digest == self.inspect_transition().state_digest
            self.writes += 1; self.phase = phase
            return IsolatedFolderPolicyTransitionReadback(True, True, self.inspect_transition())

    transport = Transport()
    workflow = IsolatedFolderPolicyTransitionLiveWorkflow(transport, execution_enabled=True)
    action = action_module.IsolatedFolderPolicyTransitionMcpAction(workflow, execution_enabled=gate)
    app = create_http_app(HttpServerSettings.from_environment(env), v4_isolated_folder_policy_transition_candidate_action=action)
    scope = "fortipam:read fortipam:plan" + (" fortipam:operate" if operate else "")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token = client.post("/fpamcp/oauth/token", data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
            "resource": "https://mcp.example.com/fpamcp"})
        assert token.status_code == 200
        headers = _request_headers(token.json()["access_token"]); headers["host"] = "mcp.example.com"
        def call(name, arguments):
            response = client.post("/fpamcp", headers=headers, json={"jsonrpc": "2.0", "id": name,
                "method": "tools/call", "params": {"name": name, "arguments": arguments}})
            assert response.status_code == 200
            return response.json()["result"]
        marker = "SYNTHETIC_PRIVATE_UNKNOWN_SELECTOR"
        extra = call("preview_v4_isolated_folder_policy_transition_700", {"folder_id": marker})
        assert extra["isError"] and marker not in json.dumps(extra) and not creator
        results = []
        for suffix in ("", "_restore"):
            base = "v4_isolated_folder_policy_transition" + suffix + "_700"
            preview = call("preview_" + base, {})
            assert not preview["isError"]
            confirmed = call("confirm_" + base, {"preview_ref": preview["structuredContent"]["preview_ref"]})
            if not operate:
                assert confirmed["isError"] and transport.writes == 0
                return
            assert not confirmed["isError"]
            execution = call("execute_confirmed_" + base, {"authorization_ref": confirmed["structuredContent"]["authorization_ref"]})
            if not gate:
                assert execution["isError"] and transport.writes == 0
                return
            assert not execution["isError"] and execution["structuredContent"]["outcome"] == "succeeded"
            results.extend((preview, confirmed, execution))
        assert transport.writes == 2 and transport.phase == "inherited"
        for private in ("SYNTHETIC_SERIAL", "Synthetic Fixed Policy", "Synthetic Isolated Folder", "synthetic-owner"):
            assert private not in json.dumps(results)
