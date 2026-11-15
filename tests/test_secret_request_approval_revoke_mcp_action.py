"""Real HTTP/OAuth tool boundary; workflow semantics are tested separately."""
from types import MethodType
import pytest

from fortipam_mcp.secret_request_approval_revoke_live_workflow import SecretRequestApprovalRevokeLiveWorkflow
from fortipam_mcp.secret_request_approval_revoke_mcp_action import SecretRequestApprovalRevokeMcpAction


def _workflow():
    workflow = object.__new__(SecretRequestApprovalRevokeLiveWorkflow)
    calls = []
    def preview(self, **identity):
        calls.append(("preview", identity))
        return {"preview_ref": "synthetic-preview"}
    def authorize(self, reference, **identity):
        assert reference == "synthetic-preview"
        calls.append(("authorize", identity))
        return {"authorization_ref": "synthetic-authorization"}
    def execute(self, reference, **identity):
        assert reference == "synthetic-authorization"
        calls.append(("execute", identity))
        return {"outcome": "succeeded", "credential_values_returned": False}
    for name, method in (("preview", preview), ("authorize", authorize), ("execute", execute)):
        setattr(workflow, name, MethodType(method, workflow))
    return workflow, calls


@pytest.mark.parametrize("operate,gate", [(False, True), (True, False), (True, True)])
def test_real_oauth_scope_and_independent_execution_gate(tmp_path, operate, gate):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers
    env = _v4_environment(tmp_path / "oauth")
    env[RUNTIME_PROFILE_ENV] = "v4-controlled"
    workflow, calls = _workflow()
    action = SecretRequestApprovalRevokeMcpAction(workflow, execution_enabled=gate)
    app = create_http_app(HttpServerSettings.from_environment(env), v4_secret_request_approval_revoke_candidate_action=action)
    scope = "fortipam:read fortipam:plan" + (" fortipam:operate" if operate else "")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token = client.post("/fpamcp/oauth/token", data={"grant_type": "authorization_code", "client_id": client_id,
            "code": code, "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
            "resource": "https://mcp.example.com/fpamcp"})
        assert token.status_code == 200
        headers = _request_headers(token.json()["access_token"])
        headers["host"] = "mcp.example.com"
        def call(name, arguments):
            response = client.post("/fpamcp", headers=headers, json={"jsonrpc": "2.0", "id": name,
                "method": "tools/call", "params": {"name": name, "arguments": arguments}})
            assert response.status_code == 200
            return response.json()["result"]
        assert not call("preview_v4_secret_request_approval_revoke_700", {})["isError"]
        authorization = call("authorize_v4_secret_request_approval_revoke_700", {"preview_ref": "synthetic-preview"})
        if not operate:
            assert authorization["isError"] and [x[0] for x in calls] == ["preview"]
            return
        assert not authorization["isError"]
        outcome = call("execute_v4_secret_request_approval_revoke_700", {"authorization_ref": "synthetic-authorization"})
        assert outcome["isError"] is (not gate)
        assert [x[0] for x in calls] == (["preview", "authorize", "execute"] if gate else ["preview", "authorize"])
        assert all(identity == calls[0][1] for _, identity in calls)
        assert all(len(value) == 64 for value in calls[0][1].values())


def test_injection_requires_controlled_profile(tmp_path):
    from fortipam_mcp.http_server import HttpServerSettings, HttpConfigurationError, create_http_app
    from test_http_server import _v4_environment
    workflow, _ = _workflow()
    with pytest.raises(HttpConfigurationError):
        create_http_app(HttpServerSettings.from_environment(_v4_environment(tmp_path / "oauth")),
            v4_secret_request_approval_revoke_candidate_action=SecretRequestApprovalRevokeMcpAction(workflow))
