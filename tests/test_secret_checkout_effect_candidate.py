"""OAuth authority and fixed default-off native Checkout effect boundary."""
import json
from types import SimpleNamespace
import pytest
from fortipam_mcp.secret_checkout_effect_http_transport import SecretCheckoutEffectHttpTransport, SecretCheckoutEffectReadback
from fortipam_mcp.secret_checkout_effect_live_workflow import SecretCheckoutEffectLiveWorkflow
from fortipam_mcp.secret_checkout_effect_mcp_action import SecretCheckoutEffectMcpAction, build_secret_checkout_effect_candidate, PREFIX
from test_secret_checkout_effect_live_workflow import BINDING, CURRENT

class WorkflowTransport(SecretCheckoutEffectHttpTransport):
    def __init__(self):
        self._binding=BINDING;self._operation="checkout"
        self._reader=SimpleNamespace(_retained_account=None);self.writes=0
    def inspect(self): return CURRENT
    def execute_and_readback(self,expected):
        self.writes+=1
        return SecretCheckoutEffectReadback(True,True,True,True,True,True,True)

def workflow_factory(tmp_path, transport):
    tmp_path.mkdir(mode=0o700,exist_ok=True);tmp_path.chmod(0o700)
    key=tmp_path/"key";key.write_bytes(b"k"*32);key.chmod(0o600)
    return lambda:SecretCheckoutEffectLiveWorkflow(tmp_path/"ledger",key,transport,BINDING,operation="checkout")

def test_builder_default_off_and_invalid_gate_never_loads_provider():
    assert build_secret_checkout_effect_candidate({}) is None
    for environment in ({PREFIX+"EXECUTION_ENABLED":"true"}, {PREFIX+"ENABLED":"yes"}, {PREFIX+"ENABLED":"true"}):
        with pytest.raises(ValueError):build_secret_checkout_effect_candidate(environment)

@pytest.mark.parametrize("operate,gate", [(False, True), (True, False), (True, True)])
def test_http_oauth_authorizes_one_private_bound_mcp_write(tmp_path, operate, gate):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers

    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    transport = WorkflowTransport()
    action = SecretCheckoutEffectMcpAction(workflow_factory(tmp_path, transport)(), execution_enabled=gate)
    app = create_http_app(HttpServerSettings.from_environment(environment),
                          v4_secret_checkout_effect_candidate_action=action)
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

        preview = call("preview_v4_secret_checkout_effect_700", {})
        assert not preview["isError"]
        assert BINDING.secret_name not in json.dumps(preview)
        confirmation = call("confirm_v4_secret_checkout_effect_700", {
            "preview_ref": preview["structuredContent"]["preview_ref"],
        })
        if not operate:
            assert confirmation["isError"] and transport.writes == 0
            return
        assert not confirmation["isError"]
        args = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_secret_checkout_effect_700", args)
        if not gate:
            assert result["isError"] and transport.writes == 0
            return
        assert not result["isError"] and result["structuredContent"]["outcome"] == "succeeded"
        assert call("execute_confirmed_v4_secret_checkout_effect_700", args)["structuredContent"]["idempotent_replay"]
        assert transport.writes == 1





def test_effect_candidate_requires_controlled_oauth_profile(tmp_path):
    from fortipam_mcp.http_server import HttpConfigurationError, HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment
    environment=_v4_environment(tmp_path/"oauth")
    environment[RUNTIME_PROFILE_ENV]="v4-plan-only"
    transport=WorkflowTransport()
    action=SecretCheckoutEffectMcpAction(workflow_factory(tmp_path/"workflow",transport)(), execution_enabled=False)
    with pytest.raises(HttpConfigurationError, match="Secret checkout effect candidate requires"):
        create_http_app(HttpServerSettings.from_environment(environment),v4_secret_checkout_effect_candidate_action=action)
    assert transport.writes==0
