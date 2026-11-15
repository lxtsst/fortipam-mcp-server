"""Durable description transactions and authenticated MCP boundary behavior."""
from dataclasses import asdict, replace
import json
import sqlite3
import pytest
from fortipam_mcp.secret_description_update_http_transport import (
    FortiPamSecretDescriptionUpdateHttpTransport, SecretDescriptionReadback,
)
from fortipam_mcp.secret_description_update_live_workflow import (
    SecretDescriptionUpdateLiveWorkflow, SecretDescriptionUpdateLiveWorkflowError,
)
from fortipam_mcp.secret_description_update_mcp_action import (
    SecretDescriptionUpdateMcpAction, PREFIX, BINDING_CONTRACT,
    build_secret_description_update_candidate, _load_binding,
)
from fortipam_mcp.secret_description_update_http_transport import SecretDescriptionBinding, SecretDescriptionInspection
BINDING = SecretDescriptionBinding("synthetic-owner", "Public/fixture", "mcp-v4-secret-metadata-update-r3", "synthetic-target", "Unix Account (SSH Password)", "192.0.2.1")
CURRENT = SecretDescriptionInspection(23, 17, "Before", "d" * 64)
DESCRIPTION = "After"
REQUESTER='b'*64
class WorkflowTransport(FortiPamSecretDescriptionUpdateHttpTransport):
    def __init__(self, failure=None):
        self.state=CURRENT; self.failure=failure; self.writes=0
        self._binding=BINDING; self._description=DESCRIPTION
        self._retained_account=lambda:"synthetic-account"
    def inspect(self):return self.state
    def update_and_readback(self, expected):
        self.writes+=1
        if self.failure=='ambiguous':raise TimeoutError('synthetic-protected-detail')
        self.state=replace(CURRENT,description=DESCRIPTION)
        return SecretDescriptionReadback(True,True,self.failure!='readback',True,False,200,True)

def workflow_factory(tmp_path,transport,clock=lambda:1000):
    tmp_path.mkdir(mode=0o700,exist_ok=True);tmp_path.chmod(0o700)
    key=tmp_path/'key'
    if not key.exists():key.write_bytes(b'a'*32);key.chmod(0o600)
    return lambda:SecretDescriptionUpdateLiveWorkflow(tmp_path/'state.sqlite3',key,transport,BINDING,description=DESCRIPTION,clock=clock)

@pytest.mark.parametrize('failure',[None,'ambiguous','readback'])
def test_restart_and_multiple_previews_never_repeat_dispatch(tmp_path,failure):
    transport=WorkflowTransport(failure);factory=workflow_factory(tmp_path,transport)
    previews=[factory().preview(requester_digest=REQUESTER) for _ in range(2)]
    assert BINDING.secret_name not in json.dumps(previews)
    authorization=factory().confirm(previews[0]['preview_ref'],requester_digest=REQUESTER)
    result=factory().execute(authorization['authorization_ref'],requester_digest=REQUESTER)
    assert result['outcome']==('succeeded' if failure is None else 'reconciliation_required')
    replay=factory().execute(authorization['authorization_ref'],requester_digest=REQUESTER)
    assert replay['idempotent_replay'] and replay['outcome']==result['outcome']
    assert transport.writes==1
    with pytest.raises(SecretDescriptionUpdateLiveWorkflowError):factory().preview(requester_digest=REQUESTER)
    # Even a pre-existing independent preview cannot reserve a second dispatch.
    try:
        other=factory().confirm(previews[1]['preview_ref'],requester_digest=REQUESTER)
        factory().execute(other['authorization_ref'],requester_digest=REQUESTER)
    except SecretDescriptionUpdateLiveWorkflowError:pass
    assert transport.writes==1


@pytest.mark.parametrize("mode", ["drift", "expired", "binding_drift"])
def test_stale_or_rebound_authorization_never_dispatches(tmp_path,mode):
    transport=WorkflowTransport();factory=workflow_factory(tmp_path,transport)
    preview=factory().preview(requester_digest=REQUESTER)
    auth=factory().confirm(preview['preview_ref'],requester_digest=REQUESTER)
    if mode=='drift':transport.state=replace(CURRENT,preserved_metadata_digest='e'*64)
    elif mode=='expired':factory=workflow_factory(tmp_path,transport,clock=lambda:1600)
    else:
        transport._description='Different'
        with pytest.raises(SecretDescriptionUpdateLiveWorkflowError):factory()
        assert transport.writes==0
        return
    try:
        result=factory().execute(auth['authorization_ref'],requester_digest=REQUESTER)
        assert result['outcome']=='not_executed'
    except SecretDescriptionUpdateLiveWorkflowError:
        assert mode=='expired'
    assert transport.writes==0


def test_record_tampering_and_requester_drift_are_rejected(tmp_path):
    transport=WorkflowTransport();factory=workflow_factory(tmp_path,transport)
    preview=factory().preview(requester_digest=REQUESTER)
    with pytest.raises(SecretDescriptionUpdateLiveWorkflowError):factory().confirm(preview['preview_ref'],requester_digest='c'*64)
    with sqlite3.connect(tmp_path/'state.sqlite3') as connection:
        connection.execute("UPDATE secret_description_update_workflow SET state='authorized'")
    with pytest.raises(SecretDescriptionUpdateLiveWorkflowError):factory().confirm(preview['preview_ref'],requester_digest=REQUESTER)
    assert transport.writes==0


def test_default_off_and_private_binding_permissions(tmp_path):
    assert build_secret_description_update_candidate({}) is None
    with pytest.raises(ValueError):build_secret_description_update_candidate({PREFIX+'EXECUTION_ENABLED':'true'})
    path=tmp_path/'binding.json';path.write_text(json.dumps({'contract':BINDING_CONTRACT,**asdict(BINDING),'account_name':'synthetic-account','description':DESCRIPTION}));path.chmod(0o600)
    assert _load_binding(path)==(BINDING,DESCRIPTION,"synthetic-account")
    path.chmod(0o644)
    with pytest.raises(ValueError):_load_binding(path)

@pytest.mark.parametrize("operate,gate", [(False, True), (True, False), (True, True)])
def test_http_oauth_authorizes_one_private_bound_mcp_write(tmp_path, operate, gate):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers

    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    transport = WorkflowTransport()
    action = SecretDescriptionUpdateMcpAction(workflow_factory(tmp_path, transport)(), execution_enabled=gate)
    app = create_http_app(HttpServerSettings.from_environment(environment),
                          v4_secret_description_update_candidate_action=action)
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

        preview = call("preview_v4_secret_description_update_700", {})
        assert not preview["isError"]
        assert BINDING.secret_name not in json.dumps(preview)
        confirmation = call("confirm_v4_secret_description_update_700", {
            "preview_ref": preview["structuredContent"]["preview_ref"],
        })
        if not operate:
            assert confirmation["isError"] and transport.writes == 0
            return
        assert not confirmation["isError"]
        args = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_secret_description_update_700", args)
        if not gate:
            assert result["isError"] and transport.writes == 0
            return
        assert not result["isError"] and result["structuredContent"]["outcome"] == "succeeded"
        assert call("execute_confirmed_v4_secret_description_update_700", args)["structuredContent"]["idempotent_replay"]
        assert transport.writes == 1
