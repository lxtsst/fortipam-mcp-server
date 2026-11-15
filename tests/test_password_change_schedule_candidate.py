"""Behavior coverage for persistent daily-change enable/disable candidates."""
from dataclasses import asdict, replace
import json
import sqlite3
import pytest
from fortipam_mcp.password_change_schedule_http_transport import (
    FortiPamPasswordChangeScheduleHttpTransport, PasswordChangeScheduleReadback,
)
from fortipam_mcp.password_change_schedule_live_workflow import (
    PasswordChangeScheduleLiveWorkflow, PasswordChangeScheduleLiveWorkflowError,
)
from fortipam_mcp.password_change_schedule_mcp_action import (
    PasswordChangeScheduleMcpAction, PREFIX, BINDING_CONTRACT,
    build_password_change_schedule_candidate, _load_binding,
)
from test_password_change_schedule_http_transport import BINDING, CURRENT
REQUESTER='b'*64
class WorkflowTransport(FortiPamPasswordChangeScheduleHttpTransport):
    def __init__(self, failure=None):
        self.state=CURRENT; self.failure=failure; self.writes=0
    def inspect(self):return self.state
    def enable_and_readback(self, expected):
        self.writes+=1
        if self.failure=='ambiguous':raise TimeoutError('synthetic-protected-detail')
        self.state=replace(CURRENT,enabled=True,frequency='day',start_epoch=1300)
        return PasswordChangeScheduleReadback(True,self.failure!='readback',True,True)
    def disable_and_readback(self,expected):
        self.writes+=1;self.state=CURRENT
        return PasswordChangeScheduleReadback(True,True,False,True)

def workflow_factory(tmp_path,transport,operation='enable'):
    tmp_path.mkdir(mode=0o700,exist_ok=True);tmp_path.chmod(0o700)
    key=tmp_path/'key'
    if not key.exists():key.write_bytes(b'a'*32);key.chmod(0o600)
    return lambda:PasswordChangeScheduleLiveWorkflow(tmp_path/'state.sqlite3',key,transport,BINDING,operation=operation,clock=lambda:1000)

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
    with pytest.raises(PasswordChangeScheduleLiveWorkflowError):factory().preview(requester_digest=REQUESTER)
    # Even a pre-existing independent preview cannot reserve a second dispatch.
    try:
        other=factory().confirm(previews[1]['preview_ref'],requester_digest=REQUESTER)
        factory().execute(other['authorization_ref'],requester_digest=REQUESTER)
    except PasswordChangeScheduleLiveWorkflowError:pass
    assert transport.writes==1


def test_disable_has_separate_bound_operation_and_durable_claim(tmp_path):
    transport=WorkflowTransport();enable=workflow_factory(tmp_path,transport)
    preview=enable().preview(requester_digest=REQUESTER)
    auth=enable().confirm(preview['preview_ref'],requester_digest=REQUESTER)
    assert enable().execute(auth['authorization_ref'],requester_digest=REQUESTER)['outcome']=='succeeded'
    disable=workflow_factory(tmp_path,transport,'disable')
    with pytest.raises(PasswordChangeScheduleLiveWorkflowError):disable().execute(auth['authorization_ref'],requester_digest=REQUESTER)
    preview=disable().preview(requester_digest=REQUESTER)
    assert preview['Expected State']['automatic_change_enabled'] is False
    auth=disable().confirm(preview['preview_ref'],requester_digest=REQUESTER)
    assert disable().execute(auth['authorization_ref'],requester_digest=REQUESTER)['outcome']=='succeeded'
    assert disable().execute(auth['authorization_ref'],requester_digest=REQUESTER)['idempotent_replay']
    assert transport.writes==2 and not transport.state.enabled


def test_record_tampering_and_requester_drift_are_rejected(tmp_path):
    transport=WorkflowTransport();factory=workflow_factory(tmp_path,transport)
    preview=factory().preview(requester_digest=REQUESTER)
    with pytest.raises(PasswordChangeScheduleLiveWorkflowError):factory().confirm(preview['preview_ref'],requester_digest='c'*64)
    with sqlite3.connect(tmp_path/'state.sqlite3') as connection:
        connection.execute("UPDATE password_change_schedule_workflow SET state='authorized'")
    with pytest.raises(PasswordChangeScheduleLiveWorkflowError):factory().confirm(preview['preview_ref'],requester_digest=REQUESTER)
    assert transport.writes==0


def test_default_off_and_private_binding_permissions(tmp_path):
    assert build_password_change_schedule_candidate({}) is None
    with pytest.raises(ValueError):build_password_change_schedule_candidate({PREFIX+'EXECUTION_ENABLED':'true'})
    path=tmp_path/'binding.json';path.write_text(json.dumps({'contract':BINDING_CONTRACT,**asdict(BINDING)}));path.chmod(0o600)
    assert _load_binding(path)==BINDING
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
    action = PasswordChangeScheduleMcpAction(workflow_factory(tmp_path, transport)(), execution_enabled=gate)
    app = create_http_app(HttpServerSettings.from_environment(environment),
                          v4_password_change_schedule_candidate_action=action)
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

        preview = call("preview_v4_password_change_schedule_700", {})
        assert not preview["isError"]
        assert BINDING.secret_name not in json.dumps(preview)
        confirmation = call("confirm_v4_password_change_schedule_700", {
            "preview_ref": preview["structuredContent"]["preview_ref"],
        })
        if not operate:
            assert confirmation["isError"] and transport.writes == 0
            return
        assert not confirmation["isError"]
        args = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_password_change_schedule_700", args)
        if not gate:
            assert result["isError"] and transport.writes == 0
            return
        assert not result["isError"] and result["structuredContent"]["outcome"] == "succeeded"
        assert call("execute_confirmed_v4_password_change_schedule_700", args)["structuredContent"]["idempotent_replay"]
        assert transport.writes == 1
