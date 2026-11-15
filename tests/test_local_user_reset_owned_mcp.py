"""Actual requester, persistent M4 and HTTP/OAuth boundaries; product IO synthetic."""
from dataclasses import replace
import json

import pytest
from v4_planning import AuthenticatedRequester

from fortipam_mcp.local_user_reset_owned_mcp import LocalResetOwnedMcpAction,LocalResetOwnedMcpError,CONTRACT,LOGIN_CONTRACT,TOOLS
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_local_user_reset_owned_material import Harness
from test_local_user_reset_owned_adapter import Native
from test_local_user_reset_fixture_custody import NAME,SERIAL


def prepare(root,monkeypatch,*,enabled=True,fault=None,verify_login=False):
    h=Harness(root,monkeypatch,verify_login=verify_login);h.stage()
    if not enabled:h.material.close();h.material=h.reopen(enabled=False)
    native=Native(h,fault=fault)
    login_args={}
    if verify_login:
        from test_local_user_reset_owned_login import LoginPeer
        login_args["login_client_factory"]=LoginPeer(h).factory
    action=LocalResetOwnedMcpAction(h.material,authority_key=b"j"*32,environment_ref="owned-reset-mcp-environment",
        scope_ref="owned-reset-mcp-scope",audience_ref="owned-reset-mcp-audience",transport_digest="c"*64,
        execution_enabled=enabled,clock=lambda:h.now,connection_factory=native.factory,**login_args)
    principal=V4PlanningPrincipal(AuthenticatedRequester("owned-reset-operator-0001","operator"),"b"*64)
    return h,native,action,principal


def authorize(action,principal):
    preview=action.preview(principal)
    result=action.authorize(preview["preview_ref"],principal)
    return preview,result


def test_requester_bound_rest_execution_and_terminal_cache_do_not_reload_material(tmp_path,monkeypatch):
    h,native,action,principal=prepare(tmp_path,monkeypatch)
    preview,issued=authorize(action,principal)
    assert preview["can_authorize"] and issued["policy_mode"]=="lab_auto"
    repeated_preview=action.preview(principal)
    assert repeated_preview["preview_ref"]==preview["preview_ref"] and repeated_preview["state"]=="authorized"
    repeated_auth=action.authorize(preview["preview_ref"],principal)
    assert repeated_auth==issued
    result=action.execute(issued["authorization_ref"],principal)
    assert result["outcome"]=="succeeded" and result["backend_change_acknowledged"] is True
    assert result["complete_nonmaterial_state_preserved"] is True and result["authentication_verified"] is False
    assert len(native.calls)==2 and h.store.claim_count==1
    unavailable=action.preview(principal)
    assert unavailable["state"]=="not_ready" and "Current State" not in unavailable
    h.now=5000
    assert action.execute(issued["authorization_ref"],principal)=={**result,"idempotent_replay":True}
    assert len(native.calls)==2 and h.store.claim_count==1
    serialized=json.dumps((preview,issued,result))
    for private in (NAME,SERIAL,"synthetic-owner","synthetic-token",str(tmp_path),"initial-password","next-password"):
        assert private not in serialized
    action.close()
    assert not action._enabled and not h.material._enabled and h.inspector._sources._closed


@pytest.mark.parametrize("phase",["authorize","execute"])
@pytest.mark.parametrize("identity",["requester","transport"])
def test_foreign_identity_cannot_transfer_references_before_product_io(tmp_path,monkeypatch,phase,identity):
    h,native,action,principal=prepare(tmp_path,monkeypatch)
    preview=action.preview(principal)
    ref=preview["preview_ref"]
    if phase=="execute":ref=action.authorize(ref,principal)["authorization_ref"]
    foreign=(replace(principal,requester=AuthenticatedRequester("foreign-operator-0002","operator")) if identity=="requester"
        else replace(principal,transport_namespace_digest="f"*64))
    reads=len(h.h.network.calls)+len(h.h.network.http_calls)
    with pytest.raises(LocalResetOwnedMcpError):getattr(action,phase)(ref,foreign)
    assert len(h.h.network.calls)+len(h.h.network.http_calls)==reads and not native.calls and h.store.claim_count==0


@pytest.mark.parametrize("phase",["authorize","execute"])
def test_expired_refs_and_unrecognized_inputs_cannot_dispatch(tmp_path,monkeypatch,phase):
    h,native,action,principal=prepare(tmp_path,monkeypatch);preview=action.preview(principal);ref=preview["preview_ref"]
    if phase=="execute":ref=action.authorize(ref,principal)["authorization_ref"]
    h.now=preview["expires_at"]
    with pytest.raises(LocalResetOwnedMcpError):getattr(action,phase)(ref,principal)
    with pytest.raises(LocalResetOwnedMcpError):getattr(action,phase)("SENSITIVE_INPUT",principal)
    assert not native.calls and h.store.claim_count==0


def test_readonly_preview_never_enables_material_or_authority(tmp_path,monkeypatch):
    h,native,action,principal=prepare(tmp_path,monkeypatch,enabled=False)
    preview=action.preview(principal)
    assert preview["state"]=="previewed" and not preview["can_authorize"] and "preview_ref" not in preview
    assert not h.material._enabled and not action._records
    with pytest.raises(LocalResetOwnedMcpError):action.authorize("owned-reset-preview-"+"a"*48,principal)
    assert not native.calls and h.store.claim_count==0


def test_unknown_preserves_acknowledged_change_without_claiming_complete_metadata(tmp_path,monkeypatch):
    h,native,action,principal=prepare(tmp_path,monkeypatch,fault="metadata");_,issued=authorize(action,principal)
    result=action.execute(issued["authorization_ref"],principal)
    assert result["outcome"]=="reconciliation_required" and result["verification"]=="unknown"
    assert result["backend_change_acknowledged"] is True and result["complete_nonmaterial_state_preserved"] is None
    assert len(native.calls)==2 and h.store.claim_count==1
    assert action.execute(issued["authorization_ref"],principal)["idempotent_replay"]
    assert len(native.calls)==2 and not action.preview(principal)["can_authorize"]


def test_reservation_verifier_failure_is_not_fabricated_as_a_terminal_store_result(tmp_path,monkeypatch):
    h,native,action,principal=prepare(tmp_path,monkeypatch);_,issued=authorize(action,principal)
    record=next(iter(action._records.values()))
    def fail(*args,**kwargs):raise ValueError("SYNTHETIC_PRIVATE_ERROR")
    monkeypatch.setattr(record.authority,"verify",fail)
    result=action.execute(issued["authorization_ref"],principal)
    assert result["outcome"]=="reconciliation_required" and result["backend_change_acknowledged"] is None
    assert not native.calls and h.store.claim_count==1 and not h.material._consumed
    assert "SYNTHETIC_PRIVATE_ERROR" not in json.dumps(result)
    assert action.execute(issued["authorization_ref"],principal)["idempotent_replay"]


@pytest.mark.parametrize("operate",[False,True])
@pytest.mark.parametrize("verify_login",[False,True])
def test_normal_http_oauth_mcp_enforces_operate_scope_and_strict_private_schema(tmp_path,monkeypatch,operate,verify_login):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings,create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment,_register_public_client,_authorize_and_login,_request_headers
    h,native,action,_=prepare(tmp_path,monkeypatch,verify_login=verify_login)
    env=_v4_environment(tmp_path/"oauth");env[RUNTIME_PROFILE_ENV]="v4-controlled"
    app=create_http_app(HttpServerSettings.from_environment(env),v4_local_user_reset_owned_action=action)
    scope="fortipam:read fortipam:plan"+(" fortipam:operate" if operate else "")
    with TestClient(app,base_url="https://mcp.example.com") as client:
        client_id=_register_public_client(client,scope);code,verifier=_authorize_and_login(client,client_id,scope)
        token=client.post("/fpamcp/oauth/token",data={"grant_type":"authorization_code","client_id":client_id,"code":code,
            "code_verifier":verifier,"redirect_uri":"https://client.example/callback","resource":"https://mcp.example.com/fpamcp"})
        assert token.status_code==200
        headers=_request_headers(token.json()["access_token"]);headers["host"]="mcp.example.com"
        def request(method,params,request_headers=None):
            response=client.post("/fpamcp",headers=headers if request_headers is None else request_headers,
                json={"jsonrpc":"2.0","id":"owned-request","method":method,"params":params})
            assert response.status_code==200
            return response.json()["result"]
        def call(name,args):return request("tools/call",{"name":name,"arguments":args})
        schemas={tool["name"]:tool["inputSchema"] for tool in request("tools/list",{})["tools"]}
        assert all(name in schemas and schemas[name]["additionalProperties"] is False for name in TOOLS)
        assert schemas[TOOLS[0]]["properties"]=={} and set(schemas[TOOLS[1]]["properties"])=={"preview_ref"}
        assert set(schemas[TOOLS[2]]["properties"])=={"authorization_ref"}
        assert call(TOOLS[0],{"username":"CALLER_PRIVATE_SELECTOR"})["isError"] and not native.calls
        preview=call(TOOLS[0],{})["structuredContent"]
        assert preview["contract"]==(LOGIN_CONTRACT if verify_login else CONTRACT) and preview["can_authorize"]
        auth=call(TOOLS[1],{"preview_ref":preview["preview_ref"]})
        if not operate:
            assert auth["isError"] and not native.calls and h.store.claim_count==0
        else:
            assert not auth.get("isError",False)
            other_client=_register_public_client(client,scope)
            other_code,other_verifier=_authorize_and_login(client,other_client,scope)
            other_token=client.post("/fpamcp/oauth/token",data={"grant_type":"authorization_code","client_id":other_client,
                "code":other_code,"code_verifier":other_verifier,"redirect_uri":"https://client.example/callback",
                "resource":"https://mcp.example.com/fpamcp"})
            other_headers=_request_headers(other_token.json()["access_token"]);other_headers["host"]="mcp.example.com"
            transferred=request("tools/call",{"name":TOOLS[2],"arguments":{"authorization_ref":auth["structuredContent"]["authorization_ref"]}},other_headers)
            assert transferred["isError"] and not native.calls and h.store.claim_count==0
            result=call(TOOLS[2],{"authorization_ref":auth["structuredContent"]["authorization_ref"]})
            assert result["structuredContent"]["outcome"]=="succeeded" and len(native.calls)==2 and h.store.claim_count==1
            assert result["structuredContent"]["authentication_verified"] is verify_login
            assert NAME not in json.dumps(result) and "synthetic-token" not in json.dumps(result)
            repeated=call(TOOLS[2],{"authorization_ref":auth["structuredContent"]["authorization_ref"]})
            assert repeated["structuredContent"]["idempotent_replay"] and len(native.calls)==2
    assert action._closed and not h.material._enabled and h.inspector._sources._closed


def test_http_host_refuses_wrong_profile_type_or_legacy_shared_binding(tmp_path,monkeypatch):
    from fortipam_mcp.http_server import HttpConfigurationError,HttpServerSettings,create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment
    env=_v4_environment(tmp_path/"oauth")
    with pytest.raises(HttpConfigurationError):create_http_app(HttpServerSettings.from_environment(env),v4_local_user_reset_owned_action=object())
    env[RUNTIME_PROFILE_ENV]="v4-controlled"
    with pytest.raises(HttpConfigurationError):create_http_app(HttpServerSettings.from_environment(env),v4_local_user_reset_owned_action=object())
    _,_,action,_=prepare(tmp_path,monkeypatch)
    with pytest.raises(HttpConfigurationError):create_http_app(HttpServerSettings.from_environment(env),
        v4_local_user_reset_owned_action=action,v4_local_user_reset_candidate_action=object())


@pytest.mark.parametrize("fail",[False,True])
def test_normal_main_injects_the_owned_builder_and_closes_on_serve_or_configuration_failure(tmp_path,monkeypatch,fail):
    import os
    import uvicorn
    from fortipam_mcp import http_server
    from fortipam_mcp import local_user_reset_owned_runtime as runtime
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment
    h,_,action,_=prepare(tmp_path,monkeypatch)
    env=_v4_environment(tmp_path/"oauth");env[RUNTIME_PROFILE_ENV]="v4-controlled"
    monkeypatch.setattr(os,"environ",env);monkeypatch.setattr(http_server,"load_http_runtime_environment",lambda:False)
    monkeypatch.setattr(runtime,"build_local_reset_owned_candidate",lambda _:action)
    def create(settings,**components):
        assert components["v4_local_user_reset_owned_action"] is action
        if fail:raise http_server.HttpConfigurationError("Synthetic configuration refusal.")
        return object()
    async def serve(self,sockets=None):pass
    monkeypatch.setattr(http_server,"create_http_app",create);monkeypatch.setattr(uvicorn.Server,"serve",serve)
    if fail:
        with pytest.raises(SystemExit):http_server.main()
    else:http_server.main()
    assert action._closed and not h.material._enabled and h.inspector._sources._closed


def test_http_environment_file_loads_only_owned_runtime_flags_and_reference(tmp_path,monkeypatch):
    import os
    from fortipam_mcp import http_server
    from fortipam_mcp.local_user_reset_owned_runtime import PREFIX
    path=tmp_path/"runtime.env";path.write_text(PREFIX+"ENABLED=true\n"+PREFIX+"EXECUTION_ENABLED=false\n"+PREFIX+"DESCRIPTOR_FILE=/synthetic/owned.json\n");path.chmod(0o600)
    monkeypatch.setattr(os,"environ",{http_server.HTTP_ENV_FILE_VARIABLE:str(path)})
    assert http_server.load_http_runtime_environment()
    assert os.environ[PREFIX+"ENABLED"]=="true" and os.environ[PREFIX+"EXECUTION_ENABLED"]=="false"
    assert os.environ[PREFIX+"DESCRIPTOR_FILE"]=="/synthetic/owned.json"
