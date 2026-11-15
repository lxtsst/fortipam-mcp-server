"""Synthetic workflow behind the real HTTP/OAuth RADIUS lifecycle tool boundary."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from dataclasses import replace
import json
import os
from pathlib import Path
import pickle
from typing import Any, cast

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import HttpConfigurationError, HttpServerSettings, create_http_app
from fortipam_mcp.radius_server_lifecycle_workflow import RadiusServerLifecycleWorkflow
from fortipam_mcp.radius_server_lifecycle_mcp_action import RadiusServerLifecycleMcpAction
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from v4_planning.material_provider import MaterialAccessDenied
from v4_planning.models import AuthenticatedRequester

from test_http_server import (
    _authorize_and_login,
    _register_public_client,
    _request_headers,
    _v4_environment,
)

_PREVIEW = "preview_v4_radius_primary_lifecycle_700"
_AUTHORIZE = "authorize_v4_radius_primary_lifecycle_700"
_EXECUTE = "execute_v4_radius_primary_lifecycle_700"
_TOOLS = {_PREVIEW, _AUTHORIZE, _EXECUTE}
_ERROR = "FortiPAM RADIUS lifecycle is unavailable."
Call = tuple[str, dict[str, str]]


def _workflow(monkeypatch: pytest.MonkeyPatch) -> tuple[RadiusServerLifecycleWorkflow, list[Call]]:
    calls: list[Call] = []

    def preview(self: RadiusServerLifecycleWorkflow, **identity: str) -> dict[str, object]:
        calls.append(("preview", identity))
        return {"preview_ref": "synthetic-preview"}

    def authorize(self: RadiusServerLifecycleWorkflow, reference: str, **identity: str) -> dict[str, object]:
        assert reference == "synthetic-preview"
        calls.append(("authorize", identity))
        return {"authorization_ref": "synthetic-authorization"}

    def execute(self: RadiusServerLifecycleWorkflow, reference: str, **identity: str) -> dict[str, object]:
        assert reference == "synthetic-authorization"
        calls.append(("execute", identity))
        return {"outcome": "succeeded", "verification": "verified"}

    monkeypatch.setattr(RadiusServerLifecycleWorkflow, "close", lambda self: None)
    monkeypatch.setattr(RadiusServerLifecycleWorkflow, "preview", preview)
    monkeypatch.setattr(RadiusServerLifecycleWorkflow, "authorize", authorize)
    monkeypatch.setattr(RadiusServerLifecycleWorkflow, "execute", execute)
    return object.__new__(RadiusServerLifecycleWorkflow), calls


def _settings(tmp_path: Path) -> HttpServerSettings:
    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    return HttpServerSettings.from_environment(environment)


def _login(client: TestClient, scope: str) -> dict[str, str]:
    client_id = _register_public_client(client, scope)
    code, verifier = _authorize_and_login(client, client_id, scope)
    response = client.post("/fpamcp/oauth/token", data={
        "grant_type": "authorization_code", "client_id": client_id, "code": code,
        "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
        "resource": "https://mcp.example.com/fpamcp",
    })
    assert response.status_code == 200
    headers = _request_headers(str(response.json()["access_token"]))
    headers["host"] = "mcp.example.com"
    return headers


def _call(client: TestClient, headers: dict[str, str], name: str,
          arguments: Mapping[str, object]) -> dict[str, Any]:
    response = client.post("/fpamcp", headers=headers, json={
        "jsonrpc": "2.0", "id": name, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    assert response.status_code == 200
    return cast(dict[str, Any], response.json()["result"])


@pytest.mark.parametrize("plan,operate,gate", [
    (False, False, True), (True, False, True), (True, True, False), (True, True, True),
])
def test_real_oauth_scopes_and_independent_execution_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, plan: bool, operate: bool, gate: bool,
) -> None:
    workflow, calls = _workflow(monkeypatch)
    action = RadiusServerLifecycleMcpAction(workflow, execution_enabled=gate)
    app = create_http_app(_settings(tmp_path), v4_radius_server_lifecycle_candidate_action=action)
    scope = "fortipam:read" + (" fortipam:plan" if plan else "") + (" fortipam:operate" if operate else "")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        headers = _login(client, scope)
        preview = _call(client, headers, _PREVIEW, {})
        assert preview["isError"] is (not plan)
        if not plan:
            assert calls == []
            return
        authorization = _call(client, headers, _AUTHORIZE, {"preview_ref": "synthetic-preview"})
        assert authorization["isError"] is (not operate)
        execution = _call(client, headers, _EXECUTE, {"authorization_ref": "synthetic-authorization"})
        assert execution["isError"] is (not operate or not gate)
        assert [name for name, _ in calls] == (
            ["preview", "authorize", "execute"] if operate and gate
            else ["preview", "authorize"] if operate else ["preview"]
        )
        assert all(identity == calls[0][1] for _, identity in calls)
        assert set(calls[0][1]) == {"requester_digest", "transport_digest"}
        assert all(len(value) == 64 for value in calls[0][1].values())


def test_default_host_keeps_plan_only_tool_without_ldap_mutation_tools(tmp_path: Path) -> None:
    app = create_http_app(_settings(tmp_path))
    with TestClient(app, base_url="https://mcp.example.com") as client:
        headers = _login(client, "fortipam:read fortipam:plan")
        response = client.post("/fpamcp", headers=headers, json={
            "jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {},
        })
        assert response.status_code == 200
        names = {tool["name"] for tool in response.json()["result"]["tools"]}
        assert "get_v4_radius_server_plan_requirements" in names
        assert not names.intersection(_TOOLS)
        assert not any('radius_primary_configure' in name or 'radius_primary_remove' in name for name in names)


@pytest.mark.parametrize("invalid", ["profile", "auth", "authority", "type"])
def test_injection_requires_exact_action_and_controlled_oauth_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str,
) -> None:
    workflow, calls = _workflow(monkeypatch)
    action: object = RadiusServerLifecycleMcpAction(workflow)
    settings = _settings(tmp_path)
    if invalid == "profile":
        from fortipam_mcp.runtime_profile import RuntimeProfile
        settings = replace(settings, runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid == "auth":
        settings = replace(settings, auth_mode="bearer", bearer_token="synthetic-token")
    elif invalid == "authority":
        settings = replace(settings, v4_planning_authorization=None)
    else:
        action = object()
    with pytest.raises(HttpConfigurationError):
        create_http_app(settings, v4_radius_server_lifecycle_candidate_action=action)
    assert calls == []


def test_real_http_rejects_caller_binding_and_material_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, calls = _workflow(monkeypatch)
    app = create_http_app(_settings(tmp_path),
        v4_radius_server_lifecycle_candidate_action=RadiusServerLifecycleMcpAction(workflow, execution_enabled=True))
    with TestClient(app, base_url="https://mcp.example.com") as client:
        headers = _login(client, "fortipam:read fortipam:plan fortipam:operate")
        for name, arguments in (
            (_PREVIEW, {"binding": "synthetic-private-marker"}),
            (_AUTHORIZE, {"preview_ref": "synthetic-preview", "password": "synthetic-private-marker"}),
            (_EXECUTE, {"authorization_ref": "synthetic-authorization", "path": "synthetic-private-marker"}),
        ):
            result = _call(client, headers, name, arguments)
            assert result["isError"]
            assert "synthetic-private-marker" not in json.dumps(result)
        assert calls == []


@pytest.mark.parametrize('operate,gate',[(False,True),(True,False),(True,True)])
def test_independent_remove_tools_require_operation_scope_and_gate(
        tmp_path: Path,monkeypatch: pytest.MonkeyPatch,operate: bool,gate: bool) -> None:
    workflow,calls=_workflow(monkeypatch)
    workflow._retain_on_success=True
    for target,original in (('preview_removal','preview'),('authorize_removal','authorize'),
                            ('execute_removal','execute')):
        monkeypatch.setattr(RadiusServerLifecycleWorkflow,target,getattr(RadiusServerLifecycleWorkflow,original))
    action=RadiusServerLifecycleMcpAction(workflow,execution_enabled=gate,persistent_primary=True)
    with TestClient(create_http_app(_settings(tmp_path),v4_radius_server_lifecycle_candidate_action=action),
            base_url='https://mcp.example.com') as client:
        scope='fortipam:read fortipam:plan'+(' fortipam:operate' if operate else '')
        headers=_login(client,scope)
        p=_call(client,headers,'preview_v4_radius_primary_remove_700',{})
        assert not p['isError']
        a=_call(client,headers,'authorize_v4_radius_primary_remove_700',{'preview_ref':'synthetic-preview'})
        assert a['isError'] is (not operate)
        result=_call(client,headers,'execute_v4_radius_primary_remove_700',{'authorization_ref':'synthetic-authorization'})
        assert result['isError'] is (not operate or not gate)
        extra=_call(client,headers,'execute_v4_radius_primary_remove_700',
            {'authorization_ref':'synthetic-authorization','selector':'synthetic-private-marker'})
        assert extra['isError'] and 'synthetic-private-marker' not in json.dumps(extra)
    assert [name for name,_ in calls]==(['preview','authorize','execute'] if operate and gate
        else ['preview','authorize'] if operate else ['preview'])


def test_action_is_opaque_immutable_and_requires_exact_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, calls = _workflow(monkeypatch)
    action = RadiusServerLifecycleMcpAction(workflow)
    assert repr(action) == str(action) == "<RadiusServerLifecycleMcpAction redacted>"
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(action)
    with pytest.raises(TypeError):
        json.dumps(action)
    with pytest.raises(ValueError, match=_ERROR):
        setattr(action, "_enabled", True)
    with pytest.raises(ValueError, match=_ERROR):
        delattr(action, "_workflow")
    invalid = cast(V4PlanningPrincipal, object())
    with pytest.raises(RuntimeError, match=_ERROR):
        action.preview(invalid)
    with pytest.raises(RuntimeError, match=_ERROR):
        action.authorize("synthetic-preview", invalid)
    principal = V4PlanningPrincipal(AuthenticatedRequester("synthetic-operator", "operator"), "a" * 64)
    with pytest.raises(RuntimeError, match=_ERROR):
        action.execute("synthetic-authorization", principal)
    with pytest.raises(ValueError, match=_ERROR):
        RadiusServerLifecycleMcpAction(workflow, execution_enabled=cast(bool, 1))
    assert calls == []


def test_workflow_failure_is_value_free(monkeypatch: pytest.MonkeyPatch) -> None:
    workflow, _ = _workflow(monkeypatch)

    def fail(self: RadiusServerLifecycleWorkflow, *args: object, **kwargs: str) -> dict[str, object]:
        raise ValueError("synthetic-private-marker")

    action = RadiusServerLifecycleMcpAction(workflow, execution_enabled=True)
    principal = V4PlanningPrincipal(AuthenticatedRequester("synthetic-operator", "operator"), "a" * 64)
    for method in ("preview", "authorize", "execute"):
        monkeypatch.setattr(RadiusServerLifecycleWorkflow, method, fail)
    callbacks: tuple[Callable[[], dict[str, object]], ...] = (
        lambda: action.preview(principal),
        lambda: action.authorize("synthetic-preview", principal),
        lambda: action.execute("synthetic-authorization", principal),
    )
    for callback in callbacks:
        with pytest.raises(RuntimeError) as failure:
            callback()
        assert str(failure.value) == _ERROR
        assert failure.value.__cause__ is None
        assert failure.value.__suppress_context__


def test_normal_main_injects_private_builder_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn
    from fortipam_mcp import http_server, radius_server_lifecycle_runtime

    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    workflow, _ = _workflow(monkeypatch)
    action = RadiusServerLifecycleMcpAction(workflow)
    captured: dict[str, object] = {}
    monkeypatch.setattr(os, "environ", environment)
    monkeypatch.setattr(http_server, "load_http_runtime_environment", lambda: False)

    def build(value: dict[str, str]) -> RadiusServerLifecycleMcpAction:
        assert value is environment
        captured["built"] = True
        return action

    def create(settings: HttpServerSettings, **kwargs: object) -> object:
        captured["action"] = kwargs["v4_radius_server_lifecycle_candidate_action"]
        return object()

    async def serve(self: uvicorn.Server, sockets: object = None) -> None:
        captured["served"] = True

    monkeypatch.setattr(radius_server_lifecycle_runtime, "build_radius_server_lifecycle_candidate", build)
    monkeypatch.setattr(http_server, "create_http_app", create)
    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    http_server.main()
    assert captured == {"built": True, "action": action, "served": True}



@pytest.mark.parametrize("retain",[False,True])
def test_real_oauth_http_runs_actual_parent_and_original_child_kernels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retain: bool,
) -> None:
    import asyncio,time
    from fortipam_mcp.local_oauth import LocalOAuthProvider
    from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
    from test_radius_server_lifecycle_workflow import setup
    from scripts.v4_radius_server_lifecycle_mcp_oauth_acceptance import (
        _validate_preview,_validate_authorization,_validate_execution,
        _validate_removal_preview,_validate_removal_authorization,_validate_removal_execution,
    )
    settings=_settings(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read fortipam:plan fortipam:operate')
    assert settings.local_oauth is not None and settings.v4_planning_authorization is not None
    bearer=next(v for k,v in headers.items()if k.lower()=='authorization').removeprefix('Bearer ')
    token=asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(bearer))
    principal=planning_principal_from_access_token(token,settings.v4_planning_authorization)
    identity={'requester_digest':principal.requester.digest,'transport_digest':principal.transport_namespace_digest}
    root=tmp_path/'candidate';root.mkdir(mode=0o700)
    parent,peer,source,now,create,native,restore,_=setup(root,monkeypatch,identity=identity,retain=retain)
    now[0]=int(time.time())
    app=create_http_app(settings,v4_radius_server_lifecycle_candidate_action=RadiusServerLifecycleMcpAction(parent,execution_enabled=True,persistent_primary=retain))
    names=tuple(f'{verb}_v4_radius_primary_configure_700' for verb in ('preview','authorize','execute')) if retain else (_PREVIEW,_AUTHORIZE,_EXECUTE)
    with TestClient(app,base_url='https://mcp.example.com')as client:
        p=_call(client,headers,names[0],{})
        assert not p['isError'];preview=p['structuredContent'];_validate_preview(preview,persistent_primary=retain)
        a=_call(client,headers,names[1],{'preview_ref':preview['preview_ref']})
        assert not a['isError'];authorization=a['structuredContent'];_validate_authorization(authorization,preview,persistent_primary=retain)
        result=_call(client,headers,names[2],{'authorization_ref':authorization['authorization_ref']})
        assert not result['isError'];_validate_execution(result['structuredContent'],persistent_primary=retain)
        assert peer.posts==peer.native_posts==source.loads==1
        assert peer.deletes==int(not retain) and (peer.row is not None) is retain
        assert create._execution_store.claim_count==native._store.claim_count==1
        assert restore._store.claim_count==int(not retain)
        repeat=_call(client,headers,names[2],{'authorization_ref':authorization['authorization_ref']})
        assert repeat['isError'] and peer.posts==peer.native_posts==source.loads==1
        assert peer.deletes==int(not retain)

    if retain:
        from test_radius_server_lifecycle_workflow import restart
        resumed=restart(parent,root,peer,now,identity=identity)
        app=create_http_app(settings,v4_radius_server_lifecycle_candidate_action=
            RadiusServerLifecycleMcpAction(resumed,execution_enabled=True,persistent_primary=True))
        with TestClient(app,base_url='https://mcp.example.com') as client:
            p=_call(client,headers,'preview_v4_radius_primary_remove_700',{})
            assert not p['isError'];_validate_removal_preview(p['structuredContent'])
            a=_call(client,headers,'authorize_v4_radius_primary_remove_700',
                {'preview_ref':p['structuredContent']['preview_ref']})
            assert not a['isError'];_validate_removal_authorization(a['structuredContent'],p['structuredContent'])
            result=_call(client,headers,'execute_v4_radius_primary_remove_700',
                {'authorization_ref':a['structuredContent']['authorization_ref']})
            assert not result['isError'] and result['structuredContent']['outcome']=='succeeded'
            assert result['structuredContent']['verification']=='verified'
            _validate_removal_execution(result['structuredContent'])
        assert peer.row is None and peer.posts==peer.native_posts==peer.deletes==source.loads==1
        assert resumed._closed()



def test_http_lifespan_closes_unused_real_candidate(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    from test_radius_server_lifecycle_workflow import setup
    root=tmp_path/'candidate';root.mkdir(mode=0o700)
    parent,peer,source,*_=setup(root,monkeypatch)
    app=create_http_app(_settings(tmp_path),v4_radius_server_lifecycle_candidate_action=RadiusServerLifecycleMcpAction(parent,execution_enabled=True))
    with TestClient(app,base_url='https://mcp.example.com'):
        assert not parent._closed()
    assert parent._closed() and peer.posts==source.loads==0


def test_standard_http_env_file_loads_only_declared_radius_configuration(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp import http_server
    from fortipam_mcp.radius_server_lifecycle_runtime import PREFIX
    path=tmp_path/'runtime.env';path.write_text(PREFIX+'ENABLED=true\n'+PREFIX+'EXECUTION_ENABLED=false\n')
    path.chmod(0o600)
    monkeypatch.setattr(os,'environ',{http_server.HTTP_ENV_FILE_VARIABLE:str(path)})
    assert http_server.load_http_runtime_environment()
    assert os.environ[PREFIX+'ENABLED']=='true' and os.environ[PREFIX+'EXECUTION_ENABLED']=='false'


def test_normal_main_closes_candidate_on_app_creation_failure(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp import http_server,radius_server_lifecycle_runtime
    env=_v4_environment(tmp_path/'oauth');env[RUNTIME_PROFILE_ENV]='v4-controlled'
    workflow,_=_workflow(monkeypatch);action=RadiusServerLifecycleMcpAction(workflow)
    closed=[]
    monkeypatch.setattr(RadiusServerLifecycleWorkflow,'close',lambda self:closed.append(True))
    monkeypatch.setattr(os,'environ',env)
    monkeypatch.setattr(http_server,'load_http_runtime_environment',lambda:False)
    monkeypatch.setattr(radius_server_lifecycle_runtime,'build_radius_server_lifecycle_candidate',lambda _:action)
    def fail(*a: object,**k: object) -> object:raise HttpConfigurationError('Synthetic startup refused.')
    monkeypatch.setattr(http_server,'create_http_app',fail)
    with pytest.raises(SystemExit):http_server.main()
    assert closed==[True]
