"""Synthetic workflow behind the real HTTP/OAuth LDAP tool boundary."""

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
from fortipam_mcp.ldap_server_live_workflow import LdapServerLiveWorkflow
from fortipam_mcp.ldap_server_mcp_action import LdapServerMcpAction
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

_PREVIEW = "preview_v4_ldap_server_create_700"
_AUTHORIZE = "authorize_v4_ldap_server_create_700"
_EXECUTE = "execute_v4_ldap_server_create_700"
_TOOLS = {_PREVIEW, _AUTHORIZE, _EXECUTE}
_ERROR = "FortiPAM LDAP server creation is unavailable."
Call = tuple[str, dict[str, str]]


def _workflow(monkeypatch: pytest.MonkeyPatch) -> tuple[LdapServerLiveWorkflow, list[Call]]:
    calls: list[Call] = []

    def preview(self: LdapServerLiveWorkflow, **identity: str) -> dict[str, object]:
        calls.append(("preview", identity))
        return {"preview_ref": "synthetic-preview"}

    def authorize(self: LdapServerLiveWorkflow, reference: str, **identity: str) -> dict[str, object]:
        assert reference == "synthetic-preview"
        calls.append(("authorize", identity))
        return {"authorization_ref": "synthetic-authorization"}

    def execute(self: LdapServerLiveWorkflow, reference: str, **identity: str) -> dict[str, object]:
        assert reference == "synthetic-authorization"
        calls.append(("execute", identity))
        return {"outcome": "succeeded", "verification": "verified"}

    monkeypatch.setattr(LdapServerLiveWorkflow, "preview", preview)
    monkeypatch.setattr(LdapServerLiveWorkflow, "authorize", authorize)
    monkeypatch.setattr(LdapServerLiveWorkflow, "execute", execute)
    return object.__new__(LdapServerLiveWorkflow), calls


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
    action = LdapServerMcpAction(workflow, execution_enabled=gate)
    app = create_http_app(_settings(tmp_path), v4_ldap_server_candidate_action=action)
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
        assert "get_v4_ldap_server_plan_requirements" in names
        assert not names.intersection(_TOOLS)


@pytest.mark.parametrize("invalid", ["profile", "auth", "authority", "type"])
def test_injection_requires_exact_action_and_controlled_oauth_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str,
) -> None:
    workflow, calls = _workflow(monkeypatch)
    action: object = LdapServerMcpAction(workflow)
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
        create_http_app(settings, v4_ldap_server_candidate_action=action)
    assert calls == []


def test_real_http_rejects_caller_binding_and_material_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, calls = _workflow(monkeypatch)
    app = create_http_app(_settings(tmp_path),
        v4_ldap_server_candidate_action=LdapServerMcpAction(workflow, execution_enabled=True))
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


def test_action_is_opaque_immutable_and_requires_exact_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, calls = _workflow(monkeypatch)
    action = LdapServerMcpAction(workflow)
    assert repr(action) == str(action) == "<LdapServerMcpAction redacted>"
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
        LdapServerMcpAction(workflow, execution_enabled=cast(bool, 1))
    assert calls == []


def test_workflow_failure_is_value_free(monkeypatch: pytest.MonkeyPatch) -> None:
    workflow, _ = _workflow(monkeypatch)

    def fail(self: LdapServerLiveWorkflow, *args: object, **kwargs: str) -> dict[str, object]:
        raise ValueError("synthetic-private-marker")

    action = LdapServerMcpAction(workflow, execution_enabled=True)
    principal = V4PlanningPrincipal(AuthenticatedRequester("synthetic-operator", "operator"), "a" * 64)
    for method in ("preview", "authorize", "execute"):
        monkeypatch.setattr(LdapServerLiveWorkflow, method, fail)
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
    from fortipam_mcp import http_server, ldap_server_runtime

    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    workflow, _ = _workflow(monkeypatch)
    action = LdapServerMcpAction(workflow)
    captured: dict[str, object] = {}
    monkeypatch.setattr(os, "environ", environment)
    monkeypatch.setattr(http_server, "load_http_runtime_environment", lambda: False)

    def build(value: dict[str, str]) -> LdapServerMcpAction:
        assert value is environment
        captured["built"] = True
        return action

    def create(settings: HttpServerSettings, **kwargs: object) -> object:
        captured["action"] = kwargs["v4_ldap_server_candidate_action"]
        return object()

    async def serve(self: uvicorn.Server, sockets: object = None) -> None:
        captured["served"] = True

    monkeypatch.setattr(ldap_server_runtime, "build_ldap_server_candidate", build)
    monkeypatch.setattr(http_server, "create_http_app", create)
    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    http_server.main()
    assert captured == {"built": True, "action": action, "served": True}
