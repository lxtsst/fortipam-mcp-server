"""Real local OAuth and HTTP schemas for the fixed LDAP update phases."""
from __future__ import annotations

from collections.abc import Callable

import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import pickle
from typing import Any, cast

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import HttpConfigurationError, HttpServerSettings, create_http_app
from fortipam_mcp.ldap_server_update_contract import CONTRACT
from fortipam_mcp.ldap_server_update_live_workflow import LdapServerUpdateLiveWorkflow
from fortipam_mcp.ldap_server_update_mcp_action import LdapServerUpdateMcpAction
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV, RuntimeProfile
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from v4_planning.material_provider import MaterialAccessDenied
from v4_planning.models import AuthenticatedRequester

from test_http_server import _v4_environment
from test_ldap_server_mcp_action import _call, _login, _settings

_ERROR = "FortiPAM LDAP server update is unavailable."
Call = tuple[str, dict[str, str]]


def _names(phase: str) -> tuple[str, str, str]:
    return (f"preview_v4_ldap_server_{phase}_700", f"authorize_v4_ldap_server_{phase}_700",
            f"execute_v4_ldap_server_{phase}_700")


def _workflow(monkeypatch: pytest.MonkeyPatch, phase: str = "update") -> tuple[LdapServerUpdateLiveWorkflow, list[Call]]:
    calls: list[Call] = []

    def preview(self: LdapServerUpdateLiveWorkflow, **identity: str) -> dict[str, object]:
        calls.append(("preview", identity))
        return {"contract": CONTRACT, "phase": phase, "preview_ref": "synthetic-preview"}

    def authorize(self: LdapServerUpdateLiveWorkflow, reference: str, **identity: str) -> dict[str, object]:
        assert reference == "synthetic-preview"
        calls.append(("authorize", identity))
        return {"contract": CONTRACT, "phase": phase, "authorization_ref": "synthetic-authorization"}

    def execute(self: LdapServerUpdateLiveWorkflow, reference: str, **identity: str) -> dict[str, object]:
        assert reference == "synthetic-authorization"
        calls.append(("execute", identity))
        return {"contract": CONTRACT, "phase": phase, "outcome": "succeeded", "verification": "verified"}

    monkeypatch.setattr(LdapServerUpdateLiveWorkflow, "phase", property(lambda self: phase))
    monkeypatch.setattr(LdapServerUpdateLiveWorkflow, "preview", preview)
    monkeypatch.setattr(LdapServerUpdateLiveWorkflow, "authorize", authorize)
    monkeypatch.setattr(LdapServerUpdateLiveWorkflow, "execute", execute)
    return object.__new__(LdapServerUpdateLiveWorkflow), calls


@pytest.mark.parametrize("phase", ["update", "restore"])
@pytest.mark.parametrize("plan,operate,gate", [
    (False, False, True), (True, False, True), (True, True, False), (True, True, True),
])
def test_phase_oauth_scopes_and_independent_execution_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, plan: bool, operate: bool, gate: bool,
) -> None:
    workflow, calls = _workflow(monkeypatch, phase)
    action = LdapServerUpdateMcpAction(workflow, execution_enabled=gate)
    app = create_http_app(_settings(tmp_path), v4_ldap_server_update_candidate_action=action)
    preview_name, authorize_name, execute_name = _names(phase)
    scope = "fortipam:read" + (" fortipam:plan" if plan else "") + (" fortipam:operate" if operate else "")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        headers = _login(client, scope)
        preview = _call(client, headers, preview_name, {})
        assert preview["isError"] is (not plan)
        if not plan:
            assert calls == []
            return
        assert preview["structuredContent"]["phase"] == phase
        assert preview["structuredContent"]["contract"] == CONTRACT
        authorization = _call(client, headers, authorize_name, {"preview_ref": "synthetic-preview"})
        assert authorization["isError"] is (not operate)
        execution = _call(client, headers, execute_name, {"authorization_ref": "synthetic-authorization"})
        assert execution["isError"] is (not operate or not gate)
        assert [name for name, _ in calls] == (
            ["preview", "authorize", "execute"] if operate and gate
            else ["preview", "authorize"] if operate else ["preview"]
        )
        assert all(identity == calls[0][1] for _, identity in calls)
        assert set(calls[0][1]) == {"requester_digest", "transport_digest"}
        assert all(len(value) == 64 for value in calls[0][1].values())


@pytest.mark.parametrize("phase", [None, "update", "restore"])
def test_only_fixed_phase_tools_registered_and_schemas_have_opaque_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str | None,
) -> None:
    action = None
    if phase is not None:
        workflow, _ = _workflow(monkeypatch, phase)
        action = LdapServerUpdateMcpAction(workflow)
    app = create_http_app(_settings(tmp_path), v4_ldap_server_update_candidate_action=action)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        headers = _login(client, "fortipam:read fortipam:plan")
        response = client.post("/fpamcp", headers=headers, json={
            "jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {},
        })
        assert response.status_code == 200
        tools = {tool["name"]: tool for tool in response.json()["result"]["tools"]}
        all_phase_tools = set(_names("update")) | set(_names("restore"))
        assert "get_v4_ldap_server_plan_requirements" in tools
        assert set(tools).intersection(all_phase_tools) == (set() if phase is None else set(_names(phase)))
        if phase is not None:
            for name, arguments in zip(_names(phase), (set(), {"preview_ref"}, {"authorization_ref"}), strict=True):
                assert set(tools[name]["inputSchema"]["properties"]) == arguments


@pytest.mark.parametrize("invalid", ["readonly", "plan_only", "auth", "authority", "type"])
def test_injection_requires_exact_action_controlled_local_oauth_and_planning_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str,
) -> None:
    workflow, calls = _workflow(monkeypatch)
    action: object = LdapServerUpdateMcpAction(workflow)
    settings = _settings(tmp_path)
    if invalid == "readonly": settings = replace(settings, runtime_profile=RuntimeProfile.READONLY)
    elif invalid == "plan_only": settings = replace(settings, runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid == "auth": settings = replace(settings, auth_mode="bearer", bearer_token="synthetic-token")
    elif invalid == "authority": settings = replace(settings, v4_planning_authorization=None)
    else: action = object()
    with pytest.raises(HttpConfigurationError):
        create_http_app(settings, v4_ldap_server_update_candidate_action=action)
    assert calls == []


@pytest.mark.parametrize("phase", ["update", "restore"])
def test_http_rejects_caller_phase_binding_body_and_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    workflow, calls = _workflow(monkeypatch, phase)
    app = create_http_app(_settings(tmp_path), v4_ldap_server_update_candidate_action=
        LdapServerUpdateMcpAction(workflow, execution_enabled=True))
    preview, authorize, execute = _names(phase)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        headers = _login(client, "fortipam:read fortipam:plan fortipam:operate")
        for name, arguments in (
            (preview, {"phase": "synthetic-private-marker"}),
            (preview, {"selector": "synthetic-private-marker"}),
            (authorize, {"preview_ref": "synthetic-preview", "password": "synthetic-private-marker"}),
            (execute, {"authorization_ref": "synthetic-authorization", "body": "synthetic-private-marker"}),
        ):
            result = _call(client, headers, name, arguments)
            assert result["isError"]
            assert "synthetic-private-marker" not in json.dumps(result)
        assert calls == []


def test_action_is_opaque_immutable_and_requires_exact_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    workflow, calls = _workflow(monkeypatch)
    action = LdapServerUpdateMcpAction(workflow)
    assert repr(action) == str(action) == "<LdapServerUpdateMcpAction redacted>"
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied): operation(action)
    with pytest.raises(TypeError): json.dumps(action)
    with pytest.raises(ValueError, match=_ERROR): setattr(action, "_enabled", True)
    with pytest.raises(ValueError, match=_ERROR): setattr(action, "phase", "restore")
    with pytest.raises(ValueError, match=_ERROR): delattr(action, "_workflow")
    invalid = cast(V4PlanningPrincipal, object())
    with pytest.raises(RuntimeError, match=_ERROR): action.preview(invalid)
    with pytest.raises(RuntimeError, match=_ERROR): action.authorize("synthetic-preview", invalid)
    principal = V4PlanningPrincipal(AuthenticatedRequester("synthetic-operator", "operator"), "a" * 64)
    with pytest.raises(RuntimeError, match=_ERROR): action.execute("synthetic-authorization", principal)
    with pytest.raises(ValueError, match=_ERROR): LdapServerUpdateMcpAction(workflow, execution_enabled=cast(bool, 1))
    assert calls == []


def test_workflow_failure_is_value_free(monkeypatch: pytest.MonkeyPatch) -> None:
    workflow, _ = _workflow(monkeypatch)

    def fail(self: LdapServerUpdateLiveWorkflow, *args: object, **kwargs: str) -> dict[str, object]:
        raise ValueError("synthetic-private-marker")

    action = LdapServerUpdateMcpAction(workflow, execution_enabled=True)
    principal = V4PlanningPrincipal(AuthenticatedRequester("synthetic-operator", "operator"), "a" * 64)
    for method in ("preview", "authorize", "execute"):
        monkeypatch.setattr(LdapServerUpdateLiveWorkflow, method, fail)
    callbacks: tuple[Callable[[], dict[str, object]], ...] = (
        lambda: action.preview(principal),
        lambda: action.authorize("synthetic-preview", principal),
        lambda: action.execute("synthetic-authorization", principal))
    for callback in callbacks:
        with pytest.raises(RuntimeError) as failure: callback()
        assert str(failure.value) == _ERROR
        assert failure.value.__cause__ is None and failure.value.__suppress_context__


def test_normal_main_composes_update_builder_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn
    from fortipam_mcp import http_server, ldap_server_update_runtime

    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    workflow, _ = _workflow(monkeypatch, "restore")
    action = LdapServerUpdateMcpAction(workflow)
    captured: dict[str, object] = {}
    monkeypatch.setattr(os, "environ", environment)
    monkeypatch.setattr(http_server, "load_http_runtime_environment", lambda: False)

    def build(value: dict[str, str]) -> LdapServerUpdateMcpAction:
        assert value is environment
        captured["built"] = True
        return action

    def create(settings: HttpServerSettings, **kwargs: object) -> object:
        captured["action"] = kwargs["v4_ldap_server_update_candidate_action"]
        return object()

    async def serve(self: uvicorn.Server, sockets: object = None) -> None:
        captured["served"] = True

    monkeypatch.setattr(ldap_server_update_runtime, "build_ldap_server_update_candidate", build)
    monkeypatch.setattr(http_server, "create_http_app", create)
    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    http_server.main()
    assert captured == {"built": True, "action": action, "served": True}


def test_http_environment_file_loads_exact_update_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp.http_server import HTTP_ENV_FILE_VARIABLE, load_http_runtime_environment
    from fortipam_mcp.ldap_server_update_runtime import PREFIX

    values = {PREFIX + "ENABLED": "true", PREFIX + "EXECUTION_ENABLED": "false",
              PREFIX + "STARTUP_MANIFEST_FILE": "/protected/ldap-update-startup.json"}
    ignored = "FORTIPAM_MCP_V4_LDAP_SERVER_UPDATE_EXTRA_ENABLED"
    env_file = tmp_path / "http-update.env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()) + f"{ignored}=true\n")
    env_file.chmod(0o600)
    monkeypatch.setenv(HTTP_ENV_FILE_VARIABLE, str(env_file))
    for key in (*values, ignored):
        monkeypatch.setenv(key, "")
        monkeypatch.delenv(key, raising=False)
    assert load_http_runtime_environment()
    assert {key: os.environ.get(key) for key in values} == values
    assert ignored not in os.environ
