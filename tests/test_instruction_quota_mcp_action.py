"""Authenticated local OAuth/MCP scopes with a real M4 quota cycle."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import HttpConfigurationError, create_http_app
from fortipam_mcp.instruction_quota_mcp_action import InstructionQuotaMcpAction
from fortipam_mcp.runtime_profile import RuntimeProfile
from test_instruction_quota_live_workflow import Cycle, cycle as cycle, workflow
from test_ldap_server_mcp_action import _settings, _login, _call


def names(phase: str) -> tuple[str,str,str]:
    return tuple(f"{verb}_v4_instruction_quota_{phase}_700" for verb in ("preview","authorize","execute"))  # type: ignore[return-value]


from test_instruction_feature_mcp_action import principal


def test_real_oauth_mcp_m4_allocate_restore_and_no_second_put(tmp_path: Path, cycle: Cycle,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path/"http")
    identity,headers = principal(settings,monkeypatch)
    for phase in ("allocate","restore"):
        item = workflow(cycle,phase,allowed_requester_digest=identity["requester_digest"],
                        allowed_transport_digest=identity["transport_digest"])
        action = InstructionQuotaMcpAction(item,execution_enabled=True)
        app = create_http_app(settings,v4_instruction_quota_candidate_action=action)
        with TestClient(app,base_url="https://mcp.example.com") as client:
            preview_name,authorize_name,execute_name = names(phase)
            preview = _call(client,headers,preview_name,{})
            assert not preview["isError"]
            content = preview["structuredContent"]
            assert content["Proposed Changes"]["video_and_software_preserved"] is True
            issued = _call(client,headers,authorize_name,{"preview_ref":content["preview_ref"]})
            assert not issued["isError"]
            arguments = {"authorization_ref":issued["structuredContent"]["authorization_ref"]}
            result = _call(client,headers,execute_name,arguments)
            assert not result["isError"] and result["structuredContent"]["verification"]=="verified"
            count = len(cycle.device.requests)
            replay = _call(client,headers,execute_name,arguments)
            assert replay["structuredContent"]["idempotent_replay"] is True
            assert len(cycle.device.requests)==count
    assert cycle.device.instruction == 0 and len(cycle.device.requests)==2


@pytest.mark.parametrize("plan,operate,action_gate", [(False,False,True),(True,False,True),
                                                    (True,True,False),(True,True,True)])
def test_scopes_and_independent_mcp_gate(tmp_path: Path, cycle: Cycle, monkeypatch: pytest.MonkeyPatch,
                                       plan: bool, operate: bool, action_gate: bool) -> None:
    settings = _settings(tmp_path/"http")
    scope = "fortipam:read"+(" fortipam:plan" if plan else "")+(" fortipam:operate" if operate else "")
    identity,bound_headers = principal(settings,monkeypatch,scope if plan else "fortipam:read fortipam:plan")
    item = workflow(cycle,allowed_requester_digest=identity["requester_digest"],
                    allowed_transport_digest=identity["transport_digest"])
    preview_calls: list[bool] = []
    original_preview = type(item).preview
    def observe_preview(self: object, **kwargs: str) -> dict[str,object]:
        preview_calls.append(True)
        return original_preview(self,**kwargs)  # type: ignore[arg-type]
    monkeypatch.setattr(type(item),"preview",observe_preview)
    app = create_http_app(settings,v4_instruction_quota_candidate_action=InstructionQuotaMcpAction(item,execution_enabled=action_gate))
    with TestClient(app,base_url="https://mcp.example.com") as client:
        headers = bound_headers if plan else _login(client,scope)
        preview_name,authorize_name,execute_name = names("allocate")
        preview = _call(client,headers,preview_name,{})
        assert preview["isError"] is (not plan)
        if not plan:
            assert not preview_calls
            assert not cycle.device.requests and item._execution_store.claim_count==0
            return
        issued = _call(client,headers,authorize_name,{"preview_ref":preview["structuredContent"]["preview_ref"]})
        assert issued["isError"] is (not operate or not action_gate)
        reference = "synthetic-unissued-authorization" if not operate or not action_gate else issued["structuredContent"]["authorization_ref"]
        result = _call(client,headers,execute_name,{"authorization_ref":reference})
        assert result["isError"] is (not operate or not action_gate)
        assert len(cycle.device.requests)==int(operate and action_gate)
        assert item._execution_store.claim_count==int(operate and action_gate)


@pytest.mark.parametrize("phase", [None,"allocate","restore"])
def test_default_absence_and_only_fixed_reference_schemas(tmp_path: Path, cycle: Cycle, phase: str | None) -> None:
    action = None if phase is None else InstructionQuotaMcpAction(workflow(cycle,phase))
    app = create_http_app(_settings(tmp_path/"http"),v4_instruction_quota_candidate_action=action)
    with TestClient(app,base_url="https://mcp.example.com") as client:
        headers = _login(client,"fortipam:read fortipam:plan")
        response = client.post("/fpamcp",headers=headers,json={"jsonrpc":"2.0","id":"list","method":"tools/list","params":{}})
        assert response.status_code==200
        tools = {value["name"]:value for value in response.json()["result"]["tools"]}
        assert set(tools)&(set(names("allocate"))|set(names("restore"))) == (set() if phase is None else set(names(phase)))
        if phase is not None:
            for name,arguments in zip(names(phase),(set(),{"preview_ref"},{"authorization_ref"}),strict=True):
                assert set(tools[name]["inputSchema"]["properties"])==arguments


def test_invalid_runtime_and_non_quota_action_rejected(tmp_path: Path, cycle: Cycle) -> None:
    settings = _settings(tmp_path/"http")
    action = InstructionQuotaMcpAction(workflow(cycle))
    with pytest.raises(HttpConfigurationError):
        create_http_app(replace(settings,runtime_profile=RuntimeProfile.V4_PLAN_ONLY),v4_instruction_quota_candidate_action=action)
    with pytest.raises(HttpConfigurationError):
        create_http_app(settings,v4_instruction_quota_candidate_action=object())


def test_protected_startup_oauth_mcp_cycle_reopens_original_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp import instruction_quota_runtime as runtime
    from test_instruction_quota_runtime import setup,save,connect

    env,manifest,path,context = setup(tmp_path)
    connect(monkeypatch,context)
    settings = _settings(tmp_path/"http")
    identity,headers = principal(settings,monkeypatch)
    manifest["identity"]["allowed_requester_digest"] = identity["requester_digest"]
    manifest["identity"]["allowed_transport_digest"] = identity["transport_digest"]
    env[runtime.PREFIX+"EXECUTION_ENABLED"]="true"
    for phase in ("allocate","restore"):
        manifest["phase"]=phase
        save(path,manifest)
        action = runtime.build_instruction_quota_candidate(env)
        assert action is not None
        app = create_http_app(settings,v4_instruction_quota_candidate_action=action)
        with TestClient(app,base_url="https://mcp.example.com") as client:
            preview_name,authorize_name,execute_name = names(phase)
            preview = _call(client,headers,preview_name,{})
            assert not preview["isError"]
            authorization = _call(client,headers,authorize_name,{"preview_ref":preview["structuredContent"]["preview_ref"]})
            assert not authorization["isError"]
            result = _call(client,headers,execute_name,{"authorization_ref":authorization["structuredContent"]["authorization_ref"]})
            assert not result["isError"] and result["structuredContent"]["verification"]=="verified"
    assert len(context.device.requests)==2 and context.device.instruction == 0
