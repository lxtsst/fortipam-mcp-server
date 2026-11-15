"""Real local OAuth/MCP boundary with synthetic protected incident/native M4."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import http_server as h
from fortipam_mcp import instruction_quota_runtime as old
from fortipam_mcp import instruction_quota_recovery_runtime as r
from fortipam_mcp.instruction_quota_recovery_mcp_action import InstructionQuotaRecoveryMcpAction
from fortipam_mcp.runtime_profile import RuntimeProfile
from test_instruction_feature_mcp_action import principal
from test_instruction_quota_http_transport import Connection
from test_instruction_quota_runtime import setup, save, connect
from test_instruction_quota_recovery_runtime import retained
from test_instruction_quota_recovery_workflow import policy_for_test
from test_ldap_server_mcp_action import _settings, _login, _call

NAMES = tuple(f"{verb}_v4_instruction_quota_incident_correction_700" for verb in ("preview", "authorize", "execute"))


def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, identity: dict[str, str], *, enabled: bool = True) -> tuple[dict[str, str], Any, r.InstructionQuotaRecoveryRuntime]:
    tmp_path.mkdir(mode=0o700)
    env, manifest, path, cycle = setup(tmp_path)
    connect(monkeypatch, cycle)
    manifest["identity"].update(allowed_requester_digest=identity["requester_digest"], allowed_transport_digest=identity["transport_digest"])
    env[old.PREFIX + "EXECUTION_ENABLED"] = "true"
    for phase in ("allocate", "restore"):
        manifest["phase"] = phase; save(path, manifest)
        action = old.build_instruction_quota_candidate(env)
        assert action is not None
        item = action._workflow
        preview = item.preview(**identity)
        auth = item.authorize(cast(str, preview["preview_ref"]), **identity)
        if phase == "allocate":
            assert item.execute(cast(str, auth["authorization_ref"]), **identity)["verification"] == "verified"
        else:
            with monkeypatch.context() as patch:
                def lost(self: Connection, *args: object, **kwargs: object) -> None:
                    raise RuntimeError("synthetic-private-original-unknown")
                patch.setattr(Connection, "request", lost)
                assert item.execute(cast(str, auth["authorization_ref"]), **identity)["verification"] == "unknown"
    env[old.PREFIX + "EXECUTION_ENABLED"] = "false"
    env[r.PREFIX + "ENABLED"] = "true"
    env[r.PREFIX + "EXECUTION_ENABLED"] = "true" if enabled else "false"
    for index, suffix in enumerate(r._KEYS.values()):
        fd = os.open(cycle.path / (r._PREFIX + suffix), os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out: out.write(bytes([81 + index]) * 32)
    runtime = r.build_instruction_quota_recovery_candidate(env)
    assert runtime is not None
    return env, cycle, runtime


def test_oauth_reference_only_mcp_requires_real_policy_and_preserves_unknown(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path / "http")
    identity, headers = principal(settings, monkeypatch)
    env, cycle, runtime = prepared(tmp_path / "runtime", monkeypatch, identity)
    before = retained(tmp_path / "runtime")
    app = h.create_http_app(settings, v4_instruction_quota_recovery_candidate_action=InstructionQuotaRecoveryMcpAction(runtime, execution_enabled=True))
    with TestClient(app, base_url="https://mcp.example.com") as client:
        preview = _call(client, headers, NAMES[0], {})
        assert not preview["isError"] and preview["structuredContent"]["Expected State"]["instruction_quota_percent"] == 0
        arguments = {"preview_ref": preview["structuredContent"]["preview_ref"]}
        assert _call(client, headers, NAMES[1], arguments)["isError"]
        assert runtime._store.claim_count == 0 and len(cycle.device.requests) == 1
        assert runtime._workflow is not None
        policy_for_test(runtime._workflow)
        authorization = _call(client, headers, NAMES[1], arguments)
        assert not authorization["isError"]
        execute = {"authorization_ref": authorization["structuredContent"]["authorization_ref"]}
        result = _call(client, headers, NAMES[2], execute)
        assert not result["isError"]
        value = result["structuredContent"]
        assert value["verification"] == "verified" and value["original_restore_unknown_preserved"] is True
        assert value["incident_closed"] is False and value["forward_resource_work_authorized"] is False
        assert _call(client, headers, NAMES[2], execute)["structuredContent"]["idempotent_replay"] is True
        assert _call(client, headers, NAMES[0], {})["isError"]
        for private in (identity["requester_digest"], identity["transport_digest"], "synthetic-token", str(cycle.path)):
            assert private not in json.dumps(result)
    assert len(cycle.device.requests) == 2 and runtime._store.claim_count == 1
    assert retained(tmp_path / "runtime") == before and not (cycle.path / "restore.ack.json").exists()


@pytest.mark.parametrize("plan,operate,runtime_gate,action_gate", [(False,False,True,True), (True,False,True,True), (True,True,False,True), (True,True,True,False), (True,True,True,True)])
def test_authenticated_scopes_and_both_execution_gates(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, plan: bool, operate: bool, runtime_gate: bool, action_gate: bool) -> None:
    settings = _settings(tmp_path / "http")
    scope = "fortipam:read" + (" fortipam:plan" if plan else "") + (" fortipam:operate" if operate else "")
    identity, headers = principal(settings, monkeypatch, scope if plan else "fortipam:read fortipam:plan")
    env, cycle, runtime = prepared(tmp_path / "runtime", monkeypatch, identity, enabled=runtime_gate)
    app = h.create_http_app(settings, v4_instruction_quota_recovery_candidate_action=InstructionQuotaRecoveryMcpAction(runtime, execution_enabled=action_gate))
    with TestClient(app, base_url="https://mcp.example.com") as client:
        if not plan: headers = _login(client, scope)
        preview = _call(client, headers, NAMES[0], {})
        assert preview["isError"] is (not plan)
        if not plan:
            assert runtime._workflow is None and runtime._store.claim_count == 0 and len(cycle.device.requests) == 1
            return
        assert runtime._workflow is not None
        policy_for_test(runtime._workflow)
        authorized = _call(client, headers, NAMES[1], {"preview_ref": preview["structuredContent"]["preview_ref"]})
        allowed = operate and runtime_gate and action_gate
        assert authorized["isError"] is (not allowed)
        reference = authorized["structuredContent"]["authorization_ref"] if allowed else "synthetic-unissued-auth"
        result = _call(client, headers, NAMES[2], {"authorization_ref": reference})
        assert result["isError"] is (not allowed)
        assert len(cycle.device.requests) == 1 + int(allowed) and runtime._store.claim_count == int(allowed)


@pytest.mark.parametrize("present", [False, True])
def test_default_absence_fixed_schemas_and_old_tools_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, present: bool) -> None:
    settings = _settings(tmp_path / "http")
    identity, headers = principal(settings, monkeypatch)
    action = None
    if present:
        env, cycle, runtime = prepared(tmp_path / "runtime", monkeypatch, identity, enabled=False)
        action = InstructionQuotaRecoveryMcpAction(runtime)
    app = h.create_http_app(settings, v4_instruction_quota_recovery_candidate_action=action)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        response = client.post("/fpamcp", headers=headers, json={"jsonrpc":"2.0","id":"list","method":"tools/list","params":{}})
        tools = {v["name"]: v for v in response.json()["result"]["tools"]}
        assert set(tools) & set(NAMES) == (set(NAMES) if present else set())
        assert not any(f"{verb}_v4_instruction_quota_{phase}_700" in tools for verb in ("preview","authorize","execute") for phase in ("allocate","restore"))
        if present:
            for name, keys in zip(NAMES, (set(), {"preview_ref"}, {"authorization_ref"})):
                assert set(tools[name]["inputSchema"]["properties"]) == keys
            assert tools[NAMES[0]]["annotations"]["readOnlyHint"] is True
            assert tools[NAMES[2]]["annotations"]["readOnlyHint"] is False


@pytest.mark.parametrize("invalid", ["profile", "auth", "authority", "type", "coexistence"])
def test_injection_requires_exclusive_exact_action_controlled_oauth(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str) -> None:
    settings = _settings(tmp_path / "http")
    identity, headers = principal(settings, monkeypatch)
    env, cycle, runtime = prepared(tmp_path / "runtime", monkeypatch, identity)
    action: object = InstructionQuotaRecoveryMcpAction(runtime)
    kwargs: dict[str, object] = {}
    if invalid == "profile": settings = replace(settings, runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid == "auth": settings = replace(settings, auth_mode="bearer", bearer_token="synthetic-private-token")
    elif invalid == "authority": settings = replace(settings, v4_planning_authorization=None)
    elif invalid == "type": action = object()
    elif invalid == "coexistence": kwargs["v4_instruction_quota_candidate_action"] = runtime._original
    with pytest.raises(h.HttpConfigurationError):
        h.create_http_app(settings, v4_instruction_quota_recovery_candidate_action=action, **kwargs)
    assert runtime._workflow is None and runtime._store.claim_count == 0 and len(cycle.device.requests) == 1


def test_caller_bindings_credentials_routes_and_policy_arguments_never_reach_runtime(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path / "http")
    identity, headers = principal(settings, monkeypatch)
    env, cycle, runtime = prepared(tmp_path / "runtime", monkeypatch, identity)
    app = h.create_http_app(settings, v4_instruction_quota_recovery_candidate_action=InstructionQuotaRecoveryMcpAction(runtime, execution_enabled=True))
    with TestClient(app, base_url="https://mcp.example.com") as client:
        for name, args in ((NAMES[0], {"state_root":"synthetic-private-argument"}),
                (NAMES[1], {"preview_ref":"synthetic", "policy":"synthetic-private-argument"}),
                (NAMES[2], {"authorization_ref":"synthetic", "route":"synthetic-private-argument", "token":"synthetic-private-argument"})):
            result = _call(client, headers, name, args)
            assert result["isError"] and "synthetic-private-argument" not in json.dumps(result)
    assert runtime._workflow is None and runtime._store.claim_count == 0 and len(cycle.device.requests) == 1


@pytest.mark.parametrize("selected", [True, False])
def test_normal_main_selects_recovery_exclusively_and_never_opens_a_listener(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selected: bool) -> None:
    import uvicorn
    settings = replace(_settings(tmp_path / "http"), v4_confirmation=None)
    identity, headers = principal(settings, monkeypatch)
    env, cycle, runtime = prepared(tmp_path / "runtime", monkeypatch, identity)
    if not selected:
        env[r.PREFIX + "ENABLED"] = "false"; env[r.PREFIX + "EXECUTION_ENABLED"] = "false"
    monkeypatch.setattr(h, "load_http_runtime_environment", lambda: False)
    monkeypatch.setattr(h.HttpServerSettings, "from_environment", classmethod(lambda cls: settings))
    monkeypatch.setattr(h.os, "environ", env)
    # Any old writable bootstrap would violate this test's original-byte guard.
    if selected:
        monkeypatch.setattr(old, "build_instruction_quota_candidate", lambda *a, **k: pytest.fail("selected incident loaded old writable quota factory"))
    captured: list[Any] = []
    async def serve(self: Any, *args: object, **kwargs: object) -> None:
        captured.append(self.config.app)
    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    before = retained(tmp_path / "runtime")
    cycle.device.on_read = lambda: pytest.fail("main startup reached device reader")
    h.main()
    assert len(captured) == 1
    after = retained(tmp_path / "runtime")
    # The legacy factory retains its ordinary SQLite reopen behavior.
    if selected: assert after == before
    else: assert {p: b for p, b in after.items() if p.suffix != ".sqlite"} == {p: b for p, b in before.items() if p.suffix != ".sqlite"}
    with TestClient(captured[0], base_url="https://mcp.example.com") as client:
        response = client.post("/fpamcp", headers=headers, json={"jsonrpc":"2.0","id":"list","method":"tools/list","params":{}})
        names = {v["name"] for v in response.json()["result"]["tools"]}
        assert names & set(NAMES) == (set(NAMES) if selected else set())
        assert ("preview_v4_instruction_quota_restore_700" in names) is (not selected)
    assert len(cycle.device.requests) == 1


def test_mcp_ambiguous_correction_stays_consumed_and_cannot_restart_from_preview(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path / "http")
    identity, headers = principal(settings, monkeypatch)
    env, cycle, runtime = prepared(tmp_path / "runtime", monkeypatch, identity)
    before = retained(tmp_path / "runtime")
    app = h.create_http_app(settings, v4_instruction_quota_recovery_candidate_action=InstructionQuotaRecoveryMcpAction(runtime, execution_enabled=True))
    with TestClient(app, base_url="https://mcp.example.com") as client:
        preview = _call(client, headers, NAMES[0], {})
        assert runtime._workflow is not None
        policy_for_test(runtime._workflow)
        auth = _call(client, headers, NAMES[1], {"preview_ref":preview["structuredContent"]["preview_ref"]})
        def lost(self: Connection, *args: object, **kwargs: object) -> None:
            raise RuntimeError("synthetic-private-independent-write-unknown")
        monkeypatch.setattr(Connection, "request", lost)
        args = {"authorization_ref": auth["structuredContent"]["authorization_ref"]}
        result = _call(client, headers, NAMES[2], args)
        value = result["structuredContent"]
        assert not result["isError"] and value["outcome"] == "reconciliation_required" and value["verification"] == "unknown"
        assert value["compensation"] == "not_requested" and value["incident_closed"] is False
        assert _call(client, headers, NAMES[2], args)["structuredContent"]["idempotent_replay"] is True
        assert _call(client, headers, NAMES[0], {})["isError"]
    assert len(cycle.device.requests) == 1 and runtime._store.claim_count == 1
    assert retained(tmp_path / "runtime") == before and not (cycle.path / "restore.ack.json").exists()


@pytest.mark.parametrize("field", ["requester_digest", "transport_digest"])
def test_authenticated_but_wrong_retained_subject_is_denied_before_device_read(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    settings = _settings(tmp_path / "http")
    identity, headers = principal(settings, monkeypatch)
    env, cycle, runtime = prepared(tmp_path / "runtime", monkeypatch, {**identity, field: "9" * 64})
    cycle.device.on_read = lambda: pytest.fail("wrong subject reached fresh observation")
    app = h.create_http_app(settings, v4_instruction_quota_recovery_candidate_action=InstructionQuotaRecoveryMcpAction(runtime, execution_enabled=True))
    with TestClient(app, base_url="https://mcp.example.com") as client:
        assert _call(client, headers, NAMES[0], {})["isError"]
    assert runtime._workflow is None and runtime._store.claim_count == 0 and len(cycle.device.requests) == 1
