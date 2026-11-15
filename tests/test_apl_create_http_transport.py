"""Disabled REST APL creation, dependency preservation and durable no-replay."""

import asyncio
import copy
import json

import httpx
import pytest

from fortipam_mcp import apl_create_http_transport as module
from fortipam_mcp.apl_live_workflow import AplCreateLiveWorkflow
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

RULE = "mcp-v4-apl-rest-test"
GROUP = "mcp-v4-user-group-test"
ROLE = "mcp-v4-role-test"


@pytest.fixture
def harness(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "_ssl_context", lambda _: True)
    tmp_path.chmod(0o700)
    claim = tmp_path / "dispatch.json"
    records = {
        "auto-provision-rule": [{"name": "mcp-v4-apl-retained", "status": "disable"}],
        "group": {"name": GROUP, "match": [{"server-name": "ldap-fixture"}]},
        "accprofile": {"name": ROLE, "secretgrp": "read"},
    }
    calls = []
    controls = {}

    def handler(request):
        parts = request.url.path.split("/")
        path, table = parts[4:6]
        key = parts[6] if len(parts) == 7 else None
        body = json.loads(request.content) if request.content else None
        calls.append((request.method, table, body))
        if request.method == "POST":
            assert claim.is_file()
            assert RULE not in claim.read_text()
            if controls.get("ambiguous_before_commit"):
                raise httpx.ReadTimeout("private response", request=request)
            records[table].append({**body, "priority": 1})
            if controls.get("post_drift"):
                records["accprofile"]["secretgrp"] = "write"
        results = copy.deepcopy(records[table])
        if table == "auto-provision-rule" and key:
            results = [row for row in results if row["name"] == key]
        elif isinstance(results, dict):
            results = [results]
        payload = {"status": "success", "http_status": 200, "http_method": request.method,
                   "path": path, "name": table, "version": "v7.0.0", "build": 29,
                   "results": results, "limit_reached": False}
        if controls.get("wrong_build"):
            payload["build"] = 30
        if controls.get("truncated") and table == "auto-provision-rule":
            payload["limit_reached"] = True
        if controls.get("denied"):
            return httpx.Response(403, json={"private": "response"})
        return httpx.Response(200, json=payload)

    def factory(**kwargs):
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        return httpx.Client(transport=httpx.MockTransport(handler), **kwargs)

    def build():
        return module.FortiPamAplCreateHttpTransport(
            SecretMetadataHttpTransportConfig("https://fixture.example", "private-token", 15, None),
            module.AplCreateHttpBinding(RULE, GROUP, ROLE), claim, client_factory=factory,
        )

    return build, records, calls, controls, claim


def test_registered_mcp_create_uses_fixed_rest_body_and_preserves_existing_state(harness, monkeypatch):
    from mcp import Client
    from fortipam_mcp.apl_mcp_action import ProtectedAplMcpAction
    from fortipam_mcp.server import FortiPamMcpServer, RuntimeProfile
    from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
    from test_v4_m3 import _requester
    from scripts.v4_apl_mcp_oauth_acceptance import (
        _validate_preview, _validate_execution, AplMcpOAuthAcceptanceError,
    )

    build, records, calls, _, claim = harness
    before = copy.deepcopy(records)
    action = ProtectedAplMcpAction(AplCreateLiveWorkflow(build(), write_transport="rest_700"))
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    server = FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=object(), v4_folder_action_enabled=True,
        v4_apl_action=action, v4_apl_action_enabled=True, v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: principal)
    monkeypatch.setattr(server, "_v4_apl_action_principal", lambda: principal)

    async def exercise():
        async with Client(server.mcp) as client:
            preview = await client.call_tool("preview_v4_auto_provision_rule_create", {
                "auto_provision_rule_name": RULE, "remote_user_group_name": GROUP, "role_name": ROLE,
            })
            _validate_preview(preview.structured_content, RULE, GROUP, ROLE, preview.is_error,
                              write_transport="rest_700")
            with pytest.raises(AplMcpOAuthAcceptanceError):
                _validate_preview(preview.structured_content, RULE, GROUP, ROLE, preview.is_error)
            confirmation = await client.call_tool("confirm_v4_auto_provision_rule_create", {
                "preview_ref": preview.structured_content["preview_ref"],
            })
            arguments = {"authorization_ref": confirmation.structured_content["authorization_ref"]}
            result = await client.call_tool("execute_confirmed_v4_auto_provision_rule_create", arguments)
            _validate_execution(result.structured_content, result.is_error, write_transport="rest_700")
            replay = await client.call_tool("execute_confirmed_v4_auto_provision_rule_create", arguments)
            assert replay.structured_content["idempotent_replay"] is True

    asyncio.run(exercise())
    assert [call for call in calls if call[0] == "POST"] == [
        ("POST", "auto-provision-rule", {
            "name": RULE, "status": "disable", "remote-group": GROUP, "accprofile": ROLE,
        })
    ]
    assert records["auto-provision-rule"][:-1] == before["auto-provision-rule"]
    assert records["group"] == before["group"] and records["accprofile"] == before["accprofile"]
    assert claim.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("surface", ["auto-provision-rule", "group", "accprofile"])
def test_full_state_drift_blocks_create(harness, surface):
    build, records, calls, _, claim = harness
    adapter = build()
    assert adapter.inspect(RULE, GROUP, ROLE).create_baseline_verified
    record = records[surface][0] if surface == "auto-provision-rule" else records[surface]
    record["changed"] = True
    with pytest.raises(module.AplCreateHttpTransportError):
        adapter.create_disabled_and_readback(RULE, GROUP, ROLE)
    assert not claim.exists() and not any(call[0] == "POST" for call in calls)


@pytest.mark.parametrize("failure", ["ambiguous_before_commit", "post_drift"])
def test_ambiguous_or_unverified_write_is_consumed_even_after_restart(harness, failure):
    build, _, calls, controls, claim = harness
    adapter = build()
    workflow = AplCreateLiveWorkflow(adapter, write_transport="rest_700")
    preview = workflow.preview(auto_provision_rule_name=RULE, remote_user_group_name=GROUP,
                               role_name=ROLE, requester_digest="a" * 64)
    authorized = workflow.confirm(preview["preview_ref"], requester_digest="a" * 64)
    controls[failure] = True
    result = workflow.execute(authorized["authorization_ref"], requester_digest="a" * 64)
    assert result["outcome"] == "reconciliation_required"
    controls.clear()
    for instance in (adapter, build()):
        with pytest.raises(module.AplCreateHttpTransportError):
            instance.inspect(RULE, GROUP, ROLE)
        with pytest.raises(module.AplCreateHttpTransportError):
            instance.create_disabled_and_readback(RULE, GROUP, ROLE)
    assert claim.exists() and sum(call[0] == "POST" for call in calls) == 1


@pytest.mark.parametrize("failure", ["wrong_build", "truncated", "denied"])
def test_unqualified_read_does_not_establish_absence(harness, failure):
    build, _, calls, controls, claim = harness
    controls[failure] = True
    with pytest.raises(module.AplCreateHttpTransportError, match="unavailable"):
        build().inspect(RULE, GROUP, ROLE)
    assert not claim.exists() and not any(call[0] == "POST" for call in calls)


def test_binding_unprepared_and_existing_rule_cannot_write(harness):
    build, records, calls, _, claim = harness
    for args in ((RULE, GROUP, ROLE), (RULE + "-other", GROUP, ROLE)):
        with pytest.raises(module.AplCreateHttpTransportError):
            build().create_disabled_and_readback(*args)
    records["auto-provision-rule"].append({"name": RULE, "status": "disable"})
    adapter = build()
    assert not adapter.inspect(RULE, GROUP, ROLE).create_baseline_verified
    with pytest.raises(module.AplCreateHttpTransportError):
        adapter.create_disabled_and_readback(RULE, GROUP, ROLE)
    assert not claim.exists() and not any(call[0] == "POST" for call in calls)


def test_independent_transport_instances_share_exclusive_claim(harness):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    build, _, calls, _, _ = harness
    adapters = [build(), build()]
    for adapter in adapters:
        adapter.inspect(RULE, GROUP, ROLE)
    start = Barrier(2)

    def dispatch(adapter):
        start.wait(timeout=5)
        try:
            return adapter.create_disabled_and_readback(RULE, GROUP, ROLE).verified
        except module.AplCreateHttpTransportError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(dispatch, adapters)) == [False, True]
    assert sum(call[0] == "POST" for call in calls) == 1


@pytest.fixture
def rest_environment(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "binding.json"
    path.write_text(json.dumps({"contract": module.BINDING_CONTRACT, "rule_name": RULE,
                                "group_name": GROUP, "role_name": ROLE}))
    path.chmod(0o600)
    return {module.REST_ENV_PREFIX + "BINDING_FILE": str(path),
            module.REST_ENV_PREFIX + "CLAIM_FILE": str(tmp_path / "claim.json"),
            module.REST_ENV_PREFIX + "BASE_URL": "https://fixture.example",
            module.REST_ENV_PREFIX + "API_TOKEN": "private-token",
            "FORTIPAM_MCP_V4_APL_TRANSPORT": "rest_700"}, path


def test_rest_builder_retains_default_closed_gate(rest_environment):
    from fortipam_mcp.apl_mcp_action import build_v4_apl_action, V4AplActionRuntimeError
    env, _ = rest_environment
    action = build_v4_apl_action(env)
    assert action._workflow._write_transport == "rest_700"
    with pytest.raises(V4AplActionRuntimeError):
        action.execute("opaque", object())


@pytest.mark.parametrize("failure", ["permissions", "symlink", "claim_parent", "generic_token",
                                     "unknown_transport", "missing_claim"])
def test_builder_rejects_unsafe_or_incomplete_configuration(rest_environment, failure):
    from fortipam_mcp.apl_mcp_action import build_v4_apl_action, V4AplActionConfigurationError
    env, path = rest_environment
    if failure == "permissions":
        path.chmod(0o644)
    elif failure == "symlink":
        link = path.with_name("link.json")
        link.symlink_to(path)
        env[module.REST_ENV_PREFIX + "BINDING_FILE"] = str(link)
    elif failure == "claim_parent":
        path.parent.chmod(0o755)
    elif failure == "generic_token":
        del env[module.REST_ENV_PREFIX + "API_TOKEN"]
        env["FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_API_TOKEN"] = "private-token"
    elif failure == "missing_claim":
        del env[module.REST_ENV_PREFIX + "CLAIM_FILE"]
    else:
        env["FORTIPAM_MCP_V4_APL_TRANSPORT"] = "rest"
    with pytest.raises(V4AplActionConfigurationError):
        build_v4_apl_action(env)
