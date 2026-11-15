"""Canonical phase client against actual SDK tools; OAuth itself is separately qualified."""
import asyncio
import json
from types import SimpleNamespace

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from scripts import v4_isolated_folder_policy_transition_mcp_oauth_acceptance as acceptance
from test_isolated_folder_policy_transition_mcp_action import _candidate, _host


@pytest.fixture
def harness(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    action, workflow, transport = _candidate()
    host, _ = _host(action)
    state = SimpleNamespace(transport=transport, calls=[], omitted=None, transform=None, revoked=0)
    class Session:
        async def list_tools(self):
            return SimpleNamespace(tools=[t for t in await host.mcp.list_tools() if t.name != state.omitted])
        async def call_tool(self, name, arguments):
            state.calls.append(name)
            try:
                result = await host.mcp.call_tool(name, arguments)
            except ToolError:
                return SimpleNamespace(is_error=True, structured_content=None)
            if state.transform and result.structured_content:
                state.transform(name, result.structured_content)
            return result
    async def common(*args, **kwargs):
        try:
            await kwargs["tool_session_callback"](Session())
        finally:
            state.revoked += 1
        return {"oauth_metadata_verified": True, "mcp_initialized": True, "token_revoked": True,
                "credential_values_returned": False}
    monkeypatch.setattr(acceptance.oauth, "run_address_mcp_oauth_surface_acceptance", common)
    def run(operation="assign", execute=False):
        path = tmp_path / (operation + ".json")
        return asyncio.run(acceptance.run_isolated_folder_policy_transition_mcp_oauth_acceptance(
            "https://mcp.example.test/mcp", tmp_path / "login", tmp_path / "client",
            operation=operation, **{"execute_preview_state_file" if execute else "preview_state_file": path}))
    return state, run


def test_canonical_split_phases_validate_sdk_dtos_and_consume_private_state_once(harness, tmp_path):
    state, run = harness
    for operation in ("assign", "restore"):
        assert run(operation)["preview_verified"]
        path = tmp_path / (operation + ".json")
        assert path.stat().st_mode & 0o777 == 0o600
        assert set(json.loads(path.read_text())) == {"contract", "operation", "preview_ref"}
        result = run(operation, True)
        assert result["execution_verified"] and result["token_revoked"] and not path.exists()
        claim = path.with_name(path.name + ".dispatch.json")
        assert claim.stat().st_mode & 0o777 == 0o600 and json.loads(claim.read_text())["retry_allowed"] is False
        with pytest.raises(acceptance.IsolatedFolderPolicyTransitionMcpOAuthAcceptanceError): run(operation, True)
    assert state.transport.writes == 2 and state.revoked == 4


def test_uncertain_client_attempt_cannot_reconfirm_or_dispatch_again(harness, tmp_path):
    state, run = harness
    run()
    state.transport.fail = "raise"
    with pytest.raises(acceptance.IsolatedFolderPolicyTransitionMcpOAuthAcceptanceError): run(execute=True)
    count = len(state.calls)
    assert (tmp_path / "assign.json.dispatch.json").exists()
    with pytest.raises(acceptance.IsolatedFolderPolicyTransitionMcpOAuthAcceptanceError): run(execute=True)
    assert len(state.calls) == count and state.transport.writes == 0


@pytest.mark.parametrize("fault", ("private_dto", "tool_surface", "wrong_phase_state", "permissions"))
def test_source_or_local_state_refusal_does_not_reach_confirmation(harness, tmp_path, fault):
    state, run = harness
    if fault == "private_dto": state.transform = lambda name, value: value.update(private_folder_id="synthetic-private")
    if fault == "tool_surface": state.omitted = next(iter(acceptance.ASSIGN_TOOLS))
    if fault in {"private_dto", "tool_surface"}:
        with pytest.raises(acceptance.IsolatedFolderPolicyTransitionMcpOAuthAcceptanceError): run()
    else:
        run()
        path = tmp_path / "assign.json"
        if fault == "wrong_phase_state":
            value = json.loads(path.read_text()); value["operation"] = "restore"; path.write_text(json.dumps(value))
        else: path.chmod(0o644)
        with pytest.raises(acceptance.IsolatedFolderPolicyTransitionMcpOAuthAcceptanceError): run(execute=True)
    assert state.transport.writes == 0
    assert all(not name.startswith("confirm_") for name in state.calls)
