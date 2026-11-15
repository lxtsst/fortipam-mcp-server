"""Explicit local MCP registration over synthetic qualified snapshots; no network."""
from __future__ import annotations

import asyncio
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from fortipam_mcp.isolated_folder_policy_transition_contract import IsolatedFolderPolicyTransitionReadback
from fortipam_mcp.isolated_folder_policy_transition_live_workflow import IsolatedFolderPolicyTransitionLiveWorkflow
from fortipam_mcp.isolated_folder_policy_transition_mcp_action import (
    ASSIGN_TOOLS, RESTORE_TOOLS, TOOLS, UNAVAILABLE, IsolatedFolderPolicyTransitionMcpAction,
    IsolatedFolderPolicyTransitionMcpActionError, register_isolated_folder_policy_transition_candidate_tools,
    valid_isolated_folder_policy_transition_ref, validate_isolated_folder_policy_transition_preview,
    validate_isolated_folder_policy_transition_confirmation, validate_isolated_folder_policy_transition_result,
)
from fortipam_mcp.server import FortiPamMcpServer, _harden_mcp_input_validation
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_isolated_folder_policy_transition_live_workflow import Clock, Transport, inspection, POLICY, SERIAL
from test_v4_m3 import _requester

PRINCIPAL = V4PlanningPrincipal(_requester(), "a" * 64)
SENTINEL = "synthetic-private-sentinel"


class BoundTransport(Transport):
    def __init__(self, clock: Clock) -> None:
        super().__init__(clock)
        self.inspections = 0
        self.current = inspection(creator=PRINCIPAL.requester.digest)

    def inspect_transition(self):
        self.inspections += 1
        return super().inspect_transition()

    def _dispatch(self, digest, expiry, clock, phase):
        assert digest == self.current.state_digest
        self.clock.value += self.dispatch_delay
        if clock() >= expiry or self.fail == "raise":
            raise RuntimeError(SENTINEL)
        self.writes += 1
        self.current = inspection(phase, creator=PRINCIPAL.requester.digest)
        return IsolatedFolderPolicyTransitionReadback(True, self.fail != "logout", self.current)


def _candidate(*, gate: bool = True, workflow_gate: bool = True):
    clock = Clock()
    transport = BoundTransport(clock)
    workflow = IsolatedFolderPolicyTransitionLiveWorkflow(transport, execution_enabled=workflow_gate, clock=clock)
    return IsolatedFolderPolicyTransitionMcpAction(workflow, execution_enabled=gate), workflow, transport


def _outputs():
    action, _, transport = _candidate()
    preview = action.preview_transition(PRINCIPAL)
    confirmed = action.confirm_transition(str(preview["preview_ref"]), PRINCIPAL)
    result = action.execute_transition(str(confirmed["authorization_ref"]), PRINCIPAL)
    return action, transport, preview, confirmed, result


def _host(action, *, planning=None, operation=None):
    calls = []
    def principal(kind, selected):
        calls.append(kind)
        return selected or PRINCIPAL
    host = SimpleNamespace(mcp=MCPServer("isolated-policy-candidate"),
        _v4_planning_principal=lambda: principal("planning", planning),
        _v4_folder_action_principal=lambda: principal("operation", operation))
    register_isolated_folder_policy_transition_candidate_tools(host, action)
    _harden_mcp_input_validation(host.mcp)
    return host, calls


def test_default_server_has_no_candidate_and_explicit_registration_has_six_closed_schemas():
    assert len(TOOLS) == 6 and not ASSIGN_TOOLS & RESTORE_TOOLS
    assert not TOOLS & {tool.name for tool in asyncio.run(FortiPamMcpServer().mcp.list_tools())}
    action, _, transport = _candidate()
    host, _ = _host(action)
    listing = asyncio.run(host.mcp.list_tools())
    assert {tool.name for tool in listing} == TOOLS
    for tool in listing:
        expected = set() if tool.name.startswith("preview") else {"preview_ref"} if tool.name.startswith("confirm") else {"authorization_ref"}
        assert set(tool.input_schema.get("properties", {})) == expected
        assert tool.input_schema["additionalProperties"] is False
    assert transport.inspections == transport.writes == 0


def test_local_sdk_assign_and_separate_restore_use_only_designated_principal_getters():
    action, _, transport = _candidate()
    host, calls = _host(action)
    async def scenario():
        with pytest.raises(ToolError):
            await host.mcp.call_tool("preview_v4_isolated_folder_policy_transition_restore_700", {})
        for suffix, operation in (("", "assign"), ("_restore", "restore")):
            preview = (await host.mcp.call_tool(f"preview_v4_isolated_folder_policy_transition{suffix}_700", {})).structured_content
            validate_isolated_folder_policy_transition_preview(preview, operation)
            confirmed = (await host.mcp.call_tool(f"confirm_v4_isolated_folder_policy_transition{suffix}_700",
                {"preview_ref": preview["preview_ref"]})).structured_content
            validate_isolated_folder_policy_transition_confirmation(confirmed, operation, preview["preview_ref"])
            args = {"authorization_ref": confirmed["authorization_ref"]}
            result = (await host.mcp.call_tool(f"execute_confirmed_v4_isolated_folder_policy_transition{suffix}_700", args)).structured_content
            validate_isolated_folder_policy_transition_result(result, operation, require_success=True)
            replay = (await host.mcp.call_tool(f"execute_confirmed_v4_isolated_folder_policy_transition{suffix}_700", args)).structured_content
            assert replay["idempotent_replay"] is True
            public = json.dumps((preview, confirmed, result, replay))
            for private in (SERIAL, POLICY, "Synthetic Isolated Folder", "Synthetic Bound Secret", "synthetic-owner"):
                assert private not in public
    asyncio.run(scenario())
    assert transport.assign_calls == transport.restore_calls == 1 and transport.writes == 2
    assert calls == ["planning", "planning", "operation", "operation", "operation",
                     "planning", "operation", "operation", "operation"]


@pytest.mark.parametrize("gate,workflow_gate", [(False, True), (True, False)])
def test_both_independent_execution_gates_fail_closed(gate, workflow_gate):
    action, _, transport = _candidate(gate=gate, workflow_gate=workflow_gate)
    preview = action.preview_transition(PRINCIPAL)
    confirmed = action.confirm_transition(str(preview["preview_ref"]), PRINCIPAL)
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError, match=UNAVAILABLE):
        action.execute_transition(str(confirmed["authorization_ref"]), PRINCIPAL)
    assert transport.assign_calls == transport.writes == 0


def test_action_default_gate_and_constructor_are_strict():
    _, workflow, transport = _candidate()
    action = IsolatedFolderPolicyTransitionMcpAction(workflow)
    preview = action.preview_transition(PRINCIPAL)
    confirmed = action.confirm_transition(str(preview["preview_ref"]), PRINCIPAL)
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError):
        action.execute_transition(str(confirmed["authorization_ref"]), PRINCIPAL)
    for selected, gate in ((object(), False), (workflow, 1)):
        with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError):
            IsolatedFolderPolicyTransitionMcpAction(selected, execution_enabled=gate)
    host = SimpleNamespace(mcp=MCPServer("invalid-action"))
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError):
        register_isolated_folder_policy_transition_candidate_tools(host, object())
    assert not asyncio.run(host.mcp.list_tools())
    assert transport.writes == 0


@pytest.mark.parametrize("name,args", [
    ("preview_v4_isolated_folder_policy_transition_700", {"folder_id": 23}),
    ("preview_v4_isolated_folder_policy_transition_restore_700", {"policy_name": SENTINEL}),
    ("confirm_v4_isolated_folder_policy_transition_700", {"preview_ref": "isolated-folder-policy-assign-preview-x", "secret_id": 42}),
    ("execute_confirmed_v4_isolated_folder_policy_transition_700", {"authorization_ref": "isolated-folder-policy-assign-authorized-x", "password": SENTINEL}),
])
def test_private_input_expansion_is_denied_before_principal_or_source(name, args):
    action, _, transport = _candidate()
    host, calls = _host(action)
    with pytest.raises(ToolError) as error:
        asyncio.run(host.mcp.call_tool(name, args))
    assert SENTINEL not in str(error.value)
    assert not calls and transport.inspections == transport.writes == 0


@pytest.mark.parametrize("stage", ["preview", "confirm", "execute"])
@pytest.mark.parametrize("principal", [object(), SimpleNamespace(requester=SimpleNamespace(digest="b" * 64))])
def test_nonprincipal_is_rejected_before_workflow(stage, principal):
    action, _, transport = _candidate()
    method, args = {"preview": (action.preview_transition, []),
        "confirm": (action.confirm_transition, ["isolated-folder-policy-assign-preview-x"]),
        "execute": (action.execute_transition, ["isolated-folder-policy-assign-authorized-x"])}[stage]
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError):
        method(*args, principal)
    assert transport.inspections == transport.writes == 0


@pytest.mark.parametrize("stage", ["confirm", "execute"])
@pytest.mark.parametrize("reference", [None, 23, "wrong-ref", "isolated-folder-policy-restore-preview-x",
    "isolated-folder-policy-restore-authorized-x", "isolated-folder-policy-assign-preview-x",
    "isolated-folder-policy-assign-authorized-x", "isolated-folder-policy-assign-preview-" + "a" * 129])
def test_wrong_operation_or_reference_is_denied_without_source(stage, reference):
    action, _, transport = _candidate()
    method = action.confirm_transition if stage == "confirm" else action.execute_transition
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError):
        method(reference, PRINCIPAL)
    assert transport.inspections == transport.writes == 0


def test_real_assign_refs_cannot_be_used_for_restore_and_restart_has_no_restore_authority():
    action, workflow, transport = _candidate()
    preview = action.preview_transition(PRINCIPAL)
    confirmed = action.confirm_transition(str(preview["preview_ref"]), PRINCIPAL)
    for method, reference in ((action.confirm_restore, preview["preview_ref"]),
                              (action.execute_restore, confirmed["authorization_ref"])):
        with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError):
            method(reference, PRINCIPAL)
    assert transport.writes == 0
    action.execute_transition(str(confirmed["authorization_ref"]), PRINCIPAL)
    restarted = IsolatedFolderPolicyTransitionMcpAction(IsolatedFolderPolicyTransitionLiveWorkflow(
        transport, execution_enabled=True, clock=transport.clock), execution_enabled=True)
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError):
        restarted.preview_restore(PRINCIPAL)
    assert action.preview_restore(PRINCIPAL)


@pytest.mark.parametrize("phase", ["preview", "confirmation", "result"])
@pytest.mark.parametrize("defect", ["private", "contract", "operation", "bool_as_int"])
def test_exact_public_dto_rejects_private_fields_and_wrong_shapes(phase, defect):
    _, _, preview, confirmation, result = _outputs()
    values = {"preview": preview, "confirmation": confirmation, "result": result}
    value = deepcopy(values[phase])
    if defect == "private":
        if phase == "preview": value["Current State"]["private_snapshot"] = SENTINEL
        else: value["private_snapshot"] = SENTINEL
    elif defect == "contract": value["contract"] = "wrong-contract"
    elif defect == "operation":
        if phase == "preview": value["Proposed Changes"]["operation"] = "restore"
        elif phase == "confirmation": value["authorization_ref"] = "isolated-folder-policy-restore-authorized-x"
        else: value["operation"] = "restore"
    else:
        if phase == "preview": value["Current State"]["single_secret_verified"] = 1
        elif phase == "confirmation": value["expires_at"] = True
        else: value["private_snapshot_returned"] = 0
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError) as error:
        if phase == "preview": validate_isolated_folder_policy_transition_preview(value, "assign")
        elif phase == "confirmation": validate_isolated_folder_policy_transition_confirmation(value, "assign", str(preview["preview_ref"]))
        else: validate_isolated_folder_policy_transition_result(value, "assign")
    assert SENTINEL not in str(error.value)


@pytest.mark.parametrize("phase", ["preview", "confirm", "execute"])
def test_upstream_exceptions_are_categorical_without_protected_details(monkeypatch, phase):
    action, workflow, transport = _candidate()
    def fail(*args, **kwargs): raise RuntimeError(SENTINEL)
    monkeypatch.setattr(workflow, {"preview": "preview_transition", "confirm": "confirm", "execute": "execute"}[phase], fail)
    method, args = {"preview": (action.preview_transition, []),
        "confirm": (action.confirm_transition, ["isolated-folder-policy-assign-preview-x"]),
        "execute": (action.execute_transition, ["isolated-folder-policy-assign-authorized-x"])}[phase]
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError) as error:
        method(*args, PRINCIPAL)
    assert str(error.value) == UNAVAILABLE and error.value.__suppress_context__
    assert transport.inspections == transport.writes == 0


@pytest.mark.parametrize("phase", ["preview", "confirm", "execute"])
def test_workflow_private_output_cannot_escape_the_action(monkeypatch, phase):
    action, workflow, transport = _candidate()
    monkeypatch.setattr(workflow, {"preview": "preview_transition", "confirm": "confirm", "execute": "execute"}[phase],
        lambda *args, **kwargs: {"private_snapshot": SENTINEL})
    method, args = {"preview": (action.preview_transition, []),
        "confirm": (action.confirm_transition, ["isolated-folder-policy-assign-preview-x"]),
        "execute": (action.execute_transition, ["isolated-folder-policy-assign-authorized-x"])}[phase]
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError) as error:
        method(*args, PRINCIPAL)
    assert str(error.value) == UNAVAILABLE and error.value.__suppress_context__
    assert transport.inspections == transport.writes == 0


def test_registration_fails_closed_when_sdk_schema_protection_is_unavailable():
    class UnsafeMcp:
        def tool(self, **kwargs):
            return lambda function: function
        @property
        def _tool_manager(self):
            raise RuntimeError(SENTINEL)
    action, _, transport = _candidate()
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError) as error:
        register_isolated_folder_policy_transition_candidate_tools(SimpleNamespace(mcp=UnsafeMcp()), action)
    assert str(error.value) == UNAVAILABLE and error.value.__suppress_context__
    assert transport.inspections == transport.writes == 0


@pytest.mark.parametrize("name", ["preview_v4_isolated_folder_policy_transition_700",
    "confirm_v4_isolated_folder_policy_transition_700", "execute_confirmed_v4_isolated_folder_policy_transition_700"])
def test_principal_getter_exception_is_sanitized_before_workflow(name):
    action, _, transport = _candidate()
    host, _ = _host(action)
    def fail(): raise RuntimeError(SENTINEL)
    host._v4_planning_principal = host._v4_folder_action_principal = fail
    args = {} if name.startswith("preview") else {"preview_ref": "isolated-folder-policy-assign-preview-x"} if name.startswith("confirm") else {"authorization_ref": "isolated-folder-policy-assign-authorized-x"}
    with pytest.raises(ToolError) as error:
        asyncio.run(host.mcp.call_tool(name, args))
    assert UNAVAILABLE in str(error.value) and SENTINEL not in str(error.value)
    assert transport.inspections == transport.writes == 0


@pytest.mark.parametrize("fault", ["raise", "logout"])
def test_uncertain_dispatch_stays_consumed_and_cannot_restore(fault):
    action, _, transport = _candidate()
    preview = action.preview_transition(PRINCIPAL)
    confirmed = action.confirm_transition(str(preview["preview_ref"]), PRINCIPAL)
    transport.fail = fault
    result = action.execute_transition(str(confirmed["authorization_ref"]), PRINCIPAL)
    assert result["outcome"] == "reconciliation_required"
    validate_isolated_folder_policy_transition_result(result, "assign")
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError):
        validate_isolated_folder_policy_transition_result(result, "assign", require_success=True)
    transport.fail = None
    assert action.execute_transition(str(confirmed["authorization_ref"]), PRINCIPAL)["idempotent_replay"] is True
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError): action.preview_restore(PRINCIPAL)
    assert transport.assign_calls == 1 and SENTINEL not in json.dumps(result)


def test_reference_validator_has_fixed_operation_kind_and_string_boundary():
    assert valid_isolated_folder_policy_transition_ref("isolated-folder-policy-assign-preview-x", "assign", "preview")
    assert not valid_isolated_folder_policy_transition_ref("isolated-folder-policy-assign-other-x", "assign", "other")
    assert not valid_isolated_folder_policy_transition_ref("isolated-folder-policy-delete-preview-x", "delete", "preview")
