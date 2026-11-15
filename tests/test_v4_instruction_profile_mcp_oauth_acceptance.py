"""Offline fixed-phase OAuth/MCP acceptance, expiry and no-replay checks."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import copy
import json
import os
from pathlib import Path
import stat
import time
from types import SimpleNamespace
from typing import Any, cast
import urllib.request

import anyio
import pytest
from mcp import ClientSession, types

from scripts import v4_https_oauth_acceptance as oauth
from scripts import v4_ldap_server_mcp_oauth_acceptance as create_client
from scripts import v4_instruction_profile_mcp_oauth_acceptance as acceptance
from test_instruction_profile_http_transport import Fixture, fixture as fixture, run
from test_instruction_profile_live_workflow import IDENTITY, make, owned as owned
from test_v4_ldap_server_mcp_oauth_acceptance import _payloads as _create_payloads


@pytest.mark.parametrize("phase", ["create", "delete"])
def test_rich_acceptance_requires_explicit_contract_through_every_stage(phase: str, tmp_path: Path) -> None:
    preview_tool, authorize_tool, execute_tool = acceptance._tools(phase)
    payloads = _payloads(phase)
    for value in payloads.values():
        value["contract"] = acceptance.RICH_CONTRACT
    preview, authorized, executed = (payloads[key] for key in (preview_tool, authorize_tool, execute_tool))
    preview["Proposed Changes"]["operation"] = phase + "_rich_structure_instruction_profile"
    acceptance._validate_preview(preview, phase, acceptance.RICH_CONTRACT)
    acceptance._validate_authorization(authorized, preview, phase, acceptance.RICH_CONTRACT)
    acceptance._validate_execution(executed, phase, acceptance.RICH_CONTRACT)
    for operation, args in ((acceptance._validate_preview, (preview, phase)),
            (acceptance._validate_authorization, (authorized, preview, phase)),
            (acceptance._validate_execution, (executed, phase))):
        with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError):
            operation(*args)
    tmp_path.chmod(0o700)
    marker = tmp_path / "dispatch.json"
    acceptance._reserve_dispatch(marker, phase, acceptance.RICH_CONTRACT)
    assert json.loads(marker.read_text())["content_contract"] == acceptance.RICH_CONTRACT
    with pytest.raises(Exception):
        acceptance._reserve_dispatch(marker, phase)
    previous = "fortipam-700-build29-instruction-profile-rich-structure-private-v1"
    for operation, args in ((acceptance._validate_preview, (preview, phase, previous)),
            (acceptance._validate_authorization, (authorized, preview, phase, previous)),
            (acceptance._validate_execution, (executed, phase, previous))):
        with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError):
            operation(*args)
    unused = tmp_path / "prior-revision.json"
    with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError):
        acceptance._reserve_dispatch(unused, phase, previous)
    assert not unused.exists()


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 100.0)


def _payloads(phase: str) -> dict[str, dict[str, Any]]:
    preview_tool, authorize_tool, execute_tool = acceptance._tools(phase)
    preview = {
        "contract": acceptance.CONTRACT, "phase": phase, "policy_mode": "lab_auto",
        "preview_ref": "instruction-profile-preview-" + "a" * 64, "expires_at": 160,
        "Current State": {"bound_profile_absent": phase == "create",
            "original_creation_ownership_verified": phase == "delete",
            "complete_state_and_definitions_verified": True},
        "Proposed Changes": {"operation": phase + "_plain_text_instruction_profile",
            "content_privately_bound": True, "resource_upload": False,
            "secret_attachment": False, "feature_change": False},
        "Expected State": {"owned_zero_reference_profile_verified": phase == "create",
            "original_creation_records_preserved": True, "bound_profile_absent": phase == "delete"},
        "device_write_executed": False,
    }
    authorized = {"contract": acceptance.CONTRACT, "phase": phase, "policy_mode": "lab_auto",
        "authorization_ref": "instruction-profile-auth-" + "b" * 64, "expires_at": 160}
    # Reuse the existing synthetic M4 result, with the new exact phase contract.
    result = {**_create_payloads()[create_client.EXECUTE_TOOL], "contract": acceptance.CONTRACT, "phase": phase}
    return {preview_tool: preview, authorize_tool: authorized, execute_tool: result}


@pytest.mark.parametrize("phase", ["create", "delete"])
@pytest.mark.parametrize("content_contract", [acceptance.CONTRACT, acceptance.RICH_CONTRACT])
@pytest.mark.parametrize("failure", [None, "oauth", "tools", "other_phase", "preview", "authorization",
    "execute", "cancelled", "no_op", "result", "cleanup", "cleanup_exception", "file_fsync",
    "directory_fsync", "expired_before_execute", "error_reply"])
def test_one_phase_dispatch_preserves_claim_and_cleans_tokens_and_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, phase: str, content_contract: str, failure: str | None,
) -> None:
    tmp_path.chmod(0o700)
    login = tmp_path / "login.env"
    login.write_text(f"{acceptance.LOGIN_USERNAME}=synthetic-user\n{acceptance.LOGIN_PASSWORD}=synthetic-login\n")
    login.chmod(0o600)
    monkeypatch.setenv(acceptance.LOGIN_USERNAME, "stale-user")
    monkeypatch.setenv(acceptance.LOGIN_PASSWORD, "stale-login")
    marker = tmp_path / "dispatch.json"
    preview_tool, authorize_tool, execute_tool = acceptance._tools(phase)
    payloads = _payloads(phase)
    if content_contract == acceptance.RICH_CONTRACT:
        for value in payloads.values():
            value["contract"] = content_contract
        payloads[preview_tool]["Proposed Changes"]["operation"] = phase + "_rich_structure_instruction_profile"
    calls: list[str] = []
    cleanups: list[bool] = []
    syncs: list[str] = []
    if failure == "preview":
        payloads[preview_tool]["raw"] = "private-source-value"
    elif failure == "authorization":
        payloads[authorize_tool]["phase"] = "delete" if phase == "create" else "create"
    elif failure == "no_op":
        payloads[execute_tool]["verification"] = False
    elif failure == "result":
        payloads[execute_tool]["raw"] = "private-source-value"

    class Session:
        async def initialize(self) -> None:
            assert acceptance.LOGIN_USERNAME not in os.environ
            assert acceptance.LOGIN_PASSWORD not in os.environ
            calls.append("initialize")

        async def list_tools(self) -> Any:
            names = set(acceptance._tools(phase))
            if failure == "tools":
                names.remove(execute_tool)
            elif failure == "other_phase":
                names.update(acceptance._tools("delete" if phase == "create" else "create"))
            return SimpleNamespace(tools=[SimpleNamespace(name=name, input_schema={"type": "object"},
                output_schema={"type": "object"}) for name in names])

        async def call_tool(self, name: str, arguments: dict[str, object]) -> Any:
            calls.append(name)
            if name == preview_tool:
                assert arguments == {}
            elif name == authorize_tool:
                assert arguments == {"preview_ref": payloads[preview_tool]["preview_ref"]}
            elif name == execute_tool:
                assert arguments == {"authorization_ref": payloads[authorize_tool]["authorization_ref"]}
                assert marker.stat().st_mode & 0o777 == 0o600
                assert syncs == ["file", "directory"]
                assert json.loads(marker.read_text()) == {"contract": acceptance.DISPATCH_CONTRACT,
                    **({"content_contract": content_contract} if content_contract != acceptance.CONTRACT else {}),
                    "phase": phase, "dispatch_reserved": True, "retry_allowed": False}
                if failure == "execute":
                    raise RuntimeError("private-source-value")
                if failure == "cancelled":
                    raise asyncio.CancelledError("private-source-value")
            return SimpleNamespace(is_error=failure == "error_reply", structured_content=payloads[name])

    @asynccontextmanager
    async def session(*args: Any) -> AsyncIterator[Session]:
        yield Session()

    async def token(*args: Any, **kwargs: Any) -> tuple[str, bool, bool, str]:
        calls.append("token")
        assert kwargs["include_operation_scope"] is True
        assert kwargs["username"] == "synthetic-user" and kwargs["password"] == "synthetic-login"
        if failure == "oauth":
            raise RuntimeError("private-login-value")
        return "private-token-value", False, True, "private-client-value"

    async def revoke(*args: Any) -> bool:
        assert acceptance.LOGIN_USERNAME not in os.environ
        assert acceptance.LOGIN_PASSWORD not in os.environ
        cleanups.append(True)
        if failure == "cleanup_exception":
            raise RuntimeError("private-source-value")
        return failure != "cleanup"

    real_fsync = os.fsync

    def fsync(descriptor: int) -> None:
        kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
        syncs.append(kind)
        if failure == kind + "_fsync":
            raise OSError("private-source-value")
        real_fsync(descriptor)
        if failure == "expired_before_execute" and kind == "directory":
            monkeypatch.setattr(time, "time", lambda: 160.0)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(oauth, "_mcp_session", session)
    monkeypatch.setattr(oauth, "_oauth_token", token)
    monkeypatch.setattr(oauth, "_revoke_and_prove_401", revoke)

    def run() -> dict[str, object]:
        return asyncio.run(acceptance.run_instruction_profile_mcp_oauth_acceptance(
            "https://synthetic.example.test/mcp", login, tmp_path / "client.json", marker,
            phase=phase, content_contract=content_contract))

    if failure is not None:
        with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError) as caught:
            run()
        rendered = str(caught.value)
        assert "private-" not in rendered and "instruction-profile-" not in rendered
        assert "retry_allowed=false" in rendered
        assert f"dispatch_reserved={str(marker.exists()).lower()}" in rendered
    else:
        result = run()
        assert result["phase"] == phase
        assert result["fixed_readback_verified"] is True
        assert result["profile_created"] is result["owner_cleanup_required"] is (phase == "create")
        assert result["owned_profile_absent"] is (phase == "delete")
        assert result["token_revoked"] is result["revoked_access_rejected"] is True
        if content_contract == acceptance.RICH_CONTRACT:
            assert result.pop("content_contract") == content_contract
        assert "private-" not in json.dumps(result) and "instruction-profile-" not in json.dumps(result)
    assert acceptance.LOGIN_USERNAME not in os.environ and acceptance.LOGIN_PASSWORD not in os.environ
    assert cleanups == ([] if failure == "oauth" else [True])
    expected_execute = failure in {None, "execute", "cancelled", "no_op", "result", "cleanup", "cleanup_exception"}
    assert calls.count(execute_tool) == int(expected_execute)
    if marker.exists():
        before = list(calls)
        with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError):
            run()
        assert calls == before


@pytest.mark.parametrize("phase", ["create", "delete"])
@pytest.mark.parametrize("failure", ["expired", "float", "boolean_expiry", "extended", "wrong_phase",
    "wrong_ref", "wrong_field", "wrong_value", "false_readback", "extra", "nested_extra", "integer_boolean"])
def test_preview_requires_exact_phase_state_and_expiry(phase: str, failure: str) -> None:
    body = copy.deepcopy(_payloads(phase)[acceptance._tools(phase)[0]])
    if failure in {"expired", "float", "boolean_expiry", "extended"}:
        body["expires_at"] = {"expired": 100, "float": 160.0, "boolean_expiry": True, "extended": 161}[failure]
    elif failure == "wrong_phase":
        body["phase"] = "delete" if phase == "create" else "create"
    elif failure == "wrong_ref":
        body["preview_ref"] = "ldap-preview-" + "a" * 64
    elif failure == "wrong_field":
        body["Proposed Changes"]["operation"] = "arbitrary"
    elif failure == "wrong_value":
        body["Proposed Changes"]["resource_upload"] = True
    elif failure == "false_readback":
        body["Expected State"]["original_creation_records_preserved"] = False
    elif failure == "extra":
        body["raw"] = "private-source-value"
    elif failure == "nested_extra":
        body["Current State"]["entry"] = "private-selector"
    else:
        body["Current State"]["complete_state_and_definitions_verified"] = 1
    with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError):
        acceptance._validate_preview(body, phase)


@pytest.mark.parametrize("phase", ["create", "delete"])
@pytest.mark.parametrize("field,value", [
    ("contract", "another-contract"), ("phase", "update"), ("policy_mode", "manual"),
    ("authorization_ref", "ldap-auth-" + "a" * 64), ("expires_at", 159), ("expires_at", 160.0), ("raw", "private-value"),
])
def test_authorization_cannot_change_bound_phase_or_expiry(phase: str, field: str, value: Any) -> None:
    preview_tool, authorize_tool, _ = acceptance._tools(phase)
    payloads = _payloads(phase)
    payloads[authorize_tool][field] = value
    with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError):
        acceptance._validate_authorization(payloads[authorize_tool], payloads[preview_tool], phase)


@pytest.mark.parametrize("phase", ["create", "delete"])
@pytest.mark.parametrize("field,value", [
    ("phase", "update"), ("idempotent_replay", True), ("idempotent_replay", 0),
    ("verification", False), ("outcome", "reconciliation_required"),
    ("compensation", "verified"), ("raw", "private-value"),
])
def test_execution_needs_a_fresh_verified_phase_result(phase: str, field: str, value: Any) -> None:
    body = _payloads(phase)[acceptance._tools(phase)[2]]
    body[field] = value
    with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError):
        acceptance._validate_execution(body, phase)


@pytest.mark.parametrize("phase", ["update", "CREATE", "", None, ["create"]])
def test_invalid_phase_refuses_before_login_and_clears_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, phase: Any,
) -> None:
    monkeypatch.setenv(acceptance.LOGIN_USERNAME, "synthetic-user")
    monkeypatch.setenv(acceptance.LOGIN_PASSWORD, "synthetic-login")
    monkeypatch.setattr(acceptance, "load_prefixed_environment_file", lambda *args, **kwargs: pytest.fail("Loaded login"))
    with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError):
        asyncio.run(acceptance.run_instruction_profile_mcp_oauth_acceptance(
            "https://synthetic.example.test/mcp", tmp_path / "login", tmp_path / "client", tmp_path / "marker", phase=phase))
    assert acceptance.LOGIN_USERNAME not in os.environ and acceptance.LOGIN_PASSWORD not in os.environ


def test_dispatch_marker_is_phase_bound_and_cannot_be_reused_for_delete(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    marker = tmp_path / "dispatch.json"
    acceptance._reserve_dispatch(marker, "create")
    before = marker.read_bytes()
    with pytest.raises(create_client.LdapServerMcpOAuthAcceptanceError):
        acceptance._reserve_dispatch(marker, "delete")
    assert marker.read_bytes() == before
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(create_client.LdapServerMcpOAuthAcceptanceError):
        acceptance._reserve_dispatch(alias / "new.json", "delete")


def test_actual_workflow_public_contract_matches_both_client_phases(tmp_path: Path, owned: Fixture) -> None:
    creation, peer, _ = owned
    original = {path.name: path.read_bytes() for path in creation.iterdir()}
    for phase in ("create", "delete"):
        workflow = make(tmp_path, owned, phase)
        preview = workflow.preview(**IDENTITY)
        acceptance._validate_preview(preview, phase)
        authorization = workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
        acceptance._validate_authorization(authorization, preview, phase)
        result = workflow.execute(cast(str, authorization["authorization_ref"]), **IDENTITY)
        acceptance._validate_execution(result, phase)
        replay = workflow.execute(cast(str, authorization["authorization_ref"]), **IDENTITY)
        with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError):
            acceptance._validate_execution(replay, phase)
    assert peer.writes == ["POST", "DELETE"]
    assert peer.created is None
    assert all((creation / name).read_bytes() == value for name, value in original.items())
    assert all(not any(body) for body in peer.bodies)


@pytest.mark.parametrize("keyword", [None, "$ref", "$dynamicRef", "$recursiveRef", "$id", "id",
    "$schema", "$anchor", "$dynamicAnchor"])
@pytest.mark.parametrize("location", ["input", "output"])
def test_sdk_schema_references_refuse_before_tools_and_revoke(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, keyword: str | None, location: str,
) -> None:
    tmp_path.chmod(0o700)
    login = tmp_path / "login.env"
    login.write_text(f"{acceptance.LOGIN_USERNAME}=synthetic-user\n{acceptance.LOGIN_PASSWORD}=synthetic-login\n")
    login.chmod(0o600)
    marker = tmp_path / "dispatch.json"
    payloads = _payloads("create")
    calls: list[str] = []
    retrieved: list[bool] = []
    revoked: list[bool] = []
    listing = types.ListToolsResult(tools=[types.Tool(name=name, input_schema={"type": "object"},
        output_schema={"type": "object"}) for name in acceptance._tools("create")])
    if keyword is not None:
        schema = getattr(listing.tools[0], location + "_schema")
        schema["allOf"] = [{keyword: "relative-schema.json"}]

    # Keep the real SDK listing cache, call_tool and output-schema validator.
    send, receive = anyio.create_memory_object_stream[Any]()
    sdk = ClientSession(receive, send)

    async def initialize() -> None:
        return None

    async def send_request(request: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(request, types.ListToolsRequest):
            return listing
        assert isinstance(request, types.CallToolRequest)
        calls.append(request.params.name)
        return types.CallToolResult(content=[], structured_content=payloads[request.params.name])

    @asynccontextmanager
    async def session(*args: Any) -> AsyncIterator[ClientSession]:
        yield sdk

    async def token(*args: Any, **kwargs: Any) -> tuple[str, bool, bool, str]:
        return "synthetic-token", True, True, "synthetic-client"

    async def revoke(*args: Any) -> bool:
        revoked.append(True)
        return True

    def retrieve(*args: Any, **kwargs: Any) -> Any:
        retrieved.append(True)
        raise AssertionError("Unexpected external schema retrieval")

    monkeypatch.setattr(sdk, "initialize", initialize)
    monkeypatch.setattr(sdk, "send_request", send_request)
    monkeypatch.setattr(urllib.request, "urlopen", retrieve)
    monkeypatch.setattr(oauth, "_mcp_session", session)
    monkeypatch.setattr(oauth, "_oauth_token", token)
    monkeypatch.setattr(oauth, "_revoke_and_prove_401", revoke)
    pending = acceptance.run_instruction_profile_mcp_oauth_acceptance(
        "https://synthetic.example.test/mcp", login, tmp_path / "client.json", marker, phase="create")
    if keyword is None:
        assert asyncio.run(pending)["fixed_readback_verified"] is True
        assert calls == list(acceptance._tools("create")) and marker.is_file()
    else:
        with pytest.raises(acceptance.InstructionProfileMcpOAuthAcceptanceError):
            asyncio.run(pending)
        assert calls == [] and not marker.exists()
    assert retrieved == [] and revoked == [True]
    assert acceptance.LOGIN_USERNAME not in os.environ and acceptance.LOGIN_PASSWORD not in os.environ
