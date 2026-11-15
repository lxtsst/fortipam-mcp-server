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

import pytest

from scripts import v4_https_oauth_acceptance as oauth
from scripts import v4_ldap_server_mcp_oauth_acceptance as create_client
from scripts import v4_apl_role_update_mcp_oauth_acceptance as acceptance
from test_apl_role_update_http_transport import Fixture, fixture as fixture, run
from test_apl_role_update_live_workflow import IDENTITY, make, owned as owned
from test_v4_ldap_server_mcp_oauth_acceptance import _payloads as _create_payloads


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 100.0)


def _payloads(phase: str) -> dict[str, dict[str, Any]]:
    preview_tool, authorize_tool, execute_tool = acceptance._tools(phase)
    preview = {
        "contract": acceptance.CONTRACT, "phase": phase, "policy_mode": "lab_auto",
        "preview_ref": "apl-role-preview-" + "a" * 64, "expires_at": 160,
        "Current State": {"original_creation_ownership_verified": True,
            "zero_references_verified": True, "complete_bound_state_verified": True},
        "Proposed Changes": {"operation": phase + "_apl_role", "field": "accprofile",
            "mapping": "original_role" if phase == "restore" else "bound_updated_role",
            "rule_remains_disabled": True},
        "Expected State": {"complete_bound_state_verified": True,
            "original_state_restored": phase == "restore", "rule_order_and_dependencies_preserved": True},
        "device_write_executed": False,
    }
    authorized = {"contract": acceptance.CONTRACT, "phase": phase, "policy_mode": "lab_auto",
        "authorization_ref": "apl-role-auth-" + "b" * 64, "expires_at": 160}
    # Reuse the existing synthetic M4 result, with the new exact phase contract.
    result = {**_create_payloads()[create_client.EXECUTE_TOOL], "contract": acceptance.CONTRACT, "phase": phase}
    return {preview_tool: preview, authorize_tool: authorized, execute_tool: result}


@pytest.mark.parametrize("phase", ["update", "restore"])
@pytest.mark.parametrize("failure", [None, "oauth", "tools", "other_phase", "preview", "authorization",
    "execute", "cancelled", "no_op", "result", "cleanup", "cleanup_exception", "file_fsync",
    "directory_fsync", "expired_before_execute", "error_reply"])
def test_one_phase_dispatch_preserves_claim_and_cleans_tokens_and_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, phase: str, failure: str | None,
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
    calls: list[str] = []
    cleanups: list[bool] = []
    syncs: list[str] = []
    if failure == "preview":
        payloads[preview_tool]["raw"] = "private-source-value"
    elif failure == "authorization":
        payloads[authorize_tool]["phase"] = "restore" if phase == "update" else "update"
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
                names.update(acceptance._tools("restore" if phase == "update" else "update"))
            return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in names])

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
        return asyncio.run(acceptance.run_apl_role_update_mcp_oauth_acceptance(
            "https://synthetic.example.test/mcp", login, tmp_path / "client.json", marker, phase=phase))

    if failure is not None:
        with pytest.raises(acceptance.AplRoleUpdateMcpOAuthAcceptanceError) as caught:
            run()
        rendered = str(caught.value)
        assert "private-" not in rendered and "apl-role-" not in rendered
        assert "retry_allowed=false" in rendered
        assert f"dispatch_reserved={str(marker.exists()).lower()}" in rendered
    else:
        result = run()
        assert result["phase"] == phase
        assert result["fixed_readback_verified"] is result["rule_order_and_dependencies_preserved"] is True
        assert result["role_mapping_updated"] is result["owner_restore_required"] is (phase == "update")
        assert result["original_state_restored"] is (phase == "restore")
        assert result["token_revoked"] is result["revoked_access_rejected"] is True
        assert "private-" not in json.dumps(result) and "apl-role-" not in json.dumps(result)
    assert acceptance.LOGIN_USERNAME not in os.environ and acceptance.LOGIN_PASSWORD not in os.environ
    assert cleanups == ([] if failure == "oauth" else [True])
    expected_execute = failure in {None, "execute", "cancelled", "no_op", "result", "cleanup", "cleanup_exception"}
    assert calls.count(execute_tool) == int(expected_execute)
    if marker.exists():
        before = list(calls)
        with pytest.raises(acceptance.AplRoleUpdateMcpOAuthAcceptanceError):
            run()
        assert calls == before


@pytest.mark.parametrize("phase", ["update", "restore"])
@pytest.mark.parametrize("failure", ["expired", "float", "boolean_expiry", "extended", "wrong_phase",
    "wrong_ref", "wrong_field", "wrong_value", "false_readback", "extra", "nested_extra", "integer_boolean"])
def test_preview_requires_exact_phase_state_and_expiry(phase: str, failure: str) -> None:
    body = copy.deepcopy(_payloads(phase)[acceptance._tools(phase)[0]])
    if failure in {"expired", "float", "boolean_expiry", "extended"}:
        body["expires_at"] = {"expired": 100, "float": 160.0, "boolean_expiry": True, "extended": 161}[failure]
    elif failure == "wrong_phase":
        body["phase"] = "restore" if phase == "update" else "update"
    elif failure == "wrong_ref":
        body["preview_ref"] = "ldap-preview-" + "a" * 64
    elif failure == "wrong_field":
        body["Proposed Changes"]["field"] = "password"
    elif failure == "wrong_value":
        body["Proposed Changes"]["mapping"] = "unbound_role"
    elif failure == "false_readback":
        body["Expected State"]["rule_order_and_dependencies_preserved"] = False
    elif failure == "extra":
        body["raw"] = "private-source-value"
    elif failure == "nested_extra":
        body["Current State"]["entry"] = "private-selector"
    else:
        body["Current State"]["zero_references_verified"] = 1
    with pytest.raises(acceptance.AplRoleUpdateMcpOAuthAcceptanceError):
        acceptance._validate_preview(body, phase)


@pytest.mark.parametrize("phase", ["update", "restore"])
@pytest.mark.parametrize("field,value", [
    ("contract", "another-contract"), ("phase", "create"), ("policy_mode", "manual"),
    ("authorization_ref", "ldap-auth-" + "a" * 64), ("expires_at", 159), ("expires_at", 160.0), ("raw", "private-value"),
])
def test_authorization_cannot_change_bound_phase_or_expiry(phase: str, field: str, value: Any) -> None:
    preview_tool, authorize_tool, _ = acceptance._tools(phase)
    payloads = _payloads(phase)
    payloads[authorize_tool][field] = value
    with pytest.raises(acceptance.AplRoleUpdateMcpOAuthAcceptanceError):
        acceptance._validate_authorization(payloads[authorize_tool], payloads[preview_tool], phase)


@pytest.mark.parametrize("phase", ["update", "restore"])
@pytest.mark.parametrize("field,value", [
    ("phase", "create"), ("idempotent_replay", True), ("idempotent_replay", 0),
    ("verification", False), ("outcome", "reconciliation_required"),
    ("compensation", "verified"), ("raw", "private-value"),
])
def test_execution_needs_a_fresh_verified_phase_result(phase: str, field: str, value: Any) -> None:
    body = _payloads(phase)[acceptance._tools(phase)[2]]
    body[field] = value
    with pytest.raises(acceptance.AplRoleUpdateMcpOAuthAcceptanceError):
        acceptance._validate_execution(body, phase)


@pytest.mark.parametrize("phase", ["create", "UPDATE", "", None, ["update"]])
def test_invalid_phase_refuses_before_login_and_clears_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, phase: Any,
) -> None:
    monkeypatch.setenv(acceptance.LOGIN_USERNAME, "synthetic-user")
    monkeypatch.setenv(acceptance.LOGIN_PASSWORD, "synthetic-login")
    monkeypatch.setattr(acceptance, "load_prefixed_environment_file", lambda *args, **kwargs: pytest.fail("Loaded login"))
    with pytest.raises(acceptance.AplRoleUpdateMcpOAuthAcceptanceError):
        asyncio.run(acceptance.run_apl_role_update_mcp_oauth_acceptance(
            "https://synthetic.example.test/mcp", tmp_path / "login", tmp_path / "client", tmp_path / "marker", phase=phase))
    assert acceptance.LOGIN_USERNAME not in os.environ and acceptance.LOGIN_PASSWORD not in os.environ


def test_dispatch_marker_is_phase_bound_and_cannot_be_reused_for_restore(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    marker = tmp_path / "dispatch.json"
    acceptance._reserve_dispatch(marker, "update")
    before = marker.read_bytes()
    with pytest.raises(create_client.LdapServerMcpOAuthAcceptanceError):
        acceptance._reserve_dispatch(marker, "restore")
    assert marker.read_bytes() == before
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(create_client.LdapServerMcpOAuthAcceptanceError):
        acceptance._reserve_dispatch(alias / "new.json", "restore")


def test_actual_workflow_public_contract_matches_both_client_phases(tmp_path: Path, owned: Fixture) -> None:
    creation, peer, _ = owned
    original = {path.name: path.read_bytes() for path in creation.iterdir()}
    for phase in ("update", "restore"):
        workflow = make(tmp_path, owned, phase)
        preview = workflow.preview(**IDENTITY)
        acceptance._validate_preview(preview, phase)
        authorization = workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
        acceptance._validate_authorization(authorization, preview, phase)
        result = workflow.execute(cast(str, authorization["authorization_ref"]), **IDENTITY)
        acceptance._validate_execution(result, phase)
        replay = workflow.execute(cast(str, authorization["authorization_ref"]), **IDENTITY)
        with pytest.raises(acceptance.AplRoleUpdateMcpOAuthAcceptanceError):
            acceptance._validate_execution(replay, phase)
    assert peer.writes == ["POST", "PUT", "PUT"]
    assert peer.created == peer.original
    assert all((creation / name).read_bytes() == value for name, value in original.items())
    assert all(not body for body in peer.bodies)
    run(owned, "delete")
