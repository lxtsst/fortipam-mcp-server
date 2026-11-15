"""Offline OAuth/MCP client contract and durable dispatch tests."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import copy
import inspect
import json
import os
from pathlib import Path
import stat
import time
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import v4_ldap_server_mcp_oauth_acceptance as acceptance
from scripts import v4_https_oauth_acceptance as oauth


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 100.0)


def _payloads() -> dict[str, dict[str, Any]]:
    preview = {
        "contract": acceptance.CONTRACT, "policy_mode": "lab_auto",
        "preview_ref": "ldap-preview-" + "a" * 64, "expires_at": 160,
        "Current State": {"bound_entry_absent": True, "schema_defaults_qualified": True, "pinned_ca_verified": True},
        "Proposed Changes": {"operation": "create_ldap_server", "scope": "privately_bound_lab_fixture",
            "secure": "ldaps", "port": 636, "server_identity_check": True},
        "Expected State": {"exact_owned_entry_verified": True, "existing_entries_preserved": True},
        "device_write_executed": False,
    }
    authorized = {"contract": acceptance.CONTRACT, "policy_mode": "lab_auto",
                  "authorization_ref": "ldap-auth-" + "b" * 64, "expires_at": 160}
    result = {"contract": acceptance.CONTRACT, "outcome": "succeeded", "verification": "verified",
              "compensation": "not_requested", "idempotent_replay": False}
    return {acceptance.PREVIEW_TOOL: preview, acceptance.AUTHORIZE_TOOL: authorized, acceptance.EXECUTE_TOOL: result}


@pytest.mark.parametrize("failure", [None, "oauth", "tools", "preview", "authorization", "execute", "result",
    "cleanup", "cleanup_exception", "file_fsync", "directory_fsync", "expired_before_execute", "error_reply"])
def test_one_shot_flow_revoke_and_non_disclosing_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str | None,
) -> None:
    tmp_path.chmod(0o700)
    marker = tmp_path / "dispatch.json"
    payloads = _payloads()
    calls: list[str] = []
    cleanups: list[bool] = []
    syncs: list[str] = []
    if failure == "preview":
        payloads[acceptance.PREVIEW_TOOL]["raw"] = "private-source-value"
    if failure == "authorization":
        payloads[acceptance.AUTHORIZE_TOOL]["expires_at"] = 159
    if failure == "result":
        payloads[acceptance.EXECUTE_TOOL]["outcome"] = "reconciliation_required"

    class Session:
        async def initialize(self) -> None:
            calls.append("initialize")

        async def list_tools(self) -> Any:
            names = acceptance.TOOLS - ({acceptance.EXECUTE_TOOL} if failure == "tools" else set())
            return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in names])

        async def call_tool(self, name: str, arguments: dict[str, object]) -> Any:
            calls.append(name)
            if name == acceptance.PREVIEW_TOOL:
                assert arguments == {}
            elif name == acceptance.AUTHORIZE_TOOL:
                assert arguments == {"preview_ref": payloads[acceptance.PREVIEW_TOOL]["preview_ref"]}
            elif name == acceptance.EXECUTE_TOOL:
                assert arguments == {"authorization_ref": payloads[acceptance.AUTHORIZE_TOOL]["authorization_ref"]}
                assert marker.exists() and marker.stat().st_mode & 0o777 == 0o600
                assert syncs == ["file", "directory"]
                assert json.loads(marker.read_text())["retry_allowed"] is False
                if failure == "execute":
                    raise RuntimeError("private-source-value")
            return SimpleNamespace(is_error=failure == "error_reply", structured_content=payloads[name])

    @asynccontextmanager
    async def session(*args: Any) -> AsyncIterator[Session]:
        yield Session()

    async def token(*args: Any, **kwargs: Any) -> tuple[str, bool, bool, str]:
        calls.append("token")
        assert kwargs["include_operation_scope"] is True
        if failure == "oauth":
            raise RuntimeError("private-login-value")
        return "private-token-value", False, True, "private-client-value"

    async def revoke(*args: Any) -> bool:
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
    monkeypatch.setattr(acceptance, "load_prefixed_environment_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(oauth, "_required_login_value", lambda name: "private-login-value")

    def run() -> dict[str, object]:
        return asyncio.run(acceptance.run_ldap_server_mcp_oauth_acceptance(
            "https://synthetic.example.test/mcp", tmp_path / "login.env", tmp_path / "client.json", marker))

    if failure is not None:
        with pytest.raises(acceptance.LdapServerMcpOAuthAcceptanceError) as caught:
            run()
        rendered = str(caught.value)
        assert "private-" not in rendered and "ldap-preview-" not in rendered and "ldap-auth-" not in rendered
        assert "retry_allowed=false" in rendered
        assert f"dispatch_reserved={str(marker.exists()).lower()}" in rendered
    else:
        result = run()
        assert result["ldap_created"] is result["fixed_readback_verified"] is True
        assert result["ldap_cleanup_completed"] is False and result["owner_recovery_required"] is True
        assert result["token_revoked"] is result["revoked_access_rejected"] is True
        assert "private-" not in json.dumps(result)
        assert "ldap-preview-" not in json.dumps(result) and "ldap-auth-" not in json.dumps(result)
    assert cleanups == ([] if failure == "oauth" else [True])
    expected_execute = failure in {None, "execute", "result", "cleanup", "cleanup_exception"}
    assert calls.count(acceptance.EXECUTE_TOOL) == int(expected_execute)
    if marker.exists():
        before = list(calls)
        with pytest.raises(acceptance.LdapServerMcpOAuthAcceptanceError):
            run()
        assert calls == before


@pytest.mark.parametrize("mutation", ["expired", "float", "nan", "bool_expiry", "extended", "boolean",
    "raw", "extra", "wrong_ref", "uppercase_ref", "short_ref", "ldaps", "port", "policy"])
def test_preview_requires_exact_cpe_and_integer_short_ttl(mutation: str) -> None:
    preview = copy.deepcopy(_payloads()[acceptance.PREVIEW_TOOL])
    if mutation in {"expired", "float", "nan", "bool_expiry", "extended"}:
        preview["expires_at"] = {"expired": 100, "float": 160.0, "nan": float("nan"),
                                 "bool_expiry": True, "extended": 161}[mutation]
    elif mutation == "boolean":
        preview["Current State"]["bound_entry_absent"] = 1
    elif mutation == "raw":
        preview["Current State"]["raw"] = "synthetic-value"
    elif mutation == "extra":
        preview["extra"] = True
    elif mutation in {"wrong_ref", "uppercase_ref", "short_ref"}:
        preview["preview_ref"] = {"wrong_ref": "ldap-auth-" + "a" * 64,
            "uppercase_ref": "ldap-preview-" + "A" * 64, "short_ref": "ldap-preview-" + "a" * 63}[mutation]
    elif mutation == "ldaps":
        preview["Proposed Changes"]["secure"] = "ldap"
    elif mutation == "port":
        preview["Proposed Changes"]["port"] = 636.0
    else:
        preview["policy_mode"] = "manual"
    with pytest.raises(acceptance.LdapServerMcpOAuthAcceptanceError):
        acceptance._validate_preview(preview)


@pytest.mark.parametrize("field,value", [
    ("authorization_ref", "ldap-preview-" + "a" * 64), ("authorization_ref", "ldap-auth-" + "b" * 63),
    ("expires_at", 159), ("expires_at", 160.0), ("policy_mode", "manual"), ("extra", True),
])
def test_authorization_cannot_change_preview_expiry_or_shape(field: str, value: Any) -> None:
    values = _payloads()
    values[acceptance.AUTHORIZE_TOOL][field] = value
    with pytest.raises(acceptance.LdapServerMcpOAuthAcceptanceError):
        acceptance._validate_authorization(values[acceptance.AUTHORIZE_TOOL], values[acceptance.PREVIEW_TOOL])


@pytest.mark.parametrize("field,value", [
    ("idempotent_replay", True), ("idempotent_replay", 0), ("verification", "unknown"),
    ("outcome", "reconciliation_required"), ("compensation", "verified"),
    ("raw", "synthetic-value"), ("contract", "another-contract"),
])
def test_execution_requires_fresh_m4_verified_creation(field: str, value: Any) -> None:
    body = _payloads()[acceptance.EXECUTE_TOOL]
    body[field] = value
    with pytest.raises(acceptance.LdapServerMcpOAuthAcceptanceError):
        acceptance._validate_execution(body)


def test_marker_reservation_is_exclusive_private_and_rejects_alias(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    marker = tmp_path / "dispatch.json"
    acceptance._reserve_dispatch(marker)
    assert marker.stat().st_mode & 0o777 == 0o600
    assert json.loads(marker.read_text()) == {"contract": acceptance.DISPATCH_CONTRACT,
                                            "dispatch_reserved": True, "retry_allowed": False}
    with pytest.raises(acceptance.LdapServerMcpOAuthAcceptanceError):
        acceptance._reserve_dispatch(marker)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(acceptance.LdapServerMcpOAuthAcceptanceError):
        acceptance._new_dispatch_path(alias / "new-marker.json")
    tmp_path.chmod(0o750)
    with pytest.raises(acceptance.LdapServerMcpOAuthAcceptanceError):
        acceptance._new_dispatch_path(tmp_path / "new-marker.json")


def test_cli_contract_matches_actual_workflow_and_tool_registration(tmp_path: Path) -> None:
    from fortipam_mcp.ldap_server_contract import CONTRACT
    from fortipam_mcp.ldap_server_mcp_action import register_ldap_server_candidate_tools
    from test_ldap_server_live_workflow import IDENTITY, _setup

    assert acceptance.CONTRACT == CONTRACT
    registered = inspect.getsource(register_ldap_server_candidate_tools)
    assert all(name in registered for name in acceptance.TOOLS)
    workflow, loader, peer, _, _ = _setup(tmp_path)
    preview = workflow.preview(**IDENTITY)
    acceptance._validate_preview(preview)
    authorization = workflow.authorize(preview["preview_ref"], **IDENTITY)
    acceptance._validate_authorization(authorization, preview)
    assert loader.loads == peer.posts == 0
    result = workflow.execute(authorization["authorization_ref"], **IDENTITY)
    acceptance._validate_execution(result)
    assert loader.loads == peer.posts == 1 and peer.deletes == 0
