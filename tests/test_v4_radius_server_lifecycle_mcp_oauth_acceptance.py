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

from scripts import v4_radius_server_lifecycle_mcp_oauth_acceptance as acceptance
from scripts import v4_https_oauth_acceptance as oauth


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 100.0)


def _payloads() -> dict[str, dict[str, Any]]:
    preview = {
        "contract": acceptance.CONTRACT, "policy_mode": "lab_auto",
        "preview_ref": "radius-lifecycle-preview-" + "a" * 64, "expires_at": 160,
        "Current State": {"bound_entry_absent": True, "schema_defaults_qualified": True,
            "dual_absence_verified": True, "child_dispatches_unconsumed": True},
        "Proposed Changes": {"operation": "qualify_disposable_radius_primary", "primary_only": True,
            "user_group_associations": False,
            "fixed_sequence": ["create", "owned_native_connect", "original_ack_remove"],
            "material_acquisitions_maximum": 1},
        "Expected State": {"original_m4_success_required": True, "exact_reject_only_response_required": True,
            "full_created_state_preserved": True, "final_dual_absence_required": True,
            "all_candidate_gates_closed": True},
        "device_write_executed": False,
    }
    authorized = {"contract": acceptance.CONTRACT, "policy_mode": "lab_auto",
                  "authorization_ref": "radius-lifecycle-auth-" + "b" * 64, "expires_at": 160}
    result = {"contract": acceptance.CONTRACT, "outcome": "succeeded", "verification": "verified",
              "idempotent_replay": False, "create_verified": True, "native_m4_verified": True,
              "exact_reject_only_response_verified": True, "original_ack_removal_verified": True,
              "private_reject_only_connectivity_verified": True, "user_authentication_verified": False,
              "all_candidate_gates_closed": True, "failure_stage": None}
    return {acceptance.PREVIEW_TOOL: preview, acceptance.AUTHORIZE_TOOL: authorized, acceptance.EXECUTE_TOOL: result}


@pytest.mark.parametrize("mode",["qualify","configure","remove"])
@pytest.mark.parametrize("failure", [None, "oauth", "tools", "preview", "authorization", "execute", "result",
    "cleanup", "cleanup_exception", "file_fsync", "directory_fsync", "expired_before_execute", "error_reply"])
def test_one_shot_flow_revoke_and_non_disclosing_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str | None, mode: str,
) -> None:
    retain=mode=="configure";remove=mode=="remove"
    tmp_path.chmod(0o700)
    marker = tmp_path / "dispatch.json"
    (tmp_path/"client.json").write_text("synthetic-existing-client")
    (tmp_path/"client.json").chmod(0o600)
    (tmp_path/"login.json").write_text(json.dumps({"username":"private-login-value","password":"private-login-value"}))
    (tmp_path/"login.json").chmod(0o600)
    payloads = _payloads()
    ptool,atool,etool=(acceptance.PREVIEW_TOOL,acceptance.AUTHORIZE_TOOL,acceptance.EXECUTE_TOOL)
    if retain:
        preview=payloads[ptool];authorized=payloads[atool];result=payloads[etool]
        for value in (preview,authorized,result):value['contract']=acceptance.PERSISTENT_CONTRACT
        preview['Proposed Changes']['operation']='configure_radius_primary'
        preview['Proposed Changes']['fixed_sequence']=['create','owned_native_connect']
        preview['Expected State'].pop('final_dual_absence_required')
        preview['Expected State'].update(owned_entry_retained=True,independent_original_ack_removal_available=True)
        result.update(owned_entry_retained=True,original_ack_removal_verified=False)
        ptool,atool,etool=acceptance.CONFIGURE_TOOLS
        payloads=dict(zip((ptool,atool,etool),(preview,authorized,result)))
    if remove:
        ptool,atool,etool=tuple(f'{verb}_v4_radius_primary_remove_700' for verb in ('preview','authorize','execute'))
        preview={'contract':acceptance.REMOVAL_CONTRACT,'policy_mode':'lab_auto',
            'preview_ref':'radius-recovery-preview-'+'a'*64,'expires_at':160,
            'Current State':{'original_creation_ack_verified':True,'full_state_unchanged':True,'zero_references':True},
            'Proposed Changes':{'operation':'remove_original_owned_radius_row','material_access':False},
            'Expected State':{'exact_detail_absent':True,'complete_collection_absent':True},'device_write_executed':False}
        authorization={'contract':acceptance.REMOVAL_CONTRACT,'policy_mode':'lab_auto',
            'authorization_ref':'radius-recovery-auth-'+'b'*64,'expires_at':160}
        result={'contract':acceptance.REMOVAL_CONTRACT,'outcome':'succeeded','verification':'verified',
            'compensation':'not_requested','idempotent_replay':False}
        payloads={ptool:preview,atool:authorization,etool:result}
    calls: list[str] = []
    cleanups: list[bool] = []
    syncs: list[str] = []
    if failure == "preview":
        payloads[ptool]["raw"] = "private-source-value"
    if failure == "authorization":
        payloads[atool]["expires_at"] = 159
    if failure == "result":
        payloads[etool]["outcome"] = "reconciliation_required"

    class Session:
        async def initialize(self) -> None:
            calls.append("initialize")

        async def list_tools(self) -> Any:
            names = (set(acceptance.CONFIGURE_TOOLS) | acceptance.REMOVE_TOOLS if retain else (acceptance.REMOVE_TOOLS if remove else acceptance.TOOLS)) - ({etool} if failure == "tools" else set())
            return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in names])

        async def call_tool(self, name: str, arguments: dict[str, object]) -> Any:
            calls.append(name)
            if name == ptool:
                assert arguments == {}
            elif name == atool:
                assert arguments == {"preview_ref": payloads[ptool]["preview_ref"]}
            elif name == etool:
                assert arguments == {"authorization_ref": payloads[atool]["authorization_ref"]}
                assert marker.exists() and marker.stat().st_mode & 0o777 == 0o600
                assert syncs == ["file", "directory"]
                assert json.loads(marker.read_text())["retry_allowed"] is False
                if failure == "execute":
                    raise RuntimeError("private-source-value")
            return SimpleNamespace(is_error=failure == "error_reply", structured_content=payloads[name])

    @asynccontextmanager
    async def session(*args: Any, **kwargs: Any) -> AsyncIterator[Session]:
        assert kwargs["timeout_seconds"] == 300.0
        yield Session()

    async def token(*args: Any, **kwargs: Any) -> tuple[str, bool, bool, str]:
        calls.append("token")
        assert kwargs["include_operation_scope"] is True
        assert kwargs["require_existing_client"] is True
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

    def run() -> dict[str, object]:
        return asyncio.run(acceptance.run_radius_server_lifecycle_mcp_oauth_acceptance(
            "https://synthetic.example.test/mcp", tmp_path / "login.json", tmp_path / "client.json", marker,persistent_primary=retain,remove_owned_primary=remove))

    if failure is not None:
        with pytest.raises(acceptance.RadiusLifecycleMcpOAuthAcceptanceError) as caught:
            run()
        rendered = str(caught.value)
        assert "private-" not in rendered and "radius-lifecycle-preview-" not in rendered and "radius-lifecycle-auth-" not in rendered
        assert "retry_allowed=false" in rendered
        assert f"dispatch_reserved={str(marker.exists()).lower()}" in rendered
    else:
        result = run()
        if remove:
            assert result["original_ack_removal_verified"] and result["final_dual_absence_verified"]
            assert result["material_acquisitions"]==0
        else:
            assert result["radius_created_and_full_readback_verified"] is result["original_native_m4_verified"] is True
        assert result["original_ack_removal_verified"] is (not retain)
        assert result["final_dual_absence_verified"] is (not retain)
        if retain:assert result["owned_entry_retained"] is True
        assert result["existing_client_reused"] and not result["dynamic_client_registration_performed"]
        assert result["token_revoked"] is result["revoked_access_rejected"] is True
        assert "private-" not in json.dumps(result)
        assert "radius-lifecycle-preview-" not in json.dumps(result) and "radius-lifecycle-auth-" not in json.dumps(result)
    assert cleanups == ([] if failure == "oauth" else [True])
    expected_execute = failure in {None, "execute", "result", "cleanup", "cleanup_exception"}
    assert calls.count(etool) == int(expected_execute)
    if marker.exists():
        before = list(calls)
        with pytest.raises(acceptance.RadiusLifecycleMcpOAuthAcceptanceError):
            run()
        assert calls == before


@pytest.mark.parametrize('field',['create_verified','native_m4_verified','exact_reject_only_response_verified',
    'original_ack_removal_verified','private_reject_only_connectivity_verified','all_candidate_gates_closed'])
def test_client_requires_every_parent_success_condition(field):
    payload=_payloads()[acceptance.EXECUTE_TOOL];payload[field]=False
    with pytest.raises(acceptance.RadiusLifecycleMcpOAuthAcceptanceError):acceptance._validate_execution(payload)


def test_missing_client_is_not_registered(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(oauth,'_oauth_token',lambda *a,**k:pytest.fail('OAuth called for missing client'))
    with pytest.raises(acceptance.RadiusLifecycleMcpOAuthAcceptanceError):
        asyncio.run(acceptance.run_radius_server_lifecycle_mcp_oauth_acceptance(
            'https://synthetic.example.test/mcp',tmp_path/'login.env',tmp_path/'missing.json',tmp_path/'dispatch.json'))
    assert not (tmp_path/'dispatch.json').exists()


@pytest.mark.parametrize('change',['sequence','extra','boolean_count','scope'])
def test_parent_cpe_cannot_expand_or_reorder_children(change):
    payload=_payloads()[acceptance.PREVIEW_TOOL]
    if change=='sequence':payload['Proposed Changes']['fixed_sequence'].reverse()
    elif change=='extra':payload['Proposed Changes']['raw']='SYNTHETIC_PRIVATE'
    elif change=='boolean_count':payload['Proposed Changes']['material_acquisitions_maximum']=True
    elif change=='scope':payload['Proposed Changes']['user_group_associations']=True
    with pytest.raises(acceptance.RadiusLifecycleMcpOAuthAcceptanceError):acceptance._validate_preview(payload)
