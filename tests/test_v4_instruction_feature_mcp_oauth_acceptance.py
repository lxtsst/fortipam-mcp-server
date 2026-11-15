"""Fixed shared-setting phase acceptance refuses drift and retains dispatch."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import time
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import v4_instruction_feature_mcp_oauth_acceptance as a


@pytest.mark.parametrize("phase,reconciled_restore",[("enable",False),("restore",False),("restore",True)])
@pytest.mark.parametrize("failure",[None,"preservation","original_proof","execution","result","cleanup",
    "connect","initialize","listing","schema","preview_call","preview_error","preview_body"])
def test_fixed_cycle_rejects_changed_evidence_and_never_replays_dispatch(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, reconciled_restore: bool, failure: str | None) -> None:
    tmp_path.chmod(0o700)
    login=tmp_path/"login.env"
    login.write_text(a.LOGIN_USERNAME+"=synthetic-user\n"+a.LOGIN_PASSWORD+"=synthetic-password\n")
    login.chmod(0o600)
    marker=tmp_path/"dispatch.json"
    expiry=int(time.time())+60
    preview={"contract":a.CONTRACT,"phase":phase,"policy_mode":"lab_auto",
        "preview_ref":"instruction-feature-preview-"+"a"*64,"expires_at":expiry,
        "Current State":{"instruction_enabled":phase=="restore","complete_setting_verified":True,
            "original_enable_ack_and_readback_verified":phase=="restore"},
        "Proposed Changes":{"operation":phase+"_instruction_feature","shared_setting_change":True,
            "other_setting_fields_preserved":True},
        "Expected State":{"instruction_enabled":phase=="enable","complete_setting_verified":True,
            "original_disabled_state_restored":phase=="restore"},"device_write_executed":False}
    authorization={"contract":a.CONTRACT,"phase":phase,"policy_mode":"lab_auto",
        "authorization_ref":"instruction-feature-auth-"+"b"*64,"expires_at":expiry}
    result={"contract":a.CONTRACT,"phase":phase,"outcome":"succeeded","verification":"verified",
        "compensation":"not_requested","idempotent_replay":False}
    if failure=="preservation":preview["Proposed Changes"]["other_setting_fields_preserved"]=False
    if failure=="original_proof":preview["Current State"]["original_enable_ack_and_readback_verified"]=phase!="restore"
    if failure=="result":result["verification"]="unknown"
    calls: list[str]=[]
    cleanups: list[bool]=[]
    class Session:
        async def initialize(self) -> None:
            assert a.LOGIN_USERNAME not in a.os.environ and a.LOGIN_PASSWORD not in a.os.environ
            if failure=="initialize":raise RuntimeError("synthetic-private-response")
        async def list_tools(self) -> Any:
            if failure=="listing":raise RuntimeError("synthetic-private-response")
            return SimpleNamespace(tools=[SimpleNamespace(name=n,input_schema={"type":"object"},
                output_schema={"$ref":"https://synthetic-private.invalid/schema"} if failure=="schema"
                else {"type":"object"}) for n in a._tools(phase,reconciled_restore)])
        async def call_tool(self, name: str, arguments: object) -> Any:
            calls.append(name)
            if name==a._tools(phase,reconciled_restore)[0]:
                if failure=="preview_call":raise RuntimeError("synthetic-private-response")
                if failure=="preview_error":return SimpleNamespace(is_error=True,structured_content=preview)
                if failure=="preview_body":return SimpleNamespace(is_error=False,structured_content=None)
                body=preview
            elif name==a._tools(phase)[1]:body=authorization
            else:
                assert json.loads(marker.read_text())=={"contract":a.DISPATCH_CONTRACT,
                    "phase":phase,"dispatch_reserved":True,"retry_allowed":False}
                assert marker.stat().st_mode & 0o777==0o600
                if failure=="execution":raise RuntimeError("synthetic-private-response")
                body=result
            return SimpleNamespace(is_error=False,structured_content=body)
    @asynccontextmanager
    async def session(*args: Any) -> Any:
        if failure=="connect":raise RuntimeError("synthetic-private-response")
        yield Session()
    async def token(*args: Any, **kwargs: Any) -> Any:
        assert kwargs["include_operation_scope"] is True
        path=tmp_path/"client.json"
        path.write_text('{"client_id":"synthetic-client"}')
        path.chmod(0o600)
        return "synthetic-token",False,True,"synthetic-client"
    async def revoke(*args: Any) -> bool:
        cleanups.append(True)
        return failure!="cleanup"
    monkeypatch.setattr(a.oauth,"_mcp_session",session)
    monkeypatch.setattr(a.oauth,"_oauth_token",token)
    monkeypatch.setattr(a.oauth,"_revoke_and_prove_401",revoke)
    async def run() -> dict[str,object]:
        return await a.run_instruction_feature_mcp_oauth_acceptance("https://localhost:18483/fpamcp",
            login,tmp_path/"client.json",marker,phase=phase,cleanup_state_file=tmp_path/"cleanup.json",
            reconciled_restore=reconciled_restore)
    if failure is None:
        assert asyncio.run(run())["fixed_readback_verified"] is True
    else:
        with pytest.raises(a.InstructionFeatureMcpOAuthAcceptanceError) as error:
            asyncio.run(run())
        assert "synthetic-private" not in str(error.value)
        expected_stage={"connect":"mcp_connect","initialize":"mcp_initialize","listing":"tool_listing",
            "schema":"tool_schema","preview_call":"preview_call","preview_error":"preview_tool_error",
            "preview_body":"preview_body","preservation":"preview_contract","original_proof":"preview_contract"}
        if failure in expected_stage:
            assert "stage="+expected_stage[failure]+";" in str(error.value)
            assert "dispatch_reserved=false; reconciliation_required=false;" in str(error.value)
            assert "token_revoked_and_401_verified=true; retry_allowed=false" in str(error.value)
            assert a._tools(phase)[1] not in calls and a._tools(phase)[2] not in calls
    assert cleanups==[True]
    protected=json.loads((tmp_path/"cleanup.json").read_text())
    assert protected["token"]=="synthetic-token" and protected["contract"]==a.CLEANUP_CONTRACT
    assert (tmp_path/"cleanup.json").stat().st_mode & 0o777==0o600
    assert marker.exists() is (failure in {None,"execution","result","cleanup"})
    if marker.exists():
        before=marker.read_bytes()
        with pytest.raises(a.InstructionFeatureMcpOAuthAcceptanceError):asyncio.run(run())
        assert marker.read_bytes()==before and calls.count(a._tools(phase)[2])==1
        assert cleanups==[True]
    assert a.LOGIN_USERNAME not in a.os.environ and a.LOGIN_PASSWORD not in a.os.environ


def test_unreadable_dispatch_marker_keeps_categorical_error_and_refuses_replay(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker=tmp_path/"synthetic-private-marker.json"
    def refuse(*args: object) -> None:
        raise PermissionError("synthetic-private-marker.json")
    original=Path.exists
    def exists(path: Path) -> bool:
        if path==marker:raise PermissionError("synthetic-private-marker.json")
        return original(path)
    monkeypatch.setattr(a.create_client,"_new_dispatch_path",refuse)
    monkeypatch.setattr(Path,"exists",exists)
    with pytest.raises(a.InstructionFeatureMcpOAuthAcceptanceError) as error:
        asyncio.run(a.run_instruction_feature_mcp_oauth_acceptance("https://localhost:18483/fpamcp",
            tmp_path/"unused-login.env",tmp_path/"unused-client.json",marker,phase="enable",
            cleanup_state_file=tmp_path/"unused-cleanup.json"))
    assert "synthetic-private" not in str(error.value)
    assert "dispatch_reserved=true" in str(error.value) and "reconciliation_required=true" in str(error.value)
    assert "retry_allowed=false" in str(error.value)
