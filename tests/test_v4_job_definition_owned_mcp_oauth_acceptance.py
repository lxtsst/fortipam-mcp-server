"""Client refusal before dispatch and irreversible marker/token cleanup."""
import asyncio
from contextlib import asynccontextmanager
import json
from types import SimpleNamespace

import pytest
from v4_planning import canonical_digest
from scripts import v4_job_definition_owned_mcp_oauth_acceptance as c


def payloads():
    preview = {"contract":c.CONTRACT,"phase":"create","policy_mode":"lab_auto",
        "preview_ref":"job-preview-"+"a"*64,"expires_at":220,
        "Current State":{"digest":"b"*64,"dependency_digest":"e"*64,"global_absence":True,"original_terminal_full_custody":False},
        "Proposed Changes":{"operation":"create_disabled_job","maximum_native_mutations":1,"activation_or_execution":False,"credential_or_policy_changes":False,"close_write_channel_before_readback":True,"wad_publication_delay_ms":3000},
        "Expected State":{"digest":"c"*64,"complete_pristine_state_or_global_absence":True,"original_records_preserved":True},
        "recovery":"separate_fresh_m4_original_constructor_ack_full_state_only_no_replay","device_write_executed":False}
    preview["summary_digest"] = canonical_digest(preview)
    return {c.PREVIEW:preview,
        c.AUTHORIZE:{"contract":c.CONTRACT,"phase":"create","policy_mode":"lab_auto","expires_at":220,"authorization_ref":"job-auth-"+"d"*64},
        c.EXECUTE:{"contract":c.CONTRACT,"phase":"create","outcome":"succeeded","verification":"verified","idempotent_replay":False,
            "complete_pristine_state_or_global_absence":True,"original_records_preserved":True,"original_store_read_only":False,
            "activation_or_execution":False,"native_claim_count":1,"write_channel_closed_before_readback":True,"wad_publication_delay_observed":True,"source_failure":{"source_reader_phase":None,"reader_failure_stage":None},
            "all_candidate_gates_closed":True,"owner_logout_verified":True}}


@pytest.mark.parametrize("fault", ["none", "wrong-phase", "widened-effect", "bad-digest", "bad-auth", "unknown-result", "transport", "cancelled"])
def test_client_never_replays_and_always_revokes_after_token_acquisition(tmp_path, monkeypatch, fault):
    tmp_path.chmod(0o700); login = tmp_path / "login.json"; login.write_text(json.dumps({"username":"SYNTHETIC_LOGIN","password":"SYNTHETIC_PASSWORD"})); login.chmod(0o600)
    state = tmp_path / "client.env"; state.write_text("SYNTHETIC_CLIENT"); state.chmod(0o600)
    marker = tmp_path / "dispatch.json"; values = payloads(); calls = []; revoked = []
    if fault == "wrong-phase": values[c.PREVIEW]["phase"] = "recover"
    if fault == "widened-effect": values[c.PREVIEW]["Proposed Changes"]["maximum_native_mutations"] = 2
    if fault == "bad-digest": values[c.PREVIEW]["summary_digest"] = "f"*64
    if fault == "bad-auth": values[c.AUTHORIZE]["expires_at"] = 219
    if fault == "unknown-result": values[c.EXECUTE]["outcome"] = "reconciliation_required"
    class Session:
        async def initialize(self): pass
        async def list_tools(self): return SimpleNamespace(tools=[SimpleNamespace(name=n) for n in c.TOOLS])
        async def call_tool(self, name, arguments):
            calls.append(name)
            if name == c.EXECUTE:
                assert marker.exists() and json.loads(marker.read_bytes())["retry_allowed"] is False
                if fault == "transport": raise RuntimeError("PRIVATE_NATIVE_DETAIL")
                if fault == "cancelled": raise asyncio.CancelledError
            return SimpleNamespace(is_error=False, structured_content=values[name])
    @asynccontextmanager
    async def session(*a, **k): yield Session()
    async def token(*a, **k):
        assert k["require_existing_client"] and k["include_operation_scope"]
        return "SYNTHETIC_TOKEN", False, True, "SYNTHETIC_CLIENT"
    async def revoke(*a, **k): revoked.append(True); return True
    monkeypatch.setattr(c.time, "time", lambda:100.0)
    monkeypatch.setattr(c.oauth, "_mcp_session", session)
    monkeypatch.setattr(c.oauth, "_oauth_token", token)
    monkeypatch.setattr(c.oauth, "_revoke_and_prove_401", revoke)
    async def run(): return await c.run_job_definition_owned_mcp_oauth_acceptance("https://mcp.example/fpamcp", login, state, marker, phase="create")
    if fault == "none": assert asyncio.run(run())["completed"]
    else:
        with pytest.raises(asyncio.CancelledError if fault == "cancelled" else c.JobOwnedAcceptanceError): asyncio.run(run())
    attempted = fault in {"none", "unknown-result", "transport", "cancelled"}
    assert calls.count(c.EXECUTE) == int(attempted) and marker.exists() is attempted and revoked == [True]
    if attempted:
        with pytest.raises(c.JobOwnedAcceptanceError): asyncio.run(run())
        assert calls.count(c.EXECUTE) == 1 and revoked == [True]


@pytest.mark.parametrize("field", ["complete_pristine_state_or_global_absence","original_records_preserved","all_candidate_gates_closed","owner_logout_verified"])
def test_partial_execution_evidence_never_counts_as_acceptance(field):
    value=payloads()[c.EXECUTE];value[field]=False
    with pytest.raises(c.JobOwnedAcceptanceError):c._validate_execution(value,"create")


def test_recovery_requires_readonly_original_store():
    value=payloads()[c.EXECUTE];value["phase"]="recover"
    with pytest.raises(c.JobOwnedAcceptanceError):c._validate_execution(value,"recover")
    value["original_store_read_only"]=True;c._validate_execution(value,"recover")
