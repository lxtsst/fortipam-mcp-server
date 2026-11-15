"""Client refusal before dispatch and irreversible marker/token cleanup."""
import asyncio
from contextlib import asynccontextmanager
import json
from types import SimpleNamespace

import pytest
from v4_planning import canonical_digest
from scripts import v4_jwt_rotation_mcp_oauth_acceptance as c


def payloads(*,activation_diagnostic=False):
    preview = {"contract":c.CONTRACT,"policy_mode":"lab_auto","preview_ref":"jwt-rotation-preview-"+"a"*32,"expires_at":220,
        "Current State":{"original_key_custody_verified":True,"jwt_user_absent":True,"digest":"b"*64},
        "Proposed Changes":{"fixed_child_sequence":["user-create","user-initialize","overlap","cutover","restore","user-remove"],
            "overlap_submission_order":["new","old"],
            "maximum_native_mutations":6,"owned_user_api_key_initialization":True,"generated_api_key_discarded":True,"claim_match":"exact","lease_minutes":10,"private_assertion_algorithm":"RS256","secret_acl_changes":False},
        "Expected State":{"original_key_restored":True,"owned_jwt_user_absent":True,"authentication_and_lease_effects_observed":True},
        "recovery":"unused_original_owned_restore_then_user_removal_only_no_native_replay","device_write_executed":False}
    preview["summary_digest"] = canonical_digest(preview)
    result = {c.PREVIEW:preview,
        c.AUTHORIZE:{"contract":c.CONTRACT,"policy_mode":"lab_auto","expires_at":220,"authorization_ref":"jwt-rotation-auth-"+"d"*64},
        c.EXECUTE:{"contract":c.CONTRACT,"outcome":"succeeded","verification":"verified","idempotent_replay":False,
            "original_key_restored_and_user_absent":True,"existing_old_lease_after_cutover":"still-valid",
            "overlap_authentication":{"old":True,"new":True},
            "all_issued_leases_denied_after_user_removal":True,"failure_stage":None,"native_phase_claims":6,
            "all_candidate_gates_closed":True,"owner_logout_and_cookie_rejection":True,"private_assertions_and_leases_cleared":True}}
    if activation_diagnostic:
        for value in result.values():value["contract"] = c.DIAGNOSTIC_CONTRACT
        preview["Proposed Changes"]["failed_overlap_path"] = "single_new_key_probe_then_original_restore"
        preview["Proposed Changes"]["assertion_connection_policy"] = "new_verified_client_per_assertion"
        preview["Proposed Changes"].update(runtime_sample_offsets_after_poststate_ms=[0,1000,4000],
            maximum_authentication_requests=32,maximum_lease_checks=64)
        preview["Expected State"]["rotation_accepted"] = False
        preview["summary_digest"] = canonical_digest({k:v for k,v in preview.items()if k != "summary_digest"})
        result[c.EXECUTE].update(rotation_accepted=False,activation_discriminator_completed=True,
            overlap_authentication={"old":True,"new":False},single_new_key_authentication={"old":False,"new":True},
            runtime_samples={phase:[{"requested_offset_ms":offset,"observed_offset_ms":offset,"old":old,"new":new}
                for offset in (0,1000,4000)]for phase,old,new in (("overlap",True,False),("cutover",False,True),("restore",True,False))})
    else:
        preview["Proposed Changes"].update(assertion_connection_policy="new_verified_client_per_assertion",
            runtime_readiness_offsets_after_poststate_ms=[0,1000,4000],maximum_authentication_requests=32,maximum_lease_checks=64,
            post_removal_denial_offsets_ms=[0,1000,4000],unqualified_http401_is_revocation_evidence=False)
        preview["summary_digest"] = canonical_digest({k:v for k,v in preview.items()if k != "summary_digest"})
        result[c.EXECUTE]["runtime_samples"] = {phase:[{"requested_offset_ms":0,"observed_offset_ms":0,"old":old,"new":new}]
            for phase,old,new in (("overlap",True,True),("cutover",False,True),("restore",True,False))}
        result[c.EXECUTE]["post_removal_samples"] = [{"requested_offset_ms":0,"observed_offset_ms":0,
            "qualified_denial":True,"unqualified_http401":False}]
    return result


@pytest.mark.parametrize("diagnostic", [False,True])
@pytest.mark.parametrize("fault", ["missing","wrong-time","wrong-predicate","nonboolean"])
def test_runtime_evidence_cannot_replace_the_required_phase_predicates(diagnostic,fault):
    result = payloads(activation_diagnostic=diagnostic)[c.EXECUTE]
    if fault == "missing":result.pop("runtime_samples")
    elif fault == "wrong-time":result["runtime_samples"]["restore"][-1]["observed_offset_ms"] = -1
    elif fault == "wrong-predicate":result["runtime_samples"]["restore"][-1]["old"] = False
    else:result["runtime_samples"]["cutover"][-1]["old"] = 0
    with pytest.raises(c.JwtRotationAcceptanceError):c._validate_execution(result,activation_diagnostic=diagnostic)


def test_normal_readiness_must_stop_at_the_first_qualified_predicate():
    result = payloads()[c.EXECUTE]
    result["runtime_samples"]["overlap"].append({"requested_offset_ms":1000,"observed_offset_ms":1000,"old":True,"new":True})
    with pytest.raises(c.JwtRotationAcceptanceError):c._validate_execution(result)


@pytest.mark.parametrize("fault", ["missing","unqualified","nonboolean","duplicate-qualified"])
def test_final_revocation_evidence_must_be_qualified_and_bounded(fault):
    result = payloads()[c.EXECUTE]
    if fault == "missing":result.pop("post_removal_samples")
    elif fault == "unqualified":result["post_removal_samples"][0].update(qualified_denial=False,unqualified_http401=True)
    elif fault == "nonboolean":result["post_removal_samples"][0]["qualified_denial"] = 1
    else:result["post_removal_samples"].append(dict(result["post_removal_samples"][0],requested_offset_ms=1000,observed_offset_ms=1000))
    with pytest.raises(c.JwtRotationAcceptanceError):c._validate_execution(result)


@pytest.mark.parametrize("activation_diagnostic", [False,True])
@pytest.mark.parametrize("fault", ["none", "wrong-sequence", "old-overlap-order", "widened-effect", "bad-digest", "bad-auth", "unknown-result", "lease-live", "transport", "cancelled", "wrong-purpose"])
def test_client_never_replays_and_always_revokes_after_token_acquisition(tmp_path, monkeypatch, fault,activation_diagnostic):
    tmp_path.chmod(0o700); login = tmp_path / "login.json"; login.write_text(json.dumps({"username":"SYNTHETIC_LOGIN","password":"SYNTHETIC_PASSWORD"})); login.chmod(0o600)
    state = tmp_path / "client.env"; state.write_text("SYNTHETIC_CLIENT"); state.chmod(0o600)
    marker = tmp_path / "dispatch.json"; values = payloads(activation_diagnostic=activation_diagnostic); calls = []; revoked = []
    if fault == "wrong-purpose":values = payloads(activation_diagnostic=not activation_diagnostic)
    if fault == "wrong-sequence": values[c.PREVIEW]["Proposed Changes"]["fixed_child_sequence"].reverse()
    if fault == "old-overlap-order":
        values[c.PREVIEW]["Proposed Changes"]["overlap_submission_order"].reverse()
        values[c.PREVIEW]["summary_digest"] = canonical_digest({k:v for k,v in values[c.PREVIEW].items()if k != "summary_digest"})
    if fault == "widened-effect": values[c.PREVIEW]["Proposed Changes"]["maximum_native_mutations"] = 7
    if fault == "bad-digest": values[c.PREVIEW]["summary_digest"] = "f"*64
    if fault == "bad-auth": values[c.AUTHORIZE]["expires_at"] = 219
    if fault == "unknown-result": values[c.EXECUTE]["outcome"] = "reconciliation_required"
    if fault == "lease-live": values[c.EXECUTE]["all_issued_leases_denied_after_user_removal"] = False
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
    async def run(): return await c.run_jwt_rotation_mcp_oauth_acceptance("https://mcp.example/fpamcp", login, state, marker,activation_diagnostic=activation_diagnostic)
    if fault == "none":
        result = asyncio.run(run());assert result["completed"]
        if activation_diagnostic:
            assert result["rotation_accepted"] is False and result["single_new_key_authentication"] == {"old":False,"new":True}
    else:
        with pytest.raises(asyncio.CancelledError if fault == "cancelled" else c.JwtRotationAcceptanceError): asyncio.run(run())
    attempted = fault in {"none", "unknown-result", "lease-live", "transport", "cancelled"}
    assert calls.count(c.EXECUTE) == int(attempted) and marker.exists() is attempted and revoked == [True]
    if attempted:
        with pytest.raises(c.JwtRotationAcceptanceError): asyncio.run(run())
        assert calls.count(c.EXECUTE) == 1 and revoked == [True]
