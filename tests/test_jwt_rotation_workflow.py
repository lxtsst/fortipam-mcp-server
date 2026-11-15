"""Real six-child M4 graph and RSA probes over synthetic native peers."""
from pathlib import Path

import pytest
import httpx

from fortipam_mcp.jwt_rotation_authentication import JwtRotationAuthenticationProbe
from fortipam_mcp.jwt_rotation_workflow import JwtRotationWorkflow,JwtRotationPhaseSpec
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_jwt_rotation_phase import RotationLab,source,keyfile
from test_jwt_manual_key_owner_workflow import workflow,run,IDENTITY
from test_jwt_rotation_authentication import Peer
from test_jwt_manual_rotation_contract import replacement
from test_jwt_manual_key_contract import synthetic_key
from test_v4_execution_kernel import REQUESTER

CALLER = {"requester_digest":REQUESTER,"transport_digest":"d"*64}


class SamplingClock:
    def __init__(self):self.now = 0.0
    def __call__(self):return self.now
    def wait(self,seconds):self.now += seconds


def graph(lab,owner,creator,old,new,monkeypatch,*,fault="none",enabled=True,first_member_only=False,
        activation_diagnostic=False,stale_original=False,lagged_runtime=False,delayed_runtime=False,removal_denial="normal"):
    scoped = source(lab,owner,creator,enabled=enabled)
    auth = Peer(lab.root,old,new,monkeypatch,fault=fault); auth.config = owner._config
    actual = auth.reply
    activation = {"puts":-1,"at":0.0};removed_at = None
    def reply(request):
        nonlocal removed_at
        members = lab.row["key"][:1] if first_member_only else lab.row["key"]
        if stale_original: members = scoped.keys.members("original")
        if lagged_runtime:
            members = scoped.keys.members("original" if lab.puts <= 1 else "overlap" if lab.puts == 2 else "cutover")
        if delayed_runtime:
            if activation["puts"] != lab.puts:activation.update(puts=lab.puts,at=sample_clock.now)
            if lab.puts and sample_clock.now-activation["at"]<1:
                members = scoped.keys.members("original" if lab.puts == 1 else "overlap" if lab.puts == 2 else "cutover")
        auth.active = {name for name,key in (("old",scoped.keys._old),("new",scoped.keys._new))
            if any(entry["key-name"] == key._pem.decode() for entry in members)}
        auth.revoked = lab.user is None
        if request.url.path == "/auth/jwt/login" and (lab.user is None or not lab.key_initialized):
            if lab.user is None and lab.user_deletes:
                if removed_at is None:removed_at = sample_clock.now
                if removal_denial == "timeout":raise httpx.ReadTimeout("synthetic unavailable")
                if removal_denial in {"large","lockout","delayed"} and (removal_denial != "delayed" or sample_clock.now-removed_at<1):
                    content = '<html><script>location="/remote/login";</script>'+'x'*1024
                    if removal_denial == "lockout":content += "Too many login attempts"
                    return httpx.Response(401,text=content,headers={"Content-Type":"text/html"})
            return httpx.Response(401,json={"status":"error"})
        return actual(request)
    auth.reply = reply
    probe = JwtRotationAuthenticationProbe(owner._config,scoped.binding,scoped.keys,old,new,
        probe_enabled=enabled,source_guard=scoped.probe_ready,client_factory=auth.factory,clock=lambda:auth.clock,
        fresh_assertion_clients=True,runtime_sampling=True)
    specs = {}
    for i,name in enumerate(("user-create","user-initialize","overlap","cutover","restore","user-remove")):
        directory = lab.root/("phase-"+name); directory.mkdir(mode=0o700)
        authority = keyfile(directory/"authority.key",bytes([65+i])*32)
        execution = keyfile(directory/"execution.key",bytes([80+i])*32)
        specs[name] = JwtRotationPhaseSpec(PersistentM4ExecutionStateStore(directory/"execution.sqlite3",execution),
            directory,authority,"synthetic-rotation-"+name)
    directory = lab.root/"parent"; directory.mkdir(mode=0o700)
    sample_clock = SamplingClock()
    parent = JwtRotationWorkflow(scoped,lambda:probe,specs,directory=directory,
        authority_key_file=keyfile(directory/"authority.key",b"Z"*32),
        environment_ref=IDENTITY["environment_ref"],audience_ref=IDENTITY["audience_ref"],execution_enabled=enabled,
        activation_diagnostic=activation_diagnostic,sampling_clock=sample_clock,sampling_wait=sample_clock.wait)
    return parent,auth


def invoke(parent):
    preview = parent.preview(**CALLER); authorization = parent.authorize(preview["preview_ref"],**CALLER)
    return parent.execute(authorization["authorization_ref"],**CALLER)


@pytest.mark.parametrize("denial_html", [False,True])
@pytest.mark.parametrize("reorder_native", [False,True])
def test_actual_parent_graph_restores_configuration_and_distinguishes_live_old_lease(tmp_path,synthetic_key,replacement,monkeypatch,denial_html,reorder_native):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create"); run(creator)
        parent,auth = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch)
        auth.denial_html = denial_html
        if reorder_native: lab.rotation_fault = "reorder-overlap"
        result = invoke(parent)
        assert result["outcome"] == "succeeded" and result["verification"] == "verified",result
        assert result["native_phase_claims"] == 6 and result["existing_old_lease_after_cutover"] == "still-valid"
        assert result["overlap_authentication"] == {"old":True,"new":True}
        assert result["all_issued_leases_denied_after_user_removal"] and result["original_key_restored_and_user_absent"]
        assert result["owner_logout_and_cookie_rejection"] and result["private_assertions_and_leases_cleared"]
        assert result["all_candidate_gates_closed"] and lab.user is None and lab.puts == 3 and lab.user_posts == lab.user_deletes == 1
        assert all(spec.store.claim_count == 1 for spec in parent.phases.values())
        assert parent.probe._auth_count == 13 and all(c.is_closed for c in auth.clients)
        assert lab.key_generations == 1
        with pytest.raises(RuntimeError): parent.preview(**CALLER)
        assert lab.puts == 3


def test_first_member_only_peer_records_both_signatures_then_restores_without_cutover(tmp_path,synthetic_key,replacement,monkeypatch):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create");run(creator)
        parent,auth = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch,first_member_only=True)
        auth.denial_html = True;result = invoke(parent)
        assert result["outcome"] == "reconciliation_required" and result["failure_stage"] == "overlap_assertions"
        assert result["overlap_authentication"] == {"old":False,"new":True}
        assert result["native_phase_claims"] == 5 and lab.puts == 2
        assert parent.phases["cutover"].store.claim_count == 0
        assert result["original_key_restored_and_user_absent"] and result["all_issued_leases_denied_after_user_removal"]
        assert result["all_candidate_gates_closed"] and lab.user is None and lab.key_generations == 1


@pytest.mark.parametrize("denial", ["delayed","large","lockout","timeout"])
def test_user_removal_requires_qualified_denial_without_replaying_writes(tmp_path,synthetic_key,replacement,monkeypatch,denial):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create");run(creator)
        parent,auth = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch,removal_denial=denial)
        result = invoke(parent)
        accepted = denial == "delayed"
        assert (result["outcome"] == "succeeded") is accepted,result
        assert result["failure_stage"] == (None if accepted else "lease_revocation")
        assert lab.puts == 3 and lab.user_posts == lab.user_deletes == 1 and lab.user is None
        assert result["native_phase_claims"] == 6 and result["original_key_restored_and_user_absent"]
        assert result["all_issued_leases_denied_after_user_removal"] and result["all_candidate_gates_closed"]
        samples = result["post_removal_samples"]
        assert len(samples) == {"delayed":2,"large":3,"lockout":0,"timeout":0}[denial]
        if samples:
            assert samples[0]["unqualified_http401"] and samples[0]["qualified_denial"] is False
        if accepted:
            assert samples[-1]["qualified_denial"] and samples[-1]["unqualified_http401"] is False
        assert all(c.is_closed for c in auth.clients)


@pytest.mark.parametrize("effect", ["both","first-member","stale-original"])
def test_explicit_diagnostic_distinguishes_single_new_key_effect_without_accepting_rotation(tmp_path,synthetic_key,replacement,monkeypatch,effect):
    from fortipam_mcp.jwt_rotation_workflow import DIAGNOSTIC_CONTRACT
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create");run(creator)
        parent,auth = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch,
            activation_diagnostic=True,first_member_only=effect == "first-member",stale_original=effect == "stale-original")
        lab.rotation_fault = "reorder-overlap";auth.denial_html = True
        preview = parent.preview(**CALLER)
        assert preview["contract"] == DIAGNOSTIC_CONTRACT
        assert preview["Proposed Changes"]["failed_overlap_path"] == "single_new_key_probe_then_original_restore"
        assert preview["Expected State"]["rotation_accepted"] is False
        authorization = parent.authorize(preview["preview_ref"],**CALLER)
        result = parent.execute(authorization["authorization_ref"],**CALLER)
        assert result["contract"] == DIAGNOSTIC_CONTRACT and result["outcome"] == "succeeded",result
        assert result["activation_discriminator_completed"] and result["rotation_accepted"] is False
        assert result["overlap_authentication"] == {"old":True,"new":effect == "both"}
        assert result["single_new_key_authentication"] == {"old":effect == "stale-original","new":effect != "stale-original"}
        assert result["native_phase_claims"] == 6 and lab.puts == 3
        assert result["original_key_restored_and_user_absent"] and result["all_issued_leases_denied_after_user_removal"]
        assert result["all_candidate_gates_closed"] and result["owner_logout_and_cookie_rejection"]
        assert lab.user is None and lab.row["key"] == lab.keys.members("original")
        assert all(spec.store.claim_count == 1 for spec in parent.phases.values())


def test_diagnostic_purpose_cannot_change_after_authorization(tmp_path,synthetic_key,replacement,monkeypatch):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create");run(creator)
        parent,_ = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch,activation_diagnostic=True)
        preview = parent.preview(**CALLER);authorization = parent.authorize(preview["preview_ref"],**CALLER)
        parent._activation_diagnostic = False
        with pytest.raises(RuntimeError):parent.execute(authorization["authorization_ref"],**CALLER)
        assert lab.user_posts == lab.puts == lab.user_deletes == 0
        assert all(spec.store.claim_count == 0 for spec in parent.phases.values())
        parent.close()


def test_native_observed_lag_keeps_failed_restore_and_removes_user_without_replaying_restore(tmp_path,synthetic_key,replacement,monkeypatch):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create");run(creator)
        parent,auth = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch,
            activation_diagnostic=True,lagged_runtime=True)
        auth.denial_html = True;result = invoke(parent)
        assert result["outcome"] == "reconciliation_required" and result["failure_stage"] == "restore_assertions"
        assert result["rotation_accepted"] is False and result["activation_discriminator_completed"] is False
        assert result["overlap_authentication"] == {"old":True,"new":False}
        assert result["single_new_key_authentication"] == {"old":True,"new":True}
        assert result["original_key_restored_and_user_absent"] and result["all_issued_leases_denied_after_user_removal"]
        assert lab.puts == 3 and lab.user_deletes == 1 and result["native_phase_claims"] == 6
        assert lab.row["key"] == lab.keys.members("original") and lab.user is None
        assert result["all_candidate_gates_closed"] and result["owner_logout_and_cookie_rejection"]
        assert all(spec.store.claim_count == 1 for spec in parent.phases.values())


@pytest.mark.parametrize("activation_diagnostic", [False,True])
def test_fixed_samples_distinguish_time_convergence_without_another_configuration_write(tmp_path,synthetic_key,replacement,monkeypatch,activation_diagnostic):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create");run(creator)
        parent,_ = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch,
            activation_diagnostic=activation_diagnostic,delayed_runtime=True)
        result = invoke(parent)
        assert result["outcome"] == "succeeded",result
        if activation_diagnostic:assert result["rotation_accepted"] is False
        expected = {"overlap":({"old":True,"new":False},{"old":True,"new":True}),
            "cutover":({"old":True,"new":True},{"old":False,"new":True}),
            "restore":({"old":False,"new":True},{"old":True,"new":False})}
        for phase,(before,after) in expected.items():
            samples = result["runtime_samples"][phase]
            assert [x["observed_offset_ms"]for x in samples] == ([0,1000,4000]if activation_diagnostic else[0,1000])
            assert {k:samples[0][k]for k in before} == before
            assert all({k:x[k]for k in after}==after for x in samples[1:])
        assert parent.probe._auth_count == (25 if activation_diagnostic else 19) and lab.puts == 3
        assert result["native_phase_claims"] == 6 and result["all_issued_leases_denied_after_user_removal"]
        assert result["original_key_restored_and_user_absent"] and result["all_candidate_gates_closed"]


def test_sampling_clock_failure_does_not_repeat_mutations_and_uses_original_cleanup(tmp_path,synthetic_key,replacement,monkeypatch):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create");run(creator)
        parent,_ = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch,activation_diagnostic=True)
        clock = parent._sampling_clock
        def backwards(_):clock.now -= 1
        parent._sampling_wait = parent._sampling_wait_pin = backwards
        result = invoke(parent)
        assert result["failure_stage"] == "overlap_assertions" and result["rotation_accepted"] is False
        assert result["original_key_restored_and_user_absent"] and result["all_issued_leases_denied_after_user_removal"]
        assert lab.puts == 2 and parent.phases["cutover"].store.claim_count == 0


@pytest.mark.parametrize("fault", ["init-403","init-timeout"])
def test_uncertain_initialization_never_retries_or_launches_and_uses_only_owned_cleanup(tmp_path,synthetic_key,replacement,monkeypatch,fault):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create"); run(creator)
        parent,_ = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch)
        lab.rotation_fault = fault; result = invoke(parent)
        assert result["failure_stage"] == "user-initialize" and result["outcome"] == "reconciliation_required"
        assert result["native_phase_claims"] == 3 and result["original_key_restored_and_user_absent"]
        assert not result["all_issued_leases_denied_after_user_removal"] and parent.probe._auth_count == 0
        assert lab.user_posts == lab.user_deletes == lab.key_generations == 1 and lab.puts == 0
        assert not(lab.rotation/"user-initialize.ack.json").exists()
        assert parent.phases["user-initialize"].store.claim_count == 1 and result["all_candidate_gates_closed"]


@pytest.mark.parametrize("fault", ["wrong-role","wrong-device","missing-token","timeout"])
def test_probe_failure_stops_cutover_and_uses_only_unused_owned_cleanup(tmp_path,synthetic_key,replacement,monkeypatch,fault):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create"); run(creator)
        parent,_ = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch,fault=fault)
        result = invoke(parent)
        assert result["outcome"] == "reconciliation_required" and result["failure_stage"] == "original_assertions"
        assert result["original_key_restored_and_user_absent"] and result["all_candidate_gates_closed"]
        assert lab.puts == 0 and lab.user_posts == lab.user_deletes == 1
        assert parent.phases["user-create"].store.claim_count == parent.phases["user-remove"].store.claim_count == 1
        assert parent.phases["overlap"].store.claim_count == parent.phases["restore"].store.claim_count == 0
        if fault == "missing-token":
            assert not parent.probe._leases and not result["all_issued_leases_denied_after_user_removal"]


@pytest.mark.parametrize("activation_diagnostic", [False,True])
def test_failed_cutover_observation_does_not_retry_any_mutation_and_restores_once(tmp_path,synthetic_key,replacement,monkeypatch,activation_diagnostic):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create"); run(creator)
        parent,auth = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch,activation_diagnostic=activation_diagnostic)
        actual = auth.reply
        def stale_old_key(request):
            response = actual(request)
            if lab.puts == 2 and request.url.path == "/auth/jwt/login":
                # A transport error is unknown, never a synthetic rejection.
                import httpx
                raise httpx.ReadTimeout("PRIVATE_RESPONSE")
            return response
        auth.reply = stale_old_key
        result = invoke(parent)
        assert result["outcome"] == "reconciliation_required" and result["failure_stage"] == "cutover_assertions"
        assert result["original_key_restored_and_user_absent"] and lab.puts == 3
        assert lab.row["key"] == lab.keys.members("original") and lab.user is None
        assert lab.user_posts == lab.user_deletes == 1


@pytest.mark.parametrize("fault", ["requester","transport","disabled","parent-key","child-key"])
def test_parent_identity_and_key_gates_precede_child_claims(tmp_path,synthetic_key,replacement,monkeypatch,fault):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create"); run(creator)
        parent,_ = graph(lab,owner,creator,synthetic_key,replacement,monkeypatch,enabled=fault != "disabled")
        if fault in {"requester","transport"}:
            count = len(lab.calls); caller = dict(CALLER); caller["requester_digest" if fault == "requester" else "transport_digest"] = "0"*64
            with pytest.raises(RuntimeError): parent.preview(**caller)
            assert len(lab.calls) == count
        else:
            p = parent.preview(**CALLER)
            if fault == "parent-key": parent._key_file.write_bytes(b"x"*32)
            if fault == "child-key": parent.phases["overlap"].authority_key_file.write_bytes(b"x"*32)
            with pytest.raises(RuntimeError): parent.authorize(p["preview_ref"],**CALLER)
        assert lab.user_posts == lab.puts == lab.user_deletes == 0
        assert all(spec.store.claim_count == 0 for spec in parent.phases.values())
        parent.close()
