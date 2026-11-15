"""Original JWT response evidence through the real checkpointed M4 kernel."""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Thread

import pytest
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4ExecutionPlan, canonical_digest

from fortipam_mcp import jwt_manual_key_response_custody as c
from fortipam_mcp.jwt_manual_key_actor_evidence import JwtManualKeyActorEvidence
from fortipam_mcp.jwt_manual_key_contract import JwtManualCreatePlan, JwtManualPublicKey
from fortipam_mcp.jwt_manual_key_request_contract import JwtManualCreateRequest
from fortipam_mcp.m4_execution_store import M4ExecutionStoreTail, PersistentM4ExecutionStateStore
from test_jwt_manual_key_contract import defaults, public_pem, synthetic_key
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier, REQUESTER, CONFIRMATION, APPROVAL


def components(root, checkpoint=None, *, now=None, read_only=False, controls=None):
    checkpoint = checkpoint or _ExternalM4Checkpoint()
    controls = controls if controls is not None else dict(enabled=True, source=True, actor=True)
    clock = now if now is not None else [1000]
    key = JwtManualPublicKey((root / "synthetic-public.pem").read_bytes())
    context = dict(schema_digest="6" * 64, serial_digest=hashlib.sha256(b"synthetic-appliance").hexdigest())
    body_plan = JwtManualCreatePlan("mcp-v4-jwt-synthetic", "7" * 64, key, defaults(), **context)
    request = JwtManualCreateRequest(body_plan, defaults(), **context)
    actor = JwtManualKeyActorEvidence("8" * 64, "9" * 64, context["serial_digest"])
    current = c.jwt_manual_create_current_digest(request, actor, "a" * 64, "b" * 64)
    store = PersistentM4ExecutionStateStore(root / "execution.sqlite", root / "execution.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF, read_only=read_only)
    fields = dict(plan_ref="manual-jwt-original-plan-01", revision=1, action_id=c.ACTION_ID, action_version="1.0.0",
        adapter_ref=c.ADAPTER_REF, target_ref="bound-manual-jwt-public-key", requester_digest=REQUESTER,
        summary_digest="c" * 64, confirmation_digest=CONFIRMATION, approval_digest=APPROVAL,
        parameters_digest=request.digest, expected_current_digest=current, expected_state_digest="d" * 64,
        idempotency_digest="e" * 64, expires_at=1300, compensation_ref=None)
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    auth = _authorization(plan)
    custody = c.JwtManualKeyResponseCustody(root / "custody", root / "witness.key", request, actor, "a" * 64,
        "b" * 64, plan, auth, store, execution_enabled=lambda: controls['enabled'],
        source_guard=lambda: controls['source'], actor_reader=lambda: actor if controls['actor'] else
            JwtManualKeyActorEvidence("f" * 64, "9" * 64, context["serial_digest"]), clock=lambda: clock[0])
    return custody, store, plan, auth, request, checkpoint, clock, controls


def create(root, key, **kwargs):
    root.chmod(0o700); (root / "custody").mkdir(mode=0o700)
    for name, value in [("execution.key", b"e" * 32), ("witness.key", b"w" * 32), ("synthetic-public.pem", public_pem(key))]:
        (root / name).write_bytes(value); (root / name).chmod(0o600)
    return components(root, **kwargs)


def response(**changes):
    value = dict(version="v7.0.0", build=29, serial="synthetic-appliance", http_method="POST", http_status=200,
                 status="success", path="secret", name="jwt-key", vdom="root", mkey="mcp-v4-jwt-synthetic", error=0)
    value.update(changes)
    return bytearray(json.dumps(value, separators=(",", ":")).encode())


class Adapter:
    def __init__(self, bundle, fault="none"):
        self.c, self.store, self.p, self.a, self.request, self.checkpoint, self.clock, self.controls = bundle
        self.fault = fault; self.sends = 0; self.raw = None; self.observed = None

    def read_current(self, plan): return plan.expected_current_digest

    def dispatch(self, plan):
        try:
            self.c.begin_original_send(); self.sends += 1
            if self.fault == "crash-before-response": raise KeyboardInterrupt
            self.raw = response(); status = 200; content = "application/json"; state = "complete"
            if self.fault == "error":
                self.raw = response(status="error", http_status=500, error=-3, message="SYNTHETIC_PRIVATE_NOTE",
                                    results={"private-note": "SYNTHETIC_PRIVATE_NOTE"}); status = 500
            if self.fault == "html": self.raw = bytearray(b"<html>SYNTHETIC_PRIVATE_NOTE</html>"); status = 502; content = "text/html"
            if self.fault == "malformed": self.raw = bytearray(b'{"status":"error",')
            if self.fault == "partial": state = "partial"
            if self.fault == "oversize": self.raw = bytearray(b"x" * (c._MAX_BYTES + 100))
            if self.fault == "foreign": self.raw = response(serial="foreign-appliance")
            if self.fault == "schema": self.raw = response(schema_errors=[])
            if self.fault == "expired": self.clock[0] = self.a.expires_at
            if self.fault == "backward": self.clock[0] = 900
            if self.fault == "invalid-clock": self.clock[0] = True
            if self.fault == "gate-closed": self.controls['enabled'] = False
            if self.fault == "source-drift": self.controls['source'] = False
            if self.fault == "request-closed": self.request.close()
            self.observed = self.c.capture_original_response(self.raw, http_status=status, content_type=content, body_state=state,
                producer_context_valid=self.fault!='producer-invalid')
            if not self.observed.success_ack_retained: raise M4AdapterAmbiguous("Synthetic response is not a creation receipt.")
        except c.JwtManualKeyResponseCustodyError:
            raise M4AdapterAmbiguous("Synthetic custody unavailable.") from None

    def read_postcondition(self, plan):
        if self.fault == "post-unknown": raise M4AdapterAmbiguous("Synthetic readback unavailable.")
        return plan.expected_state_digest


def execute(bundle, *, fault="none", adapter=None):
    custody, store, plan, auth, *_ = bundle
    adapter = adapter if adapter is not None else Adapter(bundle, fault)
    return adapter, M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: 1000).execute(plan, auth)


def test_failure_response_is_retained_before_native_parsing_and_is_not_a_creation_receipt(tmp_path, synthetic_key, monkeypatch):
    bundle = create(tmp_path, synthetic_key)
    original = bundle[0]._native_summary
    def summary(raw):
        baseline = json.loads((tmp_path / "custody/response.json").read_bytes())
        assert baseline['http_status'] == 500 and baseline['response_hmac']
        assert not (tmp_path / "custody/response-metadata.json").exists()
        return original(raw)
    monkeypatch.setattr(bundle[0], '_native_summary', summary)
    scalar=c.parser._scalar
    def selected_only(raw,span):
        assert b'SYNTHETIC_PRIVATE_NOTE' not in raw[slice(*span)]
        return scalar(raw,span)
    monkeypatch.setattr(c.parser,'_scalar',selected_only)
    adapter, result = execute(bundle, fault="error")
    assert result.outcome == "reconciliation_required" and adapter.sends == 1 and not adapter.raw
    observed = bundle[0].inspect_original_response()
    assert (observed.http_status, observed.native_http_status, observed.native_status, observed.native_error) == (500, 500, 'error', -3)
    assert observed.native_context_matches and not observed.success_ack_retained
    assert observed.original_outcome == 'reconciliation_required' and observed.original_verification == 'unknown'
    records = b''.join(path.read_bytes() for path in (tmp_path / 'custody').iterdir())
    for forbidden in (b'synthetic-appliance', b'mcp-v4-jwt-synthetic', b'PUBLIC KEY', b'PRIVATE_NOTE'):
        assert forbidden not in records and forbidden.decode() not in repr(observed)


@pytest.mark.parametrize("fault", ["html", "malformed", "partial", "oversize", "foreign", "schema", "expired", "backward",
    "invalid-clock", "gate-closed", "source-drift", "request-closed", "producer-invalid"])
def test_unknown_or_drifted_original_response_remains_consumed_observation(tmp_path, synthetic_key, fault):
    bundle = create(tmp_path, synthetic_key)
    adapter, result = execute(bundle, fault=fault)
    assert adapter.sends == 1 and result.outcome == 'reconciliation_required' and not adapter.raw
    observed = bundle[0].inspect_original_response()
    assert not observed.success_ack_retained and not (tmp_path / 'custody/create-ack.json').exists()
    assert observed.body_state == ('partial' if fault == 'partial' else 'oversize' if fault == 'oversize' else 'complete')
    if fault in {'partial', 'oversize', 'html', 'malformed'}: assert observed.native_status == 'unknown'
    before = {p.name: p.read_bytes() for p in (tmp_path / 'custody').iterdir()}
    clone = components(tmp_path, bundle[5])
    fresh = response()
    with pytest.raises(c.JwtManualKeyResponseCustodyError): clone[0].capture_original_response(fresh, http_status=200, content_type='application/json')
    assert not fresh
    replay, replay_result = execute(clone)
    assert replay_result.idempotent_replay and replay.sends == 0 and clone[1].claim_count == 1
    assert {p.name: p.read_bytes() for p in (tmp_path / 'custody').iterdir()} == before


@pytest.mark.parametrize('fault',['error','post-unknown'])
def test_original_error_or_ack_and_unknown_result_survive_independent_process_after_expiry(tmp_path, synthetic_key, fault):
    bundle = create(tmp_path, synthetic_key)
    adapter, result = execute(bundle, fault=fault)
    assert result.outcome == 'reconciliation_required' and adapter.sends == 1 and not adapter.raw
    observed = bundle[0].inspect_original_response()
    assert observed.success_ack_retained is (fault=='post-unknown') and observed.original_verification == 'unknown'
    bundle[4].close()
    assert bundle[0].inspect_original_response() == observed
    before = {p.name: p.read_bytes() for p in (tmp_path / 'custody').iterdir()}
    child = '''
import sys
from pathlib import Path
from test_jwt_manual_key_response_custody import components
from test_m4_execution_store import _ExternalM4Checkpoint
from fortipam_mcp.m4_execution_store import M4ExecutionStoreTail
checkpoint=_ExternalM4Checkpoint()
checkpoint.tail=M4ExecutionStoreTail(checkpoint.tail.store_ref,int(sys.argv[2]),sys.argv[3])
bundle=components(Path(sys.argv[1]),checkpoint,now=[2000],read_only=True)
bundle[4].close()
observed=bundle[0].inspect_original_response()
assert observed.success_ack_retained is (sys.argv[4]=='post-unknown') and observed.original_outcome=='reconciliation_required'
if sys.argv[4]=='error':assert observed.native_error==-3 and observed.http_status==500
assert observed.original_verification=='unknown' and bundle[1].claim_count==1
print(observed.custody_digest)
'''
    env = {**os.environ, 'PYTHONPATH': os.pathsep.join((str(Path(__file__).parent), os.environ.get('PYTHONPATH', '')))}
    done = subprocess.run([sys.executable, '-c', child, str(tmp_path), str(bundle[5].tail.sequence), bundle[5].tail.chain_hmac, fault],
                          env=env, capture_output=True, text=True, timeout=20)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == observed.custody_digest
    assert {p.name: p.read_bytes() for p in (tmp_path / 'custody').iterdir()} == before


@pytest.mark.parametrize('fault', ['default-gates', 'source', 'actor', 'expired'])
def test_pre_send_guard_refusal_never_creates_a_send_or_response(tmp_path, synthetic_key, fault):
    bundle = create(tmp_path, synthetic_key)
    if fault == 'default-gates': bundle[0]._execution_enabled = None
    if fault == 'source': bundle[7]['source'] = False
    if fault == 'actor': bundle[7]['actor'] = False
    if fault == 'expired': bundle[6][0] = bundle[3].expires_at
    adapter, result = execute(bundle)
    assert adapter.sends == 0 and result.outcome == 'reconciliation_required'
    assert list((tmp_path / 'custody').iterdir()) == []


def test_response_parsing_interruption_keeps_original_baseline_without_late_backfill(tmp_path, synthetic_key, monkeypatch):
    bundle = create(tmp_path, synthetic_key)
    def interrupted(raw): raise KeyboardInterrupt
    monkeypatch.setattr(bundle[0], '_native_summary', interrupted)
    adapter = Adapter(bundle)
    with pytest.raises(KeyboardInterrupt): execute(bundle, adapter=adapter)
    assert adapter.sends == 1 and not adapter.raw
    assert {p.name for p in (tmp_path / 'custody').iterdir()} == {'send.claim.json', 'response.json'}
    observed = bundle[0].inspect_original_response()
    assert observed.http_status == 200 and observed.native_status == 'unknown' and not observed.success_ack_retained
    assert observed.original_outcome == 'in_progress'
    clone = components(tmp_path, bundle[5])
    raw = response()
    with pytest.raises(c.JwtManualKeyResponseCustodyError): clone[0].capture_original_response(raw, http_status=200, content_type='application/json')
    assert not raw and len(list((tmp_path / 'custody').iterdir())) == 2


def test_matching_reservation_alone_cannot_start_custody(tmp_path, synthetic_key):
    bundle = create(tmp_path, synthetic_key)
    custody, store, p, a, *_ = bundle
    store.claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest, idempotency_digest=p.idempotency_digest,
        authorization_digest=a.authorization_digest, context_digest=canonical_digest({'plan_digest':p.plan_digest,
            'authorization_digest':a.authorization_digest,'revision':p.revision}))
    with pytest.raises(c.JwtManualKeyResponseCustodyError): custody.begin_original_send()
    assert list((tmp_path / 'custody').iterdir()) == []


@pytest.mark.parametrize('field',['action_id','adapter_ref','target_ref','parameters_digest','expected_current_digest'])
def test_custody_rejects_a_valid_m4_plan_for_another_action_or_request(tmp_path, synthetic_key, field):
    bundle=create(tmp_path,synthetic_key)
    fields=asdict(bundle[2]);fields.pop('plan_digest')
    fields[field]='f'*64 if field.endswith('_digest') else 'another-bound-action'
    plan=M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields));auth=_authorization(plan)
    with pytest.raises(c.JwtManualKeyResponseCustodyError):
        c.JwtManualKeyResponseCustody(tmp_path/'custody',tmp_path/'witness.key',bundle[4],bundle[0]._actor,
            'a'*64,'b'*64,plan,auth,bundle[1])
    assert bundle[1].claim_count==0 and list((tmp_path/'custody').iterdir())==[]


@pytest.mark.parametrize('fault',['source','clock','interrupt'])
def test_drift_or_interruption_after_ack_parse_does_not_issue_a_success_receipt(tmp_path, synthetic_key, monkeypatch, fault):
    bundle=create(tmp_path,synthetic_key)
    consume=c.consume_jwt_manual_create_ack
    def after_parse(*args,**kwargs):
        result=consume(*args,**kwargs)
        assert (tmp_path/'custody/response.json').exists() and (tmp_path/'custody/response-metadata.json').exists()
        if fault=='source':bundle[7]['source']=False
        if fault=='clock':bundle[6][0]=bundle[3].expires_at
        if fault=='interrupt':raise KeyboardInterrupt
        return result
    monkeypatch.setattr(c,'consume_jwt_manual_create_ack',after_parse)
    adapter=Adapter(bundle)
    if fault=='interrupt':
        with pytest.raises(KeyboardInterrupt):execute(bundle,adapter=adapter)
    else:
        _,result=execute(bundle,adapter=adapter)
        assert result.outcome=='reconciliation_required'
    observed=bundle[0].inspect_original_response()
    assert observed.native_status=='success' and not observed.success_ack_retained and not adapter.raw
    assert {p.name for p in (tmp_path/'custody').iterdir()}=={'send.claim.json','response.json','response-metadata.json'}


def test_other_instance_and_thread_cannot_adopt_the_original_in_flight_response(tmp_path, synthetic_key):
    bundle = create(tmp_path, synthetic_key); clone = components(tmp_path, bundle[5])
    class PeerAdapter(Adapter):
        def dispatch(self, plan):
            self.c.begin_original_send(); self.sends += 1
            for candidate in (clone[0], self.c):
                errors=[]; raw=response()
                def attempt():
                    try: candidate.capture_original_response(raw,http_status=200,content_type='application/json')
                    except c.JwtManualKeyResponseCustodyError: errors.append(True)
                if candidate is clone[0]: attempt()
                else:
                    worker=Thread(target=attempt);worker.start();worker.join(timeout=3);assert not worker.is_alive()
                assert errors == [True] and not raw
            raise M4AdapterAmbiguous('Synthetic no legitimate capture.')
    adapter,result=execute(bundle,adapter=PeerAdapter(bundle))
    assert adapter.sends==1 and result.outcome=='reconciliation_required'
    assert {p.name for p in (tmp_path/'custody').iterdir()} == {'send.claim.json'}


@pytest.mark.parametrize('fault',['hmac','context','key','permissions'])
def test_drifted_original_evidence_is_never_repaired(tmp_path, synthetic_key, fault):
    bundle=create(tmp_path,synthetic_key);execute(bundle,fault='error')
    path=tmp_path/'custody/response.json'
    if fault in {'hmac','context'}:
        value=json.loads(path.read_bytes());value['http_status' if fault=='hmac' else 'context_digest']=200 if fault=='hmac' else 'f'*64
        path.write_text(json.dumps(value))
    if fault=='key': (tmp_path/'witness.key').write_bytes(b'z'*32)
    if fault=='permissions': path.chmod(0o644)
    before={p.name:p.read_bytes() for p in (tmp_path/'custody').iterdir()}
    with pytest.raises(c.JwtManualKeyResponseCustodyError):bundle[0].inspect_original_response()
    assert {p.name:p.read_bytes() for p in (tmp_path/'custody').iterdir()}==before
