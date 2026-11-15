"""Independent pair recovery HMAC/M4 authority and original-ACK ownership."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_server_pair_recovery_workflow import RadiusServerPairRecoveryWorkflow, RadiusServerPairRecoveryError
from v4_planning import canonical_digest
from test_radius_server_pair_live_workflow import setup, grant, IDENTITY, CONFIG
from test_radius_server_pair_m4_runtime import store
from test_radius_server_projection import SERIAL

RECOVERY_KEY=b'synthetic-pair-recovery-key-00001'


def recovery(root: Path,peer: Any,now: list[int],**overrides: Any) -> Any:
    values=dict(expected_serial=SERIAL,state_directory=root/'http',execution_store=store(root,'recovery',True),
        authority_key=RECOVERY_KEY,environment_ref='synthetic-pair-lab',scope_ref='synthetic-pair-recovery',
        audience_ref='synthetic-pair-audience',allowed_requester_digest=IDENTITY['requester_digest'],
        allowed_transport_digest=IDENTITY['transport_digest'],execution_enabled=True,clock=lambda:now[0],
        connection_factory=peer.connection)
    values.update(overrides)
    return RadiusServerPairRecoveryWorkflow(peer.binding,CONFIG,**values)


def created(root: Path,**faults: Any) -> tuple[Any,...]:
    w,peer,now,factory,values=setup(root)
    ref=grant(w)
    for name,value in faults.items():setattr(peer,name,value)
    result=w.execute(ref,**IDENTITY)
    return w,peer,now,factory,result


def test_independent_authority_after_create_shutdown_and_exact_summary_binding(tmp_path: Path) -> None:
    w,peer,now,factory,result=created(tmp_path)
    assert result['outcome']=='succeeded'
    create_approver=w._authority._issued.authorization.approver_digest
    w.close();now[0]=170
    r=recovery(tmp_path,peer,now)
    p=r.preview(**IDENTITY)
    assert p['summary_digest']==canonical_digest({k:v for k,v in p.items() if k!='summary_digest'})
    auth=r.authorize(p['preview_ref'],**IDENTITY)
    assert r._issued.plan.summary_digest==p['summary_digest']
    assert r._issued.authorization.approver_digest!=create_approver
    result=r.execute(auth['authorization_ref'],**IDENTITY)
    assert result['outcome']=='succeeded' and result['verification']=='verified'
    assert peer.posts==peer.deletes==r._store.claim_count==1 and peer.row is None and len(factory.calls)==4
    before=len(peer.connections)
    assert r.execute(auth['authorization_ref'],**IDENTITY)['idempotent_replay']
    fresh=recovery(tmp_path,peer,now)
    with pytest.raises(RadiusServerPairRecoveryError):fresh.preview(**IDENTITY)
    assert len(peer.connections)==before and peer.deletes==1 and len(factory.calls)==4
    encoded=json.dumps([p,auth,result,repr(r)])
    for private in (peer.binding.name,peer.binding.server,peer.binding.secondary_server,peer.binding.private_nonce,
                    'A'*32,'B'*32,SERIAL,'synthetic-token',str(tmp_path)):
        assert private not in encoded


@pytest.mark.parametrize('fault',['lost_post_ack','failed_readback'])
def test_create_uncertainty_does_not_invent_original_ack(tmp_path: Path,fault: str) -> None:
    w,peer,now,factory,result=created(tmp_path,**{fault:True})
    assert result['outcome']=='reconciliation_required'
    r=recovery(tmp_path,peer,now)
    if fault=='lost_post_ack':
        with pytest.raises(RadiusServerPairRecoveryError):grant(r)
        assert peer.deletes==0
    else:
        peer.failed_readback=False
        assert r.execute(grant(r),**IDENTITY)['outcome']=='succeeded'
        assert peer.deletes==1
    assert len(factory.calls)==4


@pytest.mark.parametrize('fault',['q_ref','secondary','secondary_token','other_scalar','defaults'])
def test_full_pair_state_drift_rejects_before_delete(tmp_path: Path,fault: str) -> None:
    w,peer,now,factory,_=created(tmp_path);r=recovery(tmp_path,peer,now);ref=grant(r)
    if fault=='q_ref':peer.row['q_ref']=1
    elif fault=='secondary':peer.row['secondary-server']='192.0.2.12'
    elif fault=='secondary_token':peer.row['secondary-secret']='SYNTHETIC_CHANGED'
    elif fault=='other_scalar':peer.row['timeout']=15
    else:peer.defaults['timeout']=15
    assert r.execute(ref,**IDENTITY)['outcome']!='succeeded'
    assert peer.deletes==0 and not (tmp_path/'http/delete.claim.json').exists() and len(factory.calls)==4


@pytest.mark.parametrize('fault',['identity','expired','clock','gate','scope','plan','key','api','store','callback','native_gate'])
def test_invalid_recovery_authority_never_dispatches(tmp_path: Path,fault: str) -> None:
    w,peer,now,factory,_=created(tmp_path);r=recovery(tmp_path,peer,now);ref=grant(r)
    identity=dict(IDENTITY)
    if fault=='native_gate':r._transport._owned_connect_enabled=True
    elif fault=='identity':identity['requester_digest']='f'*64
    elif fault=='expired':now[0]=160
    elif fault=='clock':now[0]=99
    elif fault=='gate':r.close()
    elif fault=='scope':r._namespace['scope_ref']='foreign-scope'
    elif fault=='plan':object.__setattr__(r._issued.plan,'summary_digest','f'*64)
    elif fault=='key':r._key=b'x'*32
    elif fault=='api':r._transport._config=replace(CONFIG,base_url='https://other.example')
    elif fault=='store':r._store=w._execution_store
    else:r._transport._authorize_recovery=lambda *a:True
    with pytest.raises(RadiusServerPairRecoveryError):r.execute(ref,**identity)
    assert peer.deletes==0 and len(factory.calls)==4


@pytest.mark.parametrize('fault',['lost_ack','absence','expiry_at_send','gate_at_send'])
def test_uncertain_delete_retains_claims_and_only_readonly_reconciliation(tmp_path: Path,fault: str) -> None:
    w,peer,now,factory,_=created(tmp_path);r=recovery(tmp_path,peer,now);ref=grant(r)
    if fault=='lost_ack':peer.lost_delete_ack=True
    elif fault=='absence':peer.bad_absence=True
    else:
        def on_connect() -> None:
            if (tmp_path/'http/delete.claim.json').exists():
                if fault=='expiry_at_send':now[0]=160
                else:r._enabled=False
        peer.on_connect=on_connect
    result=r.execute(ref,**IDENTITY)
    assert result['outcome']=='reconciliation_required' and r._store.claim_count==1
    assert peer.deletes==int(fault in {'lost_ack','absence'}) and len(factory.calls)==4
    peer.on_connect=None;peer.bad_absence=False
    if fault in {'lost_ack','absence'}:
        before=len(peer.connections)
        assert r.execute(ref,**IDENTITY)['idempotent_replay']
        assert len(peer.connections)==before and r._transport.inspect_deleted()
    fresh=recovery(tmp_path,peer,now)
    with pytest.raises(RadiusServerPairRecoveryError):fresh.preview(**IDENTITY)
    assert peer.deletes==int(fault in {'lost_ack','absence'})


def test_default_gate_foreign_create_ref_and_original_create_ledger_are_denied(tmp_path: Path) -> None:
    w,peer,now,factory,_=created(tmp_path)
    closed=recovery(tmp_path,peer,now,execution_enabled=False)
    p=closed.preview(**IDENTITY)
    with pytest.raises(RadiusServerPairRecoveryError):closed.authorize(p['preview_ref'],**IDENTITY)
    r=recovery(tmp_path,peer,now);grant(r)
    with pytest.raises(RadiusServerPairRecoveryError):r.execute(w._authority._issued.authorization.authorization_ref,**IDENTITY)
    with pytest.raises(RadiusServerPairRecoveryError):r.preview(**IDENTITY)
    duplicate=recovery(tmp_path,peer,now,execution_store=w._execution_store)
    before=len(peer.connections)
    with pytest.raises(RadiusServerPairRecoveryError):duplicate.preview(**IDENTITY)
    assert len(peer.connections)==before and peer.deletes==0 and len(factory.calls)==4


def test_orphan_in_progress_recovery_cannot_recreate_original_dispatch(tmp_path: Path) -> None:
    w,peer,now,factory,_=created(tmp_path);r=recovery(tmp_path,peer,now);ref=grant(r)
    p,a=r._issued.plan,r._issued.authorization
    r._store.claim(plan_ref=p.plan_ref,requester_digest=p.requester_digest,idempotency_digest=p.idempotency_digest,
        authorization_digest=a.authorization_digest,context_digest=canonical_digest({
            'authorization_digest':a.authorization_digest,'plan_digest':p.plan_digest,'revision':p.revision}))
    r._started=True
    assert not r._authorize_delete(peer.binding,r._preview.owned_digest,r._preview.state_digest)
    assert r.execute(ref,**IDENTITY)['outcome']=='reconciliation_required'
    assert peer.deletes==0 and len(factory.calls)==4
