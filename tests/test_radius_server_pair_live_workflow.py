"""Real paired HMAC/M4/C3/pipe composition; synthetic fixture and HTTP peers."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_pair_fixture_material_worker import _digest
from fortipam_mcp.radius_server_pair_live_workflow import RadiusServerPairLiveWorkflow, RadiusServerPairLiveWorkflowError
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import canonical_digest
from test_radius_server_pair_http_transport import Peer
from test_radius_server_pair_m4_runtime import store
from test_radius_pair_fixture_material_worker import fixture, write
from test_radius_pair_fixture_material_loader import Factory, peer_script
from test_radius_server_projection import SERIAL

IDENTITY={'requester_digest':'1'*64,'transport_digest':'2'*64}
CONFIG=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',1,None)
KEY=b'synthetic-pair-authority-key-00001'


def setup(root: Path,*,enabled: bool=True,lose_primary: bool=False,**overrides: Any) -> tuple[Any,...]:
    peer=Peer();now=[100];task=root/'fixture'
    _,inspections,policy=fixture(task)
    policy['scope_digest']=canonical_digest('synthetic-pair-scope')
    policy['audience_digest']=canonical_digest('synthetic-pair-audience')
    write(task/'pair-material-policy.json',policy)
    for name in ('identity','known_hosts'):write(root/name,b'synthetic-file')
    factory=Factory(peer_script(task,inspections,lose_primary_reply=lose_primary))
    (root/'http').mkdir(mode=0o700)
    values=dict(expected_serial=SERIAL,state_directory=root/'http',source_host='fixture.example',
        source_identity_file=root/'identity',source_known_hosts_file=root/'known_hosts',
        source_policy_digest=_digest(policy),source_reservation_store=store(root,'group'),
        execution_store=store(root,'m4',True),material_store=store(root,'usage'),authority_key=KEY,
        environment_ref='synthetic-pair-lab',scope_ref='synthetic-pair-scope',audience_ref='synthetic-pair-audience',
        allowed_requester_digest=IDENTITY['requester_digest'],allowed_transport_digest=IDENTITY['transport_digest'],
        execution_enabled=enabled,clock=lambda:now[0],connection_factory=peer.connection,source_process_factory=factory)
    values.update(overrides)
    selected=RadiusServerPairLiveWorkflow(peer.binding,CONFIG,**values)
    return selected,peer,now,factory,values


def grant(w: Any) -> str:
    p=w.preview(**IDENTITY)
    return w.authorize(p['preview_ref'],**IDENTITY)['authorization_ref']


def test_signed_display_summary_real_kernel_pipe_and_persistent_nonreplay(tmp_path: Path) -> None:
    w,peer,now,factory,values=setup(tmp_path)
    assert not peer.connections and not factory.calls
    preview=w.preview(**IDENTITY)
    assert preview['summary_digest']==canonical_digest({k:v for k,v in preview.items() if k!='summary_digest'})
    auth=w.authorize(preview['preview_ref'],**IDENTITY)
    assert w._authority._issued.plan.summary_digest==preview['summary_digest']
    assert not factory.calls and peer.posts==0
    result=w.execute(auth['authorization_ref'],**IDENTITY)
    assert result['outcome']=='succeeded' and result['verification']=='verified'
    assert len(factory.calls)==4 and peer.posts==1 and peer.deletes==0
    assert w._execution_store.claim_count==w._material_store.claim_count==w._group_store.claim_count==1
    assert all(not any(b) for b in peer.bodies)
    before=len(peer.connections)
    assert w.execute(auth['authorization_ref'],**IDENTITY)['idempotent_replay']
    assert len(peer.connections)==before and len(factory.calls)==4
    fresh=RadiusServerPairLiveWorkflow(peer.binding,CONFIG,**values)
    with pytest.raises(RadiusServerPairLiveWorkflowError):fresh.preview(**IDENTITY)
    assert len(peer.connections)==before and len(factory.calls)==4
    encoded=json.dumps([preview,auth,result,repr(w)])
    for private in (peer.binding.name,peer.binding.server,peer.binding.secondary_server,peer.binding.private_nonce,
                    'A'*32,'B'*32,SERIAL,'synthetic-token','synthetic-pair-scope',str(tmp_path)):
        assert private not in encoded


@pytest.mark.parametrize('fault',['identity','expired','clock','gate','scope','plan','key','source','store','source_file','api'])
def test_authority_or_namespace_drift_prevents_material_and_post(tmp_path: Path,fault: str) -> None:
    w,peer,now,factory,_=setup(tmp_path);ref=grant(w);identity=dict(IDENTITY)
    if fault=='identity':identity['transport_digest']='f'*64
    elif fault=='expired':now[0]=160
    elif fault=='clock':now[0]=99
    elif fault=='gate':w._enabled=False
    elif fault=='scope':w._authority._namespace['scope_ref']='another-scope'
    elif fault=='plan':object.__setattr__(w._authority._issued.plan,'summary_digest','f'*64)
    elif fault=='key':w._authority._key=b'x'*32
    elif fault=='source':w._source._host='another.example'
    elif fault=='store':w._group_store=w._material_store
    elif fault=='source_file':write(tmp_path/'identity',b'changed-synthetic-file')
    else:w._config=replace(CONFIG,base_url='https://other.example')
    with pytest.raises(RadiusServerPairLiveWorkflowError):w.execute(ref,**identity)
    assert not factory.calls and peer.posts==0


@pytest.mark.parametrize('fault',['primary_reply','lost_ack','readback','state_drift','close','gate'])
def test_uncertain_or_revoked_run_consumes_without_source_rehydration(tmp_path: Path,fault: str) -> None:
    w,peer,now,factory,values=setup(tmp_path,lose_primary=fault=='primary_reply')
    ref=grant(w)
    if fault=='lost_ack':peer.lost_post_ack=True
    elif fault=='readback':peer.failed_readback=True
    elif fault=='state_drift':peer.defaults['timeout']=15
    else:
        if fault in {'close','gate'}:
            def on_connect() -> None:
                if (tmp_path/'http/create.claim.json').exists():
                    if fault=='close':w.close()
                    else:w._enabled=False
            peer.on_connect=on_connect
    result=w.execute(ref,**IDENTITY)
    assert result['outcome']==('precondition_failed' if fault=='state_drift' else 'reconciliation_required')
    assert result['verification']==('not_started' if fault=='state_drift' else 'unknown')
    assert peer.posts==int(fault in {'lost_ack','readback'})
    before=len(factory.calls)
    if w._enabled:assert w.execute(ref,**IDENTITY)['idempotent_replay']
    fresh=RadiusServerPairLiveWorkflow(peer.binding,CONFIG,**values)
    with pytest.raises(RadiusServerPairLiveWorkflowError):fresh.preview(**IDENTITY)
    assert len(factory.calls)==before and all(not any(b) for b in peer.bodies)


def test_default_closed_preview_has_no_source_access_and_cannot_authorize(tmp_path: Path) -> None:
    w,peer,_,factory,_=setup(tmp_path,enabled=False)
    p=w.preview(**IDENTITY)
    with pytest.raises(RadiusServerPairLiveWorkflowError):w.authorize(p['preview_ref'],**IDENTITY)
    assert not factory.calls and peer.posts==0


def test_authorization_is_once_bound_and_cannot_be_superseded_before_dispatch(tmp_path: Path) -> None:
    w,peer,_,factory,_=setup(tmp_path);p=w.preview(**IDENTITY)
    auth=w.authorize(p['preview_ref'],**IDENTITY)
    with pytest.raises(RadiusServerPairLiveWorkflowError):w.preview(**IDENTITY)
    with pytest.raises(RadiusServerPairLiveWorkflowError):w.authorize(p['preview_ref'],**IDENTITY)
    assert not factory.calls and peer.posts==0
    assert w.execute(auth['authorization_ref'],**IDENTITY)['outcome']=='succeeded'


@pytest.mark.parametrize('fault',['stale_ref','expired','current_drift','foreign_authority'])
def test_preview_cannot_authorize_after_binding_or_freshness_changes(tmp_path: Path,fault: str) -> None:
    w,peer,now,factory,values=setup(tmp_path);p=w.preview(**IDENTITY)
    selected=w
    if fault=='stale_ref':w.preview(**IDENTITY)
    elif fault=='expired':now[0]=160
    elif fault=='current_drift':peer.defaults['timeout']=15
    else:
        selected=RadiusServerPairLiveWorkflow(peer.binding,CONFIG,**(values|{'scope_ref':'another-scope'}))
        selected._preview=w._preview
    with pytest.raises(RadiusServerPairLiveWorkflowError):selected.authorize(p['preview_ref'],**IDENTITY)
    assert not factory.calls and peer.posts==w._execution_store.claim_count==w._material_store.claim_count==w._group_store.claim_count==0


def test_constructor_refuses_shared_material_store_or_authority_key(tmp_path: Path) -> None:
    w,peer,now,factory,values=setup(tmp_path)
    for changed in ({'source_reservation_store':values['material_store']},
                    {'authority_key':values['execution_store']._key}):
        with pytest.raises(RadiusServerPairLiveWorkflowError):RadiusServerPairLiveWorkflow(peer.binding,CONFIG,**(values|changed))
    assert not factory.calls and not peer.connections
