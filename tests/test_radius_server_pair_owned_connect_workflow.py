"""Original HMAC/M4 ordinal probes, no real device or connectivity qualification."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_server_pair_owned_connect_workflow import RadiusServerPairOwnedConnectWorkflow, RadiusServerPairOwnedConnectError
from fortipam_mcp.radius_server_pair_owned_connect_contract import CONNECT_PATH
from fortipam_mcp.radius_server_pair_contract import RadiusServerPairError
from test_radius_server_pair_live_workflow import IDENTITY, CONFIG, grant
from test_radius_server_pair_recovery_workflow import created, recovery
from test_radius_server_pair_m4_runtime import store
from test_radius_server_pair_http_transport import Response
from test_radius_server_projection import SERIAL, envelope
from v4_planning import canonical_digest

KEY=b'synthetic-pair-native-key-0000001'


def setup(root: Path) -> tuple[Any,...]:
    w,peer,now,factory,result=created(root)
    assert result['outcome']=='succeeded'
    original=peer.handle;peer.native_posts=[];peer.native_fault=None;peer.native_status='reachable'
    def native(method: str,path: str,body: Any) -> Any:
        if method!='POST' or path!=CONNECT_PATH:return original(method,path,body)
        submitted=json.loads(bytes(body));ordinal=submitted['ordinal']
        assert ordinal in {'primary','secondary'}
        address=peer.binding.server if ordinal=='primary' else peer.binding.secondary_server
        assert submitted=={'mkey':peer.binding.name,'server':address,'auth_type':'auto','ordinal':ordinal}
        peer.native_posts.append(ordinal)
        if peer.native_fault=='lost':raise TimeoutError('Synthetic native reply lost.')
        if peer.native_fault=='drift':peer.row['secondary-secret']='SYNTHETIC_CHANGED'
        result={'status':peer.native_status}
        if peer.native_fault=='reject_shape':result|={'access_status':'Access-Reject','access_message':'SYNTHETIC_PRIVATE'}
        if peer.native_fault=='foreign_server':result['server']='192.0.2.12'
        return Response(envelope(http_method='POST',action='test-connect',mkey=peer.binding.name,results=result))
    peer.handle=native
    return w,peer,now,factory


def connect(root: Path,peer: Any,now: list[int],ordinal: str,**changes: Any) -> Any:
    values=dict(ordinal=ordinal,expected_serial=SERIAL,state_directory=root/'http',
        execution_store=store(root,'native-'+ordinal,True),authority_key=KEY,
        environment_ref='synthetic-pair-lab',scope_ref='synthetic-pair-native-'+ordinal,
        audience_ref='synthetic-pair-audience',allowed_requester_digest=IDENTITY['requester_digest'],
        allowed_transport_digest=IDENTITY['transport_digest'],execution_enabled=True,clock=lambda:now[0],
        connection_factory=peer.connection)
    values.update(changes)
    return RadiusServerPairOwnedConnectWorkflow(peer.binding,CONFIG,**values)


@pytest.mark.parametrize('status',['reachable','invalid_secret','SYNTHETIC_UNKNOWN'])
def test_both_ordinals_are_independent_once_only_observations_then_recover(tmp_path: Path,status: str) -> None:
    w,peer,now,factory=setup(tmp_path);peer.native_status=status
    plans=[]
    for ordinal in ('primary','secondary'):
        selected=connect(tmp_path,peer,now,ordinal)
        p=selected.preview(**IDENTITY)
        assert p['summary_digest']==canonical_digest({k:v for k,v in p.items() if k!='summary_digest'})
        auth=selected.authorize(p['preview_ref'],**IDENTITY)
        assert selected._issued.plan.summary_digest==p['summary_digest']
        plans.append(selected._issued.plan.parameters_digest)
        result=selected.execute(auth['authorization_ref'],**IDENTITY)
        assert result['outcome']=='succeeded' and result['verification']=='verified'
        assert result['ordinal']==ordinal and result['execution_scope']=='native_response_observation_only'
        assert result['observation']['ordinal']==ordinal and not result['connectivity_qualified']
        assert not result['observation']['connectivity_qualified'] and selected._store.claim_count==1
        count=len(peer.connections)
        assert selected.execute(auth['authorization_ref'],**IDENTITY)['idempotent_replay']
        with pytest.raises(RadiusServerPairError):selected._transport.observe_owned_connect()
        with pytest.raises(RadiusServerPairOwnedConnectError):connect(tmp_path,peer,now,ordinal).preview(**IDENTITY)
        assert len(peer.connections)==count
        selected.close()
        rendered=json.dumps([p,auth,result])
        for value in (peer.binding.name,peer.binding.server,peer.binding.secondary_server,SERIAL,
                      peer.binding.private_nonce,'SYNTHETIC_UNKNOWN'):
            assert value not in rendered
    assert plans[0]!=plans[1] and peer.native_posts==['primary','secondary'] and len(factory.calls)==4
    r=recovery(tmp_path,peer,now)
    assert r.execute(grant(r),**IDENTITY)['outcome']=='succeeded' and peer.deletes==1 and len(factory.calls)==4
    assert all(not any(b) for b in peer.bodies)


@pytest.mark.parametrize('fault',['default','expiry','clock','identity','gate','plan','namespace','ordinal','api','callback','store'])
def test_invalid_native_authority_cannot_dispatch(tmp_path: Path,fault: str) -> None:
    w,peer,now,factory=setup(tmp_path)
    selected=connect(tmp_path,peer,now,'secondary',execution_enabled=fault!='default')
    if fault=='default':
        p=selected.preview(**IDENTITY)
        with pytest.raises(RadiusServerPairOwnedConnectError):selected.authorize(p['preview_ref'],**IDENTITY)
    else:
        ref=grant(selected);identity=dict(IDENTITY)
        if fault=='expiry':now[0]=160
        elif fault=='clock':now[0]=99
        elif fault=='identity':identity['transport_digest']='f'*64
        elif fault=='gate':selected.close()
        elif fault=='plan':object.__setattr__(selected._issued.plan,'summary_digest','f'*64)
        elif fault=='namespace':selected._namespace['scope_ref']='another-scope'
        elif fault=='ordinal':selected._transport._ordinal='primary'
        elif fault=='api':selected._transport._config=replace(CONFIG,base_url='https://other.example')
        elif fault=='callback':selected._transport._authorize_owned_connect=lambda *a:True
        else:selected._store=w._execution_store
        with pytest.raises(RadiusServerPairOwnedConnectError):selected.execute(ref,**identity)
    assert not peer.native_posts and len(factory.calls)==4


@pytest.mark.parametrize('fault',['lost','drift','foreign_server','expire_at_send','close_at_send'])
def test_uncertain_native_retains_http_and_m4_claims_without_replay(tmp_path: Path,fault: str) -> None:
    w,peer,now,factory=setup(tmp_path);selected=connect(tmp_path,peer,now,'primary');ref=grant(selected)
    if fault in {'lost','drift','foreign_server'}:peer.native_fault=fault
    else:
        def on_connect() -> None:
            if (tmp_path/'http/pair-native-primary.claim.json').exists():
                if fault=='expire_at_send':now[0]=160
                else:selected.close()
        peer.on_connect=on_connect
    result=selected.execute(ref,**IDENTITY)
    assert result['outcome']=='reconciliation_required' and result['verification']=='unknown'
    assert selected._store.claim_count==1 and (tmp_path/'http/pair-native-primary.claim.json').exists()
    assert peer.native_posts==(['primary'] if fault in {'lost','drift','foreign_server'} else [])
    peer.on_connect=None
    if fault not in {'expire_at_send','close_at_send'}:
        before=len(peer.connections)
        assert selected.execute(ref,**IDENTITY)['idempotent_replay']
        assert len(peer.connections)==before
    with pytest.raises(RadiusServerPairOwnedConnectError):connect(tmp_path,peer,now,'primary').preview(**IDENTITY)
    assert len(factory.calls)==4 and all(not any(b) for b in peer.bodies)


def test_reject_shape_is_only_syntax_and_stored_result_cannot_cross_ordinals(tmp_path: Path) -> None:
    w,peer,now,factory=setup(tmp_path);peer.native_status='ok';peer.native_fault='reject_shape'
    selected=connect(tmp_path,peer,now,'secondary')
    result=selected.execute(grant(selected),**IDENTITY)
    assert result['outcome']=='succeeded' and result['observation']['reject_only_shape']
    assert not result['observation']['connectivity_qualified']
    path=tmp_path/'http/pair-native-secondary.result.json';record=json.loads(path.read_text())
    record['observation']['ordinal']='primary';path.write_text(json.dumps(record));path.chmod(0o600)
    with pytest.raises(RadiusServerPairError):selected._transport.inspect_owned_connect_observation()
    assert peer.native_posts==['secondary'] and len(factory.calls)==4


def test_copied_authority_and_orphan_claim_do_not_supply_original_dispatch(tmp_path: Path) -> None:
    w,peer,now,factory=setup(tmp_path);selected=connect(tmp_path,peer,now,'primary');ref=grant(selected)
    secondary=connect(tmp_path,peer,now,'secondary');secondary._preview=selected._preview
    with pytest.raises(RadiusServerPairOwnedConnectError):secondary.authorize(selected._preview.preview_ref,**IDENTITY)
    p,a=selected._issued.plan,selected._issued.authorization
    selected._store.claim(plan_ref=p.plan_ref,requester_digest=p.requester_digest,idempotency_digest=p.idempotency_digest,
        authorization_digest=a.authorization_digest,context_digest=canonical_digest({
            'authorization_digest':a.authorization_digest,'plan_digest':p.plan_digest,'revision':p.revision}))
    selected._started=True
    assert not selected._authorize_connect(peer.binding,'primary',selected._preview.owned_digest,selected._preview.state_digest)
    assert selected.execute(ref,**IDENTITY)['outcome']=='reconciliation_required'
    assert not peer.native_posts and len(factory.calls)==4


def test_native_marker_without_namespace_is_not_adopted(tmp_path: Path) -> None:
    w,peer,now,factory=setup(tmp_path)
    namespace=tmp_path/'http/namespace.json';namespace.unlink()
    claim=tmp_path/'http/pair-native-secondary.claim.json';claim.write_text('{}');claim.chmod(0o600)
    with pytest.raises(RadiusServerPairOwnedConnectError):connect(tmp_path,peer,now,'secondary').preview(**IDENTITY)
    assert not namespace.exists() and not peer.native_posts and len(factory.calls)==4


def test_result_persistence_failure_consumes_native_and_clears_body(tmp_path: Path,monkeypatch: Any) -> None:
    from fortipam_mcp.radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport
    w,peer,now,factory=setup(tmp_path);selected=connect(tmp_path,peer,now,'secondary');ref=grant(selected)
    original=FortiPamRadiusPairHttpTransport._write_once
    def write(self: Any,name: str,value: Any) -> None:
        if name=='pair-native-secondary.result.json':raise OSError('Synthetic disk error.')
        original(self,name,value)
    monkeypatch.setattr(FortiPamRadiusPairHttpTransport,'_write_once',write)
    assert selected.execute(ref,**IDENTITY)['outcome']=='reconciliation_required'
    assert peer.native_posts==['secondary'] and all(not any(b) for b in peer.bodies)
    assert (tmp_path/'http/pair-native-secondary.diagnostic.json').exists()
    assert selected.execute(ref,**IDENTITY)['idempotent_replay'] and peer.native_posts==['secondary']
