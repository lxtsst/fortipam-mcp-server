"""Fixed pair HTTP lifecycle and original-ACK drift/replay denials; synthetic I/O."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_server_contract import RadiusServerCreateObservation, RadiusServerCreateOutcome
from fortipam_mcp.radius_server_http_transport import FortiPamRadiusServerHttpTransport
from fortipam_mcp.radius_server_pair_contract import ACTION_ID, RadiusServerPairError
from fortipam_mcp.radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_radius_server_contract import binding as primary_binding
from test_radius_server_pair_contract import binding
from test_radius_server_material_runtime import request as primary_request
from test_radius_server_http_transport import Peer as BasePeer, Connection as BaseConnection, Response, TABLE
from test_radius_server_projection import SERIAL, envelope


class Connection(BaseConnection):
    def request(self, method: str, path: str, body: memoryview | None, headers: dict[str,str]) -> None:
        assert headers['User-Agent']=='fortipam-private-radius-pair-create/1'
        assert headers['Accept-Encoding']=='identity'
        if body is not None:
            assert body.readonly
            self.peer.bodies.append(body.obj)
        self.response=self.peer.handle(method,path,body)
        self.sock=None


class Peer(BasePeer):
    def __init__(self) -> None:
        super().__init__();self.binding=binding()

    def connection(self,host: str,port: int,**kwargs: Any) -> Connection:
        assert host=='pam.example' and port==443 and kwargs['context'].check_hostname
        c=Connection(self);self.connections.append(c);return c

    def handle(self,method: str,path: str,body: memoryview | None) -> Response:
        if method!='POST':return super().handle(method,path,body)
        assert path==TABLE and body is not None
        submitted=json.loads(bytes(body))
        assert set(submitted)=={'name','$originalName','auth-type','server','secondary-server','secret','secondary-secret'}
        assert submitted.pop('secret')=='A'*32 and submitted.pop('secondary-secret')=='B'*32
        assert submitted.pop('$originalName')==''
        self.posts+=1
        self.row=self.defaults|submitted|{'q_ref':0,'secret':'SYNTHETIC_PRIMARY_OPAQUE',
            'secondary-secret':'SYNTHETIC_SECONDARY_OPAQUE'}
        if self.lost_post_ack:raise TimeoutError('SYNTHETIC_PRIVATE')
        return Response(envelope(http_method='POST',mkey='other' if self.foreign_ack else self.binding.name))


def transport(root: Path,peer: Peer,**extra: Any) -> FortiPamRadiusPairHttpTransport:
    root.mkdir(mode=0o700,exist_ok=True)
    values={'expected_serial':SERIAL,'state_directory':root,'clock':lambda:100,'connection_factory':peer.connection}
    values.update(extra)
    return FortiPamRadiusPairHttpTransport(SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,None),peer.binding,**values)


def create(root: Path,peer: Peer,*,authorize: Any=lambda *a:True) -> tuple[Any,...]:
    reader=transport(root,peer);current=reader.inspect_create()
    req=replace(primary_request(),action_id=ACTION_ID)
    writer=transport(root,peer,execution_enabled=True,execution_request=req,
        expected_current_digest=current.state_digest,create_authorizer=authorize)
    a,b=bytearray(b'A'*32),bytearray(b'B'*32)
    with memoryview(a).toreadonly() as p,memoryview(b).toreadonly() as s:
        outcome=writer._create_and_verify_pair_material(peer.binding,req,p,s)
    return writer,outcome,req


def test_pair_create_full_readback_and_separate_original_ack_recovery(tmp_path: Path) -> None:
    peer=Peer();writer,outcome,req=create(tmp_path,peer)
    assert outcome is RadiusServerCreateOutcome.VERIFIED_CREATED
    assert writer.inspect_owned() and peer.posts==1
    assert all(not any(body) for body in peer.bodies)
    restore=transport(tmp_path,peer,recovery_enabled=True,recovery_authorizer=lambda *a:True)
    assert restore.delete_owned() and restore.inspect_deleted() and peer.row is None and peer.deletes==1
    with pytest.raises(RadiusServerPairError):restore.delete_owned()
    assert peer.deletes==1


def test_lost_delete_ack_allows_readonly_reconciliation_without_replay(tmp_path: Path) -> None:
    peer=Peer();create(tmp_path,peer)
    peer.lost_delete_ack=True
    restore=transport(tmp_path,peer,recovery_enabled=True,recovery_authorizer=lambda *a:True)
    with pytest.raises(RadiusServerPairError):restore.delete_owned()
    assert peer.deletes==1 and peer.row is None
    assert restore.inspect_deleted()
    restarted=transport(tmp_path,peer,recovery_enabled=True,recovery_authorizer=lambda *a:True)
    with pytest.raises(RadiusServerPairError):restarted.delete_owned()
    assert restarted.inspect_deleted() and peer.deletes==1


@pytest.mark.parametrize('fault',['lost','foreign','readback'])
def test_uncertain_pair_create_never_replays_or_adopts_without_original_ack(tmp_path: Path,fault: str) -> None:
    peer=Peer()
    if fault=='lost':peer.lost_post_ack=True
    elif fault=='foreign':peer.foreign_ack=True
    else:peer.failed_readback=True
    writer,outcome,req=create(tmp_path,peer)
    assert outcome is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED and peer.posts==1
    assert all(not any(body) for body in peer.bodies)
    before=peer.posts
    with memoryview(bytearray(b'A'*32)).toreadonly() as p,memoryview(bytearray(b'B'*32)).toreadonly() as s:
        assert writer._create_and_verify_pair_material(peer.binding,req,p,s) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts==before
    if fault!='readback':
        assert writer.inspect_uncertain_create() is RadiusServerCreateObservation.PRESENT_OBSERVED
        with pytest.raises(RadiusServerPairError):writer.inspect_owned()
    else:
        peer.failed_readback=False
        assert writer.inspect_owned()


@pytest.mark.parametrize('fault',['reference','secondary','secondary_token','other_scalar','other_opaque','default'])
def test_recovery_refuses_any_reference_or_pair_full_state_drift(tmp_path: Path,fault: str) -> None:
    peer=Peer();writer,outcome,req=create(tmp_path,peer)
    assert outcome is RadiusServerCreateOutcome.VERIFIED_CREATED and peer.row is not None
    if fault=='reference':peer.row['q_ref']=1
    elif fault=='secondary':peer.row['secondary-server']='192.0.2.12'
    elif fault=='secondary_token':peer.row['secondary-secret']='SYNTHETIC_CHANGED'
    elif fault=='other_scalar':peer.row['timeout']=15
    elif fault=='other_opaque':peer.row['tertiary-secret']='SYNTHETIC_CHANGED'
    else:peer.defaults['timeout']=15
    restore=transport(tmp_path,peer,recovery_enabled=True,recovery_authorizer=lambda *a:True)
    with pytest.raises(RadiusServerPairError):restore.delete_owned()
    assert peer.deletes==0


def test_pair_and_primary_journals_cannot_adopt_each_other(tmp_path: Path) -> None:
    from fortipam_mcp.radius_server_contract import RadiusServerCandidateError,RadiusServerCreateBinding
    peer=Peer();transport(tmp_path,peer).inspect_create()
    selected=RadiusServerCreateBinding(peer.binding.name,peer.binding.server,peer.binding.private_nonce)
    primary=FortiPamRadiusServerHttpTransport(SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,None),
        selected,expected_serial=SERIAL,state_directory=tmp_path,clock=lambda:100,connection_factory=peer.connection)
    with pytest.raises(RadiusServerCandidateError):primary.inspect_create()
    other=tmp_path/'orphan';other.mkdir(mode=0o700)
    marker=other/'native-owned-connect.claim.json';marker.write_text('{}');marker.chmod(0o600)
    with pytest.raises(RadiusServerPairError):transport(other,peer).inspect_create()


def test_default_closed_and_final_tls_authorization_recheck_prevent_send(tmp_path: Path) -> None:
    peer=Peer();writer,outcome,req=create(tmp_path,peer,authorize=lambda *a:False)
    assert outcome is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED and peer.posts==0
    peer.on_connect=lambda:setattr(writer,'_execution_enabled',False)
    writer._authorize_create=lambda *a:True
    with memoryview(bytearray(b'A'*32)).toreadonly() as p,memoryview(bytearray(b'B'*32)).toreadonly() as s:
        assert writer._create_and_verify_pair_material(peer.binding,req,p,s) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts==0


def test_mutable_gates_and_native_route_cannot_be_combined_or_inferred(tmp_path: Path) -> None:
    peer=Peer()
    with pytest.raises(RadiusServerPairError):transport(tmp_path,peer,execution_enabled=True,recovery_enabled=True,
        execution_request=replace(primary_request(),action_id=ACTION_ID),expected_current_digest='a'*64,
        create_authorizer=lambda *a:True,recovery_authorizer=lambda *a:True)
    with pytest.raises(RadiusServerPairError):transport(tmp_path,peer)._exchange('POST',
        '/api/v2/monitor/user/radius/test-connect',stop=__import__('time').monotonic()+1,body=bytearray(b'{}'))
    assert peer.posts==peer.deletes==0


@pytest.mark.parametrize('other_gate',['create','recovery'])
def test_native_gate_cannot_share_a_mutable_phase(tmp_path: Path,other_gate: str) -> None:
    peer=Peer()
    extra={'owned_connect_enabled':True,'owned_connect_ordinal':'primary','owned_connect_authorizer':lambda *a:True}
    if other_gate=='create':extra|={'execution_enabled':True,'execution_request':replace(primary_request(),action_id=ACTION_ID),
        'expected_current_digest':'a'*64,'create_authorizer':lambda *a:True}
    else:extra|={'recovery_enabled':True,'recovery_authorizer':lambda *a:True}
    with pytest.raises(RadiusServerPairError):transport(tmp_path,peer,**extra)
    assert not peer.connections
