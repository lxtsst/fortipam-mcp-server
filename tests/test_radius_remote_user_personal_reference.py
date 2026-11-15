"""Original local M4/ACK custody plus synthetic fixed native metadata only."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_remote_user_personal_reference import (
    RadiusPersonalReferenceError, RadiusPersonalReferenceFrames,
    RadiusRemoteUserPersonalReferenceInspector,
)
from fortipam_mcp.folder_namespace_ssh_reader import _NAME_PROJECTION as FOLDER_NAMES
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
from test_radius_remote_user_live_workflow import setup, IDENTITY
from test_single_secret_folder_membership_source import columns, frame, ROOT, FOLDER, SERIAL

FOLDER_ID = 42


class Provider:
    def __init__(self, peer: Any, now: list[int]) -> None:
        self.peer, self.now = peer, now
        self.calls = 0
        self.last: RadiusPersonalReferenceFrames | None = None
        self.fault: str | None = None

    def read_reference(self) -> RadiusPersonalReferenceFrames:
        self.calls += 1
        username = self.peer.username
        command = f'show full-configuration secret folder "{FOLDER_ID}"'
        lines = [b'config secret folder', b'    edit 42',
            f'        set name "{username}"'.encode(), b'        set parent-folder 0',
            b'        set folder-type personal', b'        set inherit-policy disable',
            b'        set secret-policy ""', b'        set inherit-permission disable',
            b'        set inherit-folder-ztna disable', b'        set ztna-tags-match-logic or',
            b'        config user-permission', b'            edit 1',
            f'                set user-name "{username}"'.encode(),
            b'                set folder-permission owner', b'                set secret-permission owner',
            b'            next', b'        end', b'    next', b'end']
        detail = bytearray(frame(command, lines))
        usage = dict(version='v7.0.0', build=29, serial=self.peer.serial, status='success',
            http_method='GET', http_status=200, path='system', name='object', action='usage', vdom='root',
            mkey=username, results={'currently_using': [{'path':'secret','name':'folder','mkey':FOLDER_ID,'static':False}]})
        current = columns(parents=(0,7), folders=(7,7))
        current = replace(current,
            folder_names=frame(FOLDER_NAMES, [f'    set name "{username}"'.encode(),b'    set name "Synthetic Folder Witness"'],FOLDER),
            serial_output=current.serial_output.replace(SERIAL.encode(),self.peer.serial.encode()))
        captured = self.now[0]
        first = bytearray(json.dumps(usage).encode())
        snapshot = RadiusPersonalReferenceFrames(FOLDER_ID,captured,first,bytearray(first),detail,bytearray(detail),current,current)
        fault = self.fault
        if fault=='public': snapshot.detail_after[:] = snapshot.detail_after.replace(b'personal',b'public')
        elif fault=='owner': snapshot.detail_after[:] = snapshot.detail_after.replace(b'set secret-permission owner',b'set secret-permission view')
        elif fault=='foreign_owner': snapshot.detail_after[:] = snapshot.detail_after.replace(b'set user-name "'+username.encode()+b'"',b'set user-name "Foreign"')
        elif fault=='unknown': snapshot.detail_after[:] = snapshot.detail_after.replace(b'    next\r\nend',b'        set unknown disable\r\n    next\r\nend')
        elif fault=='column_drift': snapshot=replace(snapshot,columns_after=replace(current,folder_parents=current.folder_parents.replace(b'set parent-folder 7',b'set parent-folder 8')))
        elif fault=='child':
            bad=replace(current,folder_parents=current.folder_parents.replace(b'set parent-folder 7',b'set parent-folder 42'))
            snapshot=replace(snapshot,columns_before=bad,columns_after=bad)
        elif fault=='secret':
            bad=replace(current,secret_folders=current.secret_folders.replace(b'set folder 7',b'set folder 42',1))
            snapshot=replace(snapshot,columns_before=bad,columns_after=bad)
        elif fault=='serial':
            bad=replace(current,serial_output=current.serial_output.replace(self.peer.serial.encode(),b'FOREIGN'))
            snapshot=replace(snapshot,columns_before=bad,columns_after=bad)
        elif fault=='truncated': snapshot.detail_after.pop()
        elif fault=='usage': snapshot.usage_after[:] = snapshot.usage_after.replace(b'"mkey": 42',b'"mkey": 43')
        elif fault=='usage_drift': snapshot.usage_after[:] = snapshot.usage_after.replace(b'"static": false',b'"static": false, "changed": true')
        elif fault=='static': snapshot.usage_after[:] = snapshot.usage_after.replace(b'"static": false',b'"static": true')
        elif fault=='stale': snapshot=replace(snapshot,captured_at=captured-1)
        elif fault=='future': snapshot=replace(snapshot,captured_at=captured+1)
        elif fault=='expired': self.now[0]+=30
        elif fault=='user_drift': self.peer.row['comments']='Changed during reference capture'
        elif fault=='defaults_drift': self.peer.defaults['comments']='Changed source default'
        elif fault=='shape': snapshot=replace(snapshot,folder_id=True)
        elif fault=='static_omitted':
            for buf in (snapshot.usage_before,snapshot.usage_after):
                buf[:]=buf.replace(b', "static": false',b'')
        self.last=snapshot
        return snapshot


def prepared(tmp_path: Path, *, lost_ack: bool = False) -> tuple[Any, ...]:
    creator, remove, peer, now, material, _ = setup(tmp_path)
    envelope=peer.envelope
    peer.envelope=lambda **kwargs: envelope(**(kwargs|{'vdom':'root'}))
    handle=peer.handle
    def native_personal_reference(method: str,path: str,body: Any) -> Any:
        result=handle(method,path,body)
        if method=='POST': peer.row['q_ref']=1
        return result
    peer.handle=native_personal_reference
    peer.lost_post_ack=lost_ack
    preview=creator.preview(**IDENTITY);auth=creator.authorize(preview['preview_ref'],**IDENTITY)
    result=creator.execute(auth['authorization_ref'],**IDENTITY)
    assert result['outcome']=='reconciliation_required' and result['verification']=='unknown'
    creator.close()
    recovery=remove(execution_enabled=False)
    return recovery,peer,now,material


def evidence(workflow: Any) -> dict[str,str]:
    root=workflow._reader._directory
    return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}


def cleared(provider: Provider) -> None:
    assert provider.last is not None
    assert all(not value for value in (provider.last.usage_before,provider.last.usage_after,
        provider.last.detail_before,provider.last.detail_after))


def test_original_unknown_ack_and_complete_user_join_without_record_repair(tmp_path: Path) -> None:
    workflow,peer,now,material=prepared(tmp_path)
    provider=Provider(peer,now);before=evidence(workflow);calls=len(material.calls)
    original_claims=workflow._original_store.claim_count
    result=RadiusRemoteUserPersonalReferenceInspector(workflow,provider).inspect()
    assert result.as_dict()['original_ack_and_terminal_m4_verified'] is True
    assert result.as_dict()['child_folder_count']==result.as_dict()['secret_membership_count']==0
    assert result.as_dict()['recovery_authority'] is False
    assert result.as_dict()['request_job_session_cascade_qualified'] is False
    assert result.as_dict()['global_folder_count']==result.as_dict()['global_secret_metadata_count']==2
    assert len(result.evidence_digest)==64 and before==evidence(workflow)
    assert workflow._store.claim_count==0 and workflow._original_store.claim_count==original_claims
    assert peer.posts==1 and peer.deletes==0 and len(material.calls)==calls
    assert not (workflow._reader._directory/'created.json').exists()
    output=json.dumps(result.as_dict())+repr(result)
    for private in (peer.username,peer.serial,str(tmp_path),result.evidence_digest): assert private not in output
    cleared(provider)


@pytest.mark.parametrize('fault',['public','owner','foreign_owner','unknown','column_drift','child','secret','serial',
    'truncated','usage','usage_drift','static','stale','future','expired','user_drift','defaults_drift','shape'])
def test_bad_scope_drift_or_freshness_fails_without_claim_or_record_repair(tmp_path: Path,fault: str) -> None:
    workflow,peer,now,_=prepared(tmp_path);provider=Provider(peer,now);provider.fault=fault
    before=evidence(workflow)
    with pytest.raises(RadiusPersonalReferenceError,match='unavailable'):
        RadiusRemoteUserPersonalReferenceInspector(workflow,provider).inspect()
    assert before==evidence(workflow) and peer.deletes==0 and workflow._store.claim_count==0
    cleared(provider)


def test_missing_original_ack_refuses_before_reference_source(tmp_path: Path) -> None:
    workflow,peer,now,_=prepared(tmp_path,lost_ack=True);provider=Provider(peer,now)
    before=evidence(workflow)
    with pytest.raises(RadiusPersonalReferenceError): RadiusRemoteUserPersonalReferenceInspector(workflow,provider).inspect()
    assert provider.calls==0 and peer.deletes==0 and before==evidence(workflow)


def test_no_default_source_and_legacy_zero_reference_recovery_remains_closed(tmp_path: Path) -> None:
    workflow,peer,_,_=prepared(tmp_path);before=evidence(workflow)
    with pytest.raises(RadiusPersonalReferenceError): RadiusRemoteUserPersonalReferenceInspector(workflow).inspect()
    with pytest.raises(Exception): workflow._reader.inspect_recovery()
    assert peer.row['q_ref']==1 and peer.deletes==0 and before==evidence(workflow)


def test_existing_namespace_recomposes_with_all_m4_stores_readonly(tmp_path: Path) -> None:
    workflow,peer,now,_=prepared(tmp_path)
    original=workflow._original_store
    removal=workflow._store
    assert original is not None
    before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in tmp_path.rglob('*') if p.is_file()}
    reader=RadiusRemoteUserLiveWorkflow(workflow._binding,workflow._reader._config,target=workflow._target,
        state_directory=workflow._reader._directory,operation='remove',execution_enabled=False,existing_only=True,
        execution_store=PersistentM4ExecutionStateStore(removal._path,removal._key_path,read_only=True),
        original_create_store=PersistentM4ExecutionStateStore(original._path,original._key_path,read_only=True),
        authority_key=workflow._key,original_create_authority_key=workflow._original_key,
        environment_ref=workflow._namespace['environment_ref'],scope_ref=workflow._namespace['scope_ref'],
        audience_ref=workflow._namespace['audience_ref'],allowed_requester_digest=workflow._namespace['requester_digest'],
        allowed_transport_digest=workflow._namespace['transport_digest'],clock=workflow._clock,connection_factory=peer.connection)
    RadiusRemoteUserPersonalReferenceInspector(reader,Provider(peer,now)).inspect()
    assert before=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in tmp_path.rglob('*') if p.is_file()}
    assert reader._store.claim_count==0 and peer.deletes==0
    reader.close()


def test_native_three_part_monitor_route_and_omitted_static_are_not_cmdb_defaults(tmp_path: Path) -> None:
    workflow,peer,now,_=prepared(tmp_path);provider=Provider(peer,now);provider.fault='static_omitted'
    result=RadiusRemoteUserPersonalReferenceInspector(workflow,provider).inspect()
    assert result.as_dict()['personal_folder_observed'] is True
    assert result.as_dict()['recovery_authority'] is False
    cleared(provider)


def test_consumed_removal_marker_denies_before_any_reference_read(tmp_path: Path) -> None:
    workflow,peer,now,_=prepared(tmp_path);provider=Provider(peer,now)
    (workflow._reader._directory/'delete.claim.json').write_text('{}')
    before=evidence(workflow)
    with pytest.raises(RadiusPersonalReferenceError) as caught:
        RadiusRemoteUserPersonalReferenceInspector(workflow,provider).inspect()
    assert caught.value.stage=='original_context'
    assert provider.calls==0 and before==evidence(workflow) and peer.deletes==0


def test_concurrent_real_m4_removal_claim_invalidates_observation(tmp_path: Path) -> None:
    workflow,peer,now,_=prepared(tmp_path);provider=Provider(peer,now)
    read=provider.read_reference
    def competing_claim() -> RadiusPersonalReferenceFrames:
        snapshot=read()
        workflow._store.claim(plan_ref='synthetic-concurrent-removal',requester_digest=IDENTITY['requester_digest'],
            idempotency_digest='a'*64,context_digest='b'*64,authorization_digest='c'*64)
        return snapshot
    provider.read_reference=competing_claim  # type: ignore[method-assign]
    before=evidence(workflow)
    with pytest.raises(RadiusPersonalReferenceError) as caught:
        RadiusRemoteUserPersonalReferenceInspector(workflow,provider).inspect()
    assert caught.value.stage=='original_preservation'
    assert workflow._store.claim_count==1 and peer.deletes==0 and before==evidence(workflow)
    cleared(provider)


def test_reference_delta_diagnosis_preserves_actual_state_and_zero_reference_denial() -> None:
    from fortipam_mcp.radius_remote_user_personal_reference import _pair_reference_delta_matches_original
    from fortipam_mcp.radius_server_pair_contract import (
        RadiusServerPairError, qualify_radius_pair_created_state,
    )
    from fortipam_mcp.radius_server_projection import (
        RadiusServerSchema, RadiusServerState, project_radius_defaults, project_radius_detail,
    )
    from test_radius_server_pair_contract import binding
    from test_radius_server_projection import default_row, encoded, envelope, schema
    from test_radius_server_projection import SERIAL as PAIR_SERIAL

    shape=schema();intent=binding()
    defaults=project_radius_defaults(encoded(envelope(action='default',results=default_row())),shape,expected_serial=PAIR_SERIAL)
    row=default_row()|intent.desired_nonmaterial()|{'secret':'SYNTHETIC_PRIMARY_OPAQUE',
        'secondary-secret':'SYNTHETIC_SECONDARY_OPAQUE','q_ref':0}
    original=project_radius_detail(encoded(envelope(results=[row])),shape,expected_serial=PAIR_SERIAL)
    qualify_radius_pair_created_state(original,defaults,shape,intent,expected_serial=PAIR_SERIAL)
    actual=project_radius_detail(encoded(envelope(results=[row|{'q_ref':1}])),shape,expected_serial=PAIR_SERIAL)
    actual_digest=actual.state_digest
    assert _pair_reference_delta_matches_original(actual,original.state_digest)
    for changed in (
        RadiusServerState(dict(actual.values)|{'timeout':99},actual.opaque_token_digests,actual.metadata,shape),
        RadiusServerState(actual.values,dict(actual.opaque_token_digests)|{'secret':'a'*64},actual.metadata,shape),
        RadiusServerState(actual.values,actual.opaque_token_digests,dict(actual.metadata)|{'q_static':True},shape),
        RadiusServerState(actual.values,actual.opaque_token_digests,actual.metadata,RadiusServerSchema('f'*64)),
        RadiusServerState(actual.values,actual.opaque_token_digests,dict(actual.metadata)|{'q_ref':2},shape),
        original,
    ):
        assert not _pair_reference_delta_matches_original(changed,original.state_digest)
    for digest in ('a'*64,'','SYNTHETIC_PRIVATE_DIGEST'):
        assert not _pair_reference_delta_matches_original(actual,digest)
    assert actual.metadata['q_ref']==1 and actual.state_digest==actual_digest
    with pytest.raises(RadiusServerPairError):
        qualify_radius_pair_created_state(actual,defaults,shape,intent,expected_serial=PAIR_SERIAL)
