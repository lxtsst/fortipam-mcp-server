"""Synthetic owner-only pair trees; no Docker, SSH, device or real material."""
from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from fortipam_mcp import radius_pair_fixture_material_worker as worker
from fortipam_mcp import radius_fixture_material_worker as primary_worker
from fortipam_mcp.radius_server_pair_contract import ACTION_ID
from test_radius_server_pair_contract import binding
from test_radius_server_material_runtime import request as primary_request


def write(path: Path,value: Any) -> None:
    path.write_bytes(value if isinstance(value,bytes) else json.dumps(value,sort_keys=True,separators=(',',':')).encode())
    path.chmod(0o600)


def fixture(root: Path) -> tuple[Any,...]:
    root.mkdir(mode=0o700)
    request=replace(primary_request(),action_id=ACTION_ID)
    pair=binding();fixtures={};inspections={}
    for index,ordinal in enumerate(('primary','secondary')):
        leaf=root/ordinal;leaf.mkdir(mode=0o700)
        for name in ('config','material'):(leaf/name).mkdir(mode=0o700)
        address=pair.server if index==0 else pair.secondary_server
        bound={'created_at':1,'expires_at':200,'device_ip':'192.0.2.10','server_ip':address,
            'fixture_nonce':('b' if index==0 else 'c')*64,'image_id':'sha256:'+'f'*64,'name':'synthetic-'+ordinal}
        ack={'acknowledged_at':2,'container_id':('d' if index==0 else 'e')*64,'nonce':bound['fixture_nonce']}
        main=b'synthetic-pinned-radius-config-'+ordinal.encode();material=(b'A' if index==0 else b'B')*32
        write(leaf/'binding.private.json',bound);write(leaf/'start.ack.json',ack)
        write(leaf/'config/radiusd.conf',main);write(leaf/'material/primary-secret',material)
        clients=bytearray()
        for i,client in enumerate((bound['device_ip'],address)):
            clients.extend(('client fixture_'+str(i)+' {\n ipaddr = '+client+'/32\n proto = udp\n require_message_authenticator = yes\n limit_proxy_state = yes\n secret = "').encode())
            clients.extend(material);clients.extend(b'"\n}\n')
        write(leaf/'config/clients.conf',bytes(clients))
        fixtures[ordinal]={'binding':bound,'ack':ack,'config_digest':hashlib.sha256(main).hexdigest()}
        inspections[ack['container_id']]={'Id':ack['container_id'],'State':{'Running':True},'Image':bound['image_id'],
            'Config':{'Labels':{'fortipam.radius.fixture':bound['fixture_nonce']},'User':'10001:10001'},
            'HostConfig':{'ReadonlyRootfs':True,'LogConfig':{'Type':'none'}},
            'Mounts':[{'Source':str(leaf/'config'),'Destination':'/radius-config','Type':'bind','RW':False}]}
    policy={'contract':worker.CONTRACT,'parameters_digest':pair.parameters_digest,'binding':{
        'name':pair.name,'server':pair.server,'secondary_server':pair.secondary_server,'private_nonce':pair.private_nonce},
        'scope_digest':request.scope_digest,'audience_digest':request.audience_digest,'fixtures':fixtures,'expires_at':200}
    write(root/'pair-material-policy.json',policy)
    incoming={'contract':worker.CONTRACT,'operation':'validate','ordinal':'both','parameters_digest':pair.parameters_digest,
        'source_policy_digest':worker._digest(policy),'request':asdict(request)}
    return incoming,inspections,policy


def handle(root: Path,incoming: Any,inspections: Any,clock: Any=lambda:100) -> bytearray:
    return worker._handle(root,incoming,clock=clock,inspector=lambda value:inspections[value],
        owner_uid=os.getuid(),config_uid=os.getuid())


def acquire(root: Path,incoming: Any,inspections: Any,ordinal: str) -> bytearray:
    return handle(root,incoming|{'operation':'acquire','ordinal':ordinal},inspections)


def test_validate_is_metadata_only_and_both_sources_are_single_use(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    root=tmp_path/'pair';incoming,inspections,policy=fixture(root)
    reads=[];original=worker._read
    def observe(directory: int,name: str,*args: Any) -> bytearray:
        reads.append(name)
        if name in {'primary-secret','clients.conf'}:
            assert (root/'create-material.claim.json').exists()
            leaf='secondary' if (root/'secondary/create-material.claim.json').exists() else 'primary'
            assert (root/leaf/'create-material.claim.json').exists()
        return original(directory,name,*args)
    monkeypatch.setattr(worker,'_read',observe)
    assert handle(root,incoming,inspections)==b'available\n'
    assert 'primary-secret' not in reads and 'clients.conf' not in reads
    assert not (root/'create-material.claim.json').exists()
    for ordinal,value in (('primary',b'A'*32),('secondary',b'B'*32)):
        material=acquire(root,incoming,inspections,ordinal);assert material==value;worker._wipe(material)
        assert (root/ordinal/'material-ready.ack.json').exists()
    count=reads.count('primary-secret')
    for ordinal in ('primary','secondary'):
        with pytest.raises((ValueError,OSError)):acquire(root,incoming,inspections,ordinal)
    with pytest.raises((ValueError,OSError)):handle(root,incoming,inspections)
    assert reads.count('primary-secret')==count==2


def test_secondary_cannot_precede_primary_or_change_the_original_request(tmp_path: Path) -> None:
    root=tmp_path/'pair';incoming,inspections,_=fixture(root)
    with pytest.raises((ValueError,OSError)):acquire(root,incoming,inspections,'secondary')
    assert not (root/'secondary/create-material.claim.json').exists()
    worker._wipe(acquire(root,incoming,inspections,'primary'))
    for field in ('authorization_digest','plan_digest'):
        changed=incoming|{'request':incoming['request']|{field:'f'*64}}
        with pytest.raises(ValueError):acquire(root,changed,inspections,'secondary')
    assert not (root/'secondary/create-material.claim.json').exists()
    with pytest.raises(ValueError):
        handle(root,incoming|{'operation':'acquire','ordinal':'secondary'},inspections,clock=lambda:99)


@pytest.mark.parametrize('fault',['wrong_action','wrong_version','wrong_scope','wrong_policy','extra_path',
    'ordinal','ordinal_path','primary_alias','secondary_alias','same_container','same_nonce','config',
    'stopped','rw_mount','material_mode','policy_mode','symlink','expired'])
def test_invalid_context_or_either_fixture_refuses_before_material(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,fault: str) -> None:
    root=tmp_path/'pair';incoming,inspections,policy=fixture(root);clock=lambda:100
    if fault=='wrong_action':incoming['request']['action_id']='radius-server-create'
    elif fault=='wrong_version':incoming['request']['action_version']='1.0.1'
    elif fault=='wrong_scope':incoming['request']['scope_digest']='f'*64
    elif fault=='wrong_policy':incoming['source_policy_digest']='f'*64
    elif fault=='extra_path':incoming['path']='SYNTHETIC_PRIVATE'
    elif fault=='ordinal':incoming['ordinal']='secondary'
    elif fault=='ordinal_path':incoming['ordinal']='../secondary'
    elif fault in {'primary_alias','secondary_alias'}:
        key='server' if fault=='primary_alias' else 'secondary_server'
        policy['binding'][key]='127.0.0.1'
    elif fault=='same_container':policy['fixtures']['secondary']['ack']['container_id']=policy['fixtures']['primary']['ack']['container_id']
    elif fault=='same_nonce':policy['fixtures']['secondary']['binding']['fixture_nonce']=policy['fixtures']['primary']['binding']['fixture_nonce']
    elif fault=='config':write(root/'secondary/config/radiusd.conf',b'synthetic-changed-config')
    elif fault=='stopped':inspections['e'*64]['State']['Running']=False
    elif fault=='rw_mount':inspections['e'*64]['Mounts'][0]['RW']=True
    elif fault=='material_mode':(root/'secondary/material/primary-secret').chmod(0o644)
    elif fault=='policy_mode':(root/'pair-material-policy.json').chmod(0o644)
    elif fault=='symlink':
        target=root/'secondary/material/primary-secret';target.rename(target.with_suffix('.retained'));target.symlink_to(target.with_suffix('.retained'))
    elif fault=='expired':clock=lambda:160
    if fault in {'primary_alias','secondary_alias','same_container','same_nonce'}:
        write(root/'pair-material-policy.json',policy);incoming['source_policy_digest']=worker._digest(policy)
    original=worker._read
    def forbid(directory: int,name: str,*args: Any) -> bytearray:
        assert name not in {'primary-secret','clients.conf'}
        return original(directory,name,*args)
    monkeypatch.setattr(worker,'_read',forbid)
    with pytest.raises((ValueError,OSError)):handle(root,incoming,inspections,clock)
    assert not (root/'create-material.claim.json').exists()


def test_post_read_drift_clears_material_and_leaves_claims_without_ready_ack(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    root=tmp_path/'pair';incoming,inspections,_=fixture(root)
    original=worker._read;buffers=[]
    def drift(directory: int,name: str,*args: Any) -> bytearray:
        result=original(directory,name,*args)
        if name=='primary-secret':
            buffers.append(result);inspections['e'*64]['State']['Running']=False
        return result
    monkeypatch.setattr(worker,'_read',drift)
    with pytest.raises(ValueError):acquire(root,incoming,inspections,'primary')
    assert buffers and all(not any(b) for b in buffers)
    assert (root/'create-material.claim.json').exists() and (root/'primary/create-material.claim.json').exists()
    assert not (root/'primary/material-ready.ack.json').exists()
    inspections['e'*64]['State']['Running']=True
    for ordinal in ('primary','secondary'):
        with pytest.raises((ValueError,OSError)):acquire(root,incoming,inspections,ordinal)
    assert len(buffers)==1


def test_uncertain_group_claim_never_reads_material_and_blocks_fresh_authorization(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    root=tmp_path/'pair';incoming,inspections,_=fixture(root)
    original=worker._claim
    def lost(directory: int,value: Any) -> None:
        original(directory,value);raise OSError('SYNTHETIC_PRIVATE')
    monkeypatch.setattr(worker,'_claim',lost)
    with pytest.raises(OSError):acquire(root,incoming,inspections,'primary')
    assert (root/'create-material.claim.json').exists()
    assert not (root/'primary/material-ready.ack.json').exists()
    changed=incoming|{'request':incoming['request']|{'authorization_digest':'f'*64}}
    with pytest.raises(ValueError):acquire(root,changed,inspections,'primary')


def test_partial_group_claim_is_not_repairable(tmp_path: Path) -> None:
    root=tmp_path/'pair';incoming,inspections,_=fixture(root)
    write(root/'create-material.claim.json',b'{')
    for ordinal in ('primary','secondary'):
        with pytest.raises((ValueError,OSError)):acquire(root,incoming,inspections,ordinal)
    assert (root/'create-material.claim.json').read_bytes()==b'{'


def test_invalid_primary_ready_marker_cannot_release_secondary(tmp_path: Path) -> None:
    root=tmp_path/'pair';incoming,inspections,_=fixture(root)
    worker._wipe(acquire(root,incoming,inspections,'primary'))
    write(root/'primary/material-ready.ack.json',{'contract':worker.CONTRACT,'claim_digest':'f'*64})
    with pytest.raises(ValueError):acquire(root,incoming,inspections,'secondary')
    assert not (root/'secondary/create-material.claim.json').exists()
    with pytest.raises(ValueError):acquire(root,incoming,inspections,'primary')


def test_only_one_racing_primary_request_can_receive_material(tmp_path: Path) -> None:
    root=tmp_path/'pair';incoming,inspections,_=fixture(root)
    def call() -> bool:
        try:material=acquire(root,incoming,inspections,'primary');worker._wipe(material);return True
        except (ValueError,OSError):return False
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:call(),range(2)))
    assert sum(results)==1


def test_standalone_helpers_match_frozen_primary_implementations_and_entry_has_no_import_dependency() -> None:
    old=ast.parse(Path(primary_worker.__file__).read_text());new=ast.parse(Path(worker.__file__).read_text())
    for name in ('_wipe','_pairs','_json','_directory','_read','_metadata','_exists','_claim','_clock','_inspect'):
        assert ast.dump(next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name==name))==ast.dump(
            next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name==name))
    assert all(n.module in {'__future__','pathlib','typing'} for n in new.body if isinstance(n,ast.ImportFrom))
    result=subprocess.run([sys.executable,'-I',worker.__file__,'--forbidden'],input=b'{}',capture_output=True,timeout=5)
    assert result.returncode==1 and result.stdout==result.stderr==b''
