"""Protected fixed startup metadata; no device, SSH process or material access."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp import radius_server_pair_lifecycle_runtime as runtime
from fortipam_mcp.radius_pair_fixture_material_loader import RadiusPairFixtureMaterialLoader
from fortipam_mcp.radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport
from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
from test_radius_server_pair_contract import binding
from test_radius_server_projection import SERIAL


def setup(root: Path) -> tuple[dict[str,str],dict[str,Any],Path,dict[str,Path]]:
    root.chmod(0o700)
    state = root/'http';state.mkdir(mode=0o700)
    paths = {name:root/(name+'.fixture') for name in runtime._PATH_NAMES}
    paths['state_directory'] = state
    for index,name in enumerate(runtime._KEY_NAMES,1):
        paths[name].write_bytes(bytes([index])*32);paths[name].chmod(0o600)
    for name in ('ssh_identity_file','ssh_known_hosts_file'):
        paths[name].write_text('synthetic-file');paths[name].chmod(0o600)
    b = binding()
    manifest = {'contract':runtime.CONTRACT,'binding':{k:getattr(b,k) for k in runtime._SCHEMA['binding']},
        'source':{'host':'fixture.example','source_policy_digest':'a'*64},
        'identity':{'environment_ref':'synthetic-radius-environment','audience_ref':'synthetic-radius-audience',
            'create_scope_ref':'synthetic-radius-create','native_primary_scope_ref':'synthetic-radius-native',
            'native_secondary_scope_ref':'synthetic-radius-secondary',
            'recovery_scope_ref':'synthetic-radius-recovery','allowed_requester_digest':'1'*64,
            'allowed_transport_digest':'2'*64,'expected_serial':SERIAL},
        'paths':{k:str(v) for k,v in paths.items()}}
    path = root/'startup.json';path.write_text(json.dumps(manifest));path.chmod(0o600)
    env = {runtime.PREFIX+'ENABLED':'true',runtime.PREFIX+'STARTUP_MANIFEST_FILE':str(path),
        ENV_PREFIX+'ENABLED':'true',ENV_PREFIX+'BASE_URL':'https://pam.example',ENV_PREFIX+'API_TOKEN':'synthetic-token'}
    return env,manifest,path,paths


def test_disabled_reads_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime,'_read',lambda *a:pytest.fail('Disabled source read'))
    assert runtime.build_radius_server_pair_lifecycle_candidate({}) is None


@pytest.mark.parametrize('values',[{'ENABLED':'TRUE'},{'ENABLED':True},{'EXECUTION_ENABLED':'true'},
    {'EXECUTION_ENABLED':'yes'}])
def test_invalid_or_partial_flags_fail_before_io(values: dict[str,Any]) -> None:
    with pytest.raises(ValueError):
        runtime.build_radius_server_pair_lifecycle_candidate({runtime.PREFIX+k:v for k,v in values.items()})


def test_startup_and_restart_do_not_connect_or_acquire(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    env,manifest,path,paths = setup(tmp_path)
    monkeypatch.setattr(FortiPamRadiusPairHttpTransport,'_exchange',lambda *a,**k:pytest.fail('Device connected'))
    monkeypatch.setattr(RadiusPairFixtureMaterialLoader,'_exchange',lambda *a,**k:pytest.fail('SSH opened'))
    first = runtime.build_radius_server_pair_lifecycle_candidate(env)
    assert first is not None and not first._enabled and not first._workflow._enabled
    env[runtime.PREFIX+'EXECUTION_ENABLED'] = 'true'
    second = runtime.build_radius_server_pair_lifecycle_candidate(env)
    assert second is not None and second._enabled and second._workflow._enabled
    assert all(paths[role+'_database_file'].exists() for role in runtime._ROLES)
    assert (paths['state_directory']/'runtime.namespace.json').exists()
    # The startup pin is metadata, not a consumed dispatch. The first normal
    # preview must still be able to establish its independent HTTP namespace.
    second._workflow._create._reader._namespace()
    assert (paths['state_directory']/'namespace.json').exists()


@pytest.mark.parametrize('fault',['extra','duplicate','material_value','nested','contract','mode','symlink',
    'key_reuse','key_length','path_collision','sidecar','state_collision','identity','same_scope','source',
    'unsafe_ssh_path','url_userinfo'])
def test_invalid_startup_refuses_before_ledger_creation(tmp_path: Path,fault: str) -> None:
    env,manifest,path,paths = setup(tmp_path);raw = None
    if fault == 'extra':manifest['unknown'] = 'synthetic-private'
    elif fault == 'duplicate':raw = json.dumps(manifest).replace('"source":','"contract":"duplicate","source":')
    elif fault == 'material_value':manifest['source']['secret'] = 'synthetic-private'
    elif fault == 'nested':manifest['source']['host'] = {'private':'value'}
    elif fault == 'contract':manifest['contract'] = 'other'
    elif fault == 'mode':path.chmod(0o644)
    elif fault == 'symlink':
        target = tmp_path/'actual.json';path.rename(target);path.symlink_to(target)
    elif fault == 'key_reuse':paths[runtime._KEY_NAMES[1]].write_bytes(paths[runtime._KEY_NAMES[0]].read_bytes())
    elif fault == 'key_length':paths[runtime._KEY_NAMES[0]].write_bytes(b'x'*31)
    elif fault == 'path_collision':manifest['paths']['ssh_identity_file'] = str(paths['parent_authority_key_file'])
    elif fault == 'sidecar':manifest['paths']['native_primary_database_file'] = str(paths['create_database_file'])+'-wal'
    elif fault == 'state_collision':manifest['paths']['create_database_file'] = str(paths['state_directory']/'ledger.sqlite')
    elif fault == 'identity':manifest['identity']['allowed_requester_digest'] = 'private'
    elif fault == 'same_scope':manifest['identity']['native_primary_scope_ref'] = manifest['identity']['create_scope_ref']
    elif fault == 'source':manifest['source']['source_policy_digest'] = 'invalid'
    elif fault == 'unsafe_ssh_path':manifest['paths']['ssh_identity_file'] = '/private/tmp/unsafe path'
    elif fault == 'url_userinfo':env[ENV_PREFIX+'BASE_URL'] = 'https://user:pass@pam.example'
    if fault != 'symlink':path.write_text(raw or json.dumps(manifest))
    with pytest.raises(ValueError) as caught:runtime.build_radius_server_pair_lifecycle_candidate(env)
    assert str(caught.value) == 'FortiPAM paired RADIUS lifecycle startup is unavailable.'
    assert not any(paths[role+'_database_file'].exists() for role in runtime._ROLES)


@pytest.mark.parametrize('fault',['source','operator','api_identity','authority_key','source_file'])
def test_runtime_namespace_cannot_change_identity_or_source_after_startup(tmp_path: Path,fault: str) -> None:
    env,manifest,path,paths = setup(tmp_path)
    assert runtime.build_radius_server_pair_lifecycle_candidate(env) is not None
    if fault == 'source':manifest['source']['source_policy_digest'] = 'b'*64
    elif fault == 'operator':manifest['identity']['allowed_requester_digest'] = '3'*64
    elif fault == 'api_identity':env[ENV_PREFIX+'API_TOKEN'] = 'other-synthetic-token'
    elif fault == 'authority_key':paths['native_primary_authority_key_file'].write_bytes(b'z'*32)
    elif fault == 'source_file':paths['ssh_identity_file'].write_text('changed-synthetic-source-key')
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):runtime.build_radius_server_pair_lifecycle_candidate(env)


def test_existing_runtime_pin_cannot_recreate_a_missing_consumed_store(tmp_path: Path) -> None:
    env,_,_,paths=setup(tmp_path)
    first=runtime.build_radius_server_pair_lifecycle_candidate(env)
    assert first is not None
    first.close()
    selected=paths['source_group_database_file'];selected.unlink()
    with pytest.raises(ValueError):runtime.build_radius_server_pair_lifecycle_candidate(env)
    assert not selected.exists()


def test_partial_startup_closes_constructed_create_and_source(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    env,_,_,_=setup(tmp_path)
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    children=[];original=runtime.RadiusServerPairLiveWorkflow
    def create(*a: Any,**k: Any) -> Any:
        value=original(*a,**k);children.append(value);return value
    def fail(*a: Any,**k: Any) -> Any:raise ValueError('Synthetic private data.')
    monkeypatch.setattr(runtime,'RadiusServerPairLiveWorkflow',create)
    monkeypatch.setattr(runtime,'RadiusServerPairOwnedConnectWorkflow',fail)
    with pytest.raises(ValueError):runtime.build_radius_server_pair_lifecycle_candidate(env)
    assert len(children)==1 and not children[0]._enabled and not children[0]._source._enabled


@pytest.mark.parametrize('value',['true','false'])
def test_pair_completion_mode_is_explicit_default_closed_and_never_acquires(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,value: str) -> None:
    env,_,_,_=setup(tmp_path);env[runtime.PREFIX+'RETAIN_ON_SUCCESS']=value
    monkeypatch.setattr(FortiPamRadiusPairHttpTransport,'_exchange',lambda *a,**k:pytest.fail('Device connected'))
    monkeypatch.setattr(RadiusPairFixtureMaterialLoader,'_exchange',lambda *a,**k:pytest.fail('SSH opened'))
    action=runtime.build_radius_server_pair_lifecycle_candidate(env)
    assert action is not None and action._persistent is (value=='true')
    assert action._workflow._retain_on_success is (value=='true')
    assert not action._enabled
    action.close();assert action._workflow._closed()


@pytest.mark.parametrize('values',[{'RETAIN_ON_SUCCESS':'true'},{'ENABLED':'true','RETAIN_ON_SUCCESS':'yes'}])
def test_pair_completion_flags_cannot_activate_a_disabled_or_invalid_profile(values: dict[str,str]) -> None:
    with pytest.raises(ValueError):runtime.build_radius_server_pair_lifecycle_candidate({runtime.PREFIX+k:v for k,v in values.items()})
