"""Associated startup pins all eight stores/sixteen keys before any device I/O."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import pytest
from fortipam_mcp import radius_remote_user_lifecycle_runtime as runtime
from fortipam_mcp import radius_server_pair_lifecycle_runtime as pair_runtime
from fortipam_mcp.radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport
from fortipam_mcp.radius_pair_fixture_material_loader import RadiusPairFixtureMaterialLoader
from test_radius_server_pair_lifecycle_runtime import setup as pair_setup


def setup(root: Path) -> tuple[Any, ...]:
    pair = root / 'pair'; pair.mkdir(mode=0o700)
    env, pair_manifest, pair_path, pair_paths = pair_setup(pair)
    env = {k:v for k,v in env.items() if not k.startswith(pair_runtime.PREFIX)}
    directory = root / 'user'; directory.mkdir(mode=0o700)
    paths = {name: root / (name + '.fixture') for name in runtime._SCHEMA['paths']}
    paths['user_state_directory'] = directory
    for index, name in enumerate(runtime._KEYS, 40):
        paths[name].write_bytes(bytes([index]) * 32); paths[name].chmod(0o600)
    manifest = {'contract': runtime.CONTRACT, 'pair_manifest_file':str(pair_path),
        'binding':{'username':'mcp-v4-radius-user-01234567','private_nonce':'c'*64},
        'identity':{'user_create_scope_ref':'synthetic-user-create','user_remove_scope_ref':'synthetic-user-remove'},
        'paths':{k:str(v) for k,v in paths.items()}}
    path = root / 'startup.json'; path.write_text(json.dumps(manifest)); path.chmod(0o600)
    env.update({runtime.PREFIX+'ENABLED':'true',runtime.PREFIX+'STARTUP_MANIFEST_FILE':str(path)})
    return env, manifest, path, paths, pair_manifest, pair_paths


def test_disabled_has_no_file_or_source_access(monkeypatch: Any) -> None:
    monkeypatch.setattr(runtime, '_read', lambda *a: pytest.fail('Disabled profile read a file'))
    assert runtime.build_radius_remote_user_lifecycle_candidate({}) is None


@pytest.mark.parametrize('value', [{'ENABLED':True},{'ENABLED':'TRUE'},{'EXECUTION_ENABLED':'true'}, {'ENABLED':'true','EXECUTION_ENABLED':'yes'}])
def test_bad_flags_fail_before_io(value: Any) -> None:
    with pytest.raises(ValueError): runtime.build_radius_remote_user_lifecycle_candidate({runtime.PREFIX+k:v for k,v in value.items()})


def test_startup_recomposition_and_legacy_profile_exclusion(tmp_path: Path, monkeypatch: Any) -> None:
    env, manifest, path, paths, _, pair_paths = setup(tmp_path)
    monkeypatch.setattr(FortiPamRadiusPairHttpTransport, '_exchange', lambda *a,**k: pytest.fail('Device HTTP at startup'))
    monkeypatch.setattr(RadiusPairFixtureMaterialLoader, '_exchange', lambda *a,**k: pytest.fail('SSH at startup'))
    first = runtime.build_radius_remote_user_lifecycle_candidate(env)
    assert first is not None and not first._enabled
    first.close()
    env[runtime.PREFIX+'EXECUTION_ENABLED'] = 'true'
    second = runtime.build_radius_remote_user_lifecycle_candidate(env)
    assert second is not None and second._enabled
    assert len(second._workflow._user_stores) == 2
    assert all(paths[role+'_database_file'].is_file() for role in runtime._ROLES)
    legacy = {k:v for k,v in env.items() if not k.startswith(runtime.PREFIX)}
    legacy.update({pair_runtime.PREFIX+'ENABLED':'true',pair_runtime.PREFIX+'STARTUP_MANIFEST_FILE':manifest['pair_manifest_file']})
    with pytest.raises(ValueError): pair_runtime.build_radius_server_pair_lifecycle_candidate(legacy)
    second.close()
    paths['user_create_database_file'].unlink()
    with pytest.raises(ValueError): runtime.build_radius_remote_user_lifecycle_candidate(env)
    assert not paths['user_create_database_file'].exists()


@pytest.mark.parametrize('fault', ['extra','duplicate','material','contract','name','scope','key_reuse','path_collision',
    'sidecar','state_nested','legacy_enabled','unknown_mode','key_change','partial_pin'])
def test_invalid_graph_refuses_before_new_ledgers(tmp_path: Path, fault: str) -> None:
    env, manifest, path, paths, pair_manifest, pair_paths = setup(tmp_path)
    raw = None
    if fault == 'extra': manifest['unexpected'] = 'synthetic'
    elif fault == 'duplicate': raw = json.dumps(manifest).replace('"contract":','"contract":"duplicate","contract":')
    elif fault == 'material': manifest['binding']['password'] = 'NEVER_ACCEPT_MATERIAL'
    elif fault == 'contract': manifest['contract'] = 'foreign'
    elif fault == 'name': manifest['binding']['username'] = 'admin'
    elif fault == 'scope': manifest['identity']['user_create_scope_ref'] = pair_manifest['identity']['create_scope_ref']
    elif fault == 'key_reuse': paths['user_create_authority_key_file'].write_bytes(pair_paths['parent_authority_key_file'].read_bytes())
    elif fault == 'path_collision': manifest['paths']['user_create_database_file'] = str(pair_paths['ssh_identity_file'])
    elif fault == 'sidecar': manifest['paths']['user_create_database_file'] = str(pair_paths['create_database_file']) + '-wal'
    elif fault == 'state_nested': manifest['paths']['user_state_directory'] = str(pair_paths['state_directory'])
    elif fault == 'legacy_enabled': env[pair_runtime.PREFIX+'ENABLED'] = 'true'
    elif fault == 'unknown_mode': env[runtime.PREFIX+'RECOVERY_ONLY'] = 'true'
    else:
        action = runtime.build_radius_remote_user_lifecycle_candidate(env); action.close()
        if fault == 'key_change': paths['user_create_authority_key_file'].write_bytes(b'x'*32)
        else: paths['user_remove_database_file'].unlink()
    path.write_text(raw if raw is not None else json.dumps(manifest))
    before = {role:paths[role+'_database_file'].exists() for role in runtime._ROLES}
    with pytest.raises(ValueError): runtime.build_radius_remote_user_lifecycle_candidate(env)
    assert before == {role:paths[role+'_database_file'].exists() for role in runtime._ROLES}
    if fault not in {'key_change','partial_pin'}:
        assert not any(pair_paths[role+'_database_file'].exists() for role in pair_runtime._ROLES)
