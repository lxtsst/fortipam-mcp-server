"""Protected normal-main runtime rebuilds only immutable original ownership."""
import json
from pathlib import Path

import pytest

import fortipam_mcp.local_user_reset_owned_runtime as module
from fortipam_mcp.local_user_reset_owned_runtime import PREFIX,CONTRACT,LOGIN_CONTRACT,build_local_reset_owned_candidate
from fortipam_mcp.local_user_reset_owned_mcp import LocalResetOwnedMcpError
from test_local_user_reset_owned_material import Harness


def save(path,value):
    path.write_text(json.dumps(value));path.chmod(0o600)


def inputs(root,monkeypatch,*,gate=True,verify_login=False):
    h=Harness(root,monkeypatch,verify_login=verify_login);h.stage()
    original=h.inspector._original;source=h.h.source;state=source._state;draft=state._draft
    path=root/"original-draft.private.json"
    save(path,dict(username=draft.username,access_profile=draft.access_profile,source_defaults_digest=draft.source_defaults_digest,
        nonmaterial_request_digest=draft.nonmaterial_request_digest,wire=draft._wire.decode("ascii"),response_vdom=draft._response_vdom))
    key=root/"mcp-authority.key";key.write_bytes(b"j"*32);key.chmod(0o600)
    descriptor=dict(contract=LOGIN_CONTRACT if verify_login else CONTRACT,original_directory=str(original._directory),original_packet_file=str(original._packet_file),
        original_witness_key_file=str(original._key_file),original_store_file=str(original._store._path),
        original_store_key_file=str(original._store._key_path),original_checkpoint_store_ref=original._store._checkpoint_store_ref,
        original_draft_file=str(path),initial_material_directory=str(h.inspector._initial._directory),
        initial_witness_key_file=str(h.inspector._initial._key_file),reset_material_directory=str(h.material._directory),
        reset_witness_key_file=str(h.material._key_file),reset_store_file=str(h.store._path),reset_store_key_file=str(h.store._key_path),
        reset_checkpoint_store_ref=h.store._checkpoint_store_ref,checkpoint_socket=str(root/"checkpoint.sock"),
        checkpoint_authority_ref="owned-reset-runtime-test-checkpoint",authority_key_file=str(key),expected_serial=source._serial,
        api_principal=state._principal,ssh_host=source._ssh.host,ssh_port=source._ssh.port,
        ssh_known_hosts_file=str(source._ssh.known_hosts_file),ssh_timeout_seconds=source._ssh.timeout_seconds,
        environment_ref="owned-reset-test-environment",scope_ref="owned-reset-test-scope",audience_ref="owned-reset-test-audience",
        transport_digest="c"*64)
    assert set(descriptor)==module._FIELDS
    metadata=root/"owned-runtime.private.json";save(metadata,descriptor)
    monkeypatch.setattr(module,"load_secret_metadata_http_transport_config",lambda env:source._config)
    monkeypatch.setattr(module,"owner_login_provider",lambda env:source._provider)
    checkpoints=iter((h.h.cp,h.cp))
    monkeypatch.setattr(module,"_M4PlanningCheckpoint",lambda *args:next(checkpoints))
    env={PREFIX+"ENABLED":"true",PREFIX+"EXECUTION_ENABLED":str(gate).lower(),PREFIX+"VERIFY_LOGIN":str(verify_login).lower(),PREFIX+"DESCRIPTOR_FILE":str(metadata)}
    return h,env,descriptor,metadata


def test_default_off_does_not_read_config_credentials_or_files(monkeypatch):
    def forbidden(*args,**kwargs):raise AssertionError("No input should be opened.")
    monkeypatch.setattr(module,"_metadata",forbidden)
    assert build_local_reset_owned_candidate({}) is None
    for env in ({PREFIX+"EXECUTION_ENABLED":"true"},{PREFIX+"ENABLED":"True"},{PREFIX+"EXECUTION_ENABLED":"yes"}):
        with pytest.raises(LocalResetOwnedMcpError):build_local_reset_owned_candidate(env)


@pytest.mark.parametrize("gate",[False,True])
def test_exact_protected_original_and_staged_material_reconstruct_without_product_requests(tmp_path,monkeypatch,gate):
    h,env,_,_=inputs(tmp_path,monkeypatch,gate=gate)
    before=len(h.h.network.calls)+len(h.h.network.http_calls)
    action=build_local_reset_owned_candidate(env)
    assert action._enabled is gate and action._material._enabled is gate
    assert action._material._store.claim_count==0 and action._material.reference==h.reference
    assert action._material._inspector._original._store._read_only
    assert action._material._inspector._creation_digest==h.inspector._creation_digest
    assert len(h.h.network.calls)+len(h.h.network.http_calls)==before
    action.close()
    assert action._material._sources._closed and action._material._inspector._initial._closed


@pytest.mark.parametrize("fault",["extra","mode","contract","serial","body","packet","no-owner","shared-key"])
def test_unsafe_or_foreign_runtime_inputs_cannot_create_an_execution_binding(tmp_path,monkeypatch,fault):
    h,env,descriptor,path=inputs(tmp_path,monkeypatch)
    if fault=="extra":descriptor["password"]="SENSITIVE_SENTINEL";save(path,descriptor)
    elif fault=="mode":path.chmod(0o644)
    elif fault=="contract":descriptor["contract"]="foreign-contract";save(path,descriptor)
    elif fault=="serial":descriptor["expected_serial"]="FOREIGN01";save(path,descriptor)
    elif fault=="body":
        draft=Path(descriptor["original_draft_file"]);value=json.loads(draft.read_bytes());value["wire"]='{"password":"SENSITIVE_SENTINEL"}';save(draft,value)
    elif fault=="packet":
        packet=Path(descriptor["original_packet_file"]);value=json.loads(packet.read_bytes());value["pins"]["private_nonce"]="6"*64;save(packet,value)
    elif fault=="no-owner":monkeypatch.setattr(module,"owner_login_provider",lambda env:None)
    elif fault=="shared-key":descriptor["authority_key_file"]=descriptor["reset_witness_key_file"];save(path,descriptor)
    with pytest.raises(LocalResetOwnedMcpError) as error:build_local_reset_owned_candidate(env)
    assert "SENSITIVE_SENTINEL" not in str(error.value) and h.store.claim_count==0


def test_consumed_material_cannot_be_reopened_writable_by_main(tmp_path,monkeypatch):
    h,env,_,_=inputs(tmp_path,monkeypatch)
    assert str(h.execute().outcome)=="succeeded"
    with pytest.raises(LocalResetOwnedMcpError):build_local_reset_owned_candidate(env)
    assert h.store.claim_count==1


@pytest.mark.parametrize("gate",[False,True])
def test_v2_explicit_login_descriptor_and_staged_material_reconstruct_without_io(tmp_path,monkeypatch,gate):
    h,env,_,_=inputs(tmp_path,monkeypatch,gate=gate,verify_login=True)
    calls=len(h.h.network.calls)+len(h.h.network.http_calls)
    action=build_local_reset_owned_candidate(env)
    assert action._material._verify_login and action._material._enabled is gate
    assert action._contract.endswith("-v2") and action._material.reference==h.reference
    assert calls==len(h.h.network.calls)+len(h.h.network.http_calls)
    action.close()


@pytest.mark.parametrize("fault",["missing-login-opt-in","foreign-descriptor","foreign-staged-material"])
def test_v2_flag_descriptor_and_material_cannot_be_cross_selected(tmp_path,monkeypatch,fault):
    h,env,descriptor,path=inputs(tmp_path,monkeypatch,verify_login=fault!="foreign-staged-material")
    if fault=="missing-login-opt-in":env.pop(PREFIX+"VERIFY_LOGIN")
    elif fault=="foreign-descriptor":descriptor["contract"]=CONTRACT;save(path,descriptor)
    else:
        env[PREFIX+"VERIFY_LOGIN"]="true";descriptor["contract"]=LOGIN_CONTRACT;save(path,descriptor)
    with pytest.raises(LocalResetOwnedMcpError):build_local_reset_owned_candidate(env)
    assert h.store.claim_count==0


@pytest.mark.parametrize("env",[{PREFIX+"VERIFY_LOGIN":"true"},{PREFIX+"VERIFY_LOGIN":"True"}])
def test_login_flag_fails_closed_without_enabled_runtime(env):
    with pytest.raises(LocalResetOwnedMcpError):build_local_reset_owned_candidate(env)
