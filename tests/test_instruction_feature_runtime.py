"""Protected owner startup pins both phases and preserves original execution."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from fortipam_mcp import instruction_feature_runtime as r
from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
from test_instruction_feature_contract import SERIAL, state
from test_instruction_feature_http_transport import Cycle, Device, assert_closed
from test_instruction_feature_live_workflow import IDENTITY


def setup(tmp_path: Path) -> tuple[dict[str,str],dict[str,Any],Path,Cycle]:
    tmp_path = tmp_path.resolve()
    tmp_path.chmod(0o700)
    root = tmp_path/"admitted"
    root.mkdir(mode=0o700)
    directory = root/("instruction-feature-"+SERIAL)
    directory.mkdir(mode=0o700)
    cycle = Cycle(directory,Device())
    baseline = state()
    paths: dict[str,str] = {}
    for phase in ("enable","restore"):
        paths[phase+"_execution_database_file"] = str(tmp_path/(phase+".sqlite"))
    for index,name in enumerate(sorted(r._PATH_KEYS-{"enable_execution_database_file","restore_execution_database_file"})):
        key = tmp_path/(name+".key")
        key.write_bytes(bytes([65+index])*32)
        key.chmod(0o600)
        paths[name] = str(key)
    manifest: dict[str,Any] = {"contract":r.CONTRACT,"phase":"enable",
        "baseline":{"serial_digest":baseline._serial,"schema_digest":baseline._schema,
            "preserved_digest":baseline._preserved,"state_digest":baseline._state,"field_count":str(baseline.field_count)},
        "cycle":{"cycle_nonce":"c"*64,"enable_nonce":"a"*64,"restore_nonce":"b"*64},
        "identity":{"environment_ref":"synthetic-environment","scope_ref":r.SCOPE,
            "audience_ref":"synthetic-audience","allowed_requester_digest":IDENTITY["requester_digest"],
            "allowed_transport_digest":IDENTITY["transport_digest"]},"paths":paths}
    path = tmp_path/"startup.json"
    save(path,manifest)
    environment = {r.PREFIX+"ENABLED":"true",r.PREFIX+"ADMITTED_STATE_ROOT":str(root),
        r.PREFIX+"STARTUP_MANIFEST_FILE":str(path),ENV_PREFIX+"ENABLED":"true",
        ENV_PREFIX+"BASE_URL":"https://synthetic.invalid",ENV_PREFIX+"API_TOKEN":"synthetic-token"}
    return environment,manifest,path,cycle


def save(path: Path, manifest: dict[str,Any]) -> None:
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)


def connect(monkeypatch: pytest.MonkeyPatch, cycle: Cycle) -> None:
    monkeypatch.setattr(http.client,"HTTPSConnection",cycle.device.connect)
    monkeypatch.setattr(r,"read_instruction_feature_setting",cycle.device.read)


def run(action: Any) -> dict[str,object]:
    item = action._workflow
    preview = item.preview(**IDENTITY)
    authorization = item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    return item.execute(cast(str,authorization["authorization_ref"]),**IDENTITY)


def test_disabled_and_invalid_flags_have_no_file_or_device_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r,"_path",lambda *args,**kwargs:pytest.fail("disabled startup read a path"))
    assert r.build_instruction_feature_candidate({}) is None
    for values in ({"EXECUTION_ENABLED":"true"},{"ENABLED":"TRUE"},{"ENABLED":True}):
        with pytest.raises(ValueError):
            r.build_instruction_feature_candidate({r.PREFIX+key:value for key,value in values.items()})


@pytest.mark.parametrize("old_component", ["startup", "baseline"])
def test_v2_rejects_old_startup_and_baseline_before_device_io(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, old_component: str) -> None:
    env, manifest, path, cycle = setup(tmp_path)
    connect(monkeypatch, cycle)
    if old_component == "startup":
        manifest["contract"] = "fortipam-v4-shared-instruction-feature-startup-v1"
    else:
        baseline = manifest["baseline"]
        baseline["state_digest"] = r._digest([
            "fortipam-700-build29-instruction-feature-private-v1", baseline["serial_digest"],
            baseline["schema_digest"], baseline["preserved_digest"], "disable"])
    save(path, manifest)
    with pytest.raises(ValueError):
        r.build_instruction_feature_candidate(env)
    assert not cycle.device.connections and not cycle.device.requests


def test_startup_closed_then_reopen_enable_and_restore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    connect(monkeypatch,cycle)
    action = r.build_instruction_feature_candidate(env)
    assert action is not None and not action._enabled and not action._workflow._enabled
    assert not action._workflow._transport._enabled
    assert not cycle.device.connections
    preview = action._workflow.preview(**IDENTITY)
    with pytest.raises(RuntimeError):
        action._workflow.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    assert not cycle.device.requests
    original_marker = (cycle.path/r._MARKER).read_bytes()
    env[r.PREFIX+"EXECUTION_ENABLED"] = "true"
    action = r.build_instruction_feature_candidate(env)
    assert run(action)["verification"]=="verified"
    original = {p.name:p.read_bytes() for p in cycle.path.glob("enable.*.json")}
    restarted = r.build_instruction_feature_candidate(env)
    assert restarted is not None
    with pytest.raises(RuntimeError):
        restarted._workflow.preview(**IDENTITY)
    manifest["phase"] = "restore"
    save(path,manifest)
    restore = r.build_instruction_feature_candidate(env)
    assert restore is not None and restore.phase=="restore"
    assert run(restore)["verification"]=="verified"
    for name,raw in original.items():
        assert (cycle.path/name).read_bytes()==raw
    assert (cycle.path/r._MARKER).read_bytes()==original_marker
    assert len(cycle.device.requests)==2 and not cycle.device.enabled
    assert_closed(cycle.device)


@pytest.mark.parametrize("change",["contract","scope","baseline","field_count","extra","key_alias","key_reuse","database_alias","nonce_reuse"])
def test_invalid_owner_inputs_refuse_before_config_or_namespace_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    if change=="contract": manifest["contract"]="other-contract"
    elif change=="scope": manifest["identity"]["scope_ref"]="synthetic-profile-only-scope"
    elif change=="baseline": manifest["baseline"]["state_digest"]="f"*64
    elif change=="field_count": manifest["baseline"]["field_count"]="02"
    elif change=="extra": manifest["unselected"]="synthetic-private-value"
    elif change=="key_alias": manifest["paths"]["enable_authority_hmac_key_file"]=manifest["paths"]["state_hmac_key_file"]
    elif change=="key_reuse": Path(manifest["paths"]["enable_authority_hmac_key_file"]).write_bytes(Path(manifest["paths"]["state_hmac_key_file"]).read_bytes())
    elif change=="database_alias": manifest["paths"]["restore_execution_database_file"]=manifest["paths"]["enable_execution_database_file"]+"-wal"
    elif change=="nonce_reuse": manifest["cycle"]["restore_nonce"]=manifest["cycle"]["enable_nonce"]
    save(path,manifest)
    monkeypatch.setattr(r,"load_secret_metadata_http_transport_config",lambda *args:pytest.fail("invalid startup loaded API config"))
    with pytest.raises(ValueError,match="^FortiPAM Instruction feature startup is unavailable.$"):
        r.build_instruction_feature_candidate(env)
    assert not (cycle.path/r._MARKER).exists() and not cycle.device.requests


@pytest.mark.parametrize("change",["root_alias","file_mode","hardlink","symlink","root_in_manifest"])
def test_root_and_manifest_ownership_are_independent(tmp_path: Path, change: str) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    if change=="root_alias":
        alias=tmp_path/"alias";alias.symlink_to(Path(env[r.PREFIX+"ADMITTED_STATE_ROOT"]));env[r.PREFIX+"ADMITTED_STATE_ROOT"]=str(alias)
    elif change=="file_mode": path.chmod(0o644)
    elif change=="hardlink": os.link(path,tmp_path/"duplicate")
    elif change=="symlink":
        alias=tmp_path/"alias.json";alias.symlink_to(path);env[r.PREFIX+"STARTUP_MANIFEST_FILE"]=str(alias)
    elif change=="root_in_manifest": manifest["admitted_root"]=env.pop(r.PREFIX+"ADMITTED_STATE_ROOT");save(path,manifest)
    with pytest.raises(ValueError): r.build_instruction_feature_candidate(env)
    assert not (cycle.path/r._MARKER).exists()


@pytest.mark.parametrize("change",["identity","nonce","key","timeout","missing_enable_ledger","missing_restore_ledger","marker"])
def test_reopen_rejects_drift_or_missing_records_without_recreating_ledgers(tmp_path: Path, change: str) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    assert r.build_instruction_feature_candidate(env) is not None
    if change=="identity": manifest["identity"]["allowed_requester_digest"]="9"*64;save(path,manifest)
    elif change=="nonce": manifest["cycle"]["enable_nonce"]="f"*64;save(path,manifest)
    elif change=="key": Path(manifest["paths"]["enable_authority_hmac_key_file"]).write_bytes(b"Z"*32)
    elif change=="timeout": env[ENV_PREFIX+"TIMEOUT_SECONDS"]="1"
    elif change.startswith("missing_"):
        phase="enable" if change=="missing_enable_ledger" else "restore"
        Path(manifest["paths"][phase+"_execution_database_file"]).unlink()
    elif change=="marker": (cycle.path/r._MARKER).write_bytes(b"{}")
    before = {p.name:p.read_bytes() for p in tmp_path.glob("*.sqlite")}
    with pytest.raises(ValueError): r.build_instruction_feature_candidate(env)
    assert {p.name:p.read_bytes() for p in tmp_path.glob("*.sqlite") }==before


def test_restore_needs_original_proof_and_drifted_digest_projection_is_not_a_native_observation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    connect(monkeypatch,cycle)
    manifest["phase"]="restore";save(path,manifest)
    with pytest.raises(ValueError): r.build_instruction_feature_candidate(env)
    assert not cycle.device.requests
    manifest["phase"]="enable";save(path,manifest)
    action = r.build_instruction_feature_candidate(env)
    assert action is not None
    cycle.device.sibling="changed"
    with pytest.raises(RuntimeError): action._workflow.preview(**IDENTITY)
    assert not cycle.device.requests


def test_normal_main_composes_feature_builder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn
    from fortipam_mcp import http_server
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment

    env,_,_,_ = setup(tmp_path)
    action = r.build_instruction_feature_candidate(env)
    assert action is not None
    environment = _v4_environment(tmp_path/"oauth")
    environment[RUNTIME_PROFILE_ENV]="v4-controlled"
    captured: dict[str,object] = {}
    monkeypatch.setattr(os,"environ",environment)
    monkeypatch.setattr(http_server,"load_http_runtime_environment",lambda:False)
    def build(value: object) -> Any:
        assert value is environment
        captured["built"]=True
        return action
    def create(settings: object, **kwargs: object) -> object:
        captured["action"]=kwargs["v4_instruction_feature_candidate_action"]
        return object()
    async def serve(self: object, sockets: object = None) -> None:
        captured["served"]=True
    monkeypatch.setattr(r,"build_instruction_feature_candidate",build)
    monkeypatch.setattr(http_server,"create_http_app",create)
    monkeypatch.setattr(uvicorn.Server,"serve",serve)
    http_server.main()
    assert captured=={"built":True,"action":action,"served":True}


def test_protected_http_environment_loads_only_versioned_feature_namespace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp.http_server import HTTP_ENV_FILE_VARIABLE, load_http_runtime_environment
    values = {r.PREFIX+"ENABLED":"true",r.PREFIX+"EXECUTION_ENABLED":"false",
        r.PREFIX+"STARTUP_MANIFEST_FILE":"/protected/feature.json",r.PREFIX+"ADMITTED_STATE_ROOT":"/protected/feature"}
    path=tmp_path/"http.env"
    path.write_text("".join(key+"="+value+"\n" for key,value in values.items()))
    path.chmod(0o600)
    monkeypatch.setenv(HTTP_ENV_FILE_VARIABLE,str(path))
    for name in values: monkeypatch.delenv(name,raising=False)
    assert load_http_runtime_environment()
    assert {name:os.environ.get(name) for name in values}==values
    assert r.build_instruction_feature_candidate({"FORTIPAM_MCP_V4_INSTRUCTION_FEATURE_EXTRA_ENABLED":"true"}) is None
