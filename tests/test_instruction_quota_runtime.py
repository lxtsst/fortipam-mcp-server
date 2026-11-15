"""Protected owner startup pins both phases and preserves original execution."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from fortipam_mcp import instruction_quota_runtime as r
from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
from test_instruction_quota_contract import SERIAL, state, usage
from test_instruction_quota_http_transport import Connection, Cycle, Device, assert_closed
from test_instruction_quota_live_workflow import IDENTITY


def usage_projection(value: Any) -> dict[str,str]:
    return {"state_digest":value._state,**{key:str(number) for key,number in zip(
        ("total_bytes","video_bytes","file_bytes","software_bytes","instruction_bytes"),value._bytes)}}


def setup(tmp_path: Path) -> tuple[dict[str,str],dict[str,Any],Path,Cycle]:
    tmp_path = tmp_path.resolve()
    tmp_path.chmod(0o700)
    root = tmp_path/"admitted"
    root.mkdir(mode=0o700)
    directory = root/("instruction-quota-"+SERIAL)
    directory.mkdir(mode=0o700)
    cycle = Cycle(directory,Device())
    baseline = state(other=cycle.device.sibling)
    paths: dict[str,str] = {}
    for phase in ("allocate","restore"):
        paths[phase+"_execution_database_file"] = str(tmp_path/(phase+".sqlite"))
    for index,name in enumerate(sorted(r._PATH_KEYS-{"allocate_execution_database_file","restore_execution_database_file"})):
        key = tmp_path/(name+".key")
        key.write_bytes(bytes([65+index])*32)
        key.chmod(0o600)
        paths[name] = str(key)
    manifest: dict[str,Any] = {"contract":r.CONTRACT,"phase":"allocate",
        "baseline":{"serial_digest":baseline._serial,"schema_digest":baseline._schema,
            "preserved_digest":baseline._preserved,"state_digest":baseline._state,"field_count":str(baseline.field_count),
            **{name:str(value) for name,value in zip(("video_quota_percent","file_quota_percent",
                "software_quota_percent","instruction_quota_percent"),baseline._quotas)}},
        "usage":usage_projection(usage()),
        "cycle":{"cycle_nonce":"c"*64,"allocate_nonce":"a"*64,"restore_nonce":"b"*64},
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
    monkeypatch.setattr(r,"read_instruction_quota_context",cycle.device.read)


def run(action: Any) -> dict[str,object]:
    item = action._workflow
    preview = item.preview(**IDENTITY)
    authorization = item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    return item.execute(cast(str,authorization["authorization_ref"]),**IDENTITY)


def test_disabled_and_invalid_flags_have_no_file_or_device_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r,"_path",lambda *args,**kwargs:pytest.fail("disabled startup read a path"))
    assert r.build_instruction_quota_candidate({}) is None
    for values in ({"EXECUTION_ENABLED":"true"},{"ENABLED":"TRUE"},{"ENABLED":True}):
        with pytest.raises(ValueError):
            r.build_instruction_quota_candidate({r.PREFIX+key:value for key,value in values.items()})


@pytest.mark.parametrize("old_component", ["startup", "baseline"])
def test_rejects_feature_startup_and_state_before_device_io(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, old_component: str) -> None:
    env, manifest, path, cycle = setup(tmp_path)
    connect(monkeypatch, cycle)
    if old_component == "startup":
        manifest["contract"] = "fortipam-v4-shared-instruction-feature-startup-v2"
    else:
        manifest["baseline"]["state_digest"] = r._digest([
            "fortipam-700-build29-instruction-feature-private-v2", "synthetic-state"])
    save(path, manifest)
    with pytest.raises(ValueError):
        r.build_instruction_quota_candidate(env)
    assert not cycle.device.connections and not cycle.device.requests


def test_startup_closed_then_reopen_allocate_and_restore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    connect(monkeypatch,cycle)
    action = r.build_instruction_quota_candidate(env)
    assert action is not None and not action._enabled and not action._workflow._enabled
    assert not action._workflow._transport._enabled
    assert not cycle.device.connections
    preview = action._workflow.preview(**IDENTITY)
    with pytest.raises(RuntimeError):
        action._workflow.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    assert not cycle.device.requests
    original_marker = (cycle.path/r._MARKER).read_bytes()
    env[r.PREFIX+"EXECUTION_ENABLED"] = "true"
    action = r.build_instruction_quota_candidate(env)
    assert run(action)["verification"]=="verified"
    original = {p.name:p.read_bytes() for p in cycle.path.glob("allocate.*.json")}
    restarted = r.build_instruction_quota_candidate(env)
    assert restarted is not None
    with pytest.raises(RuntimeError):
        restarted._workflow.preview(**IDENTITY)
    manifest["phase"] = "restore"
    save(path,manifest)
    restore = r.build_instruction_quota_candidate(env)
    assert restore is not None and restore.phase=="restore"
    assert run(restore)["verification"]=="verified"
    for name,raw in original.items():
        assert (cycle.path/name).read_bytes()==raw
    assert (cycle.path/r._MARKER).read_bytes()==original_marker
    assert len(cycle.device.requests)==2 and cycle.device.instruction == 0
    assert_closed(cycle.device)


@pytest.mark.parametrize("missing", [None, "marker", "ledger"])
def test_readonly_reconciliation_bootstrap_never_initializes_or_changes_original_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str | None,
) -> None:
    from fortipam_mcp.instruction_quota_reconciliation import InstructionQuotaRestoreReconciler
    env, manifest, path, cycle = setup(tmp_path)
    connect(monkeypatch, cycle)
    env[r.PREFIX + "EXECUTION_ENABLED"] = "true"
    assert run(r.build_instruction_quota_candidate(env))["verification"] == "verified"
    manifest["phase"] = "restore"
    save(path, manifest)
    restore = r.build_instruction_quota_candidate(env)
    with monkeypatch.context() as patch:
        def fail_put(self: Connection, *args: object, **kwargs: object) -> None:
            raise RuntimeError("synthetic-lost-restoration")
        patch.setattr(Connection, "request", fail_put)
        assert run(restore)["verification"] == "unknown"
    env[r.PREFIX + "EXECUTION_ENABLED"] = "false"
    if missing == "marker":
        (cycle.path / r._MARKER).unlink()
    elif missing == "ledger":
        Path(manifest["paths"]["restore_execution_database_file"]).unlink()
    files = list(tmp_path.rglob("*"))
    before = {str(item): item.read_bytes() for item in files if item.is_file()}
    if missing:
        with pytest.raises(ValueError):
            r.build_instruction_quota_candidate(env, read_only_reconciliation=True)
    else:
        item = r.build_instruction_quota_candidate(env, read_only_reconciliation=True)
        assert item is not None and not item._enabled
        report = InstructionQuotaRestoreReconciler(item._workflow).assess(**IDENTITY)
        assert report["outcome"] == "not-assessed" and report["original_native_m4_witness_unchanged"] is True
    after = {str(item): item.read_bytes() for item in tmp_path.rglob("*") if item.is_file()}
    assert after == before and len(cycle.device.requests) == 1


@pytest.mark.parametrize("invalid", ["enabled", "execution", "phase"])
def test_readonly_reconciliation_requires_enabled_closed_restore_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str,
) -> None:
    env, manifest, path, cycle = setup(tmp_path)
    connect(monkeypatch, cycle)
    if invalid == "enabled":
        env[r.PREFIX + "ENABLED"] = "false"
    elif invalid == "execution":
        env[r.PREFIX + "EXECUTION_ENABLED"] = "true"
    with pytest.raises(ValueError):
        r.build_instruction_quota_candidate(env, read_only_reconciliation=True)
    assert not cycle.device.requests and not (cycle.path / r._MARKER).exists()


@pytest.mark.parametrize("change",["contract","scope","baseline","field_count","extra","key_alias","key_reuse","database_alias","nonce_reuse"])
def test_invalid_owner_inputs_refuse_before_config_or_namespace_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    if change=="contract": manifest["contract"]="other-contract"
    elif change=="scope": manifest["identity"]["scope_ref"]="synthetic-profile-only-scope"
    elif change=="baseline": manifest["baseline"]["state_digest"]="f"*64
    elif change=="field_count": manifest["baseline"]["field_count"]="02"
    elif change=="extra": manifest["unselected"]="synthetic-private-value"
    elif change=="key_alias": manifest["paths"]["allocate_authority_hmac_key_file"]=manifest["paths"]["state_hmac_key_file"]
    elif change=="key_reuse": Path(manifest["paths"]["allocate_authority_hmac_key_file"]).write_bytes(Path(manifest["paths"]["state_hmac_key_file"]).read_bytes())
    elif change=="database_alias": manifest["paths"]["restore_execution_database_file"]=manifest["paths"]["allocate_execution_database_file"]+"-wal"
    elif change=="nonce_reuse": manifest["cycle"]["restore_nonce"]=manifest["cycle"]["allocate_nonce"]
    save(path,manifest)
    monkeypatch.setattr(r,"load_secret_metadata_http_transport_config",lambda *args:pytest.fail("invalid startup loaded API config"))
    with pytest.raises(ValueError,match="^FortiPAM Instruction quota startup is unavailable.$"):
        r.build_instruction_quota_candidate(env)
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
    with pytest.raises(ValueError): r.build_instruction_quota_candidate(env)
    assert not (cycle.path/r._MARKER).exists()


@pytest.mark.parametrize("change",["identity","nonce","key","timeout","missing_allocate_ledger","missing_restore_ledger","marker"])
def test_reopen_rejects_drift_or_missing_records_without_recreating_ledgers(tmp_path: Path, change: str) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    assert r.build_instruction_quota_candidate(env) is not None
    if change=="identity": manifest["identity"]["allowed_requester_digest"]="9"*64;save(path,manifest)
    elif change=="nonce": manifest["cycle"]["allocate_nonce"]="f"*64;save(path,manifest)
    elif change=="key": Path(manifest["paths"]["allocate_authority_hmac_key_file"]).write_bytes(b"Z"*32)
    elif change=="timeout": env[ENV_PREFIX+"TIMEOUT_SECONDS"]="1"
    elif change.startswith("missing_"):
        phase="allocate" if change=="missing_allocate_ledger" else "restore"
        Path(manifest["paths"][phase+"_execution_database_file"]).unlink()
    elif change=="marker": (cycle.path/r._MARKER).write_bytes(b"{}")
    before = {p.name:p.read_bytes() for p in tmp_path.glob("*.sqlite")}
    with pytest.raises(ValueError): r.build_instruction_quota_candidate(env)
    assert {p.name:p.read_bytes() for p in tmp_path.glob("*.sqlite") }==before


def test_restore_needs_original_proof_and_drifted_digest_projection_is_not_a_native_observation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    connect(monkeypatch,cycle)
    manifest["phase"]="restore";save(path,manifest)
    with pytest.raises(ValueError): r.build_instruction_quota_candidate(env)
    assert not cycle.device.requests
    manifest["phase"]="allocate";save(path,manifest)
    action = r.build_instruction_quota_candidate(env)
    assert action is not None
    cycle.device.sibling="changed"
    with pytest.raises(RuntimeError): action._workflow.preview(**IDENTITY)
    assert not cycle.device.requests


def test_normal_main_composes_quota_builder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn
    from fortipam_mcp import http_server
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment

    env,_,_,_ = setup(tmp_path)
    action = r.build_instruction_quota_candidate(env)
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
        captured["action"]=kwargs["v4_instruction_quota_candidate_action"]
        return object()
    async def serve(self: object, sockets: object = None) -> None:
        captured["served"]=True
    monkeypatch.setattr(r,"build_instruction_quota_candidate",build)
    monkeypatch.setattr(http_server,"create_http_app",create)
    monkeypatch.setattr(uvicorn.Server,"serve",serve)
    http_server.main()
    assert captured=={"built":True,"action":action,"served":True}


def test_protected_http_environment_loads_only_versioned_quota_namespace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp.http_server import HTTP_ENV_FILE_VARIABLE, load_http_runtime_environment
    monkeypatch.setattr(os,"environ",dict(os.environ))
    values = {r.PREFIX+"ENABLED":"true",r.PREFIX+"EXECUTION_ENABLED":"false",
        r.PREFIX+"STARTUP_MANIFEST_FILE":"/protected/feature.json",r.PREFIX+"ADMITTED_STATE_ROOT":"/protected/feature"}
    path=tmp_path/"http.env"
    path.write_text("".join(key+"="+value+"\n" for key,value in values.items()))
    path.chmod(0o600)
    monkeypatch.setenv(HTTP_ENV_FILE_VARIABLE,str(path))
    for name in values: monkeypatch.delenv(name,raising=False)
    assert load_http_runtime_environment()
    assert {name:os.environ.get(name) for name in values}==values
    assert r.build_instruction_quota_candidate({"FORTIPAM_MCP_V4_INSTRUCTION_QUOTA_EXTRA_ENABLED":"true"}) is None


@pytest.mark.parametrize("section,key,value", [
    ("baseline","file_quota_percent","1"),
    ("baseline","instruction_quota_percent","1"),
    ("baseline","video_quota_percent","91"),
    ("baseline","file_quota_percent","05"),
    ("usage","total_bytes","0"),
    ("usage","file_bytes","401"),
    ("usage","instruction_bytes","1"),
    ("usage","total_bytes",str(2**53)),
    ("usage","file_bytes","３５０"),
    ("usage","file_bytes",350),
    ("usage","state_digest","f"*64),
])
def test_invalid_numeric_expectations_refuse_before_api_or_runtime_state(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, section: str, key: str, value: object) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    manifest[section][key] = value
    # Bind the modified numeric value where possible, so validation must also
    # enforce byte/percentage semantics rather than only detecting a bad hash.
    if section == "usage" and key != "state_digest" and isinstance(value,str) and value.isascii() and value.isdecimal():
        values = tuple(int(manifest["usage"][name]) for name in (
            "total_bytes","video_bytes","file_bytes","software_bytes","instruction_bytes"))
        manifest["usage"]["state_digest"] = r._digest([r.USAGE_CONTRACT,SERIAL,values])
    save(path,manifest)
    monkeypatch.setattr(r,"load_secret_metadata_http_transport_config",lambda *args:pytest.fail("invalid projection loaded API config"))
    with pytest.raises(ValueError):
        r.build_instruction_quota_candidate(env)
    assert not (cycle.path/r._MARKER).exists() and not cycle.device.requests


def test_phase_usage_can_refresh_without_changing_original_cycle_or_claims(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    connect(monkeypatch,cycle)
    env[r.PREFIX+"EXECUTION_ENABLED"] = "true"
    allocate = r.build_instruction_quota_candidate(env)
    assert run(allocate)["verification"] == "verified"
    originals = {p.name:p.read_bytes() for p in cycle.path.glob("*.json")}
    # Different phase-local usage after resource cleanup requires a new binding;
    # all original allocation anchors and the immutable runtime pin remain.
    cycle.device.used_file = 351
    manifest["phase"] = "restore"
    manifest["usage"] = usage_projection(usage(file=351))
    save(path,manifest)
    restore = r.build_instruction_quota_candidate(env)
    assert restore is not None and allocate is not None
    assert restore._workflow._binding._usage != allocate._workflow._binding._usage
    assert run(restore)["verification"] == "verified"
    for name,raw in originals.items():
        assert (cycle.path/name).read_bytes() == raw
    assert len(cycle.device.requests) == 2 and cycle.device.instruction == 0


def test_expected_usage_projection_cannot_replace_live_observation(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    connect(monkeypatch,cycle)
    action = r.build_instruction_quota_candidate(env)
    assert action is not None
    cycle.device.used_file = 351
    with pytest.raises(RuntimeError):
        action._workflow.preview(**IDENTITY)
    assert not cycle.device.requests and action._workflow._execution_store.claim_count == 0


def test_new_usage_snapshot_does_not_clear_consumed_unknown_claim(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env,manifest,path,cycle = setup(tmp_path)
    connect(monkeypatch,cycle)
    env[r.PREFIX+"EXECUTION_ENABLED"] = "true"
    action = r.build_instruction_quota_candidate(env)
    cycle.device.status = 500
    assert run(action)["outcome"] == "reconciliation_required"
    originals = {p.name:p.read_bytes() for p in cycle.path.glob("*.json")}
    manifest["usage"] = usage_projection(usage(file=351))
    save(path,manifest)
    restarted = r.build_instruction_quota_candidate(env)
    assert restarted is not None
    with pytest.raises(RuntimeError):
        restarted._workflow.preview(**IDENTITY)
    for name,raw in originals.items():
        assert (cycle.path/name).read_bytes() == raw
    assert len(cycle.device.requests) == 1 and restarted._workflow._execution_store.claim_count == 1
