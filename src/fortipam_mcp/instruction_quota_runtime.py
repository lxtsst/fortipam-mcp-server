"""Default-closed owner startup for a fixed shared-setting quota cycle.

Protected configuration independently selects the admitted root. The manifest
contains digest projections, selected numeric quotas/usage and private controls.
It never contains unrestricted native settings or responses.
Startup performs no device reads; every preview/dispatch must freshly verify the
complete native setting. Original ledgers and keys cannot be recreated on reopen.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import http.client
import json
import os
from pathlib import Path
from typing import Any, Literal, cast

from v4_planning.models import require_digest, require_ref

from .instruction_quota_contract import (
    InstructionQuotaState, InstructionQuotaTransition, _quotas_valid, _state_digest,
)
from .instruction_feature_contract import _digest
from .instruction_quota_http_transport import FortiPamInstructionQuotaHttpTransport
from .instruction_quota_http_reader import read_instruction_quota_context
from .instruction_resource_usage import CONTRACT as USAGE_CONTRACT, InstructionResourceUsage
from .instruction_quota_live_workflow import InstructionQuotaLiveWorkflow
from .instruction_quota_mcp_action import InstructionQuotaMcpAction
from .ldap_server_projection import _members, _validate
from .ldap_server_runtime import _key, _path, _private_file, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import (
    _json_value_end, _skip_json_space, _zeroize_mutable,
    SecretMetadataHttpTransportConfig,
    load_secret_metadata_http_transport_config,
)

PREFIX = "FORTIPAM_MCP_V4_INSTRUCTION_QUOTA_700_"
CONTRACT = "fortipam-v4-shared-instruction-quota-startup-v1"
SCOPE = "fortipam-lab-shared-secret-setting"
_ERROR = "FortiPAM Instruction quota startup is unavailable."
_MARKER = "quota.runtime.json"
_PATH_KEYS = frozenset({"state_hmac_key_file", *(
    phase+suffix for phase in ("allocate","restore")
    for suffix in ("_execution_database_file","_execution_hmac_key_file","_authority_hmac_key_file"))})
_SCHEMA = {
    "baseline":frozenset({"serial_digest","schema_digest","preserved_digest","state_digest","field_count",
        "video_quota_percent","file_quota_percent","software_quota_percent","instruction_quota_percent"}),
    "usage":frozenset({"state_digest","total_bytes","video_bytes","file_bytes","software_bytes","instruction_bytes"}),
    "cycle":frozenset({"cycle_nonce","allocate_nonce","restore_nonce"}),
    "identity":frozenset({"environment_ref","scope_ref","audience_ref",
                         "allowed_requester_digest","allowed_transport_digest"}),
    "paths":_PATH_KEYS,
}


def _flag(environment: Mapping[str,str], suffix: str) -> bool:
    value = environment.get(PREFIX+suffix,"false")
    if type(value) is not str or value not in {"true","false"}:
        raise ValueError
    return value=="true"


def _manifest(path: Path) -> dict[str,Any]:
    raw = _read(path,16384)
    try:
        start = _skip_json_space(raw,0)
        end = _json_value_end(raw,start)
        if _skip_json_space(raw,end)!=len(raw):
            raise ValueError
        _validate(raw,(start,end))
        fields = _members(raw,(start,end))
        if set(fields)!=set(_SCHEMA)|{"contract","phase"}:
            raise ValueError
        for name,span in fields.items():
            if name in {"contract","phase"}:
                if raw[span[0]]!=34:
                    raise ValueError
            else:
                children = _members(raw,span)
                if set(children)!=_SCHEMA[name] or any(raw[left]!=34 for left,_ in children.values()):
                    raise ValueError
        value = json.loads(raw)
        if value["contract"]!=CONTRACT or value["phase"] not in {"allocate","restore"}:
            raise ValueError
        return value  # type: ignore[no-any-return]
    finally:
        _zeroize_mutable(raw)


def _unsigned(value: str, maximum: int) -> int:
    if (type(value) is not str or not 1<=len(value)<=16 or not value.isascii()
            or not value.isdecimal() or str(int(value))!=value or not 0<=int(value)<=maximum):
        raise ValueError
    return int(value)


def _expected_state(baseline: dict[str,str], *, allocated: bool) -> InstructionQuotaState:
    """Owner expectation only; preview and dispatch still require native reads."""
    for key in ("serial_digest","schema_digest","preserved_digest","state_digest"):
        require_digest(baseline[key],key)
    count = _unsigned(baseline["field_count"],512)
    if count<3:
        raise ValueError
    quotas = tuple(_unsigned(baseline[key],95) for key in (
        "video_quota_percent","file_quota_percent","software_quota_percent","instruction_quota_percent"))
    original = cast(tuple[int,int,int,int],quotas)
    _quotas_valid(original)
    if original[3]!=0 or original[1]<2:
        raise ValueError
    state = object.__new__(InstructionQuotaState)
    for key,value in {"_serial":baseline["serial_digest"],"_schema":baseline["schema_digest"],
            "_preserved":baseline["preserved_digest"],"field_count":count}.items():
        object.__setattr__(state,key,value)
    if _state_digest(state,original)!=baseline["state_digest"]:
        raise ValueError
    video,file,software,_ = original
    target = (video,file-1,software,1) if allocated else original
    _quotas_valid(target)
    object.__setattr__(state,"_quotas",target)
    object.__setattr__(state,"_state",_state_digest(state,target))
    return state


def _expected_usage(values: dict[str,str], serial: str) -> InstructionResourceUsage:
    """Validate a private phase snapshot; it never replaces the live source."""
    require_digest(values["state_digest"],"usage_digest")
    counts = cast(tuple[int,int,int,int,int],tuple(_unsigned(values[key],2**53-1) for key in (
        "total_bytes","video_bytes","file_bytes","software_bytes","instruction_bytes")))
    total,*used = counts
    if total<=0 or any(value>total for value in used) or sum(used)>total:
        raise ValueError
    expected = _digest([USAGE_CONTRACT,serial,counts])
    if expected!=values["state_digest"]:
        raise ValueError
    usage = object.__new__(InstructionResourceUsage)
    for key,value in {"_serial":serial,"_bytes":counts,"_state":expected}.items():
        object.__setattr__(usage,key,value)
    return usage


def _family(path: Path) -> set[Path]:
    return {Path(str(path)+suffix) for suffix in ("","-wal","-shm","-journal")}


def _paths(manifest: dict[str,Any], manifest_path: Path, root: Path) -> tuple[Path,dict[str,Path]]:
    state = _path(str(root/("instruction-quota-"+manifest["baseline"]["serial_digest"])),directory=True)
    paths = {name:_path(value) for name,value in manifest["paths"].items()}
    protected = {manifest_path,*paths.values()}
    if len(protected)!=1+len(paths) or any(state==item or state in item.parents for item in protected):
        raise ValueError
    families = [_family(paths[phase+"_execution_database_file"]) for phase in ("allocate","restore")]
    if families[0]&families[1]:
        raise ValueError
    for phase,family in zip(("allocate","restore"),families,strict=True):
        if (family-{paths[phase+"_execution_database_file"]})&protected:
            raise ValueError
        for member in family:
            if os.path.lexists(member):
                _private_file(member)
    return state,paths


def _build_instruction_quota_candidate_binding(environment: Mapping[str,str], *,
        read_only_reconciliation: bool = False) -> tuple[InstructionQuotaMcpAction | None, frozenset[str]]:
    """Admit owner-only startup inputs without exposing a device or new authority."""
    try:
        enabled,execution = _flag(environment,"ENABLED"),_flag(environment,"EXECUTION_ENABLED")
        if type(read_only_reconciliation) is not bool or (read_only_reconciliation and (not enabled or execution)):
            raise ValueError
        if not enabled:
            if execution:
                raise ValueError
            return None, frozenset()
        # This root comes independently from protected server configuration,
        # never from the manifest, profile fixtures or MCP arguments.
        root = _path(environment[PREFIX+"ADMITTED_STATE_ROOT"],directory=True)
        manifest_path = _path(environment[PREFIX+"STARTUP_MANIFEST_FILE"])
        manifest = _manifest(manifest_path)
        baseline = _expected_state(manifest["baseline"],allocated=False)
        phase: Literal["allocate","restore"] = manifest["phase"]
        identity = manifest["identity"]
        if identity["scope_ref"]!=SCOPE:
            raise ValueError
        for name in ("environment_ref","scope_ref","audience_ref"):
            require_ref(identity[name],name)
        for name in ("allowed_requester_digest","allowed_transport_digest"):
            require_digest(identity[name],name)
        nonces = manifest["cycle"]
        for value in nonces.values():
            require_digest(value,"cycle_nonce")
        if len(set(nonces.values()))!=3:
            raise ValueError
        state,paths = _paths(manifest,manifest_path,root)
        if read_only_reconciliation:
            required = ("quota.runtime.json", "operation.lock", "allocate.claim.json", "allocate.ack.json",
                        "allocate.result.json", "allocate.m4.json", "restore.claim.json")
            if (phase != "restore" or any(not (state/name).is_file() for name in required)
                    or any(not paths[name+"_execution_database_file"].is_file() for name in ("allocate", "restore"))
                    or any(os.path.lexists(state/name) for name in ("restore.ack.json", "restore.result.json"))):
                raise ValueError
            for name in required:
                _private_file(state/name)
        keys = {name:_key(path) for name,path in paths.items() if name.endswith("_hmac_key_file")}
        if len(set(keys.values()))!=5:
            raise ValueError
        binding = InstructionQuotaTransition(baseline,_expected_state(manifest["baseline"],allocated=phase=="restore"),
            _expected_usage(manifest["usage"],baseline._serial),
            phase=phase,operation_nonce=nonces[phase+"_nonce"])
        config = load_secret_metadata_http_transport_config(environment)

        def fresh_state(config: SecretMetadataHttpTransportConfig, *, serial_digest: str) -> tuple[InstructionQuotaState,InstructionResourceUsage]:
            current,usage = read_instruction_quota_context(config,serial_digest=serial_digest)
            if current.field_count!=baseline.field_count:
                raise ValueError
            return current,usage

        transport = FortiPamInstructionQuotaHttpTransport(config,baseline,binding,
            state_directory=state,cycle_nonce=nonces["cycle_nonce"],state_key=keys["state_hmac_key_file"],
            execution_enabled=execution,state_reader=fresh_state,
            connection_factory=http.client.HTTPSConnection)
        root_info = root.lstat()
        # Usage is phase-local and included in binding.digest. The immutable
        # cycle pin retains all baseline, identity, nonce, path and key inputs.
        common = {"contract":CONTRACT,"digest":_digest({
            "manifest":{key:value for key,value in manifest.items() if key not in {"phase","usage"}},
            "root":str(root),"root_identity":[root_info.st_dev,root_info.st_ino],
            "transport_namespace":transport._namespace,
            "timeout_seconds":config.timeout_seconds,
            "keys":{name:hashlib.sha256(value).hexdigest() for name,value in keys.items()}})}
        with transport.operation_lock(require_existing=read_only_reconciliation):
            existing = transport._exists(_MARKER)
            if existing:
                if transport._read(_MARKER)!=common:
                    raise ValueError
                if any(not paths[phase+"_execution_database_file"].exists() for phase in ("allocate","restore")):
                    raise ValueError
            else:
                if read_only_reconciliation:
                    raise ValueError
                native_names = {name+suffix for name in ("allocate","restore")
                                for suffix in (".claim.json",".ack.json",".result.json")} | {"allocate.m4.json"}
                if (any(transport._exists(name) for name in native_names)
                        or any(os.path.lexists(member) for phase in ("allocate","restore")
                               for member in _family(paths[phase+"_execution_database_file"]))):
                    raise ValueError
                transport._write_once(_MARKER,common)
            stores = {name:PersistentM4ExecutionStateStore(paths[name+"_execution_database_file"],
                        paths[name+"_execution_hmac_key_file"], read_only=read_only_reconciliation)
                      for name in ("allocate","restore")}
            if phase=="restore":
                transport._original_allocate()
                proof = transport._read("allocate.m4.json")
                if proof["store"]!=InstructionQuotaLiveWorkflow._store_binding(stores["allocate"]):
                    raise ValueError
        workflow = InstructionQuotaLiveWorkflow(transport,canonical_state_directory=state,
            execution_store=stores[phase],authority_key=keys[phase+"_authority_hmac_key_file"],
            original_allocate_store=stores["allocate"] if phase=="restore" else None,
            execution_enabled=execution,**identity)
        if phase=="restore":
            with transport.operation_lock(require_existing=read_only_reconciliation):
                workflow._original_m4()
        return (InstructionQuotaMcpAction(workflow,execution_enabled=execution),
                frozenset(hashlib.sha256(value).hexdigest() for value in keys.values()))
    except Exception:
        raise ValueError(_ERROR) from None


def build_instruction_quota_candidate(environment: Mapping[str,str], *,
        read_only_reconciliation: bool = False) -> InstructionQuotaMcpAction | None:
    """Public startup interface; private cohort never enters MCP results."""
    return _build_instruction_quota_candidate_binding(environment,
        read_only_reconciliation=read_only_reconciliation)[0]


__all__ = ["build_instruction_quota_candidate"]
