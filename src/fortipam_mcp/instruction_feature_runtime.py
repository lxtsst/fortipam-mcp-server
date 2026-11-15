"""Default-closed owner startup for a fixed shared-setting feature cycle.

Protected configuration independently selects the admitted root. The manifest
contains digest projections and private control metadata, never native values.
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
from typing import Any, Literal

from v4_planning.models import require_digest, require_ref

from .instruction_feature_contract import (
    CONTRACT as STATE_CONTRACT, InstructionFeatureState, InstructionFeatureTransition, _digest,
)
from .instruction_feature_http_transport import FortiPamInstructionFeatureHttpTransport
from .instruction_feature_http_reader import read_instruction_feature_setting
from .instruction_feature_live_workflow import InstructionFeatureLiveWorkflow
from .instruction_feature_mcp_action import InstructionFeatureMcpAction
from .ldap_server_projection import _members, _validate
from .ldap_server_runtime import _key, _path, _private_file, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import (
    _json_value_end, _skip_json_space, _zeroize_mutable,
    SecretMetadataHttpTransportConfig,
    load_secret_metadata_http_transport_config,
)

PREFIX = "FORTIPAM_MCP_V4_INSTRUCTION_FEATURE_700_"
CONTRACT = "fortipam-v4-shared-instruction-feature-startup-v2"
SCOPE = "fortipam-lab-shared-secret-setting"
_ERROR = "FortiPAM Instruction feature startup is unavailable."
_MARKER = "feature.runtime.json"
_PATH_KEYS = frozenset({"state_hmac_key_file", *(
    phase+suffix for phase in ("enable","restore")
    for suffix in ("_execution_database_file","_execution_hmac_key_file","_authority_hmac_key_file"))})
_SCHEMA = {
    "baseline":frozenset({"serial_digest","schema_digest","preserved_digest","state_digest","field_count"}),
    "cycle":frozenset({"cycle_nonce","enable_nonce","restore_nonce"}),
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
        if value["contract"]!=CONTRACT or value["phase"] not in {"enable","restore"}:
            raise ValueError
        return value  # type: ignore[no-any-return]
    finally:
        _zeroize_mutable(raw)


def _expected_state(baseline: dict[str,str], *, enabled: bool) -> InstructionFeatureState:
    """Bind an owner's expected digest projection, not an observed native state."""
    for key in ("serial_digest","schema_digest","preserved_digest","state_digest"):
        require_digest(baseline[key],key)
    count = baseline["field_count"]
    if (not 1<=len(count)<=3 or not count.isascii() or not count.isdecimal()
            or not 2<=int(count)<=512 or str(int(count))!=count):
        raise ValueError
    disabled = _digest([STATE_CONTRACT,baseline["serial_digest"],baseline["schema_digest"],
                        baseline["preserved_digest"],"disable"])
    if baseline["state_digest"]!=disabled:
        raise ValueError
    state = object.__new__(InstructionFeatureState)
    values: dict[str,object] = {"_serial":baseline["serial_digest"],"_schema":baseline["schema_digest"],
        "_preserved":baseline["preserved_digest"],"field_count":int(count),"enabled":enabled,
        "_state":_digest([STATE_CONTRACT,baseline["serial_digest"],baseline["schema_digest"],
                          baseline["preserved_digest"],"enable" if enabled else "disable"])}
    for key,value in values.items():
        object.__setattr__(state,key,value)
    return state


def _family(path: Path) -> set[Path]:
    return {Path(str(path)+suffix) for suffix in ("","-wal","-shm","-journal")}


def _paths(manifest: dict[str,Any], manifest_path: Path, root: Path) -> tuple[Path,dict[str,Path]]:
    state = _path(str(root/("instruction-feature-"+manifest["baseline"]["serial_digest"])),directory=True)
    paths = {name:_path(value) for name,value in manifest["paths"].items()}
    protected = {manifest_path,*paths.values()}
    if len(protected)!=1+len(paths) or any(state==item or state in item.parents for item in protected):
        raise ValueError
    families = [_family(paths[phase+"_execution_database_file"]) for phase in ("enable","restore")]
    if families[0]&families[1]:
        raise ValueError
    for phase,family in zip(("enable","restore"),families,strict=True):
        if (family-{paths[phase+"_execution_database_file"]})&protected:
            raise ValueError
        for member in family:
            if os.path.lexists(member):
                _private_file(member)
    return state,paths


def build_instruction_feature_candidate(environment: Mapping[str,str]) -> InstructionFeatureMcpAction | None:
    """Admit owner-only startup inputs without exposing a device or new authority."""
    try:
        enabled,execution = _flag(environment,"ENABLED"),_flag(environment,"EXECUTION_ENABLED")
        if not enabled:
            if execution:
                raise ValueError
            return None
        # This root comes independently from protected server configuration,
        # never from the manifest, profile fixtures or MCP arguments.
        root = _path(environment[PREFIX+"ADMITTED_STATE_ROOT"],directory=True)
        manifest_path = _path(environment[PREFIX+"STARTUP_MANIFEST_FILE"])
        manifest = _manifest(manifest_path)
        baseline = _expected_state(manifest["baseline"],enabled=False)
        phase: Literal["enable","restore"] = manifest["phase"]
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
        keys = {name:_key(path) for name,path in paths.items() if name.endswith("_hmac_key_file")}
        if len(set(keys.values()))!=5:
            raise ValueError
        binding = InstructionFeatureTransition(baseline,_expected_state(manifest["baseline"],enabled=phase=="restore"),
            phase=phase,operation_nonce=nonces[phase+"_nonce"])
        config = load_secret_metadata_http_transport_config(environment)

        def fresh_state(config: SecretMetadataHttpTransportConfig, *, serial_digest: str) -> InstructionFeatureState:
            current = read_instruction_feature_setting(config,serial_digest=serial_digest)
            if current.field_count!=baseline.field_count:
                raise ValueError
            return current

        transport = FortiPamInstructionFeatureHttpTransport(config,baseline,binding,
            state_directory=state,cycle_nonce=nonces["cycle_nonce"],state_key=keys["state_hmac_key_file"],
            execution_enabled=execution,state_reader=fresh_state,
            connection_factory=http.client.HTTPSConnection)
        root_info = root.lstat()
        common = {"contract":CONTRACT,"digest":_digest({
            "manifest":{key:value for key,value in manifest.items() if key!="phase"},
            "root":str(root),"root_identity":[root_info.st_dev,root_info.st_ino],
            "transport_namespace":transport._namespace,
            "timeout_seconds":config.timeout_seconds,
            "keys":{name:hashlib.sha256(value).hexdigest() for name,value in keys.items()}})}
        with transport.operation_lock():
            existing = transport._exists(_MARKER)
            if existing:
                if transport._read(_MARKER)!=common:
                    raise ValueError
                if any(not paths[phase+"_execution_database_file"].exists() for phase in ("enable","restore")):
                    raise ValueError
            else:
                native_names = {name+suffix for name in ("enable","restore")
                                for suffix in (".claim.json",".ack.json",".result.json")} | {"enable.m4.json"}
                if (any(transport._exists(name) for name in native_names)
                        or any(os.path.lexists(member) for phase in ("enable","restore")
                               for member in _family(paths[phase+"_execution_database_file"]))):
                    raise ValueError
                transport._write_once(_MARKER,common)
            stores = {name:PersistentM4ExecutionStateStore(paths[name+"_execution_database_file"],
                        paths[name+"_execution_hmac_key_file"]) for name in ("enable","restore")}
            if phase=="restore":
                transport._original_enable()
                proof = transport._read("enable.m4.json")
                if proof["store"]!=InstructionFeatureLiveWorkflow._store_binding(stores["enable"]):
                    raise ValueError
        workflow = InstructionFeatureLiveWorkflow(transport,canonical_state_directory=state,
            execution_store=stores[phase],authority_key=keys[phase+"_authority_hmac_key_file"],
            original_enable_store=stores["enable"] if phase=="restore" else None,
            execution_enabled=execution,**identity)
        if phase=="restore":
            with transport.operation_lock():
                workflow._original_m4()
        return InstructionFeatureMcpAction(workflow,execution_enabled=execution)
    except Exception:
        raise ValueError(_ERROR) from None


__all__ = ["build_instruction_feature_candidate"]
