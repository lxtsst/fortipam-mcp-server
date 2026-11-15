"""Default-off normal startup; defer private signers until authorized execute."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import jwt_manual_key_owner_runtime as definition
from .jwt_manual_key_contract import JwtManualPublicKey, _digest, _require_digest
from .jwt_manual_key_owner_http import JwtManualKeyOwnerHttp,JwtManualKeyOwnerHttpConfig
from .jwt_manual_rotation_contract import JwtManualRotationBinding,JwtManualRotationKeys,USER_FIELDS
from .jwt_rotation_authentication import JwtRotationAuthenticationProbe
from .jwt_rotation_mcp_action import JwtRotationMcpAction
from .jwt_rotation_owner_source import JwtRotationOriginalCreation,JwtRotationOwnerSource,PHASES
from .jwt_rotation_workflow import JwtRotationWorkflow,JwtRotationPhaseSpec
from .ldap_server_runtime import _key,_path,_read,_private_file
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_collector_runtime import owner_login_provider,PREFIX as OWNER_PREFIX
from .secret_approval_build29_http_transport import _validate_ack_json
from .secret_metadata_http_transport import _json_value_end,_skip_json_space,_zeroize_mutable
from .secret_request_approval_revoke_detail_contract import _reject_raw_duplicates

PREFIX = "FORTIPAM_MCP_V4_JWT_ROTATION_700_"
CONTRACT = "fortipam-build29-jwt-rotation-startup-v5"
DIAGNOSTIC_CONTRACT = "fortipam-build29-manual-jwt-update-discriminator-startup-v3"
_ERROR = "FortiPAM manual JWT rotation startup is unavailable."
_FIELDS = {"contract","original_manifest_file","user_metadata_file","user_name","private_nonce",
    "old_public_file","new_public_file","new_public_digest","old_signer_file","new_signer_file"}


def _flag(environment: Mapping[str,str], suffix: str) -> bool:
    value = environment.get(PREFIX+suffix,"false")
    if type(value) is not str or value not in {"true","false"}:
        raise ValueError
    return value == "true"


def _document(path: Path) -> tuple[dict[str,Any],str]:
    raw = _read(path,65536)
    try:
        start = _skip_json_space(raw,0); end = _json_value_end(raw,start)
        if _skip_json_space(raw,end) != len(raw):
            raise ValueError
        _validate_ack_json(raw,start,end); _reject_raw_duplicates(raw,start,end)
        value = json.loads(raw)
        if type(value) is not dict:
            raise ValueError
        return value,hashlib.sha256(raw).hexdigest()
    finally:
        _zeroize_mutable(raw)


def _signer(path: Path) -> rsa.RSAPrivateKey:
    raw = _read(path,16384)
    try:
        signer = serialization.load_pem_private_key(bytes(raw),password=None)
        if not isinstance(signer,rsa.RSAPrivateKey):
            raise ValueError
        return signer
    finally:
        _zeroize_mutable(raw)


def build_jwt_rotation_candidate(environment: Mapping[str,str]) -> JwtRotationMcpAction | None:
    try:
        environment = dict(environment)
        enabled,execute = _flag(environment,"ENABLED"),_flag(environment,"EXECUTION_ENABLED")
        if not enabled:
            if execute:
                raise ValueError
            return None
        if any(k.startswith(PREFIX) and k.removeprefix(PREFIX) not in {"ENABLED","EXECUTION_ENABLED","STARTUP_MANIFEST_FILE"} for k in environment):
            raise ValueError
        if any(environment.get(definition.PREFIX+s,"false") != "false" for s in ("ENABLED","EXECUTION_ENABLED")):
            raise ValueError
        path = _path(environment[PREFIX+"STARTUP_MANIFEST_FILE"])
        manifest,fingerprint = _document(path)
        if set(manifest) != _FIELDS or manifest["contract"] not in {CONTRACT,DIAGNOSTIC_CONTRACT}:
            raise ValueError
        _require_digest(manifest["new_public_digest"])
        paths = {field:_path(manifest[field]) for field in _FIELDS if field.endswith("_file")}
        if len(set(paths.values())|{path}) != len(paths)+1:
            raise ValueError
        original,original_fingerprint = definition._manifest(paths["original_manifest_file"])
        if original["phase"] != "create" or original["public_key_file"] != str(paths["old_public_file"]):
            raise ValueError
        config = JwtManualKeyOwnerHttpConfig(**original["wire"])
        metadata,metadata_fingerprint = _document(paths["user_metadata_file"])
        if (set(metadata) != {"schema","defaults","serial_digest","schema_projection_sha256","defaults_projection_sha256"}
                or set(metadata["schema"]) != USER_FIELDS or set(metadata["defaults"]) != USER_FIELDS
                or metadata["serial_digest"] != original["binding"]["serial_digest"]
                or _digest(metadata["schema"]) != metadata["schema_projection_sha256"]
                or _digest(metadata["defaults"]) != metadata["defaults_projection_sha256"]):
            raise ValueError
        binding = JwtManualRotationBinding(original["binding"]["name"],manifest["user_name"],manifest["private_nonce"],
            serial_digest=original["binding"]["serial_digest"])
        for name in ("old_signer_file","new_signer_file","old_public_file","new_public_file"):
            _private_file(paths[name])
        credentials = owner_login_provider(environment)
        if credentials is None:
            raise ValueError
        reference = {k:v for k,v in environment.items() if k.startswith(OWNER_PREFIX)}
        if hashlib.sha256(json.dumps(reference,sort_keys=True,separators=(",",":")).encode()).hexdigest() != config.credential_reference_digest:
            raise ValueError
        root,original_root = path.parent,paths["original_manifest_file"].parent
        native = _path(str(root/"native"),directory=True); parent = _path(str(root/"parent"),directory=True)
        original_native = _path(str(original_root/"native"),directory=True)
        creator_directory = _path(str(original_root/"create-authority"),directory=True)
        witness = _path(str(root/"rotation.witness.key")); parent_key = _path(str(parent/"authority.key"))
        directories = {phase:_path(str(root/("phase-"+phase)),directory=True) for phase in PHASES}
        if any(native.iterdir()) or {p.name for p in parent.iterdir()} != {"authority.key"} or any(
                {p.name for p in directory.iterdir()} != {"authority.key","execution.key"} for directory in directories.values()):
            raise ValueError
        key_paths = [witness,parent_key,*(_path(str(directory/(role+".key")))for directory in directories.values() for role in ("authority","execution"))]
        old_key_paths = [_path(str(original_root/(name+".key")))for name in definition._KEYS]
        if len({_key(p)for p in (*key_paths,*old_key_paths)}) != 19:
            raise ValueError
        ca_fingerprint = hashlib.sha256(Path(config.ca_file).read_bytes()).hexdigest()

        def guard() -> bool:
            try:
                return (_document(path)[1] == fingerprint and definition._manifest(paths["original_manifest_file"])[1] == original_fingerprint
                    and _document(paths["user_metadata_file"])[1] == metadata_fingerprint
                    and hashlib.sha256(Path(config.ca_file).read_bytes()).hexdigest() == ca_fingerprint)
            except Exception:
                return False

        def factory() -> JwtRotationWorkflow:
            owner = None
            try:
                if not guard():
                    raise ValueError
                public = [JwtManualPublicKey(_read_public(paths[name])) for name in ("old_public_file","new_public_file")]
                keys = JwtManualRotationKeys(*public)
                if keys._old.digest != original["binding"]["public_key_digest"] or keys._new.digest != manifest["new_public_digest"]:
                    raise ValueError
                def protected_guard() -> bool:
                    return guard() and all(hashlib.sha256(_read_public(paths[name])).hexdigest() == expected.digest for name,expected in
                        (("old_public_file",keys._old),("new_public_file",keys._new)))
                owner = JwtManualKeyOwnerHttp.from_original_creation(config,credentials,directory=original_native,
                    witness_key_file=original_root/"witness.key",source_guard=protected_guard,execution_enabled=execute)
                store = PersistentM4ExecutionStateStore(original_root/"create.sqlite3",original_root/"create.execution.key",read_only=True)
                custody = JwtRotationOriginalCreation(owner,store,creator_directory,original_root/"create.authority.key",**original["identity"])
                scoped = JwtRotationOwnerSource(custody,binding,keys,directory=native,witness_key_file=witness,
                    user_schema_digest=metadata["schema_projection_sha256"],user_defaults_digest=metadata["defaults_projection_sha256"],execution_enabled=execute)
                specs = {phase:JwtRotationPhaseSpec(PersistentM4ExecutionStateStore(directory/"execution.sqlite3",directory/"execution.key"),
                    directory,directory/"authority.key",original["identity"]["scope_ref"]+"-"+phase) for phase,directory in directories.items()}
                def probe() -> JwtRotationAuthenticationProbe:
                    if not execute or not protected_guard():
                        raise ValueError
                    return JwtRotationAuthenticationProbe(config,binding,keys,_signer(paths["old_signer_file"]),_signer(paths["new_signer_file"]),
                        probe_enabled=True,source_guard=scoped.probe_ready,
                        fresh_assertion_clients=True,runtime_sampling=True)
                owner.__enter__()
                return JwtRotationWorkflow(scoped,probe,specs,directory=parent,authority_key_file=parent_key,
                    environment_ref=original["identity"]["environment_ref"],audience_ref=original["identity"]["audience_ref"],execution_enabled=execute,
                    activation_diagnostic=manifest["contract"] == DIAGNOSTIC_CONTRACT)
            except BaseException:
                if owner is not None:
                    owner.close()
                raise
        return JwtRotationMcpAction(factory,requester_digest=config.requester_digest,transport_digest=config.transport_digest,execution_enabled=execute)
    except Exception:
        raise ValueError(_ERROR) from None


def _read_public(path: Path) -> bytes:
    raw = _read(path,2047)
    try:
        return bytes(raw)
    finally:
        _zeroize_mutable(raw)
