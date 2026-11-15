"""Default-off startup for one fresh pair/disabled-User lifecycle.

The owner supplies protected metadata and sixteen existing HMAC key files. No
startup path loads RADIUS material, dispatches product HTTP or renews old inputs.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from .ldap_server_runtime import _read, _path, _key, _private_file
from .ldap_server_projection import _members, _validate, _digest
from .m4_execution_store import PersistentM4ExecutionStateStore
from .radius_server_pair_contract import RadiusServerPairBinding
from .radius_remote_user_contract import RadiusRemoteUserBinding
from .radius_remote_user_lifecycle_workflow import RadiusRemoteUserLifecycleWorkflow
from .radius_remote_user_lifecycle_mcp_action import RadiusRemoteUserLifecycleMcpAction
from . import radius_server_pair_lifecycle_runtime as pair_runtime
from .secret_metadata_http_transport import _skip_json_space, _json_value_end, _zeroize_mutable
from v4_planning.models import require_ref

PREFIX = "FORTIPAM_MCP_V4_RADIUS_USER_LIFECYCLE_700_"
CONTRACT = "fortipam-v4-radius-user-lifecycle-startup-v1"
_ERROR = "FortiPAM RADIUS User lifecycle startup is unavailable."
_ROLES = ("user_create", "user_remove")
_KEYS = tuple(role + "_execution_key_file" for role in _ROLES) + tuple(
    role + "_authority_key_file" for role in (*_ROLES, "parent"))
_SCHEMA = {
    "binding": {"username", "private_nonce"},
    "identity": {"user_create_scope_ref", "user_remove_scope_ref"},
    "paths": {"user_state_directory", *(role + "_database_file" for role in _ROLES), *_KEYS},
}


def _flag(environment: Mapping[str, str], name: str) -> bool:
    value = environment.get(PREFIX + name, "false")
    if type(value) is not str or value not in {"true", "false"}: raise ValueError
    return value == "true"


def _manifest(path: Path) -> dict[str, Any]:
    raw = _read(path, 32768)
    try:
        start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw): raise ValueError
        _validate(raw, (start, end)); fields = _members(raw, (start, end))
        if set(fields) != {"contract", "pair_manifest_file", *_SCHEMA}: raise ValueError
        if any(raw[fields[k][0]] != 34 for k in ("contract", "pair_manifest_file")): raise ValueError
        for section, allowed in _SCHEMA.items():
            values = _members(raw, fields[section])
            if set(values) != allowed or any(raw[a] != 34 for a, _ in values.values()): raise ValueError
        result: dict[str, Any] = json.loads(raw)
        if result["contract"] != CONTRACT: raise ValueError
        return result
    finally:
        _zeroize_mutable(raw)


def _profile(manifest_path: Path) -> tuple[dict[str, Any], dict[str, Path], dict[str, Any], dict[str, Path], dict[str, bytes], dict[str, bytes], str]:
    """Validate the shared original graph without constructing any source client."""
    manifest = _manifest(manifest_path)
    pair_path = _path(manifest["pair_manifest_file"])
    pair_manifest = pair_runtime._manifest(pair_path)
    pair_paths = pair_runtime._paths(pair_manifest, pair_path)
    paths = {name: _path(value, directory=name == "user_state_directory")
        for name, value in manifest["paths"].items()}
    protected = {manifest_path, pair_path, *paths.values(), *pair_paths.values()}
    if len(protected) != len(paths) + len(pair_paths) + 2: raise ValueError
    directories = (paths["user_state_directory"], pair_paths["state_directory"])
    if any(d in p.parents for d in directories for p in protected if p != d): raise ValueError
    keys = {name: _key(paths[name]) for name in _KEYS}
    pair_keys = {name: _key(pair_paths[name]) for name in pair_runtime._KEY_NAMES}
    if len(set((*keys.values(), *pair_keys.values()))) != 16: raise ValueError
    scopes = [manifest["identity"][role + "_scope_ref"] for role in _ROLES]
    for scope in scopes: require_ref(scope, "user_scope_ref")
    if len(set(scopes + [pair_manifest["identity"][role + "_scope_ref"] for role in pair_runtime._ROLES[:4]])) != 6:
        raise ValueError
    radius = RadiusServerPairBinding(**pair_manifest["binding"])
    RadiusRemoteUserBinding(radius=radius, **manifest["binding"])
    databases = [paths[role + "_database_file"] for role in _ROLES] + [pair_paths[role + "_database_file"] for role in pair_runtime._ROLES]
    reserved: set[Path] = set()
    for database in databases:
        family = {Path(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")}
        if family & reserved or (family - {database}) & protected: raise ValueError
        for path in family:
            if path.exists() or path.is_symlink(): _private_file(path)
        reserved.update(family)
    pinned = (pair_paths["state_directory"] / "runtime.namespace.json").exists()
    if pinned and any(not path.exists() for path in databases): raise ValueError
    context = _digest({"contract": CONTRACT, "manifest": manifest,
        "keys": {name: hashlib.sha256(value).hexdigest() for name, value in keys.items()}})
    return manifest, paths, pair_manifest, pair_paths, keys, pair_keys, context


def build_radius_remote_user_lifecycle_candidate(environment: Mapping[str, str]) -> RadiusRemoteUserLifecycleMcpAction | None:
    pair_action = None
    try:
        environment = dict(environment)
        enabled, execute = _flag(environment, "ENABLED"), _flag(environment, "EXECUTION_ENABLED")
        if not enabled:
            if execute: raise ValueError
            return None
        if any(name.startswith(PREFIX) and name.removeprefix(PREFIX) not in {
                "ENABLED", "EXECUTION_ENABLED", "STARTUP_MANIFEST_FILE"} for name in environment):
            raise ValueError
        if any(environment.get(pair_runtime.PREFIX + name, "false") != "false"
                for name in ("ENABLED", "EXECUTION_ENABLED", "RETAIN_ON_SUCCESS")):
            raise ValueError
        manifest_path = _path(environment[PREFIX + "STARTUP_MANIFEST_FILE"])
        manifest, paths, pair_manifest, pair_paths, keys, _, context = _profile(manifest_path)
        if any(paths["user_state_directory"].iterdir()): raise ValueError
        scopes = [manifest["identity"][role + "_scope_ref"] for role in _ROLES]
        pair_path = _path(manifest["pair_manifest_file"])
        nested = dict(environment)
        nested.update({pair_runtime.PREFIX + "ENABLED": "true", pair_runtime.PREFIX + "EXECUTION_ENABLED": str(execute).lower(),
            pair_runtime.PREFIX + "RETAIN_ON_SUCCESS": "true", pair_runtime.PREFIX + "STARTUP_MANIFEST_FILE": str(pair_path)})
        pair_action = pair_runtime.build_radius_server_pair_lifecycle_candidate(nested, _profile_context_digest=context)
        if pair_action is None: raise ValueError
        stores = {role: PersistentM4ExecutionStateStore(paths[role + "_database_file"], paths[role + "_execution_key_file"])
            for role in _ROLES}
        binding = RadiusRemoteUserBinding(radius=pair_action._workflow._create._binding, **manifest["binding"])
        workflow = RadiusRemoteUserLifecycleWorkflow(pair_action._workflow, binding,
            user_state_directory=paths["user_state_directory"], user_create_store=stores["user_create"],
            user_remove_store=stores["user_remove"], user_create_authority_key=keys["user_create_authority_key_file"],
            user_remove_authority_key=keys["user_remove_authority_key_file"], authority_key=keys["parent_authority_key_file"],
            user_create_scope_ref=scopes[0], user_remove_scope_ref=scopes[1], execution_enabled=execute)
        return RadiusRemoteUserLifecycleMcpAction(workflow, execution_enabled=execute)
    except Exception:
        if pair_action is not None: pair_action.close()
        raise ValueError(_ERROR) from None
