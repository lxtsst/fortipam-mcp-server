"""Default-off owner-only composition for one fixed RADIUS lifecycle candidate.

Startup reads only protected metadata/keys and opens durable local stores. The
existing fixed SSH worker may acquire material only in the original create M4.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any

from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.models import require_digest, require_ref

from .ldap_server_runtime import _read, _path, _key, _private_file
from .ldap_server_projection import _members, _validate
from .m4_execution_store import PersistentM4ExecutionStateStore
from .radius_fixture_material_loader import _file_identity
from .radius_server_pair_contract import RadiusServerPairBinding
from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport, _MARKERS
from .radius_server_pair_live_workflow import RadiusServerPairLiveWorkflow
from .radius_server_pair_owned_connect_workflow import RadiusServerPairOwnedConnectWorkflow
from .radius_server_pair_recovery_workflow import RadiusServerPairRecoveryWorkflow
from .radius_server_pair_lifecycle_workflow import RadiusServerPairLifecycleWorkflow
from .radius_server_pair_lifecycle_mcp_action import RadiusServerPairLifecycleMcpAction
from .secret_metadata_http_transport import (
    _skip_json_space, _json_value_end, _zeroize_mutable, load_secret_metadata_http_transport_config,
)

PREFIX = "FORTIPAM_MCP_V4_RADIUS_PAIR_LIFECYCLE_700_"
CONTRACT = "fortipam-v4-radius-pair-lifecycle-startup-v1"
_ERROR = "FortiPAM paired RADIUS lifecycle startup is unavailable."
_ROLES = ("create", "native_primary", "native_secondary", "recovery", "material", "source_group")
_KEY_NAMES = tuple(role + "_execution_key_file" for role in _ROLES[:4]) + ("material_key_file", "source_group_key_file") + tuple(
    role + "_authority_key_file" for role in (*_ROLES[:4], "parent"))
_PATH_NAMES = frozenset({"state_directory", "ssh_identity_file", "ssh_known_hosts_file",
    *(role + "_database_file" for role in _ROLES), *_KEY_NAMES})
_SCHEMA = {
    "binding": frozenset({"name", "server", "secondary_server", "private_nonce"}),
    "identity": frozenset({"environment_ref", "create_scope_ref", "native_primary_scope_ref", "native_secondary_scope_ref", "recovery_scope_ref",
        "audience_ref", "allowed_requester_digest", "allowed_transport_digest", "expected_serial"}),
    "source": frozenset({"host", "source_policy_digest"}),
    "paths": _PATH_NAMES,
}


def _flag(environment: Mapping[str, str], name: str) -> bool:
    value = environment.get(PREFIX + name, "false")
    if type(value) is not str or value not in {"false", "true"}:
        raise ValueError
    return value == "true"


def _manifest(path: Path) -> dict[str, Any]:
    raw = _read(path, 32768)
    try:
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        _validate(raw, (start, end))
        fields = _members(raw, (start, end))
        if set(fields) != {"contract", *_SCHEMA} or raw[fields["contract"][0]] != 34:
            raise ValueError
        for name in _SCHEMA:
            children = _members(raw, fields[name])
            if set(children) != _SCHEMA[name] or any(raw[a] != 34 for a, _ in children.values()):
                raise ValueError
        result: dict[str, Any] = json.loads(raw)
        if result["contract"] != CONTRACT:
            raise ValueError
        return result
    finally:
        _zeroize_mutable(raw)


def _paths(manifest: dict[str, Any], manifest_path: Path) -> dict[str, Path]:
    paths = {name: _path(value, directory=name == "state_directory")
             for name, value in manifest["paths"].items()}
    protected = {manifest_path, *paths.values()}
    state = paths["state_directory"]
    if len(protected) != len(paths) + 1 or any(state in item.parents for item in protected if item != state):
        raise ValueError
    reserved: set[Path] = set()
    for role in _ROLES:
        database = paths[role + "_database_file"]
        family = {Path(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")}
        if family & reserved or (family - {database}) & protected:
            raise ValueError
        for path in family:
            if path.exists() or path.is_symlink():
                _private_file(path)
        reserved.update(family)
    return paths


def _pin(transport: FortiPamRadiusPairHttpTransport, manifest: dict[str, Any],
         keys: dict[str, bytes], profile_context_digest: str | None = None, *, existing_only: bool = False) -> None:
    config = transport._config
    content = {"manifest": manifest, "keys": {name: hashlib.sha256(value).hexdigest()
        for name, value in keys.items()}, "api_base_url": config.base_url, "api_ca_file": config.ca_file,
        "api_identity_digest": hashlib.sha256(config.bearer_token.encode()).hexdigest()}
    if profile_context_digest is not None:
        require_digest(profile_context_digest, "profile_context_digest")
        content["associated_profile_digest"] = profile_context_digest
    content["source_file_identities"] = {name: [str(v) for v in _file_identity(Path(manifest["paths"][name]))]
        for name in ("ssh_identity_file", "ssh_known_hosts_file")}
    value = {"contract": CONTRACT, "digest": hmac.new(keys["parent_authority_key_file"],
        b"radius-pair-lifecycle-runtime-namespace-v1\x00" + json.dumps(content, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()}
    marker = "runtime.namespace.json"
    if not transport._exists(marker):
        if existing_only: raise ValueError
        if any(transport._exists(name) for name in _MARKERS):
            raise ValueError
        try:
            transport._write_once(marker, value)
        except FileExistsError:
            pass
    if transport._read_state(marker) != value:
        raise ValueError


def build_radius_server_pair_lifecycle_candidate(environment: Mapping[str, str], *,
        _profile_context_digest: str | None = None) -> RadiusServerPairLifecycleMcpAction | None:
    """Build the fixed profile; disabled configuration returns before any file I/O."""
    children: list[Any] = []
    try:
        enabled, execute = _flag(environment, "ENABLED"), _flag(environment, "EXECUTION_ENABLED")
        retain = _flag(environment, "RETAIN_ON_SUCCESS")
        if not enabled:
            if execute or retain:
                raise ValueError
            return None
        manifest_path = _path(environment[PREFIX + "STARTUP_MANIFEST_FILE"])
        manifest = _manifest(manifest_path)
        paths = _paths(manifest, manifest_path)
        binding = RadiusServerPairBinding(**manifest["binding"])
        identity = dict(manifest["identity"])
        for name in ("environment_ref", "audience_ref", "create_scope_ref", "native_primary_scope_ref", "native_secondary_scope_ref", "recovery_scope_ref"):
            require_ref(identity[name], name)
        if len({identity[role + "_scope_ref"] for role in _ROLES[:4]}) != 4:
            raise ValueError
        for name in ("allowed_requester_digest", "allowed_transport_digest"):
            require_digest(identity[name], name)
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity["expected_serial"]) is None:
            raise ValueError
        keys = {name: _key(paths[name]) for name in _KEY_NAMES}
        if len(set(keys.values())) != len(keys):
            raise ValueError
        require_digest(manifest["source"]["source_policy_digest"], "source_policy_digest")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", manifest["source"]["host"]) is None:
            raise ValueError
        for name in ("ssh_identity_file", "ssh_known_hosts_file"):
            _file_identity(paths[name])
        config = load_secret_metadata_http_transport_config(environment)
        preview = FortiPamRadiusPairHttpTransport(config, binding,
            expected_serial=identity["expected_serial"], state_directory=paths["state_directory"])
        if preview._exists("runtime.namespace.json") and any(not paths[role + "_database_file"].exists() for role in _ROLES):
            raise ValueError
        _pin(preview, manifest, keys, _profile_context_digest)
        stores = {role: PersistentM4ExecutionStateStore(paths[role + "_database_file"],
            paths[role + "_execution_key_file"]) for role in _ROLES[:4]}
        material = PersistentMaterialUseStateStore(paths["material_database_file"], paths["material_key_file"])
        group = PersistentMaterialUseStateStore(paths["source_group_database_file"], paths["source_group_key_file"])
        scopes = {role: identity.pop(role + "_scope_ref") for role in _ROLES[:4]}
        common = {**identity, "state_directory": paths["state_directory"], "execution_enabled": execute}
        create = RadiusServerPairLiveWorkflow(binding, config,
            source_host=manifest["source"]["host"], source_identity_file=paths["ssh_identity_file"],
            source_known_hosts_file=paths["ssh_known_hosts_file"], source_policy_digest=manifest["source"]["source_policy_digest"],
            source_reservation_store=group, execution_store=stores["create"], material_store=material,
            scope_ref=scopes["create"], authority_key=keys["create_authority_key_file"], **common)
        children.append(create)
        native = []
        for ordinal in ("primary", "secondary"):
            role = "native_" + ordinal
            child = RadiusServerPairOwnedConnectWorkflow(binding, config, ordinal=ordinal,
                execution_store=stores[role], scope_ref=scopes[role], authority_key=keys[role + "_authority_key_file"], **common)
            children.append(child)
            native.append(child)
        recovery = RadiusServerPairRecoveryWorkflow(binding, config, execution_store=stores["recovery"],
            scope_ref=scopes["recovery"], authority_key=keys["recovery_authority_key_file"], **common)
        children.append(recovery)
        parent = RadiusServerPairLifecycleWorkflow(create, native[0], native[1], recovery,
            authority_key=keys["parent_authority_key_file"], execution_enabled=execute, retain_on_success=retain)
        return RadiusServerPairLifecycleMcpAction(parent, execution_enabled=execute, persistent_pair=retain)
    except Exception:
        try:
            for child in children:
                child.close()
        finally:
            raise ValueError(_ERROR) from None
