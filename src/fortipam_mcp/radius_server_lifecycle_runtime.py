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
from .radius_fixture_material_loader import RadiusFixtureMaterialLoader
from .radius_server_contract import RadiusServerCreateBinding
from .radius_server_http_transport import FortiPamRadiusServerHttpTransport, _MARKERS
from .radius_server_live_workflow import RadiusServerLiveWorkflow
from .radius_server_owned_connect_workflow import RadiusServerOwnedConnectWorkflow
from .radius_server_recovery_workflow import RadiusServerRecoveryWorkflow
from .radius_server_lifecycle_workflow import RadiusServerLifecycleWorkflow
from .radius_server_lifecycle_mcp_action import RadiusServerLifecycleMcpAction
from .secret_metadata_http_transport import (
    _skip_json_space, _json_value_end, _zeroize_mutable, load_secret_metadata_http_transport_config,
)

PREFIX = "FORTIPAM_MCP_V4_RADIUS_PRIMARY_LIFECYCLE_700_"
CONTRACT = "fortipam-v4-radius-primary-lifecycle-startup-v1"
_ERROR = "FortiPAM RADIUS lifecycle startup is unavailable."
_ROLES = ("create", "native", "recovery", "material")
_KEY_NAMES = tuple(role + "_execution_key_file" for role in _ROLES[:3]) + ("material_key_file",) + tuple(
    role + "_authority_key_file" for role in (*_ROLES[:3], "parent"))
_PATH_NAMES = frozenset({"state_directory", "ssh_identity_file", "ssh_known_hosts_file",
    *(role + "_database_file" for role in _ROLES), *_KEY_NAMES})
_SCHEMA = {
    "binding": frozenset({"name", "server", "private_nonce"}),
    "identity": frozenset({"environment_ref", "create_scope_ref", "native_scope_ref", "recovery_scope_ref",
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


def _pin(transport: FortiPamRadiusServerHttpTransport, manifest: dict[str, Any],
         keys: dict[str, bytes], *, retain_on_success: bool = False) -> None:
    config = transport._config
    content = {"manifest": manifest, "keys": {name: hashlib.sha256(value).hexdigest()
        for name, value in keys.items()}, "api_base_url": config.base_url, "api_ca_file": config.ca_file,
        "api_identity_digest": hashlib.sha256(config.bearer_token.encode()).hexdigest()}
    if retain_on_success:
        content["completion_mode"] = "retain_verified_primary"
    value = {"contract": CONTRACT, "digest": hmac.new(keys["parent_authority_key_file"],
        b"radius-lifecycle-runtime-namespace-v1\x00" + json.dumps(content, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()}
    marker = "runtime.namespace.json"
    if not transport._exists(marker):
        if any(transport._exists(name) for name in _MARKERS):
            raise ValueError
        try:
            transport._write_once(marker, value)
        except FileExistsError:
            pass
    if transport._read_state(marker) != value:
        raise ValueError


def build_radius_server_lifecycle_candidate(environment: Mapping[str, str]) -> RadiusServerLifecycleMcpAction | None:
    """Build the fixed profile; disabled configuration returns before any file I/O."""
    source: RadiusFixtureMaterialLoader | None = None
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
        binding = RadiusServerCreateBinding(**manifest["binding"])
        identity = dict(manifest["identity"])
        for name in ("environment_ref", "audience_ref", "create_scope_ref", "native_scope_ref", "recovery_scope_ref"):
            require_ref(identity[name], name)
        if len({identity[role + "_scope_ref"] for role in _ROLES[:3]}) != 3:
            raise ValueError
        for name in ("allowed_requester_digest", "allowed_transport_digest"):
            require_digest(identity[name], name)
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity["expected_serial"]) is None:
            raise ValueError
        keys = {name: _key(paths[name]) for name in _KEY_NAMES}
        if len(set(keys.values())) != len(keys):
            raise ValueError
        holder: list[RadiusServerLiveWorkflow] = []
        source = RadiusFixtureMaterialLoader(binding, host=manifest["source"]["host"],
            identity_file=paths["ssh_identity_file"], known_hosts_file=paths["ssh_known_hosts_file"],
            source_policy_digest=manifest["source"]["source_policy_digest"], acquisition_enabled=execute,
            execution_guard=lambda b, r: holder[0]._guard_material_source(b, r))
        config = load_secret_metadata_http_transport_config(environment)
        preview = FortiPamRadiusServerHttpTransport(config, binding,
            expected_serial=identity["expected_serial"], state_directory=paths["state_directory"])
        _pin(preview, manifest, keys, retain_on_success=retain)
        stores = {role: PersistentM4ExecutionStateStore(paths[role + "_database_file"],
            paths[role + "_execution_key_file"]) for role in _ROLES[:3]}
        material = PersistentMaterialUseStateStore(paths["material_database_file"], paths["material_key_file"])
        scopes = {role: identity.pop(role + "_scope_ref") for role in _ROLES[:3]}
        common = {**identity, "state_directory": paths["state_directory"], "execution_enabled": execute}
        create = RadiusServerLiveWorkflow(binding, config, loader=source,
            execution_store=stores["create"], material_store=material, scope_ref=scopes["create"],
            authority_key=keys["create_authority_key_file"], **common)
        children.append(create)
        holder.append(create)
        native = RadiusServerOwnedConnectWorkflow(binding, config, execution_store=stores["native"],
            scope_ref=scopes["native"], authority_key=keys["native_authority_key_file"], **common)
        children.append(native)
        recovery = RadiusServerRecoveryWorkflow(binding, config, execution_store=stores["recovery"],
            scope_ref=scopes["recovery"], authority_key=keys["recovery_authority_key_file"], **common)
        children.append(recovery)
        parent = RadiusServerLifecycleWorkflow(create, native, recovery, source,
            authority_key=keys["parent_authority_key_file"], execution_enabled=execute,
            retain_on_success=retain)
        return RadiusServerLifecycleMcpAction(parent, execution_enabled=execute, persistent_primary=retain)
    except Exception:
        try:
            if source is not None:
                source.close()
            for child in children:
                child.close()
        finally:
            raise ValueError(_ERROR) from None
