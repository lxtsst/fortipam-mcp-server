"""Default-closed owner startup for independently authorized APL Role phases.

Startup validates sealed original creation records and metadata-only manifests
without a device request. Each phase pins distinct keys and an M4 ledger.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, cast

from v4_planning.models import require_digest, require_ref

from .apl_role_update_contract import AplRoleUpdateBinding
from .ldap_server_projection import _members, _validate
from .ldap_server_runtime import _decode, _key, _path, _private_file, _read
from .apl_role_update_http_transport import FortiPamAplRoleUpdateHttpTransport, Phase
from .apl_role_update_live_workflow import AplRoleUpdateLiveWorkflow
from .apl_role_update_mcp_action import AplRoleUpdateMcpAction
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import (
    _json_value_end, _skip_json_space,
    _zeroize_mutable, load_secret_metadata_http_transport_config,
)

PREFIX = "FORTIPAM_MCP_V4_APL_ROLE_UPDATE_700_"
CONTRACT = "fortipam-v4-apl-role-update-startup-v1"
_UNAVAILABLE = "FortiPAM APL role update startup is unavailable."
_PATH_KEYS = frozenset({"state_directory",
    "execution_database_file", "execution_hmac_key_file", "authority_hmac_key_file"})
_SCHEMA = {
    "binding": frozenset({"rule_name", "group_name", "original_role", "updated_role", "nonce"}),
    "identity": frozenset({"environment_ref", "scope_ref", "audience_ref", "allowed_requester_digest",
        "allowed_transport_digest", "serial_digest", "schema_digest"}),
    "paths": _PATH_KEYS,
}
_COMMON_MARKER = "role-runtime.namespace.json"


def _flag(environment: Mapping[str, str], suffix: str) -> bool:
    value = environment.get(PREFIX + suffix, "false")
    if type(value) is not str or value not in {"true", "false"}:
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
        if set(fields) != set(_SCHEMA) | {"contract", "phase"}:
            raise ValueError
        for name, (left, right) in fields.items():
            if name in {"contract", "phase"}:
                if raw[left] != 34:
                    raise ValueError
                continue
            children = _members(raw, (left, right))
            if set(children) != _SCHEMA[name] or any(raw[a] != 34 for a, _ in children.values()):
                raise ValueError
        result = _decode(bytes(raw))
        if result["contract"] != CONTRACT or result["phase"] not in {"update", "restore"}:
            raise ValueError
        return result
    finally:
        _zeroize_mutable(raw)


def _database_family(database: Path) -> set[Path]:
    return {Path(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")}


def _paths(manifest: dict[str, Any], manifest_path: Path) -> dict[str, Path]:
    paths = {name: _path(value, directory=name.endswith("state_directory"))
             for name, value in manifest["paths"].items()}
    protected = [manifest_path, *paths.values()]
    state = paths["state_directory"]
    if (len(set(protected)) != len(protected)
            or any(state in item.parents for item in protected if item != state)):
        raise ValueError
    database = paths["execution_database_file"]
    family = _database_family(database)
    if (family - {database}) & set(protected):
        raise ValueError
    for member in family:
        if os.path.lexists(member):
            _private_file(member)
    return paths


def _digest(value: object) -> str:
    return hashlib.sha256(b"apl-role-update-startup-pin-v1\x00" + json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def _phase_marker(phase: str) -> str:
    return f"role-runtime.{phase}.namespace.json"


def _phase_state(phase: str) -> tuple[str, ...]:
    return (f"{phase}.claim.json", f"{phase}-ack.json", f"{phase}-verified.json")


def _pin(transport: FortiPamAplRoleUpdateHttpTransport, marker: str, value: dict[str, object]) -> None:
    if not os.path.lexists(transport._directory / marker):
        try:
            transport._write_once(marker, value)
        except FileExistsError:
            pass
    if transport._read(marker) != value:
        raise ValueError


def _pin_namespace(transport: FortiPamAplRoleUpdateHttpTransport, manifest: dict[str, Any],
                   paths: dict[str, Path], keys: dict[str, bytes]) -> None:
    phase = manifest["phase"]
    plan = transport._plan()
    anchors = transport._anchors(plan)
    if any(os.path.lexists(transport._directory / name) for name in ("delete.claim.json", "delete-ack.json", "delete-verified.json")):
        raise ValueError
    common: dict[str, object] = {"contract": CONTRACT, "digest": _digest({
        "transport_namespace": transport._namespace, "state_plan_digest": _digest(plan),
        "creation_anchors": anchors,
    })}
    all_state = (*_phase_state("update"), *_phase_state("restore"),
                 _phase_marker("update"), _phase_marker("restore"))
    if (not os.path.lexists(transport._directory / _COMMON_MARKER)
            and any(os.path.lexists(transport._directory / name) for name in all_state)):
        raise ValueError
    for stored_phase in ("update", "restore"):
        if (any(os.path.lexists(transport._directory / name) for name in _phase_state(stored_phase))
                and not os.path.lexists(transport._directory / _phase_marker(stored_phase))):
            raise ValueError
    family = _database_family(paths["execution_database_file"])
    database_digests = sorted(_digest(str(path)) for path in family)
    key_digests = sorted(hashlib.sha256(key).hexdigest() for key in keys.values())
    key_path_digests = sorted(_digest(str(paths[name + "_hmac_key_file"])) for name in keys)
    marker = _phase_marker(phase)
    phase_pin = {"contract": CONTRACT, "phase": phase, "common_digest": common["digest"],
        "database_family_digests": database_digests, "key_digests": key_digests,
        "key_path_digests": key_path_digests,
        "digest": hmac.new(keys["authority"], b"apl-role-update-phase-namespace-v1\x00" +
            json.dumps({"manifest": manifest, "keys": key_digests}, sort_keys=True,
                       separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()}
    other_marker = _phase_marker("restore" if phase == "update" else "update")
    if os.path.lexists(transport._directory / other_marker):
        other = transport._read(other_marker)
        if (set(other) != set(phase_pin) or other["contract"] != CONTRACT
                or other["phase"] != ("restore" if phase == "update" else "update")
                or other["common_digest"] != common["digest"]):
            raise ValueError
        validated: dict[str, set[str]] = {}
        for name, count in (("database_family_digests", 4), ("key_digests", 2), ("key_path_digests", 2)):
            values = other[name]
            if (type(values) is not list or len(values) != count
                    or any(type(value) is not str for value in values)):
                raise ValueError
            for value in values:
                require_digest(value, name)
            if len(set(values)) != count:
                raise ValueError
            validated[name] = set(values)
        other_digest = other["digest"]
        if type(other_digest) is not str:
            raise ValueError
        require_digest(other_digest, "phase namespace digest")
        if (set(database_digests).intersection(validated["database_family_digests"])
                or set(key_digests).intersection(validated["key_digests"])
                or set(key_path_digests).intersection(validated["key_path_digests"])):
            raise ValueError
    if not os.path.lexists(transport._directory / marker):
        phase_state = _phase_state(phase)
        if (any(os.path.lexists(transport._directory / name) for name in phase_state)
                or any(os.path.lexists(path) for path in family)):
            raise ValueError
    elif not paths["execution_database_file"].exists():
        # M4 can consume a claim before the transport creates an HTTP marker.
        # A pinned phase must never recreate its missing ledger automatically.
        raise ValueError
    _pin(transport, _COMMON_MARKER, common)
    _pin(transport, marker, phase_pin)


def build_apl_role_update_candidate(environment: Mapping[str, str]) -> AplRoleUpdateMcpAction | None:
    """Compose one fixed phase; disabled startup returns before any file I/O."""
    try:
        enabled, execution = _flag(environment, "ENABLED"), _flag(environment, "EXECUTION_ENABLED")
        if not enabled:
            if execution:
                raise ValueError
            return None
        manifest_path = _path(environment[PREFIX + "STARTUP_MANIFEST_FILE"])
        manifest = _manifest(manifest_path)
        paths = _paths(manifest, manifest_path)
        binding = AplRoleUpdateBinding(**manifest["binding"])
        identity = manifest["identity"]
        for name in ("environment_ref", "scope_ref", "audience_ref"):
            require_ref(identity[name], name)
        for name in ("allowed_requester_digest", "allowed_transport_digest", "serial_digest", "schema_digest"):
            require_digest(identity[name], name)
        keys = {name: _key(paths[name + "_hmac_key_file"]) for name in ("authority", "execution")}
        if len(set(keys.values())) != 2:
            raise ValueError
        config = load_secret_metadata_http_transport_config(environment)
        transport = FortiPamAplRoleUpdateHttpTransport(config, binding,
            serial_digest=identity["serial_digest"], schema_digest=identity["schema_digest"],
            state_directory=paths["state_directory"], phase=cast(Phase, manifest["phase"]))
        with transport.operation_lock():
            _pin_namespace(transport, manifest, paths, keys)
            execution_store = PersistentM4ExecutionStateStore(
                paths["execution_database_file"], paths["execution_hmac_key_file"])
        workflow = AplRoleUpdateLiveWorkflow(binding, config,
            state_directory=paths["state_directory"], phase=manifest["phase"],
            execution_store=execution_store, authority_key=keys["authority"],
            execution_enabled=execution, **identity)
        return AplRoleUpdateMcpAction(workflow, execution_enabled=execution)
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


__all__ = ["build_apl_role_update_candidate"]
