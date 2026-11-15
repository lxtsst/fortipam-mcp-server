"""Default-closed owner-only startup for fixed LDAP update and restore phases.

The native existing-entry update never composes a bind-password loader or a
material ledger. Startup validates private metadata without device I/O.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from typing import Any

from v4_planning.models import require_digest, require_ref

from .ldap_server_contract import LdapServerCreateBinding
from .ldap_server_http_transport import FortiPamLdapServerHttpTransport
from .ldap_server_projection import _members, _validate
from .ldap_server_runtime import _decode, _key, _path, _private_file, _read
from .ldap_server_update_http_transport import FortiPamLdapServerUpdateHttpTransport
from .ldap_server_update_live_workflow import LdapServerUpdateLiveWorkflow
from .ldap_server_update_mcp_action import LdapServerUpdateMcpAction
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space,
    _zeroize_mutable, load_secret_metadata_http_transport_config,
)

PREFIX = "FORTIPAM_MCP_V4_LDAP_SERVER_UPDATE_700_"
CONTRACT = "fortipam-v4-ldap-server-update-startup-v1"
_UNAVAILABLE = "FortiPAM LDAP server update startup is unavailable."
_PATH_KEYS = frozenset({"creation_state_directory", "state_directory",
    "execution_database_file", "execution_hmac_key_file", "authority_hmac_key_file"})
_SCHEMA = {
    "binding": frozenset({"name", "server", "dn", "ca_name", "username", "private_nonce", "ca_certificate_sha256"}),
    "identity": frozenset({"environment_ref", "scope_ref", "audience_ref", "allowed_requester_digest",
        "allowed_transport_digest", "expected_serial"}),
    "paths": _PATH_KEYS,
}
_COMMON_MARKER = "update-runtime.namespace.json"


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
    creation, state = paths["creation_state_directory"], paths["state_directory"]
    if (len(set(protected)) != len(protected)
            or state != creation.with_name(creation.name + ".ldap-update")
            or any(directory in item.parents for directory in (creation, state)
                   for item in protected if item != directory)):
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
    return hashlib.sha256(b"ldap-update-startup-pin-v1\x00" + json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def _phase_marker(phase: str) -> str:
    return f"update-runtime.{phase}.namespace.json"


def _phase_state(phase: str) -> tuple[str, ...]:
    return (f"{phase}.claim.json", f"{phase}-ack.json", f"{phase}-verified.json")


def _pin(transport: FortiPamLdapServerHttpTransport, marker: str, value: dict[str, object]) -> None:
    if not os.path.lexists(transport._directory / marker):
        try:
            transport._write_once(marker, value)
        except FileExistsError:
            pass
    if transport._read_state(marker) != value:
        raise ValueError


def _pin_namespace(transport: FortiPamLdapServerHttpTransport, manifest: dict[str, Any],
                   paths: dict[str, Path], keys: dict[str, bytes],
                   config: SecretMetadataHttpTransportConfig) -> None:
    phase = manifest["phase"]
    directory_identities = {}
    for name in ("creation_state_directory", "state_directory"):
        info = paths[name].lstat()
        directory_identities[name] = [str(paths[name]), info.st_dev, info.st_ino]
    common: dict[str, object] = {"contract": CONTRACT, "digest": _digest({
        "binding": manifest["binding"], "directories": directory_identities,
        "expected_serial": manifest["identity"]["expected_serial"],
        "api_base_url": config.base_url, "api_ca_file": config.ca_file,
        "api_identity_digest": hashlib.sha256(config.bearer_token.encode()).hexdigest(),
    })}
    all_state = ("update.plan.json", *_phase_state("update"), *_phase_state("restore"))
    if (not os.path.lexists(transport._directory / _COMMON_MARKER)
            and any(os.path.lexists(transport._directory / name) for name in all_state)):
        raise ValueError
    family = _database_family(paths["execution_database_file"])
    database_digests = sorted(_digest(str(path)) for path in family)
    key_digests = sorted(hashlib.sha256(key).hexdigest() for key in keys.values())
    key_path_digests = sorted(_digest(str(paths[name + "_hmac_key_file"])) for name in keys)
    marker = _phase_marker(phase)
    phase_pin = {"contract": CONTRACT, "phase": phase, "common_digest": common["digest"],
        "database_family_digests": database_digests, "key_digests": key_digests,
        "key_path_digests": key_path_digests,
        "digest": hmac.new(keys["authority"], b"ldap-update-phase-namespace-v1\x00" +
            json.dumps({"manifest": manifest, "keys": key_digests}, sort_keys=True,
                       separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()}
    other_marker = _phase_marker("restore" if phase == "update" else "update")
    if os.path.lexists(transport._directory / other_marker):
        other = transport._read_state(other_marker)
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
        phase_state = _phase_state(phase) + (("update.plan.json",) if phase == "update" else ())
        if (any(os.path.lexists(transport._directory / name) for name in phase_state)
                or any(os.path.lexists(path) for path in family)):
            raise ValueError
    elif not paths["execution_database_file"].exists():
        # M4 can consume a claim before the transport creates an HTTP marker.
        # A pinned phase must never recreate its missing ledger automatically.
        raise ValueError
    _pin(transport, _COMMON_MARKER, common)
    _pin(transport, marker, phase_pin)


def build_ldap_server_update_candidate(environment: Mapping[str, str]) -> LdapServerUpdateMcpAction | None:
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
        binding = LdapServerCreateBinding(**manifest["binding"])
        identity = manifest["identity"]
        for name in ("environment_ref", "scope_ref", "audience_ref"):
            require_ref(identity[name], name)
        for name in ("allowed_requester_digest", "allowed_transport_digest"):
            require_digest(identity[name], name)
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity["expected_serial"]) is None:
            raise ValueError
        keys = {name: _key(paths[name + "_hmac_key_file"]) for name in ("authority", "execution")}
        if len(set(keys.values())) != 2:
            raise ValueError
        config = load_secret_metadata_http_transport_config(environment)
        transport = FortiPamLdapServerHttpTransport(config, binding,
            expected_serial=identity["expected_serial"], state_directory=paths["state_directory"])
        operation = FortiPamLdapServerUpdateHttpTransport(config, binding,
            expected_serial=identity["expected_serial"],
            creation_state_directory=paths["creation_state_directory"],
            state_directory=paths["state_directory"], phase=manifest["phase"])
        with operation.operation_lock():
            _pin_namespace(transport, manifest, paths, keys, config)
            execution_store = PersistentM4ExecutionStateStore(
                paths["execution_database_file"], paths["execution_hmac_key_file"])
        workflow = LdapServerUpdateLiveWorkflow(binding, config,
            creation_state_directory=paths["creation_state_directory"],
            state_directory=paths["state_directory"], phase=manifest["phase"],
            execution_store=execution_store, authority_key=keys["authority"],
            execution_enabled=execution, **identity)
        return LdapServerUpdateMcpAction(workflow, execution_enabled=execution)
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


__all__ = ["build_ldap_server_update_candidate"]
