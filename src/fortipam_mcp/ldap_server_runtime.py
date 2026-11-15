"""Default-closed owner-only composition for one fixed LDAP lab candidate.

The manifest contains private metadata and references only. Bind credentials
are resolved by the existing central inventory loader at material-use time.
Startup opens no device connection and does not extract bind material.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus
from v4_planning.models import require_digest, require_ref

from .mutable_json_buffer import _take_mutable_prefix
from .ldap_server_contract import LdapServerCreateBinding
from .ldap_server_http_transport import FortiPamLdapServerHttpTransport
from .ldap_server_live_workflow import LdapServerLiveWorkflow
from .ldap_server_mcp_action import LdapServerMcpAction
from .ldap_server_projection import _members, _validate
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_central_lab_binding import _resolve_binding
from .secret_create_central_lab_provider import OwnerOnlyCentralLabSecretCreateEnvFileLoader
from .secret_metadata_http_transport import (
    _json_value_end, _skip_json_space, _zeroize_mutable,
    load_secret_metadata_http_transport_config,
)

PREFIX = "FORTIPAM_MCP_V4_LDAP_SERVER_700_"
CONTRACT = "fortipam-v4-ldap-server-startup-v1"
_UNAVAILABLE = "FortiPAM LDAP server startup is unavailable."
_PATH_KEYS = frozenset({"state_directory", "execution_database_file", "material_database_file",
    "execution_hmac_key_file", "material_hmac_key_file", "authority_hmac_key_file",
    "credential_bindings_file", "secret_env_file"})
_SCHEMA = {
    "binding": frozenset({"name", "server", "dn", "ca_name", "username", "private_nonce", "ca_certificate_sha256"}),
    "identity": frozenset({"environment_ref", "scope_ref", "audience_ref", "allowed_requester_digest",
        "allowed_transport_digest", "expected_serial"}),
    "paths": _PATH_KEYS,
    "material": frozenset({"credential_binding_id"}),
}


class _CentralLdapLoader(C3MaterialBinding):
    """Pin central binding metadata without copying its credential source."""

    __slots__ = ("_binding_path", "_env_path", "_selected_id", "_snapshot", "_loader")

    def __init__(self, binding_path: Path, env_path: Path, selected_id: str) -> None:
        self._binding_path, self._env_path, self._selected_id = binding_path, env_path, selected_id
        self._snapshot = _resolve_binding(binding_path, selected_id)
        username, password, _ = self._snapshot
        self._loader = OwnerOnlyCentralLabSecretCreateEnvFileLoader(secret_env_path=env_path,
            username_variable_name=username, password_variable_name=password)

    def _unchanged(self) -> None:
        _path(str(self._binding_path), central=True)
        _path(str(self._env_path), central=True)
        if _resolve_binding(self._binding_path, self._selected_id) != self._snapshot:
            raise MaterialAccessDenied(_UNAVAILABLE)

    def validate_prebound(self) -> MaterialBindingStatus:
        try:
            self._unchanged()
            return self._loader.validate_prebound()
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]:
        try:
            self._unchanged()
            return self._loader.load_secret_create_material_once()
        except Exception:
            raise MaterialAccessDenied(_UNAVAILABLE) from None


def _flag(environment: Mapping[str, str], suffix: str) -> bool:
    value = environment.get(PREFIX + suffix, "false")
    if type(value) is not str or value not in {"true", "false"}:
        raise ValueError
    return value == "true"


def _private_directory(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(_UNAVAILABLE)
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError(_UNAVAILABLE)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError(_UNAVAILABLE)


def _private_file(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
    ):
        raise ValueError(_UNAVAILABLE)


def _read(path: Path, limit: int) -> bytearray:
    parent = descriptor = None
    raw = bytearray(limit + 1)
    try:
        try:
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError
            parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
            for part in path.parent.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                previous, parent = parent, child
                os.close(previous)
            info = os.fstat(parent)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 0 < before.st_size <= limit):
                raise ValueError
            count = os.readv(descriptor, [raw])
            after = os.fstat(descriptor)
            if (count != before.st_size or os.read(descriptor, 1)
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError
            raw = _take_mutable_prefix(raw, count)
        finally:
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                if parent is not None:
                    os.close(parent)
    except BaseException as error:
        _zeroize_mutable(raw)
        if isinstance(error, Exception):
            raise ValueError(_UNAVAILABLE) from None
        raise
    return raw


def _path(value: object, *, directory: bool = False, central: bool = False) -> Path:
    if type(value) is not str or not 0 < len(value) <= 4096:
        raise ValueError
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError
    if directory:
        _private_directory(path)
    else:
        if central:
            # Central metadata may live in a shared readable directory; its
            # owner-only file and every path component still must be genuine.
            if any(item.is_symlink() for item in (path, *path.parents)):
                raise ValueError
        else:
            _private_directory(path.parent)
        if central or path.exists() or path.is_symlink():
            _private_file(path)
    return path


def _decode(raw: bytes) -> dict[str, Any]:
    """Decode only after the manifest's fixed string-only schema is checked."""
    value = json.loads(raw)
    if type(value) is not dict:
        raise ValueError
    return value


def _manifest(path: Path) -> dict[str, Any]:
    raw = _read(path, 32768)
    try:
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        _validate(raw, (start, end))
        fields = _members(raw, (start, end))
        if set(fields) != set(_SCHEMA) | {"contract"}:
            raise ValueError
        for name, (left, right) in fields.items():
            if name == "contract":
                if raw[left] != 34:
                    raise ValueError
                continue
            children = _members(raw, (left, right))
            if set(children) != _SCHEMA[name] or any(raw[a] != 34 for a, _ in children.values()):
                raise ValueError
        result = _decode(bytes(raw))
        if result["contract"] != CONTRACT:
            raise ValueError
        return result
    finally:
        _zeroize_mutable(raw)


def _key(path: Path) -> bytes:
    raw = _read(path, 32)
    try:
        if len(raw) != 32:
            raise ValueError
        return bytes(raw)
    finally:
        _zeroize_mutable(raw)


def _paths(manifest: dict[str, Any], manifest_path: Path) -> dict[str, Path]:
    paths = {name: _path(value, directory=name == "state_directory",
                        central=name in {"credential_bindings_file", "secret_env_file"})
             for name, value in manifest["paths"].items()}
    protected = [manifest_path, *paths.values()]
    state = paths["state_directory"]
    if len(set(protected)) != len(protected) or any(state in item.parents for item in protected if item != state):
        raise ValueError
    # Reserve all names used by both SQLite stores, including their sidecars.
    reserved: set[Path] = set()
    for name in ("execution_database_file", "material_database_file"):
        database = paths[name]
        family = {Path(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")}
        if family & reserved or (family - {database}) & set(protected):
            raise ValueError
        for member in family:
            if member.exists() or member.is_symlink():
                _private_file(member)
        reserved.update(family)
    return paths


def _pin_namespace(transport: FortiPamLdapServerHttpTransport, content: dict[str, Any], key: bytes) -> None:
    namespace = {"contract": CONTRACT, "digest": hmac.new(key,
        b"ldap-runtime-namespace-v1\x00" + json.dumps(content, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()}
    marker = "runtime.namespace.json"
    if not (transport._directory / marker).exists():
        if any((transport._directory / name).exists() for name in (
                "create.claim.json", "create-ack.json", "created.json", "delete.claim.json", "deleted.json")):
            raise ValueError
        try:
            transport._write_once(marker, namespace)
        except FileExistsError:
            pass
    if transport._read_state(marker) != namespace:
        raise ValueError


def build_ldap_server_candidate(environment: Mapping[str, str]) -> LdapServerMcpAction | None:
    """Compose the fixed private lab boundary; default returns before file I/O."""
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
        keys = {name: _key(paths[name + "_hmac_key_file"]) for name in ("authority", "execution", "material")}
        if len(set(keys.values())) != 3:
            raise ValueError
        loader = _CentralLdapLoader(paths["credential_bindings_file"], paths["secret_env_file"],
            manifest["material"]["credential_binding_id"])
        config = load_secret_metadata_http_transport_config(environment)
        preview_transport = FortiPamLdapServerHttpTransport(config, binding,
            expected_serial=identity["expected_serial"], state_directory=paths["state_directory"])
        _pin_namespace(preview_transport, {"manifest": manifest,
            "keys": {name: hashlib.sha256(value).hexdigest() for name, value in keys.items()},
            "source_binding_digest": loader._snapshot[2].hex(),
            "api_base_url": config.base_url, "api_ca_file": config.ca_file,
            "api_identity_digest": hashlib.sha256(config.bearer_token.encode()).hexdigest()}, keys["authority"])
        execution_store = PersistentM4ExecutionStateStore(paths["execution_database_file"], paths["execution_hmac_key_file"])
        material_store = PersistentMaterialUseStateStore(paths["material_database_file"], paths["material_hmac_key_file"])
        workflow = LdapServerLiveWorkflow(binding, config, loader=loader,
            state_directory=paths["state_directory"], execution_store=execution_store, material_store=material_store,
            authority_key=keys["authority"], execution_enabled=execution, **identity)
        return LdapServerMcpAction(workflow, execution_enabled=execution)
    except Exception:
        raise ValueError(_UNAVAILABLE) from None
