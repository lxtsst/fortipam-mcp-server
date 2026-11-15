"""Owner-only 8022 binding resolver for one fixed Secret-create workflow."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import NoReturn, SupportsIndex

import yaml  # type: ignore[import-untyped]

from v4_planning.material_provider import (
    C3MaterialBinding,
    MaterialAccessDenied,
    MaterialBindingStatus,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
)
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
)

from .secret_create_central_lab_provider import (
    MAX_SECRET_CREATE_LEASE_SECONDS,
    OwnerOnlyCentralLabSecretCreateEnvFileLoader,
)


_UNAVAILABLE = "The central lab Secret-create binding is unavailable."
_SCHEMA_VERSION = "credential-bindings-v1"
_MAX_BINDING_FILE_BYTES = 65_536
_SAFE_PRIVATE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,255}$")
_SAFE_BINDING_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_VARIABLE_ROLES = {
    "api_key",
    "identity_file",
    "known_hosts_file",
    "password",
    "session",
    "ssh_password",
    "ssh_username",
    "token",
    "username",
}


class OwnerOnlyCentralLabSecretCreateBindingResolver:
    """Pin one 8022 credential binding to one value-free lease request.

    Paths and identifiers are accepted only at trusted owner-side composition.
    The public methods neither list bindings nor return paths, identifiers, or
    environment-variable names.  The metadata file must remain byte-for-byte
    unchanged between startup resolution and material use.
    """

    __slots__ = (
        "_binding",
        "_binding_file_digest",
        "_binding_ref",
        "_credential_binding_id",
        "_credential_bindings_path",
        "_env_loader",
        "_request",
    )

    def __init__(
        self,
        *,
        credential_bindings_path: Path,
        secret_env_path: Path,
        binding_ref: str,
        credential_binding_id: str,
        request: MaterialLeaseRequest,
    ) -> None:
        try:
            binding_path = Path(credential_bindings_path)
            env_path = Path(secret_env_path)
            if (
                not binding_path.is_absolute()
                or not env_path.is_absolute()
                or not isinstance(binding_ref, str)
                or _SAFE_PRIVATE_REFERENCE.fullmatch(binding_ref) is None
                or not isinstance(credential_binding_id, str)
                or _SAFE_BINDING_ID.fullmatch(credential_binding_id) is None
                or not _valid_request(request)
            ):
                raise ValueError
            username_name, password_name, digest = _resolve_binding(
                binding_path,
                credential_binding_id,
            )
            env_loader = OwnerOnlyCentralLabSecretCreateEnvFileLoader(
                secret_env_path=env_path,
                username_variable_name=username_name,
                password_variable_name=password_name,
            )
        except Exception:
            raise MaterialAccessDenied(_UNAVAILABLE) from None
        self._credential_bindings_path = binding_path
        self._credential_binding_id = credential_binding_id
        self._binding_ref = binding_ref
        self._request = request
        self._binding_file_digest = digest
        self._env_loader = env_loader
        self._binding = C3MaterialBinding()

    def __repr__(self) -> str:
        return "<OwnerOnlyCentralLabSecretCreateBindingResolver redacted>"

    __str__ = __repr__

    def __copy__(self) -> NoReturn:
        raise MaterialAccessDenied(_UNAVAILABLE)

    def __deepcopy__(self, memo: object) -> NoReturn:
        del memo
        raise MaterialAccessDenied(_UNAVAILABLE)

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise MaterialAccessDenied(_UNAVAILABLE)

    def resolve(
        self,
        binding_ref: str,
        request: MaterialLeaseRequest,
    ) -> C3MaterialBinding:
        """Return only the pinned opaque binding for the exact private request."""

        if binding_ref != self._binding_ref or request != self._request:
            raise MaterialAccessDenied(_UNAVAILABLE)
        if not self._metadata_is_unchanged():
            raise MaterialAccessDenied(_UNAVAILABLE)
        return self._binding

    def validate_prebound(self) -> MaterialBindingStatus:
        """Validate pinned metadata and env material without exposing either."""

        if not self._metadata_is_unchanged():
            return MaterialBindingStatus.UNAVAILABLE
        return self._env_loader.validate_prebound()

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]:
        """Load the two pinned values only while binding metadata is unchanged."""

        if not self._metadata_is_unchanged():
            raise MaterialAccessDenied(_UNAVAILABLE)
        return self._env_loader.load_secret_create_material_once()

    def _metadata_is_unchanged(self) -> bool:
        try:
            _, _, digest = _resolve_binding(
                self._credential_bindings_path,
                self._credential_binding_id,
            )
        except Exception:
            return False
        return digest == self._binding_file_digest


def _valid_request(request: object) -> bool:
    return (
        isinstance(request, MaterialLeaseRequest)
        and request.action_id == SECRET_CREATE_ACTION_ID
        and request.action_version == SECRET_CREATE_ACTION_VERSION
        and request.provider_class
        is MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
        and request.purpose is MaterialPurpose.INITIAL_ONBOARDING
        and 0 < request.expires_at - request.requested_at
        <= MAX_SECRET_CREATE_LEASE_SECONDS
    )


def _resolve_binding(path: Path, selected_id: str) -> tuple[str, str, bytes]:
    content = _read_owner_only_file(path)
    try:
        digest = hashlib.sha256(content).digest()
        raw = yaml.safe_load(bytes(content))
    finally:
        content[:] = b"\x00" * len(content)
        content.clear()
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "bindings"}
        or raw.get("schema_version") != _SCHEMA_VERSION
        or not isinstance(raw.get("bindings"), list)
    ):
        raise MaterialAccessDenied(_UNAVAILABLE)
    selected: tuple[str, str] | None = None
    seen: set[str] = set()
    for item in raw["bindings"]:
        if not isinstance(item, dict) or set(item) != {"id", "provider", "variables"}:
            raise MaterialAccessDenied(_UNAVAILABLE)
        binding_id = item.get("id")
        variables = item.get("variables")
        if (
            not isinstance(binding_id, str)
            or _SAFE_BINDING_ID.fullmatch(binding_id) is None
            or binding_id in seen
            or item.get("provider") != "env-file"
            or not isinstance(variables, dict)
            or not variables
        ):
            raise MaterialAccessDenied(_UNAVAILABLE)
        seen.add(binding_id)
        if any(
            not isinstance(role, str)
            or role not in _VARIABLE_ROLES
            or not isinstance(env_name, str)
            or _ENV_NAME.fullmatch(env_name) is None
            for role, env_name in variables.items()
        ):
            raise MaterialAccessDenied(_UNAVAILABLE)
        if binding_id != selected_id:
            continue
        if set(variables) != {"username", "password"}:
            raise MaterialAccessDenied(_UNAVAILABLE)
        username = variables.get("username")
        password = variables.get("password")
        if (
            not isinstance(username, str)
            or _ENV_NAME.fullmatch(username) is None
            or not isinstance(password, str)
            or _ENV_NAME.fullmatch(password) is None
            or username == password
        ):
            raise MaterialAccessDenied(_UNAVAILABLE)
        selected = (username, password)
    if selected is None:
        raise MaterialAccessDenied(_UNAVAILABLE)
    return selected[0], selected[1], digest


def _read_owner_only_file(path: Path) -> bytearray:
    if not hasattr(os, "O_NOFOLLOW"):
        raise MaterialAccessDenied(_UNAVAILABLE)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = -1
    content = bytearray()
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not _valid_metadata(before):
            raise MaterialAccessDenied(_UNAVAILABLE)
        while len(content) <= _MAX_BINDING_FILE_BYTES:
            remaining = _MAX_BINDING_FILE_BYTES + 1 - len(content)
            chunk = os.read(descriptor, min(8192, remaining))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(content) != before.st_size
            or len(content) > _MAX_BINDING_FILE_BYTES
            or not _same_file(before, after)
        ):
            content[:] = b"\x00" * len(content)
            content.clear()
            raise MaterialAccessDenied(_UNAVAILABLE)
        return content
    except Exception:
        content[:] = b"\x00" * len(content)
        content.clear()
        raise MaterialAccessDenied(_UNAVAILABLE) from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _valid_metadata(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= _MAX_BINDING_FILE_BYTES
    )


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        _valid_metadata(after)
        and before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
    )


__all__ = ["OwnerOnlyCentralLabSecretCreateBindingResolver"]
