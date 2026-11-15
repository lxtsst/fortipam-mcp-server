"""Owner-side single-secret SCIM resolver; never bound by normal startup.

Trusted composition supplies one central credential-bindings-v1 entry and its
env file. Only the native base-auth password role is supported. The reference
digest covers metadata, not material, and proves neither credential identity
nor authentication. The lease provider still owns action/authorization checks.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from threading import RLock

import yaml  # type: ignore[import-untyped]

from v4_planning import canonical_digest
from v4_planning.material_provider import MaterialAccessDenied, MaterialBindingStatus, _OpaqueC3Object

from .secret_create_191_http_transport import _valid_material_view
from .secret_create_central_lab_binding import (_ENV_NAME, _SAFE_BINDING_ID, _VARIABLE_ROLES,
    _read_owner_only_file)
from .secret_create_central_lab_provider import (_ascii_identifier, _dotenv_value_range,
    _is_valid_utf8, _read_owner_only_secret_env_file)
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = 'The private SCIM material source is unavailable.'


def _selected_variable(path: Path, selected_id: str) -> tuple[bytes, str]:
    content = _read_owner_only_file(path)
    try:
        # This registry contains variable references only; env values never
        # enter the YAML decoder or a metadata fingerprint.
        digest = hashlib.sha256(content).hexdigest()
        raw = yaml.safe_load(bytes(content))
    finally: _zeroize_mutable(content)
    if (type(raw) is not dict or set(raw) != {'schema_version', 'bindings'}
            or raw['schema_version'] != 'credential-bindings-v1' or type(raw['bindings']) is not list): raise ValueError
    seen: set[str] = set()
    selected: bytes | None = None
    for item in raw['bindings']:
        if type(item) is not dict or set(item) != {'id', 'provider', 'variables'}: raise ValueError
        name, variables = item['id'], item['variables']
        if (type(name) is not str or _SAFE_BINDING_ID.fullmatch(name) is None or name in seen
                or item['provider'] != 'env-file' or type(variables) is not dict or not variables): raise ValueError
        seen.add(name)
        if any(type(role) is not str or role not in _VARIABLE_ROLES or type(value) is not str
                or _ENV_NAME.fullmatch(value) is None for role, value in variables.items()): raise ValueError
        if name == selected_id:
            if set(variables) != {'password'}: raise ValueError
            selected = variables['password'].encode('ascii')
    if selected is None: raise ValueError
    return selected, digest


class ScimCentralLabMaterialResolver(_OpaqueC3Object):
    """One prebound central password variable, one material loading attempt.

    Availability checks read/clear protected bytes without extracting material.
    They are not acquisitions or proofs of old/new credential consistency.
    Metadata changes refuse the existing object. Reconstructing a resolver does
    not clear the separate durable M4/material consumption records.
    """
    def __init__(self, *, credential_bindings_path: Path, secret_env_path: Path,
            credential_binding_id: str) -> None:
        try:
            registry, env = Path(credential_bindings_path), Path(secret_env_path)
            if (not registry.is_absolute() or not env.is_absolute() or registry.resolve() == env.resolve()
                    or type(credential_binding_id) is not str
                    or _SAFE_BINDING_ID.fullmatch(credential_binding_id) is None): raise ValueError
            variable, digest = _selected_variable(registry, credential_binding_id)
            self._registry, self._env, self._selected = registry, env, credential_binding_id
            self._variable, self._registry_digest = variable, digest
            # Registry aliases for the same env variable produce the same
            # reference; changing an entry label cannot invent a rotation.
            self._binding_digest = canonical_digest(dict(contract='scim-central-base-secret-reference/v1',
                registry=str(registry.resolve()), metadata=digest, env=str(env.resolve()), variable=variable.decode('ascii')))
            self._attempted = self._closed = False
            self._lock = RLock()
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    @property
    def binding_digest(self) -> str:
        return self._binding_digest

    def _metadata(self) -> None:
        if self._closed or _selected_variable(self._registry, self._selected) != (self._variable, self._registry_digest):
            raise ValueError

    def _read(self, *, extract: bool) -> bytearray | None:
        content = _read_owner_only_secret_env_file(self._env)
        try:
            if not _is_valid_utf8(content) or 0 in content or 13 in content: raise ValueError
            seen: set[bytes] = set()
            selected: tuple[int, int] | None = None
            start = 0
            while start < len(content):
                end = content.find(b'\n', start)
                if end < 0: end = len(content)
                if end == start or content[start] == 35:
                    start = end+1
                    continue
                equals = content.find(b'=', start, end)
                if equals <= start: raise ValueError
                name = bytes(content[start:equals])
                if not _ascii_identifier(name) or name in seen: raise ValueError
                seen.add(name)
                if name == self._variable:
                    left, right = _dotenv_value_range(content, equals+1, end)
                    if not 1 <= right-left <= 59: raise ValueError
                    with memoryview(content)[left:right] as view:
                        if not _valid_material_view(view): raise ValueError
                    selected = left, right
                start = end+1
            if selected is None: raise ValueError
            self._metadata()
            if extract:
                with memoryview(content)[selected[0]:selected[1]] as view: return bytearray(view)
            return None
        finally: _zeroize_mutable(content)

    def validate_prebound(self) -> MaterialBindingStatus:
        with self._lock:
            try:
                self._metadata(); self._read(extract=False)
                return MaterialBindingStatus.AVAILABLE
            except Exception: return MaterialBindingStatus.UNAVAILABLE

    def load_scim_material_once(self) -> bytearray:
        with self._lock:
            try:
                if self._attempted: raise ValueError
                self._attempted = True
                self._metadata()
                material = self._read(extract=True)
                if type(material) is not bytearray: raise ValueError
                return material
            except Exception: raise MaterialAccessDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock: self._closed = True
