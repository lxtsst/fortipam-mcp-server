"""Private build29 SCIM native codec and nonmaterial lifecycle comparisons.

The eight-field SDK always forwards a secret and overwrites three security
fields. This module supplies no material resolver, permission, I/O or runtime
registration. Configuration equality cannot prove credential equality, service
isolation, provisioning effects or an independent recovery path.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
from typing import Literal
from urllib.parse import urlsplit

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_material, _valid_material_view
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = 'fortipam-build29-scim-native-lifecycle-local/v1'
NATIVE_NAME = 'fortipam-scim-server'
NONMATERIAL_FIELDS = frozenset({'id', 'name', 'status', 'base-url', 'auth-method',
    'client-identity-check', 'certificate', 'token-certificate'})
_CONTEXT_FIELDS = frozenset({'serial_digest', 'schema_digest', 'global_digest',
    'interfaces_digest', 'saml_digest', 'trust_digest'})
_ERROR = 'The private SCIM lifecycle contract is unavailable.'
Operation = Literal['create', 'rotate', 'disable']


class ScimClientContractError(RuntimeError):
    """Fixed refusal without source values, selectors, bindings or material."""


def _bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def _values(values: Mapping[str, object]) -> dict[str, str | int]:
    if not isinstance(values, Mapping) or set(values) != NONMATERIAL_FIELDS: raise ValueError
    selected: dict[str, str | int] = {}
    for name, value in values.items():
        if name == 'id':
            if type(value) is not int or not 0 <= value <= 4294967295: raise ValueError
        else:
            limit = {'name': 35, 'base-url': 127, 'certificate': 79, 'token-certificate': 79}.get(name, 16)
            if (type(value) is not str or len(value.encode('utf-8')) > limit
                    or any(ord(c) < 32 or ord(c) == 127 for c in value)): raise ValueError
        if not isinstance(value, (str, int)): raise ValueError
        selected[name] = value
    if (selected['status'] not in ('enable', 'disable') or selected['auth-method'] != 'base'
            or selected['client-identity-check'] not in ('enable', 'disable')): raise ValueError
    url = selected['base-url']
    if url:
        if type(url) is not str: raise ValueError
        parsed = urlsplit(url)
        # The native editor separates the shared port; this codec never changes it.
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.port is not None or parsed.query or parsed.fragment
                or not parsed.path.endswith('/scim/v2') or any(c.isspace() for c in url) or '\\' in url): raise ValueError
    return selected


@dataclass(frozen=True, slots=True, repr=False)
class ScimNonmaterialState(_OpaqueC3Object):
    """Eight complete nonmaterial fields; deliberately no credential witness."""
    _encoded: bytes

    @classmethod
    def from_values(cls, values: Mapping[str, object]) -> ScimNonmaterialState:
        try: return cls(_bytes(_values(values)))
        except Exception: raise ScimClientContractError(_ERROR) from None

    def _values(self) -> dict[str, str | int]:
        value = _values(json.loads(self._encoded))
        if _bytes(value) != self._encoded: raise ValueError
        return value


def _context(value: Mapping[str, str]) -> bytes:
    if not isinstance(value, Mapping) or set(value) != _CONTEXT_FIELDS: raise ValueError
    for digest in value.values(): require_digest(digest, 'SCIM source context')
    return _bytes(dict(value))


def _native_profile(state: ScimNonmaterialState) -> dict[str, str | int]:
    if type(state) is not ScimNonmaterialState: raise ValueError
    current = state._values()
    if (current['name'] != NATIVE_NAME or not current['base-url'] or current['status'] != 'enable'
            or current['client-identity-check'] != 'disable' or current['certificate'] != ''): raise ValueError
    return current


@dataclass(frozen=True, slots=True, repr=False)
class ScimClientTransition(_OpaqueC3Object):
    """Local candidate intent; material bindings are provider references, not passwords.

    The private compiler checks the selected binding digest. A future protected
    provider must verify and resolve it under M4; this object cannot do either.
    """
    operation: Operation
    _original: ScimNonmaterialState
    _proposed: ScimNonmaterialState
    _context: bytes
    _old_material_binding_digest: str | None
    _new_material_binding_digest: str

    def __post_init__(self) -> None:
        try:
            if (self.operation not in ('create', 'rotate', 'disable')
                    or type(self._original) is not ScimNonmaterialState
                    or type(self._proposed) is not ScimNonmaterialState
                    or type(self._context) is not bytes
                    or _context(json.loads(self._context)) != self._context): raise ValueError
            require_digest(self._new_material_binding_digest, 'SCIM material binding')
            original, proposed = self._original._values(), self._proposed._values()
            if self.operation == 'create':
                if (self._old_material_binding_digest is not None or original['id'] != 0 or original['name'] != ''
                        or original['base-url'] != '' or original['status'] != 'disable'
                        or original['client-identity-check'] != 'enable' or original['certificate'] != ''
                        or not proposed['base-url'] or proposed != {**original, 'name': NATIVE_NAME,
                            'base-url': proposed['base-url'], 'status': 'enable', 'client-identity-check': 'disable'}): raise ValueError
            else:
                original = _native_profile(self._original)
                if type(self._old_material_binding_digest) is not str: raise ValueError
                require_digest(self._old_material_binding_digest, 'SCIM material binding')
                equal = self._old_material_binding_digest == self._new_material_binding_digest
                if self.operation == 'rotate':
                    if equal or proposed != original: raise ValueError
                elif not equal or proposed != {**original, 'status': 'disable'}: raise ValueError
        except Exception: raise ScimClientContractError(_ERROR) from None

    @property
    def parameters_digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT, operation=self.operation,
            original=hashlib.sha256(self._original._encoded).hexdigest(),
            proposed=hashlib.sha256(self._proposed._encoded).hexdigest(),
            context=hashlib.sha256(self._context).hexdigest(), old_material_binding=self._old_material_binding_digest,
            new_material_binding=self._new_material_binding_digest))

    def preview(self) -> dict[str, object]:
        original, proposed = self._original._values(), self._proposed._values()
        changed = sorted(key for key in NONMATERIAL_FIELDS if
            original[key] != proposed[key])
        return {'contract': CONTRACT, 'operation': self.operation,
            'Current State': {'record_present': self.operation != 'create', 'credential_value_observed': False,
                'client_identity_check_enabled': original['client-identity-check'] == 'enable'},
            'Proposed Changes': {'nonmaterial_field_names': changed,
                'credential_binding_changes': self.operation in ('create', 'rotate'),
                'native_client_identity_check_disabled': True},
            'Expected State': {'nonmaterial_field_count': 8, 'omitted_token_certificate_preserved': True,
                'client_identity_check_enabled': False, 'independent_credential_verification_required': True},
            'shared_global_interface_saml_writes_included': False,
            'creation_id_assignment_qualified': False, 'native_backend_qualified': False,
            'independent_recovery_qualified': False, 'configuration_write_authorized': False}

    def _fresh(self, current: ScimNonmaterialState | None, context: Mapping[str, str], *, restore: bool) -> None:
        if _context(context) != self._context: raise ValueError
        expected = self._proposed if restore else self._original
        if self.operation == 'create' and not restore:
            if current is not None: raise ValueError
        elif type(current) is not ScimNonmaterialState or current._values() != expected._values(): raise ValueError

    def verify_nonmaterial_applied(self, current: ScimNonmaterialState, context: Mapping[str, str]) -> None:
        """Compare configuration only; native ID allocation and credentials stay unqualified."""
        try: self._fresh(current, context, restore=True)
        except Exception: raise ScimClientContractError(_ERROR) from None

    def verify_nonmaterial_restored(self, current: ScimNonmaterialState, context: Mapping[str, str]) -> None:
        try:
            if self.operation == 'create': raise ValueError
            self._fresh(current, context, restore=False)
        except Exception: raise ScimClientContractError(_ERROR) from None


def prepare_scim_create(defaults: ScimNonmaterialState, *, base_url: str,
        material_binding_digest: str, context: Mapping[str, str]) -> ScimClientTransition:
    try:
        if type(defaults) is not ScimNonmaterialState: raise ValueError
        original = defaults._values()
        proposed = ScimNonmaterialState.from_values({**original, 'name': NATIVE_NAME, 'base-url': base_url,
            'status': 'enable', 'client-identity-check': 'disable', 'certificate': ''})
        return ScimClientTransition('create', defaults, proposed, _context(context), None, material_binding_digest)
    except Exception: raise ScimClientContractError(_ERROR) from None


def prepare_scim_rotate(current: ScimNonmaterialState, *, current_material_binding_digest: str,
        replacement_material_binding_digest: str, context: Mapping[str, str]) -> ScimClientTransition:
    try:
        return ScimClientTransition('rotate', current, current, _context(context),
            current_material_binding_digest, replacement_material_binding_digest)
    except Exception: raise ScimClientContractError(_ERROR) from None


def prepare_scim_disable(current: ScimNonmaterialState, *, current_material_binding_digest: str,
        context: Mapping[str, str]) -> ScimClientTransition:
    try:
        if type(current) is not ScimNonmaterialState: raise ValueError
        original = current._values()
        proposed = ScimNonmaterialState.from_values({**original, 'status': 'disable'})
        return ScimClientTransition('disable', current, proposed, _context(context),
            current_material_binding_digest, current_material_binding_digest)
    except Exception: raise ScimClientContractError(_ERROR) from None


def build_scim_request_with_material(transition: ScimClientTransition, material: memoryview, *,
        current: ScimNonmaterialState | None, context: Mapping[str, str], material_binding_digest: str,
        restore: bool = False) -> bytearray:
    """Private codec only, not material resolution/authorization. Caller clears the returned body.

    No material is decoded into a Python string, stored in the draft or hashed
    into a plan. The local UTF-8 material limit is59 octets; native Unicode
    length semantics and encrypted/masked credential readback are not qualified.
    """
    with _MutableJSONBuffer() as body:
        try:
            if (type(transition) is not ScimClientTransition or type(restore) is not bool
                    or type(material) is not memoryview or material.format != 'B' or not material.c_contiguous
                    or not _valid_material_view(material) or material.nbytes > 59
                    or restore and transition.operation == 'create'): raise ValueError
            transition._fresh(current, context, restore=restore)
            expected_binding = transition._old_material_binding_digest if restore else transition._new_material_binding_digest
            if (type(material_binding_digest) is not str or type(expected_binding) is not str
                    or not hmac.compare_digest(expected_binding, material_binding_digest)): raise ValueError
            state = transition._original if restore else transition._proposed
            fields = state._values()
            del fields['token-certificate']
            fields.update({'name': NATIVE_NAME, 'auth-method': 'base', 'client-identity-check': 'disable', 'certificate': ''})
            body.extend(_bytes(fields)[:-1]); body.extend(b',"secret":')
            _append_material(body, material); body.extend(b'}')
            return body.finish()
        except Exception:
            raise ScimClientContractError(_ERROR) from None
