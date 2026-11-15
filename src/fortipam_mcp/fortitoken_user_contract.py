"""Private build29 existing-User FortiToken codec; no execution or enrollment.

The native User model omits password on update and derives authentication type
only while MFA is enabled. Token selectors stay in byte views, outside decoded
state and its digest. This codec cannot prove unassigned ownership, permission,
notification isolation, recovery or the server's complete revoke postcondition.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any, Literal

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as metadata
from .local_user_reset_fixture_create import _FIELDS
from .mutable_json_buffer import _clear_mutable_group
from .local_user_reset_projection import _object_spans, _sanitize_object, _schema_fields, _string_or_empty
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_material, _quoted_material
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

CONTRACT = 'fortipam-build29-fortitoken-existing-user-codec-local/v1'
_NAME = re.compile(r'mcp-v4-user-ftk-[a-f0-9]{8}\Z')
_ERROR = 'The private FortiToken User codec is unavailable.'
Operation = Literal['assign','revoke']


class FortitokenUserContractError(RuntimeError):
    """Fixed refusal, without token, user, source or material values."""


def _encoded(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _schema_types(fields: Mapping[str,Any], depth: int = 0) -> dict[str,Any]:
    if depth > 16 or len(fields) > 512: raise ValueError
    result = {}
    for name,descriptor in fields.items():
        if type(name) is not str or not isinstance(descriptor,Mapping): raise ValueError
        kind = descriptor.get('type')
        if kind is not None and (type(kind) is not str or len(kind)>64): raise ValueError
        children = descriptor.get('children')
        if children is not None and not isinstance(children,Mapping): raise ValueError
        result[name] = {'type':kind, 'children':_schema_types(children,depth+1) if children is not None else None}
    return result


@dataclass(frozen=True, slots=True, repr=False)
class FortitokenUserBinding(_OpaqueC3Object):
    username: str
    user_id: int
    token_reference_digest: str
    private_nonce: str

    def __post_init__(self) -> None:
        if (type(self.username) is not str or _NAME.fullmatch(self.username) is None
                or type(self.user_id) is not int or not 1 <= self.user_id <= 2147483647): raise ValueError(_ERROR)
        for value in (self.token_reference_digest,self.private_nonce): require_digest(value,'FortiToken binding')

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,username=self.username,user_id=self.user_id,
            token_reference=self.token_reference_digest,nonce=self.private_nonce))


@dataclass(frozen=True, slots=True, repr=False)
class FortitokenUserState(_OpaqueC3Object):
    binding: FortitokenUserBinding
    schema_digest: str
    serial_digest: str
    _encoded: bytes
    token_present: bool

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,binding=self.binding.digest,schema=self.schema_digest,
            serial=self.serial_digest,record=hashlib.sha256(self._encoded).hexdigest(),token_present=self.token_present))


def project_fortitoken_user(content: bytearray, schema: object, binding: FortitokenUserBinding, *,
        expected_serial: str, matched_token: memoryview | None = None) -> FortitokenUserState:
    """Consume a full private User read; never decode/hash its token selector.

When supplied for revoke encoding, matched_token is compared to the source's
canonical JSON token before either input is decoded. It remains caller-owned.
No projection claims complete references, role entitlement or token ownership.
    """
    sanitized = bytearray(); selected_token = bytearray()
    try:
        if (type(content) is not bytearray or not 0 < len(content) <= 1048576
                or type(binding) is not FortitokenUserBinding or type(expected_serial) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{1,128}',expected_serial) is None): raise ValueError
        fields = _schema_fields(schema)
        if not isinstance(schema,Mapping) or schema.get('serial') != expected_serial: raise ValueError
        if not _FIELDS | {'webauthn'} <= fields.keys(): raise ValueError
        if any(not isinstance(fields[key],Mapping) or fields[key].get('type') == 'password-2'
                for key in _FIELDS-{'fortitoken'}): raise ValueError
        left = _skip_json_space(content,0); right = _json_value_end(content,left)
        if _skip_json_space(content,right) != len(content): raise ValueError
        metadata._validate_json(content,left,right,depth=0,budget=[50000]); envelope = _object_spans(content,left,right)
        if not set(envelope) <= {'build','http_method','http_status','name','path','status','version',
                'vdom','serial','mkey','results','revision','error'}: raise ValueError
        if 'error' in envelope:
            error = metadata._scalar(content,envelope['error'])
            if type(error) is not int or error != 0: raise ValueError
        for key,expected in dict(build=29,http_method='GET',http_status=200,name='admin',path='system',
                status='success',version='v7.0.0',vdom='root',serial=expected_serial).items():
            value = metadata._scalar(content,envelope[key])
            if type(value) is not type(expected) or value != expected: raise ValueError
        if 'mkey' in envelope and metadata._scalar(content,envelope['mkey']) != binding.username: raise ValueError
        span = envelope['results']
        if content[span[0]] == 91:
            rows = metadata._array(content,span,1)
            if len(rows) != 1: raise ValueError
            span = rows[0]
        members = _object_spans(content,*span)
        if 'fortitoken' not in members: raise ValueError
        token_span = members['fortitoken']
        with memoryview(content)[slice(*token_span)] as token:
            _string_or_empty(token); present = not hmac.compare_digest(token,b'""')
            if matched_token is not None:
                _validate_token(matched_token); selected_token = _quoted_material(matched_token)
                if not hmac.compare_digest(token,selected_token): raise ValueError
        # FortiToken serials are C3 even when the source schema describes
        # the field as a string. Reuse the complete User sanitizer with this
        # one field classified as material before a whole-record decode.
        _sanitize_object(content,*span,{**fields,'fortitoken':{'type':'password-2'}},sanitized,depth=0)
        record = json.loads(sanitized)
        if (record.get('name') != binding.username or record.get('id') != binding.user_id
                or type(record['id']) is not int or record.get('q_origin_key') != binding.username
                or record.get('q_mkey_type') != 'string' or record.get('q_name') != 'admin'
                or record.get('q_path') != 'system' or type(record.get('q_type')) is not int or record['q_type'] != 1
                or type(record.get('q_ref')) is not int or record['q_ref'] != 0): raise ValueError
        if any(record.get(key) is not False for key in ('q_no_edit','q_no_rename','q_static','q_global_entry')): raise ValueError
        if (record.get('status') != 'disable' or record.get('accprofile') != 'pam_standard_user'
                or record.get('auto-created-user') != 'no' or record.get('vdom') != []
                or any(record.get(key) != 'disable' for key in ('wildcard','remote-auth','guest-auth','cert-auth','force-saml-login'))
                or any(record.get(key) != '' for key in ('remote-group','remote-server','sponsor-group','schedule'))): raise ValueError
        if record.get('two-factor') not in ('disable','fortitoken'): raise ValueError
        webauthn = record.get('webauthn')
        if (not isinstance(webauthn,dict) or webauthn.get('status') != 'disable'
                or any(webauthn.get(key,'') != '' for key in ('create-time','user-handle','credential-id','public-key','transports'))
                or webauthn.get('algorithm',0) != 0): raise ValueError
        return FortitokenUserState(binding,canonical_digest(_schema_types(fields)),
            canonical_digest(dict(serial=expected_serial)),_encoded(record),present)
    except Exception: raise FortitokenUserContractError(_ERROR) from None
    finally:
        _clear_mutable_group((content,sanitized,selected_token), _zeroize_mutable)


def _validate_token(token: memoryview) -> None:
    if (type(token) is not memoryview or token.ndim != 1 or token.itemsize != 1 or not token.contiguous
            or not 1 <= len(token) <= 128 or any(value not in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-' for value in token)):
        raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class FortitokenUserPlan(_OpaqueC3Object):
    current: FortitokenUserState
    operation: Operation

    def __post_init__(self) -> None:
        if type(self.current) is not FortitokenUserState or self.operation not in ('assign','revoke'): raise ValueError(_ERROR)
        record = json.loads(self.current._encoded)
        if (self.operation == 'assign' and (self.current.token_present or record['two-factor'] != 'disable')
                or self.operation == 'revoke' and (not self.current.token_present or record['two-factor'] != 'fortitoken')):
            raise ValueError(_ERROR)

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,current=self.current.digest,operation=self.operation))

    def preview(self) -> dict[str,object]:
        public: dict[str,object] = {'Current State':dict(disabled_local_standard_profile=True,
                token_selector_present=self.current.token_present),
            'Proposed Changes':dict(two_factor_enabled=self.operation == 'assign',token_bound=self.operation == 'assign',
                password_submitted=False,activation_request_sent=False),
            'Expected State':dict(two_factor_enabled=self.operation == 'assign',token_bound=self.operation == 'assign',
                native_readback_required=True,complete_postcondition_qualified=False),
            'Security Changes':dict(mfa_requirement_removed=self.operation == 'revoke')}
        public.update(contract=CONTRACT,operation=self.operation,
            complete_postcondition_qualified=False,token_ownership_verified=False,role_entitlement_verified=False,
            independent_recovery_verified=False,native_backend_qualified=False,configuration_write_authorized=False,
            activation_delivery_verified=False,mfa_login_verified=False)
        return public


def expected_fortitoken_user_state(plan: FortitokenUserPlan) -> FortitokenUserState:
    """Strict local comparison profile, not a qualified server postcondition.

The omitted authentication member must remain exact on revoke. Any native
normalization requires its own evidence; it cannot be silently ignored here.
    """
    try:
        if type(plan) is not FortitokenUserPlan: raise ValueError
        plan.__post_init__(); record = json.loads(plan.current._encoded)
        if type(record.get('two-factor-authentication')) is not str: raise ValueError
        record['two-factor'] = 'fortitoken' if plan.operation == 'assign' else 'disable'
        if plan.operation == 'assign': record['two-factor-authentication'] = 'fortitoken'
        return FortitokenUserState(plan.current.binding,plan.current.schema_digest,plan.current.serial_digest,
            _encoded(record),plan.operation == 'assign')
    except Exception: raise FortitokenUserContractError(_ERROR) from None


def build_fortitoken_user_body(plan: FortitokenUserPlan, content: bytearray, schema: object, *,
        expected_serial: str, token_reference_digest: str, token: memoryview) -> bytearray:
    """Recheck complete fresh nonmaterial state and encode the native update.

This is a private codec, without transport, M4 claims or dispatch authority.
The caller clears the returned buffer and owns/clears its material lease.
    """
    body = bytearray()
    try:
        if type(plan) is not FortitokenUserPlan: raise ValueError
        plan.__post_init__(); _validate_token(token)
        if token_reference_digest != plan.current.binding.token_reference_digest: raise ValueError
        fresh = project_fortitoken_user(content,schema,plan.current.binding,expected_serial=expected_serial,
            matched_token=token if plan.operation == 'revoke' else None)
        if fresh.digest != plan.current.digest: raise ValueError
        body = _encode_fortitoken_user_update(plan,token)
        return body
    except Exception:
        _zeroize_mutable(body)
        raise FortitokenUserContractError(_ERROR) from None
    finally:
        if type(content) is bytearray: _zeroize_mutable(content)


def _encode_fortitoken_user_update(plan: FortitokenUserPlan, token: memoryview) -> bytearray:
    """Encode the fixed projection; callers separately prove fresh provenance."""
    with _MutableJSONBuffer() as body:
        try:
            plan.__post_init__()
            if plan.operation == 'assign': _validate_token(token)
            record = json.loads(plan.current._encoded)
            values = {name:record[name] for name in _FIELDS-{'fortitoken'}}
            values.update({'$originalName':plan.current.binding.username,
                'two-factor':'fortitoken' if plan.operation == 'assign' else 'disable','webauthn':{'status':'disable'}})
            if plan.operation == 'assign': values['two-factor-authentication'] = 'fortitoken'
            body.extend(_encoded(values)[:-1]); body.extend(b',"fortitoken":')
            if plan.operation == 'assign': _append_material(body,token)
            else: body.extend(b'""')
            body.append(125)
            return body.finish()
        except Exception:
            raise
