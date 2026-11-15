"""Private full nonmaterial Windows JIT draft; no native PUT or authority.

Credential slot values, TOTP keys and schema-declared material are erased
before decoding or hashing. The seven-field fragment is not a qualified wire
body; original custody, material preservation and privilege effects stay open.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any
import uuid

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .local_user_reset_projection import _METADATA, _object_spans, _sanitize_value
from .secret_checkout_association_contract import CONTROLS, IDLE_FIELD
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .windows_jit_script_contract import _script_names

CONTRACT = 'fortipam-build29-windows-jit-secret-metadata-local/v1'
_ERROR = 'The private Windows JIT Secret contract is unavailable.'
_REQUIRED = CONTROLS | {IDLE_FIELD,'id','name','uuid','folder','template','target','field','totp-setting',
    'proxy','recording','target-privilege-account','associated-secret','auto-association','target-info','permissions'}
_TOP = {'build','http_method','http_status','name','path','status','version','vdom','serial','mkey','results','revision','error'}


def _encoded(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


@dataclass(frozen=True, slots=True, repr=False)
class WindowsJitSecretBinding(_OpaqueC3Object):
    secret_id: int
    folder_id: int
    secret_uuid: str
    associated_secret_id: int
    nonce: str

    def __post_init__(self) -> None:
        for value in (self.secret_id,self.folder_id,self.associated_secret_id):
            if type(value) is not int or not 0 < value <= 2147483647: raise ValueError(_ERROR)
        if (self.secret_id == self.associated_secret_id or type(self.secret_uuid) is not str
                or str(uuid.UUID(self.secret_uuid)) != self.secret_uuid or uuid.UUID(self.secret_uuid).int == 0): raise ValueError(_ERROR)
        _script_names(self.nonce)

    @property
    def identity(self) -> dict[str,object]:
        return dict(id=self.secret_id,name='MCPV4JitSubject'+self.nonce,uuid=self.secret_uuid,folder=self.folder_id,
            template='Windows Machine',target='MCPV4JitTarget'+self.nonce)


@dataclass(frozen=True, slots=True, repr=False)
class WindowsJitSecretState(_OpaqueC3Object):
    binding: WindowsJitSecretBinding
    schema_digest: str
    serial_digest: str
    _encoded: bytes

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,identity=canonical_digest(self.binding.identity),
            schema=self.schema_digest,serial=self.serial_digest,record=hashlib.sha256(self._encoded).hexdigest()))


def _schema(schema: object, expected_serial: str) -> dict[str,Any]:
    if not isinstance(schema,Mapping): raise ValueError
    for key,value in dict(build=29,http_method='GET',http_status=200,name='database',path='secret',status='success',
            version='v7.0.0',serial=expected_serial,action='schema').items():
        if type(schema.get(key)) is not type(value) or schema[key] != value: raise ValueError
    fields = schema['results']['children']
    if not isinstance(fields,Mapping) or not _REQUIRED <= fields.keys(): raise ValueError
    result = dict(fields)
    for name,member in (('field','value'),('totp-setting','shared-key')):
        descriptor = fields[name]
        if not isinstance(descriptor,Mapping) or not isinstance(descriptor.get('children'),Mapping): raise ValueError
        children = dict(descriptor['children'])
        if member not in children: raise ValueError
        result[name] = {**descriptor,'children':{**children,member:{'type':'password-2'}}}
    if any(not isinstance(result[key],Mapping) or result[key].get('type') == 'password-2'
            for key in _REQUIRED-{'field','totp-setting'}): raise ValueError
    return result


def _types(fields: Mapping[str,Any], depth: int = 0) -> dict[str,Any]:
    if depth>16 or len(fields)>512: raise ValueError
    result = {}
    for name,spec in fields.items():
        if not isinstance(spec,Mapping): raise ValueError
        kind = spec.get('type'); children = spec.get('children')
        if kind is not None and (type(kind) is not str or not 1 <= len(kind) <= 64): raise ValueError
        if children is not None and not isinstance(children,Mapping): raise ValueError
        result[name] = dict(type=kind,children=_types(children,depth+1) if children is not None else None)
    return result


def _erase_material(raw: bytearray, span: tuple[int,int], spec: Mapping[str,Any], depth: int = 0) -> None:
    if depth>16: raise ValueError
    left,right = span
    if spec.get('type') == 'password-2':
        with memoryview(raw)[left:right] as token:
            if token[0] != 34 and not hmac.compare_digest(token,b'null'): raise ValueError
        raw[left:right] = b'""'+b' '*(right-left-2)
        return
    children = spec.get('children')
    if not isinstance(children,Mapping): return
    spans = metadata._array(raw,span,512) if raw[left] == 91 else [span]
    for item in spans:
        for name,value_span in _object_spans(raw,*item).items():
            if name in children: _erase_material(raw,value_span,children[name],depth+1)


def project_windows_jit_secret(raw: bytearray, schema: object, binding: WindowsJitSecretBinding, *,
        expected_serial: str) -> WindowsJitSecretState:
    sanitized = bytearray()
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= 2097152 or type(binding) is not WindowsJitSecretBinding
                or type(expected_serial) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,128}',expected_serial) is None): raise ValueError
        binding.__post_init__(); fields = _schema(schema,expected_serial)
        left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
        if _skip_json_space(raw,right) != len(raw): raise ValueError
        metadata._validate_json(raw,left,right,depth=0,budget=[50000]); root = _object_spans(raw,left,right)
        if not root.keys() <= _TOP: raise ValueError
        for name,expected in dict(build=29,http_method='GET',http_status=200,name='database',path='secret',status='OK',
                version='v7.0.0',vdom='root',serial=expected_serial).items():
            with memoryview(raw)[slice(*root[name])] as actual:
                if not hmac.compare_digest(actual,_encoded(expected)): raise ValueError
        for option,expected in (('error',0),('mkey',binding.secret_id)):
            if option in root:
                actual_value = metadata._scalar(raw,root[option])
                if type(actual_value) is not int or actual_value != expected: raise ValueError
        span = root['results']
        if raw[span[0]] == 91:
            rows = metadata._array(raw,span,1)
            if len(rows) != 1: raise ValueError
            span = rows[0]
        row = _object_spans(raw,*span)
        if not fields.keys() <= row.keys() <= fields.keys() | _METADATA: raise ValueError
        slots = metadata._array(raw,row['field'],3)
        if not slots: raise ValueError
        for slot in slots:
            if 'value' not in _object_spans(raw,*slot): raise ValueError
        if 'shared-key' not in _object_spans(raw,*row['totp-setting']): raise ValueError
        _erase_material(raw,span,dict(children=fields))
        sanitized.append(123)
        for index,(name,value_span) in enumerate(row.items()):
            if index: sanitized.append(44)
            sanitized.extend(_encoded(name)); sanitized.append(58)
            if name in _METADATA:
                value = metadata._scalar(raw,value_span)
                if type(value) not in (str,int,bool): raise ValueError
                sanitized.extend(_encoded(value))
            elif fields[name].get('type') == 'password-2':
                sanitized.extend(b'null')
            else: _sanitize_value(raw,*value_span,fields[name],sanitized,depth=1)
        sanitized.append(125); record = json.loads(sanitized)
        for name,expected in binding.identity.items():
            if type(record.get(name)) is not type(expected) or record[name] != expected: raise ValueError
        if (type(record.get('q_ref')) is not int or record['q_ref'] != 0 or record.get('q_static') is not False
                or record.get('associated-secret') != binding.associated_secret_id
                or type(record['associated-secret']) is not int
                or record.get('target-privilege-account') != 'disable' or record.get('auto-association') != 'disable'
                or any(record.get(name) != 'enable' for name in ('proxy','recording'))
                or record['totp-setting'].get('status') != 'disable'
                or type(record['target-info'].get('priv_acct')) is not int or record['target-info']['priv_acct'] != 0): raise ValueError
        if 'q_origin_key' in record:
            origin = record['q_origin_key']
            if not (type(origin) is int and origin == binding.secret_id or type(origin) is str and origin == str(binding.secret_id)): raise ValueError
        if any(record.get(name,False) is not False for name in ('q_no_edit','q_no_rename','q_global_entry')): raise ValueError
        names = [slot['name'] for slot in record['field']]; identifiers = [slot['id'] for slot in record['field']]
        if (not {'Username','Password'} <= set(names) <= {'Host','Username','Password'} or len(names) != len(set(names))
                or len(identifiers) != len(set(identifiers))
                or any(type(value) is not int or not 0 < value <= 2147483647 for value in identifiers)): raise ValueError
        _controls(record)
        return WindowsJitSecretState(binding,canonical_digest(_types(fields)),canonical_digest(dict(serial=expected_serial)),_encoded(record))
    except Exception: raise ValueError(_ERROR) from None
    finally:
        _zeroize_mutable(sanitized)
        if type(raw) is bytearray: _zeroize_mutable(raw)


def _controls(record: Mapping[str,Any]) -> None:
    for name,minimum,maximum in (('checkout-duration',3,1440),('checkout-renew-times',1,5),(IDLE_FIELD,0,30)):
        value = record[name]
        if type(value) is not int or not minimum <= value <= maximum: raise ValueError
    if any(record[name] != 'disable' for name in ('checkout-duration-renew','checkin-pwd-change')): raise ValueError
    if record['checkout'] not in ('enable','disable'): raise ValueError
    expected = ('required','forbidden') if record['checkout'] == 'enable' else ('none','allowed')
    permissions = record['permissions']
    if (not isinstance(permissions,Mapping) or any(type(permissions.get(name)) is not str or permissions[name] != value
            for name,value in zip(('checkout_status','passwd_change'),expected))): raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class WindowsJitSecretPlan(_OpaqueC3Object):
    baseline: WindowsJitSecretState

    def __post_init__(self) -> None:
        if type(self.baseline) is not WindowsJitSecretState: raise ValueError(_ERROR)
        record = json.loads(self.baseline._encoded); _controls(record)
        if record['checkout'] != 'disable' or record['checkout-script'] != '' or record['checkin-script'] != '': raise ValueError(_ERROR)

    def expected(self) -> WindowsJitSecretState:
        record = json.loads(self.baseline._encoded); grant,revoke = _script_names(self.baseline.binding.nonce)
        record.update(checkout='enable',**{'checkout-script':grant,'checkin-script':revoke,'checkout-duration':5})
        record['permissions'].update(checkout_status='required',passwd_change='forbidden')
        return WindowsJitSecretState(self.baseline.binding,self.baseline.schema_digest,self.baseline.serial_digest,_encoded(record))

    def compile_metadata_patch(self, current: WindowsJitSecretState, *, restore: bool = False) -> dict[str,object]:
        """A private fragment; final transport must separately retain C3/full state."""
        try:
            if type(current) is not WindowsJitSecretState or type(restore) is not bool: raise ValueError
            self.__post_init__(); applied = self.expected(); before,after = (applied,self.baseline) if restore else (self.baseline,applied)
            if current.digest != before.digest: raise ValueError
            record = json.loads(after._encoded)
            return {name:record[name] for name in CONTROLS}
        except Exception: raise ValueError(_ERROR) from None

    def preview(self) -> dict[str,object]:
        self.__post_init__()
        return {'contract':CONTRACT,
            'Current State':dict(checkout_disabled_locally=True,script_references_empty=True,
                associated_account_preserved=True,proxy_and_recording_enabled=True),
            'Proposed Changes':dict(fixed_script_pair_attached=True,checkout_enabled=True,checkout_duration_minutes=5,
                renewal_enabled=False,password_change_requested=False,credential_submitted=False),
            'Expected State':dict(full_nonmaterial_readback_required=True,independent_password_totp_continuity_required=True,
                independent_script_result_and_logon_effects_required=True,exact_derived_checkout_permissions_required=True),
            'Security Changes':dict(script_failure_blocks_checkout=False,group_removal_revokes_existing_logon_privilege=False,
                checkout_duration_bounds_os_logon_privilege=False),
            'metadata_patch_only':True,'native_partial_put_qualified':False,'configuration_ready':False,'execution_authorized':False,
            'script_ownership_verified':False,'associated_admin_qualified':False,'original_subject_custody_verified':False,
            'material_preservation_qualified':False,'standalone_target_qualified':False,'jit_privilege_effect_verified':False,
            'product_actor_verified':False,'permission_verified':False,'complete_activity_scope_verified':False,
            'independent_recovery_verified':False}
