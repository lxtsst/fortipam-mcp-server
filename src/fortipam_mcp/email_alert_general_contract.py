"""Private build29 general-alert draft; no compound master switch or transport.

Native model18496 serializes nine general fields. Critical automation,
certificate settings, SMTP and delivery need independent scope/evidence. The
complete supplied schema is compared; no native completeness or PUT-preservation
qualification is inferred. Mail identities remain private C4 data.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as metadata
from .local_user_reset_projection import _METADATA, _object_spans, _sanitize_value
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

CONTRACT = 'fortipam-build29-email-alert-general-local/v1'
FIELDS = frozenset({'username','email-to','filter-mode','email-interval','antivirus-logs',
    'configuration-changes-logs','HA-logs','severity','FDS-license-expiring-days'})
_TOP = {'build','http_method','http_status','name','path','status','version','vdom','serial','mkey','results','revision','error'}
_ERROR = 'The private general email-alert contract is unavailable.'
_MATERIAL = re.compile(r'(?:password|passwd|shared-key|private-key|access-token|refresh-token|client-secret)',re.I)
_SCALAR_TYPES = {'string','var-string','integer','option','user','ipv4-classnet','ipv6-prefix','datetime'}


def _encoded(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _mailbox(value: object, *, empty: bool = False) -> None:
    if empty and value == '': return
    if (type(value) is not str or not 1 <= len(value) <= 63 or not value.isascii()
            or re.fullmatch(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",value) is None
            or value.count('@') != 1 or '..' in value or value[0] == '.' or '.@' in value): raise ValueError


def _specs(fields: Mapping[str,Any], depth: int = 0) -> dict[str,Any]:
    if depth>16 or not 0 < len(fields) <= 128: raise ValueError
    result: dict[str,Any] = {}
    for name,spec in fields.items():
        if (type(name) is not str or not 1 <= len(name) <= 128 or _MATERIAL.search(name)
                or not isinstance(spec,Mapping)): raise ValueError
        kind,children = spec.get('type'),spec.get('children')
        if children is not None:
            if not isinstance(children,Mapping) or kind is not None and kind not in ('table','list'): raise ValueError
            result[name] = dict(type=kind,children=_specs(children,depth+1)); continue
        if kind not in _SCALAR_TYPES: raise ValueError
        item: dict[str,Any] = dict(type=kind)
        if 'size' in spec:
            size = spec['size']
            if type(size) is not int or not 1 <= size <= 65535: raise ValueError
            item['size'] = size
        for bound in ('min-value','max-value'):
            if bound in spec:
                value = spec[bound]
                if type(value) is not int or not -2147483648 <= value <= 2147483647: raise ValueError
                item[bound] = value
        if 'options' in spec:
            options = spec['options']
            if not isinstance(options,list) or not 1 <= len(options) <= 128: raise ValueError
            values = [option.get('name') if isinstance(option,Mapping) else option for option in options]
            if any(type(value) is not str or not 1 <= len(value) <= 128 for value in values) or len(set(values)) != len(values): raise ValueError
            item['options'] = sorted(values)
        result[name] = item
    return result


def _schema(schema: object, serial: str) -> dict[str,Any]:
    if not isinstance(schema,Mapping): raise ValueError
    for name,value in dict(build=29,http_method='GET',http_status=200,name='setting',path='alertemail',
            version='v7.0.0',serial=serial,action='schema').items():
        if type(schema.get(name)) is not type(value) or schema[name] != value: raise ValueError
    if schema.get('status') not in ('success','OK') or schema.get('vdom','root') != 'root': raise ValueError
    if 'error' in schema and (type(schema['error']) is not int or schema['error'] != 0): raise ValueError
    fields = schema['results']['children']
    if not isinstance(fields,Mapping) or not FIELDS <= fields.keys(): raise ValueError
    return _specs(fields)


def email_alert_general_schema_digest(schema: object, *, expected_serial: str) -> str:
    try: return canonical_digest(_schema(schema,expected_serial))
    except Exception: raise ValueError(_ERROR) from None


def _record(record: Mapping[str,Any]) -> None:
    _mailbox(record['username'],empty=True)
    recipients = record['email-to']
    if not isinstance(recipients,list) or len(recipients)>256: raise ValueError
    names = []
    for entry in recipients:
        if not isinstance(entry,dict) or set(entry) != {'name'}: raise ValueError
        _mailbox(entry['name']); names.append(entry['name'])
    if len(set(names)) != len(names): raise ValueError
    if record['filter-mode'] not in ('category','threshold'): raise ValueError
    interval = record['email-interval']; expiry = record['FDS-license-expiring-days']
    if type(interval) is not int or not 1 <= interval <= 99999 or type(expiry) is not int or not 0 <= expiry <= 2147483647: raise ValueError
    for name in ('antivirus-logs','configuration-changes-logs','HA-logs'):
        if record[name] not in ('enable','disable'): raise ValueError
    severity = record['severity']
    if type(severity) is not str or re.fullmatch(r'[a-z-]{1,32}',severity) is None: raise ValueError


def _values(record: Mapping[str,Any], fields: Mapping[str,Any], depth: int = 0) -> None:
    if depth>16 or not fields.keys() <= record.keys() <= fields.keys() | _METADATA: raise ValueError
    for name,spec in fields.items():
        value = record[name]; children = spec.get('children')
        if children is not None:
            rows = value if isinstance(value,list) else [value]
            if len(rows)>256: raise ValueError
            for row in rows:
                if not isinstance(row,Mapping): raise ValueError
                _values(row,children,depth+1)
        elif spec['type'] == 'integer':
            if (type(value) is not int or not spec.get('min-value',-2147483648) <= value <= spec.get('max-value',2147483647)): raise ValueError
        elif (type(value) is not str or len(value.encode()) > spec.get('size',65535)
                or 'options' in spec and value not in spec['options']): raise ValueError


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertMailScope(_OpaqueC3Object):
    binding_digest: str
    sender: str
    recipient: str

    def __post_init__(self) -> None:
        require_digest(self.binding_digest,'general alert mail scope'); _mailbox(self.sender); _mailbox(self.recipient)

    @property
    def digest(self) -> str:
        return canonical_digest(dict(binding=self.binding_digest,sender=self.sender,recipient=self.recipient))


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertGeneralState(_OpaqueC3Object):
    schema_digest: str
    serial_digest: str
    _encoded: bytes
    _specs: bytes

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,schema=self.schema_digest,serial=self.serial_digest,
            record=hashlib.sha256(self._encoded).hexdigest()))


def project_email_alert_general(raw: bytearray, schema: object, *, expected_serial: str,
        expected_schema_digest: str) -> EmailAlertGeneralState:
    sanitized = bytearray()
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= 1048576 or type(expected_serial) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{1,128}',expected_serial) is None): raise ValueError
        require_digest(expected_schema_digest,'general alert schema')
        fields = _schema(schema,expected_serial)
        if canonical_digest(fields) != expected_schema_digest: raise ValueError
        left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
        if _skip_json_space(raw,right) != len(raw): raise ValueError
        metadata._validate_json(raw,left,right,depth=0,budget=[50000]); root = _object_spans(raw,left,right)
        if not root.keys() <= _TOP: raise ValueError
        for name,value in dict(build=29,http_method='GET',http_status=200,name='setting',path='alertemail',
                version='v7.0.0',serial=expected_serial).items():
            with memoryview(raw)[slice(*root[name])] as actual:
                if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
        if metadata._scalar(raw,root['status']) not in ('success','OK'): raise ValueError
        for name,value in (('vdom','root'),('mkey',''),('error',0)):
            if name in root:
                actual_value = metadata._scalar(raw,root[name])
                if type(actual_value) is not type(value) or actual_value != value: raise ValueError
        row = _object_spans(raw,*root['results'])
        if not fields.keys() <= row.keys() <= fields.keys() | _METADATA: raise ValueError
        sanitized.append(123)
        for index,(name,span) in enumerate(row.items()):
            if index: sanitized.append(44)
            sanitized.extend(_encoded(name)); sanitized.append(58)
            if name in _METADATA:
                member = metadata._scalar(raw,span)
                if type(member) not in (str,int,bool): raise ValueError
                sanitized.extend(_encoded(member))
            else: _sanitize_value(raw,*span,fields[name],sanitized,depth=1)
        sanitized.append(125); record = json.loads(sanitized); _record(record); _values(record,fields)
        return EmailAlertGeneralState(expected_schema_digest,canonical_digest(dict(serial=expected_serial)),_encoded(record),_encoded(fields))
    except Exception: raise ValueError(_ERROR) from None
    finally:
        _zeroize_mutable(sanitized)
        if type(raw) is bytearray: _zeroize_mutable(raw)


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertGeneralPlan(_OpaqueC3Object):
    baseline: EmailAlertGeneralState
    mail_scope: EmailAlertMailScope

    def __post_init__(self) -> None:
        if type(self.baseline) is not EmailAlertGeneralState or type(self.mail_scope) is not EmailAlertMailScope: raise ValueError(_ERROR)
        self.mail_scope.__post_init__(); _record(json.loads(self.baseline._encoded))

    def expected(self) -> EmailAlertGeneralState:
        self.__post_init__(); row = json.loads(self.baseline._encoded)
        row.update(username=self.mail_scope.sender,**{'email-to':[dict(name=self.mail_scope.recipient)],'filter-mode':'category',
            'email-interval':5,'antivirus-logs':'disable','configuration-changes-logs':'enable','HA-logs':'disable'})
        _values(row,json.loads(self.baseline._specs))
        return EmailAlertGeneralState(self.baseline.schema_digest,self.baseline.serial_digest,_encoded(row),self.baseline._specs)

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,baseline=self.baseline.digest,mail_scope=self.mail_scope.digest))

    def compile(self, current: EmailAlertGeneralState, *, restore: bool = False) -> bytearray:
        try:
            if type(current) is not EmailAlertGeneralState or type(restore) is not bool: raise ValueError
            self.__post_init__(); expected = self.expected(); before,after = (expected,self.baseline) if restore else (self.baseline,expected)
            if current.digest != before.digest or before.digest == after.digest: raise ValueError
            row = json.loads(after._encoded)
            return bytearray(_encoded({name:row[name] for name in FIELDS}))
        except Exception: raise ValueError(_ERROR) from None

    def preview(self) -> dict[str,object]:
        self.__post_init__()
        return dict(contract=CONTRACT,
            **{'Current State':dict(full_supplied_schema_compared=True,mail_identities_private=True),
               'Proposed Changes':dict(scope='general_only',configuration_change_alerts=True,antivirus_alerts=False,ha_alerts=False,
                    filter_mode='category',email_interval_minutes=5,recipient_count=1,threshold_severity_preserved=True,
                    fds_expiry_days_preserved=True),
               'Expected State':dict(full_general_readback_required=True,independent_mail_and_compound_scope_required=True,
                    independent_restore_authorization_required=True),
               'Security Changes':dict(external_email_possible=True,master_switch_is_derived=True)},
            configuration_ready=False,execution_authorized=False,native_put_qualified=False,global_master_state_verified=False,
            critical_automation_preserved=False,certificate_settings_preserved=False,mail_service_qualified=False,
            recipient_scope_authorized=False,delivery_verified=False,independent_recovery_verified=False)
