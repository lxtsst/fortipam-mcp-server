"""Private ordered alert draft across general, three critical pairs and certificates.

Only existing fixed builtin graphs are eligible. Trigger creation/repair is
unsupported. Serialization and prefix equality confer no dispatch, original ACK
or inverse authority. Secret-setting's empty reverse-service subtree is retained
as an explicit unqualified native-serialization boundary, never assumed safe.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass,replace
import hashlib
import hmac
import json
import re
from typing import Any,Literal

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from . import secret_bulk_import_metadata as metadata
from .email_alert_general_contract import (EmailAlertGeneralPlan,EmailAlertGeneralState,EmailAlertMailScope,
    _encoded,_mailbox,_specs,_values)
from .local_user_reset_projection import _METADATA,_object_spans,_sanitize_value
from .secret_metadata_http_transport import _json_value_end,_skip_json_space,_zeroize_mutable

CONTRACT = 'fortipam-build29-email-alert-compound-local/v1'
Slot = Literal['glass','license','floating']
Kind = Literal['action','stitch','trigger','settings']
Step = Literal['general','glass_action','license_action','floating_action','glass_stitch','license_stitch','floating_stitch','certificate']
SLOTS: tuple[Slot,...] = ('glass','license','floating')
STEPS: tuple[Step,...] = ('general','glass_action','license_action','floating_action','glass_stitch','license_stitch','floating_stitch','certificate')
_NAMES = {
    'glass':('Glassbreaking Email','Glass Breaking Notification','Glass Breaking Activated'),
    'license':('License Expired Notification Email','License Expired Notification','License Expired Notification'),
    'floating':('Floating License Grace Period Email','Floating License Expiry','Floating License In Grace Period'),
}
_TABLES = {'action':('system','automation-action'),'stitch':('system','automation-stitch'),
    'trigger':('system','automation-trigger'),'settings':('secret','setting')}
_REQUIRED = {'action':{'name','action-type','email-from','email-to','email-subject'},
    'stitch':{'name','status','trigger','actions','description'},'trigger':{'name','trigger-type','event-type','logid'},
    'settings':{'cert-setting','reverse-service-setting'}}
_TOP = {'build','http_method','http_status','name','path','status','version','vdom','serial','mkey','results','revision','error'}
_ERROR = 'The private compound email-alert contract is unavailable.'


def _frame_values(row: Mapping[str,Any], fields: Mapping[str,Any], kind: Kind) -> None:
    if 'q_class' in row and 'q_class' not in fields:
        if kind not in ('action','stitch') or type(row['q_class']) is not str or len(row['q_class'])>255: raise ValueError
        row = {key:value for key,value in row.items() if key != 'q_class'}
    _values(row,fields)


def _identity(kind: Kind, slot: Slot | None) -> tuple[str,str,str]:
    if kind not in _TABLES or kind == 'settings' and slot is not None or kind != 'settings' and slot not in SLOTS: raise ValueError
    if kind == 'settings': return *_TABLES[kind],''
    if slot is None: raise ValueError
    name = _NAMES[slot][('action','stitch','trigger').index(kind)]
    return *_TABLES[kind],name


def _schema(schema: object, kind: Kind, serial: str) -> dict[str,Any]:
    path,table = _TABLES[kind]
    if not isinstance(schema,Mapping): raise ValueError
    for key,value in dict(build=29,http_method='GET',http_status=200,name=table,path=path,version='v7.0.0',serial=serial,action='schema').items():
        if type(schema.get(key)) is not type(value) or schema[key] != value: raise ValueError
    if schema.get('status') not in ('OK','success') or schema.get('vdom','root') != 'root': raise ValueError
    if 'error' in schema and (type(schema['error']) is not int or schema['error'] != 0): raise ValueError
    fields = schema['results']['children']
    if not isinstance(fields,Mapping) or not _REQUIRED[kind] <= fields.keys(): raise ValueError
    return _specs(fields)


def email_alert_frame_schema_digest(schema: object, kind: Kind, *, expected_serial: str) -> str:
    try: return canonical_digest(_schema(schema,kind,expected_serial))
    except Exception: raise ValueError(_ERROR) from None


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertFrame(_OpaqueC3Object):
    kind: Kind
    slot: Slot | None
    schema_digest: str
    serial_digest: str
    _encoded: bytes
    _specs: bytes

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,kind=self.kind,slot=self.slot,schema=self.schema_digest,
            serial=self.serial_digest,record=hashlib.sha256(self._encoded).hexdigest()))


def project_email_alert_frame(raw: bytearray, schema: object, kind: Kind, slot: Slot | None, *,
        expected_serial: str, expected_schema_digest: str) -> EmailAlertFrame:
    sanitized = bytearray()
    try:
        path,table,name = _identity(kind,slot)
        if (type(raw) is not bytearray or not 0 < len(raw) <= 1048576 or type(expected_serial) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{1,128}',expected_serial) is None): raise ValueError
        require_digest(expected_schema_digest,'alert frame schema'); fields = _schema(schema,kind,expected_serial)
        if canonical_digest(fields) != expected_schema_digest: raise ValueError
        left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
        if _skip_json_space(raw,right) != len(raw): raise ValueError
        metadata._validate_json(raw,left,right,depth=0,budget=[50000]); root = _object_spans(raw,left,right)
        if not root.keys() <= _TOP: raise ValueError
        for key,value in dict(build=29,http_method='GET',http_status=200,name=table,path=path,version='v7.0.0',serial=expected_serial).items():
            with memoryview(raw)[slice(*root[key])] as actual:
                if not hmac.compare_digest(actual,_encoded(value)): raise ValueError
        if metadata._scalar(raw,root['status']) not in ('success','OK'): raise ValueError
        for key,value in (('vdom','root'),('mkey',name),('error',0)):
            if key in root:
                actual_value = metadata._scalar(raw,root[key])
                if type(actual_value) is not type(value) or actual_value != value: raise ValueError
        span = root['results']
        if raw[span[0]] == 91:
            items = metadata._array(raw,span,1)
            if len(items) != 1: raise ValueError
            span = items[0]
        row = _object_spans(raw,*span); extra = {'q_class'} if kind in ('action','stitch') else set()
        if not fields.keys() <= row.keys() <= fields.keys() | _METADATA | extra: raise ValueError
        sanitized.append(123)
        for index,(key,value_span) in enumerate(row.items()):
            if index: sanitized.append(44)
            sanitized.extend(_encoded(key)); sanitized.append(58)
            if key in _METADATA | extra:
                value = metadata._scalar(raw,value_span)
                if type(value) not in (str,int,bool): raise ValueError
                sanitized.extend(_encoded(value))
            else: _sanitize_value(raw,*value_span,fields[key],sanitized,depth=1)
        sanitized.append(125); record = json.loads(sanitized); _frame_values(record,fields,kind)
        if kind != 'settings' and record['name'] != name: raise ValueError
        if 'q_origin_key' in record and record['q_origin_key'] != name: raise ValueError
        return EmailAlertFrame(kind,slot,expected_schema_digest,canonical_digest(dict(serial=expected_serial)),_encoded(record),_encoded(fields))
    except Exception: raise ValueError(_ERROR) from None
    finally:
        _zeroize_mutable(sanitized)
        if type(raw) is bytearray: _zeroize_mutable(raw)


def _recipients(value: object) -> None:
    if not isinstance(value,list) or len(value)>256: raise ValueError
    names = []
    for row in value:
        if not isinstance(row,dict) or set(row) != {'name'}: raise ValueError
        _mailbox(row['name']); names.append(row['name'])
    if len(set(names)) != len(names): raise ValueError


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertCompoundState(_OpaqueC3Object):
    general: EmailAlertGeneralState
    actions: tuple[EmailAlertFrame,...]
    stitches: tuple[EmailAlertFrame,...]
    triggers: tuple[EmailAlertFrame,...]
    settings: EmailAlertFrame

    def __post_init__(self) -> None:
        if type(self.general) is not EmailAlertGeneralState or type(self.settings) is not EmailAlertFrame: raise ValueError(_ERROR)
        if (self.settings.kind,self.settings.slot) != ('settings',None): raise ValueError(_ERROR)
        for kind,items in (('action',self.actions),('stitch',self.stitches),('trigger',self.triggers)):
            if type(items) is not tuple or len(items) != 3: raise ValueError(_ERROR)
            for slot,item in zip(SLOTS,items):
                if type(item) is not EmailAlertFrame or (item.kind,item.slot) != (kind,slot): raise ValueError(_ERROR)
        if any(item.serial_digest != self.general.serial_digest for item in (*self.actions,*self.stitches,*self.triggers,self.settings)): raise ValueError(_ERROR)
        for slot,action,stitch,trigger in zip(SLOTS,self.actions,self.stitches,self.triggers):
            a,s,t = (json.loads(frame._encoded) for frame in (action,stitch,trigger))
            if a['name'] != _NAMES[slot][0] or a['action-type'] != 'email': raise ValueError(_ERROR)
            _mailbox(a['email-from'],empty=True); _recipients(a['email-to'])
            if type(a['email-subject']) is not str or not 1 <= len(a['email-subject']) <= 255: raise ValueError(_ERROR)
            if (s['name'] != _NAMES[slot][1] or s['trigger'] != _NAMES[slot][2] or s['status'] not in ('enable','disable')
                    or type(s['description']) is not str or s['actions'] != [dict(id=1,action=_NAMES[slot][0],required='enable')]): raise ValueError(_ERROR)
            event,logs = ('license-near-expiry',[]) if slot == 'license' else ('event-log',[dict(id=44557 if slot == 'glass' else 37912)])
            if (t['name'] != _NAMES[slot][2] or t['trigger-type'] != 'event-based' or t['event-type'] != event or t['logid'] != logs): raise ValueError(_ERROR)
        cert = json.loads(self.settings._encoded)['cert-setting']
        if (not isinstance(cert,dict) or not {'alert-status','warning-days-before-expiry','email-to'} <= cert.keys()
                or cert['alert-status'] not in ('enable','disable') or type(cert['warning-days-before-expiry']) is not int
                or not 1 <= cert['warning-days-before-expiry'] <= 2147483647): raise ValueError(_ERROR)
        _recipients(cert['email-to'])

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,general=self.general.digest,actions=[a.digest for a in self.actions],
            stitches=[s.digest for s in self.stitches],triggers=[t.digest for t in self.triggers],settings=self.settings.digest))

    def master_enabled(self) -> bool:
        self.__post_init__(); general = json.loads(self.general._encoded)
        return bool(general['username'] or general['email-to'] or any(json.loads(a._encoded)['email-to'] for a in self.actions)
            or json.loads(self.settings._encoded)['cert-setting']['email-to'])


def _changed(frame: EmailAlertFrame, **values: Any) -> EmailAlertFrame:
    row = json.loads(frame._encoded); row.update(values); _frame_values(row,json.loads(frame._specs),frame.kind)
    return replace(frame,_encoded=_encoded(row))


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertCompoundPlan(_OpaqueC3Object):
    baseline: EmailAlertCompoundState
    mail_scope: EmailAlertMailScope

    def __post_init__(self) -> None:
        if type(self.baseline) is not EmailAlertCompoundState or type(self.mail_scope) is not EmailAlertMailScope: raise ValueError(_ERROR)
        self.baseline.__post_init__(); self.mail_scope.__post_init__()

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,baseline=self.baseline.digest,mail_scope=self.mail_scope.digest))

    def expected(self, completed: int = 8) -> EmailAlertCompoundState:
        self.__post_init__()
        if type(completed) is not int or not 0 <= completed <= len(STEPS): raise ValueError(_ERROR)
        result = self.baseline
        for step in STEPS[:completed]:
            if step == 'general': result = replace(result,general=EmailAlertGeneralPlan(result.general,self.mail_scope).expected())
            elif step == 'certificate':
                cert = json.loads(result.settings._encoded)['cert-setting']
                cert.update({'alert-status':'enable','warning-days-before-expiry':3,'email-to':[dict(name=self.mail_scope.recipient)]})
                result = replace(result,settings=_changed(result.settings,**{'cert-setting':cert}))
            else:
                slot,kind = step.split('_'); index = next(i for i,name in enumerate(SLOTS) if name == slot)
                if kind == 'action':
                    items = list(result.actions); items[index] = _changed(items[index],**{'email-from':self.mail_scope.sender,'email-to':[dict(name=self.mail_scope.recipient)]})
                    result = replace(result,actions=tuple(items))
                else:
                    items = list(result.stitches); items[index] = _changed(items[index],status='enable')
                    result = replace(result,stitches=tuple(items))
        return result

    def compile(self, step: Step, current: EmailAlertCompoundState, *, restore: bool = False) -> bytearray:
        try:
            if step not in STEPS or type(current) is not EmailAlertCompoundState or type(restore) is not bool: raise ValueError
            index = STEPS.index(step); before,after = (index+1,index) if restore else (index,index+1)
            expected_before,expected_after = self.expected(before),self.expected(after)
            if current.digest != expected_before.digest or expected_before.digest == expected_after.digest: raise ValueError
            if step == 'general':
                return EmailAlertGeneralPlan(self.baseline.general,self.mail_scope).compile(current.general,restore=restore)
            if step == 'certificate':
                cert = json.loads(expected_after.settings._encoded)['cert-setting']
                # Native model53961 unparse/JSON emits this empty sibling from
                # a cert-only savePartial. Its merge/effect semantics need proof.
                return bytearray(_encoded({'cert-setting':cert,'reverse-service-setting':{}}))
            slot,kind = step.split('_'); at = next(i for i,name in enumerate(SLOTS) if name == slot)
            frame = expected_after.actions[at] if kind == 'action' else expected_after.stitches[at]
            row = json.loads(frame._encoded)
            fields = ('name','action-type','email-from','email-to','email-subject') if kind == 'action' else ('name','status','trigger','actions','description')
            return bytearray(_encoded({**{key:row[key] for key in fields},'$originalName':row['name']}))
        except Exception: raise ValueError(_ERROR) from None

    @property
    def changed_steps(self) -> tuple[Step,...]:
        return tuple(step for i,step in enumerate(STEPS) if self.expected(i).digest != self.expected(i+1).digest)

    def preview(self) -> dict[str,object]:
        self.__post_init__()
        return dict(contract=CONTRACT,
            **{'Current State':dict(complete_supplied_graph_compared=True,critical_pairs=3,existing_graph_only=True,
                    master_enabled_locally=self.baseline.master_enabled()),
               'Proposed Changes':dict(ordered_write_steps=len(self.changed_steps),general_configuration_change_alerts=True,critical_email_actions=3,
                    critical_stitches_enabled=3,certificate_warning_days=3,fixed_recipient_count=1,trigger_write_requested=False),
               'Expected State':dict(per_object_original_readback_required=True,independent_recovery_authority_required=True,
                    full_compound_readback_required=True),
               'Security Changes':dict(external_email_possible=True,master_switch_is_derived=True,
                    certificate_serialization_contains_empty_reverse_service_block=True,
                    configuration_restore_does_not_recall_mail=True,sender_quiescence_required_before_restore=True)},
            configuration_ready=False,execution_authorized=False,native_put_qualified=False,recipient_scope_authorized=False,
            critical_graph_native_qualified=False,certificate_merge_qualified=False,reverse_service_preservation_qualified=False,
            device_model_qualified=False,delivery_verified=False,independent_recovery_verified=False)
