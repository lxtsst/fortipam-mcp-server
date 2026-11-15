"""Fixed Approval Email schema metadata; skip all defaults and unrelated values.

This consumes one byte buffer, not a generic schema or configuration accessor.
Only compiled field/type/option names and integer constraints may be published.
"""
from __future__ import annotations

import hmac
import re

from . import secret_bulk_import_metadata as metadata
from .approval_delivery_contract import _FIELDS,_MATERIAL
from .secret_metadata_http_transport import _json_string_end,_json_value_end,_skip_json_space,_zeroize_mutable

CONTRACT='fortipam-build29-approval-email-schema-metadata-local/v1'
SCHEMA_PATH='/api/v2/cmdb/secret/setting?action=schema'
MAX_SCHEMA_BYTES=2*1024*1024
_ERROR='The private approval-delivery schema metadata is unavailable.'
_EXPECTED={'version':b'"v7.0.0"','build':b'29','http_method':b'"GET"','http_status':b'200',
    'path':b'"secret"','name':b'"setting"','action':b'"schema"'}
_TYPES=('string','integer','option','password','password-2','table','list','boolean','object','group')
_OPTIONS={'approval-email-protocol':('imaps','ms-graph'),'ssl-min-version':('tls-1.1','tls-1.2','tls-1.3')}


def _members(raw: bytearray,span: tuple[int,int],selected: frozenset[str]) -> tuple[dict[str,tuple[int,int]],int]:
    # Count keys without decoding or retaining any unselected key/value.
    start,end=span
    if raw[start]!=123 or raw[end-1]!=125: raise ValueError
    cursor=_skip_json_space(raw,start+1);count=0
    while cursor<end-1:
        right=_json_string_end(raw,cursor)+1
        separator=_skip_json_space(raw,right)
        if raw[separator]!=58: raise ValueError
        first=_skip_json_space(raw,separator+1);last=_json_value_end(raw,first)
        count+=1
        if count>1024: raise ValueError
        cursor=_skip_json_space(raw,last)
        if cursor==end-1: break
        if raw[cursor]!=44: raise ValueError
        cursor=_skip_json_space(raw,cursor+1)
    return metadata._object_spans(raw,start,end,selected),count


def _known(raw: bytearray,span: tuple[int,int],choices: tuple[str,...]) -> str | None:
    with memoryview(raw)[slice(*span)] as token:
        for choice in choices:
            if hmac.compare_digest(token,('"'+choice+'"').encode('ascii')): return choice
    return None


def _integer(raw: bytearray,span: tuple[int,int]) -> int:
    with memoryview(raw)[slice(*span)] as token:
        if len(token)>20 or re.fullmatch(rb'-?(?:0|[1-9][0-9]*)',token) is None: raise ValueError
        value=int(token)
    if not -(2**63)<=value<2**63: raise ValueError
    return value


def consume_approval_delivery_schema(raw: bytearray) -> dict[str,object]:
    """Minimize one schema reply and clear input on every exit, including interrupts."""
    try:
        if type(raw) is not bytearray or not 0<len(raw)<=MAX_SCHEMA_BYTES: raise ValueError
        start=_skip_json_space(raw,0);end=_json_value_end(raw,start)
        if _skip_json_space(raw,end)!=len(raw): raise ValueError
        metadata._validate_json(raw,start,end,depth=0,budget=[50000])
        root,_=_members(raw,(start,end),frozenset(_EXPECTED)|{'status','results'})
        for name,expected in _EXPECTED.items():
            with memoryview(raw)[slice(*root[name])] as value:
                if not hmac.compare_digest(value,expected): raise ValueError
        if _known(raw,root['status'],('success','OK')) is None: raise ValueError
        results,_=_members(raw,root['results'],frozenset({'children'}))
        settings,_=_members(raw,results['children'],frozenset({'approval-email-setting'}))
        fields: dict[str,object]={};extra=0;parent_kind=None;has_children=False
        if 'approval-email-setting' in settings:
            parent,_=_members(raw,settings['approval-email-setting'],frozenset({'type','children'}))
            parent_kind=_known(raw,parent['type'],_TYPES) if 'type' in parent else None
            has_children='children' in parent
            if has_children:
                selected,count=_members(raw,parent['children'],frozenset(_FIELDS));extra=count-len(selected)
                for name in _FIELDS:
                    if name not in selected: continue
                    descriptor,_=_members(raw,selected[name],frozenset({'type','size','min-value','max-value','options','children'}))
                    item: dict[str,object]=dict(protected_slot=name in _MATERIAL)
                    item['type']=_known(raw,descriptor['type'],_TYPES) if 'type' in descriptor else None
                    for key in ('size','min-value','max-value'):
                        if key in descriptor: item[key]=_integer(raw,descriptor[key])
                    item['has_children']='children' in descriptor
                    if name in _OPTIONS and 'options' in descriptor:
                        options=metadata._array(raw,descriptor['options'],32);recognized=[]
                        for option in options:
                            members,_=_members(raw,option,frozenset({'name'}))
                            choice=_known(raw,members['name'],_OPTIONS[name])
                            if choice is not None:
                                if choice in recognized: raise ValueError
                                recognized.append(choice)
                        item['recognized_options']=sorted(recognized)
                        item['unclassified_option_count']=len(options)-len(recognized)
                    fields[name]=item
        return dict(contract=CONTRACT,approval_setting_present='approval-email-setting' in settings,
            approval_setting_type=parent_kind,approval_setting_has_children=has_children,
            selected_field_count=len(fields),unclassified_child_count=extra,fields=fields,
            defaults_and_unselected_values_decoded_or_hashed=False,schema_metadata_only=True,
            full_action_contract_qualified=False,native_instance_identity_verified=False,
            configuration_or_material_read=False,configuration_written=False)
    except Exception: raise ValueError(_ERROR) from None
    finally:
        if type(raw) is bytearray: _zeroize_mutable(raw)
