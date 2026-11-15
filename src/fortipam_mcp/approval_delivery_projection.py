"""Private wire-empty Approval Email projection, not a configuration reader.

All protected slots must be explicitly empty on the wire before any selected
nonmaterial string is decoded. Wire emptiness does not prove backend emptiness
or preservation: masking behavior and independent material custody remain open.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import json

from v4_planning.material_provider import _OpaqueC3Object
from . import secret_bulk_import_metadata as metadata
from .approval_delivery_contract import (
    ApprovalDeliveryEmptyDisableDraft,_FIELDS,_MATERIAL,prepare_empty_disabled_approval_delivery,
)
from .approval_delivery_schema import _members,_known,_integer
from .secret_metadata_http_transport import _json_value_end,_skip_json_space,_zeroize_mutable

CONTRACT='fortipam-build29-approval-email-wire-empty-projection-local/v1'
_ERROR='The private approval-delivery projection is unavailable.'
_EXPECTED={'version':b'"v7.0.0"','build':b'29','http_method':b'"GET"','http_status':b'200',
    'path':b'"secret"','name':b'"setting"'}
_MAX_BYTES=2*1024*1024


@dataclass(frozen=True,slots=True,repr=False)
class ApprovalDeliveryWireEmptyProjection(_OpaqueC3Object):
    _draft: ApprovalDeliveryEmptyDisableDraft
    _protocol: str
    _server_present: bool
    _pulling_server_present: bool

    def summary(self) -> dict[str,object]:
        enabled=self._server_present if self._protocol=='ms-graph' else self._server_present or self._pulling_server_present
        return dict(contract=CONTRACT,protocol=self._protocol,ui_enabled_inference=enabled,
            model_field_count=14,wire_empty_protected_slot_count=3,
            material_empty_state_proved=False,native_masking_or_material_continuity_qualified=False,
            whole_setting_baseline_verified=False,native_current_response_contract_qualified=False,
            partial_put_merge_qualified=False,restore_authorized=False,execution_authorized=False,
            configuration_written=False)


def project_wire_empty_approval_delivery(raw: bytearray,*,expected_serial: str) -> ApprovalDeliveryWireEmptyProjection:
    """Consume one provided response; no HTTP, identity lookup or material source.

    Unknown/unrelated values remain byte-only. A missing/null/masked protected
    slot refuses; even explicit wire-empty strings do not certify stored state.
    """
    try:
        selected=_selected_current_fields(raw,expected_serial=expected_serial)
        # Do this for ALL protected slots before decoding ANY current value.
        for name in _MATERIAL:
            with memoryview(raw)[slice(*selected[name])] as token:
                if not hmac.compare_digest(token,b'""'): raise ValueError
        values: dict[str,object]={}
        for name in _FIELDS:
            if name in _MATERIAL: continue
            span=selected[name]
            if name in ('port','check-interval'): values[name]=_integer(raw,span)
            else:
                if raw[span[0]]!=34: raise ValueError
                values[name]=metadata._scalar(raw,span)
        draft=prepare_empty_disabled_approval_delivery(values,username_empty=True,credential_empty=True,client_secret_empty=True)
        return ApprovalDeliveryWireEmptyProjection(draft,str(values['approval-email-protocol']),
            bool(values['server']),bool(values['email-pulling-server']))
    except Exception: raise ValueError(_ERROR) from None
    finally:
        if type(raw) is bytearray: _zeroize_mutable(raw)


def _selected_current_fields(raw: bytearray,*,expected_serial: str) -> dict[str,tuple[int,int]]:
    """Validate the fixed local envelope, leaving every value byte-only.

    The consuming projector must clear raw on every exit. This helper neither
    reads a source nor qualifies the provided frame as an authoritative GET.
    """
    if (type(raw) is not bytearray or not 0<len(raw)<=_MAX_BYTES
            or type(expected_serial) is not str or not 0<len(expected_serial)<=128): raise ValueError
    start=_skip_json_space(raw,0);end=_json_value_end(raw,start)
    if _skip_json_space(raw,end)!=len(raw): raise ValueError
    metadata._validate_json(raw,start,end,depth=0,budget=[50000])
    root,_=_members(raw,(start,end),frozenset(_EXPECTED)|{'serial','status','results','action','error'})
    expected={**_EXPECTED,'serial':json.dumps(expected_serial,ensure_ascii=True).encode('ascii')}
    for name,literal in expected.items():
        with memoryview(raw)[slice(*root[name])] as token:
            if not hmac.compare_digest(token,literal): raise ValueError
    if _known(raw,root['status'],('success','OK')) is None: raise ValueError
    if 'error' in root:
        with memoryview(raw)[slice(*root['error'])] as token:
            if not hmac.compare_digest(token,b'0') and not hmac.compare_digest(token,b'null'): raise ValueError
    if 'action' in root:
        with memoryview(raw)[slice(*root['action'])] as token:
            if not hmac.compare_digest(token,b'""'): raise ValueError
    settings,_=_members(raw,root['results'],frozenset({'approval-email-setting'}))
    selected,count=_members(raw,settings['approval-email-setting'],frozenset(_FIELDS))
    if count!=len(_FIELDS) or set(selected)!=set(_FIELDS): raise ValueError
    return selected
