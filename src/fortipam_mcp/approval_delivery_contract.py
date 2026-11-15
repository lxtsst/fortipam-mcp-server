"""Private build29 Approval Email request facts and empty-material disable codec.

The retained SDK updates only approval-email-setting inside secret/setting.
Native partial-update merging, full baseline, material custody, polling and
approval effects remain unqualified. No device or delivery authority is given.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

CONTRACT='fortipam-build29-approval-email-empty-material-disable-request/v1'
REQUEST_SOURCE_SHA256='af9f72445871576551f7b77a9bda6a1c137798f6eae0f944401094019d681eca'
SCHEMA_METADATA_SHA256='05652ae1f77e7d0b2ea2360aee9d37831a8a7fda880c2bb7004ee7d9d9e892c4'
NORMALIZER_SOURCE_SHA256='0c2bf35bb5cde1a5154012d6bf2f529d8d59e782a35aebe0bd29976ca9da434f'
CONFIGURATION_PATH='/api/v2/cmdb/secret/setting'
_FIELDS=('approval-email-protocol','email-pulling-server','server','port','username','credential',
    'server-cert','email-folder','ssl-min-version','check-interval','tenant-id','app-id','client-secret','user-id')
_MATERIAL=frozenset({'username','credential','client-secret'})
_NONMATERIAL=set(_FIELDS)-_MATERIAL
_SIZES={'email-pulling-server':255,'server':255,'server-cert':79,'email-folder':79,
    'tenant-id':79,'app-id':79,'user-id':79}
_EMPTY_CERTIFICATE_KEYS=frozenset({'%0%','%1%'})
_ERROR='The private approval-delivery request is unavailable.'


def _wire(value: object) -> bytes:
    return json.dumps(value,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _checked_nonmaterial(values: Mapping[str,Any]) -> dict[str,Any]:
    if not isinstance(values,Mapping) or set(values)!=_NONMATERIAL: raise ValueError
    selected=dict(values)
    for key,value in selected.items():
        if key in ('port','check-interval'):
            maximum=65535 if key=='port' else 1440
            if type(value) is not int or not 1<=value<=maximum: raise ValueError
        elif (type(value) is not str or len(value.encode('utf-8'))>_SIZES.get(key,4096)
                or any(ord(char)<32 or ord(char)==127 for char in value)): raise ValueError
    if (selected['approval-email-protocol'] not in ('imaps','ms-graph')
            or selected['ssl-min-version'] not in ('tls-1.1','tls-1.2','tls-1.3')): raise ValueError
    return selected


@dataclass(frozen=True,slots=True,repr=False)
class ApprovalDeliveryEmptyDisableDraft(_OpaqueC3Object):
    """Typed input only; not a source observation, material seal or permission."""
    request_digest: str
    input_nonmaterial_digest: str
    schema_metadata_digest: str
    _wire: bytes

    def _encode(self) -> bytearray: return bytearray(self._wire)


def prepare_empty_disabled_approval_delivery(values: Mapping[str,Any],*,username_empty: bool=False,
        credential_empty: bool=False,client_secret_empty: bool=False) -> ApprovalDeliveryEmptyDisableDraft:
    """Mirror the SDK's disable branch for already-empty protected slots.

    server-cert is a scalar key; the two native empty markers normalize to empty.
    No reference object,
    material value or enabled profile is accepted. Emptiness arguments are
    required local facts, not independent preservation or execution evidence.
    Captured string sizes are applied as local UTF-8 byte limits; native Unicode
    normalization and password-size interpretation are not qualified here.
    """
    try:
        if any(type(flag) is not bool or flag is not True for flag in
                (username_empty,credential_empty,client_secret_empty)): raise ValueError
        selected=_checked_nonmaterial(values)
        # The editor disables by clearing both server fields and preserves every
        # other SDK field; there is no native enabled toggle in this payload.
        payload={key:'' if key in _MATERIAL or key in ('server','email-pulling-server')
            else selected[key] for key in _FIELDS}
        if payload['server-cert'] in _EMPTY_CERTIFICATE_KEYS: payload['server-cert']=''
        body=_wire({'approval-email-setting':payload})
        prefix=(CONTRACT.encode('ascii')+b'\0schema\0'+SCHEMA_METADATA_SHA256.encode('ascii')
            +b'\0normalizer\0'+NORMALIZER_SOURCE_SHA256.encode('ascii'))
        return ApprovalDeliveryEmptyDisableDraft(
            hashlib.sha256(prefix+b'\0request\0'+body).hexdigest(),
            hashlib.sha256(prefix+b'\0input\0'+_wire(selected)).hexdigest(),SCHEMA_METADATA_SHA256,body)
    except Exception: raise ValueError(_ERROR) from None


def approval_delivery_request_boundary() -> dict[str,object]:
    """Only fixed source facts; no mailbox, identity, material or input digest."""
    return dict(contract=CONTRACT,request_source_sha256=REQUEST_SOURCE_SHA256,
        schema_metadata_sha256=SCHEMA_METADATA_SHA256,captured_child_schema_constraints_observed=True,
        certificate_normalizer_source_sha256=NORMALIZER_SOURCE_SHA256,
        scalar_certificate_reference_normalization_source_verified=True,object_certificate_reference_qualified=False,
        full_parent_schema_type_qualified=False,native_unicode_or_password_size_units_qualified=False,
        source_kind='retained_build29_settings_frontend',method='PUT',path=CONFIGURATION_PATH,
        subtree='approval-email-setting',sdk_field_count=14,protocols=['imaps','ms-graph'],
        disabled_ui_clears_both_servers=True,native_enabled_field=False,
        empty_protected_slots_required=True,normalized_scalar_certificate_key_only=True,
        typed_input_is_not_native_observation=True,native_schema_or_ack_verified=False,
        singleton_partial_put_merge_qualified=False,complete_baseline_or_material_preservation_verified=False,
        disable_does_not_recall_mail_or_approval_requests=True,
        outbound_system_email_is_separate=True,polling_delivery_or_approval_effect_verified=False,
        source_or_request_grants_authority=False,execution_authorized=False,
        http_transport_registered=False,mcp_tool_registered=False,device_contacted=False)
