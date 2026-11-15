"""Bounded Build29 Unix creation serialization; never write authority.

The complete expected material remains separate from the native request. Omitted
fields are still part of the proposal and must match the actual created readback.
"""
from __future__ import annotations

import json
import ipaddress
import re

from . import secret_bulk_import_metadata as m
from . import target_preservation_contract as c
from .secret_metadata_http_transport import _zeroize_mutable, _skip_json_space, _json_value_end
from .target_contract import DEFAULT_TEMPLATE

CONTRACT = 'fortipam-build29-unix-target-create-serialization-v1'
WINDOWS_EXECUTION_CONTRACT = 'fortipam-build29-windows-execution-target-create-serialization-v1'
JOB_MAPPED_CONTRACT = 'fortipam-build29-job-mapped-target-create-serialization-v1'
SERVICE_ACCOUNT_CONTRACT = 'fortipam-build29-service-account-target-create-serialization-v1'
SERVICE_ACCOUNT_REFERENCE_CONTRACT = 'fortipam-build29-service-reference-target-create-serialization-v2'
_ERROR = 'Protected Target creation serialization unavailable.'
_SQL = frozenset({'log-all', 'log-rpc-parameters', 'max-log-entry-sz', 'monitor-db'})


def compile_request(proposal: c.TargetState, material: bytearray) -> bytearray:
    """Consume full expected fields and return an exact, supported wire projection.

    This first profile requires an explicit sole Owner ACL, no group grant,
    disabled Web Proxy, and no service-address or host-key transformations.
    It never chooses an owner, adds permissions, or supplies omitted defaults.
    """
    return _compile_owner_only_request(proposal, material, expected_template=DEFAULT_TEMPLATE)


def compile_job_mapped_target_request(proposal: c.TargetState, material: bytearray) -> bytearray:
    """One named mapped SSH Job prerequisite with the qualified native Owner ACL."""
    try:
        c._checked_state(proposal)
        if (re.fullmatch(r'mcp-v4-target-job-mapped-[0-9]{8}-r[1-9][0-9]{0,2}',proposal.name) is None
                or proposal.coordinates.template != DEFAULT_TEMPLATE
                or proposal.coordinates.domain or proposal.coordinates.url):raise ValueError
        address=ipaddress.IPv4Address(proposal.coordinates.address)
        if address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local:raise ValueError
        return _compile_owner_only_request(proposal,material,expected_template=DEFAULT_TEMPLATE,native_acl_metadata=True)
    except Exception:
        if type(material) is bytearray:_zeroize_mutable(material)
        raise ValueError(_ERROR) from None


def compile_windows_execution_target_request(proposal: c.TargetState, material: bytearray) -> bytearray:
    """Separate fixed LOCAL/HTTP WinRM prerequisite, never a Unix qualification.

    No credentials, privileged-account assignment, service address, gateway,
    domain or proxy activation can be introduced by this private profile.
    Full proposed state still binds every field omitted by native serialization.
    """
    return _compile_windows_target_request(proposal, material,
        name_pattern=r'MCPV4WinTarget[0-9]{8}R[1-9][0-9]{0,2}')


def compile_service_account_target_request(proposal: c.TargetState, material: bytearray) -> bytearray:
    """Separate owned service prerequisite, with the same fixed LOCAL WinRM wire."""
    return _compile_windows_target_request(proposal, material,
        name_pattern=r'mcp-v4-target-svc-[0-9]{8}-r[1-9][0-9]{0,2}')


def compile_service_account_reference_target_request(proposal: c.TargetState, material: bytearray) -> bytearray:
    """Keep the accepted reference default; Secret selection remains independent."""
    return _compile_windows_target_request(proposal, material,
        name_pattern=r'mcp-v4-target-svc-ref-[0-9]{8}-r[1-9][0-9]{0,2}', expected_template=DEFAULT_TEMPLATE)


def _compile_windows_target_request(proposal: c.TargetState, material: bytearray, *, name_pattern: str,
        expected_template: str = 'Windows Machine') -> bytearray:
    try:
        from .target_creation_http_transport import _verify_body
        c._checked_state(proposal)
        _verify_body(material, proposal)
        if (re.fullmatch(name_pattern, proposal.name) is None
                or proposal.coordinates.template != expected_template
                or proposal.coordinates.domain or proposal.coordinates.url):
            raise ValueError
        address = ipaddress.IPv4Address(proposal.coordinates.address)
        if (str(address) != proposal.coordinates.address or address.is_loopback
                or address.is_multicast or address.is_unspecified or address.is_link_local):
            raise ValueError
        # These are observed Target fields, not invented WinRM port/auth options.
        start = _skip_json_space(material, 0); end = _json_value_end(material, start)
        fields = m._object_spans(material, start, end, frozenset({
            'winrm-https', 'dynamic-gateway', 'gateway', 'gateway-cn', 'user-base',
            'user-naming-attribute', 'kdc-address', 'sql-server-log-status'}))
        wanted = {'winrm-https':'disable', 'dynamic-gateway':'disable', 'gateway':'', 'gateway-cn':'',
            'user-base':'', 'user-naming-attribute':'sAMAccountName', 'kdc-address':'', 'sql-server-log-status':'disable'}
        # Preserve the observed naming default; LOCAL selection is the empty
        # domain plus the machine-qualified credential, not clearing this field.
        for name, expected in wanted.items():
            value = m._scalar(material, fields[name])
            if type(value) is not type(expected) or value != expected:
                raise ValueError
        return _compile_owner_only_request(proposal, material, expected_template=expected_template,
                                           native_acl_metadata=True)
    except Exception:
        if type(material) is bytearray:
            _zeroize_mutable(material)
        raise ValueError(_ERROR) from None


def _compile_owner_only_request(proposal: c.TargetState, material: bytearray, *, expected_template: str,
                               native_acl_metadata: bool = False) -> bytearray:
    """Native omission kernel shared only by the two explicit profile entries."""
    output = bytearray()
    try:
        from .target_creation_http_transport import _verify_body
        c._checked_state(proposal)
        _verify_body(material, proposal)
        start = _skip_json_space(material, 0)
        end = _json_value_end(material, start)
        fields = m._object_spans(material, start, end, c.TARGET_STATE_FIELDS | {'$originalName'})
        if (m._scalar(material, fields['class']) != 'Other'
            or proposal.coordinates.template != expected_template
            or m._scalar(material, fields['access']) != 'customized'
            or m._scalar(material, fields['web-proxy-status']) != 'disable'):
            raise ValueError
        for name in ('service-addrs', 'hostkey', 'group-permission'):
            if m._array(material, fields[name], 1):
                raise ValueError
        acl = m._array(material, fields['user-permission'], 2)
        if len(acl) != 1:
            raise ValueError
        owner_fields = {'id', 'user-name', 'permission'}
        owner = m._object_spans(material, *acl[0], frozenset(owner_fields | ({'q_origin_key'} if native_acl_metadata else set())))
        if (not owner_fields <= owner.keys()
            or c._member_count(material, acl[0]) != len(owner)
            or type(m._scalar(material, owner['id'])) is not int
            or m._scalar(material, owner['id']) != 1
            or m._scalar(material, owner['permission']) != 'owner'):
            raise ValueError
        if 'q_origin_key' in owner:
            origin = m._scalar(material, owner['q_origin_key'])
            if type(origin) is not int or origin != 1:
                raise ValueError
        users = m._array(material, owner['user-name'], 2)
        if len(users) != 1:
            raise ValueError
        user = m._object_spans(material, *users[0], frozenset({'name'} | ({'q_origin_key'} if native_acl_metadata else set())))
        if 'name' not in user or c._member_count(material, users[0]) != len(user):
            raise ValueError
        owner_name = m._text(m._scalar(material, user['name']), maximum=255)
        if 'q_origin_key' in user and m._scalar(material, user['q_origin_key']) != owner_name:
            raise ValueError
        sql = m._object_spans(material, *fields['sql-log'], _SQL)
        if set(sql) != _SQL or c._member_count(material, fields['sql-log']) != 4:
            raise ValueError
        output.extend(b'{')
        for index, name in enumerate(sorted(set(fields) - {'web-proxy'})):
            if index:
                output.extend(b',')
            output.extend(json.dumps(name).encode() + b':')
            if name == 'user-permission' and native_acl_metadata and ('q_origin_key' in owner or 'q_origin_key' in user):
                # Native module12972 rebuilds this relation, omitting q_ metadata.
                # The complete expected material above still fingerprints it.
                output.extend(json.dumps([{'id': 1, 'user-name': [{'name': owner_name}],
                    'permission': 'owner'}], ensure_ascii=True, separators=(',', ':')).encode())
            elif name == 'sql-log':
                output.extend(b'{')
                for child_index, child in enumerate(('log-all', 'max-log-entry-sz', 'monitor-db')):
                    if child_index:
                        output.extend(b',')
                    output.extend(json.dumps(child).encode() + b':')
                    left, right = sql[child]
                    output.extend(memoryview(material)[left:right])
                output.extend(b'}')
            else:
                left, right = fields[name]
                output.extend(memoryview(material)[left:right])
        output.extend(b'}')
        result, output = output, bytearray()
        return result
    except Exception:
        raise ValueError(_ERROR) from None
    finally:
        _zeroize_mutable(output)
        if isinstance(material, bytearray):
            _zeroize_mutable(material)
