"""Private build-29 disabled-route projections; no dispatch or authority.

The only candidate is an unreferenced, disabled blackhole host route in the
benchmark network. Existing routes are preserved in full. Native schemas and
state stay private; only categorical previews may cross the MCP boundary.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Any, NoReturn, cast

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

CONTRACT = 'fortipam-build29-disabled-route-v1'
PATH = '/api/v2/cmdb/router/static'
DESTINATION = '198.18.0.1 255.255.255.255'
_ERROR = 'The fixed disabled route is unavailable.'
_DEFAULTS: dict[str, Any] = {
    'seq-num': 0, 'status': 'enable', 'dst': '0.0.0.0 0.0.0.0',
    'src': '0.0.0.0 0.0.0.0', 'gateway': '0.0.0.0', 'distance': 10,
    'weight': 0, 'priority': 1, 'device': '', 'comment': '',
    'blackhole': 'disable', 'sdwan-zone': [], 'dstaddr': '',
    'link-monitor-exempt': 'disable',
}
_TYPES = {
    'seq-num': 'integer', 'status': 'option', 'dst': 'ipv4-classnet',
    'src': 'ipv4-classnet', 'gateway': 'ipv4-address', 'distance': 'integer',
    'weight': 'integer', 'priority': 'integer', 'device': 'string',
    'comment': 'var-string', 'blackhole': 'option', 'dstaddr': 'string',
    'link-monitor-exempt': 'option',
}
_RANGES = {'seq-num': (0, 4294967295), 'distance': (1, 255),
           'weight': (0, 255), 'priority': (1, 65535)}
_METADATA = {
    'q_origin_key': int, 'q_ref': int, 'q_static': bool, 'q_no_rename': bool,
    'q_global_entry': bool, 'q_type': int, 'q_path': str, 'q_name': str,
    'q_mkey_type': str, 'q_no_edit': bool,
}


class DisabledRouteContractError(ValueError):
    """Value-free rejection of incompatible or incomplete evidence."""


def _fail() -> NoReturn:
    raise DisabledRouteContractError(_ERROR)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class DisabledRouteBinding(_OpaqueC3Object):
    sequence: int
    nonce: str
    benchmark_host: int = 1

    def __post_init__(self) -> None:
        if (type(self.sequence) is not int or not 100000 <= self.sequence <= 199999
                or type(self.nonce) is not str or re.fullmatch(r'[a-f0-9]{32}', self.nonce) is None
                or type(self.benchmark_host) is not int or self.benchmark_host not in {1, 2}):
            _fail()

    @property
    def destination(self) -> str:
        return f'198.18.0.{self.benchmark_host} 255.255.255.255'

    @property
    def body(self) -> dict[str, Any]:
        self.__post_init__()
        return {**_DEFAULTS, 'sdwan-zone': [], 'seq-num': self.sequence,
                'status': 'disable', 'blackhole': 'enable', 'dst': self.destination,
                'comment': 'mcp-v4-disabled-route-' + self.nonce}

    @property
    def parameters_digest(self) -> str:
        return _digest({'contract': CONTRACT, 'body': self.body})


def _envelope(payload: object, serial_digest: str, action: str | None = None) -> Mapping[str, Any]:
    require_digest(serial_digest, 'serial_digest')
    if not isinstance(payload, Mapping):
        _fail()
    assert isinstance(payload, Mapping)
    if (any(type(payload.get(k)) is not type(v) or payload[k] != v for k, v in {
            'version': 'v7.0.0', 'build': 29, 'path': 'router', 'name': 'static',
            'http_method': 'GET', 'http_status': 200,
        }.items()) or payload.get('status') not in {'success', 'OK'}
            or type(payload.get('serial')) is not str or not payload['serial']
            or hashlib.sha256(payload['serial'].encode()).hexdigest() != serial_digest
            or payload.get('action') != action):
        _fail()
    return payload


def qualify_schema(payload: object, *, serial_digest: str) -> str:
    """Check the complete fixed field contract before considering a body."""
    try:
        schema = _envelope(payload, serial_digest, 'schema')['results']
        if (not isinstance(schema, dict) or schema.get('name') != 'static'
                or schema.get('path') != 'router' or schema.get('mkey') != 'seq-num'
                or schema.get('mkey_type') != 'integer' or schema.get('category') != 'table'):
            _fail()
        fields = schema['children']
        if type(fields) is not dict or set(fields) != set(_DEFAULTS):
            _fail()
        for name, field_type in _TYPES.items():
            field = fields[name]
            if type(field) is not dict or field.get('type') != field_type:
                _fail()
            if name != 'comment' and (type(field.get('default')) is not type(_DEFAULTS[name])
                                     or field['default'] != _DEFAULTS[name]):
                _fail()
            if field_type == 'option' and sorted(x['name'] for x in field['options']) != ['disable', 'enable']:
                _fail()
        for name, limits in _RANGES.items():
            if any(type(fields[name].get(key)) is not int or fields[name][key] != expected
                   for key, expected in zip(('min-value', 'max-value'), limits)):
                _fail()
        for name, size in (('device', 35), ('comment', 255), ('dstaddr', 79)):
            if type(fields[name].get('size')) is not int or fields[name]['size'] != size:
                _fail()
        zone = fields['sdwan-zone']
        if (zone.get('mkey') != 'name' or zone.get('mkey_type') != 'string'
                or set(zone['children']) != {'name'} or zone['children']['name'].get('type') != 'string'
                or zone['children']['name'].get('size') != 79):
            _fail()
        return _digest({'serial': serial_digest, 'fields': fields})
    except Exception:
        raise DisabledRouteContractError(_ERROR) from None


def _record(row: object, *, metadata: bool) -> dict[str, Any]:
    if type(row) is not dict or set(row) != set(_DEFAULTS) | (set(_METADATA) if metadata else set()):
        _fail()
    assert isinstance(row, dict)
    for name, (minimum, maximum) in _RANGES.items():
        if type(row[name]) is not int or not minimum <= row[name] <= maximum:
            _fail()
    for name in ('status', 'blackhole', 'link-monitor-exempt'):
        if type(row[name]) is not str or row[name] not in {'enable', 'disable'}:
            _fail()
    for name, size in (('device', 35), ('comment', 255), ('dstaddr', 79)):
        if (type(row[name]) is not str or len(row[name].encode()) > size
                or any(ord(c) < 32 or ord(c) == 127 for c in row[name])):
            _fail()
    if type(row['gateway']) is not str:
        _fail()
    ipaddress.IPv4Address(row['gateway'])
    for name in ('dst', 'src'):
        address, mask = row[name].split(' ')
        ipaddress.IPv4Network(address + '/' + mask, strict=True)
    if type(row['sdwan-zone']) is not list or len(row['sdwan-zone']) > 32:
        _fail()
    for zone in row['sdwan-zone']:
        if (type(zone) is not dict or set(zone) != {'name'} or type(zone['name']) is not str
                or not 1 <= len(zone['name'].encode()) <= 79
                or any(ord(c) < 32 or ord(c) == 127 for c in zone['name'])):
            _fail()
    if metadata:
        if (any(type(row[k]) is not kind for k, kind in _METADATA.items())
                or row['q_origin_key'] != row['seq-num'] or row['q_ref'] < 0):
            _fail()
    return cast(dict[str, Any], json.loads(_canonical(row)))


@dataclass(frozen=True, slots=True, repr=False)
class DisabledRoutePreparation(_OpaqueC3Object):
    """Private immutable wire snapshots; no authorization or ownership claim."""
    parameters_digest: str
    schema_digest: str
    current_digest: str
    expected_digest: str
    body_bytes: bytes
    preserved_bytes: bytes


def prepare_disabled_route(schema: object, defaults: object, table: object, *,
                           serial_digest: str, binding: DisabledRouteBinding) -> DisabledRoutePreparation:
    try:
        if type(binding) is not DisabledRouteBinding:
            _fail()
        schema_digest = qualify_schema(schema, serial_digest=serial_digest)
        default_row = _record(_envelope(defaults, serial_digest, 'default')['results'], metadata=False)
        if default_row != _DEFAULTS:
            _fail()
        rows = project_route_table(table, serial_digest=serial_digest)
        if any(row['seq-num'] == binding.sequence or row['dst'] == binding.destination for row in rows):
            _fail()
        body = binding.body
        current = _digest({'schema': schema_digest, 'defaults': default_row, 'routes': rows})
        expected = _digest({'preserved': rows, 'created': body})
        return DisabledRoutePreparation(binding.parameters_digest, schema_digest, current, expected,
                                        _canonical(body), _canonical(rows))
    except Exception:
        raise DisabledRouteContractError(_ERROR) from None


def project_route_table(payload: object, *, serial_digest: str) -> list[dict[str, Any]]:
    """Reject truncated or duplicate route tables; retain values privately."""
    try:
        envelope = _envelope(payload, serial_digest)
        rows = envelope['results']
        if (type(rows) is not list or len(rows) > 4096
                or type(envelope.get('size')) is not int or envelope['size'] != len(rows)
                or type(envelope.get('matched_count')) is not int or envelope['matched_count'] != len(rows)
                or (envelope.get('limit_reached') is not None and envelope['limit_reached'] is not False)
                or type(envelope.get('next_idx')) is not int
                or envelope['next_idx'] != max(0, len(rows) - 1)):
            _fail()
        projected = [_record(row, metadata=True) for row in rows]
        if any(row['seq-num'] == 0 for row in projected) or len({r['seq-num'] for r in projected}) != len(projected):
            _fail()
        return sorted(projected, key=lambda r: r['seq-num'])
    except Exception:
        raise DisabledRouteContractError(_ERROR) from None


def verify_disabled_route(table: object, preparation: DisabledRoutePreparation, *,
                          serial_digest: str, removed: bool = False) -> bool:
    """Verify complete disabled state plus preservation, or exact restoration.

    A matching object never establishes original creation ownership; the action
    transport must retain the original successful ACK before offering deletion.
    """
    try:
        if type(preparation) is not DisabledRoutePreparation or type(removed) is not bool:
            _fail()
        rows = project_route_table(table, serial_digest=serial_digest)
        preserved, body = json.loads(preparation.preserved_bytes), json.loads(preparation.body_bytes)
        if removed:
            return bool(rows == preserved)
        owned = [row for row in rows if row['seq-num'] == body['seq-num']]
        others = [row for row in rows if row['seq-num'] != body['seq-num']]
        return (len(owned) == 1 and others == preserved and owned[0]['q_ref'] == 0
                and owned[0]['q_no_edit'] is False and owned[0]['q_static'] is False
                and {key: owned[0][key] for key in _DEFAULTS} == body)
    except Exception:
        raise DisabledRouteContractError(_ERROR) from None
