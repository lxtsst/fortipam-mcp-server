"""Private build29 DNS timeout contract; preserve the complete configuration."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

CONTRACT = 'fortipam-build29-dns-timeout-v1'
PATH = '/api/v2/cmdb/system/dns'
_ERROR = 'The fixed DNS timeout is unavailable.'


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class DnsTimeoutBinding(_OpaqueC3Object):
    nonce: str
    baseline_digest: str

    def __post_init__(self) -> None:
        require_digest(self.baseline_digest, 'baseline_digest')
        if type(self.nonce) is not str or re.fullmatch(r'[a-f0-9]{32}', self.nonce) is None:
            raise ValueError(_ERROR)

    @property
    def parameters_digest(self) -> str:
        self.__post_init__()
        return _digest({'contract': CONTRACT, 'nonce': self.nonce,
                        'baseline': self.baseline_digest, 'timeout': [5, 6]})


def _envelope(payload: object, serial_digest: str, *, method: str = 'GET',
              action: str | None = None) -> dict[str, Any]:
    require_digest(serial_digest, 'serial_digest')
    if (type(payload) is not dict or any(type(payload.get(k)) is not type(v) or payload[k] != v
            for k, v in {'version': 'v7.0.0', 'build': 29, 'path': 'system', 'name': 'dns',
                         'http_method': method, 'http_status': 200}.items())
            or payload.get('status') not in {'success', 'OK'}
            or type(payload.get('serial')) is not str or not payload['serial']
            or hashlib.sha256(payload['serial'].encode()).hexdigest() != serial_digest
            or payload.get('action') != action):
        raise ValueError(_ERROR)
    return payload


def _unprotected(value: object) -> bool:
    if type(value) is dict:
        if value.get('type') in {'password', 'secret'} or value.get('sensitive') is True:
            return False
        return all(_unprotected(v) for v in value.values())
    return type(value) is not list or all(_unprotected(v) for v in value)


def qualify_schema(payload: object, *, serial_digest: str) -> str:
    try:
        schema = _envelope(payload, serial_digest, action='schema')['results']
        if (type(schema) is not dict or schema.get('name') != 'dns' or schema.get('path') != 'system'
                or schema.get('category') != 'complex' or schema.get('mkey') is not None
                or schema.get('mkey_type') is not None or type(schema.get('children')) is not dict
                or len(schema['children']) != 20 or not _unprotected(schema)):
            raise ValueError
        timeout = schema['children']['timeout']
        if any(type(timeout.get(k)) is not type(v) or timeout[k] != v for k, v in
               {'type': 'integer', 'default': 5, 'min-value': 1, 'max-value': 10}.items()):
            raise ValueError
        return _digest({'serial': serial_digest, 'schema': schema})
    except Exception:
        raise ValueError(_ERROR) from None


def _state(payload: object, *, serial_digest: str, fields: tuple[str, ...]) -> bytes:
    envelope = _envelope(payload, serial_digest)
    state = envelope['results']
    if (type(state) is not dict or set(state) != set(fields)
            or type(state.get('timeout')) is not int or not 1 <= state['timeout'] <= 10
            or envelope.get('limit_reached') is True):
        raise ValueError(_ERROR)
    return _canonical(state)


@dataclass(frozen=True, slots=True, repr=False)
class DnsTimeoutPreparation(_OpaqueC3Object):
    parameters_digest: str
    schema_digest: str
    fields: tuple[str, ...]
    original_bytes: bytes
    body_bytes: bytes
    current_digest: str
    expected_digest: str


def prepare_dns_timeout(schema: object, current: object, *, serial_digest: str,
                        binding: DnsTimeoutBinding) -> DnsTimeoutPreparation:
    try:
        if type(binding) is not DnsTimeoutBinding:
            raise ValueError
        qualified = qualify_schema(schema, serial_digest=serial_digest)
        fields = tuple(sorted(_envelope(schema, serial_digest, action='schema')['results']['children']))
        original = _state(current, serial_digest=serial_digest, fields=fields)
        digest = hashlib.sha256(original).hexdigest()
        state = json.loads(original)
        if digest != binding.baseline_digest or state['timeout'] != 5:
            raise ValueError
        state['timeout'] = 6
        body = _canonical(state)
        return DnsTimeoutPreparation(binding.parameters_digest, qualified, fields,
            original, body, digest, hashlib.sha256(body).hexdigest())
    except Exception:
        raise ValueError(_ERROR) from None


def verify_dns_timeout(payload: object, preparation: DnsTimeoutPreparation, *,
                       serial_digest: str, restored: bool = False) -> bool:
    try:
        if type(preparation) is not DnsTimeoutPreparation or type(restored) is not bool:
            raise ValueError
        expected = preparation.original_bytes if restored else preparation.body_bytes
        return _state(payload, serial_digest=serial_digest, fields=preparation.fields) == expected
    except Exception:
        raise ValueError(_ERROR) from None
