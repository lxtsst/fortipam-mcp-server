"""Consuming private Target preflight projection, never transport or M4 authority.

The trusted reader must supply actual fixed-route responses in order, from one
qualified actor/origin and a bounded fresh window. This pure contract cannot
prove those source properties or permission to create/update/delete a Target.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from . import target_preservation_contract as c
from .secret_bulk_import_dependencies import project_importable_templates
from .secret_metadata_http_transport import _skip_json_space, _json_value_end, _zeroize_mutable

_ERROR = 'Protected Target lifecycle dependencies unavailable.'
_ENVELOPE = m._ENVELOPE_FIELDS | frozenset({'action', 'mkey'})
_ACTOR = frozenset({'name', 'login_name', 'sponsored_group_name', 'guest_admin'})
_ROLE = frozenset({'name', 'accprofile', 'status', 'remote-auth', 'wildcard', 'q_origin_key'})
_SCHEMA = frozenset({'type', 'size', 'read_only', 'readonly', 'read-only'})
_COORDINATE_FIELDS = {'target-address': 'address', 'domain': 'domain', 'url': 'url'}
_CONTRACT = 'fortipam-build29-target-lifecycle-dependencies-v1'
_API_CONTRACT = 'fortipam-build29-target-api-lifecycle-dependencies-v1'
_API_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\Z')


class TargetLifecycleDependencyError(ValueError):
    """Fixed non-disclosing refusal; no partial evidence is returned."""


@dataclass(frozen=True, slots=True, repr=False)
class TargetLifecycleDependencies(_OpaqueC3Object):
    serial_digest: str
    actor_digest: str
    template_digests: tuple[tuple[str, str], ...]
    schema_digest: str
    coordinates_digest: str
    dependency_digest: str


def _spans(content: bytearray) -> dict[str, tuple[int, int]]:
    if type(content) is not bytearray or not 0 < len(content) <= m._MAX_BYTES:
        raise ValueError
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError
    m._validate_json(content, start, end, depth=0, budget=[50000])
    return m._object_spans(content, start, end, _ENVELOPE)


def _equal(content: bytearray, fields: dict[str, tuple[int, int]], expected: dict[str, object]) -> None:
    for key, value in expected.items():
        actual = m._scalar(content, fields[key])
        if type(actual) is not type(value) or actual != value:
            raise ValueError


def _envelope(content: bytearray, *, path: str, name: str, serial_digest: str,
              monitor: bool = False, action: str = '') -> tuple[int, int]:
    fields = _spans(content)
    expected: dict[str, object] = {'version': 'v7.0.0', 'build': 29, 'path': path,
        'name': name, 'http_method': 'GET'}
    if not monitor or 'http_status' in fields:
        expected['http_status'] = 200
    if (not monitor and path == 'secret') or 'vdom' in fields:
        expected['vdom'] = 'root'
    if 'action' in fields:
        expected['action'] = action
    _equal(content, fields, expected)
    status = m._scalar(content, fields['status'])
    if status not in (('success',) if monitor or path == 'secret' else ('success', 'OK')):
        raise ValueError
    if 'error' in fields:
        error = m._scalar(content, fields['error'])
        if error is not None and (type(error) is not int or error != 0):
            raise ValueError
    if not monitor or 'serial' in fields:
        serial = m._text(m._scalar(content, fields['serial']), maximum=128)
        if not hmac.compare_digest(hashlib.sha256(serial.encode()).hexdigest(), serial_digest):
            raise ValueError
    return fields['results']


def _one(content: bytearray, span: tuple[int, int]) -> tuple[int, int]:
    if content[span[0]] == 91:
        items = m._array(content, span, 1)
        if len(items) != 1:
            raise ValueError
        return items[0]
    return span


def _actor(actor: bytearray, role: bytearray, name: str, serial_digest: str) -> str:
    span = _envelope(actor, path='web-ui', name='state', serial_digest=serial_digest, monitor=True)
    state = m._object_spans(actor, *span, frozenset({'admin'}))
    identity = m._object_spans(actor, *state['admin'], _ACTOR)
    expected: dict[str, object] = {'name': name, 'login_name': name,
        'sponsored_group_name': '', 'guest_admin': False}
    _equal(actor, identity, expected)
    span = _one(role, _envelope(role, path='system', name='admin', serial_digest=serial_digest))
    fields = m._object_spans(role, *span, _ROLE)
    role_values: dict[str, object] = {'name': name, 'accprofile': 'super_admin',
        'status': 'enable', 'remote-auth': 'disable', 'wildcard': 'disable'}
    _equal(role, fields, role_values)
    if 'q_origin_key' in fields:
        _equal(role, fields, {'q_origin_key': name})
    return c._digest((_CONTRACT, serial_digest, expected, role_values))


def _schema(content: bytearray, serial_digest: str) -> str:
    span = _one(content, _envelope(content, path='secret', name='target', serial_digest=serial_digest, action='schema'))
    root = m._object_spans(content, *span, frozenset({'children'}))
    fields = m._object_spans(content, *root['children'], c.TARGET_STATE_FIELDS)
    if set(fields) != c.TARGET_STATE_FIELDS:
        raise ValueError
    for name in c._COORDINATES:
        properties = m._object_spans(content, *fields[name], _SCHEMA)
        _equal(content, properties, {'type': 'var-string' if name == 'url' else 'string',
                                    'size': 79 if name == 'template' else 255})
        for flag in ('read_only', 'readonly', 'read-only'):
            if flag in properties and m._scalar(content, properties[flag]) is not False:
                raise ValueError
    # Bind all schema tokens, including undecoded options and nested definitions.
    return c._token_digest(content, span)


def _templates(content: bytearray, serial_digest: str,
               coordinates: tuple[c.TargetCoordinates, ...]) -> tuple[tuple[str, str], ...]:
    fields = _spans(content)
    needed = {coordinate.template for coordinate in coordinates}
    selected: dict[str, str] = {}
    for span in m._array(content, fields['results'], m._MAX_ROWS):
        row = m._object_spans(content, *span, frozenset({'name'}))
        name = m._text(m._scalar(content, row['name']))
        if name in needed:
            if name in selected:
                raise ValueError
            selected[name] = c._token_digest(content, span)
    # The existing consuming projector qualifies the full native POST envelope.
    collection = m.project_native_import_metadata(content, table='template', expected_serial_digest=serial_digest)
    records: list[m.ImportMetadataTemplate] = []
    for record in collection.rows:
        if type(record) is not m.ImportMetadataTemplate:
            raise ValueError
        records.append(record)
    usable = {template.name: template for template in project_importable_templates(tuple(records))}
    if set(selected) != needed or not needed <= usable.keys():
        raise ValueError
    for coordinate in coordinates:
        for field in usable[coordinate.template].fields:
            if field.mandatory and field.kind in _COORDINATE_FIELDS:
                if not getattr(coordinate, _COORDINATE_FIELDS[field.kind]):
                    raise ValueError
    return tuple(sorted(selected.items()))


def qualify_target_lifecycle_dependencies(
    actor_before: bytearray, role_before: bytearray, templates: bytearray, schema: bytearray,
    actor_after: bytearray, role_after: bytearray, *, expected_actor: str,
    expected_serial_digest: str, coordinates: tuple[c.TargetCoordinates, ...],
) -> TargetLifecycleDependencies:
    """Consume six owned buffers; caller supplies freshness/origin, not this digest."""
    buffers = (actor_before, role_before, templates, schema, actor_after, role_after)
    try:
        if (any(type(buffer) is not bytearray for buffer in buffers)
            or len({id(buffer) for buffer in buffers}) != len(buffers)
            or type(expected_serial_digest) is not str or c._DIGEST.fullmatch(expected_serial_digest) is None
            or type(coordinates) is not tuple or not 1 <= len(coordinates) <= 2):
            raise ValueError
        m._text(expected_actor, maximum=64)
        for coordinate in coordinates:
            if type(coordinate) is not c.TargetCoordinates:
                raise ValueError
            coordinate.__post_init__()
        before = _actor(actor_before, role_before, expected_actor, expected_serial_digest)
        after = _actor(actor_after, role_after, expected_actor, expected_serial_digest)
        if not hmac.compare_digest(before, after):
            raise ValueError
        template_digests = _templates(templates, expected_serial_digest, coordinates)
        schema_digest = _schema(schema, expected_serial_digest)
        coordinates_digest = c._digest(tuple(tuple(getattr(value, key) for key in c._COORDINATES)
                                               for value in coordinates))
        digest = c._digest((_CONTRACT, expected_serial_digest, before, template_digests,
                            schema_digest, coordinates_digest))
        return TargetLifecycleDependencies(expected_serial_digest, before, template_digests,
                                            schema_digest, coordinates_digest, digest)
    except Exception:
        raise TargetLifecycleDependencyError(_ERROR) from None
    finally:
        for buffer in buffers:
            if isinstance(buffer, bytearray):
                _zeroize_mutable(buffer)


def _api_actor(actor: bytearray, api_user: bytearray, profile: bytearray,
               name: str, serial_digest: str) -> str:
    span = _envelope(actor, path='web-ui', name='state', serial_digest=serial_digest, monitor=True)
    state = m._object_spans(actor, *span, frozenset({'admin'}))
    identity = m._object_spans(actor, *state['admin'], _ACTOR)
    expected: dict[str, object] = {'name': name, 'login_name': name,
        'sponsored_group_name': '', 'guest_admin': False}
    _equal(actor, identity, expected)
    api_span = _one(api_user, _envelope(api_user, path='system', name='api-user',
                                      serial_digest=serial_digest))
    api_fields = m._object_spans(api_user, *api_span, frozenset({'name', 'q_origin_key', 'accprofile'}))
    _equal(api_user, api_fields, {'name': name})
    if 'q_origin_key' in api_fields:
        _equal(api_user, api_fields, {'q_origin_key': name})
    profile_name = m._text(m._scalar(api_user, api_fields['accprofile']), maximum=64)
    if _API_NAME.fullmatch(profile_name) is None:
        raise ValueError
    role_span = _one(profile, _envelope(profile, path='system', name='accprofile',
                                      serial_digest=serial_digest))
    role_fields = m._object_spans(profile, *role_span,
        frozenset({'name', 'q_origin_key', 'secretgrp', 'secretgrp-permission'}))
    _equal(profile, role_fields, {'name': profile_name, 'secretgrp': 'custom'})
    if 'q_origin_key' in role_fields:
        _equal(profile, role_fields, {'q_origin_key': profile_name})
    permissions = m._object_spans(profile, *role_fields['secretgrp-permission'], frozenset({'target'}))
    _equal(profile, permissions, {'target': 'read-write'})
    # Only the source-qualified custom-profile representation is accepted.
    # Full row tokens bind other properties without decoding their values.
    return c._digest((_API_CONTRACT, serial_digest, expected,
        c._token_digest(api_user, api_span), c._token_digest(profile, role_span)))


def qualify_target_api_lifecycle_dependencies(
    actor_before: bytearray, api_user_before: bytearray, profile_before: bytearray,
    templates: bytearray, schema: bytearray, profile_after: bytearray,
    api_user_after: bytearray, actor_after: bytearray, *, expected_actor: str,
    expected_serial_digest: str, coordinates: tuple[c.TargetCoordinates, ...],
) -> TargetLifecycleDependencies:
    """Consume eight buffers from one API principal's fresh observation window.

    Declared custom-profile Target access is necessary evidence, not a backend
    mutation result, object ownership, provenance or an M4 execution grant.
    The trusted transport must bind these responses to the actual writer.
    """
    buffers = (actor_before, api_user_before, profile_before, templates, schema,
               profile_after, api_user_after, actor_after)
    try:
        if (any(type(buffer) is not bytearray for buffer in buffers)
            or len({id(buffer) for buffer in buffers}) != len(buffers)
            or type(expected_serial_digest) is not str or c._DIGEST.fullmatch(expected_serial_digest) is None
            or type(expected_actor) is not str or _API_NAME.fullmatch(expected_actor) is None
            or type(coordinates) is not tuple or not 1 <= len(coordinates) <= 2):
            raise ValueError
        for coordinate in coordinates:
            if type(coordinate) is not c.TargetCoordinates:
                raise ValueError
            coordinate.__post_init__()
        before = _api_actor(actor_before, api_user_before, profile_before,
                            expected_actor, expected_serial_digest)
        after = _api_actor(actor_after, api_user_after, profile_after,
                           expected_actor, expected_serial_digest)
        if not hmac.compare_digest(before, after):
            raise ValueError
        template_digests = _templates(templates, expected_serial_digest, coordinates)
        schema_digest = _schema(schema, expected_serial_digest)
        coordinates_digest = c._digest(tuple(tuple(getattr(value, key) for key in c._COORDINATES)
                                               for value in coordinates))
        digest = c._digest((_API_CONTRACT, expected_serial_digest, before, template_digests,
                            schema_digest, coordinates_digest))
        return TargetLifecycleDependencies(expected_serial_digest, before, template_digests,
                                            schema_digest, coordinates_digest, digest)
    except Exception:
        raise TargetLifecycleDependencyError(_ERROR) from None
    finally:
        for buffer in buffers:
            if isinstance(buffer, bytearray):
                _zeroize_mutable(buffer)
