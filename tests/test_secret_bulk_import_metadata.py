"""Protected fixed native metadata projection and malformed-response denials."""
from __future__ import annotations

import copy
import hashlib
import json
import pickle

import pytest
from v4_planning.material_provider import MaterialAccessDenied

from fortipam_mcp import secret_bulk_import_metadata as metadata

SERIAL = 'synthetic-device'
SERIAL_DIGEST = hashlib.sha256(SERIAL.encode()).hexdigest()
MATERIAL = 'SYNTHETIC_UNSELECTED_C3_MARKER'


def response(table: str = 'database') -> dict[str, object]:
    row: dict[str, object] = {'name': 'Synthetic', 'permissions': {'user': 'owner'},
        'unknown': {'a key with spaces': {'nested / key': MATERIAL}}, 'field': [{
            'name': 'Password', 'type': 'password', 'mandatory': 'enable', 'value': MATERIAL}],
        'password': MATERIAL, 'totp-setting': {'shared-key': MATERIAL}}
    if table == 'database':
        row['id'] = 7
    elif table == 'folder':
        row.update(id=7, **{'parent-folder': 0, 'folder-type': 'public'})
    elif table == 'target':
        row.update(template='Synthetic Template', address='192.0.2.9', domain='', url='')
    return {'version': 'v7.0.0', 'build': 29, 'path': 'secret', 'name': table,
        'http_method': 'POST', 'status': 'OK', 'http_status': 200, 'vdom': 'root',
        'serial': SERIAL, 'results': [row]}


def parse(payload: dict[str, object], table: str = 'database') -> metadata.NativeImportMetadataCollection:
    content = bytearray(json.dumps(payload).encode())
    try:
        return metadata.project_native_import_metadata(content, table=table, expected_serial_digest=SERIAL_DIGEST)  # type: ignore[arg-type]
    finally:
        assert not any(content)


@pytest.mark.parametrize('table', ['template', 'target', 'folder', 'database'])
def test_fixed_projection_skips_all_unselected_material_and_opaque_copy(table: str, monkeypatch: pytest.MonkeyPatch) -> None:
    original = json.loads
    def guarded(raw: object, *args: object, **kwargs: object) -> object:
        assert MATERIAL not in str(raw)
        assert 'a key with spaces' not in str(raw)
        return original(raw, *args, **kwargs)  # type: ignore[arg-type]
    monkeypatch.setattr(metadata.json, 'loads', guarded)
    result = parse(response(table), table)
    assert result.size is result.filtered_count is result.revision is None
    assert len(result.rows) == 1 and result.rows[0].permission == 'owner'
    assert 'Synthetic' not in repr(result) and MATERIAL not in repr(result.rows[0])
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(result)
    if table == 'template':
        row = result.rows[0]
        assert isinstance(row, metadata.ImportMetadataTemplate)
        assert row.fields[0].kind == 'password' and row.fields[0].mandatory is True
        assert not hasattr(row.fields[0], 'value')


def test_visible_folder_counts_do_not_become_global_completeness() -> None:
    payload = response('folder'); payload.update(size=27, filtered_count=1)
    result = parse(payload, 'folder')
    assert result.size == 27 and result.filtered_count == 1 and len(result.rows) == 1
    assert not hasattr(result, 'coverage') and not hasattr(result, 'authority')


@pytest.mark.parametrize('permission', [None, 'none', 'list', 'view', 'edit', 'owner'])
def test_secret_permissions_have_no_owner_fallback(permission: str | None) -> None:
    payload = response(); row = payload['results'][0]  # type: ignore[index]
    row['permissions'] = {} if permission is None else {'user': permission}
    assert parse(payload).rows[0].permission == permission
    del row['permissions']
    assert parse(payload).rows[0].permission is None


@pytest.mark.parametrize(('key', 'value'), [
    ('version', 'v7.0.1'), ('build', True), ('http_method', 'GET'), ('status', 'success'),
    ('http_status', 201), ('vdom', 'other'), ('path', 'system'), ('name', 'other'),
    ('serial', 'other-device'), ('error', True), ('error', -1), ('limit_reached', True),
    ('limit_reached', 0), ('size', 0), ('size', True), ('filtered_count', 0),
    ('filtered_count', True), ('next_idx', 9), ('next_idx', False), ('revision', '\n')])
def test_envelope_drift_or_incomplete_counts_denied_and_cleared(key: str, value: object) -> None:
    payload = response(); payload[key] = value
    with pytest.raises(metadata.BulkImportMetadataError, match='^Protected bulk-import metadata unavailable.$') as error:
        parse(payload)
    assert MATERIAL not in str(error.value) and error.value.__cause__ is None


@pytest.mark.parametrize('change', ['duplicate-id', 'missing-name', 'invalid-id', 'origin', 'permission', 'folder-cycle', 'folder-path', 'kind', 'mandatory', 'field-name'])
def test_row_denials_return_no_partial_result(change: str) -> None:
    table = 'template' if change in ('kind', 'mandatory', 'field-name') else 'folder' if change.startswith('folder-') else 'database'
    payload = response(table); row = payload['results'][0]  # type: ignore[index]
    if change == 'duplicate-id': payload['results'] = [row, copy.deepcopy(row)]
    elif change == 'missing-name': del row['name']
    elif change == 'invalid-id': row['id'] = True
    elif change == 'origin': row['q_origin_key'] = 'other'
    elif change == 'permission': row['permissions'] = {'user': 'unknown'}
    elif change == 'folder-cycle': row['parent-folder'] = row['id']
    elif change == 'folder-path': row['name'] = 'a/b'
    elif change == 'kind': row['field'][0]['type'] = 'unknown'
    elif change == 'mandatory': row['field'][0]['mandatory'] = True
    elif change == 'field-name': row['field'] *= 2
    with pytest.raises(metadata.BulkImportMetadataError): parse(payload, table)


@pytest.mark.parametrize('token', [b'"bad\\q"', b'01', b'NaN', b'[1,]', b'{"key":0,}', b'{1:0}', b'"\xff"', b'{"k" 0}', b'[0 1]', b'true false'])
def test_invalid_unselected_json_is_not_sanitized_into_a_success(token: bytes) -> None:
    raw = json.dumps(response()).encode()
    content = bytearray(raw.replace(b'"' + MATERIAL.encode() + b'"', token, 1))
    with pytest.raises(metadata.BulkImportMetadataError):
        metadata.project_native_import_metadata(content, table='database', expected_serial_digest=SERIAL_DIGEST)
    assert not any(content)


def test_duplicate_selected_key_escape_is_denied() -> None:
    raw = json.dumps(response()).encode().replace(b'"id": 7', b'"id":7,"\\u0069d":8')
    content = bytearray(raw)
    with pytest.raises(metadata.BulkImportMetadataError):
        metadata.project_native_import_metadata(content, table='database', expected_serial_digest=SERIAL_DIGEST)
    assert not any(content)


def test_unselected_nested_json_keys_are_validated_without_decoding() -> None:
    payload = response()
    payload['results'][0]['unknown'] = {MATERIAL: {'': '\\"\n你好', 'a/b': [True, False, None, -1.25e10]}}  # type: ignore[index]
    assert len(parse(payload).rows) == 1


def test_empty_or_duplicate_kind_templates_remain_observations_for_later_selection() -> None:
    payload = response('template'); row = payload['results'][0]  # type: ignore[index]
    row['field'] = []
    result = parse(payload, 'template')
    assert isinstance(result.rows[0], metadata.ImportMetadataTemplate) and result.rows[0].fields == ()
    row['field'] = [{'name': name, 'type': 'password', 'mandatory': 'enable'} for name in ('First', 'Second')]
    result = parse(payload, 'template')
    assert isinstance(result.rows[0], metadata.ImportMetadataTemplate) and len(result.rows[0].fields) == 2


@pytest.mark.parametrize('limit', ['bytes', 'depth', 'rows', 'string'])
def test_resource_bounds_clear_buffer(limit: str) -> None:
    payload = response(); raw = json.dumps(payload).encode()
    if limit == 'bytes': content = bytearray(b' ' * (metadata._MAX_BYTES + 1))
    elif limit == 'depth': content = bytearray(raw.replace(b'"' + MATERIAL.encode() + b'"', b'[' * 17 + b'0' + b']' * 17, 1))
    elif limit == 'rows': payload['results'] *= metadata._MAX_ROWS + 1; content = bytearray(json.dumps(payload).encode())  # type: ignore[operator]
    else: content = bytearray(raw.replace(MATERIAL.encode(), b'x' * 65537, 1))
    with pytest.raises(metadata.BulkImportMetadataError):
        metadata.project_native_import_metadata(content, table='database', expected_serial_digest=SERIAL_DIGEST)
    assert not any(content)


@pytest.mark.parametrize('level', ['envelope', 'row', 'permissions', 'template-field'])
def test_unknown_direct_keys_never_become_decoded_strings(level: str, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = response('template')
    row = payload['results'][0]
    target = payload if level == 'envelope' else row if level == 'row' else row['permissions'] if level == 'permissions' else row['field'][0]
    target[MATERIAL + '_KEY'] = {'unknown nested key': MATERIAL}
    original = json.loads
    def guarded(raw: object, *args: object, **kwargs: object) -> object:
        assert MATERIAL not in str(raw)
        return original(raw, *args, **kwargs)
    monkeypatch.setattr(metadata.json, 'loads', guarded)
    assert len(parse(payload, 'template').rows) == 1


def test_escaped_compiled_keys_resolve_without_decoding_unknown_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    content = bytearray(json.dumps(response()).encode().replace(b'"id": 7', b'"\\u0069d":7'))
    original = json.loads
    def guarded(raw: object, *args: object, **kwargs: object) -> object:
        assert MATERIAL not in str(raw)
        assert b'\\u0069d' not in raw
        return original(raw, *args, **kwargs)
    monkeypatch.setattr(metadata.json, 'loads', guarded)
    result = metadata.project_native_import_metadata(content, table='database', expected_serial_digest=SERIAL_DIGEST)
    assert isinstance(result.rows[0], metadata.ImportMetadataSecret) and result.rows[0].identifier == 7
    assert not any(content)


@pytest.mark.parametrize('fault', [None, 'status', 'serial', 'build', 'method', 'action',
    'error', 'id', 'name', 'permission', 'placeholder', 'multiple', 'empty', 'origin', 'malformed'])
def test_detail_binds_exact_reference_without_decoding_material(fault: str | None,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    payload = response()
    payload['http_method'] = 'GET'
    row = payload['results'][0]  # type: ignore[index]
    payload['results'] = row
    if fault == 'status': payload['status'] = 'success'
    elif fault == 'serial': payload['serial'] = 'other-device'
    elif fault == 'build': payload['build'] = True
    elif fault == 'method': payload['http_method'] = 'POST'
    elif fault == 'action': payload['action'] = 'schema'
    elif fault == 'error': payload['error'] = True
    elif fault == 'id': row['id'] = 8
    elif fault == 'name': row['name'] = 'Other'
    elif fault == 'permission': row['permissions'] = {'user': 'view'}
    elif fault == 'placeholder': del row['id']
    elif fault == 'multiple': payload['results'] = [row, row]
    elif fault == 'empty': payload['results'] = []
    elif fault == 'origin': row['q_origin_key'] = True
    raw = json.dumps(payload).encode()
    if fault == 'malformed': raw = raw.replace(MATERIAL.encode(), b'bad\\q', 1)
    content = bytearray(raw)
    original = json.loads
    def guarded(raw: object, *args: object, **kwargs: object) -> object:
        assert MATERIAL not in str(raw)
        return original(raw, *args, **kwargs)  # type: ignore[arg-type]
    monkeypatch.setattr(metadata.json, 'loads', guarded)
    expected = metadata.ImportMetadataSecret(7, 'Synthetic', 'owner')
    try:
        if fault is None:
            result = metadata.project_native_import_secret_detail(
                content, expected_serial_digest=SERIAL_DIGEST, expected=expected)
            assert result == expected and not hasattr(result, 'can_associate')
            assert 'Synthetic' not in repr(result)
        else:
            with pytest.raises(metadata.BulkImportMetadataError,
                               match='^Protected bulk-import metadata unavailable.$'):
                metadata.project_native_import_secret_detail(
                    content, expected_serial_digest=SERIAL_DIGEST, expected=expected)
    finally:
        assert not any(content)


@pytest.mark.parametrize('permission', [None, 'none', 'list', 'view', 'edit', 'owner'])
def test_detail_singleton_preserves_permission_without_authority(permission: str | None) -> None:
    payload = response()
    payload['http_method'] = 'GET'
    row = payload['results'][0]  # type: ignore[index]
    row['permissions'] = {} if permission is None else {'user': permission}
    content = bytearray(json.dumps(payload).encode())
    result = metadata.project_native_import_secret_detail(content,
        expected_serial_digest=SERIAL_DIGEST, expected=metadata.ImportMetadataSecret(7, 'Synthetic', permission))
    assert result.permission == permission and not any(content)
