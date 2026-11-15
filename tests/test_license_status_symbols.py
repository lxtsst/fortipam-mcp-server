"""Synthetic static build maps; no native status values or license reads."""
import hashlib
import json

import pytest

from fortipam_mcp import license_status_symbols as module

PRIVATE = 'SYNTHETIC_UNSELECTED_BUILD_DATA_MUST_NOT_BE_DECODED_OR_HASHED'


def frame():
    return dict(SYMBOLS={**{name: index - 3 for index, name in enumerate(module._NAMES)},
        PRIVATE: {'nested': PRIVATE}}, private_build_data=PRIVATE)


def consume(payload):
    raw = bytearray(json.dumps(payload, separators=(',', ':')).encode())
    result = module.consume_license_status_symbols(raw)
    assert not any(raw)
    return result


def test_only_compiled_integer_symbols_escape_and_do_not_qualify_native_state():
    result = consume(frame())
    assert result['symbols'] == {name: index - 3 for index, name in enumerate(module._NAMES)}
    assert result['selected_symbol_count'] == result['classified_integer_count'] == 11
    assert result['unclassified_selected_count'] == 0 and result['unselected_symbol_count'] == 1
    assert result['complete_selected_integer_table'] and result['local_integer_profile_only']
    assert all(result[key] is False for key in ('unselected_values_decoded_or_hashed', 'native_source_build_verified',
        'native_status_mapping_qualified', 'current_license_read', 'installation_authorized', 'configuration_written', 'device_contacted'))
    assert PRIVATE not in repr(result)


@pytest.mark.parametrize('name', module._NAMES)
def test_missing_symbols_are_not_filled_or_treated_as_complete(name):
    data = frame(); data['SYMBOLS'].pop(name)
    result = consume(data)
    assert name not in result['symbols'] and result['selected_symbol_count'] == 10
    assert not result['complete_selected_integer_table']


@pytest.mark.parametrize('value', [None, False, True, PRIVATE, 1.0, [], {}, 2**63, -(2**63)-1])
def test_non_integer_or_out_of_profile_symbol_stays_unclassified(value):
    data = frame(); data['SYMBOLS'][module._NAMES[0]] = value
    result = consume(data)
    assert result['symbols'][module._NAMES[0]] is None
    assert result['unclassified_selected_count'] == 1 and not result['complete_selected_integer_table']
    assert PRIVATE not in repr(result)


@pytest.mark.parametrize('value', [-(2**63), 0, 2**63-1])
def test_signed_integer_boundaries_and_aliases_are_preserved_without_inference(value):
    data = frame()
    for name in module._NAMES: data['SYMBOLS'][name] = value
    result = consume(data)
    assert set(result['symbols'].values()) == {value}
    assert result['complete_selected_integer_table'] and not result['native_status_mapping_qualified']


def test_wide_static_symbols_map_does_not_inherit_cmdb_row_width_limit():
    data = frame(); data['SYMBOLS'].update({f'SYNTHETIC_UNRELATED_{i}': i for i in range(1500)})
    result = consume(data)
    assert result['unselected_symbol_count'] == 1501 and result['classified_integer_count'] == 11


@pytest.mark.parametrize('raw', [b'{}', b'[]', b'{"SYMBOLS":null}', b'{"SYMBOLS":[]}',
    b'{"SYMBOLS":{},}', b'{"SYMBOLS":{},"private":nope}', b'{"SYMBOLS":{"private":garbage}}',
    b'{"SYMBOLS":{"private":1,}}', b'{"SYMBOLS":{}} trailing', b'{"SYMBOLS":{},"SYMBOLS":{}}',
    b'{"SYMBOLS":{},"SYMB\\u004fLS":{}}', b'{"SYMBOLS":{"LICENSE_STATUS_VM_VALID":1,"LICENSE_STATUS_VM_VALID":2}}',
    b'{"SYMBOLS":{"LICENSE_STATUS_VM_VALID":1,"LICENSE_STATUS_VM_\\u0056ALID":2}}'])
def test_malformed_unknown_json_or_duplicate_selected_keys_refuse_and_wipe(raw):
    raw = bytearray(raw)
    with pytest.raises(ValueError, match='private license status symbols'): module.consume_license_status_symbols(raw)
    assert not any(raw)


def test_escaped_compiled_keys_still_select_only_the_fixed_symbols():
    raw = bytearray(json.dumps(frame()).replace('SYMBOLS', 'SYMB\\u004fLS').replace(
        'LICENSE_STATUS_VM_VALID', 'LICENSE_STATUS_VM_\\u0056ALID').encode())
    result = module.consume_license_status_symbols(raw)
    assert result['classified_integer_count'] == 11 and not any(raw)


def test_unknown_and_unclassified_values_never_reach_decode_or_hash(monkeypatch):
    data = frame(); data['SYMBOLS'][module._NAMES[0]] = PRIVATE
    raw = bytearray(json.dumps(data).encode())
    decode, digest = json.loads, hashlib.sha256
    def check(value):
        raw = value.encode() if isinstance(value, str) else value
        assert PRIVATE.encode() not in raw
    def safe_decode(value, *args, **kwargs): check(value); return decode(value, *args, **kwargs)
    def safe_digest(value=b'', *args, **kwargs): check(value); return digest(value, *args, **kwargs)
    monkeypatch.setattr(json, 'loads', safe_decode); monkeypatch.setattr(hashlib, 'sha256', safe_digest)
    result = module.consume_license_status_symbols(raw)
    assert PRIVATE not in repr(result) and not any(raw)


@pytest.mark.parametrize('error_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_validation_interrupt_clears_input_and_never_publishes(monkeypatch, error_type):
    raw = bytearray(json.dumps(frame()).encode())
    def fail(*args, **kwargs): raise error_type(PRIVATE)
    monkeypatch.setattr(module.metadata, '_validate_json', fail)
    with pytest.raises(ValueError if error_type is RuntimeError else error_type): module.consume_license_status_symbols(raw)
    assert not any(raw)


@pytest.mark.parametrize('fault', ['bytes', 'oversize', 'members', 'depth'])
def test_local_resource_and_input_bounds_are_fail_closed(fault):
    data = frame()
    if fault == 'bytes': raw = json.dumps(data).encode()
    elif fault == 'oversize': raw = bytearray(b' ' * (module.MAX_BYTES + 1))
    elif fault == 'members': raw = bytearray(json.dumps({'SYMBOLS': {str(i): 0 for i in range(8193)}}).encode())
    else: raw = bytearray(b'{"SYMBOLS":{},"private":' + b'[' * 18 + b'0' + b']' * 18 + b'}')
    with pytest.raises(ValueError): module.consume_license_status_symbols(raw)
    if type(raw) is bytearray: assert not any(raw)


@pytest.mark.parametrize('value,kind', [
    (PRIVATE, 'string'), (False, 'boolean'), (True, 'boolean'), (None, 'null'),
    ([PRIVATE], 'array'), ({PRIVATE: PRIVATE}, 'object'), (1.5, 'number'),
    (2**63, 'number'), ('1', 'string'),
])
def test_unclassified_symbol_has_value_free_type_diagnostics_without_coercion(value, kind):
    data = frame()
    for name in module._NAMES: data['SYMBOLS'][name] = value
    result = consume(data)
    assert result['selected_value_kinds'] == {name: kind for name in module._NAMES}
    assert result['selected_value_kind_counts'] == {kind: 11}
    assert result['value_kind_diagnostics_only'] is True
    assert result['classified_integer_count'] == 0 and result['unclassified_selected_count'] == 11
    assert all(value is None for value in result['symbols'].values())
    assert not result['native_status_mapping_qualified'] and PRIVATE not in repr(result)


def test_kind_counts_cover_present_symbols_only_and_do_not_fill_missing_values():
    data = frame()
    data['SYMBOLS'][module._NAMES[0]] = PRIVATE
    data['SYMBOLS'][module._NAMES[1]] = None
    data['SYMBOLS'].pop(module._NAMES[2])
    result = consume(data)
    assert result['selected_value_kind_counts'] == {'string': 1, 'null': 1, 'number': 8}
    assert len(result['selected_value_kinds']) == result['selected_symbol_count'] == 10
    assert module._NAMES[2] not in result['selected_value_kinds']
    assert not result['complete_selected_integer_table']


def test_escaped_numeric_text_remains_a_string_without_value_decoding(monkeypatch):
    name = module._NAMES[0]
    raw = bytearray(('{"SYMBOLS":{"' + name + '":"\\u0031"}}').encode())
    def refuse(*args, **kwargs): pytest.fail('Type-only diagnostics must not decode a string.')
    monkeypatch.setattr(json, 'loads', refuse)
    result = module.consume_license_status_symbols(raw)
    assert result['selected_value_kinds'] == {name: 'string'} and result['symbols'][name] is None
    assert not any(raw)
