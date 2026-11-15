"""Synthetic retained values never need decoding in the private serializer."""
import hashlib
import json

import pytest

from fortipam_mcp.secret_instruction_build29_retained_fields import compile_instruction_retained_web_body
from test_secret_instruction_build29_api_preservation import IDENTITY, PROFILE, SERIAL, _source, _raw


@pytest.mark.parametrize('current,proposed', [('', PROFILE), (PROFILE, '')])
def test_retains_original_slot_bytes_and_erases_source(current, proposed):
    source = _source(current)
    source['results'][0]['field'][0]['value'] = 'opaque-中文-"-\\'
    raw = _raw(source)
    original = json.dumps(source['results'][0]['field'][0]['value'], ensure_ascii=False).encode()
    body = compile_instruction_retained_web_body(raw, identity=IDENTITY,
        serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest(),
        current_reference=current, proposed_reference=proposed)
    assert not raw and original in body
    parsed = json.loads(body)
    assert set(parsed) == {'id', 'name', 'folder', 'template', 'instruction-profile', 'field'}
    assert parsed['instruction-profile'] == proposed
    assert {row['name']:row['value'] for row in parsed['field']} == {
        row['name']:row['value'] for row in source['results'][0]['field']}
    assert all(set(row) == {'id', 'name', 'value'} for row in parsed['field'])
    body[:] = b'\0' * len(body)


@pytest.mark.parametrize('fault', ['same-reference', 'foreign-id', 'missing-slot', 'extra-slot', 'duplicate-value'])
def test_denied_shape_never_returns_material_and_erases_source(fault):
    source = _source()
    if fault == 'foreign-id': source['results'][0]['id'] += 1
    if fault == 'missing-slot': source['results'][0]['field'].pop()
    if fault == 'extra-slot': source['results'][0]['field'].append(source['results'][0]['field'][0])
    raw = _raw(source)
    if fault == 'duplicate-value': raw = raw.replace(b'"value":"ENC MASKED"', b'"value":"ENC MASKED","value":"other"')
    with pytest.raises(ValueError, match='private retained Web Instruction body is unavailable'):
        compile_instruction_retained_web_body(raw, identity=IDENTITY,
            serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest(), current_reference='',
            proposed_reference='' if fault == 'same-reference' else PROFILE)
    assert not raw
