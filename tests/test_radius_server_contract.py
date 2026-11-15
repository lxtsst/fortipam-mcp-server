"""Synthetic ACK, absence and complete-state denial checks; no I/O or real material."""
from __future__ import annotations

import copy
import json
import pickle
from typing import Any

import pytest

from fortipam_mcp.radius_server_contract import (
    RadiusServerCandidateError, RadiusServerCreateBinding, project_radius_absence,
    project_radius_ack, qualify_radius_created_state,
)
from fortipam_mcp.radius_server_projection import project_radius_defaults, project_radius_detail
from test_radius_server_projection import SERIAL, default_row, encoded, envelope, schema
from v4_planning.material_provider import MaterialAccessDenied


def binding() -> RadiusServerCreateBinding:
    return RadiusServerCreateBinding('mcp-v4-radius-synthetic', '192.0.2.10', 'a' * 64)


def test_private_binding_cannot_serialize_or_mutate() -> None:
    value = binding()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(value)
    with pytest.raises(TypeError):
        json.dumps(value)
    with pytest.raises(RadiusServerCandidateError):
        value.server = '192.0.2.11'
    assert len(value.parameters_digest) == 64 and value.server not in repr(value)


@pytest.mark.parametrize('name,server,nonce', [
    ('production', '192.0.2.10', 'a' * 64),
    ('mcp-v4-radius-synthetic', '127.0.0.1', 'a' * 64),
    ('mcp-v4-radius-synthetic', '8.8.8.8', 'a' * 64),
    ('mcp-v4-radius-synthetic', '192.0.2.10', 'a' * 63),
])
def test_binding_rejects_unqualified_selectors(name: str, server: str, nonce: str) -> None:
    with pytest.raises(RadiusServerCandidateError):
        RadiusServerCreateBinding(name, server, nonce)


@pytest.mark.parametrize('change', [None, 'omitted_scalar', 'opaque_secondary', 'secret_unchanged',
                                    'reference', 'missing_reference', 'extra_server'])
def test_all_created_fields_and_opaque_tokens_are_pinned(change: str | None) -> None:
    shape = schema()
    defaults = project_radius_defaults(encoded(envelope(action='default', results=default_row())),
                                       shape, expected_serial=SERIAL)
    row = default_row() | binding().desired_nonmaterial() | {'secret': 'SYNTHETIC_NEW_OPAQUE', 'q_ref': 0}
    if change == 'omitted_scalar':
        row['timeout'] = 15
    elif change == 'opaque_secondary':
        row['secondary-secret'] = 'SYNTHETIC_DRIFT'
    elif change == 'secret_unchanged':
        row['secret'] = default_row()['secret']
    elif change == 'reference':
        row['q_ref'] = 1
    elif change == 'missing_reference':
        del row['q_ref']
    elif change == 'extra_server':
        row['tertiary-server'] = '192.0.2.11'
    state = project_radius_detail(encoded(envelope(results=[row])), shape, expected_serial=SERIAL)
    if change is None:
        qualify_radius_created_state(state, defaults, shape, binding(), expected_serial=SERIAL)
    else:
        with pytest.raises(RadiusServerCandidateError):
            qualify_radius_created_state(state, defaults, shape, binding(), expected_serial=SERIAL)


@pytest.mark.parametrize('method', ['POST', 'DELETE'])
def test_exact_mutation_ack_consumes_buffer(method: str) -> None:
    raw = encoded(envelope(http_method=method, mkey=binding().name, results={}))
    digest = project_radius_ack(raw, binding(), expected_serial=SERIAL, http_status=200, method=method)
    assert len(digest) == 64 and not raw


@pytest.mark.parametrize('change', [
    {'status': 'error'}, {'http_status': 500}, {'error': -1}, {'mkey': 'OTHER'},
    {'results': {'secret': 'SYNTHETIC_OPAQUE'}}, {'http_method': 'PUT'},
    {'build': 30}, {'serial': 'OTHER_DEVICE'},
])
def test_contradictory_or_foreign_ack_refuses_and_clears(change: dict[str, Any]) -> None:
    raw = encoded(envelope(http_method='POST', mkey=binding().name, results={}) | change)
    with pytest.raises(RadiusServerCandidateError):
        project_radius_ack(raw, binding(), expected_serial=SERIAL, http_status=200, method='POST')
    assert not raw


def test_ack_without_exact_selector_is_not_ownership() -> None:
    raw = encoded(envelope(http_method='POST'))
    with pytest.raises(RadiusServerCandidateError):
        project_radius_ack(raw, binding(), expected_serial=SERIAL, http_status=200, method='POST')
    assert not raw


@pytest.mark.parametrize('collection,rows,status', [
    (False, None, 404), (True, [], 200), (True, [{'name': 'synthetic-other'}], 200),
])
def test_each_fixed_absence_form_consumes_input(collection: bool, rows: object, status: int) -> None:
    document = envelope(status='success' if collection else 'error')
    if collection:
        document['results'] = rows
    raw = encoded(document)
    project_radius_absence(raw, binding(), expected_serial=SERIAL, http_status=status, collection=collection)
    assert not raw


@pytest.mark.parametrize('document,code,collection', [
    (envelope(status='error', results=[]), 404, False),
    (envelope(status='error', path='user/unknown'), 404, False),
    (envelope(status='error'), 200, False),
    (envelope(results=[{'name': 'mcp-v4-radius-synthetic'}]), 200, True),
    (envelope(results=[{'name': 'synthetic-other', 'secret': 'SYNTHETIC_OPAQUE'}]), 200, True),
])
def test_generic_404_or_filtered_incomplete_absence_is_refused(document: object, code: int,
                                                             collection: bool) -> None:
    raw = encoded(document)
    with pytest.raises(RadiusServerCandidateError):
        project_radius_absence(raw, binding(), expected_serial=SERIAL, http_status=code, collection=collection)
    assert not raw


@pytest.mark.parametrize('changes', [
    {'limit_reached': True}, {'next_idx': 1}, {'matched_count': 1}, {'size': 1},
    {'limit_reached': 0}, {'next_idx': False},
])
def test_truncated_or_contradictory_collection_does_not_prove_absence(changes: dict[str, object]) -> None:
    raw = encoded(envelope(results=[]) | changes)
    with pytest.raises(RadiusServerCandidateError):
        project_radius_absence(raw, binding(), expected_serial=SERIAL, http_status=200, collection=True)
    assert not raw


@pytest.mark.parametrize('token', [b'NaN', b'true', b'{}'])
def test_unvalidated_metadata_cannot_pass_collection_absence(token: bytes) -> None:
    raw = encoded(envelope(results=[{'name': 'synthetic-other', 'q_ref': 0}]))
    raw = raw.replace(b'"q_ref": 0', b'"q_ref": '+token)
    with pytest.raises(RadiusServerCandidateError):
        project_radius_absence(raw, binding(), expected_serial=SERIAL, http_status=200, collection=True)
    assert not raw
