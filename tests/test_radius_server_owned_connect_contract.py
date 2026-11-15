"""Fixed omission wire and bounded diagnostic observations; no device or material I/O."""
from __future__ import annotations

import copy
import json
import pickle
from typing import Any

import pytest

from fortipam_mcp.radius_server_owned_connect_contract import (
    RadiusOwnedConnectError, owned_connect_body, project_owned_connect_observation,
)
from test_radius_server_contract import binding
from test_radius_server_projection import SERIAL, envelope
from v4_planning.material_provider import MaterialAccessDenied


def document(status: str = 'reachable', **changes: Any) -> dict[str, Any]:
    return envelope(http_method='POST', action='test-connect', mkey=binding().name,
                    results={'status': status}) | changes


def project(value: object, code: int = 200) -> Any:
    raw = bytearray(json.dumps(value).encode())
    try:
        return project_owned_connect_observation(raw, binding(), expected_serial=SERIAL, http_status=code)
    finally:
        assert not raw


def test_saved_primary_wire_omits_secret_and_has_no_material_argument() -> None:
    wire = owned_connect_body(binding())
    assert json.loads(wire) == {'mkey': binding().name, 'server': binding().server,
                               'auth_type': 'auto', 'ordinal': 'primary'}
    assert b'secret' not in wire and b'password' not in wire
    with pytest.raises(RadiusOwnedConnectError):
        owned_connect_body({'name': binding().name})  # type: ignore[arg-type]


@pytest.mark.parametrize('status', ['success', 'ok', 'reachable', 'connected', 'valid_secret', 'valid', 'passed',
                                    'unreachable', 'invalid_secret', 'no_msg_authenticator_attr', 'SYNTHETIC_UNTRUSTED'])
def test_diagnostic_status_never_proves_connectivity(status: str) -> None:
    observed = project(document(status))
    public = observed.as_dict()
    assert public['connectivity_qualified'] is False and public['observation_only'] is True
    assert public['negative_status'] is (status in {'unreachable', 'invalid_secret', 'no_msg_authenticator_attr'})
    assert public['status_token'] == (None if status == 'SYNTHETIC_UNTRUSTED' else status)
    assert 'SYNTHETIC_UNTRUSTED' not in json.dumps(public)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(observed)


@pytest.mark.parametrize('changes', [
    {'serial': 'OTHER'}, {'build': 30}, {'status': 'error'}, {'http_status': 500},
    {'http_method': 'GET'}, {'mkey': 'OTHER'}, {'action': 'other'}, {'path': 'system'},
    {'error': 0}, {'results': {'status': 'reachable', 'success': True}},
    {'results': {'status': 'reachable', 'error': 0}}, {'results': []},
    {'results': {'SYNTHETIC_PRIVATE_FIELD': 'SYNTHETIC_PRIVATE_VALUE'}},
])
def test_contradictions_and_unknown_keys_are_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(RadiusOwnedConnectError, match='unavailable'):
        project(document() | changes)


def test_error_envelope_is_an_observation_only() -> None:
    observed = project(document(status='ignored', results={'status': 'unreachable'},
                                **{'http_status': 404}) | {'status': 'error'}, code=404)
    assert observed.http_status == 404 and observed.as_dict()['connectivity_qualified'] is False


def test_arbitrary_text_is_never_decoded_or_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    value = document(results={'status': 'reachable', 'message': 'SYNTHETIC_PRIVATE_VALUE',
                              'server': 'SYNTHETIC_PRIVATE_ADDRESS'})
    raw = bytearray(json.dumps(value).encode())
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError('Response decoding is forbidden.')
    monkeypatch.setattr(json, 'loads', forbidden)
    result = project_owned_connect_observation(raw, binding(), expected_serial=SERIAL, http_status=200)
    assert not raw and not result.result_status_only and 'SYNTHETIC_PRIVATE' not in str(result.as_dict())


@pytest.mark.parametrize('extra_unknown', [False, True])
def test_native_access_status_is_opaque_and_does_not_admit_other_fields(
        monkeypatch: pytest.MonkeyPatch, extra_unknown: bool) -> None:
    from fortipam_mcp.radius_server_owned_connect_contract import diagnose_owned_connect_shape
    value = document(results={'status': 'ok', 'access_status': 'SYNTHETIC_PRIVATE_VALUE'})
    if extra_unknown:
        value['results']['SYNTHETIC_PRIVATE_KEY'] = 'SYNTHETIC_PRIVATE_VALUE'
    raw = bytearray(json.dumps(value).encode())
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError('Response decoding is forbidden.')
    monkeypatch.setattr(json, 'loads', forbidden)
    shape = diagnose_owned_connect_shape(raw, binding(), expected_serial=SERIAL, http_status=200)
    assert shape['result_known_fields'] == ['access_status', 'status']
    assert shape['result_unknown_members'] == int(extra_unknown)
    assert 'SYNTHETIC_PRIVATE' not in json.dumps(shape)
    if extra_unknown:
        with pytest.raises(RadiusOwnedConnectError):
            project_owned_connect_observation(raw, binding(), expected_serial=SERIAL, http_status=200)
    else:
        result = project_owned_connect_observation(raw, binding(), expected_serial=SERIAL, http_status=200)
        assert not result.result_status_only and not result.as_dict()['connectivity_qualified']
        assert 'SYNTHETIC_PRIVATE' not in str(result.as_dict())
    assert not raw


@pytest.mark.parametrize('value', [None, False, 1, [], {}])
def test_access_status_requires_the_observed_string_type(value: object) -> None:
    with pytest.raises(RadiusOwnedConnectError):
        project(document(results={'status': 'ok', 'access_status': value}))


@pytest.mark.parametrize('fault', ['duplicate', 'trailing', 'oversized', 'boolean_http_status'])
def test_bounded_json_and_status_types_always_consume_input(fault: str) -> None:
    raw = bytearray(json.dumps(document()).encode())
    if fault == 'duplicate':raw = raw.replace(b'"status": "reachable"', b'"status": "reachable", "status": "ok"')
    elif fault == 'trailing':raw.extend(b' {}')
    elif fault == 'oversized':raw.extend(b' ' * 65536)
    with pytest.raises(RadiusOwnedConnectError):
        project_owned_connect_observation(raw, binding(), expected_serial=SERIAL,
                                         http_status=True if fault == 'boolean_http_status' else 200)
    assert not raw


def test_observation_constructor_cannot_export_unknown_status_text() -> None:
    from fortipam_mcp.radius_server_owned_connect_contract import RadiusOwnedConnectObservation
    with pytest.raises(RadiusOwnedConnectError):
        RadiusOwnedConnectObservation(200, 'SYNTHETIC_PRIVATE_VALUE', True, False)


@pytest.mark.parametrize('route', [
    {'path': 'user/radius', 'name': 'test-connect', 'action': ''},
    {'path': 'user/radius', 'name': 'test-connect'},
    {'path': 'user', 'name': 'radius/test-connect', 'action': ''},
    {'path': 'user', 'name': 'radius', 'action': 'test-connect'},
])
def test_monitor_route_is_exact_when_components_are_joined(route: dict[str, str]) -> None:
    value = document()
    del value['action']
    value.update(route)
    # The existing same-build monitor reader is the route-semantics oracle.
    from fortipam_mcp.local_user_reset_metadata_reader import _monitor_results
    oracle = bytearray(json.dumps(value | {'http_method': 'GET'}).encode())
    _monitor_results(oracle, expected_route='user/radius/test-connect', expected_mkey=binding().name)
    oracle.clear()
    observed = project(value)
    assert observed.status_token == 'reachable' and not observed.as_dict()['connectivity_qualified']


@pytest.mark.parametrize('route', [
    {'path': 'user/radius', 'name': 'test-connect', 'action': 'other'},
    {'path': 'user/radius', 'name': 'test-connect/'},
    {'path': 'user/radius', 'name': 'other'},
    {'path': 'user/radius/test-connect', 'name': ''},
    {'path': 'user', 'name': 'radius', 'action': ''},
])
def test_monitor_route_refuses_prefixes_extra_components_and_empty_names(route: dict[str, str]) -> None:
    with pytest.raises(RadiusOwnedConnectError):project(document() | route)


def test_shape_diagnostics_never_decode_unknown_keys_or_text(monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp.radius_server_owned_connect_contract import diagnose_owned_connect_shape
    value = document(results={'status': 'reachable', 'message': 'SYNTHETIC_PRIVATE_VALUE',
                              'SYNTHETIC_PRIVATE_KEY': {'SYNTHETIC_PRIVATE_CHILD': 'SYNTHETIC_PRIVATE_VALUE'}},
                     path='user/radius', name='test-connect', action='',
                     SYNTHETIC_PRIVATE_KEY='SYNTHETIC_PRIVATE_VALUE')
    raw = bytearray(json.dumps(value).encode());before = bytearray(raw)
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError('No arbitrary JSON token may be decoded.')
    monkeypatch.setattr(json, 'loads', forbidden)
    shape = diagnose_owned_connect_shape(raw, binding(), expected_serial=SERIAL, http_status=200)
    assert raw == before and shape['diagnosis_complete'] and shape['json_valid']
    assert shape['envelope_unknown_members'] == shape['result_unknown_members'] == 1
    assert shape['result_known_fields'] == ['message', 'status'] and shape['route_matches']
    assert shape['status_token'] == 'reachable' and not shape['connectivity_qualified']
    assert 'SYNTHETIC_PRIVATE' not in json.dumps(shape)
    with pytest.raises(RadiusOwnedConnectError):
        project_owned_connect_observation(raw, binding(), expected_serial=SERIAL, http_status=200)
    assert not raw


@pytest.mark.parametrize('raw', [bytearray(b'{'), bytearray(b'{} {}'), bytearray(b' ' * 65537)])
def test_malformed_or_oversized_diagnostic_does_not_throw_or_retain_input(raw: bytearray) -> None:
    from fortipam_mcp.radius_server_owned_connect_contract import diagnose_owned_connect_shape
    before = bytearray(raw)
    shape = diagnose_owned_connect_shape(raw, binding(), expected_serial=SERIAL, http_status=200)
    assert not shape['diagnosis_complete'] and not shape['json_valid']
    assert shape['status_token'] is None and not shape['connectivity_qualified'] and before == raw


def test_exact_reject_response_matches_without_decoding_or_qualifying(
        monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp.radius_server_owned_connect_contract import matches_reject_only_connect_response
    raw = bytearray(json.dumps(document(results={'status': 'ok', 'access_status': 'Access-Reject',
        'access_message': 'SYNTHETIC_PRIVATE_MESSAGE'})).encode())
    before = bytes(raw)
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError('Response decoding is forbidden.')
    monkeypatch.setattr(json, 'loads', forbidden)
    assert matches_reject_only_connect_response(raw, binding(), expected_serial=SERIAL, http_status=200)
    assert raw == before
    observed = project_owned_connect_observation(raw, binding(), expected_serial=SERIAL, http_status=200)
    assert not raw and not observed.as_dict()['connectivity_qualified']
    assert 'SYNTHETIC_PRIVATE' not in str(observed.as_dict())


@pytest.mark.parametrize('change', [
    {'status': 'unreachable'}, {'status': 'success'}, {'status': 'reachable'},
    {'access_status': 'Access-Accept'}, {'access_status': 'Access-Challenge'},
    {'access_status': 'Unknown Response'}, {'access_status': None},
    {'access_message': None}, {'access_message': False}, {'access_message': {}},
    {'SYNTHETIC_PRIVATE_KEY': 'SYNTHETIC_PRIVATE_VALUE'},
])
def test_reject_response_predicate_refuses_unproven_or_contradictory_results(change: dict[str, Any]) -> None:
    from fortipam_mcp.radius_server_owned_connect_contract import matches_reject_only_connect_response
    raw = bytearray(json.dumps(document(results={'status': 'ok', 'access_status': 'Access-Reject',
        'access_message': 'SYNTHETIC_PRIVATE_MESSAGE'} | change)).encode())
    assert not matches_reject_only_connect_response(raw, binding(), expected_serial=SERIAL, http_status=200)
    assert raw
    raw.clear()


@pytest.mark.parametrize('change', [
    {'serial': 'OTHER'}, {'build': 30}, {'http_method': 'GET'}, {'error': 0},
    {'mkey': 'OTHER'}, {'path': 'system'}, {'http_status': 500},
    {'results': {'status': 'ok', 'access_status': 'Access-Reject'}},
    {'results': {'status': 'ok', 'access_message': ''}},
])
def test_reject_response_predicate_keeps_original_envelope_and_exact_field_set(change: dict[str, Any]) -> None:
    from fortipam_mcp.radius_server_owned_connect_contract import matches_reject_only_connect_response
    raw = bytearray(json.dumps(document(results={'status': 'ok', 'access_status': 'Access-Reject',
        'access_message': 'SYNTHETIC_PRIVATE_MESSAGE'}) | change).encode())
    assert not matches_reject_only_connect_response(raw, binding(), expected_serial=SERIAL, http_status=200)
    assert raw
    raw.clear()
