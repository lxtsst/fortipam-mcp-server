"""Synthetic same-Bearer name witnesses; no network or private material."""
from dataclasses import replace
import json

import httpx
import pytest

from fortipam_mcp import target_api_dependency_reader as r
from test_target_api_dependency_reader import Harness, Body
from test_target_lifecycle_dependencies import COORDINATES, envelope, DIGEST


class NamesHarness(Harness):
    def __init__(self):
        super().__init__()
        self.name_reads = 0
        self.names_fault = None

    def handle(self, request):
        if request.url.path != '/api/v2/cmdb/secret/target' or request.url.params.get('format') != 'name':
            return super().handle(request)
        self.requests.append(request)
        self.name_reads += 1
        value = envelope('secret', 'target', [{'name': 'Synthetic A'}, {'name': 'Synthetic B'}])
        value.update(http_method='POST', status='OK', limit_reached=False, size=2)
        fault = self.names_fault
        if fault == 'drift' and self.name_reads % 2 == 0: value['results'][1]['name'] = 'Synthetic C'
        if fault == 'serial': value['serial'] = 'WRONG'
        if fault == 'limit': value['limit_reached'] = True
        if fault == 'size': value['size'] = True
        if fault == 'duplicate': value['results'][1]['name'] = 'synthetic a'
        if fault == 'control': value['results'][1]['name'] = 'bad\nname'
        if fault == 'missing': del value['results'][1]['name']
        if fault == 'envelope': value['http_method'] = 'GET'
        if fault == 'error': value['error'] = 'PRIVATE_SENTINEL'
        def eof():
            if fault == 'late': self.now = 40
        stream = Body(json.dumps(value).encode(), eof)
        self.streams.append(stream)
        return httpx.Response(200, headers={'content-type': 'application/json'}, stream=stream)


def test_names_bound_to_actual_reader_dependency_and_fixed_route(monkeypatch):
    h = NamesHarness(); reader = h.reader(); dependency = reader.observe(COORDINATES)
    owned = []; original = reader._receive
    def track(*args, **kwargs):
        value = original(*args, **kwargs); owned.append(value); return value
    monkeypatch.setattr(reader, '_receive', track)
    observed = reader.observe_names(dependency)
    reader.check_names_current(observed)
    assert observed.names == ('Synthetic A', 'Synthetic B')
    assert observed.source_context_digest == dependency.source_context_digest
    assert observed.expires_at == dependency.expires_at
    assert observed.names_digest == r.c._digest(observed.names)
    assert all(not any(value) for value in owned)
    assert all(stream.closed for stream in h.streams)
    assert all(client.is_closed for client in h.clients)
    for request in h.requests[-2:]:
        assert request.method == 'POST' and str(request.url).endswith(r._TARGET_NAMES)
        assert request.content == b'{"json_filter":[]}'
        assert request.headers['x-http-method-override'] == 'GET'
        assert request.headers['authorization'] == 'Bearer synthetic-token'
    with pytest.raises(r.TargetApiDependencyReadError): reader.check_names_current(replace(observed))
    with pytest.raises(r.TargetApiDependencyReadError): h.reader().check_names_current(observed)
    reader.close()
    with pytest.raises(r.TargetApiDependencyReadError): reader.check_names_current(observed)


@pytest.mark.parametrize('fault', ['drift', 'serial', 'limit', 'size', 'duplicate', 'control',
                                  'missing', 'envelope', 'error', 'late'])
def test_failed_name_read_revokes_previous_observation(fault):
    h = NamesHarness(); reader = h.reader(); dependency = reader.observe(COORDINATES)
    prior = reader.observe_names(dependency); h.names_fault = fault
    with pytest.raises(r.TargetApiDependencyReadError) as error: reader.observe_names(dependency)
    assert str(error.value) == r._ERROR
    with pytest.raises(r.TargetApiDependencyReadError): reader.check_names_current(prior)
    assert all(stream.closed for stream in h.streams)
    assert all(client.is_closed for client in h.clients)


@pytest.mark.parametrize('fault', ['copied', 'expired', 'closed', 'superseded', 'rollback'])
def test_invalid_dependency_denies_before_name_network(fault):
    h = NamesHarness(); reader = h.reader(); dependency = reader.observe(COORDINATES)
    if fault == 'copied': dependency = replace(dependency)
    if fault == 'expired': h.now = 40
    if fault == 'closed': reader.close()
    if fault == 'superseded': reader.observe(COORDINATES)
    if fault == 'rollback': h.now = 9
    before = len(h.requests)
    with pytest.raises(r.TargetApiDependencyReadError): reader.observe_names(dependency)
    assert len(h.requests) == before


def test_projection_skips_unselected_material(monkeypatch):
    body = envelope('secret', 'target', [{'name': 'A', 'password': 'PRIVATE_SENTINEL'}, {'name': 'B'}])
    body.update(http_method='POST', status='OK')
    original = r.m._scalar
    def scalar(content, span):
        assert b'PRIVATE_SENTINEL' not in content[slice(*span)]
        return original(content, span)
    monkeypatch.setattr(r.m, '_scalar', scalar)
    assert r._project_names(bytearray(json.dumps(body).encode()), DIGEST) == ('A', 'B')
