"""Same-source Folder qualification with real parsers and synthetic transports."""

import copy
from dataclasses import replace
import hashlib
import json
import logging
import pickle
import ssl

import httpx
import pytest

from fortipam_mcp import dlp_api_actor_guard as actor_module
from fortipam_mcp import secret_bulk_import_reference_reader as metadata_reader
from fortipam_mcp import secret_bulk_import_source_catalog as source
from test_dlp_api_actor_guard import Harness, _ACTOR, _envelope, _role
from test_secret_bulk_import_metadata import MATERIAL, response


@pytest.mark.parametrize('fault', [None, 'actor-before', 'secret-read', 'folder-denied',
    'actor-after', 'folder-drift', 'missing-parent', 'incomplete-view', 'device',
    'missing-ca', 'ca-before', 'ca-during', 'expiry', 'rollback', 'replay',
    'foreign-observation', 'ca-after', 'clock-after', 'closed'])
def test_fresh_actor_and_folder_window_qualifies_only_explicit_visible_permissions(
        tmp_path, monkeypatch, caplog, fault):
    role = _role()
    role['secretgrp-permission']['secret-table'] = 'read' if fault == 'secret-read' else 'read-write'
    if fault == 'folder-denied':
        role['secretgrp-permission']['folder-table'] = 'none'
    actor = Harness(role)
    ca = tmp_path / 'synthetic-ca.pem'
    ca.write_bytes(b'Synthetic public CA snapshot')
    config = source.SecretMetadataHttpTransportConfig(actor.config.base_url,
        actor.config.bearer_token, 5, None if fault == 'missing-ca' else str(ca))
    trust = ssl.create_default_context()
    monkeypatch.setattr(actor_module, '_ssl_context', lambda _: trust)
    monkeypatch.setattr(metadata_reader, '_ssl_context', lambda _: ssl.create_default_context())
    clock, events, requests, clients, streams, buffers = [10.0], [], [], [], [], []

    def connection(host, port, **options):
        assert options['context'] is trust
        assert 0 < options['timeout'] <= 5
        options['timeout'] = 5
        result = actor.connect(host, port, **options)
        send = result.request

        def request(method, path, **values):
            events.append('actor')
            if fault == 'actor-before' or fault == 'actor-after' and len(actor.calls) == 3:
                actor.bodies[_ACTOR] = _envelope('state', {'admin': {'name': 'different',
                    'login_name': 'different', 'guest_admin': False, 'sponsored_group_name': ''}}, monitor=True)
            send(method, path, **values)

        result.request = request
        return result

    class Stream(httpx.SyncByteStream):
        def __init__(self, raw):
            self.raw, self.closed = raw, False
            streams.append(self)

        def __iter__(self):
            yield self.raw

        def close(self):
            self.closed = True

    def handle(request):
        events.append('metadata')
        requests.append(request)
        index = (len(requests) - 1) % 3
        table = 'template' if index == 0 else 'folder'
        assert request.method == 'POST'
        assert request.url.path == '/api/v2/cmdb/secret/' + table
        assert request.headers['authorization'] == 'Bearer ' + config.bearer_token
        assert request.headers['x-http-method-override'] == 'GET'
        assert request.content == (metadata_reader._PERSONAL_BODY if index == 2 else b'{"json_filter":[]}')
        assert 'cookie' not in request.headers
        payload = response(table)
        payload['serial'] = 'different-device' if fault == 'device' else actor.binding.expected_serial
        root = payload['results'][0]
        if index == 1:
            root.update(name='Public', permissions={'user': 'view'})
            for identifier, (name, permission) in enumerate((('Child', 'add-secret'),
                    ('Editor', 'edit'), ('Owner', 'owner'), ('Missing', None), ('Denied', 'none')), 8):
                child = {**root, 'id': identifier, 'name': name, 'parent-folder': 7,
                         'permissions': {} if permission is None else {'user': permission}}
                payload['results'].append(child)
            if fault == 'missing-parent':
                payload['results'][1]['parent-folder'] = 999
            if fault == 'folder-drift' and len(requests) == 5:
                payload['results'][1]['permissions'] = {'user': 'view'}
        elif index == 2:
            root.update(id=13, name='Personal', **{'folder-type': 'personal'})
        if index:
            payload.update(size=27, filtered_count=len(payload['results']))
            if fault == 'incomplete-view':
                payload['filtered_count'] += 1
        if fault == 'ca-during' and len(requests) == 3:
            ca.write_bytes(b'Changed synthetic public CA')
        return httpx.Response(200, headers={'content-type': 'application/json'},
            stream=Stream(json.dumps(payload).encode()))

    class Client(httpx.Client):
        def __exit__(self, *values):
            super().__exit__(*values)
            if fault == 'expiry':
                clock[0] = 15.0
            elif fault == 'rollback':
                clock[0] = 9.0

    def client(**options):
        assert options['verify'] is trust
        assert options['trust_env'] is False and options['follow_redirects'] is False
        result = Client(transport=httpx.MockTransport(handle), **options)
        clients.append(result)
        return result

    wipe = metadata_reader._zeroize_mutable

    def record_wipe(raw):
        buffers.append(raw)
        wipe(raw)

    monkeypatch.setattr(metadata_reader, '_zeroize_mutable', record_wipe)
    loads = json.loads

    def selected_only(raw, *args, **options):
        assert MATERIAL not in str(raw)
        return loads(raw, *args, **options)

    monkeypatch.setattr(metadata_reader.m.json, 'loads', selected_only)
    caplog.set_level(logging.DEBUG)
    if fault == 'missing-ca':
        with pytest.raises(source.BulkImportSourceCatalogError):
            source.ImportTemplateFolderSourceReader(config, actor.binding,
                connection_factory=connection, client_factory=client, clock=lambda: clock[0])
        assert not events
        return
    reader = source.ImportTemplateFolderSourceReader(config, actor.binding,
        connection_factory=connection, client_factory=client, clock=lambda: clock[0])
    assert not events
    if fault == 'ca-before':
        ca.write_bytes(b'Changed synthetic public CA')
    successful_read = fault in {None, 'replay', 'foreign-observation', 'ca-after', 'clock-after', 'closed'}
    if successful_read:
        observed = reader.read_once()
        reader.check_current(observed)
        assert events == ['actor'] * 3 + ['metadata'] * 6 + ['actor'] * 3
        assert observed.observed_at == 10.0 and observed.expires_at == 15.0
        assert observed.serial_digest == hashlib.sha256(actor.binding.expected_serial.encode()).hexdigest()
        assert observed.source_context_digest == source._api_source_context(config.base_url,
            hashlib.sha256(config.bearer_token.encode()).hexdigest(), hashlib.sha256(ca.read_bytes()).hexdigest(),
            observed.serial_digest)
        assert observed.actor_evidence_digest == reader._guard._before.evidence_digest
        assert {folder.path: folder.can_add for folder in observed.metadata.folders} == {
            'Public': False, 'Public/Child': True, 'Public/Editor': True, 'Public/Owner': True,
            'Public/Missing': False, 'Public/Denied': False, 'Personal': True}
        assert observed.metadata.public_folder_view.size == observed.metadata.personal_folder_view.size == 27
        assert not any(hasattr(observed, field) for field in ('coverage', 'can_associate', 'catalog'))
        for item in (reader, observed):
            assert 'synthetic' not in repr(item).lower()
            for operation in (copy.copy, copy.deepcopy, pickle.dumps):
                with pytest.raises(RuntimeError):
                    operation(item)
        if fault == 'replay':
            with pytest.raises(source.BulkImportSourceCatalogError):
                reader.read_once()
        elif fault == 'foreign-observation':
            with pytest.raises(source.BulkImportSourceCatalogError):
                reader.check_current(replace(observed))
        elif fault == 'ca-after':
            ca.write_bytes(b'Changed synthetic public CA')
        elif fault == 'clock-after':
            clock[0] = 15.0
        elif fault == 'closed':
            reader.close()
        if fault is not None:
            with pytest.raises(source.BulkImportSourceCatalogError):
                reader.check_current(observed)
    else:
        with pytest.raises(source.BulkImportSourceCatalogError) as caught:
            reader.read_once()
        assert str(caught.value) == source._ERROR and caught.value.__suppress_context__
    before = tuple(events)
    with pytest.raises(source.BulkImportSourceCatalogError):
        reader.read_once()
    assert tuple(events) == before
    actor.disposed()
    assert all(client.is_closed and not client.cookies for client in clients)
    assert all(stream.closed for stream in streams) and all(not any(raw) for raw in buffers)
    assert MATERIAL not in caplog.text and 'synthetic-token' not in caplog.text
    reader.close()
