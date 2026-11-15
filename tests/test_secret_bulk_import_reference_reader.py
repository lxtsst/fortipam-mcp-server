"""Fixed read sequence, no material decoding, and failure cleanup."""
import json
import logging
import ssl

import httpx
import pytest

from fortipam_mcp import secret_bulk_import_reference_reader as r
from test_secret_bulk_import_metadata import MATERIAL, SERIAL_DIGEST, response


@pytest.mark.parametrize('fault', [None, 'absent', 'detail', 'drift', 'redirect', 'status',
    'encoding', 'type', 'oversize', 'malformed', 'deadline', 'rollback', 'close_deadline'])
def test_bounded_private_reference_sequence(fault, monkeypatch, caplog):
    requests = []; clients = []; streams = []; buffers = []; options = []
    current = [10.0]
    class Stream(httpx.SyncByteStream):
        def __init__(self, raw): self.raw = raw; self.closed = False; streams.append(self)
        def __iter__(self):
            if fault == 'deadline': current[0] += 31
            if fault == 'rollback': current[0] -= 1
            yield self.raw
        def close(self): self.closed = True
    def handle(request):
        requests.append(request)
        detail = len(requests) == 2
        assert request.url.path == r._COLLECTION + ('/7' if detail else '')
        assert request.url.query == r._QUERY[1:].encode()
        assert request.method == ('GET' if detail else 'POST')
        assert request.content == (b'' if detail else b'{"json_filter":[]}')
        assert ('x-http-method-override' in request.headers) != detail
        assert request.headers['authorization'] == 'Bearer PRIVATE_TOKEN'
        assert 'cookie' not in request.headers
        assert request.headers['user-agent'] and request.headers['accept-encoding'] == 'identity'
        data = response(); row = data['results'][0]
        if detail: data.update(http_method='GET', results=row)
        if fault == 'absent': row['id'] = 8
        if fault == 'detail' and detail: row['name'] = 'Changed'
        if fault == 'drift' and len(requests) == 3: row['permissions']['user'] = 'view'
        raw = json.dumps(data).encode()
        if fault == 'oversize': raw = b' ' * (r.m._MAX_BYTES + 1)
        if fault == 'malformed': raw = b'PRIVATE_INVALID_JSON'
        return httpx.Response(302 if fault == 'redirect' else 403 if fault == 'status' else 200,
            headers={'content-type': 'text/html' if fault == 'type' else 'application/json',
                'content-encoding': 'gzip' if fault == 'encoding' else 'identity',
                'location': 'https://other.invalid/PRIVATE_REDIRECT', 'set-cookie': 's=PRIVATE_COOKIE'},
            stream=Stream(raw))
    class Client(httpx.Client):
        def __exit__(self, *args):
            super().__exit__(*args)
            if fault == 'close_deadline': current[0] += 31
    def factory(**kwargs):
        options.append(kwargs)
        client = Client(transport=httpx.MockTransport(handle), **kwargs); clients.append(client); return client
    monkeypatch.setattr(r, '_ssl_context', lambda _: ssl.create_default_context())
    wipe = r._zeroize_mutable
    def capture(raw): buffers.append(raw); wipe(raw)
    monkeypatch.setattr(r, '_zeroize_mutable', capture)
    scalar = r.m._scalar
    def safe(raw, span):
        assert MATERIAL.encode() not in raw[slice(*span)]
        return scalar(raw, span)
    monkeypatch.setattr(r.m, '_scalar', safe)
    caplog.set_level(logging.DEBUG)
    kwargs = dict(serial_digest=SERIAL_DIGEST, expected=r.m.ImportMetadataSecret(7, 'Synthetic', 'owner'),
        clock=lambda: current[0], client_factory=factory)
    config = r.SecretMetadataHttpTransportConfig('https://synthetic.invalid', 'PRIVATE_TOKEN', 30, None)
    if fault is None:
        result = r.read_import_secret_reference(config, **kwargs)
        assert result == kwargs['expected'] and not hasattr(result, 'can_associate')
        assert len(requests) == 3
    else:
        with pytest.raises(r.BulkImportReferenceReadError, match='^Protected bulk-import reference read unavailable.$') as caught:
            r.read_import_secret_reference(config, **kwargs)
        assert caught.value.__suppress_context__
    assert len(requests) <= 3
    assert all(client.is_closed and not client.cookies for client in clients)
    assert all(stream.closed for stream in streams) and all(not any(raw) for raw in buffers)
    assert 'PRIVATE_' not in caplog.text and 'synthetic.invalid' not in caplog.text
    assert all(not opt['follow_redirects'] and not opt['trust_env'] for opt in options)


@pytest.mark.parametrize('fault', ['userinfo', 'identifier', 'permission', 'serial', 'clock'])
def test_invalid_private_binding_never_opens_client(fault):
    def forbidden(**kwargs):
        pytest.fail('Invalid binding opened an HTTP client')
    config = r.SecretMetadataHttpTransportConfig(
        'https://private@synthetic.invalid' if fault == 'userinfo' else 'https://synthetic.invalid',
        'PRIVATE_TOKEN', 30, None)
    expected = r.m.ImportMetadataSecret(True if fault == 'identifier' else 7, 'Synthetic',
        'unknown' if fault == 'permission' else 'owner')
    with pytest.raises(r.BulkImportReferenceReadError):
        r.read_import_secret_reference(config, expected=expected,
            serial_digest='invalid' if fault == 'serial' else SERIAL_DIGEST,
            clock=lambda: float('nan') if fault == 'clock' else 10.0, client_factory=forbidden)
