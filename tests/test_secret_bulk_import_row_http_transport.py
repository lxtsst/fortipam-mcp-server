"""Fixed original HTTP composition with synthetic replies, no device writes."""

import copy
from dataclasses import replace
import json
import pickle
import time

import pytest

from fortipam_mcp import secret_bulk_import_row_http_transport as transport_module
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_provider import _OriginalRowMaterialRuntime
from fortipam_mcp.secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from test_secret_bulk_import_row_conversion import fixture
from test_secret_bulk_import_row_provider import execute, material_store, assert_reopened_no_dispatch
from test_secret_bulk_import_row_readback import detail
from test_secret_bulk_import_row_wire import SERIAL, defaults_response, project
from v4_planning import M4Verification

MATERIAL = 'Synthetic forbidden native HTTP reply'


class Response:
    def __init__(self, payload):
        self.payload = bytearray(json.dumps(payload).encode())
        self.status = 200
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.payload))}
        self.offset = 0
        self.buffers = []
        self.closed = False
        self.failure = None

    def getheader(self, name):
        return self.headers.get(name)

    def readinto1(self, view):
        self.buffers.append(view.obj)
        if self.failure == 'read': raise OSError('Synthetic bounded reply failure')
        if self.failure == 'interrupt': raise KeyboardInterrupt
        count = min(len(view), len(self.payload)-self.offset)
        view[:count] = memoryview(self.payload)[self.offset:self.offset+count]
        self.offset += count
        return count

    def read(self, *_args):
        pytest.fail('No immutable or unbounded reply read')

    def close(self):
        self.closed = True
        if self.failure == 'close': raise OSError('Synthetic close failure')


class Exchange:
    def __init__(self, bridge, *, fault=None, native_id=71):
        self.bridge, self.fault, self.native_id = bridge, fault, native_id
        self.requests, self.connections, self.responses = [], [], []
        self.post_body = self.post_view = None
        self.post_json = None

    def factory(self, host, port, *, timeout, context):
        assert host == 'synthetic.example.test' and port == 443
        assert 1 <= timeout <= 10 and context.protocols == ['http/1.1']
        outer = self
        class Connection:
            closed = False
            response = None
            def request(self, method, path, body, headers):
                outer.requests.append((method,path))
                assert headers['User-Agent'] == 'fortipam-private-original-row/1'
                assert headers['Accept-Encoding'] == 'identity'
                if method == 'POST':
                    assert path == '/api/v2/cmdb/secret/database' and body.readonly
                    assert headers['Content-Length'] == str(body.nbytes)
                    outer.post_view, outer.post_body = body, body.obj
                    outer.post_json = json.loads(bytes(body))
                    # Product pre-state changes; completion must use post-state.
                    outer.bridge._loader._authority._reader.drift = True
                    payload = dict(version='v7.0.0',build=29,http_method='POST',http_status=200,
                        status='success',path='secret',name='database',vdom='root',
                        serial='Synthetic wire-default device',mkey=outer.native_id,error=0,
                        results={'credential':MATERIAL})
                    if outer.fault == 'wrong-ack-device': payload['serial'] = 'Other device'
                    if outer.fault == 'wrong-ack-status': payload['status'] = 'OK'
                    if outer.fault == 'boolean-id': payload['mkey'] = True
                elif 'action=default' in path:
                    assert path == '/api/v2/cmdb/secret/database?action=default&vdom=root'
                    payload = defaults_response()
                    if outer.fault == 'default-drift': payload['results']['recording'] = 'enable'
                    if outer.fault == 'wrong-default-device': payload['serial'] = 'Other device'
                else:
                    assert path == f'/api/v2/cmdb/secret/database/{outer.native_id}?vdom=root'
                    payload = detail(outer.post_json)
                    payload['results'].update(id=outer.native_id, q_origin_key=outer.native_id)
                    if outer.fault == 'postcondition': payload['results']['folder'] += 1
                    if outer.fault == 'post-authority': outer.bridge._loader._authority._reader.post_drift = True
                    if outer.fault == 'cancelled': outer.bridge._loader._session.close()
                self.response = Response(payload)
                outer.responses.append(self.response)
                post = method == 'POST'
                if post and outer.fault in ('post-rejected','redirect'):
                    self.response.status = 403 if outer.fault == 'post-rejected' else 302
                if post and outer.fault == 'ack-read': self.response.failure = 'read'
                if post and outer.fault == 'interrupt': self.response.failure = 'interrupt'
                if post and outer.fault == 'ack-close': self.response.failure = 'close'
                if post and outer.fault == 'chunked': self.response.headers['Transfer-Encoding'] = 'chunked'
                if post and outer.fault == 'encoded': self.response.headers['Content-Encoding'] = 'gzip'
                if post and outer.fault == 'wrong-content-type': self.response.headers['Content-Type'] = 'text/html'
            def getresponse(self):
                if outer.fault == 'lost-ack' and outer.requests[-1][0] == 'POST':
                    raise OSError('Synthetic lost original ACK')
                return self.response
            def close(self):
                self.closed = True
                if outer.fault == 'connection-close' and outer.requests[-1][0] == 'POST':
                    raise OSError('Synthetic connection close failure')
        connection = Connection(); self.connections.append(connection)
        return connection


def configured(tmp_path, monkeypatch, *, fault=None):
    loader, session, state, reference, bridge, converter, _, _ = fixture(tmp_path, monkeypatch)
    defaults = project()
    encoder = _Build29OriginalRowWireEncoder(converter, defaults,
        expected_defaults_digest=defaults.digest(), expected_serial_digest=SERIAL)
    class Tls:
        protocols = None
        def set_alpn_protocols(self, protocols): self.protocols = protocols
    monkeypatch.setattr(transport_module, '_ssl_context', lambda _: Tls())
    exchange = Exchange(bridge, fault=fault)
    config = SecretMetadataHttpTransportConfig('https://synthetic.example.test','synthetic-token',10,None)
    transport = transport_module._Build29OriginalRowHttpTransport(config, encoder,
        WebSecretCreateAckCapture(SERIAL,'success'), connection_factory=exchange.factory)
    bridge._transport = transport
    runtime = _OriginalRowMaterialRuntime(bridge, material_store(tmp_path))
    return loader, session, state, reference, bridge, transport, runtime, exchange, config


def assert_cleanup(bridge, exchange):
    assert all(connection.closed for connection in exchange.connections)
    assert all(response.closed for response in exchange.responses if response.offset or response.status != 200
        or response.headers.get('Transfer-Encoding') or response.headers.get('Content-Encoding')
        or response.headers.get('Content-Type') != 'application/json')
    assert all(not any(buffer) for response in exchange.responses for buffer in response.buffers)
    assert all(not any(buffer) for buffer in bridge._owned._buffers)
    if exchange.post_body is not None:
        assert not any(exchange.post_body)
        with pytest.raises(ValueError): exchange.post_view.tobytes()


def test_original_claim_default_drift_ack_id_readback_and_material_release_compose_once(tmp_path, monkeypatch, capfd):
    loader, session, state, reference, bridge, transport, runtime, exchange, _ = configured(tmp_path, monkeypatch)
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
            assert_reopened_no_dispatch(loader,state,runtime,M4Verification.VERIFIED)
        assert [method for method,_ in exchange.requests] == ['GET','POST','GET']
        assert transport._ack.native_secret_id == 71 and transport._post_matches
        assert transport._failure_stage is None
        assert_cleanup(bridge,exchange)
        for operation in (copy.copy,copy.deepcopy,pickle.dumps):
            with pytest.raises(RuntimeError): operation(transport)
        assert capfd.readouterr() == ('','')
    finally: session.close()


@pytest.mark.parametrize('fault', ['default-drift','wrong-default-device','lost-ack','wrong-ack-device',
    'wrong-ack-status','boolean-id','post-rejected','redirect','ack-read','ack-close','connection-close',
    'chunked','encoded','wrong-content-type','postcondition','post-authority','cancelled','interrupt'])
def test_failed_or_uncertain_http_use_never_redispatches_and_clears_owned_material(tmp_path, monkeypatch, fault, capfd):
    loader, session, state, reference, bridge, transport, runtime, exchange, _ = configured(tmp_path,monkeypatch,fault=fault)
    try:
        with reference:
            if fault == 'interrupt':
                with pytest.raises(KeyboardInterrupt): execute(loader,state,runtime)
            else: assert execute(loader,state,runtime).verification is M4Verification.UNKNOWN
            assert_reopened_no_dispatch(loader,state,runtime,M4Verification.UNKNOWN)
        assert sum(method=='POST' for method,_ in exchange.requests) == (0 if fault in ('default-drift','wrong-default-device') else 1)
        assert not transport._post_matches
        assert transport._failure_stage in {'original_permission','defaults_read','defaults_drift',
            'row_conversion','create_request','create_ack','ack_retention','create_close',
            'detail_read','detail_compare','completion_permission'}
        assert_cleanup(bridge,exchange)
        assert capfd.readouterr() == ('','')
    finally: session.close()


@pytest.mark.parametrize('fault', ['observe','wrong-device','boolean-timeout','userinfo'])
def test_constructor_cannot_observe_source_or_substitute_device_or_unsafe_config(tmp_path,monkeypatch,fault):
    _,session,_,_,_,transport,_,exchange,config=configured(tmp_path,monkeypatch)
    capture=WebSecretCreateAckCapture(SERIAL,'success')
    if fault=='observe': capture=WebSecretCreateAckCapture(SERIAL,None,observe_source=True)
    elif fault=='wrong-device': capture=WebSecretCreateAckCapture('a'*64,'success')
    elif fault=='boolean-timeout': config=replace(config,timeout_seconds=True)
    elif fault=='userinfo': config=replace(config,base_url='https://user@synthetic.example.test')
    try:
        with pytest.raises(BulkImportIntakeError):
            transport_module._Build29OriginalRowHttpTransport(config,transport._encoder,capture,connection_factory=exchange.factory)
        assert not exchange.requests
    finally: session.close()


def test_private_http_helper_cannot_send_unissued_body_before_or_after_original_use(tmp_path,monkeypatch):
    loader,session,state,reference,bridge,transport,runtime,exchange,_=configured(tmp_path,monkeypatch)
    unissued=bytearray(b'{"synthetic":0}')
    try:
        with memoryview(unissued).toreadonly() as view:
            with pytest.raises(ValueError):
                with transport._response('create',time.monotonic()+5,view):pass
            assert not exchange.requests and not transport._post_attempted
            with reference: assert execute(loader,state,runtime).verification is M4Verification.VERIFIED
            with pytest.raises(ValueError):
                with transport._response('create',time.monotonic()+5,view):pass
        assert sum(method=='POST' for method,_ in exchange.requests)==1
        assert transport._post_attempted and transport._dispatch_body is None
        assert_cleanup(bridge,exchange)
    finally: session.close()
