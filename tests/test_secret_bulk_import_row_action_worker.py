"""Independent product process with synthetic product I/O, no device access."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import time

import pytest

from fortipam_mcp.secret_bulk_import_row_action_worker import (
    _OriginalRowActionPins, _OriginalRowActionWorker, _receive, _send,
)
from fortipam_mcp.secret_bulk_import_row_wire import _WIRE_KEYS, _ARRAY_KEYS, _SCALAR_KEYS, _TOTP, _native_controls
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture, _ack_digest
from test_secret_bulk_import_row_actor import actor_harness
from test_secret_bulk_import_row_http_transport import Response
from test_secret_bulk_import_row_readback import detail, MATERIAL
from test_secret_bulk_import_row_wire import project, defaults_response

CONTEXT = hashlib.sha256(b'Synthetic exact original action').hexdigest()
SERIAL = hashlib.sha256(b'SYNTHETIC01').hexdigest()


def data():
    defaults = replace(project(), serial_digest=SERIAL)
    controls = _native_controls(defaults)
    body = {key: [] if key in _ARRAY_KEYS else json.loads(_TOTP) if key == 'totp-setting'
            else controls[key] for key in _WIRE_KEYS}
    body.update(folder=17, name='Synthetic isolated row', template='Synthetic Web Account',
        field=[{'name': 'Password', 'value': 'Synthetic private material'}])
    metadata = tuple((key, body[key]) for key in _WIRE_KEYS if key in _SCALAR_KEYS - {'description'})
    return defaults, body, metadata


def worker_main(descriptor, fault, pins_path=None):
    """Subprocess constructs product identity; parent never supplies a token."""
    defaults, body, metadata = data()
    fixture, guard, config = actor_harness(None)
    capture = WebSecretCreateAckCapture(SERIAL, 'success')
    pins = _OriginalRowActionPins(CONTEXT, defaults.digest(), capture, metadata, ('Password',), time.monotonic() + 5)
    if pins_path is not None:
        values = json.loads(Path(pins_path).read_text())
        metadata = tuple(tuple(pair) for pair in values['metadata'])
        pins = replace(pins, context_digest=values['context'], metadata=metadata,
            field_names=tuple(values['field_names']), deadline=values['deadline'])
        body = dict(metadata)
        for key in _ARRAY_KEYS: body[key] = []
    requests, responses, connections, posted = [], [], [], []
    class Connection:
        closed = False
        response = None
        def request(self, method, path, payload, headers):
            assert headers['Authorization'] == 'Bearer ' + config.bearer_token
            requests.append(method)
            if method == 'POST':
                assert payload.readonly
                posted.append(payload.obj)
                reply = dict(version='v7.0.0', build=29, http_method='POST', http_status=200,
                    status='success', path='secret', name='database', vdom='root',
                    serial='SYNTHETIC01', mkey=71, error=0, results={'material': MATERIAL})
                if fault == 'wrong-ack': reply['serial'] = 'Other synthetic device'
            elif 'action=default' in path:
                reply = defaults_response()
                reply['serial'] = 'SYNTHETIC01'
                if fault == 'default-drift': reply['results']['recording'] = 'enable'
            else:
                assert path == '/api/v2/cmdb/secret/database/71?vdom=root'
                reply = detail(body)
                reply['serial'] = 'SYNTHETIC01'
                if fault == 'detail-drift': reply['results']['folder'] = 18
            self.response = Response(reply)
            responses.append(self.response)
        def getresponse(self):
            if fault == 'lost-ack' and requests[-1] == 'POST': raise OSError('Synthetic lost response')
            return self.response
        def close(self):
            self.closed = True
            if fault == 'close' and requests[-1] == 'POST': raise OSError('Synthetic close failure')
    def connect(*args, **kwargs):
        assert kwargs['context'] is guard._tls_for_transport(config)
        connection = Connection()
        connections.append(connection)
        return connection
    worker = _OriginalRowActionWorker(config, guard, pins, connection_factory=connect)
    if pins_path is None:
        print('ready', flush=True)
    worker.serve_once(socket.socket(fileno=descriptor))
    retry, observer = socket.socketpair()
    before = len(requests)
    worker.serve_once(retry)
    replay_denied = observer.recv(1) == b'' and len(requests) == before
    observer.close()
    print(json.dumps({'posts': requests.count('POST'), 'gets': requests.count('GET'),
        'closed': all(connection.closed for connection in connections),
        'cleared': all(not any(buffer) for buffer in posted)
            and all(not any(buffer) for response in responses for buffer in response.buffers),
        'actor_reads': len(fixture.calls), 'replay_denied': replay_denied,
        'original_pins': worker._pins is pins, 'deadline_tightened': worker._deadline < pins.deadline}))


@pytest.mark.parametrize('fault', [None, 'context', 'default-drift', 'c2-drift', 'extra-key',
    'duplicate-key', 'field-name', 'field-extra', 'totp', 'lost-ack', 'wrong-ack',
    'receipt', 'disconnect', 'close', 'detail-drift', 'oversized', 'truncated', 'deadline-growth'])
def test_separate_product_process_fixed_handoff_and_terminal_failure(fault, capfd):
    root = Path(__file__).resolve().parents[1]
    parent, child = socket.socketpair()
    env = {'PATH': os.environ.get('PATH', ''),
           'PYTHONPATH': str(root / 'src') + os.pathsep + str(root / 'tests') + os.pathsep + str(root),
           'PYTHONDONTWRITEBYTECODE': '1'}
    process = subprocess.Popen([sys.executable, '-c',
        'import sys; from test_secret_bulk_import_row_action_worker import worker_main; '
        'worker_main(int(sys.argv[1]), sys.argv[2])', str(child.fileno()), fault or 'success'],
        pass_fds=(child.fileno(),), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    child.close()
    deadline = time.monotonic() + 10
    defaults, payload, _ = data()
    result = None
    try:
        # Start the action budget after imports and fixture construction, while
        # keeping subprocess startup bounded separately.
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(10), 'Synthetic product process did not start'
            assert process.stdout.readline() == b'ready\n'
        cap = time.monotonic() + 3
        _send(parent, deadline, b'P' + bytes.fromhex('0' * 64 if fault == 'context' else CONTEXT)
            + struct.pack('!d', deadline + 60 if fault == 'deadline-growth' else cap))
        if fault in {'context', 'default-drift', 'deadline-growth'}:
            with pytest.raises((ValueError, OSError)): _receive(parent, deadline, 64)
        else:
            assert _receive(parent, deadline, 64) == b'R'
            if fault == 'c2-drift': payload['folder'] += 1
            if fault == 'extra-key': payload['unknown'] = 'Synthetic value'
            if fault == 'field-name': payload['field'][0]['name'] = 'Other field'
            if fault == 'field-extra': payload['field'][0]['unknown'] = 'Synthetic value'
            if fault == 'totp': payload['totp-setting']['status'] = 'enable'
            # The encoder deliberately emits its fixed TOTP token compactly.
            raw = bytearray(json.dumps(payload, separators=(',', ':')).encode())
            if fault == 'duplicate-key': raw[-1:] = b',"folder":17}'
            cap -= 0.1
            _send(parent, deadline, b'C' + struct.pack('!d', cap))
            if fault in {'oversized', 'truncated'}:
                parent.sendall(struct.pack('!I', 1048577 if fault == 'oversized' else 1024))
                parent.shutdown(socket.SHUT_WR)
            else:
                _send(parent, deadline, raw)
            raw[:] = b'\x00' * len(raw)
            try:
                ack = _receive(parent, deadline, 64)
                assert ack[0] == ord('A') and len(ack) == 37
                expected = _ack_digest(71, WebSecretCreateAckCapture(SERIAL, 'success'))
                assert ack[5:].hex() == expected
                if fault == 'disconnect': parent.close()
                else:
                    cap -= 0.1
                    _send(parent, deadline, b'K' + bytes.fromhex('0' * 64 if fault == 'receipt' else expected)
                        + struct.pack('!d', cap))
                    result = _receive(parent, deadline, 64)
            except (ValueError, OSError):
                assert fault is not None
        output, errors = process.communicate(timeout=10)
        assert process.returncode == 0 and errors == b''
        observed = json.loads(output)
        before_post = fault in {'context', 'default-drift', 'c2-drift', 'extra-key', 'duplicate-key',
            'field-name', 'field-extra', 'totp', 'oversized', 'truncated', 'deadline-growth'}
        assert observed['posts'] == (0 if before_post else 1)
        assert observed['closed'] and observed['cleared']
        assert observed['replay_denied']
        assert observed['original_pins']
        assert observed['deadline_tightened'] is (fault not in {'context', 'deadline-growth'})
        assert result == (b'V' if fault is None else None)
        assert observed['gets'] == (0 if fault in {'context', 'deadline-growth'} else 2 if fault in {None, 'detail-drift'} else 1)
        assert observed['actor_reads'] == (0 if fault in {'context', 'deadline-growth'} else 6 if fault is None else 3)
        assert capfd.readouterr() == ('', '')
    finally:
        parent.close()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


@pytest.mark.parametrize('fault', [None, 'retention', 'detail-drift', 'lost-ack', 'decode'])
def test_original_m4_retains_ack_before_worker_readback_and_never_replays(tmp_path, monkeypatch, fault, capfd):
    from fortipam_mcp.secret_bulk_import_row_action_worker import (
        _OriginalRowActionClient, _compile_original_action_pins,
    )
    from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
    from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
    from fortipam_mcp.secret_bulk_import_row_http_transport import _Build29OriginalRowHttpTransport
    from fortipam_mcp.secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder
    from test_secret_bulk_import_row_http_transport import configured
    from test_secret_bulk_import_row_provider import execute, assert_reopened_no_dispatch
    from v4_planning import M4Verification
    loader, session, state, reference, bridge, native, runtime, _, _ = configured(tmp_path, monkeypatch)
    defaults = replace(native._encoder._defaults, serial_digest=SERIAL)
    encoder = _Build29OriginalRowWireEncoder(native._encoder._converter, defaults,
        expected_defaults_digest=defaults.digest(), expected_serial_digest=SERIAL)
    capture = WebSecretCreateAckCapture(SERIAL, 'success')
    with pytest.raises(BulkImportIntakeError):
        _compile_original_action_pins(encoder, capture)
    processes, clients, parents = [], [], []
    reads = []
    original_decode = PinnedBulkImportFile.decode
    def observed_decode(self, **options):
        reads.append(True)
        return original_decode(self, **options)
    monkeypatch.setattr(PinnedBulkImportFile, 'decode', observed_decode)
    class Runtime:
        def execute_once(self, *, now_epoch):
            nonlocal native
            pins = _compile_original_action_pins(encoder, capture)
            assert not reads and not loader._used and not bridge._used
            pins_path = tmp_path / 'synthetic-c2-pins.json'
            pins_path.write_text(json.dumps({'context': pins.context_digest, 'metadata': pins.metadata,
                'field_names': pins.field_names, 'deadline': pins.deadline}))
            pins_path.chmod(0o600)
            parent, child = socket.socketpair()
            root = Path(__file__).resolve().parents[1]
            env = {'PATH': os.environ.get('PATH', ''), 'PYTHONDONTWRITEBYTECODE': '1',
                'PYTHONPATH': os.pathsep.join(str(root / item) for item in ('src', 'tests', '.'))}
            process = subprocess.Popen([sys.executable, '-c',
                'import sys; from test_secret_bulk_import_row_action_worker import worker_main; '
                'worker_main(int(sys.argv[1]), sys.argv[2], sys.argv[3])',
                str(child.fileno()), fault or 'success', str(pins_path)], pass_fds=(child.fileno(),), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            child.close()
            client = _OriginalRowActionClient(parent, pins)
            processes.append(process); clients.append(client); parents.append(parent)
            bridge._deadline = min(bridge._deadline, pins.deadline - 0.2)
            native = _Build29OriginalRowHttpTransport(None, encoder, capture, product_client=client)
            assert client._pins is pins and client._deadline <= bridge._deadline < pins.deadline
            client._tighten_deadline(pins.deadline)
            assert client._deadline <= bridge._deadline
            bridge._transport = native
            return runtime.execute_once(now_epoch=now_epoch)
    joined = Runtime()
    if fault == 'retention':
        monkeypatch.setattr(loader._parent, '_put_original_import_row_ack',
            lambda *_: (_ for _ in ()).throw(OSError('Synthetic retention unavailable')))
    if fault == 'decode':
        monkeypatch.setattr(loader, '_load_once', lambda: (_ for _ in ()).throw(ValueError('Synthetic decode unavailable')))
    try:
        with reference:
            verification = M4Verification.VERIFIED if fault is None else M4Verification.UNKNOWN
            assert execute(loader, state, joined).verification is verification
            assert_reopened_no_dispatch(loader, state, joined, verification)
            with pytest.raises(BulkImportIntakeError):
                _compile_original_action_pins(encoder, capture)
        assert len(processes) == len(clients) == len(parents) == 1
        process, client, parent = processes[0], clients[0], parents[0]
        output, errors = process.communicate(timeout=10)
        assert process.returncode == 0 and not errors
        observed = json.loads(output)
        assert observed['posts'] == (0 if fault == 'decode' else 1)
        assert observed['gets'] == (2 if fault in {None, 'detail-drift'} else 1)
        assert observed['closed'] and observed['cleared'] and observed['replay_denied']
        assert native._config is None and native._actor_guard is None
        assert client._phase == 'closed' and parent.fileno() == -1
        assert (native._ack_record is not None) == (fault in {None, 'detail-drift'})
        assert native._post_matches is (fault is None)
        if bridge._owned is not None:
            assert all(not any(buffer) for buffer in bridge._owned._buffers)
        assert capfd.readouterr() == ('', '')
    finally:
        for client in clients: client.close()
        session.close()
        for process in processes:
            if process.poll() is None:
                process.kill(); process.communicate(timeout=5)
