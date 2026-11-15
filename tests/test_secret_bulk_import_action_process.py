"""Native inherited-descriptor custody for separate action/intake workloads."""

import json
import array
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

import pytest

from test_secret_bulk_import_submission_process import native_private_input_profile


@pytest.mark.skipif(sys.platform != 'darwin', reason='Native Mini lab restriction')
@pytest.mark.parametrize('restricted', [False, True])
def test_received_socket_keeps_intake_custody_after_owner_close(tmp_path, restricted):
    allowed = tmp_path / 'metadata'; allowed.write_text('Synthetic metadata')
    profile = native_private_input_profile(tmp_path, allowed_paths=(allowed,), remote_sockets=())
    control, child_control = socket.socketpair()
    product, intake = socket.socketpair()
    project = Path(__file__).resolve().parents[1]
    code = '''import socket,sys,time
from fortipam_mcp.secret_bulk_import_action_process import _receive_socket
peer=socket.socket(fileno=int(sys.argv[1]))
client=_receive_socket(peer,time.monotonic()+5)
peer.close()
client.sendall(b'P')
client.settimeout(5)
assert client.recv(1)==b'R'
client.close()
'''
    command = ['/usr/bin/sandbox-exec','-f',str(profile)] if restricted else []
    process = subprocess.Popen(command + [sys.executable,
        '-c',code,str(child_control.fileno())], pass_fds=(child_control.fileno(),),
        env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1',
            'PYTHONPATH':os.pathsep.join((str(project/'src'),str(project)))},
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    child_control.close()
    try:
        assert control.sendmsg([b'F'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[intake.fileno()]))])==1
        control.settimeout(5)
        assert control.recv(1)==b'D'
        control.close(); intake.close()
        product.settimeout(5)
        assert product.recv(1)==b'P'
        try:
            product.sendall(b'R')
        except BrokenPipeError:
            output, errors = process.communicate(timeout=5)
            raise AssertionError(errors.decode()) from None
        output, errors = process.communicate(timeout=5)
        assert process.returncode==0 and not output and not errors, errors
    finally:
        control.close(); child_control.close(); product.close(); intake.close()
        if process.poll() is None:
            process.kill(); process.communicate(timeout=3)


@pytest.mark.skipif(sys.platform != 'darwin', reason='Native Mini lab restriction')
def test_inherited_private_peer_works_without_new_network_authority():
    with tempfile.TemporaryDirectory(prefix='fpa-action-', dir=Path("/tmp").resolve()) as directory:
        root = Path(directory)
        allowed = root / 'allowed-c2'; allowed.write_text('Synthetic metadata')
        allowed.chmod(0o600)
        profile = native_private_input_profile(root, allowed_paths=(allowed,), remote_sockets=())
        assert '(allow network-outbound )' not in profile.read_text()
        parent, child = socket.socketpair()
        code = '''import errno,json,socket,sys
peer=socket.socket(fileno=int(sys.argv[1]))
peer.sendall(b'R')
blocked=False
probe=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
try:
    probe.connect(('127.0.0.1',9))
except PermissionError:
    blocked=True
finally:
    probe.close()
peer.close()
print(json.dumps({'unlisted_network_denied':blocked}))
'''
        process = subprocess.Popen(['/usr/bin/sandbox-exec', '-f', str(profile), sys.executable,
            '-c', code, str(child.fileno())], pass_fds=(child.fileno(),),
            env={'PATH': os.environ.get('PATH', ''), 'PYTHONDONTWRITEBYTECODE': '1'},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child.close()
        try:
            parent.settimeout(5)
            observed = parent.recv(1)
            output, errors = process.communicate(timeout=5)
            assert not errors and process.returncode == 0
            assert observed == b'R' and json.loads(output)['unlisted_network_denied']
        finally:
            parent.close()
            if process.poll() is None:
                process.kill(); process.communicate(timeout=5)


def tls_material(root):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'pam.example.test')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
        .not_valid_after(now+timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('pam.example.test')]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    ca, private = root / 'synthetic-ca.pem', root / 'synthetic-server.key'
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM)); ca.chmod(0o600)
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); private.chmod(0o600)
    return ca, private


@pytest.mark.skipif(sys.platform != 'darwin', reason='Native Mini lab restriction')
@pytest.mark.parametrize('role', ['intake', 'product'])
def test_native_roles_deny_other_inputs_aliases_persistence_signals_and_network(tmp_path, role):
    from types import SimpleNamespace
    from fortipam_mcp.secret_bulk_import_action_process import _native_profile
    intake = [tmp_path / name for name in ('row-source', 'row-pins', 'row-context', 'row-public-key')]
    product = [tmp_path / name for name in ('product-source', 'product-env', 'product-ca')]
    authority = [tmp_path / name for name in ('namespace', 'm4-store', 'material-store', 'signing-key')]
    for path in intake + product + authority:
        path.write_bytes(b'Synthetic fixture'); path.chmod(0o600)
    allowed, forbidden = (intake, product + authority) if role == 'intake' else (product, intake + authority)
    symbolic, hard = tmp_path / 'symbolic-alias', tmp_path / 'hard-alias'
    symbolic.symlink_to(forbidden[0]); os.link(forbidden[0], hard)
    # Short UDS pathname avoids Darwin's 104-byte address limit.
    with tempfile.TemporaryDirectory(prefix='fpa-role-', dir=Path("/tmp").resolve()) as directory:
        row_path = Path(directory) / 'row.sock'
        row_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer, child_peer = socket.socketpair()
        process = None
        try:
            row_listener.bind(str(row_path)); row_listener.listen(1)
            tcp_listener.bind(('127.0.0.1', 0)); tcp_listener.listen(1)
            if role == 'intake':
                profile = native_private_input_profile(tmp_path, allowed_paths=allowed, remote_sockets=(row_path,)).read_text()
            else:
                profile = _native_profile(SimpleNamespace(path=product[0], env_path=product[1], ca_path=product[2]))
            value = {'role': role, 'allowed': list(map(str, allowed)),
                'forbidden': list(map(str, forbidden + [symbolic, hard])),
                'row_socket': str(row_path), 'outside_pid': os.getpid(),
                'port': tcp_listener.getsockname()[1], 'output': str(tmp_path / 'unlisted-write')}
            code = r'''
import json, os, socket, sys
value=json.loads(sys.argv[2])
peer=socket.socket(fileno=int(sys.argv[1]))
for path in value['allowed']:
    with open(path,'rb') as source:
        assert source.read() == b'Synthetic fixture'
denied=0
for path in value['forbidden']:
    try: descriptor=os.open(path,os.O_RDONLY)
    except PermissionError: denied+=1
    else:
        os.close(descriptor)
        raise AssertionError('Cross-role read permitted')
directory=os.open(os.path.dirname(value['forbidden'][0]),os.O_RDONLY|os.O_DIRECTORY)
try:
    try: descriptor=os.open(os.path.basename(value['forbidden'][0]),os.O_RDONLY,dir_fd=directory)
    except PermissionError: denied+=1
    else:
        os.close(descriptor)
        raise AssertionError('Relative cross-role read permitted')
finally: os.close(directory)
try: descriptor=os.open(value['output'],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
except PermissionError: pass
else:
    os.close(descriptor)
    raise AssertionError('Persistence permitted')
try: os.kill(value['outside_pid'],0)
except PermissionError: pass
else: raise AssertionError('Cross-role signal permitted')
with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
    try: probe.connect(('127.0.0.1',value['port']))
    except PermissionError: pass
    else: raise AssertionError('New product connection permitted')
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
    if value['role']=='intake': probe.connect(value['row_socket'])
    else:
        try: probe.connect(value['row_socket'])
        except PermissionError: pass
        else: raise AssertionError('Product accessed owner row channel')
if value['role']=='product':
    try: pid=os.fork()
    except PermissionError: pass
    else:
        if pid==0: os._exit(1)
        os.waitpid(pid,0)
        raise AssertionError('Product fork permitted')
assert denied==len(value['forbidden'])+1
peer.sendall(b'R'); peer.close()
print(json.dumps({'denied_inputs':denied,'allowed_inputs':len(value['allowed'])}))
'''
            process = subprocess.Popen(['/usr/bin/sandbox-exec', '-p', profile, sys.executable,
                '-c', code, str(child_peer.fileno()), json.dumps(value)], pass_fds=(child_peer.fileno(),),
                env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            child_peer.close(); peer.settimeout(8)
            observed = peer.recv(1)
            output, errors = process.communicate(timeout=8)
            assert not errors and process.returncode == 0, errors
            assert observed == b'R' and json.loads(output) == {
                'denied_inputs': len(forbidden) + 3, 'allowed_inputs': len(allowed)}
            assert not Path(value['output']).exists()
        finally:
            peer.close(); child_peer.close(); row_listener.close(); tcp_listener.close()
            if process is not None and process.poll() is None:
                process.kill(); process.communicate(timeout=3)


def test_product_source_uses_owner_only_central_env_without_requiring_private_parent(
        tmp_path, monkeypatch, capfd):
    import fortipam_mcp.secret_bulk_import_action_process as boundary
    from fortipam_mcp.dlp_api_actor_guard import DlpApiActorGuardBinding
    from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError

    central = tmp_path / 'central'; central.mkdir(mode=0o755); central.chmod(0o755)
    env = central / 'synthetic.env'
    content = b'SYNTHETIC_TOKEN=synthetic-token\nSYNTHETIC_USERNAME=synthetic-owner\n'
    env.write_bytes(content); env.chmod(0o600)
    ca = tmp_path / 'synthetic-ca.pem'; ca.write_bytes(b'Synthetic public CA')
    actor = DlpApiActorGuardBinding('synthetic-owner', 'super_admin', 'SYNTHETIC01', 'a' * 64)
    value = dict(contract=boundary._CONTRACT, base_url='https://synthetic.invalid',
        connect_ip='127.0.0.1', env_file=str(env), api_token_variable='SYNTHETIC_TOKEN',
        username_variable='SYNTHETIC_USERNAME', expected_username='synthetic-owner',
        ca_file=str(ca), actor=asdict(actor))

    def source(name, **changes):
        path = tmp_path / name
        raw = json.dumps(value | changes).encode()
        path.write_bytes(raw); path.chmod(0o600)
        return boundary._ProductSource(path, hashlib.sha256(raw).hexdigest())

    read = boundary._read_owner_only_secret_env_file
    buffers = []

    def retain_owned_buffer(path):
        result = read(path)
        buffers.append(result)
        return result

    monkeypatch.setattr(boundary, '_read_owner_only_secret_env_file', retain_owned_buffer)
    original = source('product.json')
    assert not buffers
    config = original._load_product_config()
    assert config.bearer_token == 'synthetic-token' and config.ca_file == str(ca)
    assert central.stat().st_mode & 0o777 == 0o755 and env.stat().st_mode & 0o777 == 0o600
    assert buffers and all(not any(buffer) for buffer in buffers)

    env.chmod(0o644)
    with pytest.raises(BulkImportIntakeError):
        original._load_product_config()
    env.chmod(0o600)
    alternate = central / 'alternate.env'; alternate.write_bytes(content); alternate.chmod(0o600)
    env.unlink(); env.symlink_to(alternate)
    with pytest.raises(BulkImportIntakeError):
        original._load_product_config()
    env.unlink(); env.write_bytes(content); env.chmod(0o600)
    alias = tmp_path / 'central-alias'; alias.symlink_to(central, target_is_directory=True)
    with pytest.raises(BulkImportIntakeError):
        source('alias-product.json', env_file=str(alias / env.name))._load_product_config()
    with pytest.raises(BulkImportIntakeError):
        source('other-actor.json', expected_username='other-synthetic-owner')._load_product_config()
    original.path.write_bytes(original.path.read_bytes() + b' ')
    with pytest.raises(BulkImportIntakeError):
        original._load_product_config()
    assert all(not any(buffer) for buffer in buffers)
    assert capfd.readouterr() == ('', '')


@contextmanager
def synthetic_product_endpoint(tmp_path, fault=None):
    from fortipam_mcp.secret_bulk_import_action_process import _CONTRACT
    from test_secret_bulk_import_row_wire import defaults_response
    from test_secret_bulk_import_row_readback import detail
    from test_dlp_api_actor_guard import Harness, _role, _ACTOR
    ca, private = tls_material(tmp_path)
    role = _role(); role['secretgrp-permission']['secret-table'] = 'read-write'
    actor = Harness(role)
    requests, posts = [], []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def send(self, value):
            raw = json.dumps(value).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw))); self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-token'
            requests.append(('GET', self.path))
            if self.path in actor.bodies:
                value = json.loads(actor.bodies[self.path])
                if fault == 'actor-after' and self.path == _ACTOR and posts:
                    value['results']['admin']['login_name'] = 'Other synthetic actor'
            elif 'action=default' in self.path:
                value = defaults_response(); value['serial'] = 'SYNTHETIC01'
                if fault == 'default-drift': value['results']['recording'] = 'enable'
            else:
                assert self.path == '/api/v2/cmdb/secret/database/71?vdom=root'
                value = detail(posts[0]); value['serial'] = 'SYNTHETIC01'
            self.send(value)
        def do_POST(self):
            assert self.path == '/api/v2/cmdb/secret/database'
            assert self.headers['Authorization'] == 'Bearer synthetic-token'
            requests.append(('POST', self.path))
            posts.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            if fault == 'lost-ack':
                self.close_connection = True
                return
            self.send(dict(version='v7.0.0', build=29, http_method='POST', http_status=200,
                status='success', path='secret', name='database', vdom='root', serial='SYNTHETIC01', mkey=71))
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(ca, private)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    source = tmp_path / 'source.json'
    env = tmp_path / 'central.synthetic.env'
    env.write_text('SYNTHETIC_TOKEN=synthetic-token\nSYNTHETIC_USERNAME=synthetic-owner\n'); env.chmod(0o600)
    source.write_text(json.dumps({'contract': _CONTRACT,
        'base_url': f'https://pam.example.test:{server.server_port}', 'connect_ip': '127.0.0.1',
        'env_file': str(env), 'api_token_variable': 'SYNTHETIC_TOKEN', 'username_variable': 'SYNTHETIC_USERNAME',
        'expected_username': 'synthetic-owner', 'ca_file': str(ca), 'actor': asdict(actor.binding)}))
    source.chmod(0o600)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    try:
        yield source, digest, requests, posts
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.skipif(sys.platform != 'darwin', reason='Native Mini lab restriction')
@pytest.mark.parametrize('fault', [None, 'retention', 'default-drift', 'lost-ack', 'actor-after', 'handoff-close'])
def test_fixed_launcher_real_tls_and_native_restriction_preserve_original_m4(tmp_path, monkeypatch, fault, capfd):
    import fortipam_mcp.secret_bulk_import_action_process as boundary
    from fortipam_mcp.secret_bulk_import_action_process import _launch_original_action_process, _ProductSource
    from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
    from fortipam_mcp.secret_bulk_import_row_http_transport import _Build29OriginalRowHttpTransport
    from fortipam_mcp.secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder
    from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
    from test_secret_bulk_import_row_http_transport import configured
    from test_secret_bulk_import_row_provider import execute, assert_reopened_no_dispatch
    from v4_planning import M4Verification
    with synthetic_product_endpoint(tmp_path, fault) as (source, digest, requests, posts):
        case = tmp_path / 'original'; case.mkdir(mode=0o700)
        loader, session, state, reference, bridge, native, runtime, _, _ = configured(case, monkeypatch)
        serial = hashlib.sha256(b'SYNTHETIC01').hexdigest()
        defaults = replace(native._encoder._defaults, serial_digest=serial)
        encoder = _Build29OriginalRowWireEncoder(native._encoder._converter, defaults,
            expected_defaults_digest=defaults.digest(), expected_serial_digest=serial)
        capture = WebSecretCreateAckCapture(serial, 'success')
        # Root may read the startup C2 definition, but may not load product credentials.
        monkeypatch.setattr(_ProductSource, '_load_product_config', lambda *_: pytest.fail('Root loaded product credentials'))
        original_popen = subprocess.Popen
        def observed_popen(*args, **options):
            # Synthetic fixture only: capture bootstrap diagnostics without changing
            # the deployed launcher's disabled stdout/stderr sinks.
            options['stderr'] = subprocess.PIPE
            return original_popen(*args, **options)
        monkeypatch.setattr(boundary.subprocess, 'Popen', observed_popen)
        handles = []
        class Runtime:
            def execute_once(self, *, now_epoch):
                nonlocal native
                handle = _launch_original_action_process(encoder, capture, source_path=source, source_digest=digest)
                handles.append(handle)
                with pytest.raises(BulkImportIntakeError):
                    _launch_original_action_process(encoder, capture, source_path=source, source_digest=digest)
                if fault == 'handoff-close':
                    peer, closed = socket.socketpair(); closed.close()
                    try:
                        with pytest.raises(BulkImportIntakeError):
                            handle._transfer_client_once(peer)
                        with pytest.raises(BulkImportIntakeError):
                            handle._transfer_client_once(peer)
                        assert peer.fileno() == -1
                        raise RuntimeError('Synthetic failed custody handoff')
                    finally:
                        peer.close(); handle.close()
                native = _Build29OriginalRowHttpTransport(None, encoder, capture, product_client=handle.client)
                bridge._transport = native
                try: return runtime.execute_once(now_epoch=now_epoch)
                finally: handle.close()
        joined = Runtime()
        if fault == 'retention':
            monkeypatch.setattr(loader._parent, '_put_original_import_row_ack',
                lambda *_: (_ for _ in ()).throw(OSError('Synthetic retention refusal')))
        try:
            with reference:
                expected = M4Verification.VERIFIED if fault is None else M4Verification.UNKNOWN
                result = execute(loader, state, joined)
                errors = [handle._process.stderr.read() for handle in handles]
                for handle in handles:
                    handle._process.stderr.close()
                assert result.verification is expected, (native._failure_stage, requests,
                    [handle._process.poll() for handle in handles], errors)
                assert_reopened_no_dispatch(loader, state, joined, expected)
            assert len(handles) == 1 and handles[0]._process.poll() is not None
            assert not handles[0]._watcher.is_alive() and handles[0].client._phase == 'closed'
            assert not handles[0]._connector_thread.is_alive() and errors == [b'']
            expected_exit = {None: 0, 'retention': 21, 'default-drift': 18,
                'lost-ack': 20, 'actor-after': 23, 'handoff-close': 16}
            assert handles[0]._process.returncode == expected_exit[fault]
            assert len(posts) == (0 if fault in {'default-drift', 'handoff-close'} else 1)
            if fault is None:
                assert len(requests) == 9 and sum(method == 'GET' for method, _ in requests) == 8
            assert sum(path.endswith('/71?vdom=root') for _, path in requests) == (1 if fault in {None, 'actor-after'} else 0)
            assert (native._ack_record is not None) is (fault in {None, 'actor-after'})
            if fault == 'handoff-close':
                assert not requests and not loader._used and bridge._owned is None
            else:
                assert native._config is None
            assert capfd.readouterr() == ('', '')
        finally:
            for handle in handles: handle.close()
            session.close()
