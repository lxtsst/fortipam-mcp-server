"""Inactive Mini-only product launcher; no runtime registration or public API.

Startup reads private C2 references only. The child alone extracts its existing
central API token. Native OS restrictions allow exactly that source and its CA.
An Owner-side connector supplies at most nine fresh sockets to one fixed endpoint;
the child performs TLS and HTTP without gaining permission to open connections.
Source descriptors do not qualify product permissions or authorize deployment.
"""

from __future__ import annotations

from dataclasses import asdict
import array
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys
import threading
import time
from typing import Any, TYPE_CHECKING
from urllib.parse import urlsplit

from v4_planning.execution_kernel import _ACTIVE_DISPATCH, _reserve_m4_product_startup
from v4_planning import M4ExecutionPlan, M4ExecutionAuthorization, M4ExecutionStateStore
from v4_planning.material_provider import _OpaqueC3Object

from .dlp_api_actor_guard import DlpApiActorGuardBinding
from .secret_bulk_import_file import _read_owned, _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_dependencies import ImportDependencyCatalog, ResolvedImportDependencies
from .secret_bulk_import_intake_authority import _members
from .secret_bulk_import_row_action_worker import (
    _OriginalRowActionClient, _OriginalRowActionPins, _OriginalRowActionWorker,
    _compile_original_action_pins, _compile_original_channel_action_pins, _receive, _remaining, _send,
)
from .secret_bulk_import_row_actor import _OriginalRowApiActorGuard
from .secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder, _Build29SecretWireDefaults
from .secret_bulk_import_submission_startup import _map, _path
from .secret_create_central_lab_provider import (
    _parse_prebound_secret_env, _read_owner_only_secret_env_file, _validated_variable_name,
)
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from .web_secret_create_ack import WebSecretCreateAckCapture

if TYPE_CHECKING:
    from .secret_bulk_import_row_channel import OriginalRowChannelOwner

_CONTRACT = 'fortipam-original-row-product-source-v1'
_KEYS = {'contract', 'base_url', 'connect_ip', 'env_file', 'api_token_variable',
         'username_variable', 'expected_username', 'ca_file', 'actor'}


class _ProductSource(_OpaqueC3Object):
    """Pinned metadata and references; construction never reads the env file."""

    def __init__(self, path: Path, digest: str) -> None:
        raw = bytearray()
        try:
            raw, self._identity = _read_owned(path)
            if (type(digest) is not str or len(digest) != 64
                    or len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != digest):
                raise ValueError
            value = _map(json.loads(raw, object_pairs_hook=_members), _KEYS)
            if value['contract'] != _CONTRACT:
                raise ValueError
            self.path, self.digest = path, digest
            self.env_path, self.ca_path = _path(value['env_file']), _path(value['ca_file'])
            if len({self.path, self.env_path, self.ca_path}) != 3:
                raise ValueError
            self.base_url = value['base_url']
            self.origin = urlsplit(self.base_url)
            self.connect_ip = str(ipaddress.IPv4Address(value['connect_ip']))
            if (self.origin.scheme != 'https' or self.origin.hostname is None
                    or self.origin.username is not None or self.origin.password is not None
                    or self.origin.path not in {'', '/'} or self.origin.query or self.origin.fragment):
                raise ValueError
            self.port = self.origin.port or 443
            if not 1 <= self.port <= 65535:
                raise ValueError
            self.token_variable = _validated_variable_name(value['api_token_variable'])
            self.username_variable = _validated_variable_name(value['username_variable'])
            self.username = value['expected_username']
            if (self.token_variable == self.username_variable or type(self.username) is not str
                    or not self.username or len(self.username.encode()) > 256):
                raise ValueError
            self.actor = DlpApiActorGuardBinding(**_map(value['actor'],
                {'expected_actor', 'expected_profile', 'expected_serial', 'expected_role_projection_digest'}))
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            _wipe(raw)

    def _verify(self) -> None:
        raw = bytearray()
        try:
            raw, _ = _read_owned(self.path, self._identity)
            if hashlib.sha256(raw).hexdigest() != self.digest:
                raise ValueError
        finally:
            _wipe(raw)

    def _load_product_config(self) -> SecretMetadataHttpTransportConfig:
        raw, pair = bytearray(), None
        try:
            self._verify()
            if self.env_path.resolve(strict=True) != self.env_path:
                raise ValueError
            raw = _read_owner_only_secret_env_file(self.env_path)
            pair = _parse_prebound_secret_env(raw, self.token_variable, self.username_variable,
                extract_values=True)
            if pair is None or pair[1].decode() != self.username:
                raise ValueError
            result = SecretMetadataHttpTransportConfig(self.base_url, pair[0].decode(), 10, str(self.ca_path))
            self._verify()
            return result
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            _wipe(raw)
            if pair is not None:
                _wipe(pair[0]); _wipe(pair[1])


def _native_profile(source: _ProductSource) -> str:
    def literal(path: Path | str) -> str:
        return '(literal ' + json.dumps(str(Path(path).resolve())) + ')'
    def tree(path: Path | str) -> str:
        return '(subpath ' + json.dumps(str(Path(path).resolve())) + ')'
    project = Path(__file__).resolve().parents[2]
    return '\n'.join(['(version 1)', '(deny default)', '(import "system.sb")',
        '(allow file-read-metadata)', '(allow file-read-data (vnode-type DIRECTORY))',
        '(allow sysctl-read)', '(allow signal (target self))',
        '(allow process-exec ' + literal(sys.executable) + ')',
        '(allow file-read* file-map-executable ' + tree(sys.base_prefix) + ' ' + tree(sys.prefix) + ')',
        '(allow file-read* ' + tree(project / 'src') + ' ' + tree(project / 'v4_planning') + ')',
        '(allow file-read* ' + ' '.join(literal(p) for p in
            (source.path, source.env_path, source.ca_path, '/etc/apache2/mime.types')) + ')',
        '(allow file-read* file-write* (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom"))'])


def _pins_payload(pins: _OriginalRowActionPins) -> bytearray:
    return bytearray(json.dumps(asdict(pins), separators=(',', ':'), allow_nan=False).encode())


def _decode_pins(raw: bytearray) -> _OriginalRowActionPins:
    try:
        value = _map(json.loads(raw, object_pairs_hook=_members),
            {'context_digest', 'defaults_digest', 'capture', 'metadata', 'field_names', 'deadline'})
        value['capture'] = WebSecretCreateAckCapture(**_map(value['capture'],
            {'serial_digest', 'success_status', 'observe_source'}))
        if (type(value['metadata']) is not list or len(value['metadata']) != 93
                or type(value['field_names']) is not list or len(value['field_names']) > 64):
            raise ValueError
        value['metadata'] = tuple(tuple(pair) for pair in value['metadata'])
        value['field_names'] = tuple(value['field_names'])
        return _OriginalRowActionPins(**value)
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        _wipe(raw)


def _receive_socket(peer: socket.socket, deadline: float) -> socket.socket:
    """Receive one private descriptor, closing every descriptor on rejection."""
    descriptors = array.array('i')
    accepted = None
    try:
        peer.settimeout(_remaining(deadline))
        message, ancillary, flags, _ = peer.recvmsg(1, socket.CMSG_SPACE(descriptors.itemsize))
        invalid = False
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                invalid |= bool(len(data) % descriptors.itemsize)
                descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
            else:
                invalid = True
        if message != b'F' or flags or invalid or len(descriptors) != 1:
            raise ValueError
        accepted = socket.socket(fileno=descriptors[0])
        descriptors.pop()
        accepted.set_inheritable(False)
        # Keep the sender's original descriptor alive until custody is installed.
        peer.settimeout(_remaining(deadline))
        peer.sendall(b'D')
        result, accepted = accepted, None
        return result
    finally:
        if accepted is not None:
            accepted.close()
        for descriptor in descriptors:
            os.close(descriptor)


def _receive_original_action_client(peer: socket.socket) -> _OriginalRowActionClient:
    """Consume the fixed inherited Owner handoff; no file or credential input."""
    accepted = None
    raw = bytearray()
    try:
        if (type(peer) is not socket.socket or peer.family != socket.AF_UNIX
                or peer.type != socket.SOCK_STREAM):
            raise ValueError
        deadline = time.monotonic() + 5
        accepted = _receive_socket(peer, deadline)
        raw = _receive(peer, deadline, 65536)
        pins = _decode_pins(raw)
        client = _OriginalRowActionClient(accepted, pins)
        accepted = None
        return client
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        _wipe(raw)
        if accepted is not None:
            accepted.close()
        peer.close()


class _OriginalActionProcess(_OpaqueC3Object):
    """Retain child lifetime locally; exit status never upgrades an action result."""

    def __init__(self, process: subprocess.Popen[bytes], client: _OriginalRowActionClient,
                 connector: socket.socket, source: _ProductSource) -> None:
        self._process, self.client = process, client
        self._dispatch = _ACTIVE_DISPATCH.get()
        self._connector, self._source = connector, source
        self._stop = threading.Event()
        self._connector_thread = threading.Thread(target=self._connect, name='original-action-connect', daemon=True)
        self._connector_thread.start()
        self._watcher = threading.Thread(target=self._watch, name='original-action-lifetime', daemon=True)
        self._watcher.start()

    def _transfer_client_once(self, peer: socket.socket) -> None:
        """Transfer intake custody only during the original Owner dispatch."""
        scope = self._dispatch
        if (scope is None or _ACTIVE_DISPATCH.get() is not scope or not scope.active
                or scope.thread != threading.get_ident() or self.client._phase != 'new'):
            raise BulkImportIntakeError(_ERROR)
        self.client._phase = 'transferring'
        raw = bytearray()
        try:
            if (type(peer) is not socket.socket or peer.family != socket.AF_UNIX
                    or peer.type != socket.SOCK_STREAM):
                raise ValueError
            raw = _pins_payload(self.client._pins)
            peer.settimeout(_remaining(self.client._pins.deadline))
            if peer.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                    array.array('i', [self.client._peer.fileno()]))]) != 1:
                raise ValueError
            peer.settimeout(_remaining(self.client._pins.deadline))
            if peer.recv(1) != b'D':
                raise ValueError
            _send(peer, self.client._pins.deadline, raw)
        except BaseException as error:
            self.close()
            if isinstance(error, Exception):
                raise BulkImportIntakeError(_ERROR) from None
            raise
        finally:
            _wipe(raw)
            self.client.close()
            peer.close()

    def _connect(self) -> None:
        raw = bytearray()
        try:
            # Three actor reads, default, original POST, detail, three actor reads.
            # The connector handles no TLS, HTTP, response bytes or credentials.
            for index in range(9):
                raw = _receive(self._connector, self.client._pins.deadline, 2)
                if self._stop.is_set() or raw != b'C' + bytes((index,)):
                    raise ValueError
                _wipe(raw)
                self._source._verify()
                with socket.create_connection((self._source.connect_ip, self._source.port),
                        timeout=min(5.0, _remaining(self.client._pins.deadline))) as connected:
                    if self._stop.is_set():
                        raise ValueError
                    self._connector.settimeout(_remaining(self.client._pins.deadline))
                    if self._connector.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                            array.array('i', [connected.fileno()]))]) != 1:
                        raise ValueError
                    self._connector.settimeout(_remaining(self.client._pins.deadline))
                    if self._connector.recv(1) != b'D':
                        raise ValueError
        except Exception:
            pass
        finally:
            _wipe(raw)
            self._connector.close()

    def _stop_connector(self) -> None:
        try:
            self._connector.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._connector.close()

    def _watch(self) -> None:
        if not self._stop.wait(max(0.0, self.client._pins.deadline - time.monotonic())):
            self.client.close()
            self._stop_connector()
            if self._process.poll() is None:
                self._process.kill()
            self._process.wait()

    def close(self) -> None:
        self.client.close()
        self._stop.set()
        self._stop_connector()
        try:
            self._process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=2)
        self._watcher.join(timeout=2)
        self._connector_thread.join(timeout=6)


def _launch_original_action_process(encoder: _Build29OriginalRowWireEncoder,
                                   capture: WebSecretCreateAckCapture, *,
                                   source_path: Path, source_digest: str) -> _OriginalActionProcess:
    """One Owner M4 startup, fixed executable/module, selected environment only."""
    pins = _compile_original_action_pins(encoder, capture)
    loader = encoder._converter._bridge._loader
    return _launch_pinned_action_process(pins, loader._plan, loader._authorization, loader._execution,
        source_path=source_path, source_digest=source_digest)


def _launch_original_channel_action_process(owner: OriginalRowChannelOwner,
                                           catalog: ImportDependencyCatalog,
                                           projected: ResolvedImportDependencies,
                                           defaults: _Build29SecretWireDefaults, *,
                                           namespace_key_path: Path, index: int,
                                           target_name: str | None, associated_secret_id: int | None,
                                           source_path: Path, source_digest: str) -> _OriginalActionProcess:
    """Use original Owner metadata and authority without an intake session."""
    pins = _compile_original_channel_action_pins(owner, catalog, projected, defaults,
        namespace_key_path=namespace_key_path, index=index, target_name=target_name,
        associated_secret_id=associated_secret_id)
    return _launch_pinned_action_process(pins, owner._binding.plan, owner._binding.authorization,
        owner._execution, source_path=source_path, source_digest=source_digest)


def _launch_pinned_action_process(pins: _OriginalRowActionPins, plan: M4ExecutionPlan,
                                  authorization: M4ExecutionAuthorization, execution: M4ExecutionStateStore, *,
                                  source_path: Path, source_digest: str) -> _OriginalActionProcess:
    """Shared private launch body; original M4 reserves exactly one startup."""
    parent = child = process = connector = child_connector = None
    raw = bytearray()
    try:
        if sys.platform != 'darwin':
            raise ValueError
        _reserve_m4_product_startup(plan, authorization, execution)
        source = _ProductSource(source_path, source_digest)
        if hashlib.sha256(source.actor.expected_serial.encode()).hexdigest() != pins.capture.serial_digest:
            raise ValueError
        parent, child = socket.socketpair()
        connector, child_connector = socket.socketpair()
        project = Path(__file__).resolve().parents[2]
        environment = {'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1',
            'PYTHONPATH': os.pathsep.join((str(project / 'src'), str(project)))}
        process = subprocess.Popen(['/usr/bin/sandbox-exec', '-p', _native_profile(source),
            sys.executable, '-m', 'fortipam_mcp.secret_bulk_import_action_process',
            str(child.fileno()), str(source.path), source.digest, str(child_connector.fileno())],
            pass_fds=(child.fileno(), child_connector.fileno()),
            env=environment, cwd=project, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child.close(); child = None
        child_connector.close(); child_connector = None
        raw = _pins_payload(pins)
        _send(parent, pins.deadline, raw)
        source._verify()
        return _OriginalActionProcess(process, _OriginalRowActionClient(parent, pins), connector, source)
    except BaseException:
        if parent is not None: parent.close()
        if connector is not None: connector.close()
        if process is not None:
            if process.poll() is None: process.kill()
            process.wait(timeout=2)
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        if child is not None: child.close()
        if child_connector is not None: child_connector.close()
        _wipe(raw)


def _main() -> int:
    peer = connector = None
    raw = bytearray()
    stage = 2
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        if len(sys.argv) != 5:
            raise ValueError
        peer = socket.socket(fileno=int(sys.argv[1]))
        connector = socket.socket(fileno=int(sys.argv[4]))
        raw = _receive(peer, time.monotonic() + 5, 65536)
        stage = 3
        pins = _decode_pins(raw)
        stage = 4
        source = _ProductSource(_path(sys.argv[2]), sys.argv[3])
        stage = 5
        config = source._load_product_config()
        connector_index = 0
        class Connection(http.client.HTTPSConnection):
            def __init__(self, host: str, port: int, **options: Any) -> None:
                if host != source.origin.hostname or port != source.port:
                    raise ValueError
                super().__init__(host, port, **options)
                # Preserve HTTPS host/SNI while dialing only the pinned IP.
                def connect(address: object, timeout: Any, source_address: Any = None) -> socket.socket:
                    nonlocal connector_index
                    if connector is None or connector_index >= 9:
                        raise ValueError
                    _send(connector, worker._deadline, b'C' + bytes((connector_index,)))
                    connector_index += 1
                    received = _receive_socket(connector, worker._deadline)
                    accepted = None
                    try:
                        accepted = received
                        if accepted.getpeername() != (source.connect_ip, source.port):
                            raise ValueError
                        accepted.settimeout(min(float(timeout), _remaining(worker._deadline)))
                        result, accepted = accepted, None
                        return result
                    finally:
                        if accepted is not None: accepted.close()
                self._create_connection = connect
        stage = 6
        guard = _OriginalRowApiActorGuard(config, source.actor, connection_factory=Connection)
        stage = 7
        worker = _OriginalRowActionWorker(config, guard, pins, connection_factory=Connection)
        worker.serve_once(peer)
        return worker._exit_stage
    except BaseException:
        # Fixed bootstrap stage only; no exception text or private source data.
        return stage
    finally:
        _wipe(raw)
        if peer is not None: peer.close()
        if connector is not None: connector.close()


if __name__ == '__main__':
    raise SystemExit(_main())
