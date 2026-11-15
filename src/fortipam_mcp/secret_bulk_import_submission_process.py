"""Fixed restricted source process for an original Text-file submission.

The Owner supplies existing signed authority pins and inherited peers, never an
unlock or source bytes. Only the child admits the HTTP session and reads the file.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import resource
import select
import socket
import stat
import subprocess
import sys
import threading
import time

import uvicorn
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_intake_execution import _OriginalTextIntakeWorker
from .secret_bulk_import_parent_handoff import _OriginalParentReceiver
from .secret_bulk_import_row_action_worker import _receive, _send
from .secret_bulk_import_row_wire import _Build29SecretWireDefaults
from .secret_bulk_import_session_authority import (
    PinnedOwnerFileSessionAuthority, ReferenceOwnerFileSessionEligibility,
)
from .secret_bulk_import_submission_startup import PinnedOwnerFileSubmissionStartup, _catalog, _map, _path, _record
from .secret_bulk_import_token_channel import _PinnedKey, _members, _socket_identity
from .web_secret_create_ack import WebSecretCreateAckCapture

_CONTRACT = 'fortipam-original-text-submission-process-v1'
_LIMIT = 65536
_FIELDS = frozenset({'contract', 'source', 'profile_path', 'profile_sha256', 'session_permission',
    'session_policy', 'defaults', 'capture', 'namespace_key_path', 'namespace_key_sha256',
    'row_channel', 'socket_path', 'parent_context_digest', 'deadline'})
_CHANNEL_FIELDS = frozenset({'socket_path', 'request_key_path', 'request_key_sha256',
    'public_key_path', 'public_key_sha256'})


def _peer(peer: socket.socket) -> None:
    if type(peer) is not socket.socket or peer.family != socket.AF_UNIX or peer.type != socket.SOCK_STREAM:
        raise ValueError
    peer.getpeername()
    peer.set_inheritable(False)


def _close_peer(peer: socket.socket) -> None:
    try:
        peer.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    peer.close()


def _listener_path(path: Path) -> None:
    if (not isinstance(path, Path) or _path(str(path)) != path or len(os.fsencode(path)) > 100
            or path.parent.resolve(strict=True) != path.parent):
        raise ValueError
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) != 0o700):
        raise ValueError
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise ValueError


def _unlink_socket(path: Path, identity: tuple[int, ...] | None) -> None:
    try:
        if identity is not None and _socket_identity(path) == identity:
            path.unlink()
    except (OSError, ValueError):
        pass


def _native_profile(reads: set[Path], remotes: set[Path], listener: Path) -> str:
    def literal(path: Path | str) -> str:
        return '(literal ' + json.dumps(str(Path(path).resolve())) + ')'

    def tree(path: Path) -> str:
        return '(subpath ' + json.dumps(str(path.resolve())) + ')'

    project = Path(__file__).resolve().parents[2]
    return '\n'.join(['(version 1)', '(deny default)', '(import "system.sb")',
        '(allow file-read-metadata)', '(allow file-read-data (vnode-type DIRECTORY))',
        '(allow sysctl-read)', '(allow process-fork)', '(allow signal (target self) (target children))',
        '(allow process-exec ' + literal(sys.executable) + ')',
        '(allow file-read* file-map-executable ' + tree(Path(sys.base_prefix)) + ' ' + tree(Path(sys.prefix)) + ')',
        '(allow file-read* ' + tree(project / 'src') + ' ' + tree(project / 'v4_planning') + ')',
        '(allow file-read* ' + literal('/etc/apache2/mime.types') + ' '
            + ' '.join(literal(path) for path in sorted(reads)) + ')',
        '(allow file-read* file-write* (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom"))',
        '(allow network-outbound ' + ' '.join('(remote unix-socket (path-literal '
            + json.dumps(str(path)) + '))' for path in sorted(remotes)) + ')',
        '(allow file-write* ' + literal(listener) + ')',
        '(allow network-bind network-inbound (local unix-socket (path-literal '
            + json.dumps(str(listener)) + ')))'])


class _OriginalTextSubmissionProcess(_OpaqueC3Object):
    """Own the bounded child; its exit status is never a row-success receipt."""

    def __init__(self, process: subprocess.Popen[bytes], lifecycle: socket.socket,
                 parent_peer: socket.socket, control_peer: socket.socket,
                 socket_path: Path, deadline: float, identity: tuple[int, ...]) -> None:
        self._process, self._lifecycle = process, lifecycle
        self.parent_peer, self.control_peer = parent_peer, control_peer
        self.socket_path, self.deadline, self._socket_identity = socket_path, deadline, identity
        self._closed, self._lock = threading.Event(), threading.Lock()
        self._watcher = threading.Thread(target=self._watch, name='original-submission-lifetime', daemon=True)
        self._watcher.start()

    def _watch(self) -> None:
        while not self._closed.wait(min(0.1, max(0.0, self.deadline - time.monotonic()))):
            if self._process.poll() is not None or time.monotonic() >= self.deadline:
                self.close()
                return

    def close(self) -> None:
        with self._lock:
            if self._closed.is_set():
                return
            self._closed.set()
            for peer in (self._lifecycle, self.control_peer, self.parent_peer):
                _close_peer(peer)
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)
            _unlink_socket(self.socket_path, self._socket_identity)
        if threading.current_thread() is not self._watcher:
            self._watcher.join(timeout=1)


def _launch_original_text_submission_process(
    startup: PinnedOwnerFileSubmissionStartup, session_authority: PinnedOwnerFileSessionAuthority,
    receiver: _OriginalParentReceiver, parent_peer: socket.socket,
    defaults: _Build29SecretWireDefaults, capture: WebSecretCreateAckCapture, *,
    socket_path: Path, row_socket_path: Path, row_request_key_path: Path, row_request_key_sha256: str,
    row_public_key_path: Path, row_public_key_sha256: str,
) -> _OriginalTextSubmissionProcess:
    """Consume existing metadata pins; no Owner read of the source or unlock."""
    lifecycle = child_lifecycle = control = child_control = process = None
    raw = bytearray()
    acquired = False
    try:
        if (sys.platform != 'darwin' or type(startup) is not PinnedOwnerFileSubmissionStartup
                or type(session_authority) is not PinnedOwnerFileSessionAuthority
                or type(receiver) is not _OriginalParentReceiver
                or type(defaults) is not _Build29SecretWireDefaults
                or type(capture) is not WebSecretCreateAckCapture or capture.observe_source):
            raise ValueError
        acquired = startup._lock.acquire(blocking=False)
        if not acquired or startup._used:
            raise ValueError
        startup._used = True
        value = startup._load()
        source, endpoint = startup._binding, receiver._endpoint
        checker = session_authority._human_owner_verifier
        if (session_authority._binding != source or endpoint._binding != source
                or receiver._text_source is None or receiver._qualified is not None
                or endpoint._catalog != _catalog(value['catalog'])
                or type(checker) is not ReferenceOwnerFileSessionEligibility
                or type(checker._authority) is not UnixReferenceAuthorityClient
                or capture.serial_digest != defaults.serial_digest
                or row_request_key_path.parent != row_socket_path.parent
                or row_public_key_path.parent != row_socket_path.parent
                or row_request_key_sha256 == row_public_key_sha256):
            raise ValueError
        defaults.digest()
        capture.__post_init__()
        receiver._check()
        now = int(time.time())
        session_authority.verify_source_session(source, now_epoch=now)
        permission = dict(value['permission'])
        if (checker._authority._settings.socket_path != _path(permission['socket_path'])
                or checker._authority_ref != permission['authority_ref']
                or checker._requester != permission['requester_digest']
                or checker._key.path != _path(permission['scope_key_path'])
                or checker._key.digest != permission['scope_key_sha256']):
            raise ValueError
        permission['reference'] = checker._reference
        policy = dict(policy_path=str(session_authority._policy), policy_sha256=session_authority._policy_digest,
            key_path=str(session_authority._key), key_sha256=session_authority._key_digest)
        channel = dict(socket_path=str(row_socket_path), request_key_path=str(row_request_key_path),
            request_key_sha256=row_request_key_sha256, public_key_path=str(row_public_key_path),
            public_key_sha256=row_public_key_sha256)
        reads = {startup._path, source.path, checker._key.path, session_authority._policy, session_authority._key}
        reads.update(_path(value['policy'][name]) for name in ('policy_path', 'key_path'))
        reads.update(_path(value['channel_options'][name]) for name in ('request_key_path', 'public_key_path'))
        extra_keys = (receiver._key_path, row_request_key_path, row_public_key_path)
        if len(set(extra_keys)) != 3 or reads.intersection(extra_keys):
            raise ValueError
        reads.update(extra_keys)
        for path, digest in zip(extra_keys, (receiver._key_digest, row_request_key_sha256, row_public_key_sha256)):
            _PinnedKey(path, digest)
        remotes = {row_socket_path, checker._authority._settings.socket_path,
            _path(value['channel_options']['socket_path'])}
        if len(remotes) != 3 or socket_path in remotes or socket_path in reads:
            raise ValueError
        for path in remotes - {row_socket_path}:
            if _path(str(path)) != path or path.resolve(strict=True) != path:
                raise ValueError
            _socket_identity(path)
        # The original row listener starts only in M4 dispatch, after this
        # process admits the source and hands off the parent. Its signed client
        # pins the actual socket when the corresponding C2 row arrives.
        _listener_path(row_socket_path)
        _listener_path(socket_path)
        _peer(parent_peer)
        _peer(endpoint._peer)
        deadline = min(startup._deadline, endpoint._deadline,
            time.monotonic() + min(source.expires_at, checker._verified_until) - time.time())
        if not math.isfinite(deadline) or deadline <= time.monotonic():
            raise ValueError
        bootstrap = dict(contract=_CONTRACT, source={**asdict(source), 'path': str(source.path)},
            profile_path=str(startup._path), profile_sha256=startup._sha,
            session_permission=permission, session_policy=policy, defaults=asdict(defaults), capture=asdict(capture),
            namespace_key_path=str(receiver._key_path), namespace_key_sha256=receiver._key_digest,
            row_channel=channel, socket_path=str(socket_path), parent_context_digest=endpoint._context, deadline=deadline)
        raw = bytearray(json.dumps(bootstrap, separators=(',', ':'), allow_nan=False).encode())
        if len(raw) > _LIMIT:
            raise ValueError
        ready = b'R' + hashlib.sha256(raw).hexdigest().encode('ascii')
        lifecycle, child_lifecycle = socket.socketpair()
        control, child_control = socket.socketpair()
        project = Path(__file__).resolve().parents[2]
        environment = {'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1',
            'PYTHONPATH': os.pathsep.join((str(project / 'src'), str(project)))}
        process = subprocess.Popen(['/usr/bin/sandbox-exec', '-p', _native_profile(reads, remotes, socket_path),
            sys.executable, '-m', 'fortipam_mcp.secret_bulk_import_submission_process',
            str(child_lifecycle.fileno()), str(parent_peer.fileno()), str(child_control.fileno())],
            pass_fds=(child_lifecycle.fileno(), parent_peer.fileno(), child_control.fileno()),
            env=environment, cwd=project, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child_lifecycle.close(); child_lifecycle = None
        child_control.close(); child_control = None
        parent_peer.close()
        startup_deadline = min(deadline, time.monotonic() + 5)
        _send(lifecycle, startup_deadline, raw)
        response = _receive(lifecycle, startup_deadline, len(ready))
        try:
            if response != ready or process.poll() is not None or startup._load() != value:
                raise ValueError
        finally:
            _wipe(response)
        return _OriginalTextSubmissionProcess(process, lifecycle, endpoint._peer, control,
            socket_path, deadline, _socket_identity(socket_path))
    except BaseException as error:
        for peer in (lifecycle, control):
            if peer is not None:
                _close_peer(peer)
        if type(receiver) is _OriginalParentReceiver:
            receiver.close()
        if process is not None:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        if not isinstance(error, Exception):
            raise
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        for peer in (child_lifecycle, child_control, parent_peer):
            if type(peer) is socket.socket:
                peer.close()
        if acquired:
            startup._lock.release()
        _wipe(raw)


def _main() -> int:
    lifecycle = parent = control = listener = None
    worker: _OriginalTextIntakeWorker | None = None
    socket_path: Path | None = None
    identity: tuple[int, ...] | None = None
    monitor: threading.Thread | None = None
    stopping = threading.Event()
    raw = bytearray()
    result = 2
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        logging.disable(logging.CRITICAL)
        if len(sys.argv) != 4:
            raise ValueError
        lifecycle, parent, control = (socket.socket(fileno=int(value)) for value in sys.argv[1:])
        for peer in (lifecycle, parent, control):
            _peer(peer)
        raw = _receive(lifecycle, time.monotonic() + 5, _LIMIT)
        ready = b'R' + hashlib.sha256(raw).hexdigest().encode('ascii')
        value = _map(json.loads(raw, object_pairs_hook=_members), _FIELDS)
        _wipe(raw)
        if value['contract'] != _CONTRACT:
            raise ValueError
        fields = dict(value['source'])
        fields['path'] = _path(fields['path'])
        binding = _record(fields, OwnerFileIntakeBinding)
        deadline = value['deadline']
        if (type(deadline) not in {float, int} or not math.isfinite(deadline)
                or not time.monotonic() < deadline <= time.monotonic() + binding.expires_at - time.time()):
            raise ValueError
        require_digest(value['parent_context_digest'], 'original parent context')
        startup = PinnedOwnerFileSubmissionStartup(binding, profile_path=_path(value['profile_path']),
            profile_sha256=value['profile_sha256'])
        permission = _map(value['session_permission'], {'socket_path', 'authority_ref', 'reference',
            'requester_digest', 'scope_key_path', 'scope_key_sha256'})
        remote = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(
            _path(permission.pop('socket_path')), permission['authority_ref']))
        permission['scope_key_path'] = _path(permission['scope_key_path'])
        eligibility = ReferenceOwnerFileSessionEligibility(binding, authority=remote, **permission)
        policy = _map(value['session_policy'], {'policy_path', 'policy_sha256', 'key_path', 'key_sha256'})
        for name in ('policy_path', 'key_path'):
            policy[name] = _path(policy[name])
        authority = PinnedOwnerFileSessionAuthority(binding, human_owner_verifier=eligibility, **policy)
        data = _map(value['defaults'], {'scalars', 'serial_digest'})
        if type(data['scalars']) is not list or any(type(item) is not list for item in data['scalars']):
            raise ValueError
        defaults = _Build29SecretWireDefaults(tuple(tuple(item) for item in data['scalars']), data['serial_digest'])
        capture = _record(value['capture'], WebSecretCreateAckCapture)
        channel = _map(value['row_channel'], _CHANNEL_FIELDS)
        for name in ('socket_path', 'request_key_path', 'public_key_path'):
            channel[name] = _path(channel[name])
        worker = _OriginalTextIntakeWorker(control, binding, defaults, capture,
            namespace_key_path=_path(value['namespace_key_path']), namespace_key_sha256=value['namespace_key_sha256'],
            **channel)
        app = startup.create_original_parent_app_once(parent, context_digest=value['parent_context_digest'],
            deadline=deadline, session_authority=authority, execution_worker=worker)
        socket_path = _path(value['socket_path'])
        _listener_path(socket_path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        socket_path.chmod(0o600)
        identity = _socket_identity(socket_path)
        listener.listen(8)
        server = uvicorn.Server(uvicorn.Config(app, access_log=False, log_config=None, lifespan='on',
            timeout_graceful_shutdown=2, server_header=False))
        life, owned = lifecycle, worker

        def watch() -> None:
            sent = False
            try:
                while not stopping.wait(0.02):
                    if (time.monotonic() >= deadline or owned._closed.is_set()
                            or owned._session is not None and owned._session._transaction._closed.is_set()):
                        return
                    if server.started and not sent:
                        _send(life, deadline, ready)
                        sent = True
                    if select.select([life], [], [], 0)[0]:
                        return
            except Exception:
                pass
            finally:
                owned.close()
                server.should_exit = True

        monitor = threading.Thread(target=watch, name='original-submission-control', daemon=True)
        monitor.start()
        server.run(sockets=[listener])
        result = 0
    except BaseException:
        pass
    finally:
        stopping.set()
        if worker is not None:
            worker.close()
        for remaining_peer in (lifecycle, parent, control, listener):
            if remaining_peer is not None:
                remaining_peer.close()
        if monitor is not None:
            monitor.join(timeout=3)
            if monitor.is_alive():
                result = 3
        if worker is not None and (worker._thread is not None and worker._thread.is_alive()
                or worker._session is not None and (worker._session._watchdog is not None
                    and worker._session._watchdog.is_alive() or any(worker._session._password))):
            result = 3
        if socket_path is not None:
            _unlink_socket(socket_path, identity)
        _wipe(raw)
    return result


if __name__ == '__main__':
    raise SystemExit(_main())
