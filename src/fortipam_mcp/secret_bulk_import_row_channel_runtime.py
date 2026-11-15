"""One original row's signed Unix listener, owned by its active M4 dispatch."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import socket
import stat
import threading
import time

import uvicorn

from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_row_channel import OriginalRowChannelOwner, create_original_row_channel_app
from .secret_bulk_import_token_channel import _ChannelLifetime, _PinnedKey, _socket_identity


class _RowChannelConfig(uvicorn.Config):
    def configure_logging(self) -> None:
        """The enclosing main process owns logging; this listener adds none."""


class _OriginalRowChannelRuntime(_OpaqueC3Object):
    """No listener at construction; one fixed Owner and original key pins only."""

    def __init__(self, owner: OriginalRowChannelOwner, *, socket_path: Path,
                 request_key_path: Path, request_key_sha256: str,
                 signing_key_path: Path, signing_key_sha256: str) -> None:
        try:
            if (type(owner) is not OriginalRowChannelOwner or not isinstance(socket_path, Path)
                    or not socket_path.is_absolute() or '..' in socket_path.parts
                    or request_key_path.parent != socket_path.parent
                    or signing_key_path.parent != socket_path.parent
                    or socket_path in {request_key_path, signing_key_path}):
                raise ValueError
            self._owner, self._binding, self._socket_path = owner, owner._binding, socket_path
            self._request = _PinnedKey(request_key_path, request_key_sha256)
            self._signer = _PinnedKey(signing_key_path, signing_key_sha256)
            parent = socket_path.parent.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700
                    or parent.st_uid != os.getuid()):
                raise ValueError
            self._directory = parent.st_dev, parent.st_ino
            self._lifetime = _ChannelLifetime(owner._binding.lifetime_binding(), owner._clock, time.monotonic)
            self._app = create_original_row_channel_app(owner,
                request_key_path=request_key_path, request_key_sha256=request_key_sha256,
                signing_key_path=signing_key_path, signing_key_sha256=signing_key_sha256, clock=owner._clock)
            self._lock = threading.RLock()
            self._used = self._closed = self._failed = False
            self._listener: socket.socket | None = None
            self._inode: tuple[int, int] | None = None
            self._directory_fd: int | None = None
            self._server: uvicorn.Server | None = None
            self._loop: asyncio.AbstractEventLoop | None = None
            self._thread: threading.Thread | None = None
            self._done = threading.Event()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _check(self) -> None:
        if self._closed or self._failed or self._owner._binding != self._binding:
            raise ValueError
        self._lifetime.check()
        parent = self._socket_path.parent.lstat()
        if ((parent.st_dev, parent.st_ino) != self._directory or not stat.S_ISDIR(parent.st_mode)
                or stat.S_IMODE(parent.st_mode) != 0o700 or parent.st_uid != os.getuid()):
            raise ValueError
        for key in (self._request, self._signer):
            raw = key.load()
            _wipe(raw)

    def _run(self) -> None:
        async def serve() -> None:
            self._loop = asyncio.get_running_loop()
            assert self._server is not None and self._listener is not None
            await self._server.serve(sockets=[self._listener])
        try:
            asyncio.run(serve())
        except BaseException:
            self._failed = True
        finally:
            self._done.set()

    def start_once(self) -> None:
        with self._lock:
            try:
                self._check()
                if self._used:
                    raise ValueError
                self._used = True
                _require_m4_dispatch_ownership(self._binding.plan, self._binding.authorization, self._owner._execution)
                if os.path.lexists(self._socket_path):
                    raise ValueError
                self._directory_fd = os.open(self._socket_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                if (os.fstat(self._directory_fd).st_dev, os.fstat(self._directory_fd).st_ino) != self._directory:
                    raise ValueError
                self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._listener.bind(str(self._socket_path))
                created = self._socket_path.lstat()
                self._inode = created.st_dev, created.st_ino
                self._socket_path.chmod(0o600)
                identity = _socket_identity(self._socket_path)
                if identity[:2] != self._directory or identity[2:4] != self._inode:
                    raise ValueError
                self._listener.listen(8)
                self._server = uvicorn.Server(_RowChannelConfig(self._app, access_log=False,
                    log_config=None, lifespan='off', loop='asyncio',
                    timeout_keep_alive=0, timeout_graceful_shutdown=1))
                self._thread = threading.Thread(target=self._run, name='original-row-channel', daemon=True)
                self._thread.start()
                until = min(self._lifetime.deadline, time.monotonic() + 2)
                while not self._server.started:
                    if self._done.wait(0.01) or time.monotonic() >= until:
                        raise ValueError
                self._check()
                if self._done.is_set():
                    raise ValueError
            except BaseException as error:
                self._failed = True
                self.close()
                if not isinstance(error, Exception):
                    raise
                raise BulkImportIntakeError(_ERROR) from None

    def _stop(self) -> None:
        server = self._server
        if server is not None:
            server.should_exit = True
            for listener in getattr(server, 'servers', ()):
                listener.close()
            for connection in tuple(server.server_state.connections):
                connection.shutdown()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            try:
                loop, thread = self._loop, self._thread
                if loop is not None and not loop.is_closed():
                    loop.call_soon_threadsafe(self._stop)
                elif self._server is not None:
                    self._server.should_exit = True
                if thread is not None and thread is not threading.current_thread():
                    thread.join(timeout=3)
                if self._listener is not None:
                    self._listener.close()
                if thread is not None and thread.is_alive():
                    raise ValueError
            finally:
                descriptor, self._directory_fd = self._directory_fd, None
                try:
                    if descriptor is not None and self._inode is not None:
                        try:
                            current = os.stat(self._socket_path.name, dir_fd=descriptor, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        else:
                            if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == self._inode:
                                os.unlink(self._socket_path.name, dir_fd=descriptor)
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
