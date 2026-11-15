"""Default-closed HTTP issuer and its fixed private token-verification channel."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import threading
import time
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send
import uvicorn

from .local_oauth import LocalOAuthSettings
from .runtime_profile import RuntimeProfile
from .secret_bulk_import_file import _SourceIdentity, _read_owned, _wipe
from .secret_bulk_import_intake_authority import _members
from .secret_bulk_import_oauth import OwnerFileIntakeOAuthCandidate
from .secret_bulk_import_submission_startup import _path, _record
from .secret_bulk_import_token_channel import (
    IntakeTokenChannelBinding, _ChannelLifetime, _socket_identity,
    create_intake_token_verification_app,
)

PREFIX = 'FORTIPAM_MCP_V4_OWNER_FILE_ISSUER_'
CONTRACT = 'fortipam-owner-file-issuer-startup-v1'
_ERROR = 'Private intake issuer startup is unavailable.'
_FIELDS = frozenset({'contract', 'binding', 'socket_path', 'request_key_path',
    'request_key_sha256', 'signing_key_path', 'signing_key_sha256'})


class _PrivateChannelConfig(uvicorn.Config):
    def configure_logging(self) -> None:
        """The embedded channel must not reconfigure the enclosing HTTP host."""


class _OwnerFileIntakeIssuerRuntime:
    """One original channel lifetime; no file admission, Reference or row grant."""

    def __init__(self, settings: LocalOAuthSettings, *, profile_path: Path, profile_sha256: str) -> None:
        self._listener: socket.socket | None = None
        self._runner: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._watcher: threading.Thread | None = None
        self._socket_pin: tuple[int, ...] | None = None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._used = False
        self._profile, self._sha = profile_path, profile_sha256
        self._identity: _SourceIdentity | None = None
        try:
            if type(settings) is not LocalOAuthSettings:
                raise ValueError
            value = self._load()
            self._settings = settings
            self._binding = _record(value['binding'], IntakeTokenChannelBinding)
            if self._binding.issuer != settings.issuer or self._binding.planning_resource != settings.resource:
                raise ValueError
            self._lifetime = _ChannelLifetime(self._binding, lambda: int(time.time()), time.monotonic)
            self._lifetime.check()
            self._socket = _path(value['socket_path'])
            self._options: dict[str, Any] = dict(request_key_path=_path(value['request_key_path']),
                request_key_sha256=value['request_key_sha256'],
                signing_key_path=_path(value['signing_key_path']),
                signing_key_sha256=value['signing_key_sha256'])
            paths = (self._profile, self._socket, self._options['request_key_path'], self._options['signing_key_path'])
            if len(set(paths)) != len(paths) or len(str(self._socket).encode()) >= 104:
                raise ValueError
            self._check_parent()
            self.provider = OwnerFileIntakeOAuthCandidate(settings, intake_resource=self._binding.intake_resource)
            self._app = create_intake_token_verification_app(self.provider, self._binding, **self._options)
        except Exception:
            raise ValueError(_ERROR) from None

    def _load(self) -> dict[str, Any]:
        raw = bytearray()
        try:
            raw, identity = _read_owned(self._profile, self._identity)
            if not 0 < len(raw) <= 16384 or hashlib.sha256(raw).hexdigest() != self._sha:
                raise ValueError
            value: object = json.loads(raw, object_pairs_hook=_members)
            if type(value) is not dict or set(value) != _FIELDS or value['contract'] != CONTRACT:
                raise ValueError
            self._identity = identity
            return value
        finally:
            _wipe(raw)

    def _check_parent(self) -> None:
        parent = self._socket.parent
        for path in (parent, *parent.parents):
            if path.is_symlink():
                raise ValueError
        info = parent.stat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise ValueError

    def start_once(self) -> None:
        try:
            with self._lock:
                if self._used or self._stop.is_set():
                    raise ValueError
                self._used = True
                self._load()
                self._lifetime.check()
                self._check_parent()
                if os.path.lexists(self._socket):
                    raise ValueError
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._listener = listener
                listener.set_inheritable(False)
                listener.bind(str(self._socket))
                self._socket.chmod(0o600)
                self._socket_pin = _socket_identity(self._socket)
                listener.listen(8)
                self._runner = uvicorn.Server(_PrivateChannelConfig(self._app, access_log=False,
                    log_config=None, lifespan='on', loop='asyncio', timeout_graceful_shutdown=1))
                runner = self._runner
                self._thread = threading.Thread(target=runner.run, kwargs={'sockets': [listener]},
                    name='owner-file-token-channel', daemon=True)
                self._thread.start()
                deadline = time.monotonic() + 5
                while not runner.started:
                    self._lifetime.check()
                    if not self._thread.is_alive() or time.monotonic() >= deadline:
                        raise ValueError
                    self._stop.wait(0.01)
                self._watcher = threading.Thread(target=self._watch, name='owner-file-token-expiry', daemon=True)
                self._watcher.start()
        except BaseException as error:
            self.close()
            if not isinstance(error, Exception):
                raise
            raise ValueError(_ERROR) from None

    def _watch(self) -> None:
        try:
            while not self._stop.wait(0.25):
                self._lifetime.check()
                if self._thread is None or not self._thread.is_alive():
                    break
        except Exception:
            pass
        finally:
            self.close()

    def close(self) -> None:
        with self._lock:
            self._stop.set()
            runner, thread, listener = self._runner, self._thread, self._listener
            if runner is not None:
                runner.should_exit = True
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=2)
                if thread.is_alive() and runner is not None:
                    runner.force_exit = True
                    thread.join(timeout=2)
            if listener is not None:
                listener.close()
            if self._socket_pin is not None and os.path.lexists(self._socket):
                if _socket_identity(self._socket) == self._socket_pin:
                    self._socket.unlink()
            if thread is not None and thread.is_alive():
                raise ValueError(_ERROR)
        watcher = self._watcher
        if watcher is not None and watcher is not threading.current_thread():
            watcher.join(timeout=2)

    def wrap(self, app: ASGIApp) -> ASGIApp:
        async def wrapped(scope: Scope, receive: Receive, send: Send) -> None:
            if scope['type'] != 'lifespan':
                await app(scope, receive, send)
                return

            async def starting() -> Message:
                message = await receive()
                if message['type'] == 'lifespan.startup':
                    await asyncio.to_thread(self.start_once)
                return message

            try:
                await app(scope, starting, send)
            finally:
                await asyncio.to_thread(self.close)
        return wrapped


def build_owner_file_intake_issuer(environment: Mapping[str, str], *, settings: LocalOAuthSettings | None,
                                   runtime_profile: RuntimeProfile) -> _OwnerFileIntakeIssuerRuntime | None:
    """The optional issuer never enables a file route or import execution."""
    try:
        enabled = environment.get(PREFIX + 'ENABLED', 'false')
        if enabled not in {'true', 'false'}:
            raise ValueError
        if enabled == 'false':
            if any(environment.get(PREFIX + suffix) for suffix in ('PROFILE_FILE', 'PROFILE_SHA256')):
                raise ValueError
            return None
        if runtime_profile is not RuntimeProfile.V4_CONTROLLED or type(settings) is not LocalOAuthSettings:
            raise ValueError
        return _OwnerFileIntakeIssuerRuntime(settings, profile_path=_path(environment[PREFIX + 'PROFILE_FILE']),
            profile_sha256=environment[PREFIX + 'PROFILE_SHA256'])
    except Exception:
        raise ValueError(_ERROR) from None
