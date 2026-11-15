"""Private one-shot client for the fixed, dedicated RADIUS fixture SSH channel.

Trusted composition pins source policy, SSH key, host key and the active M4
guard. This class installs no account, policy or helper and grants no authority.
No general SSH command, path, remote operation or provider-selection input is
accepted at the material-use boundary.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
from threading import Lock
import time
from typing import Any

from v4_planning.material_provider import (
    MaterialAccessDenied, MaterialBindingStatus, MaterialLeaseRequest, MaterialProviderClass,
    MaterialPurpose, _OpaqueC3Object,
)
from v4_planning.material_runtime import material_lease_request_digest
from v4_planning.models import require_digest

from .radius_fixture_material_worker import CONTRACT
from .radius_server_contract import ACTION_ID, ACTION_VERSION, RadiusServerCreateBinding
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = "The owned RADIUS fixture material source is unavailable."
_USER = "fp-radius-material"
_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _file_identity(path: Path) -> tuple[int, int, int, int, int]:
    # OpenSSH expands tokens/environment variables in both identity and host-key
    # paths and parses UserKnownHostsFile as a whitespace-separated option.
    # The fixed channel permits literal paths only, never a second interpretation.
    if (not path.is_absolute() or ".." in path.parts
            or any(c.isspace() or c in {"%", "$", "\\", '"', "'"} or ord(c) < 32 or ord(c) == 127
                   for c in str(path))
            or any(p.is_symlink() for p in (path,*path.parents))): raise ValueError
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 65536): raise ValueError
    return info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns


class RadiusFixtureMaterialLoader(_OpaqueC3Object):
    """Pin one source and request; remote and local acquisition attempts are terminal."""

    __slots__ = ("_binding","_parameters","_host","_key","_known_hosts","_key_identity","_hosts_identity",
        "_source_digest","_guard","_enabled","_clock","_last_clock","_clock_failed","_request",
        "_request_digest","_attempted","_lock","_factory")
    _display_name = "RadiusFixtureMaterialLoader"

    def __init__(self, binding: RadiusServerCreateBinding, *, host: str, identity_file: Path,
            known_hosts_file: Path, source_policy_digest: str,
            execution_guard: Callable[[RadiusServerCreateBinding, MaterialLeaseRequest], None],
            acquisition_enabled: bool = False, clock: Callable[[], int] | None = None,
            process_factory: Callable[..., Any] | None = None) -> None:
        try:
            if (type(binding) is not RadiusServerCreateBinding or type(host) is not str
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}",host) is None
                    or type(acquisition_enabled) is not bool or not callable(execution_guard)
                    or clock is not None and not callable(clock)
                    or process_factory is not None and not callable(process_factory)):
                raise ValueError
            require_digest(source_policy_digest,"source_policy_digest")
            self._key_identity, self._hosts_identity = _file_identity(identity_file), _file_identity(known_hosts_file)
            self._binding, self._parameters = binding,binding.parameters_digest
            self._host,self._key,self._known_hosts = host,identity_file,known_hosts_file
            self._source_digest,self._guard,self._enabled = source_policy_digest,execution_guard,acquisition_enabled
            self._clock = clock or (lambda:int(time.time()))
            self._last_clock: int | None = None
            self._clock_failed = False
            self._request: MaterialLeaseRequest | None = None
            self._request_digest: str | None = None
            self._attempted = False
            self._lock = Lock()
            self._factory = process_factory or subprocess.Popen
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None

    def _check(self, binding: RadiusServerCreateBinding, request: MaterialLeaseRequest) -> int:
        if (self._enabled is not True or binding is not self._binding or binding.parameters_digest != self._parameters
                or type(request) is not MaterialLeaseRequest or request.action_id != ACTION_ID
                or request.action_version != ACTION_VERSION
                or request.provider_class is not MaterialProviderClass.OWNED_LAB_FIXTURE_REFERENCE
                or request.purpose is not MaterialPurpose.INITIAL_ONBOARDING): raise ValueError
        request.__post_init__()
        if self._request is None:
            self._request = replace(request)
            self._request_digest = material_lease_request_digest(request)
        if request != self._request or material_lease_request_digest(request) != self._request_digest: raise ValueError
        now = self._clock()
        if (self._clock_failed or type(now) is not int or not request.requested_at <= now < request.expires_at
                or self._last_clock is not None and now < self._last_clock):
            self._clock_failed = True
            raise ValueError
        self._last_clock = now
        if (_file_identity(self._key) != self._key_identity
                or _file_identity(self._known_hosts) != self._hosts_identity): raise ValueError
        self._guard(binding,request)
        after = self._clock()
        if type(after) is not int or not now <= after < request.expires_at:
            self._clock_failed = True
            raise ValueError
        self._last_clock = after
        if self._enabled is not True: raise ValueError
        return after

    def _exchange(self, operation: str, request: MaterialLeaseRequest, now: int) -> bytearray:
        process: Any = None
        output = bytearray(33)
        success = False
        payload = json.dumps({"contract":CONTRACT,"operation":operation,"parameters_digest":self._parameters,
            "source_policy_digest":self._source_digest,"request":asdict(request)},sort_keys=True,separators=(",",":")).encode()
        deadline = time.monotonic()+min(15,request.expires_at-now)
        try:
            args = ["/usr/bin/ssh","-F","/dev/null","-T","-i",str(self._key),"-l",_USER,
                "-o","BatchMode=yes","-o","IdentitiesOnly=yes","-o","IdentityAgent=none",
                "-o","PasswordAuthentication=no","-o","KbdInteractiveAuthentication=no",
                "-o","PreferredAuthentications=publickey","-o","StrictHostKeyChecking=yes",
                "-o","UpdateHostKeys=no","-o","GlobalKnownHostsFile=/dev/null",
                "-o","UserKnownHostsFile="+str(self._known_hosts),"-o","ClearAllForwardings=yes",
                "-o","ConnectTimeout=5","-o","ConnectionAttempts=1","-o","LogLevel=ERROR",self._host]
            process = self._factory(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                close_fds=True,bufsize=0)
            if process.stdin is None or process.stdout is None: raise ValueError
            os.set_blocking(process.stdin.fileno(),False)
            os.set_blocking(process.stdout.fileno(),False)
            sent = count = 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdin,selectors.EVENT_WRITE,"stdin")
                selector.register(process.stdout,selectors.EVENT_READ,"stdout")
                ended = False
                while not ended:
                    remaining = deadline-time.monotonic()
                    if remaining <= 0: raise TimeoutError
                    ready = selector.select(remaining)
                    if not ready: raise TimeoutError
                    for key,_ in ready:
                        if key.data == "stdin":
                            written = os.write(process.stdin.fileno(),payload[sent:])
                            if written <= 0: raise ValueError
                            sent += written
                            if sent == len(payload):
                                selector.unregister(process.stdin)
                                process.stdin.close()
                        else:
                            if count >= len(output): raise ValueError
                            with memoryview(output)[count:] as view:
                                received = os.readv(process.stdout.fileno(),[view])
                            if received == 0:
                                ended = True
                                break
                            count += received
                            if count > 32: raise ValueError
            remaining = deadline-time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0: raise ValueError
            del output[count:]
            success = True
            return output
        finally:
            if not success: _zeroize_mutable(output)
            if process is not None:
                if process.poll() is None: process.kill()
                try: process.wait(timeout=2)
                except subprocess.TimeoutExpired: pass
                for stream in (process.stdin,process.stdout):
                    if stream is not None: stream.close()

    def validate_prebound(self, binding: RadiusServerCreateBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        if not self._lock.acquire(blocking=False): return MaterialBindingStatus.UNAVAILABLE
        raw = bytearray()
        try:
            if self._attempted: raise ValueError
            now = self._check(binding,request)
            raw = self._exchange("validate",request,now)
            self._check(binding,request)
            return MaterialBindingStatus.AVAILABLE if raw == b"available\n" else MaterialBindingStatus.UNAVAILABLE
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE
        finally:
            _zeroize_mutable(raw)
            self._lock.release()

    def close(self) -> None:
        """Disable intake, including from a guard inside an active exchange.

        Do not wait on the exchange lock: its final check must see revocation
        and clear a response already in flight. Durable claims remain consumed.
        """
        self._enabled = False

    def load_radius_material_once(self, binding: RadiusServerCreateBinding, request: MaterialLeaseRequest) -> bytearray:
        if not self._lock.acquire(blocking=False): raise MaterialAccessDenied(_ERROR)
        raw = bytearray()
        try:
            if self._attempted: raise ValueError
            now = self._check(binding,request)
            self._attempted = True
            raw = self._exchange("acquire",request,now)
            self._check(binding,request)
            if len(raw) != 32 or any(value not in _ALPHABET for value in raw): raise ValueError
            result, raw = raw,bytearray()
            return result
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
            self._lock.release()
