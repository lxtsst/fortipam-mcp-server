"""Private same-device build-29 reference evidence; no mutation authority."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import time

from .cli_safety import _complete_pre_login
from .target_reference_ssh_transport import (
    FortiPamTargetReferenceSshTransport,
    _target_name,
)
from .target_ssh_transport import TargetSshTransportConfig, _send_and_read

_SERIAL = 'get system status | grep "Serial-Number"'
_VERSION = 'get system status | grep "Version"'
_REFERENCE = 'diagnose sys cmdb refcnt show secret.target.name '
_UNAVAILABLE = 'FortiPAM qualified Target reference evidence is unavailable.'
_LIMIT = 64 * 1024


class TargetQualifiedReferenceError(RuntimeError):
    """Fixed non-disclosing failure."""


class FortiPamTargetQualifiedReferenceReader:
    """Bind API serial digest before use; callers separately qualify actor and M4."""

    def __init__(self, config: TargetSshTransportConfig, *, serial_digest: str) -> None:
        try:
            if (type(config) is not TargetSshTransportConfig
                or type(serial_digest) is not str
                or re.fullmatch(r'[0-9a-f]{64}', serial_digest) is None):
                raise ValueError
            config.__post_init__()
            self._ssh = FortiPamTargetReferenceSshTransport(config)
            self._serial_digest = serial_digest
            self._timeout = config.timeout_seconds
        except Exception:
            raise TargetQualifiedReferenceError(_UNAVAILABLE) from None

    def reference_count(self, target_name: str) -> int:
        try:
            if type(target_name) is not str:
                raise ValueError
            name = _target_name(target_name)
            return asyncio.run(self._bounded_read(name))
        except Exception:
            raise TargetQualifiedReferenceError(_UNAVAILABLE) from None

    async def _bounded_read(self, name: str) -> int:
        async with asyncio.timeout(self._timeout):
            return await self._read(name)

    async def _read(self, name: str) -> int:
        deadline = time.monotonic() + self._timeout
        connection = await self._ssh._connection()
        try:
            process = await connection.create_process(
                term_type='vt100', term_size=(200, 24), encoding=None,
            )
            try:
                prompt = await _complete_pre_login(
                    process.stdout, process.stdin, deadline, _LIMIT,
                    accept_pre_login_banner=False,
                )
                if re.fullmatch(rb'[A-Za-z0-9._-]{1,63} #', prompt) is None:
                    raise ValueError
                count = 0
                for command in (_SERIAL, _VERSION, _REFERENCE + name, _SERIAL, _VERSION):
                    output = await _send_and_read(process, command, prompt, deadline)
                    lines = _lines(output, command, prompt)
                    if command == _SERIAL:
                        if len(lines) != 1:
                            raise ValueError
                        match = re.fullmatch(rb'Serial-Number: ([A-Za-z0-9_-]{1,128})', lines[0])
                        if match is None or not hmac.compare_digest(
                            hashlib.sha256(match[1]).hexdigest(), self._serial_digest,
                        ):
                            raise ValueError
                    elif command == _VERSION:
                        _version(lines)
                    else:
                        if any(b'entry used by' not in line.lower() for line in lines):
                            raise ValueError
                        count = len(lines)
                return count
            finally:
                process.close()
                try:
                    async with asyncio.timeout(1):
                        await process.wait_closed()
                except TimeoutError:
                    connection.abort()
                    raise
        finally:
            connection.abort()


def _lines(output: bytes, command: str, prompt: bytes) -> tuple[bytes, ...]:
    if type(output) is not bytes or len(output) > _LIMIT or any(
        byte < 32 and byte not in {9, 10, 13} or byte == 127 for byte in output
    ):
        raise ValueError
    echo = command.encode('ascii')
    prefix = next((p for p in (echo + b'\r\r\n', echo + b'\r\n') if output.startswith(p)), None)
    suffix = prompt + b' ' if output.endswith(prompt + b' ') else prompt
    if prefix is None or not output.endswith(suffix):
        raise ValueError
    body = output[len(prefix):-len(suffix)]
    # An empty reference result may have no extra blank line after the echo.
    if body and not body.endswith(b'\r\n'):
        raise ValueError
    lines = body[:-2].split(b'\r\n') if body else []
    if any(b'\r' in line or b'\n' in line for line in lines):
        raise ValueError
    return tuple(line for line in lines if line.strip(b' \t'))


def _version(lines: tuple[bytes, ...]) -> None:
    versions = tuple(line for line in lines if line.startswith(b'Version:'))
    auxiliary = tuple(line for line in lines if not line.startswith(b'Version:'))
    if (len(versions) != 1 or b'FortiPAM' not in versions[0]
        or re.search(rb'\bv7\.0\.0,\s*build0*29\b', versions[0]) is None
        or any(byte < 32 or byte > 126 for line in lines for byte in line)
        or len(auxiliary) > 1):
        raise ValueError
    prefix = b'Release Version Information:'
    if any(not line.startswith(prefix) or len(line) > 256
           or not line[len(prefix):].strip(b' ') for line in auxiliary):
        raise ValueError
