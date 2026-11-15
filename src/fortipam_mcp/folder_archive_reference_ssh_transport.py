"""Read fixed Folder hierarchy and references with positive build-29 witnesses."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
import hmac
import re
from pathlib import Path

from .target_reference_ssh_transport import (
    FortiPamTargetReferenceSshTransport,
    _strict_reference_count,
)
from .target_ssh_transport import (
    ENV_PREFIX as TARGET_ENV_PREFIX,
    TargetSshTransportConfig,
    _close_cli,
    _require_root_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
    load_target_ssh_transport_config,
    _private_regular_file, _safe_host, _safe_name,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_FOLDER_ARCHIVE_REFERENCE_"
_UNAVAILABLE = "FortiPAM Folder archive reference evidence is unavailable."
_SERIAL_PROJECTION = 'get system status | grep "Serial-Number"'
_PARENT_PROJECTION = 'show full-configuration | grep "set parent-folder"'


def load_folder_archive_reference_config(environment: Mapping[str, str]) -> TargetSshTransportConfig:
    """Require dedicated bindings; never fall back to another action identity."""
    return load_target_ssh_transport_config({
        TARGET_ENV_PREFIX + key.removeprefix(ENV_PREFIX): value
        for key, value in environment.items() if key.startswith(ENV_PREFIX)
    })


class OwnerFolderArchiveReferenceSshTransport:
    """Explicitly reuse the fixed Owner provider for private read-only SSH.

    Credentials resolve only at a reference decision; no password file or
    process-environment copy is created. The same serial/hierarchy/positive
    reference calibration as the legacy dedicated-file transport applies.
    """

    def __init__(self, environment: Mapping[str, str], *, owner_name: str,
                 credentials: Callable[[], tuple[str, str]]) -> None:
        try:
            if (environment.get(ENV_PREFIX + "ENABLED") != "true"
                    or environment.get(ENV_PREFIX + "OWNER_LOGIN_ENABLED") != "true"
                    or not _safe_name(owner_name) or not callable(credentials)):
                raise ValueError
            host = environment[ENV_PREFIX + "SSH_HOST"]
            known_hosts = Path(environment[ENV_PREFIX + "SSH_KNOWN_HOSTS_FILE"])
            port = int(environment.get(ENV_PREFIX + "SSH_PORT", "22"))
            timeout = float(environment.get(ENV_PREFIX + "SSH_TIMEOUT_SECONDS", "15"))
            if (not _safe_host(host) or not known_hosts.is_absolute()
                    or not 1 <= port <= 65535 or not 1 <= timeout <= 60):
                raise ValueError
            _private_regular_file(known_hosts, "known_hosts")
            self._host, self._port, self._timeout = host, port, timeout
            self._known_hosts, self._owner, self._credentials = known_hosts, owner_name, credentials
        except Exception:
            raise ValueError(_UNAVAILABLE) from None

    def verify_no_references(self, folder_id: int, parent_folder_id: int, device_serial: str) -> bool:
        try:
            if (any(type(value) is not int or not 0 < value <= 2_147_483_647
                    for value in (folder_id, parent_folder_id)) or folder_id == parent_folder_id
                    or type(device_serial) is not str
                    or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", device_serial) is None):
                raise ValueError
            username, password = self._credentials()
            if username != self._owner:
                raise ValueError
            config = TargetSshTransportConfig(self._host, self._port, username, password,
                self._known_hosts, self._timeout)
            return FortiPamFolderArchiveReferenceSshTransport(config).verify_no_references(
                folder_id, parent_folder_id, device_serial)
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None


class FortiPamFolderArchiveReferenceSshTransport:
    """Reuse pinned SSH framing for compiled, read-only hierarchy/reference reads."""

    def __init__(self, config: TargetSshTransportConfig) -> None:
        self._ssh = FortiPamTargetReferenceSshTransport(config)

    def verify_no_references(self, folder_id: int, parent_folder_id: int, device_serial: str) -> bool:
        for identifier in (folder_id, parent_folder_id):
            if type(identifier) is not int or not 0 < identifier <= 2_147_483_647:
                raise ValueError(_UNAVAILABLE)
        if folder_id == parent_folder_id:
            raise ValueError(_UNAVAILABLE)
        if not isinstance(device_serial, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", device_serial) is None:
            raise ValueError(_UNAVAILABLE)
        try:
            return asyncio.run(self._verify(folder_id, parent_folder_id, device_serial))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    async def _verify(self, folder_id: int, parent_folder_id: int, device_serial: str) -> bool:
        async with self._ssh._connection() as connection:
            process, prompt, deadline = await self._ssh._open_cli(connection)
            try:
                # Compare identity inside the private boundary, including when
                # HTTPS and pinned SSH legitimately use different host aliases.
                command = _SERIAL_PROJECTION
                output = await _send_and_read(process, command, prompt, deadline)
                lines = output.replace(b"\r", b"").split(b"\n")
                if lines[0].strip() != command.encode() or lines[-1].rstrip(b" ") != prompt:
                    return False
                serials = [line for line in lines[1:-1] if line.strip()]
                if len(serials) != 1 or not hmac.compare_digest(
                    serials[0], b"Serial-Number: " + device_serial.encode("ascii")
                ):
                    return False
                # REST Folder collections are actor-filtered even when their
                # matched_count is complete. Check the full CLI parent-field
                # projection rather than treating REST visibility as emptiness.
                folder_prompt = await _send_and_read_dynamic_prompt(
                    process, "config secret folder", prompt, deadline,
                )
                output = await _send_and_read(process, _PARENT_PROJECTION, folder_prompt, deadline)
                parents = _folder_parent_ids(output, folder_prompt)
                returned = await _send_and_read_dynamic_prompt(process, "end", prompt, deadline)
                _require_root_prompt(prompt, returned)
                if parent_folder_id not in parents or folder_id in parents:
                    return False
                # A visible Secret reference in the parent calibrates the
                # command before an empty output is accepted for the child.
                for identifier in (parent_folder_id, folder_id):
                    command = "diagnose sys cmdb refcnt show secret.folder.id " + str(identifier)
                    output = await _send_and_read(process, command, prompt, deadline)
                    count = _strict_reference_count(output, command, prompt)
                    if identifier == parent_folder_id:
                        lines = output.replace(b"\r", b"").split(b"\n")[1:-1]
                        if count == 0 or not any(b"secret.database" in line for line in lines):
                            return False
                    elif count != 0:
                        return False
                return True
            finally:
                await _close_cli(process)


def _folder_parent_ids(output: bytes, prompt: bytes) -> tuple[int, ...]:
    """Parse the complete fixed projection; blank/error/truncated reads fail closed."""
    if len(output) > 64 * 1024:
        raise ValueError(_UNAVAILABLE)
    lines = output.replace(b"\r", b"").split(b"\n")
    if (
        len(lines) < 3 or lines[0].strip() != _PARENT_PROJECTION.encode("ascii")
        or lines[-1].rstrip(b" ") != prompt
    ):
        raise ValueError(_UNAVAILABLE)
    parents: list[int] = []
    for line in lines[1:-1]:
        if not line.strip():
            continue
        match = re.fullmatch(rb"\s*set parent-folder (0|[1-9][0-9]*)\s*", line)
        if match is None:
            raise ValueError(_UNAVAILABLE)
        value = int(match[1])
        if value > 2_147_483_647:
            raise ValueError(_UNAVAILABLE)
        parents.append(value)
    if not parents:
        raise ValueError(_UNAVAILABLE)
    return tuple(parents)
