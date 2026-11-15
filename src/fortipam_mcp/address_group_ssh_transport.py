"""Fixed SSH fallback for one single-member FortiPAM Address Group create.

The FortiPAM API catalog exposes Address Group routes, but the current 1.9.1
laboratory has no existing Group from which a REST member-body schema can be
proven. This module therefore implements only the Administration Guide's fixed
``firewall addrgrp`` CLI workflow. It is not a generic CLI relay.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, cast

import asyncssh

from .cli_safety import CliTransportError, _complete_pre_login
from .target_ssh_transport import (
    _close_cli,
    _require_context_prompt,
    _require_root_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ADDRESS_GROUP_CLI_"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Address Group CLI fallback is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024


class AddressGroupSshTransportConfigurationError(ValueError):
    """Raised when dedicated Address Group SSH settings are unsafe."""


class AddressGroupSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the fixed CLI fallback."""


@dataclass(frozen=True, slots=True)
class AddressGroupSshTransportConfig:
    """Dedicated password-file SSH settings kept only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise AddressGroupSshTransportConfigurationError(
                "The Address Group SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise AddressGroupSshTransportConfigurationError(
                "The Address Group SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise AddressGroupSshTransportConfigurationError(
                "The Address Group SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise AddressGroupSshTransportConfigurationError(
                "The Address Group SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise AddressGroupSshTransportConfigurationError(
                "The Address Group SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class AddressGroupInspection:
    """Value-minimized current state for one Address Group."""

    exists: bool


@dataclass(frozen=True, slots=True)
class AddressSshInspection:
    """Value-minimized current state for one IPv4 Address."""

    exists: bool


@dataclass(frozen=True, slots=True)
class AddressGroupReadback:
    """Categorical readback for the fixed single-member CLI contract."""

    group_exists: bool
    exactly_one_member_matches: bool

    @property
    def verified(self) -> bool:
        return self.group_exists and self.exactly_one_member_matches


@dataclass(frozen=True, slots=True)
class AddressGroupReferenceReadback:
    """Calibrated reference counts for the fixed Group and member Address."""

    group_reference_count: int
    calibration_address_reference_count: int

    @property
    def verified_zero_reference(self) -> bool:
        return (
            self.group_reference_count == 0
            and self.calibration_address_reference_count == 1
        )


def load_address_group_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> AddressGroupSshTransportConfig:
    """Load an independent, explicitly enabled Address Group CLI identity."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise AddressGroupSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise AddressGroupSshTransportConfigurationError(
            "Dedicated Address Group SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise AddressGroupSshTransportConfigurationError(
            "The Address Group SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return AddressGroupSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamAddressGroupSshTransport:
    """Run only compiled Address Group inspection/create/readback sequences."""

    def __init__(self, config: AddressGroupSshTransportConfig) -> None:
        self._config = config

    def inspect(self, group_name: str) -> AddressGroupInspection:
        name = _object_name(group_name)
        return cast(AddressGroupInspection, _run_sync(self._inspect(name)))

    def inspect_address(self, address_name: str) -> AddressSshInspection:
        """Read one exact Address presence state without changing it."""

        name = _object_name(address_name)
        return cast(AddressSshInspection, _run_sync(self._inspect_address(name)))

    def address_reference_count(self, address_name: str) -> int:
        """Return a strictly parsed fixed Address CMDB reference count."""

        name = _object_name(address_name)
        return cast(int, _run_sync(self._address_reference_count(name)))

    def create_and_readback(
        self,
        group_name: str,
        member_name: str,
    ) -> AddressGroupReadback:
        group = _object_name(group_name)
        member = _object_name(member_name)
        return cast(
            AddressGroupReadback,
            _run_sync(self._create_and_readback(group, member)),
        )

    def readback(self, group_name: str, member_name: str) -> AddressGroupReadback:
        """Read the exact single-member projection without changing it."""

        group = _object_name(group_name)
        member = _object_name(member_name)
        return cast(AddressGroupReadback, _run_sync(self._readback_only(group, member)))

    def reference_readback(
        self,
        group_name: str,
        calibration_address_name: str,
    ) -> AddressGroupReferenceReadback:
        """Prove Group zero references against its one known referenced member."""

        group = _object_name(group_name)
        address = _object_name(calibration_address_name)
        return cast(
            AddressGroupReferenceReadback,
            _run_sync(self._reference_readback(group, address)),
        )

    async def _inspect(self, group_name: str) -> AddressGroupInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                compact = await self._run_addrgrp_context(
                    process,
                    root_prompt,
                    (f"show | grep {group_name}",),
                    deadline,
                )
                full = await self._run_addrgrp_context(
                    process,
                    root_prompt,
                    (f"show | grep {group_name} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        marker = f'edit "{group_name}"'.encode("ascii")
        return AddressGroupInspection(exists=marker in compact + full)

    async def _inspect_address(self, address_name: str) -> AddressSshInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                compact = await self._run_address_context(
                    process,
                    root_prompt,
                    (f"show | grep {address_name}",),
                    deadline,
                )
                full = await self._run_address_context(
                    process,
                    root_prompt,
                    (f"show | grep {address_name} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        marker = f'edit "{address_name}"'.encode("ascii")
        return AddressSshInspection(exists=marker in compact + full)

    async def _address_reference_count(self, address_name: str) -> int:
        command = "diagnose sys cmdb refcnt show firewall.address.name " + address_name
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await _send_and_read(
                    process,
                    command,
                    root_prompt,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _reference_count(output, command, root_prompt)

    async def _readback_only(
        self,
        group_name: str,
        member_name: str,
    ) -> AddressGroupReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._run_addrgrp_context(
                    process,
                    root_prompt,
                    (f"show | grep {group_name} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, group_name, member_name)

    async def _reference_readback(
        self,
        group_name: str,
        calibration_address_name: str,
    ) -> AddressGroupReferenceReadback:
        group_command = (
            "diagnose sys cmdb refcnt show firewall.addrgrp.name " + group_name
        )
        address_command = (
            "diagnose sys cmdb refcnt show firewall.address.name "
            + calibration_address_name
        )
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                group_output = await _send_and_read(
                    process,
                    group_command,
                    root_prompt,
                    deadline,
                )
                address_output = await _send_and_read(
                    process,
                    address_command,
                    root_prompt,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return AddressGroupReferenceReadback(
            group_reference_count=_reference_count(
                group_output,
                group_command,
                root_prompt,
            ),
            calibration_address_reference_count=_reference_count(
                address_output,
                address_command,
                root_prompt,
            ),
        )

    async def _create_and_readback(
        self,
        group_name: str,
        member_name: str,
    ) -> AddressGroupReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_group(
                    process,
                    root_prompt,
                    group_name,
                    member_name,
                    deadline,
                )
                readback = await self._run_addrgrp_context(
                    process,
                    root_prompt,
                    (f"show | grep {group_name} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(readback, group_name, member_name)

    async def _create_group(
        self,
        process: Any,
        root_prompt: bytes,
        group_name: str,
        member_name: str,
        deadline: float,
    ) -> None:
        context_prompt = _addrgrp_context_prompt(root_prompt)
        try:
            await _send_and_read(
                process,
                "config firewall addrgrp",
                context_prompt,
                deadline,
            )
            entry_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{group_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set member "{member_name}"',
                entry_prompt,
                deadline,
            )
            returned_context = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            _require_context_prompt(root_prompt, returned_context, "addrgrp")
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AddressGroupSshTransportError(_UNAVAILABLE) from exc

    async def _run_addrgrp_context(
        self,
        process: Any,
        root_prompt: bytes,
        commands: tuple[str, ...],
        deadline: float,
    ) -> bytes:
        context_prompt = _addrgrp_context_prompt(root_prompt)
        try:
            await _send_and_read(
                process,
                "config firewall addrgrp",
                context_prompt,
                deadline,
            )
            outputs = [
                await _send_and_read(process, command, context_prompt, deadline)
                for command in commands
            ]
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return b"".join(outputs)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AddressGroupSshTransportError(_UNAVAILABLE) from exc

    async def _run_address_context(
        self,
        process: Any,
        root_prompt: bytes,
        commands: tuple[str, ...],
        deadline: float,
    ) -> bytes:
        context_prompt = _address_context_prompt(root_prompt)
        try:
            await _send_and_read(
                process,
                "config firewall address",
                context_prompt,
                deadline,
            )
            outputs = [
                await _send_and_read(process, command, context_prompt, deadline)
                for command in commands
            ]
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return b"".join(outputs)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AddressGroupSshTransportError(_UNAVAILABLE) from exc

    def _connection(self) -> Any:
        return asyncssh.connect(
            self._config.host,
            port=self._config.port,
            username=self._config.username,
            password=self._config.password,
            known_hosts=str(self._config.known_hosts_file),
            client_keys=None,
            agent_path=None,
            preferred_auth="password",
            public_key_auth=False,
            password_auth=True,
            kbdint_auth=False,
            host_based_auth=False,
            gss_auth=False,
            gss_kex=False,
            config=[],
            connect_timeout=self._config.timeout_seconds,
            keepalive_interval=5,
            keepalive_count_max=1,
        )

    async def _open_cli(self, connection: Any) -> tuple[Any, bytes, float]:
        try:
            process = await connection.create_process(
                term_type="vt100",
                term_size=(200, 24),
                encoding=None,
            )
            deadline = time.monotonic() + self._config.timeout_seconds
            root_prompt = await _complete_pre_login(
                process.stdout,
                process.stdin,
                deadline,
                _MAX_OUTPUT_BYTES,
                accept_pre_login_banner=False,
            )
            return process, root_prompt, deadline
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AddressGroupSshTransportError(_UNAVAILABLE) from exc


def _readback(
    output: bytes,
    group_name: str,
    member_name: str,
) -> AddressGroupReadback:
    normalized = output.replace(b"\r", b"")
    group_marker = f'edit "{group_name}"'.encode("ascii")
    member_pattern = re.compile(
        rb"^\s*set member\s+(?:\"?"
        + re.escape(member_name.encode("ascii"))
        + rb"\"?)\s*$",
        re.MULTILINE,
    )
    return AddressGroupReadback(
        group_exists=group_marker in normalized,
        exactly_one_member_matches=member_pattern.search(normalized) is not None,
    )


def _reference_count(output: bytes, command: str, root_prompt: bytes) -> int:
    """Accept only one exact echo/prompt envelope and reference rows."""

    normalized = output.replace(b"\r", b"")
    lines = normalized.split(b"\n")
    if (
        len(lines) < 2
        or lines[0].strip() != command.encode("ascii")
        or lines[-1].rstrip(b" ") != root_prompt
    ):
        raise AddressGroupSshTransportError(_UNAVAILABLE)
    middle = [line for line in lines[1:-1] if line.strip()]
    if any(b"entry used by" not in line.lower() for line in middle):
        raise AddressGroupSshTransportError(_UNAVAILABLE)
    return len(middle)


def _addrgrp_context_prompt(root_prompt: bytes) -> bytes:
    if len(root_prompt) < 3 or root_prompt[-2:-1] != b" " or root_prompt[-1:] not in {
        b"#",
        b"$",
    }:
        raise AddressGroupSshTransportError(_UNAVAILABLE)
    return root_prompt[:-2] + b" (addrgrp) " + root_prompt[-1:]


def _address_context_prompt(root_prompt: bytes) -> bytes:
    if len(root_prompt) < 3 or root_prompt[-2:-1] != b" " or root_prompt[-1:] not in {
        b"#",
        b"$",
    }:
        raise AddressGroupSshTransportError(_UNAVAILABLE)
    return root_prompt[:-2] + b" (address) " + root_prompt[-1:]


def _object_name(value: str) -> str:
    if not _safe_name(value):
        raise AddressGroupSshTransportError(_UNAVAILABLE)
    return value


def _safe_name(value: str) -> bool:
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


def _safe_host(value: str) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 255
        and not any(character.isspace() or character in "@/\\" for character in value)
    )


def _private_regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AddressGroupSshTransportConfigurationError(
            f"The Address Group SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise AddressGroupSshTransportConfigurationError(
            f"The Address Group SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AddressGroupSshTransportConfigurationError(
            f"The Address Group SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AddressGroupSshTransportConfigurationError(
            "The Address Group SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AddressGroupSshTransportConfigurationError(
            "The Address Group SSH password file is invalid."
        ) from exc


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except AddressGroupSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise AddressGroupSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "AddressGroupInspection",
    "AddressGroupReferenceReadback",
    "AddressGroupReadback",
    "AddressGroupSshTransportConfig",
    "AddressGroupSshTransportConfigurationError",
    "AddressGroupSshTransportError",
    "AddressSshInspection",
    "ENV_PREFIX",
    "FortiPamAddressGroupSshTransport",
    "load_address_group_ssh_transport_config",
]
