"""Read-only CMDB reference count for one fixed Classification Tag recovery."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
import re
import time
from typing import Any, cast

import asyncssh

from .cli_safety import CliTransportError, _complete_pre_login
from .target_ssh_transport import (
    TargetSshTransportConfig,
    _close_cli,
    _send_and_read,
)


_NAME = re.compile(r"mcp-v4-classification-tag-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_UNAVAILABLE = "FortiPAM V4 Classification Tag recovery is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_TERMINAL_COLUMNS = 200


class ClassificationTagReferenceSshTransportError(RuntimeError):
    """Stable failure for the fixed read-only reference probe."""


class FortiPamClassificationTagReferenceSshTransport:
    """Run only the compiled CMDB reference-count command for one Tag."""

    def __init__(self, config: TargetSshTransportConfig) -> None:
        self._config = config

    def reference_count(self, tag_name: str) -> int:
        safe_name = _tag_name(tag_name)
        return cast(int, _run_sync(self._reference_count(safe_name)))

    async def _reference_count(self, tag_name: str) -> int:
        command = (
            "diagnose sys cmdb refcnt show secret.classification-tag.name "
            + tag_name
        )
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
        return _strict_reference_count(output, command, root_prompt)

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
                term_size=(_TERMINAL_COLUMNS, 24),
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
            raise ClassificationTagReferenceSshTransportError(_UNAVAILABLE) from exc


def _strict_reference_count(output: bytes, command: str, root_prompt: bytes) -> int:
    normalized = output.replace(b"\r", b"")
    lines = normalized.split(b"\n")
    if (
        len(lines) < 2
        or lines[0].strip() != command.encode("ascii")
        or lines[-1].rstrip(b" ") != root_prompt
    ):
        raise ClassificationTagReferenceSshTransportError(_UNAVAILABLE)
    middle = [line for line in lines[1:-1] if line.strip()]
    if any(b"entry used by" not in line.lower() for line in middle):
        raise ClassificationTagReferenceSshTransportError(_UNAVAILABLE)
    return len(middle)


def _tag_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ClassificationTagReferenceSshTransportError(_UNAVAILABLE)
    return value


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except ClassificationTagReferenceSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise ClassificationTagReferenceSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ClassificationTagReferenceSshTransportError",
    "FortiPamClassificationTagReferenceSshTransport",
]
