"""Private, fixed HTTP-service fallback; not a registered execution action.

The owning M4 adapter must establish an exact existing Web Secret, reject drift,
consume authorization once, and verify readback. This transport never reads or
writes credential fields and never accepts caller-supplied CLI commands.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import asyncssh

from .approval_profile_ssh_transport import ApprovalProfileSshTransportConfig
from .cli_safety import CliTransportError, _complete_pre_login
from .secret_metadata_http_transport import SecretMetadataProjectionInspection
from .target_ssh_transport import (
    _close_cli, _require_root_prompt, _send_and_read, _send_and_read_dynamic_prompt,
)

API_UNAVAILABLE_REASON = "rest-field-replacement-20260915"
_UNAVAILABLE = "Web Secret HTTP-service transport is unavailable."


class WebSecretServiceSshTransportError(RuntimeError):
    """Categorical failure without connection or device output."""


class FortiPamWebSecretServiceSshTransport:
    """Enable only HTTP service on a caller-verified existing Web Secret."""

    def __init__(
        self, config: ApprovalProfileSshTransportConfig, *,
        enabled: bool = False, api_unavailable_reason: str = "",
    ) -> None:
        if (
            not isinstance(config, ApprovalProfileSshTransportConfig)
            or enabled is not True
            or api_unavailable_reason != API_UNAVAILABLE_REASON
        ):
            raise WebSecretServiceSshTransportError(_UNAVAILABLE)
        self._config = config

    def enable_http_service(
        self, secret_id: int, *, prewrite: SecretMetadataProjectionInspection,
    ) -> None:
        if (
            type(secret_id) is not int or not 0 < secret_id <= 2_147_483_647
            or not isinstance(prewrite, SecretMetadataProjectionInspection)
            or any(value is not True for value in (
                prewrite.secret_exists, prewrite.folder_exists,
                prewrite.template_exists, prewrite.folder_matches,
                prewrite.template_matches, prewrite.target_matches,
                prewrite.inherit_permission_matches, prewrite.recording_matches,
            ))
            or prewrite.http_service_enabled is not False
        ):
            raise WebSecretServiceSshTransportError(_UNAVAILABLE)
        coroutine = self._enable(secret_id)
        try:
            asyncio.run(coroutine)
        except RuntimeError:
            coroutine.close()
            raise WebSecretServiceSshTransportError(_UNAVAILABLE) from None

    async def _enable(self, secret_id: int) -> None:
        try:
            async with asyncssh.connect(
                self._config.host, port=self._config.port,
                username=self._config.username, password=self._config.password,
                known_hosts=str(self._config.known_hosts_file),
                client_keys=None, agent_path=None, preferred_auth="password",
                public_key_auth=False, password_auth=True, kbdint_auth=False,
                host_based_auth=False, gss_auth=False, gss_kex=False, config=[],
                connect_timeout=self._config.timeout_seconds,
                keepalive_interval=5, keepalive_count_max=1,
            ) as connection:
                process = await connection.create_process(
                    term_type="vt100", term_size=(200, 24), encoding=None,
                )
                try:
                    deadline = time.monotonic() + self._config.timeout_seconds
                    root = await _complete_pre_login(
                        process.stdout, process.stdin, deadline, 64 * 1024,
                        accept_pre_login_banner=False,
                    )
                    await self._apply(process, root, deadline, secret_id)
                finally:
                    await _close_cli(process)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError):
            raise WebSecretServiceSshTransportError(_UNAVAILABLE) from None

    async def _apply(
        self, process: Any, root: bytes, deadline: float, secret_id: int,
    ) -> None:
        table = await _send_and_read_dynamic_prompt(
            process, "config secret database", root, deadline,
        )
        entry = await _send_and_read_dynamic_prompt(
            process, f"edit {secret_id}", root, deadline,
        )
        await _send_and_read(process, "set http-service-status up", entry, deadline)
        returned = await _send_and_read_dynamic_prompt(process, "next", root, deadline)
        if returned != table:
            raise WebSecretServiceSshTransportError(_UNAVAILABLE)
        returned = await _send_and_read_dynamic_prompt(process, "end", root, deadline)
        _require_root_prompt(root, returned)
