"""Pinned, time-boxed FortiPAM WAD debug diagnostic transport.

This adapter implements only the CLI sequence validated during the FortiPAM
ZTNA incident: inspect the global debug state, enable the three fixed WAD
categories, collect the bounded diagnostic window, and disable global debug in
the same SSH session.  It never accepts CLI text, an endpoint, a tag, a user,
or a Secret from the MCP caller.  Raw appliance output is categorized in
process and discarded before the workflow boundary.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, cast

import asyncssh
from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.execution_kernel import M4ExecutionStateStore, _require_m4_dispatch_ownership

from .cli_safety import CliTransportError, _complete_pre_login
from . import target_qualified_reference_reader as _source_reader
from .target_ssh_transport import _close_cli, _require_root_prompt, _send_and_read


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ZTNA_WAD_DEBUG_"
ZTNA_WAD_DEBUG_CONFIGURATION = "fixed-secret-gateway-svc-conn-timeboxed-v1"
_DEBUG_INFO_COMMAND = "diagnose debug info"
_BUILD29_DEBUG_STATE_COMMAND = 'diagnose debug info | grep "^debug output:"'
_M4_ACTION = "ztna-wad-debug-capture"
_M4_VERSION = "2.0.0"
_M4_ADAPTER = "fortipam-build29-wad-debug-m4-v2"
_DEBUG_ENABLE_COMMANDS = (
    "diagnose wad debug enable level verbose",
    "diagnose wad debug enable category secret",
    "diagnose wad debug enable category gateway",
    "diagnose wad debug enable category svc-conn",
    "diagnose debug enable",
)
_DEBUG_DISABLE_COMMAND = "diagnose debug disable"
_UNAVAILABLE = "FortiPAM V4 ZTNA WAD debug diagnostic is unavailable."
_MAX_OUTPUT_BYTES = 128 * 1024
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DEBUG_DISABLED = re.compile(
    rb"\bdebug(?:ging)?(?:\s+output)?\s*(?:is\s*)?(?:disabled|disable|off)\b",
    re.IGNORECASE,
)
_DEBUG_ENABLED = re.compile(
    rb"\bdebug(?:ging)?(?:\s+output)?\s*(?:is\s*)?(?:enabled|enable|on)\b",
    re.IGNORECASE,
)
_GUI_ALLOW = re.compile(rb"\bgui_allow_launch\s+value\s*[:=]\s*1\b", re.IGNORECASE)


class ZtnaWadDebugSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded WAD diagnostic."""


class ZtnaWadDebugSshTransportConfigurationError(ValueError):
    """Raised when dedicated WAD diagnostic SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class ZtnaWadDebugSshTransportConfig:
    """Dedicated SSH settings and an operator-set bounded capture duration."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float
    capture_window_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise ZtnaWadDebugSshTransportConfigurationError(
                "The ZTNA WAD debug SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise ZtnaWadDebugSshTransportConfigurationError(
                "The ZTNA WAD debug SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise ZtnaWadDebugSshTransportConfigurationError(
                "The ZTNA WAD debug SSH port is invalid."
            )
        if not 15 <= self.timeout_seconds <= 60:
            raise ZtnaWadDebugSshTransportConfigurationError(
                "The ZTNA WAD debug SSH timeout is invalid."
            )
        if not 3 <= self.capture_window_seconds <= 30:
            raise ZtnaWadDebugSshTransportConfigurationError(
                "The ZTNA WAD debug capture window is invalid."
            )
        if self.capture_window_seconds > self.timeout_seconds - 8:
            raise ZtnaWadDebugSshTransportConfigurationError(
                "The ZTNA WAD debug capture window exceeds the safe SSH timeout budget."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise ZtnaWadDebugSshTransportConfigurationError(
                "The ZTNA WAD debug SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class ZtnaWadDebugInspection:
    """Categorical global-debug preflight state."""

    debug_is_disabled: bool


@dataclass(frozen=True, slots=True)
class ZtnaWadDebugReadback:
    """Sanitized time-boxed WAD diagnostic and cleanup evidence."""

    capture_collected: bool
    cleanup_confirmed: bool
    device_context_state: str
    device_tag_match_state: str
    launch_authorization_state: str

    @property
    def verified(self) -> bool:
        return self.capture_collected and self.cleanup_confirmed


def load_ztna_wad_debug_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ZtnaWadDebugSshTransportConfig:
    """Load the separately gated WAD diagnostic SSH configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise ZtnaWadDebugSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "20"
    window_raw = _value(env, "CAPTURE_WINDOW_SECONDS") or "10"
    if None in {host, username, password_file, known_hosts_file}:
        raise ZtnaWadDebugSshTransportConfigurationError(
            "Dedicated ZTNA WAD debug SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
        window = float(window_raw)
    except ValueError as exc:
        raise ZtnaWadDebugSshTransportConfigurationError(
            "The ZTNA WAD debug numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return ZtnaWadDebugSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
        capture_window_seconds=window,
    )


class FortiPamZtnaWadDebugSshTransport:
    """Run only the compiled WAD debug sequence and always attempt cleanup."""

    def __init__(self, config: ZtnaWadDebugSshTransportConfig, *,
                 build29_serial_digest: str | None = None) -> None:
        if build29_serial_digest is not None and (
            type(build29_serial_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", build29_serial_digest) is None
        ):
            raise ZtnaWadDebugSshTransportConfigurationError(_UNAVAILABLE)
        self._config = config
        # Private opt-in only. Existing environment/runtime bindings keep the
        # original unprojected preflight and its rejection semantics.
        self._build29_serial_digest = build29_serial_digest

    def inspect(self) -> ZtnaWadDebugInspection:
        return cast(ZtnaWadDebugInspection, _run_sync(self._inspect()))

    def capture_and_cleanup(self) -> ZtnaWadDebugReadback:
        if self._build29_serial_digest is not None:
            raise ZtnaWadDebugSshTransportError(_UNAVAILABLE)
        return cast(ZtnaWadDebugReadback, _run_sync(self._capture_and_cleanup()))

    def capture_m4_owned(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                         store: M4ExecutionStateStore, *, clock: Callable[[], int]) -> ZtnaWadDebugReadback:
        """Private build29 capture only in the original active M4 dispatch."""
        ownership = (plan, authorization, store)
        self._check_m4(ownership, clock)
        async def bounded() -> ZtnaWadDebugReadback:
            try:
                async with asyncio.timeout(20):
                    return await self._capture_and_cleanup(m4_ownership=ownership, m4_clock=clock)
            except TimeoutError:
                raise ZtnaWadDebugSshTransportError(_UNAVAILABLE) from None
        return cast(ZtnaWadDebugReadback, _run_sync(bounded()))

    def _check_m4(self, ownership: tuple[M4ExecutionPlan, M4ExecutionAuthorization, M4ExecutionStateStore],
                  clock: Callable[[], int]) -> None:
        try:
            plan, authorization, store = ownership
            _require_m4_dispatch_ownership(plan, authorization, store)
            now = clock()
            if (self._build29_serial_digest is None or type(now) is not int
                    or self._config.capture_window_seconds != 10 or self._config.timeout_seconds != 20
                    or not authorization.issued_at <= now < min(plan.expires_at, authorization.expires_at)
                    or (plan.action_id, plan.action_version, plan.adapter_ref) != (_M4_ACTION, _M4_VERSION, _M4_ADAPTER)):
                raise ValueError
        except Exception:
            raise ZtnaWadDebugSshTransportError(_UNAVAILABLE) from None

    async def _inspect(self) -> ZtnaWadDebugInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._debug_info(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        state = self._debug_state(output, root_prompt)
        if state is None:
            raise ZtnaWadDebugSshTransportError(_UNAVAILABLE)
        return ZtnaWadDebugInspection(debug_is_disabled=state)

    async def _capture_and_cleanup(self, *,
            m4_ownership: tuple[M4ExecutionPlan, M4ExecutionAuthorization, M4ExecutionStateStore] | None = None,
            m4_clock: Callable[[], int] | None = None) -> ZtnaWadDebugReadback:
        cleanup_confirmed = False
        captured = b""
        try:
            async with self._connection() as connection:
                process, root_prompt, deadline = await self._open_cli(connection)
                cleanup_required = False
                try:
                    preflight = await self._debug_info(process, root_prompt, deadline)
                    if self._debug_state(preflight, root_prompt) is not True:
                        raise ZtnaWadDebugSshTransportError(_UNAVAILABLE)
                    if self._build29_serial_digest is not None:
                        if m4_ownership is None or m4_clock is None:
                            raise ZtnaWadDebugSshTransportError(_UNAVAILABLE)
                        self._check_m4(m4_ownership, m4_clock)
                    # Any enable may reach the appliance before its response
                    # fails. Reserve cleanup before the first such dispatch.
                    cleanup_required = True
                    for command in _DEBUG_ENABLE_COMMANDS:
                        await _send_and_read(process, command, root_prompt, deadline)
                    if self._build29_serial_digest is not None:
                        active = await self._debug_info(process, root_prompt, deadline)
                        if self._debug_state(active, root_prompt) is not False:
                            raise ZtnaWadDebugSshTransportError(_UNAVAILABLE)
                    await asyncio.sleep(self._config.capture_window_seconds)
                finally:
                    if cleanup_required:
                        captured, cleanup_confirmed = await self._finish_cleanup(process, root_prompt)
                    else:
                        await _close_cli(process)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaWadDebugSshTransportError(_UNAVAILABLE) from exc
        if not cleanup_confirmed:
            return ZtnaWadDebugReadback(
                capture_collected=False,
                cleanup_confirmed=False,
                device_context_state="unknown",
                device_tag_match_state="unknown",
                launch_authorization_state="unknown",
            )
        return _project_capture(captured, cleanup_confirmed=True)

    async def _finish_cleanup(self, process: Any, root_prompt: bytes) -> tuple[bytes, bool]:
        """Complete one bounded cleanup despite cancellation of its caller.

        The child retains the same live SSH process and an independent cleanup
        deadline. Cancellation is propagated only after it finishes; there is
        no background cleanup left racing connection closure and no disable
        retry after an uncertain dispatch.
        """
        async def cleanup() -> tuple[bytes, bool]:
            output, confirmed = b"", False
            try:
                async with asyncio.timeout(5):
                    deadline = time.monotonic() + 5
                    output = await _send_and_read(process, _DEBUG_DISABLE_COMMAND, root_prompt, deadline)
                    final = await self._debug_info(process, root_prompt, deadline)
                    confirmed = self._debug_state(final, root_prompt) is True
            except Exception:
                output, confirmed = b"", False
            finally:
                try:
                    async with asyncio.timeout(1):
                        await _close_cli(process)
                except Exception:
                    output, confirmed = b"", False
            return output, confirmed

        task = asyncio.create_task(cleanup())
        cancellation = None
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError as error:
                cancellation = error
        result = task.result()
        if cancellation is not None:
            raise cancellation
        return result

    async def _debug_info(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        try:
            if self._build29_serial_digest is None:
                return await _send_and_read(process, _DEBUG_INFO_COMMAND, root_prompt, deadline)
            await self._qualify_build29_device(process, root_prompt, deadline)
            output = await _send_and_read(process, _BUILD29_DEBUG_STATE_COMMAND, root_prompt, deadline)
            await self._qualify_build29_device(process, root_prompt, deadline)
            return output
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaWadDebugSshTransportError(_UNAVAILABLE) from exc

    async def _qualify_build29_device(self, process: Any, root_prompt: bytes, deadline: float) -> None:
        try:
            raw = await _send_and_read(process, _source_reader._SERIAL, root_prompt, deadline)
            lines = _source_reader._lines(raw, _source_reader._SERIAL, root_prompt)
            match = re.fullmatch(rb"Serial-Number: ([A-Za-z0-9_-]{1,128})", lines[0]) if len(lines) == 1 else None
            if (match is None or self._build29_serial_digest is None
                    or not hmac.compare_digest(hashlib.sha256(match[1]).hexdigest(), self._build29_serial_digest)):
                raise ValueError
            raw = await _send_and_read(process, _source_reader._VERSION, root_prompt, deadline)
            _source_reader._version(_source_reader._lines(raw, _source_reader._VERSION, root_prompt))
        except Exception:
            raise ZtnaWadDebugSshTransportError(_UNAVAILABLE) from None

    def _debug_state(self, output: bytes, root_prompt: bytes) -> bool | None:
        if self._build29_serial_digest is None:
            return _debug_is_disabled(output)
        try:
            if _contains_failure_marker(_normalized(output)):
                raise ValueError
            lines = _source_reader._lines(output, _BUILD29_DEBUG_STATE_COMMAND, root_prompt)
            match = re.fullmatch(rb"[ \t]*debug output[ \t]*:[ \t]*(disable|enable)[ \t]*",
                lines[0]) if len(lines) == 1 else None
            if match is None:
                raise ValueError
            return match[1] == b"disable"
        except Exception:
            raise ZtnaWadDebugSshTransportError(_UNAVAILABLE) from None

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
                term_type="vt100", term_size=(80, 24), encoding=None
            )
            deadline = time.monotonic() + self._config.timeout_seconds
            root_prompt = await _complete_pre_login(
                process.stdout,
                process.stdin,
                deadline,
                _MAX_OUTPUT_BYTES,
                accept_pre_login_banner=False,
            )
            _require_root_prompt(root_prompt, root_prompt)
            return process, root_prompt, deadline
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaWadDebugSshTransportError(_UNAVAILABLE) from exc


def _project_capture(output: bytes, *, cleanup_confirmed: bool) -> ZtnaWadDebugReadback:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ZtnaWadDebugSshTransportError(_UNAVAILABLE)
    lowered = normalized.lower()
    context_missing = b"device context is not available" in lowered
    current_tags = b"current device tags" in lowered
    tag_matched = b"matched device tag" in lowered
    launch_allowed = bool(_GUI_ALLOW.search(normalized)) and b"token check passed" in lowered
    return ZtnaWadDebugReadback(
        capture_collected=True,
        cleanup_confirmed=cleanup_confirmed,
        device_context_state=(
            "missing"
            if context_missing
            else "available"
            if current_tags and tag_matched
            else "inconclusive"
        ),
        device_tag_match_state="matched" if tag_matched else "not_observed",
        launch_authorization_state=("allowed" if launch_allowed else "not_observed"),
    )


def _debug_is_disabled(output: bytes) -> bool | None:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ZtnaWadDebugSshTransportError(_UNAVAILABLE)
    disabled = bool(_DEBUG_DISABLED.search(normalized))
    enabled = bool(_DEBUG_ENABLED.search(normalized))
    if disabled == enabled:
        return None
    return disabled


def _normalized(output: bytes) -> bytes:
    if len(output) > _MAX_OUTPUT_BYTES:
        raise ZtnaWadDebugSshTransportError(_UNAVAILABLE)
    return output.replace(b"\r", b"")


def _contains_failure_marker(output: bytes) -> bool:
    lowered = output.lower()
    return any(
        marker in lowered
        for marker in (
            b"permission denied",
            b"not permitted",
            b"not allowed",
            b"access denied",
            b"command fail",
            b"unknown action",
            b"unknown command",
            b"parse error",
        )
    )


def _safe_name(value: str) -> bool:
    return isinstance(value, str) and _SAFE_NAME.fullmatch(value) is not None


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
        raise ZtnaWadDebugSshTransportConfigurationError(
            f"The ZTNA WAD debug {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ZtnaWadDebugSshTransportConfigurationError(
            f"The ZTNA WAD debug {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ZtnaWadDebugSshTransportConfigurationError(
            f"The ZTNA WAD debug {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ZtnaWadDebugSshTransportConfigurationError(
            "The ZTNA WAD debug password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ZtnaWadDebugSshTransportConfigurationError(
            "The ZTNA WAD debug password file is invalid."
        ) from exc


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    coroutine.close()
    raise ZtnaWadDebugSshTransportError(_UNAVAILABLE)


__all__ = [
    "ENV_PREFIX",
    "FortiPamZtnaWadDebugSshTransport",
    "ZTNA_WAD_DEBUG_CONFIGURATION",
    "ZtnaWadDebugInspection",
    "ZtnaWadDebugReadback",
    "ZtnaWadDebugSshTransportConfig",
    "ZtnaWadDebugSshTransportConfigurationError",
    "ZtnaWadDebugSshTransportError",
    "load_ztna_wad_debug_ssh_transport_config",
]
