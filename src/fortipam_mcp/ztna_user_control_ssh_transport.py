"""Pinned SSH fallback for one FortiPAM Access-level ZTNA control transition.

FortiPAM 1.9.1 documents Access-level ZTNA in the FortiGate-style CLI, but
the catalog does not establish a FortiPAM 1.9.1 REST write body for this
policy.  This adapter therefore changes only ``ztna-status`` from ``disable``
to ``enable`` on one private, pre-bound Access Proxy policy.  It first proves
that the policy already references one expected EMS tag and that the associated
Access Proxy already enforces client certificates for managed-only access.

It never changes the Access Proxy, certificate handling, EMS connector or tag,
policy references, Folder/Secret controls, WAD debugging, or sessions.
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
    _require_root_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ZTNA_USER_CONTROL_"
ZTNA_USER_CONTROL_CONFIGURATION = "access-level-enable-existing-ems-tag-v1"
ZTNA_USER_CONTROL_ROLLBACK_CONFIGURATION = "access-level-disable-existing-ems-tag-v1"
_ACCESS_PROXY_CONFIG_COMMAND = "config firewall access-proxy"
_POLICY_CONFIG_COMMAND = "config firewall policy"
_UNAVAILABLE = "FortiPAM V4 ZTNA user-control transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 80
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_POLICY_ID = re.compile(r"[1-9][0-9]{0,8}\Z")
_EDIT_NAME_LINE = re.compile(
    rb"(?P<indent>[ \t]*)edit[ \t]+(?:\"(?P<quoted>[^\"\r\n]+)\"|(?P<bare>[A-Za-z0-9][A-Za-z0-9._-]{0,127}))[ \t]*"
)
_EDIT_POLICY_LINE = re.compile(
    rb"(?P<indent>[ \t]*)edit[ \t]+(?P<policy>[1-9][0-9]{0,8})[ \t]*"
)


class ZtnaUserControlSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH adapter."""


class ZtnaUserControlSshTransportConfigurationError(ValueError):
    """Raised when private, fixed ZTNA user-control settings are unsafe."""


@dataclass(frozen=True, slots=True)
class ZtnaUserControlSshTransportConfig:
    """Dedicated SSH settings and private policy/tag references."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    access_proxy_name: str
    policy_id: str
    ems_tag_name: str
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise ZtnaUserControlSshTransportConfigurationError(
                "The ZTNA user-control SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise ZtnaUserControlSshTransportConfigurationError(
                "The ZTNA user-control SSH username is invalid."
            )
        if not _safe_name(self.access_proxy_name) or not _safe_name(self.ems_tag_name):
            raise ZtnaUserControlSshTransportConfigurationError(
                "The ZTNA user-control private object reference is invalid."
            )
        if _POLICY_ID.fullmatch(self.policy_id) is None:
            raise ZtnaUserControlSshTransportConfigurationError(
                "The ZTNA user-control private policy reference is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise ZtnaUserControlSshTransportConfigurationError(
                "The ZTNA user-control SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise ZtnaUserControlSshTransportConfigurationError(
                "The ZTNA user-control SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise ZtnaUserControlSshTransportConfigurationError(
                "The ZTNA user-control SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class ZtnaUserControlInspection:
    """Value-minimized prerequisite state of the protected Access Proxy policy."""

    client_certificate_mode: str
    empty_certificate_action: str
    policy_is_access_proxy: bool
    policy_access_proxy_matches: bool
    policy_ems_tag_matches: bool
    ztna_status: str

    @property
    def exact_disabled_access_level_baseline(self) -> bool:
        return (
            self.client_certificate_mode == "enable"
            and self.empty_certificate_action == "block"
            and self.policy_is_access_proxy
            and self.policy_access_proxy_matches
            and self.policy_ems_tag_matches
            and self.ztna_status == "disable"
        )

    @property
    def exact_enabled_access_level_baseline(self) -> bool:
        """Return whether the fixed forward outcome is eligible for rollback."""

        return (
            self.client_certificate_mode == "enable"
            and self.empty_certificate_action == "block"
            and self.policy_is_access_proxy
            and self.policy_access_proxy_matches
            and self.policy_ems_tag_matches
            and self.ztna_status == "enable"
        )


@dataclass(frozen=True, slots=True)
class ZtnaUserControlReadback:
    """Categorical readback of the one Access-level ZTNA transition."""

    client_certificate_mode: str
    empty_certificate_action: str
    policy_is_access_proxy: bool
    policy_access_proxy_matches: bool
    policy_ems_tag_matches: bool
    ztna_status: str

    @property
    def verified(self) -> bool:
        return (
            self.client_certificate_mode == "enable"
            and self.empty_certificate_action == "block"
            and self.policy_is_access_proxy
            and self.policy_access_proxy_matches
            and self.policy_ems_tag_matches
            and self.ztna_status == "enable"
        )

    @property
    def verified_disabled(self) -> bool:
        """Return whether the original disabled policy state was restored."""

        return (
            self.client_certificate_mode == "enable"
            and self.empty_certificate_action == "block"
            and self.policy_is_access_proxy
            and self.policy_access_proxy_matches
            and self.policy_ems_tag_matches
            and self.ztna_status == "disable"
        )


def load_ztna_user_control_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ZtnaUserControlSshTransportConfig:
    """Load only independently scoped, non-generic SSH configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise ZtnaUserControlSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    access_proxy_name = _value(env, "ACCESS_PROXY_NAME")
    policy_id = _value(env, "POLICY_ID")
    ems_tag_name = _value(env, "EMS_TAG_NAME")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {
        host,
        username,
        password_file,
        known_hosts_file,
        access_proxy_name,
        policy_id,
        ems_tag_name,
    }:
        raise ZtnaUserControlSshTransportConfigurationError(
            "Dedicated ZTNA user-control SSH settings and private policy/tag references are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ZtnaUserControlSshTransportConfigurationError(
            "The ZTNA user-control SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    assert access_proxy_name is not None
    assert policy_id is not None
    assert ems_tag_name is not None
    return ZtnaUserControlSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        access_proxy_name=access_proxy_name,
        policy_id=policy_id,
        ems_tag_name=ems_tag_name,
        timeout_seconds=timeout,
    )


class FortiPamZtnaUserControlSshTransport:
    """Run only compiled Access-level ZTNA preflight and status transitions."""

    def __init__(self, config: ZtnaUserControlSshTransportConfig) -> None:
        self._config = config

    def inspect(self) -> ZtnaUserControlInspection:
        return cast(ZtnaUserControlInspection, _run_sync(self._inspect()))

    def enable_and_readback(self) -> ZtnaUserControlReadback:
        return cast(ZtnaUserControlReadback, _run_sync(self._enable_and_readback()))

    def disable_and_readback(self) -> ZtnaUserControlReadback:
        """Restore only the accepted pre-action policy status."""

        return cast(ZtnaUserControlReadback, _run_sync(self._disable_and_readback()))

    async def _inspect(self) -> ZtnaUserControlInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                access_proxy_output, policy_output = await self._read_current(
                    process,
                    root_prompt,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _inspection(access_proxy_output, policy_output, self._config)

    async def _enable_and_readback(self) -> ZtnaUserControlReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                access_proxy_output, policy_output = await self._read_current(
                    process,
                    root_prompt,
                    deadline,
                )
                baseline = _inspection(access_proxy_output, policy_output, self._config)
                if not baseline.exact_disabled_access_level_baseline:
                    raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
                await self._enable_policy(process, root_prompt, deadline)
                access_proxy_output, policy_output = await self._read_current(
                    process,
                    root_prompt,
                    deadline,
                )
            finally:
                await _close_cli(process)
        current = _inspection(access_proxy_output, policy_output, self._config)
        return ZtnaUserControlReadback(
            client_certificate_mode=current.client_certificate_mode,
            empty_certificate_action=current.empty_certificate_action,
            policy_is_access_proxy=current.policy_is_access_proxy,
            policy_access_proxy_matches=current.policy_access_proxy_matches,
            policy_ems_tag_matches=current.policy_ems_tag_matches,
            ztna_status=current.ztna_status,
        )

    async def _disable_and_readback(self) -> ZtnaUserControlReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                access_proxy_output, policy_output = await self._read_current(
                    process,
                    root_prompt,
                    deadline,
                )
                baseline = _inspection(access_proxy_output, policy_output, self._config)
                if not baseline.exact_enabled_access_level_baseline:
                    raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
                await self._disable_policy(process, root_prompt, deadline)
                access_proxy_output, policy_output = await self._read_current(
                    process,
                    root_prompt,
                    deadline,
                )
            finally:
                await _close_cli(process)
        current = _inspection(access_proxy_output, policy_output, self._config)
        return ZtnaUserControlReadback(
            client_certificate_mode=current.client_certificate_mode,
            empty_certificate_action=current.empty_certificate_action,
            policy_is_access_proxy=current.policy_is_access_proxy,
            policy_access_proxy_matches=current.policy_access_proxy_matches,
            policy_ems_tag_matches=current.policy_ems_tag_matches,
            ztna_status=current.ztna_status,
        )

    async def _read_current(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> tuple[tuple[bytes, bytes], tuple[bytes, bytes]]:
        access_proxy_output = await self._show_table_filtered(
            process,
            root_prompt,
            _ACCESS_PROXY_CONFIG_COMMAND,
            self._config.access_proxy_name,
            deadline,
        )
        policy_output = await self._show_table_filtered(
            process,
            root_prompt,
            _POLICY_CONFIG_COMMAND,
            self._config.policy_id,
            deadline,
        )
        return access_proxy_output, policy_output

    async def _show_table_filtered(
        self,
        process: Any,
        root_prompt: bytes,
        config_command: str,
        filter_value: str,
        deadline: float,
    ) -> tuple[bytes, bytes]:
        if config_command == _ACCESS_PROXY_CONFIG_COMMAND:
            command = (
                "show full-configuration firewall access-proxy | grep -A "
                f'{_FULL_CONTEXT_LINES} "^ *edit.*{filter_value}"'
            )
        elif config_command == _POLICY_CONFIG_COMMAND:
            command = (
                "show full-configuration firewall policy | grep -A "
                f'{_FULL_CONTEXT_LINES} "^ *edit {filter_value}"'
            )
        else:
            raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
        try:
            full = await _send_and_read(
                process,
                command,
                root_prompt,
                deadline,
            )
            return full, full
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaUserControlSshTransportError(_UNAVAILABLE) from exc

    async def _enable_policy(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _POLICY_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            policy_prompt = await _send_and_read_dynamic_prompt(
                process,
                f"edit {self._config.policy_id}",
                root_prompt,
                deadline,
            )
            await _send_and_read(process, "set ztna-status enable", policy_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaUserControlSshTransportError(_UNAVAILABLE) from exc

    async def _disable_policy(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _POLICY_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            policy_prompt = await _send_and_read_dynamic_prompt(
                process,
                f"edit {self._config.policy_id}",
                root_prompt,
                deadline,
            )
            await _send_and_read(process, "set ztna-status disable", policy_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaUserControlSshTransportError(_UNAVAILABLE) from exc

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
            return process, root_prompt, deadline
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaUserControlSshTransportError(_UNAVAILABLE) from exc


def _inspection(
    access_proxy_output: tuple[bytes, bytes],
    policy_output: tuple[bytes, bytes],
    config: ZtnaUserControlSshTransportConfig,
) -> ZtnaUserControlInspection:
    access_proxy_compact, access_proxy_full = access_proxy_output
    policy_compact, policy_full = policy_output
    _compact_has_exact_named_reference(access_proxy_compact, config.access_proxy_name)
    access_proxy_block = _select_named_block(access_proxy_full, config.access_proxy_name)
    _compact_has_exact_policy_reference(policy_compact, config.policy_id)
    policy_block = _select_policy_block(policy_full, config.policy_id)
    client_certificate_mode = _field_value(
        access_proxy_block,
        "client-cert",
        frozenset(("enable", "disable")),
    )
    empty_certificate_action = _field_value(
        access_proxy_block,
        "empty-cert-action",
        frozenset(("accept", "block")),
    )
    ztna_status = _field_value(
        policy_block,
        "ztna-status",
        frozenset(("enable", "disable")),
    )
    if "unknown" in {
        client_certificate_mode,
        empty_certificate_action,
        ztna_status,
    }:
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
    return ZtnaUserControlInspection(
        client_certificate_mode=client_certificate_mode,
        empty_certificate_action=empty_certificate_action,
        policy_is_access_proxy=_field_equals(policy_block, "type", "access-proxy"),
        policy_access_proxy_matches=_field_equals(
            policy_block,
            "access-proxy",
            config.access_proxy_name,
        ),
        policy_ems_tag_matches=_field_equals(
            policy_block,
            "ztna-ems-tag",
            config.ems_tag_name,
        ),
        ztna_status=ztna_status,
    )


def _select_named_block(output: bytes, expected_name: str) -> bytes:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
    expected = expected_name.encode("ascii")
    blocks = _selected_blocks(normalized, _EDIT_NAME_LINE, "quoted", expected)
    if len(blocks) == 1:
        return blocks[0]
    if not blocks:
        blocks = _selected_blocks(normalized, _EDIT_NAME_LINE, "bare", expected)
    if len(blocks) != 1:
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
    return blocks[0]


def _select_policy_block(output: bytes, expected_policy_id: str) -> bytes:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
    blocks = _selected_blocks(
        normalized,
        _EDIT_POLICY_LINE,
        "policy",
        expected_policy_id.encode("ascii"),
    )
    if len(blocks) != 1:
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
    return blocks[0]


def _compact_has_exact_named_reference(output: bytes, expected_name: str) -> None:
    """Prove a full bounded Access Proxy projection includes one exact object.

    The same bounded full-configuration context is later parsed as an object
    block. Keeping this independent exact locator makes an ambiguous grep
    match fail closed before any field comparison.
    """

    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
    expected = expected_name.encode("ascii")
    matches = [
        line
        for line in normalized.splitlines()
        if (match := _EDIT_NAME_LINE.fullmatch(line)) is not None
        and (match.group("quoted") == expected or match.group("bare") == expected)
    ]
    if len(matches) != 1:
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE)


def _compact_has_exact_policy_reference(output: bytes, expected_policy_id: str) -> None:
    """Prove a full bounded policy projection includes one exact policy ID."""

    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
    expected = expected_policy_id.encode("ascii")
    matches = [
        line
        for line in normalized.splitlines()
        if (match := _EDIT_POLICY_LINE.fullmatch(line)) is not None
        and match.group("policy") == expected
    ]
    if len(matches) != 1:
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE)


def _selected_blocks(
    output: bytes,
    pattern: re.Pattern[bytes],
    group: str,
    expected: bytes,
) -> list[bytes]:
    lines = output.splitlines(keepends=True)
    candidates: list[tuple[int, bytes]] = []
    for index, line in enumerate(lines):
        match = pattern.fullmatch(line.rstrip(b"\r\n"))
        if match is None or match.group(group) != expected:
            continue
        indent = match.group("indent")
        for end_index in range(index + 1, len(lines)):
            if lines[end_index].rstrip(b"\r\n") == indent + b"next":
                candidates.append((len(indent), b"".join(lines[index : end_index + 1])))
                break
        else:
            raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
    if not candidates:
        return []
    shallowest = min(indent for indent, _ in candidates)
    return [block for indent, block in candidates if indent == shallowest]


def _field_value(output: bytes, field: str, allowed: frozenset[str]) -> str:
    values = _field_values(output, field)
    accepted = values & allowed
    return next(iter(accepted)) if len(values) == 1 and len(accepted) == 1 else "unknown"


def _field_equals(output: bytes, field: str, expected: str) -> bool:
    return _field_values(output, field) == {expected}


def _field_values(output: bytes, field: str) -> set[str]:
    pattern = re.compile(
        rb"(?im)^\s*set\s+"
        + re.escape(field.encode("ascii"))
        + rb"\s+(?:\"([^\"\r\n]+)\"|([A-Za-z0-9._:-]+))\s*$"
    )
    values: set[str] = set()
    for match in pattern.finditer(output):
        raw = match.group(1) or match.group(2)
        if raw is None:
            continue
        try:
            values.add(raw.decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ZtnaUserControlSshTransportError(_UNAVAILABLE) from exc
    return values


def _normalized(output: bytes) -> bytes:
    if len(output) > _MAX_OUTPUT_BYTES:
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE)
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
        raise ZtnaUserControlSshTransportConfigurationError(
            f"The ZTNA user-control SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ZtnaUserControlSshTransportConfigurationError(
            f"The ZTNA user-control SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ZtnaUserControlSshTransportConfigurationError(
            f"The ZTNA user-control SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ZtnaUserControlSshTransportConfigurationError(
            "The ZTNA user-control SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ZtnaUserControlSshTransportConfigurationError(
            "The ZTNA user-control SSH password file is invalid."
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
    except ZtnaUserControlSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise ZtnaUserControlSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamZtnaUserControlSshTransport",
    "ZTNA_USER_CONTROL_CONFIGURATION",
    "ZTNA_USER_CONTROL_ROLLBACK_CONFIGURATION",
    "ZtnaUserControlInspection",
    "ZtnaUserControlReadback",
    "ZtnaUserControlSshTransportConfig",
    "ZtnaUserControlSshTransportConfigurationError",
    "ZtnaUserControlSshTransportError",
    "load_ztna_user_control_ssh_transport_config",
]
