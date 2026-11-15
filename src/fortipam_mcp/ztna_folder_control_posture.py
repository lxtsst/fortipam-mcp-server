"""Fixed, non-disclosing FortiPAM Folder-level ZTNA posture diagnostic.

The FortiPAM 1.9.1 GUI and CLI establish that a Secret Folder has an
inheritance control and a ZTNA EMS Tag field.  They do not establish a safe
value-bearing tag write, multi-tag composition, or AND/OR write contract.
This adapter consequently performs one fixed, server-configured read only. It
returns categorical Folder-control posture and never exposes a Folder ID, Tag
value, raw CLI output, identity, endpoint, or Secret data.
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
from typing import Any, Protocol, cast

import asyncssh

from .cli_safety import CliTransportError, _complete_pre_login
from .target_ssh_transport import (
    _close_cli,
    _require_root_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
)


WORKFLOW_CONTRACT = "fortipam_v4_ztna_folder_control_posture_v1"
ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ZTNA_FOLDER_POSTURE_"
V4_ZTNA_FOLDER_POSTURE_FEATURE_ENV = "FORTIPAM_MCP_V4_ZTNA_FOLDER_POSTURE_ENABLED"
V4_ZTNA_FOLDER_POSTURE_TOOL = "get_v4_ztna_folder_control_posture"
V4_ZTNA_FOLDER_POSTURE_SELECTOR_ENV = f"{ENV_PREFIX}FOLDER_ID"
UNAVAILABLE = "FortiPAM V4 ZTNA Folder-control posture diagnostic is unavailable."
_CONFIG_COMMAND = "config secret folder"
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 80
_FOLDER_ID = re.compile(r"[1-9][0-9]{0,8}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_EDIT_FOLDER_LINE = re.compile(
    rb"(?P<indent>[ \t]*)edit[ \t]+(?P<folder_id>[1-9][0-9]{0,8})[ \t]*"
)
_FIELD_LINE = re.compile(
    rb"(?im)^[ \t]*set[ \t]+ztna-ems-tag(?:[ \t]+(?P<value>[^\r\n]*))?[ \t]*$"
)


class ZtnaFolderControlPostureConfigurationError(ValueError):
    """Raised when private fixed diagnostic configuration is unsafe."""


class ZtnaFolderControlPostureTransportError(RuntimeError):
    """Stable non-disclosing failure for this fixed SSH diagnostic."""


@dataclass(frozen=True, slots=True)
class ZtnaFolderControlPostureConfig:
    """Pinned SSH settings and one private, server-configured Folder ID."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    folder_id: str
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise ZtnaFolderControlPostureConfigurationError(
                "The ZTNA Folder posture SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise ZtnaFolderControlPostureConfigurationError(
                "The ZTNA Folder posture SSH username is invalid."
            )
        if _FOLDER_ID.fullmatch(self.folder_id) is None:
            raise ZtnaFolderControlPostureConfigurationError(
                "The ZTNA Folder posture reference is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise ZtnaFolderControlPostureConfigurationError(
                "The ZTNA Folder posture SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise ZtnaFolderControlPostureConfigurationError(
                "The ZTNA Folder posture SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.password
        ):
            raise ZtnaFolderControlPostureConfigurationError(
                "The ZTNA Folder posture SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


class ZtnaFolderControlPostureTransport(Protocol):
    """Private compiled transport boundary for deterministic testing."""

    def collect(self) -> tuple[bytes, bytes]: ...


def load_v4_ztna_folder_posture_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Return exact feature opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ZTNA_FOLDER_POSTURE_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise ZtnaFolderControlPostureConfigurationError(
        f"{V4_ZTNA_FOLDER_POSTURE_FEATURE_ENV} must be exactly true or false."
    )


def load_ztna_folder_control_posture_config(
    environment: Mapping[str, str] | None = None,
) -> ZtnaFolderControlPostureConfig:
    """Load independently scoped, private pinned SSH settings."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise ZtnaFolderControlPostureConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    folder_id = _value(env, "FOLDER_ID")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file, folder_id}:
        raise ZtnaFolderControlPostureConfigurationError(
            "Dedicated ZTNA Folder posture SSH settings and one Folder reference are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ZtnaFolderControlPostureConfigurationError(
            "The ZTNA Folder posture SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    assert folder_id is not None
    return ZtnaFolderControlPostureConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        folder_id=folder_id,
        timeout_seconds=timeout,
    )


class FortiPamZtnaFolderControlPostureSshTransport:
    """Read a compact locator and bounded full context for one protected Folder."""

    def __init__(self, config: ZtnaFolderControlPostureConfig) -> None:
        self._config = config

    def collect(self) -> tuple[bytes, bytes]:
        return cast(tuple[bytes, bytes], _run_sync(self._collect()))

    async def _collect(self) -> tuple[bytes, bytes]:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                return await self._read_folder(process, root_prompt, deadline)
            finally:
                await _close_cli(process)

    def _commands(self) -> tuple[str, str, str]:
        """Return the complete fixed read-only command sequence."""

        return (
            _CONFIG_COMMAND,
            f"show | grep {self._config.folder_id}",
            "show full-configuration | grep -A "
            f'{_FULL_CONTEXT_LINES} "edit {self._config.folder_id}"',
        )

    async def _read_folder(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> tuple[bytes, bytes]:
        try:
            config_command, compact_command, full_command = self._commands()
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                config_command,
                root_prompt,
                deadline,
            )
            compact = await _send_and_read(
                process,
                compact_command,
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                full_command,
                table_prompt,
                deadline,
            )
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return compact, full
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaFolderControlPostureTransportError(UNAVAILABLE) from exc

    def _connection(self) -> Any:
        return asyncssh.connect(
            self._config.host,
            port=self._config.port,
            username=self._config.username,
            password=self._config.password,
            known_hosts=str(self._config.known_hosts_file),
            client_keys=(),
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
                term_size=(80, 24),
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
            raise ZtnaFolderControlPostureTransportError(UNAVAILABLE) from exc


class FortiPamZtnaFolderControlPosture:
    """Return only categorical Folder ZTNA posture from a fixed SSH read."""

    def __init__(
        self,
        transport: ZtnaFolderControlPostureTransport,
        *,
        folder_id: str,
    ) -> None:
        if _FOLDER_ID.fullmatch(folder_id) is None:
            raise ZtnaFolderControlPostureConfigurationError(UNAVAILABLE)
        self._transport = transport
        self._folder_id = folder_id

    def collect(self) -> dict[str, object]:
        try:
            compact, full = self._transport.collect()
            projection = _project(compact, full, folder_id=self._folder_id)
        except (ZtnaFolderControlPostureTransportError, OSError, RuntimeError, ValueError):
            return _failure()
        return {
            "contract": WORKFLOW_CONTRACT,
            "execution_status": "succeeded",
            **projection,
            "folder_reference_returned": False,
            "tag_value_returned": False,
            "raw_cli_returned": False,
            "device_write_executed": False,
            "secret_override_assessed": False,
            "match_logic_assessed": False,
        }


def build_v4_ztna_folder_control_posture(
    environment: Mapping[str, str] | None = None,
) -> FortiPamZtnaFolderControlPosture:
    """Build this read-only diagnostic from current Profile SSH and one selector."""

    env = os.environ if environment is None else environment
    try:
        from .antivirus_profile_ssh_transport import (
            load_antivirus_profile_ssh_transport_config,
        )

        current_profile = load_antivirus_profile_ssh_transport_config(env)
        folder_id = env.get(V4_ZTNA_FOLDER_POSTURE_SELECTOR_ENV, "").strip()
        config = ZtnaFolderControlPostureConfig(
            host=current_profile.host,
            port=current_profile.port,
            username=current_profile.username,
            password=current_profile.password,
            known_hosts_file=current_profile.known_hosts_file,
            folder_id=folder_id,
            timeout_seconds=current_profile.timeout_seconds,
        )
        return FortiPamZtnaFolderControlPosture(
            FortiPamZtnaFolderControlPostureSshTransport(config),
            folder_id=config.folder_id,
        )
    except Exception as exc:
        raise ZtnaFolderControlPostureConfigurationError(UNAVAILABLE) from exc


def _project(
    compact: bytes,
    full: bytes,
    *,
    folder_id: str,
) -> dict[str, object]:
    _compact_has_exact_folder_reference(compact, folder_id)
    block = _select_folder_block(full, folder_id)
    inheritance = _field_value(
        block,
        "inherit-folder-ztna",
        frozenset(("enable", "disable")),
    )
    if inheritance == "unknown":
        raise ValueError("inheritance_unavailable")
    return {
        "folder_ztna_control": (
            "inherits_parent" if inheritance == "enable" else "explicit_override"
        ),
        "folder_ztna_tag_assignment": _tag_assignment_state(block),
        "folder_ztna_match_logic": "unresolved",
    }


def _failure() -> dict[str, object]:
    return {
        "contract": WORKFLOW_CONTRACT,
        "execution_status": "unavailable",
        "folder_ztna_control": "unknown",
        "folder_ztna_tag_assignment": "unknown",
        "folder_ztna_match_logic": "unresolved",
        "folder_reference_returned": False,
        "tag_value_returned": False,
        "raw_cli_returned": False,
        "device_write_executed": False,
        "secret_override_assessed": False,
        "match_logic_assessed": False,
    }


def _select_folder_block(output: bytes, folder_id: str) -> bytes:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ZtnaFolderControlPostureTransportError(UNAVAILABLE)
    expected = folder_id.encode("ascii")
    lines = normalized.splitlines(keepends=True)
    candidates: list[tuple[int, bytes]] = []
    for index, line in enumerate(lines):
        match = _EDIT_FOLDER_LINE.fullmatch(line.rstrip(b"\r\n"))
        if match is None or match.group("folder_id") != expected:
            continue
        indent = match.group("indent")
        for end_index in range(index + 1, len(lines)):
            if lines[end_index].rstrip(b"\r\n") == indent + b"next":
                candidates.append((len(indent), b"".join(lines[index : end_index + 1])))
                break
        else:
            raise ZtnaFolderControlPostureTransportError(UNAVAILABLE)
    if not candidates:
        raise ZtnaFolderControlPostureTransportError(UNAVAILABLE)
    shallowest = min(indent for indent, _ in candidates)
    selected = [block for indent, block in candidates if indent == shallowest]
    if len(selected) != 1:
        raise ZtnaFolderControlPostureTransportError(UNAVAILABLE)
    return selected[0]


def _compact_has_exact_folder_reference(output: bytes, folder_id: str) -> None:
    """Prove the short grep output names exactly one configured Folder.

    FortiPAM's non-``-f`` grep form is a locator, not a full-object projection.
    It can therefore omit ``next`` and nonmatching field lines.  Treat it only
    as a precise object-presence check; the bounded full-configuration context
    remains the sole source for complete-block and field parsing.
    """

    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ZtnaFolderControlPostureTransportError(UNAVAILABLE)
    expected = folder_id.encode("ascii")
    matches = [
        line
        for line in normalized.splitlines()
        if (
            (match := _EDIT_FOLDER_LINE.fullmatch(line)) is not None
            and match.group("folder_id") == expected
        )
    ]
    if len(matches) != 1:
        raise ZtnaFolderControlPostureTransportError(UNAVAILABLE)


def _field_value(output: bytes, field: str, allowed: frozenset[str]) -> str:
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
            raise ZtnaFolderControlPostureTransportError(UNAVAILABLE) from exc
    accepted = values & allowed
    return next(iter(accepted)) if len(values) == 1 and len(accepted) == 1 else "unknown"


def _tag_assignment_state(output: bytes) -> str:
    values = [match.group("value") for match in _FIELD_LINE.finditer(output)]
    if not values:
        return "not_observed"
    if any(value is None for value in values):
        return "unknown"
    normalized = [cast(bytes, value).strip() for value in values]
    if all(value in {b'""', b"''"} for value in normalized):
        return "not_configured"
    if all(value for value in normalized):
        return "configured"
    return "unknown"


def _normalized(output: bytes) -> bytes:
    if len(output) > _MAX_OUTPUT_BYTES:
        raise ZtnaFolderControlPostureTransportError(UNAVAILABLE)
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


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


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
        raise ZtnaFolderControlPostureConfigurationError(
            f"The ZTNA Folder posture SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ZtnaFolderControlPostureConfigurationError(
            f"The ZTNA Folder posture SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ZtnaFolderControlPostureConfigurationError(
            f"The ZTNA Folder posture SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ZtnaFolderControlPostureConfigurationError(
            "The ZTNA Folder posture SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ZtnaFolderControlPostureConfigurationError(
            "The ZTNA Folder posture SSH password is invalid."
        ) from exc
    if not value:
        raise ZtnaFolderControlPostureConfigurationError(
            "The ZTNA Folder posture SSH password is invalid."
        )
    return value


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except ZtnaFolderControlPostureTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise ZtnaFolderControlPostureTransportError(UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamZtnaFolderControlPosture",
    "FortiPamZtnaFolderControlPostureSshTransport",
    "UNAVAILABLE",
    "V4_ZTNA_FOLDER_POSTURE_FEATURE_ENV",
    "V4_ZTNA_FOLDER_POSTURE_SELECTOR_ENV",
    "V4_ZTNA_FOLDER_POSTURE_TOOL",
    "WORKFLOW_CONTRACT",
    "ZtnaFolderControlPostureConfig",
    "ZtnaFolderControlPostureConfigurationError",
    "ZtnaFolderControlPostureTransportError",
    "build_v4_ztna_folder_control_posture",
    "load_v4_ztna_folder_posture_feature",
    "load_ztna_folder_control_posture_config",
]
