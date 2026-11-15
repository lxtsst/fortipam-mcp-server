"""Fixed, non-disclosing FortiPAM ZTNA device-context diagnostic.

This module deliberately exposes no caller-controlled endpoint, tag, Access
Proxy, command, or debug input.  A protected, server-side IPv4 reference is
used only while building the one fixed WAD query.  Raw appliance output is
parsed in process and discarded before the MCP boundary.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Protocol, cast

import asyncssh

from .cli_safety import CliTransportError, _complete_pre_login
from .target_ssh_transport import _close_cli, _send_and_read


WORKFLOW_CONTRACT = "fortipam_v4_ztna_device_context_diagnostic_v1"
ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ZTNA_DIAGNOSTIC_"
V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV = (
    "FORTIPAM_MCP_V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_ENABLED"
)
V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_TOOL = (
    "get_v4_ztna_device_context_diagnostic"
)
UNAVAILABLE = "FortiPAM V4 ZTNA device-context diagnostic is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 80


class ZtnaDeviceContextDiagnosticConfigurationError(ValueError):
    """Raised when the private diagnostic configuration is incomplete or unsafe."""


class ZtnaDeviceContextDiagnosticTransportError(RuntimeError):
    """Stable non-disclosing failure for the fixed SSH diagnostic."""


@dataclass(frozen=True, slots=True)
class ZtnaDeviceContextDiagnosticConfig:
    """Dedicated SSH settings and private diagnostic references."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    access_proxy_name: str
    endpoint_ipv4: ipaddress.IPv4Address
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise ZtnaDeviceContextDiagnosticConfigurationError(
                "The ZTNA diagnostic SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise ZtnaDeviceContextDiagnosticConfigurationError(
                "The ZTNA diagnostic SSH username is invalid."
            )
        if not _safe_name(self.access_proxy_name):
            raise ZtnaDeviceContextDiagnosticConfigurationError(
                "The ZTNA diagnostic Access Proxy reference is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise ZtnaDeviceContextDiagnosticConfigurationError(
                "The ZTNA diagnostic SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise ZtnaDeviceContextDiagnosticConfigurationError(
                "The ZTNA diagnostic SSH timeout is invalid."
            )
        if not self.endpoint_ipv4.is_private:
            raise ZtnaDeviceContextDiagnosticConfigurationError(
                "The ZTNA diagnostic endpoint must be a private IPv4 address."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.password
        ):
            raise ZtnaDeviceContextDiagnosticConfigurationError(
                "The ZTNA diagnostic SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


class ZtnaDeviceContextTransport(Protocol):
    """Private compiled transport boundary for deterministic tests."""

    def collect(self) -> tuple[bytes, bytes, bytes]: ...


def load_v4_ztna_device_context_diagnostic_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Return the exact feature opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise ZtnaDeviceContextDiagnosticConfigurationError(
        f"{V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV} must be exactly true or false."
    )


def load_ztna_device_context_diagnostic_config(
    environment: Mapping[str, str] | None = None,
) -> ZtnaDeviceContextDiagnosticConfig:
    """Load the independently scoped SSH identity and private endpoint reference."""

    env = os.environ if environment is None else environment
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    access_proxy_name = _value(env, "ACCESS_PROXY_NAME")
    endpoint_raw = _value(env, "ENDPOINT_IPV4")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {
        host,
        username,
        password_file,
        known_hosts_file,
        access_proxy_name,
        endpoint_raw,
    }:
        raise ZtnaDeviceContextDiagnosticConfigurationError(
            "Dedicated ZTNA diagnostic SSH settings and a private endpoint reference are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
        endpoint = ipaddress.IPv4Address(str(endpoint_raw))
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise ZtnaDeviceContextDiagnosticConfigurationError(
            "The ZTNA diagnostic numeric or endpoint setting is invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    assert access_proxy_name is not None
    return ZtnaDeviceContextDiagnosticConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        access_proxy_name=access_proxy_name,
        endpoint_ipv4=endpoint,
        timeout_seconds=timeout,
    )


class FortiPamZtnaDeviceContextSshTransport:
    """Execute exactly three compiled read-only CLI commands over pinned SSH."""

    def __init__(self, config: ZtnaDeviceContextDiagnosticConfig) -> None:
        self._config = config

    def collect(self) -> tuple[bytes, bytes, bytes]:
        return cast(tuple[bytes, bytes, bytes], _run_sync(self._collect()))

    async def _collect(self) -> tuple[bytes, bytes, bytes]:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                outputs: list[bytes] = []
                for command in self._commands():
                    outputs.append(
                        await _send_and_read(process, command, root_prompt, deadline)
                    )
            finally:
                await _close_cli(process)
        if len(outputs) != 3:
            raise ZtnaDeviceContextDiagnosticTransportError(UNAVAILABLE)
        return cast(tuple[bytes, bytes, bytes], outputs)

    def _commands(self) -> tuple[str, str, str]:
        """Return the complete fixed command sequence without caller input."""

        return (
            "show full-configuration firewall access-proxy | grep -A "
            f'{_FULL_CONTEXT_LINES} "^ *edit.*{self._config.access_proxy_name}"',
            "diagnose firewall dynamic list",
            "diagnose wad dev query-by ipv4 " + str(self._config.endpoint_ipv4),
        )

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
            raise ZtnaDeviceContextDiagnosticTransportError(UNAVAILABLE) from exc


class FortiPamZtnaDeviceContextDiagnostic:
    """Return the first observable ZTNA gate without raw CLI disclosure."""

    def __init__(
        self,
        transport: ZtnaDeviceContextTransport,
        *,
        access_proxy_name: str,
        endpoint_ipv4: ipaddress.IPv4Address,
    ) -> None:
        self._transport = transport
        self._access_proxy_name = access_proxy_name
        self._endpoint_ipv4 = endpoint_ipv4

    def collect(self) -> dict[str, object]:
        try:
            access_proxy, dynamic_list, wad_context = self._transport.collect()
            projection = _project(
                access_proxy,
                dynamic_list,
                wad_context,
                access_proxy_name=self._access_proxy_name,
                endpoint_ipv4=self._endpoint_ipv4,
            )
        except (ZtnaDeviceContextDiagnosticTransportError, OSError, RuntimeError):
            return _failure("transport_unavailable")
        except ValueError:
            return _failure("parser_rejected")
        return {
            "contract": WORKFLOW_CONTRACT,
            "execution_status": "succeeded",
            **projection,
            "raw_cli_returned": False,
            "endpoint_value_returned": False,
            "access_proxy_reference_returned": False,
            "tag_value_returned": False,
            "identity_or_session_value_returned": False,
            "secret_launch_authorization_assessed": False,
            "access_policy_tag_assessed": False,
            "folder_or_secret_ztna_policy_assessed": False,
            "wad_debug_enabled": False,
        }


def build_v4_ztna_device_context_diagnostic(
    environment: Mapping[str, str] | None = None,
) -> FortiPamZtnaDeviceContextDiagnostic:
    """Build the read-only diagnostic only from protected local configuration."""

    env = os.environ if environment is None else environment
    try:
        config = load_ztna_device_context_diagnostic_config(env)
        return FortiPamZtnaDeviceContextDiagnostic(
            FortiPamZtnaDeviceContextSshTransport(config),
            access_proxy_name=config.access_proxy_name,
            endpoint_ipv4=config.endpoint_ipv4,
        )
    except Exception as exc:
        raise ZtnaDeviceContextDiagnosticConfigurationError(UNAVAILABLE) from exc


def _project(
    access_proxy: bytes,
    dynamic_list: bytes,
    wad_context: bytes,
    *,
    access_proxy_name: str,
    endpoint_ipv4: ipaddress.IPv4Address,
) -> dict[str, object]:
    selected_access_proxy = _select_access_proxy(access_proxy, access_proxy_name)
    client_certificate = _field_value(
        selected_access_proxy, "client-cert", frozenset({"enable", "disable"})
    )
    empty_certificate_action = _field_value(
        selected_access_proxy, "empty-cert-action", frozenset({"accept", "block"})
    )
    dynamic_endpoint = _endpoint_dynamic_state(dynamic_list, endpoint_ipv4)
    wad_device_context = _wad_context_state(wad_context)
    return {
        "access_proxy_evidence": _access_proxy_evidence(
            client_certificate,
            empty_certificate_action,
        ),
        "client_certificate_mode": {
            "enable": "enabled",
            "disable": "disabled",
        }.get(client_certificate, "unknown"),
        "empty_certificate_action": empty_certificate_action,
        "dynamic_endpoint_state": dynamic_endpoint,
        "wad_device_context_state": wad_device_context,
        "first_failed_gate": _first_failed_gate(
            client_certificate,
            dynamic_endpoint,
            wad_device_context,
        ),
    }


def _select_access_proxy(output: bytes, access_proxy_name: str) -> bytes:
    """Select one configured Access Proxy without returning its reference."""

    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ValueError("access_proxy_query_rejected")
    configured_blocks = _named_config_blocks(normalized, access_proxy_name)
    if len(configured_blocks) == 1:
        return configured_blocks[0]
    if configured_blocks:
        raise ValueError("access_proxy_reference_ambiguous")
    summary_blocks = _named_summary_blocks(normalized, access_proxy_name)
    if len(summary_blocks) == 1:
        return summary_blocks[0]
    raise ValueError("access_proxy_reference_not_observed")


def _named_config_blocks(output: bytes, access_proxy_name: str) -> list[bytes]:
    expected = access_proxy_name.encode("ascii")
    lines = output.splitlines(keepends=True)
    matches: list[bytes] = []
    for index, line in enumerate(lines):
        match = _ACCESS_PROXY_EDIT_LINE.fullmatch(line.rstrip(b"\r\n"))
        if match is None:
            continue
        candidate = match.group("quoted") or match.group("bare")
        if candidate != expected:
            continue
        indent = match.group("indent")
        for end_index in range(index + 1, len(lines)):
            if lines[end_index].rstrip(b"\r\n") == indent + b"next":
                matches.append(b"".join(lines[index : end_index + 1]))
                break
        else:
            raise ValueError("access_proxy_config_block_unterminated")
    return matches


def _named_summary_blocks(output: bytes, access_proxy_name: str) -> list[bytes]:
    expected = access_proxy_name.encode("ascii")
    lines = output.splitlines(keepends=True)
    starts = [
        index
        for index, line in enumerate(lines)
        if (match := _ACCESS_PROXY_SUMMARY_LINE.fullmatch(line.rstrip(b"\r\n")))
        is not None
        and match.group("name") == expected
    ]
    blocks: list[bytes] = []
    for index in starts:
        end_index = len(lines)
        for candidate in range(index + 1, len(lines)):
            if _ACCESS_PROXY_SUMMARY_LINE.fullmatch(
                lines[candidate].rstrip(b"\r\n")
            ) is not None:
                end_index = candidate
                break
        blocks.append(b"".join(lines[index:end_index]))
    return blocks


def _access_proxy_evidence(
    client_certificate: str,
    empty_certificate_action: str,
) -> str:
    if client_certificate != "unknown" and empty_certificate_action != "unknown":
        return "complete"
    if client_certificate != "unknown" or empty_certificate_action != "unknown":
        return "partial"
    return "unknown"


def _field_value(output: bytes, field: str, allowed: frozenset[str]) -> str:
    normalized = _normalized(output)
    pattern = re.compile(
        rb"(?im)^\s*(?:set\s+)?"
        + re.escape(field.encode("ascii"))
        + rb"\s*(?::|\s)\s*([A-Za-z-]+)\b"
    )
    values = {
        match.group(1).decode("ascii").lower()
        for match in pattern.finditer(normalized)
        if match.group(1).decode("ascii").lower() in allowed
    }
    return values.pop() if len(values) == 1 else "unknown"


def _endpoint_dynamic_state(output: bytes, endpoint_ipv4: ipaddress.IPv4Address) -> str:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ValueError("dynamic_list_rejected")
    endpoint = re.escape(str(endpoint_ipv4).encode("ascii"))
    if re.search(rb"(?<![0-9.])" + endpoint + rb"(?![0-9.])", normalized):
        return "observed"
    if _DYNAMIC_ABSENT.search(normalized):
        return "not_observed"
    return "unknown"


def _wad_context_state(output: bytes) -> str:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ValueError("wad_query_rejected")
    if _WAD_ABSENT.search(normalized):
        return "absent"
    if _WAD_PRESENT.search(normalized):
        return "present"
    return "unknown"


def _first_failed_gate(
    client_certificate: str,
    dynamic_endpoint: str,
    wad_device_context: str,
) -> str:
    if client_certificate == "disable":
        return "access_proxy_client_certificate_disabled"
    if client_certificate != "enable":
        return "access_proxy_configuration_unknown"
    if dynamic_endpoint == "not_observed":
        return "dynamic_endpoint_not_observed"
    if dynamic_endpoint != "observed":
        return "dynamic_endpoint_state_unknown"
    if wad_device_context == "absent":
        return "wad_device_context_absent"
    if wad_device_context != "present":
        return "wad_device_context_unknown"
    return "no_failure_observed"


def _failure(reason: str) -> dict[str, object]:
    return {
        "contract": WORKFLOW_CONTRACT,
        "execution_status": "failed",
        "diagnostic_state": reason,
        "first_failed_gate": "diagnostic_unavailable",
        "raw_cli_returned": False,
        "endpoint_value_returned": False,
        "access_proxy_reference_returned": False,
        "tag_value_returned": False,
        "identity_or_session_value_returned": False,
        "secret_launch_authorization_assessed": False,
        "access_policy_tag_assessed": False,
        "folder_or_secret_ztna_policy_assessed": False,
        "wad_debug_enabled": False,
    }


def _normalized(output: bytes) -> bytes:
    if len(output) > _MAX_OUTPUT_BYTES:
        raise ValueError("output_limit_exceeded")
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


_DYNAMIC_ABSENT = re.compile(
    rb"(?im)\b(?:no\s+(?:dynamic\s+)?(?:entry|record|address)|empty\s+dynamic\s+list)\b"
)
_WAD_PRESENT = re.compile(
    rb"(?im)(?:^|\n)\s*(?:device\s*(?:id|context)|endpoint\s*id|serial)\s*[:=]"
    rb"|\bdevice\s+context\s+(?:found|available|valid|matched)\b"
)
_WAD_ABSENT = re.compile(
    rb"(?im)\b(?:no\s+(?:matching\s+)?(?:device|device\s+context)|device\s+context\s+(?:is\s+)?not\s+available|device\s+not\s+found|0\s+(?:matching\s+)?devices)\b"
)
_ACCESS_PROXY_EDIT_LINE = re.compile(
    rb"(?P<indent>[ \t]*)edit[ \t]+(?:\"(?P<quoted>[^\"\r\n]+)\"|(?P<bare>[A-Za-z0-9][A-Za-z0-9._-]{0,63}))[ \t]*"
)
_ACCESS_PROXY_SUMMARY_LINE = re.compile(
    rb"(?:==[ \t]*)?\[[ \t]*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,63})[ \t]*\][ \t]*"
)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


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
        raise ZtnaDeviceContextDiagnosticConfigurationError(
            f"The ZTNA diagnostic SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ZtnaDeviceContextDiagnosticConfigurationError(
            f"The ZTNA diagnostic SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ZtnaDeviceContextDiagnosticConfigurationError(
            f"The ZTNA diagnostic SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ZtnaDeviceContextDiagnosticConfigurationError(
            "The ZTNA diagnostic SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ZtnaDeviceContextDiagnosticConfigurationError(
            "The ZTNA diagnostic SSH password file is invalid."
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
    except ZtnaDeviceContextDiagnosticTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise ZtnaDeviceContextDiagnosticTransportError(UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamZtnaDeviceContextDiagnostic",
    "FortiPamZtnaDeviceContextSshTransport",
    "UNAVAILABLE",
    "V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV",
    "V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_TOOL",
    "WORKFLOW_CONTRACT",
    "ZtnaDeviceContextDiagnosticConfig",
    "ZtnaDeviceContextDiagnosticConfigurationError",
    "ZtnaDeviceContextDiagnosticTransportError",
    "build_v4_ztna_device_context_diagnostic",
    "load_v4_ztna_device_context_diagnostic_feature",
    "load_ztna_device_context_diagnostic_config",
]
