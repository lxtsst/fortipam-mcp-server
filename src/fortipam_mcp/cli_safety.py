"""Bounded interactive SSH transport for fixed FortiPAM CLI diagnostics."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import re
import stat
import time
from typing import Any, Final, Protocol

import asyncssh

from .cli_parsers import (
    CliParseError,
    project_checksum_detail_presence,
    project_ha_configuration,
    project_ha_checksum_cluster,
    project_ha_status,
)


class CliCommandId(str, Enum):
    """Internal identifiers for the complete fixed command registry."""

    HA_CONFIGURATION = "ha_configuration"
    HA_STATUS = "ha_status"
    HA_CHECKSUM_CLUSTER = "ha_checksum_cluster"
    HA_CHECKSUM_SHOW_GLOBAL = "ha_checksum_show_global"
    HA_CHECKSUM_SHOW_ROOT = "ha_checksum_show_root"


class CliWorkflowId(str, Enum):
    """The only three public V2 CLI workflows."""

    HA_CONFIGURATION = "ha_configuration"
    HA_STATUS = "ha_status"
    HA_CHECKSUM = "ha_checksum"


@dataclass(frozen=True, slots=True)
class _CliCommand:
    command_id: CliCommandId
    argv: tuple[str, ...]
    sensitivity: str

    @property
    def text(self) -> str:
        return " ".join(self.argv)


@dataclass(frozen=True, slots=True)
class CliExecutionLimits:
    """Resource bounds for one public workflow."""

    timeout_seconds: float = 12.0
    max_output_bytes: int = 32 * 1024
    max_command_count: int = 4

    def __post_init__(self) -> None:
        if not 1.0 <= self.timeout_seconds <= 60.0:
            raise ValueError("CLI timeout must be between 1 and 60 seconds.")
        if not 1024 <= self.max_output_bytes <= 1024 * 1024:
            raise ValueError("CLI output limit must be between 1 KiB and 1 MiB.")
        if not 1 <= self.max_command_count <= 4:
            raise ValueError("CLI command count must be between one and four.")


@dataclass(frozen=True, slots=True)
class SshCliTarget:
    """Pinned SSH target supplied only by trusted local configuration."""

    host: str
    username: str
    known_hosts_file: Path
    identity_file: Path
    port: int = 22

    def __post_init__(self) -> None:
        if not self.host or any(char.isspace() or char in "@/\\" for char in self.host):
            raise ValueError("SSH host must be one configured host name or address.")
        if not self.username or any(char.isspace() or char in "@/\\" for char in self.username):
            raise ValueError("SSH username must be one configured account name.")
        if not 1 <= self.port <= 65535:
            raise ValueError("SSH port is outside the valid range.")
        _assert_pinned_known_hosts(self.known_hosts_file)
        _assert_private_identity_file(self.identity_file)


@dataclass(frozen=True, slots=True)
class CliExecutionResult:
    """Non-disclosing workflow result."""

    workflow_id: str
    execution_status: str
    evidence: Mapping[str, object]
    raw_cli_returned: bool = False
    credential_values_returned: bool = False


@dataclass(slots=True)
class _WorkflowBudget:
    """Cumulative command and output budget for one public tool invocation."""

    commands_remaining: int
    output_bytes_remaining: int


class CliTransport(Protocol):
    """Private transport boundary used by the executor and deterministic tests."""

    async def execute(
        self, commands: Sequence[_CliCommand], limits: CliExecutionLimits
    ) -> tuple[bytes, ...]: ...


_COMMANDS: Final[dict[CliCommandId, _CliCommand]] = {
    CliCommandId.HA_CONFIGURATION: _CliCommand(
        CliCommandId.HA_CONFIGURATION,
        ("show", "system", "ha"),
        "ha_configuration_structure",
    ),
    CliCommandId.HA_STATUS: _CliCommand(
        CliCommandId.HA_STATUS, ("get", "system", "ha", "status"), "ha_operational_metadata"
    ),
    CliCommandId.HA_CHECKSUM_CLUSTER: _CliCommand(
        CliCommandId.HA_CHECKSUM_CLUSTER,
        ("diagnose", "sys", "ha", "checksum", "cluster"),
        "ha_integrity_metadata",
    ),
    CliCommandId.HA_CHECKSUM_SHOW_GLOBAL: _CliCommand(
        CliCommandId.HA_CHECKSUM_SHOW_GLOBAL,
        ("diagnose", "sys", "ha", "checksum", "show", "global"),
        "ha_integrity_detail",
    ),
    CliCommandId.HA_CHECKSUM_SHOW_ROOT: _CliCommand(
        CliCommandId.HA_CHECKSUM_SHOW_ROOT,
        ("diagnose", "sys", "ha", "checksum", "show", "root"),
        "ha_integrity_detail",
    ),
}

# FortiPAM presents the normal FortiOS-style prompt with ``#`` for a fully
# privileged administrator and ``$`` for a restricted CLI identity.  Keep the
# grammar deliberately narrower than a generic POSIX shell prompt: one
# hostname token, at most one parenthesized FortiOS configuration context, one
# space, and the terminal privilege marker.
_PROMPT = re.compile(
    rb"(?:^|\n)([A-Za-z0-9._-]{1,63}(?: \([^()\r\n]{1,80}\))? [#$]) ?$"
)
# The appliance may require one acknowledgement before exposing its normal CLI
# prompt. This intentionally recognizes one compiled terminal marker only;
# banner text, prompt text, and choices are neither configured nor returned.
_PRE_LOGIN_ACCEPTANCE = re.compile(
    rb"(?:^|\n)\(Press 'a' to accept\): ?$",
    re.IGNORECASE,
)
_PRE_LOGIN_CANDIDATE = re.compile(
    rb"(?:^|\n)[^\r\n]{0,256}\b(?:accept|decline)\b[^\r\n]*$",
    re.IGNORECASE,
)
_PRE_LOGIN_ACCEPT: Final[bytes] = b"a\n"
_ANSI_ESCAPE = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_DENIED_MARKERS = (
    b"permission denied",
    b"not permitted",
    b"not allowed",
    b"access denied",
)
_REJECTED_MARKERS = (
    b"command fail",
    b"unknown action",
    b"unknown command",
    b"parse error",
    b"ambiguous command",
)


def planned_cli_diagnostics() -> tuple[dict[str, object], ...]:
    """Return three public workflow descriptions without command text."""

    return tuple(
        {
            "workflow_id": workflow.value,
            "caller_parameters_accepted": False,
            "raw_cli_returned": False,
            "live_acceptance": "not_verified",
        }
        for workflow in CliWorkflowId
    )


class AsyncSshCliTransport:
    """Run compiled commands in one pinned, public-key-authenticated PTY."""

    def __init__(self, target: SshCliTarget, *, accept_pre_login_banner: bool = False) -> None:
        self._target = target
        self._accept_pre_login_banner = accept_pre_login_banner

    async def execute(
        self, commands: Sequence[_CliCommand], limits: CliExecutionLimits
    ) -> tuple[bytes, ...]:
        if not commands or len(commands) > limits.max_command_count:
            raise PermissionError("CLI command sequence is outside the bounded workflow.")
        if any(_COMMANDS.get(command.command_id) is not command for command in commands):
            raise PermissionError("CLI command is outside the compiled registry.")
        deadline = time.monotonic() + limits.timeout_seconds
        try:
            async with asyncssh.connect(
                self._target.host,
                port=self._target.port,
                username=self._target.username,
                known_hosts=str(self._target.known_hosts_file),
                client_keys=[str(self._target.identity_file)],
                agent_path=None,
                preferred_auth="publickey",
                public_key_auth=True,
                password_auth=False,
                kbdint_auth=False,
                host_based_auth=False,
                gss_auth=False,
                gss_kex=False,
                config=[],
                connect_timeout=limits.timeout_seconds,
                keepalive_interval=5,
                keepalive_count_max=1,
            ) as connection:
                process = await connection.create_process(
                    term_type="vt100",
                    term_size=(80, 24),
                    encoding=None,
                )
                prompt = await _complete_pre_login(
                    process.stdout,
                    process.stdin,
                    deadline,
                    limits.max_output_bytes,
                    accept_pre_login_banner=self._accept_pre_login_banner,
                )
                outputs: list[bytes] = []
                for command in commands:
                    process.stdin.write(command.text.encode("ascii") + b"\n")
                    await process.stdin.drain()
                    output = await _read_until_prompt(
                        process.stdout,
                        deadline,
                        limits.max_output_bytes,
                        expected_prompt=prompt,
                    )
                    _raise_for_remote_rejection(output)
                    outputs.append(output)
                process.stdin.write(b"exit\n")
                await process.stdin.drain()
                return tuple(outputs)
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise CliTransportError("timed_out") from exc
        except asyncssh.HostKeyNotVerifiable as exc:
            raise CliTransportError("host_key_rejected") from exc
        except asyncssh.PermissionDenied as exc:
            raise CliTransportError("authentication_denied") from exc
        except asyncssh.Error as exc:
            raise CliTransportError("transport_failed") from exc
        except OSError as exc:
            raise CliTransportError("transport_unavailable") from exc


class CliTransportError(RuntimeError):
    """Non-disclosing transport failure carrying only a stable reason code."""


class FortiPamCliExecutor:
    """Execute exactly one compiled public workflow at a time."""

    def __init__(
        self,
        transport: CliTransport,
        limits: CliExecutionLimits | None = None,
    ) -> None:
        self._transport = transport
        self._limits = limits or CliExecutionLimits()
        self._single_flight = asyncio.Lock()

    async def execute(self, workflow_id: CliWorkflowId) -> CliExecutionResult:
        if not isinstance(workflow_id, CliWorkflowId):
            raise PermissionError("CLI workflow is outside the compiled registry.")
        if self._single_flight.locked():
            return _failure_result(workflow_id, "busy")
        async with self._single_flight:
            try:
                budget = _WorkflowBudget(
                    commands_remaining=self._limits.max_command_count,
                    output_bytes_remaining=self._limits.max_output_bytes,
                )
                async with asyncio.timeout(self._limits.timeout_seconds):
                    return await self._execute_workflow(workflow_id, budget)
            except (asyncio.TimeoutError, TimeoutError):
                return _failure_result(workflow_id, "timed_out")
            except CliTransportError as exc:
                return _failure_result(workflow_id, str(exc))
            except CliParseError:
                return _failure_result(workflow_id, "parser_rejected")

    async def _execute_workflow(
        self,
        workflow_id: CliWorkflowId,
        budget: _WorkflowBudget,
    ) -> CliExecutionResult:
        if workflow_id is CliWorkflowId.HA_CONFIGURATION:
            output = (await self._execute_commands(
                (_COMMANDS[CliCommandId.HA_CONFIGURATION],), budget
            ))[0]
            return _success_result(workflow_id, project_ha_configuration(output))

        ha_output = (await self._execute_commands(
            (_COMMANDS[CliCommandId.HA_STATUS],), budget
        ))[0]
        ha_evidence = project_ha_status(ha_output)
        if workflow_id is CliWorkflowId.HA_STATUS:
            return _success_result(workflow_id, ha_evidence)
        if ha_evidence.get("ha_mode") == "standalone":
            return _success_result(
                workflow_id,
                {
                    "evidence_status": "complete",
                    "ha_mode": "standalone",
                    "checksum_assessment": "not_applicable",
                    "member_count_band": "single",
                    "exact_checksum_returned": False,
                    "member_identity_returned": False,
                    "table_name_returned": False,
                    "raw_cli_returned": False,
                },
            )

        cluster_output = (await self._execute_commands(
            (_COMMANDS[CliCommandId.HA_CHECKSUM_CLUSTER],), budget
        ))[0]
        checksum = project_ha_checksum_cluster(cluster_output)
        followups: list[_CliCommand] = []
        scopes: list[str] = []
        if checksum["global_agreement"] == "mismatched":
            followups.append(_COMMANDS[CliCommandId.HA_CHECKSUM_SHOW_GLOBAL])
            scopes.append("global")
        if checksum["root_agreement"] == "mismatched":
            followups.append(_COMMANDS[CliCommandId.HA_CHECKSUM_SHOW_ROOT])
            scopes.append("root")
        detail_states: dict[str, str] = {}
        if followups:
            outputs = await self._execute_commands(tuple(followups), budget)
            for scope, output in zip(scopes, outputs, strict=True):
                detail_states[scope] = str(project_checksum_detail_presence(output)["detail_evidence"])
        evidence = dict(checksum)
        evidence["ha_mode"] = ha_evidence["ha_mode"]
        evidence["checksum_assessment"] = (
            "synchronized"
            if all(
                checksum[key] == "matched"
                for key in ("global_agreement", "root_agreement", "overall_agreement")
            )
            else "out_of_sync"
        )
        evidence["detail_evidence"] = "not_required" if not detail_states else "collected"
        return _success_result(workflow_id, evidence)

    async def _execute_commands(
        self,
        commands: Sequence[_CliCommand],
        budget: _WorkflowBudget,
    ) -> tuple[bytes, ...]:
        command_count = len(commands)
        if command_count == 0 or command_count > budget.commands_remaining:
            raise CliTransportError("command_limit_exceeded")
        if budget.output_bytes_remaining < 1024:
            raise CliTransportError("output_limit_exceeded")
        call_limits = CliExecutionLimits(
            timeout_seconds=self._limits.timeout_seconds,
            max_output_bytes=budget.output_bytes_remaining,
            max_command_count=budget.commands_remaining,
        )
        outputs = await self._transport.execute(commands, call_limits)
        if len(outputs) != command_count:
            raise CliTransportError("transport_contract_failed")
        consumed = sum(len(output) for output in outputs)
        if consumed > budget.output_bytes_remaining:
            raise CliTransportError("output_limit_exceeded")
        budget.commands_remaining -= command_count
        budget.output_bytes_remaining -= consumed
        return outputs


async def _read_until_prompt(
    reader: Any,
    deadline: float,
    max_bytes: int,
    *,
    expected_prompt: bytes | None = None,
) -> bytes:
    collected = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CliTransportError("timed_out")
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise CliTransportError("timed_out") from exc
        if not chunk:
            raise CliTransportError("session_closed")
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        if len(collected) + len(chunk) > max_bytes:
            raise CliTransportError("output_limit_exceeded")
        collected.extend(chunk)
        normalized = _ANSI_ESCAPE.sub(b"", bytes(collected)).replace(b"\r", b"")
        if expected_prompt is None and _PROMPT.search(normalized):
            return bytes(collected)
        if expected_prompt is not None and _ends_with_prompt(
            normalized,
            expected_prompt,
        ):
            return bytes(collected)


async def _complete_pre_login(
    reader: Any,
    writer: Any,
    deadline: float,
    max_bytes: int,
    *,
    accept_pre_login_banner: bool,
) -> bytes:
    """Reach the CLI prompt, accepting only one explicit opt-in banner marker."""

    initial_state, initial = await _read_initial_terminal_state(
        reader,
        deadline,
        max_bytes,
    )
    if initial_state == "prompt":
        return _extract_prompt(initial)
    if not accept_pre_login_banner:
        raise CliTransportError("pre_login_banner_rejected")

    writer.write(_PRE_LOGIN_ACCEPT)
    await writer.drain()
    remaining_bytes = max_bytes - len(initial)
    if remaining_bytes <= 0:
        raise CliTransportError("output_limit_exceeded")
    accepted = await _read_until_prompt(
        reader,
        deadline,
        remaining_bytes,
    )
    return _extract_prompt(accepted)


async def _read_initial_terminal_state(
    reader: Any,
    deadline: float,
    max_bytes: int,
) -> tuple[str, bytes]:
    """Read only until a normal prompt or the exact compiled banner marker."""

    collected = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CliTransportError("timed_out")
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise CliTransportError("timed_out") from exc
        if not chunk:
            raise CliTransportError("session_closed")
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        if len(collected) + len(chunk) > max_bytes:
            raise CliTransportError("output_limit_exceeded")
        collected.extend(chunk)
        normalized = _ANSI_ESCAPE.sub(b"", bytes(collected)).replace(b"\r", b"")
        if _PROMPT.search(normalized):
            return "prompt", bytes(collected)
        if _PRE_LOGIN_ACCEPTANCE.search(normalized):
            return "acceptance", bytes(collected)
        if _PRE_LOGIN_CANDIDATE.search(normalized):
            raise CliTransportError("pre_login_banner_rejected")


def _extract_prompt(output: bytes) -> bytes:
    normalized = _ANSI_ESCAPE.sub(b"", output).replace(b"\r", b"")
    match = _PROMPT.search(normalized)
    if match is None:
        raise CliTransportError("prompt_rejected")
    return match.group(1)


def _ends_with_prompt(output: bytes, expected_prompt: bytes) -> bool:
    final_line = output.split(b"\n")[-1].rstrip(b" ")
    return final_line == expected_prompt


def _raise_for_remote_rejection(output: bytes) -> None:
    lowered = output.lower()
    if any(marker in lowered for marker in _DENIED_MARKERS):
        raise CliTransportError("remote_denied")
    if any(marker in lowered for marker in _REJECTED_MARKERS):
        raise CliTransportError("remote_rejected")


def _success_result(
    workflow_id: CliWorkflowId, evidence: Mapping[str, object]
) -> CliExecutionResult:
    return CliExecutionResult(
        workflow_id=workflow_id.value,
        execution_status="completed",
        evidence=evidence,
    )


def _failure_result(workflow_id: CliWorkflowId, status: str) -> CliExecutionResult:
    return CliExecutionResult(
        workflow_id=workflow_id.value,
        execution_status=status,
        evidence={
            "evidence_status": "unavailable",
            "raw_cli_returned": False,
            "credential_values_returned": False,
        },
    )


def _assert_pinned_known_hosts(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("Pinned SSH known_hosts file must exist and be non-empty.")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise PermissionError("Pinned SSH known_hosts file must be owner-only.")


def _assert_private_identity_file(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("SSH identity file must exist and be non-empty.")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise PermissionError("SSH identity file must be owner-only.")
