#!/usr/bin/env python3
"""Accept four fixed CLI authorization boundaries without returning output."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import time

import asyncssh

from fortipam_mcp.cli_safety import (
    CliTransportError,
    _complete_pre_login,
    _extract_prompt,
    _read_until_prompt,
)
from fortipam_mcp.config import ConfigurationError, FortiPamCliConfig, load_cli_config
from fortipam_mcp.env import EnvironmentFileError, load_runtime_environment


@dataclass(frozen=True, slots=True)
class _DenialProbe:
    probe_id: str
    command: bytes
    may_change_context: bool = False
    accepted_classifications: frozenset[str] = frozenset({"denied"})


_PROBES = (
    _DenialProbe(
        "required_admin_configuration_context",
        b"config system admin",
        True,
        frozenset({"denied", "allowed_context_change"}),
    ),
    _DenialProbe(
        "debug_branch",
        b"diagnose debug status",
        accepted_classifications=frozenset({"denied", "invalid_or_rejected"}),
    ),
    _DenialProbe(
        "execute_branch",
        b"execute ping-options view-settings",
        accepted_classifications=frozenset({"denied", "invalid_or_rejected"}),
    ),
    _DenialProbe(
        "secret_branch",
        b"show secret jwt",
        accepted_classifications=frozenset({"denied", "invalid_or_rejected"}),
    ),
)
_DENIAL_MARKERS = (
    b"permission denied",
    b"no permission",
    b"not entitled",
    b"not permitted",
    b"not allowed",
    b"access denied",
)
_REJECTION_MARKERS = (
    b"unknown action",
    b"unknown command",
    b"parse error",
    b"ambiguous command",
    b"return code -61",
)


def classify_probe_output(
    output: bytes,
    *,
    initial_prompt: bytes,
    final_prompt: bytes,
) -> str:
    """Classify only authorization evidence; never return the supplied bytes."""

    lowered = output.lower()
    if final_prompt != initial_prompt:
        return "allowed_context_change"
    if any(marker in lowered for marker in _DENIAL_MARKERS):
        return "denied"
    if any(marker in lowered for marker in _REJECTION_MARKERS):
        return "invalid_or_rejected"
    return "allowed_or_inconclusive"


def summarize_probe_classifications(
    classifications: dict[str, str],
) -> dict[str, object]:
    """Apply the fixed authorization matrix without returning command output."""

    expected = {probe.probe_id: probe.accepted_classifications for probe in _PROBES}
    if set(classifications) != set(expected):
        raise ValueError("CLI authorization classification set is incomplete.")
    failed = sorted(
        probe_id
        for probe_id, classification in classifications.items()
        if classification not in expected[probe_id]
    )
    required_residual = classifications["required_admin_configuration_context"]
    return {
        "denied_probe_count": sum(
            classification == "denied"
            for classification in classifications.values()
        ),
        "command_tree_rejection_count": sum(
            classification == "invalid_or_rejected"
            for classification in classifications.values()
        ),
        "non_executable_prohibited_probe_count": sum(
            classifications[probe_id] in {"denied", "invalid_or_rejected"}
            for probe_id in ("debug_branch", "execute_branch", "secret_branch")
        ),
        "required_admin_context_reachable": required_residual
        == "allowed_context_change",
        "persistent_write_attempted": False,
        "failed_probe_ids": failed,
        "identity_authorization_boundary_accepted": not failed,
    }


async def run_acceptance() -> dict[str, object]:
    """Run four compiled non-mutating probes from the configured Docker source."""

    report = load_runtime_environment()
    config = load_cli_config()
    classifications: dict[str, str] = {}
    for probe in _PROBES:
        classifications[probe.probe_id] = await _run_probe(config, probe)
    summary = summarize_probe_classifications(classifications)
    return {
        "contract": "fortipam_cli_identity_authorization_acceptance_v2",
        "credential_source_loaded": report.loaded,
        "probe_count": len(_PROBES),
        "probe_classifications": dict(sorted(classifications.items())),
        **summary,
        "fixed_commands_only": True,
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }


async def _run_probe(config: FortiPamCliConfig, probe: _DenialProbe) -> str:
    limits = config.limits
    target = config.target
    deadline = time.monotonic() + limits.timeout_seconds
    try:
        async with asyncssh.connect(
            target.host,
            port=target.port,
            username=target.username,
            known_hosts=str(target.known_hosts_file),
            client_keys=[str(target.identity_file)],
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
        ) as connection:
            process = await connection.create_process(
                term_type="vt100",
                term_size=(80, 24),
                encoding=None,
            )
            initial_prompt = await _complete_pre_login(
                process.stdout,
                process.stdin,
                deadline,
                limits.max_output_bytes,
                accept_pre_login_banner=config.accept_pre_login_banner,
            )
            process.stdin.write(probe.command + b"\n")
            await process.stdin.drain()
            output = await _read_until_prompt(
                process.stdout,
                deadline,
                limits.max_output_bytes,
            )
            final_prompt = _extract_prompt(output)
            classification = classify_probe_output(
                output,
                initial_prompt=initial_prompt,
                final_prompt=final_prompt,
            )
            if final_prompt != initial_prompt and probe.may_change_context:
                process.stdin.write(b"end\n")
                await process.stdin.drain()
                await _read_until_prompt(
                    process.stdout,
                    deadline,
                    limits.max_output_bytes,
                    expected_prompt=initial_prompt,
                )
            process.stdin.write(b"exit\n")
            await process.stdin.drain()
            return classification
    except asyncssh.HostKeyNotVerifiable as exc:
        raise CliTransportError("host_key_rejected") from exc
    except asyncssh.PermissionDenied as exc:
        raise CliTransportError("authentication_denied") from exc
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise CliTransportError("transport_failed") from exc


def main() -> None:
    try:
        result = asyncio.run(run_acceptance())
    except (ConfigurationError, EnvironmentFileError, CliTransportError) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["identity_authorization_boundary_accepted"] is not True:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
