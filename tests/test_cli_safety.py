from __future__ import annotations

import asyncio
from collections.abc import Sequence
from pathlib import Path

import pytest

import fortipam_mcp.cli_safety as cli_safety

from fortipam_mcp.cli_parsers import (
    CliParseError,
    project_checksum_detail_presence,
    project_ha_checksum_cluster,
    project_ha_status,
    project_ha_configuration,
)
from fortipam_mcp.cli_safety import (
    AsyncSshCliTransport,
    CliCommandId,
    CliExecutionLimits,
    CliTransportError,
    CliWorkflowId,
    FortiPamCliExecutor,
    SshCliTarget,
    _CliCommand,
    _COMMANDS,
    _complete_pre_login,
    _extract_prompt,
    _read_until_prompt,
    _raise_for_remote_rejection,
)


HA_CONFIGURATION = b"""\
show system ha\r
config system ha\r
    set mode standalone\r
    set group-name "private-cluster"\r
    set password ENC private-secret\r
    set hbdev "private-interface" 50\r
    set priority 128\r
    set override disable\r
    set session-pickup enable\r
    set encryption enable\r
    set authentication enable\r
end\r
fpa $\r
"""

HA_STANDALONE = b"""\
get system ha status\r
HA Health Status: OK\r
Mode: Standalone\r
private #\r
"""

HA_CLUSTER = b"""\
get system ha status\r
HA Health Status: OK\r
Model: FortiPAM-VM64\r
Mode: HA A-P\r
Configuration Status:\r
PRIVATE-A (updated 4 seconds ago): in-sync\r
PRIVATE-B (updated 1 seconds ago): in-sync\r
private #\r
"""

CHECKSUM_MATCHED = b"""\
diagnose sys ha checksum cluster\r
================== PRIVATE-A ==================\r
checksum\r
global: 30 e6 4c 2b 15 fc 14 c7 4b ac 84 95 23 88 b2 8a\r
root: ee d9 e5 28 f8 65 7d 80 b9 3b 07 d9 d0 75 37 11\r
all: 73 df fd ec ca 70 b9 71 26 8c 6d c9 07 56 85 90\r
================== PRIVATE-B ==================\r
checksum\r
global: 30 e6 4c 2b 15 fc 14 c7 4b ac 84 95 23 88 b2 8a\r
root: ee d9 e5 28 f8 65 7d 80 b9 3b 07 d9 d0 75 37 11\r
all: 73 df fd ec ca 70 b9 71 26 8c 6d c9 07 56 85 90\r
private #\r
"""

CHECKSUM_MISMATCHED = CHECKSUM_MATCHED.replace(
    b"30 e6 4c 2b 15 fc 14 c7 4b ac 84 95 23 88 b2 8a\r\nroot: ee d9 e5",
    b"40 e6 4c 2b 15 fc 14 c7 4b ac 84 95 23 88 b2 8a\r\nroot: ee d9 e5",
    1,
)

CHECKSUM_DETAIL = b"""\
diagnose sys ha checksum show global\r
private.table: 30e64c2b15fc14c74bac84952388b28a\r
private.other: eed9e528f8657d80b93b07d9d0753711\r
private #\r
"""


class FakeTransport:
    def __init__(self, responses: dict[CliCommandId, bytes]) -> None:
        self.responses = responses
        self.calls: list[tuple[CliCommandId, ...]] = []

    async def execute(
        self, commands: Sequence[_CliCommand], limits: CliExecutionLimits
    ) -> tuple[bytes, ...]:
        self.calls.append(tuple(command.command_id for command in commands))
        return tuple(self.responses[command.command_id] for command in commands)


class BlockingTransport:
    async def execute(
        self, commands: Sequence[_CliCommand], limits: CliExecutionLimits
    ) -> tuple[bytes, ...]:
        await asyncio.sleep(0.05)
        return (HA_CONFIGURATION,)


class FailingTransport:
    async def execute(
        self, commands: Sequence[_CliCommand], limits: CliExecutionLimits
    ) -> tuple[bytes, ...]:
        raise CliTransportError("host_key_rejected")


class _FakeWriter:
    def __init__(self) -> None:
        self.writes: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def drain(self) -> None:
        return None


@pytest.fixture
def target(tmp_path: Path) -> SshCliTarget:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fortipam.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    identity = tmp_path / "id_ed25519"
    identity.write_text("not-a-real-key\n")
    identity.chmod(0o600)
    return SshCliTarget(
        host="fortipam.example",
        username="readonly",
        known_hosts_file=known_hosts,
        identity_file=identity,
    )


def test_registry_contains_only_fixed_commands_and_exact_official_followups() -> None:
    assert set(_COMMANDS) == set(CliCommandId)
    assert _COMMANDS[CliCommandId.HA_CONFIGURATION].argv == ("show", "system", "ha")
    assert _COMMANDS[CliCommandId.HA_STATUS].argv == ("get", "system", "ha", "status")
    assert _COMMANDS[CliCommandId.HA_CHECKSUM_CLUSTER].argv == (
        "diagnose", "sys", "ha", "checksum", "cluster"
    )
    assert _COMMANDS[CliCommandId.HA_CHECKSUM_SHOW_GLOBAL].argv == (
        "diagnose", "sys", "ha", "checksum", "show", "global"
    )
    assert _COMMANDS[CliCommandId.HA_CHECKSUM_SHOW_ROOT].argv == (
        "diagnose", "sys", "ha", "checksum", "show", "root"
    )


def test_target_requires_owner_controlled_files(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("host key\n")
    known_hosts.chmod(0o666)
    identity = tmp_path / "id_ed25519"
    identity.write_text("key\n")
    identity.chmod(0o600)
    with pytest.raises(PermissionError, match="known_hosts"):
        SshCliTarget("fortipam.example", "readonly", known_hosts, identity)

    known_hosts.chmod(0o640)
    with pytest.raises(PermissionError, match="owner-only"):
        SshCliTarget("fortipam.example", "readonly", known_hosts, identity)


def test_prompt_detection_tolerates_ansi_without_returning_modified_output() -> None:
    async def run() -> None:
        reader = asyncio.StreamReader()
        raw = b"Version: FortiPAM-VM64 v1.9.1\r\n\x1b[32mfpa #\x1b[0m"
        reader.feed_data(raw)
        reader.feed_eof()
        result = await _read_until_prompt(
            reader,
            asyncio.get_running_loop().time() + 1,
            4096,
        )
        assert result == raw
        assert _extract_prompt(result) == b"fpa #"

    asyncio.run(run())


def test_prompt_detection_requires_the_pinned_initial_prompt() -> None:
    async def run() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"Output ending like another #\r\nfpa #")
        reader.feed_eof()
        result = await _read_until_prompt(
            reader,
            asyncio.get_running_loop().time() + 1,
            4096,
            expected_prompt=b"fpa #",
        )
        assert result.endswith(b"fpa #")

    asyncio.run(run())


def test_prompt_detection_accepts_restricted_fortipam_prompt_only() -> None:
    async def run() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"Authorized restricted session\r\nfpa $")
        reader.feed_eof()
        result = await _read_until_prompt(
            reader,
            asyncio.get_running_loop().time() + 1,
            4096,
        )
        assert _extract_prompt(result) == b"fpa $"

        for unsafe in (
            b"user@fpa:~$",
            b"/bin/sh $",
            b"fpa (nested (context)) $",
            b"fpa $ trailing",
        ):
            with pytest.raises(CliTransportError, match="prompt_rejected"):
                _extract_prompt(unsafe)

    asyncio.run(run())


def test_prompt_reader_enforces_overflow_timeout_and_session_close() -> None:
    async def run() -> None:
        overflow = asyncio.StreamReader()
        overflow.feed_data(b"x" * 1025)
        overflow.feed_eof()
        with pytest.raises(CliTransportError, match="output_limit_exceeded"):
            await _read_until_prompt(
                overflow,
                asyncio.get_running_loop().time() + 1,
                1024,
            )

        closed = asyncio.StreamReader()
        closed.feed_data(b"incomplete")
        closed.feed_eof()
        with pytest.raises(CliTransportError, match="session_closed"):
            await _read_until_prompt(
                closed,
                asyncio.get_running_loop().time() + 1,
                1024,
            )

        waiting = asyncio.StreamReader()
        with pytest.raises(CliTransportError, match="timed_out"):
            await _read_until_prompt(
                waiting,
                asyncio.get_running_loop().time() + 0.01,
                1024,
            )

    asyncio.run(run())


def test_pre_login_banner_is_rejected_by_default_without_a_response() -> None:
    async def run() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"Private banner\r\n(Press 'a' to accept): ")
        writer = _FakeWriter()
        with pytest.raises(CliTransportError, match="pre_login_banner_rejected"):
            await _complete_pre_login(
                reader,
                writer,
                asyncio.get_running_loop().time() + 1,
                4096,
                accept_pre_login_banner=False,
            )
        assert writer.writes == []

    asyncio.run(run())


def test_pre_login_banner_acceptance_is_exact_opt_in_and_requires_normal_prompt() -> None:
    async def run() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"Private banner\r\n(Press 'a' to accept): ")
        writer = _FakeWriter()
        async def supply_normal_prompt() -> None:
            await asyncio.sleep(0)
            reader.feed_data(b"\r\nfpa #")

        response = asyncio.create_task(supply_normal_prompt())
        prompt = await _complete_pre_login(
            reader,
            writer,
            asyncio.get_running_loop().time() + 1,
            4096,
            accept_pre_login_banner=True,
        )
        await response
        assert prompt == b"fpa #"
        assert writer.writes == [b"a\n"]

    asyncio.run(run())


def test_pre_login_banner_rejects_malformed_or_injected_marker() -> None:
    async def run() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"(Press 'a' to accept); show full-configuration\n")
        writer = _FakeWriter()
        with pytest.raises(CliTransportError, match="pre_login_banner_rejected"):
            await _complete_pre_login(
                reader,
                writer,
                asyncio.get_running_loop().time() + 1,
                4096,
                accept_pre_login_banner=True,
            )
        assert writer.writes == []

    asyncio.run(run())


def test_pre_login_banner_rejects_unobserved_alternative_marker() -> None:
    async def run() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"Accept (a) / Decline (d): ")
        writer = _FakeWriter()
        with pytest.raises(CliTransportError, match="pre_login_banner_rejected"):
            await _complete_pre_login(
                reader,
                writer,
                asyncio.get_running_loop().time() + 1,
                1024,
                accept_pre_login_banner=True,
            )
        assert writer.writes == []

    asyncio.run(run())


def test_pre_login_state_preserves_output_timeout_and_session_bounds() -> None:
    async def run() -> None:
        overflow = asyncio.StreamReader()
        overflow.feed_data(b"x" * 1025)
        overflow.feed_eof()
        with pytest.raises(CliTransportError, match="output_limit_exceeded"):
            await _complete_pre_login(
                overflow,
                _FakeWriter(),
                asyncio.get_running_loop().time() + 1,
                1024,
                accept_pre_login_banner=True,
            )

        closed = asyncio.StreamReader()
        closed.feed_data(b"Private banner\n")
        closed.feed_eof()
        with pytest.raises(CliTransportError, match="session_closed"):
            await _complete_pre_login(
                closed,
                _FakeWriter(),
                asyncio.get_running_loop().time() + 1,
                4096,
                accept_pre_login_banner=True,
            )

        waiting = asyncio.StreamReader()
        with pytest.raises(CliTransportError, match="timed_out"):
            await _complete_pre_login(
                waiting,
                _FakeWriter(),
                asyncio.get_running_loop().time() + 0.01,
                4096,
                accept_pre_login_banner=True,
            )

    asyncio.run(run())


def test_pre_login_direct_normal_prompt_never_writes_acceptance() -> None:
    async def run() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"fpa #")
        writer = _FakeWriter()
        prompt = await _complete_pre_login(
            reader,
            writer,
            asyncio.get_running_loop().time() + 1,
            4096,
            accept_pre_login_banner=False,
        )
        assert prompt == b"fpa #"
        assert writer.writes == []

    asyncio.run(run())


def test_target_rejects_injected_host_or_username(target: SshCliTarget) -> None:
    with pytest.raises(ValueError, match="host"):
        SshCliTarget(
            "host ProxyCommand=unsafe",
            target.username,
            target.known_hosts_file,
            target.identity_file,
        )
    with pytest.raises(ValueError, match="username"):
        SshCliTarget(
            target.host,
            "readonly@other",
            target.known_hosts_file,
            target.identity_file,
        )


def test_asyncssh_transport_disables_default_identity_discovery(
    target: SshCliTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FailingConnectionContext:
        async def __aenter__(self) -> object:
            raise OSError("stop after option capture")

        async def __aexit__(self, *args: object) -> None:
            return None

    def fake_connect(host: str, **kwargs: object) -> FailingConnectionContext:
        captured["host"] = host
        captured.update(kwargs)
        return FailingConnectionContext()

    monkeypatch.setattr(cli_safety.asyncssh, "connect", fake_connect)

    async def run() -> None:
        with pytest.raises(CliTransportError, match="transport_unavailable"):
            await AsyncSshCliTransport(target).execute(
                (_COMMANDS[CliCommandId.HA_CONFIGURATION],),
                CliExecutionLimits(),
            )

    asyncio.run(run())
    assert captured == {
        "host": target.host,
        "port": target.port,
        "username": target.username,
        "known_hosts": str(target.known_hosts_file),
        "client_keys": [str(target.identity_file)],
        "agent_path": None,
        "preferred_auth": "publickey",
        "public_key_auth": True,
        "password_auth": False,
        "kbdint_auth": False,
        "host_based_auth": False,
        "gss_auth": False,
        "gss_kex": False,
        "config": [],
        "connect_timeout": 12.0,
        "keepalive_interval": 5,
        "keepalive_count_max": 1,
    }


def test_ha_configuration_projection_is_categorical_and_non_disclosing() -> None:
    result = project_ha_configuration(HA_CONFIGURATION)
    assert result == {
        "evidence_status": "complete",
        "ha_mode": "standalone",
        "session_pickup": "enabled",
        "override_state": "disabled",
        "configuration_security": "enabled",
        "identity_values_returned": False,
        "network_values_returned": False,
        "group_name_returned": False,
        "password_values_returned": False,
        "priority_values_returned": False,
        "exact_checksum_returned": False,
        "raw_cli_returned": False,
    }
    assert "private" not in str(result).lower()


def test_ha_configuration_projects_omitted_default_fields_as_unknown() -> None:
    result = project_ha_configuration(
        b"show system ha\r\nconfig system ha\r\n"
        b"    set override disable\r\nend\r\nfpa $"
    )
    assert result["evidence_status"] == "partial"
    assert result["ha_mode"] == "unknown"
    assert result["session_pickup"] == "unknown"
    assert result["override_state"] == "disabled"
    assert result["configuration_security"] == "unknown"
    assert result["raw_cli_returned"] is False


def test_ha_configuration_rejects_schema_drift_and_contradiction() -> None:
    with pytest.raises(CliParseError):
        project_ha_configuration(b"unrecognized output\n")
    with pytest.raises(CliParseError, match="contradictory"):
        project_ha_configuration(
            HA_CONFIGURATION.replace(
                b"    set mode standalone",
                b"    set mode standalone\r\n    set mode a-p",
            )
        )
    with pytest.raises(CliParseError, match="unknown setting"):
        project_ha_configuration(
            HA_CONFIGURATION.replace(
                b"    set priority 128",
                b"    set future-secret private\r\n    set priority 128",
            )
        )
    with pytest.raises(CliParseError, match="invalid setting"):
        project_ha_configuration(
            HA_CONFIGURATION.replace(
                b"    set priority 128",
                b"    unset priority",
            )
        )


def test_ha_status_projection_discards_peer_identifiers_and_exact_times() -> None:
    result = project_ha_status(HA_CLUSTER)
    assert result["ha_mode"] == "active_passive"
    assert result["ha_health"] == "healthy"
    assert result["member_count_band"] == "multiple"
    assert result["configuration_sync"] == "synchronized"
    assert "PRIVATE" not in str(result)


def test_ha_status_accepts_fortipam_standalone_summary_fields() -> None:
    result = project_ha_status(
        b"get system ha status\r\n"
        b"HA Health Status: OK\r\n"
        b"Model: FortiPAM-VM64\r\n"
        b"Mode: Standalone\r\n"
        b"Group: 0\r\n"
        b"Debug: 0\r\n"
        b"Cluster Uptime: 0 days\r\n"
        b"Cluster state change time: private-time\r\n"
        b"override: disable\r\n"
        b"System Usage stats:\r\n"
        b"HBDEV stats:\r\n"
        b"number of vcluster: 1\r\n"
        b"fpa $"
    )
    assert result == {
        "evidence_status": "complete",
        "ha_mode": "standalone",
        "ha_health": "healthy",
        "member_count_band": "single",
        "configuration_sync": "not_applicable",
        "peer_identity_returned": False,
        "network_values_returned": False,
        "exact_time_returned": False,
        "raw_cli_returned": False,
    }
    assert "private" not in str(result).lower()


def test_ha_status_rejects_unknown_fields_outside_member_sync_lines() -> None:
    with pytest.raises(CliParseError, match="unknown field"):
        project_ha_status(
            HA_CLUSTER.replace(
                b"Model: FortiPAM-VM64",
                b"Unknown HA Field: private\r\nModel: FortiPAM-VM64",
            )
        )
    with pytest.raises(CliParseError, match="unknown line"):
        project_ha_status(
            HA_CLUSTER.replace(
                b"Model: FortiPAM-VM64",
                b"unexpected bare output\r\nModel: FortiPAM-VM64",
            )
        )


def test_checksum_projection_compares_values_without_returning_them() -> None:
    matched = project_ha_checksum_cluster(CHECKSUM_MATCHED)
    mismatched = project_ha_checksum_cluster(CHECKSUM_MISMATCHED)
    assert matched["overall_agreement"] == "matched"
    assert mismatched["global_agreement"] == "mismatched"
    assert "PRIVATE" not in str(matched)
    assert "30e6" not in str(matched)
    assert project_checksum_detail_presence(CHECKSUM_DETAIL)["detail_evidence"] == "collected"


def test_checksum_projection_rejects_unknown_fields_and_lines() -> None:
    with pytest.raises(CliParseError, match="unknown field"):
        project_ha_checksum_cluster(
            CHECKSUM_MATCHED.replace(
                b"global: 30 e6",
                b"future: 30 e6 4c 2b 15 fc 14 c7 4b ac 84 95 23 88 b2 8a\r\nglobal: 30 e6",
                1,
            )
        )
    with pytest.raises(CliParseError, match="unknown line"):
        project_ha_checksum_cluster(
            CHECKSUM_MATCHED.replace(b"checksum\r\n", b"unexpected output\r\nchecksum\r\n", 1)
        )
    with pytest.raises(CliParseError, match="invalid record"):
        project_checksum_detail_presence(
            CHECKSUM_DETAIL.replace(
                b"private.other: eed9e528f8657d80b93b07d9d0753711",
                b"future sensitive line: not-a-checksum",
            )
        )


def test_three_public_workflows_and_standalone_short_circuit() -> None:
    async def run() -> None:
        transport = FakeTransport(
            {
                CliCommandId.HA_CONFIGURATION: HA_CONFIGURATION,
                CliCommandId.HA_STATUS: HA_STANDALONE,
            }
        )
        executor = FortiPamCliExecutor(transport)
        configuration = await executor.execute(CliWorkflowId.HA_CONFIGURATION)
        ha = await executor.execute(CliWorkflowId.HA_STATUS)
        checksum = await executor.execute(CliWorkflowId.HA_CHECKSUM)
        assert configuration.execution_status == "completed"
        assert ha.execution_status == "completed"
        assert checksum.evidence["checksum_assessment"] == "not_applicable"
        assert all(call != (CliCommandId.HA_CHECKSUM_CLUSTER,) for call in transport.calls)

    asyncio.run(run())


def test_cluster_checksum_runs_only_required_detail_followup() -> None:
    async def run() -> None:
        transport = FakeTransport(
            {
                CliCommandId.HA_STATUS: HA_CLUSTER,
                CliCommandId.HA_CHECKSUM_CLUSTER: CHECKSUM_MISMATCHED,
                CliCommandId.HA_CHECKSUM_SHOW_GLOBAL: CHECKSUM_DETAIL,
            }
        )
        result = await FortiPamCliExecutor(transport).execute(CliWorkflowId.HA_CHECKSUM)
        assert result.execution_status == "completed"
        assert result.evidence["checksum_assessment"] == "out_of_sync"
        assert result.evidence["detail_evidence"] == "collected"
        assert (CliCommandId.HA_CHECKSUM_SHOW_GLOBAL,) in transport.calls
        assert (CliCommandId.HA_CHECKSUM_SHOW_ROOT,) not in transport.calls

    asyncio.run(run())


def test_executor_fails_closed_for_host_key_and_parser_errors() -> None:
    async def run() -> None:
        rejected = await FortiPamCliExecutor(FailingTransport()).execute(
            CliWorkflowId.HA_CONFIGURATION
        )
        malformed = await FortiPamCliExecutor(
            FakeTransport({CliCommandId.HA_CONFIGURATION: b"private $\r\n"})
        ).execute(CliWorkflowId.HA_CONFIGURATION)
        assert rejected.execution_status == "host_key_rejected"
        assert malformed.execution_status == "parser_rejected"
        assert rejected.raw_cli_returned is False

    asyncio.run(run())


def test_executor_enforces_single_flight() -> None:
    async def run() -> None:
        executor = FortiPamCliExecutor(BlockingTransport())
        first = asyncio.create_task(executor.execute(CliWorkflowId.HA_CONFIGURATION))
        await asyncio.sleep(0)
        second = await executor.execute(CliWorkflowId.HA_CONFIGURATION)
        await first
        assert second.execution_status == "busy"

    asyncio.run(run())


def test_executor_refuses_arbitrary_workflow() -> None:
    with pytest.raises(PermissionError, match="compiled"):
        asyncio.run(
            FortiPamCliExecutor(FakeTransport({})).execute("show full-configuration")  # type: ignore[arg-type]
        )


def test_remote_rejection_is_non_disclosing() -> None:
    with pytest.raises(CliTransportError, match="remote_denied"):
        _raise_for_remote_rejection(b"Permission denied for private command")
    with pytest.raises(CliTransportError, match="remote_rejected"):
        _raise_for_remote_rejection(b"Command fail. Return code -61")


def test_limits_reject_unbounded_values() -> None:
    with pytest.raises(ValueError):
        CliExecutionLimits(timeout_seconds=0.5)
    with pytest.raises(ValueError):
        CliExecutionLimits(max_output_bytes=1023)
    with pytest.raises(ValueError):
        CliExecutionLimits(max_command_count=5)


def test_executor_enforces_one_cumulative_output_budget_across_transport_calls() -> None:
    async def run() -> None:
        padded_ha = HA_CLUSTER.replace(
            b"private #",
            (b"Model: FortiPAM-VM64\r\n" * 25) + b"private #",
        )
        assert len(padded_ha) < 1024
        transport = FakeTransport(
            {
                CliCommandId.HA_STATUS: padded_ha,
                CliCommandId.HA_CHECKSUM_CLUSTER: CHECKSUM_MATCHED,
            }
        )
        result = await FortiPamCliExecutor(
            transport,
            CliExecutionLimits(max_output_bytes=1024),
        ).execute(CliWorkflowId.HA_CHECKSUM)
        assert result.execution_status == "output_limit_exceeded"
        assert transport.calls == [(CliCommandId.HA_STATUS,)]

    asyncio.run(run())
