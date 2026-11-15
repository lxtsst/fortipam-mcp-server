from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from types import SimpleNamespace
import time

import pytest

from fortipam_mcp import ztna_wad_debug_ssh_transport as transport
from fortipam_mcp.cli_safety import CliTransportError
from fortipam_mcp.ztna_wad_debug_ssh_transport import (
    ENV_PREFIX,
    ZtnaWadDebugSshTransportConfigurationError,
    ZtnaWadDebugSshTransportError,
    _debug_is_disabled,
    _project_capture,
    load_ztna_wad_debug_ssh_transport_config,
)


def test_debug_state_parser_requires_one_explicit_state() -> None:
    assert _debug_is_disabled(b"debug is disabled\r\n") is True
    assert _debug_is_disabled(b"debug output enabled\r\n") is False
    assert _debug_is_disabled(b"diagnose debug info\r\nroot#\r\n") is None
    assert _debug_is_disabled(b"debug is enabled; debug is disabled\r\n") is None
    with pytest.raises(ZtnaWadDebugSshTransportError):
        _debug_is_disabled(b"permission denied\r\n")


def test_capture_projection_is_categorical_and_discards_raw_values() -> None:
    result = _project_capture(
        b"Current device tags: private-value\r\n"
        b"matched device tag private-value\r\n"
        b"Token check passed\r\n"
        b"gui_allow_launch value: 1\r\n",
        cleanup_confirmed=True,
    )
    assert result.verified is True
    assert result.device_context_state == "available"
    assert result.device_tag_match_state == "matched"
    assert result.launch_authorization_state == "allowed"
    missing = _project_capture(
        b"wad_gui_secret_launch_dev_check: Unable to launch secret, device context is not available\r\n",
        cleanup_confirmed=True,
    )
    assert missing.device_context_state == "missing"
    assert missing.device_tag_match_state == "not_observed"
    assert missing.launch_authorization_state == "not_observed"


def test_config_requires_explicit_enable_private_files_and_safe_time_budget(
    tmp_path: Path,
) -> None:
    password = tmp_path / "password"
    password.write_text("example-password\n", encoding="utf-8")
    password.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("example ssh-ed25519 AAAA\n", encoding="utf-8")
    known_hosts.chmod(0o600)
    environment = {
        f"{ENV_PREFIX}ENABLED": "true",
        f"{ENV_PREFIX}SSH_HOST": "fpa.example",
        f"{ENV_PREFIX}SSH_USERNAME": "operator",
        f"{ENV_PREFIX}SSH_PASSWORD_FILE": str(password),
        f"{ENV_PREFIX}SSH_KNOWN_HOSTS_FILE": str(known_hosts),
        f"{ENV_PREFIX}SSH_TIMEOUT_SECONDS": "20",
        f"{ENV_PREFIX}CAPTURE_WINDOW_SECONDS": "10",
    }
    config = load_ztna_wad_debug_ssh_transport_config(environment)
    assert config.capture_window_seconds == 10
    bad = dict(environment)
    bad[f"{ENV_PREFIX}CAPTURE_WINDOW_SECONDS"] = "13"
    with pytest.raises(ZtnaWadDebugSshTransportConfigurationError):
        load_ztna_wad_debug_ssh_transport_config(bad)


def capture_peer(tmp_path, monkeypatch, *, fault=None, preflight=b"debug is disabled"):
    """Fixed CLI peer with no sockets, credentials or appliance operations."""
    original_sleep = asyncio.sleep
    pin = tmp_path / "known-hosts"
    pin.write_text("synthetic host pin\n"); pin.chmod(0o600)
    config = transport.ZtnaWadDebugSshTransportConfig(
        "fpa.example", 22, "operator", "synthetic-password", pin, 20, 3)
    item = transport.FortiPamZtnaWadDebugSshTransport(config)
    peer = SimpleNamespace(events=[], commands=[], info_reads=0, closed=False,
        cleanup_entered=None, cleanup_release=None, hang_cleanup=False)

    class Connection:
        async def __aenter__(self):
            peer.events.append("connect")
            return self

        async def __aexit__(self, *args):
            peer.closed = True
            peer.events.append("disconnect")

    async def open_cli(connection):
        return peer, b"synthetic #", time.monotonic() + 20

    async def info(process, prompt, deadline):
        assert process is peer
        peer.info_reads += 1
        peer.events.append("info")
        return preflight if peer.info_reads == 1 else b"unknown" if fault == "final-unknown" else b"debug is disabled"

    async def send(process, command, prompt, deadline):
        assert process is peer
        peer.commands.append(command)
        peer.events.append(command)
        if command == transport._DEBUG_DISABLE_COMMAND:
            assert deadline > time.monotonic()
            if peer.cleanup_entered is not None:
                peer.cleanup_entered.set()
                await peer.cleanup_release.wait()
            if fault == "disable-failure":
                raise OSError("synthetic cleanup response loss")
            return b"no diagnostic events\n"
        if command == fault:
            raise CliTransportError("remote_rejected")
        if fault == "enable-cancel":
            raise asyncio.CancelledError
        return b""

    async def capture_wait(seconds):
        if seconds != 3:
            await original_sleep(seconds)
            return
        if fault == "capture-cancel":
            raise asyncio.CancelledError

    async def close(process):
        assert process is peer
        peer.events.append("close-cli")

    monkeypatch.setattr(item, "_connection", Connection)
    monkeypatch.setattr(item, "_open_cli", open_cli)
    monkeypatch.setattr(item, "_debug_info", info)
    monkeypatch.setattr(transport, "_send_and_read", send)
    monkeypatch.setattr(transport, "_close_cli", close)
    monkeypatch.setattr(transport.asyncio, "sleep", capture_wait)
    return item, peer


@pytest.mark.parametrize("command", transport._DEBUG_ENABLE_COMMANDS)
def test_partial_enable_failure_still_disables_and_verifies_in_same_session(tmp_path, monkeypatch, command):
    item, peer = capture_peer(tmp_path, monkeypatch, fault=command)
    with pytest.raises(ZtnaWadDebugSshTransportError):
        asyncio.run(item._capture_and_cleanup())
    assert peer.commands == list(transport._DEBUG_ENABLE_COMMANDS[:transport._DEBUG_ENABLE_COMMANDS.index(command) + 1]) + [transport._DEBUG_DISABLE_COMMAND]
    assert peer.info_reads == 2
    assert peer.events[-3:] == ["info", "close-cli", "disconnect"]
    assert peer.closed


@pytest.mark.parametrize("state", [b"debug is enabled", b"unrecognized"])
def test_unqualified_preflight_never_dispatches_enable_or_cleanup(tmp_path, monkeypatch, state):
    item, peer = capture_peer(tmp_path, monkeypatch, preflight=state)
    with pytest.raises(ZtnaWadDebugSshTransportError):
        asyncio.run(item._capture_and_cleanup())
    assert peer.commands == [] and peer.info_reads == 1 and peer.closed


@pytest.mark.parametrize("fault", [None, "disable-failure", "final-unknown"])
def test_one_cleanup_attempt_and_independent_readback_are_required_for_success(tmp_path, monkeypatch, fault):
    item, peer = capture_peer(tmp_path, monkeypatch, fault=fault)
    result = asyncio.run(item._capture_and_cleanup())
    assert result.verified is (fault is None)
    assert result.capture_collected is (fault is None)
    assert peer.commands == [*transport._DEBUG_ENABLE_COMMANDS, transport._DEBUG_DISABLE_COMMAND]
    assert peer.closed


@pytest.mark.parametrize("fault", ["enable-cancel", "capture-cancel"])
def test_cancellation_propagates_only_after_verified_cleanup(tmp_path, monkeypatch, fault):
    item, peer = capture_peer(tmp_path, monkeypatch, fault=fault)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(item._capture_and_cleanup())
    assert peer.commands[-1] == transport._DEBUG_DISABLE_COMMAND
    assert peer.info_reads == 2 and peer.closed


def test_repeated_cancellation_cannot_detach_cleanup_or_close_its_live_connection(tmp_path, monkeypatch):
    original_sleep = asyncio.sleep
    item, peer = capture_peer(tmp_path, monkeypatch)

    async def run():
        peer.cleanup_entered, peer.cleanup_release = asyncio.Event(), asyncio.Event()
        task = asyncio.create_task(item._capture_and_cleanup())
        await peer.cleanup_entered.wait()
        for _ in range(2):
            task.cancel()
            await original_sleep(0)
            assert not task.done() and not peer.closed
        peer.cleanup_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert peer.commands.count(transport._DEBUG_DISABLE_COMMAND) == 1
        assert peer.info_reads == 2 and peer.closed

    asyncio.run(run())


def test_cleanup_has_a_hard_timeout_without_replaying_uncertain_disable(tmp_path, monkeypatch):
    item, peer = capture_peer(tmp_path, monkeypatch)
    real_timeout = asyncio.timeout
    budgets = []

    def short_timeout(seconds):
        budgets.append(seconds)
        return real_timeout(0.01)

    monkeypatch.setattr(transport.asyncio, "timeout", short_timeout)

    async def run():
        peer.cleanup_entered, peer.cleanup_release = asyncio.Event(), asyncio.Event()
        result = await item._capture_and_cleanup()
        assert not result.verified and not result.cleanup_confirmed
        assert peer.commands.count(transport._DEBUG_DISABLE_COMMAND) == 1
        assert peer.closed

    asyncio.run(run())
    assert budgets == [5, 1]


def source_peer(tmp_path, monkeypatch, *, fault=None, legacy=False):
    base, peer = capture_peer(tmp_path, monkeypatch)
    serial = b"unit-debug-appliance"
    item = transport.FortiPamZtnaWadDebugSshTransport(base._config,
        build29_serial_digest=None if legacy else hashlib.sha256(serial).hexdigest())
    monkeypatch.setattr(item, "_connection", base._connection)
    monkeypatch.setattr(item, "_open_cli", base._open_cli)
    peer.frames = []

    async def send(process, command, prompt, deadline):
        index = len(peer.commands)
        peer.commands.append(command)
        if command == transport._source_reader._SERIAL:
            lines = [b"Serial-Number: " + (b"different-appliance" if fault == (index, "serial") else serial)]
        elif command == transport._source_reader._VERSION:
            lines = [b"Version: FortiPAM-VM v7.0.0,build0029, synthetic"]
            if fault == (index, "version"):
                lines = [b"Version: FortiPAM-VM v7.0.0,build0030, synthetic"]
        elif command == transport._BUILD29_DEBUG_STATE_COMMAND:
            lines = fault if type(fault) is list else [b"debug output: disable"]
        else:
            assert legacy and command == transport._DEBUG_INFO_COMMAND
            lines = [b"debug is disabled"]
        raw = command.encode() + b"\r\r\n" + b"".join(line + b"\r\n" for line in lines) + prompt
        peer.frames.append(raw)
        return raw

    monkeypatch.setattr(transport, "_send_and_read", send)
    return item, peer


@pytest.mark.parametrize("line", [b"debug output: disable", b"debug output:    disable", b"\tdebug output \t: disable \t"])
def test_private_build29_preflight_pins_both_device_brackets_and_one_complete_state_line(tmp_path, monkeypatch, line):
    item, peer = source_peer(tmp_path, monkeypatch, fault=[line])
    assert item.inspect().debug_is_disabled is True
    assert peer.commands == [transport._source_reader._SERIAL, transport._source_reader._VERSION,
        transport._BUILD29_DEBUG_STATE_COMMAND, transport._source_reader._SERIAL, transport._source_reader._VERSION]
    assert peer.closed


def test_legacy_preflight_keeps_its_original_unprojected_command(tmp_path, monkeypatch):
    item, peer = source_peer(tmp_path, monkeypatch, legacy=True)
    assert item.inspect().debug_is_disabled is True
    assert peer.commands == [transport._DEBUG_INFO_COMMAND]
    assert peer.closed


@pytest.mark.parametrize("index,kind", [(0, "serial"), (1, "version"), (3, "serial"), (4, "version")])
def test_build29_preflight_rejects_device_or_build_drift_in_either_bracket(tmp_path, monkeypatch, index, kind):
    item, peer = source_peer(tmp_path, monkeypatch, fault=(index, kind))
    with pytest.raises(ZtnaWadDebugSshTransportError):
        item.inspect()
    assert len(peer.commands) == index + 1 and peer.closed


@pytest.mark.parametrize("lines", [[], [b"debug is disabled"],
    [b"debug output: disable", b"debug output: disable"],
    [b"debug output: disable", b"debug output: enable"],
    [b"debug output: disable", b"extra native row"],
    [b"debug output: disable", b"Command fail. Return code -61"],
    [b"debug output: disable", b"permission denied"]])
def test_build29_preflight_requires_exact_single_row_and_retains_error_rejection(tmp_path, monkeypatch, lines):
    item, peer = source_peer(tmp_path, monkeypatch, fault=lines)
    with pytest.raises(ZtnaWadDebugSshTransportError):
        item.inspect()
    assert peer.closed


def test_build29_enabled_state_is_observed_but_never_dispatches_a_capture(tmp_path, monkeypatch):
    item, peer = source_peer(tmp_path, monkeypatch, fault=[b"debug output: enable"])
    with pytest.raises(ZtnaWadDebugSshTransportError):
        asyncio.run(item._capture_and_cleanup())
    assert not any(command in transport._DEBUG_ENABLE_COMMANDS or command == transport._DEBUG_DISABLE_COMMAND
        for command in peer.commands)
    assert peer.closed
