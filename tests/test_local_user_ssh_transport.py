from __future__ import annotations

from pathlib import Path

import pytest

import fortipam_mcp.local_user_ssh_transport as transport_module
from fortipam_mcp.local_user_ssh_transport import (
    FortiPamLocalUserSshTransport,
    LocalUserSshTransportError,
    _readback,
)
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig


def _config(tmp_path: Path) -> TargetSshTransportConfig:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    return TargetSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-v4-writer",
        password="test-password",
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_local_user_input_rejects_cli_injection_before_connection(tmp_path: Path) -> None:
    transport = FortiPamLocalUserSshTransport(_config(tmp_path))

    with pytest.raises(LocalUserSshTransportError):
        transport.inspect('unsafe"\nset status disable')
    with pytest.raises(LocalUserSshTransportError):
        transport.disable_and_readback("unsafe name")


def test_inspection_uses_only_fixed_show_grep_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = _FakeSshSession(
        compact=b'edit "different-user"\n',
        full_outputs=[b'edit "mcp-user-01"\n    set status enable\n'],
    )
    monkeypatch.setattr(transport_module.asyncssh, "connect", lambda *args, **kwargs: session)
    transport = FortiPamLocalUserSshTransport(_config(tmp_path))

    result = transport.inspect("mcp-user-01")

    assert result.exists is True
    assert result.status == "enable"
    assert session.commands == [
        "config system admin",
        "show | grep mcp-user-01",
        "end",
        "config system admin",
        "show | grep mcp-user-01 -f",
        "end",
        "exit",
    ]
    assert all(
        not command.startswith(("edit ", "set ", "next"))
        for command in session.commands
    )


def test_disable_uses_one_compiled_sequence_and_full_readback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = _FakeSshSession(
        compact=b'edit "mcp-user-01"\n',
        full_outputs=[
            b'edit "mcp-user-01"\n    set status disable\n',
        ],
    )
    monkeypatch.setattr(transport_module.asyncssh, "connect", lambda *args, **kwargs: session)
    transport = FortiPamLocalUserSshTransport(_config(tmp_path))

    result = transport.disable_and_readback("mcp-user-01")

    assert result.verified is True
    assert session.commands == [
        "config system admin",
        'edit "mcp-user-01"',
        "set status disable",
        "next",
        "end",
        "config system admin",
        "show | grep mcp-user-01 -f",
        "end",
        "exit",
    ]


def test_readback_requires_one_explicit_disabled_status() -> None:
    output = b'edit "mcp-user-01"\r\n    set status disable\r\n'

    assert _readback(output, "mcp-user-01").verified is True
    assert _readback(
        output.replace(b"disable", b"enable"),
        "mcp-user-01",
    ).verified is False
    assert _readback(
        output + b"    set status enable\r\n",
        "mcp-user-01",
    ).verified is False


def test_inspection_treats_omitted_default_status_as_enabled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """FortiPAM's filtered CLI suppresses the default enabled value."""

    session = _FakeSshSession(
        compact=b'edit "mcp-user-01"\n',
        full_outputs=[b'edit "mcp-user-01"\n    set accprofile "Guest"\n'],
    )
    monkeypatch.setattr(transport_module.asyncssh, "connect", lambda *args, **kwargs: session)
    transport = FortiPamLocalUserSshTransport(_config(tmp_path))

    result = transport.inspect("mcp-user-01")

    assert result.exists is True
    assert result.status == "enable"


class _FakeSshSession:
    def __init__(self, *, compact: bytes, full_outputs: list[bytes]) -> None:
        self.commands: list[str] = []
        self._reader = _FakeReader()
        self._reader.feed_data(b"fpa #")
        self._compact = compact
        self._full_outputs = list(full_outputs)
        self._context = "root"

    async def __aenter__(self) -> "_FakeSshSession":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def create_process(self, **kwargs: object) -> "_FakeProcess":
        return _FakeProcess(self)

    def dispatch(self, value: bytes) -> None:
        command = value.decode("ascii").rstrip("\n")
        self.commands.append(command)
        if command == "config system admin":
            self._context = "admin"
            self._emit(b"fpa (admin) #")
            return
        if command == "end":
            self._context = "root"
            self._emit(b"fpa #")
            return
        if command == "exit":
            return
        if self._context == "admin" and command.startswith("show | grep "):
            output = (
                self._full_outputs.pop(0)
                if command.endswith(" -f")
                else self._compact
            )
            self._emit(output + b"fpa (admin) #")
            return
        if self._context == "admin" and command in {"next"}:
            self._emit(b"fpa (admin) $")
            return
        if self._context == "admin-entry" and command in {"next"}:
            self._context = "admin"
            self._emit(b"fpa (admin) #")
            return
        if self._context == "admin" and command.startswith("edit "):
            self._context = "admin-entry"
            self._emit(b"fpa (mcp-user-01) $")
            return
        if self._context == "admin-entry" and command.startswith("set "):
            self._emit(b"fpa (mcp-user-01) $")
            return
        raise AssertionError(f"unexpected command: {command}")

    def _emit(self, output: bytes) -> None:
        self._reader.feed_data(output)


class _FakeWriter:
    def __init__(self, session: _FakeSshSession) -> None:
        self._session = session

    def write(self, value: bytes) -> None:
        self._session.dispatch(value)

    async def drain(self) -> None:
        return None


class _FakeProcess:
    def __init__(self, session: _FakeSshSession) -> None:
        self.stdin = _FakeWriter(session)
        self.stdout = session._reader


class _FakeReader:
    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed_data(self, value: bytes) -> None:
        self._buffer.extend(value)

    async def read(self, size: int) -> bytes:
        if not self._buffer:
            return b""
        value = bytes(self._buffer[:size])
        del self._buffer[:size]
        return value
