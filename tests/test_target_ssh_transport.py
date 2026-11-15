from __future__ import annotations

from pathlib import Path
import re

import pytest

import fortipam_mcp.target_ssh_transport as transport_module
from fortipam_mcp.target_ssh_transport import (
    DEFAULT_TEMPLATE,
    FortiPamTargetSshTransport,
    TargetSshTransportConfig,
    TargetSshTransportConfigurationError,
    TargetSshTransportError,
    _context_prompt,
    _readback,
    _require_context_prompt,
    _require_root_prompt,
    load_target_ssh_transport_config,
)


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> TargetSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return TargetSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-target-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_explicit_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_TARGET_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_TARGET_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_TARGET_SSH_USERNAME": "fortipam-target-writer",
        "FPA_HOME_LAB_FPA1_V4_TARGET_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_TARGET_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_target_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-target-writer"
    assert loaded.port == 22
    assert loaded.password == "test-password"

    environment["FPA_HOME_LAB_FPA1_V4_TARGET_ENABLED"] = "false"
    with pytest.raises(TargetSshTransportConfigurationError, match="ENABLED"):
        load_target_ssh_transport_config(environment)


def test_loader_rejects_group_readable_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    password.chmod(0o640)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_TARGET_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_TARGET_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_TARGET_SSH_USERNAME": "fortipam-target-writer",
        "FPA_HOME_LAB_FPA1_V4_TARGET_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_TARGET_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    with pytest.raises(TargetSshTransportConfigurationError, match="owner-only"):
        load_target_ssh_transport_config(environment)


def test_target_input_rejects_cli_injection_before_connection(tmp_path: Path) -> None:
    transport = FortiPamTargetSshTransport(_config(tmp_path))

    with pytest.raises(TargetSshTransportError):
        transport.inspect('unsafe"\nset class "Other"')
    with pytest.raises(TargetSshTransportError):
        transport.create_and_readback("safe-target", "not-an-ip")


def test_readback_requires_every_fixed_target_field() -> None:
    output = (
        b'edit "mcp-target-01"\r\n'
        b'    set class "Other"\r\n'
        + f'    set template "{DEFAULT_TEMPLATE}"\r\n'.encode("ascii")
        + b'    set address "192.0.2.10"\r\n'
        + b'    set web-proxy-status disable\r\n'
    )

    readback = _readback(output, "mcp-target-01", "192.0.2.10")

    assert readback.verified is False
    assert readback.owner_relation_matches is False
    assert readback.create_secret_group_relation_matches is False
    assert _readback(
        output.replace(b"set web-proxy-status disable", b"set web-proxy-status enable"),
        "mcp-target-01",
        "192.0.2.10",
    ).verified is False


def test_context_prompt_preserves_the_pinned_host_and_privilege_marker() -> None:
    assert _context_prompt(b"fpa #", "target") == b"fpa (target) #"
    assert _context_prompt(b"fpa $", "template") == b"fpa (template) $"
    with pytest.raises(TargetSshTransportError):
        _context_prompt(b"unexpected", "target")


def test_dynamic_target_prompt_accepts_entry_marker_but_preserves_host() -> None:
    _require_context_prompt(b"fpa #", b"fpa (target) $", "target")
    _require_root_prompt(b"fpa #", b"fpa $")
    with pytest.raises(TargetSshTransportError):
        _require_context_prompt(b"fpa #", b"other (target) $", "target")
    with pytest.raises(TargetSshTransportError):
        _require_root_prompt(b"fpa #", b"other $")


def test_inspection_uses_only_fixed_read_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = _FakeSshSession(
        target_show=b'edit "different-target"\n',
        template_show=f'edit "{DEFAULT_TEMPLATE}"\n'.encode("ascii"),
    )
    monkeypatch.setattr(transport_module.asyncssh, "connect", lambda *args, **kwargs: session)
    transport = FortiPamTargetSshTransport(_config(tmp_path))

    result = transport.inspect("mcp-target-01")

    assert result.exists is False
    assert session.commands == [
        "config secret target",
        "show | grep mcp-target-01",
        "end",
        "config secret target",
        "show | grep mcp-target-01 -f",
        "end",
        "exit",
    ]
    assert all(
        not command.startswith(("edit ", "set ", "next"))
        for command in session.commands
    )


def test_address_resolution_returns_only_one_exact_target_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = _FakeSshSession(
        target_show=(
            b'edit "unrelated"\n'
            b'    set address "192.0.2.11"\n'
            b'edit "bound-target"\n'
            b'    set address "192.0.2.10"\n'
        ),
        template_show=b"",
    )
    monkeypatch.setattr(transport_module.asyncssh, "connect", lambda *args, **kwargs: session)
    transport = FortiPamTargetSshTransport(_config(tmp_path))

    assert transport.resolve_unique_target_name_for_address("192.0.2.10") == "bound-target"
    assert session.commands == [
        "config secret target",
        "show | grep 192.0.2.10 -f",
        "end",
        "exit",
    ]
    assert transport_module._unique_target_name_for_address(
        b'edit "first"\n    set address "192.0.2.10"\n'
        b'edit "second"\n    set address "192.0.2.10"\n',
        "192.0.2.10",
    ) is None


def test_create_uses_the_exact_compiled_sequence_and_readback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = _FakeSshSession(
        target_show=b"",
        template_show=b"",
        target_readback=(
            b'edit "mcp-target-01"\n'
            b'    set class "Other"\n'
            + f'    set template "{DEFAULT_TEMPLATE}"\n'.encode("ascii")
            + b'    set address "192.0.2.10"\n'
            + b"    set web-proxy-status disable\n"
        ),
    )
    monkeypatch.setattr(transport_module.asyncssh, "connect", lambda *args, **kwargs: session)
    transport = FortiPamTargetSshTransport(_config(tmp_path))

    result = transport.create_and_readback("mcp-target-01", "192.0.2.10")

    assert result.verified is False
    assert session.commands[:5] == [
        "config secret target",
        'edit "mcp-target-01"',
        'set class "Other"',
        f'set template "{DEFAULT_TEMPLATE}"',
        'set address "192.0.2.10"',
    ]
    assert re.fullmatch(
        r"set creation-time \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
        session.commands[5],
    )
    assert session.commands[6:8] == [
        "set web-proxy-status disable",
        "next",
    ]
    assert session.commands[8:] == [
        "end",
        "config secret target",
        "show | grep mcp-target-01 -f",
        "end",
        "exit",
    ]


class _FakeSshSession:
    def __init__(
        self,
        *,
        target_show: bytes,
        template_show: bytes,
        target_readback: bytes | None = None,
    ) -> None:
        self.commands: list[str] = []
        self._reader = _FakeReader()
        self._reader.feed_data(b"fpa #")
        self._target_show = target_show
        self._template_show = template_show
        self._target_readback = target_readback
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
        if command == "config secret target":
            self._context = "target"
            self._emit(b"fpa (target) #")
            return
        if command == "config secret template":
            self._context = "template"
            self._emit(b"fpa (template) #")
            return
        if command == "end":
            self._context = "root"
            self._emit(b"fpa #")
            return
        if command == "exit":
            return
        if self._context == "target" and command.startswith("show | grep "):
            if command.endswith(" -f") and self._target_readback is not None:
                self._emit(self._target_readback + b"fpa (target) #")
            else:
                self._emit(self._target_show + b"fpa (target) #")
            return
        if self._context == "template" and command.startswith("show | grep SSH"):
            self._emit(self._template_show + b"fpa (template) #")
            return
        if self._context == "target" and command in {"next"}:
            self._context = "target"
            self._emit(b"fpa (target) $")
            return
        if self._context == "target-entry" and command in {"next"}:
            self._context = "target"
            self._emit(b"fpa (target) #")
            return
        if self._context == "target" and command.startswith("edit "):
            self._context = "target-entry"
            self._emit(b"fpa (mcp-target-01) $")
            return
        if self._context == "target-entry" and command.startswith("set "):
            self._emit(b"fpa (mcp-target-01) $")
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


def test_address_resolution_handles_indented_target_blocks_and_nested_relations():
    output = (
        b'config secret target\r\n'
        b'    edit "registered-rdp"\r\n'
        b'        set address "192.0.2.42"\r\n'
        b'        config user-permission\r\n'
        b'            edit "nested-principal"\r\n'
        b'                set permission read\r\n'
        b'            next\r\n'
        b'        end\r\n'
        b'    next\r\n'
        b'    edit "other-target"\r\n'
        b'        set address "192.0.2.43"\r\n'
        b'    next\r\n'
        b'end\r\n'
    )
    resolve = transport_module._unique_target_name_for_address
    assert resolve(output, "192.0.2.42") == "registered-rdp"
    assert resolve(output.replace(b"\r\n", b"\r\r\n"), "192.0.2.42") == "registered-rdp"
    marked = output.replace(b'edit "registered-rdp"', b'edit "registered-rdp" <---')
    marked = marked.replace(b'set address "192.0.2.42"', b'set address "192.0.2.42" <---')
    assert resolve(marked, "192.0.2.42") == "registered-rdp"
    duplicate = output.replace(b'192.0.2.43', b'192.0.2.42')
    assert resolve(duplicate, "192.0.2.42") is None
    unsupported = duplicate.replace(b'"other-target"', b'"other target"')
    assert resolve(unsupported, "192.0.2.42") is None
    assert resolve(output, "192.0.2.44") is None
