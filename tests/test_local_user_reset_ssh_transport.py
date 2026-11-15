from __future__ import annotations

import asyncio
from pathlib import Path
import time

import pytest

import fortipam_mcp.local_user_reset_ssh_transport as transport_module
from fortipam_mcp.local_user_create_ssh_transport import LocalUserCreateSshTransportConfig
from fortipam_mcp.local_user_reset_ssh_transport import (
    FortiPamLocalUserResetSshTransport,
    LocalUserResetSshTransportError,
    _readback,
)


USER = "mcp-v4-user-01"


def _config(tmp_path: Path) -> LocalUserCreateSshTransportConfig:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    return LocalUserCreateSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-local-user-writer",
        password="test-password",
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _output(*, status: str = "disable", profile: str = "Guest") -> bytes:
    return (
        f'edit "{USER}"\n'.encode("ascii")
        + f'    set accprofile "{profile}"\n'.encode("ascii")
        + f"    set status {status}\n".encode("ascii")
    )


def test_reset_rejects_out_of_namespace_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamLocalUserResetSshTransport(_config(tmp_path))

    with pytest.raises(LocalUserResetSshTransportError):
        transport.inspect("mcp-user-create-01")
    with pytest.raises(LocalUserResetSshTransportError):
        transport.reset_and_readback('mcp-v4-user-01"\nset status enable')


def test_inspection_uses_only_fixed_show_grep_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = _FakeSshSession(compact=b'edit "other-user"\n', full_outputs=[_output()])
    monkeypatch.setattr(transport_module.asyncssh, "connect", lambda *args, **kwargs: session)
    transport = FortiPamLocalUserResetSshTransport(_config(tmp_path))

    inspection = transport.inspect(USER)

    assert inspection.eligible is True
    assert session.commands == [
        "config system admin",
        "show full-configuration | grep fortipam-local-user-writer -f",
        "end",
        "config system admin",
        f"show | grep {USER}",
        "end",
        "config system admin",
        f"show | grep {USER} -f",
        "end",
        "exit",
    ]
    assert all(
        not command.startswith(("edit ", "set ", "next"))
        for command in session.commands
    )


def test_reset_uses_one_password_write_and_verifies_preserved_baseline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = _FakeSshSession(compact=b"", full_outputs=[_output()])
    monkeypatch.setattr(transport_module.asyncssh, "connect", lambda *args, **kwargs: session)
    transport = FortiPamLocalUserResetSshTransport(_config(tmp_path))

    readback = transport.reset_and_readback(USER)

    assert readback.verified is True
    assert session.commands[:3] == [
        "config system admin",
        "show full-configuration | grep fortipam-local-user-writer -f",
        "end",
    ]
    assert session.commands[3:9] == [
        "config system admin",
        f'edit "{USER}"',
        session.commands[5],
        "next",
        "end",
        "config system admin",
    ]
    assert session.commands[5].startswith('set password "McpV4!')
    assert session.commands[5].endswith('rZ9"')
    assert session.commands[9:] == [f"show | grep {USER} -f", "end", "exit"]


def test_unqualified_writer_is_rejected_before_password_generation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    session = _FakeSshSession(compact=b"", full_outputs=[], writer_profile="custom")
    monkeypatch.setattr(transport_module.asyncssh, "connect", lambda *args, **kwargs: session)
    def forbidden_generation() -> str:
        pytest.fail("Writer qualification must precede password generation")
    monkeypatch.setattr(transport_module, "_generated_replacement_password", forbidden_generation)
    transport = FortiPamLocalUserResetSshTransport(_config(tmp_path))
    with pytest.raises(LocalUserResetSshTransportError) as caught:
        transport.reset_and_readback(USER)
    assert (caught.value.phase, caught.value.reason) == ("writer_preflight", "actor_unqualified")
    assert session.commands == ["config system admin",
        "show full-configuration | grep fortipam-local-user-writer -f", "end", "exit"]


def test_writer_qualification_requires_an_exact_complete_stanza() -> None:
    raw = b'config system admin\n    edit "writer"\n        set accprofile "super_admin"\n    next\nend\n'
    assert transport_module._qualified_writer(raw, "writer")
    assert not transport_module._qualified_writer(raw, "other")
    assert not transport_module._qualified_writer(raw.replace(b"next\n", b""), "writer")
    assert not transport_module._qualified_writer(raw + raw, "writer")
    assert not transport_module._qualified_writer(
        b'config system admin\n    edit "writer"\n    edit "other"\n        set accprofile "super_admin"\n    next\nend\n',
        "writer",
    )
    nested = (b'config system admin\n    edit "writer" <---\n'
              b'        set accprofile "super_admin"\n        config nested\n'
              b'            edit "writer" <---\n                set accprofile "other"\n'
              b'            next\n        end\n    next\nend\n')
    assert transport_module._qualified_writer(nested.replace(b"\n", b"\r\n"), "writer")
    assert not transport_module._qualified_writer(
        nested.replace(b'        set accprofile "super_admin"', b'        set accprofile "custom"'), "writer",
    )
    assert not transport_module._qualified_writer(raw.replace(b"end\n", b""), "writer")


def test_native_grep_table_marker_keeps_exact_complete_writer_and_role_binding() -> None:
    raw = (b'query echo\nconfig system admin <---\n'
           b'    edit "other"\n        set accprofile "super_admin"\n    next\n'
           b'    edit "writer" <---\n        set accprofile "super_admin"\n'
           b'        config nested\n            edit "writer"\n'
           b'                set accprofile "custom"\n            next\n'
           b'        end\n    next\n'
           b'    edit "third"\n        set accprofile "custom"\n    next\nend\n'
           b'fpa (admin) #')
    assert transport_module._qualified_writer(raw, 'writer')
    for invalid in (
        raw.replace(b'config system admin <---', b'config system admin <--- <---'),
        raw.replace(b'config system admin <---', b'config system api-user <---'),
        raw + raw,
        raw.replace(b'end\nfpa', b'fpa'),
        raw.replace(b'    next\n    edit "third"', b'    edit "third"'),
        raw.replace(b'    edit "writer" <---\n        set accprofile "super_admin"',
                    b'    edit "writer" <---\n        set accprofile "custom"'),
    ):
        assert not transport_module._qualified_writer(invalid, 'writer')


def test_readback_requires_the_exact_disabled_guest_baseline() -> None:
    assert _readback(_output(), USER).verified is True
    assert _readback(_output(status="enable"), USER).verified is False
    assert _readback(_output(profile="Administrator"), USER).verified is False
    assert _readback(_output() + b"    set status enable\n", USER).verified is False


@pytest.mark.parametrize("message,code,reason", [
    (b"Old password checking error", -61, "old_password_rejected"),
    (b"Only super admin user can change password", 1, "actor_not_authorized"),
])
def test_commit_failure_retains_only_safe_phase_reason_and_code(
    message: bytes, code: int, reason: str,
) -> None:
    class RejectedCommit(_FakeSshSession):
        def dispatch(self, value: bytes) -> None:
            self.commands.append(value.decode("ascii").strip())
            self._emit(
                b"private-identity private-password\n"
                + message
                + f"\nCommand fail. Return code {code}\n".encode("ascii")
                + b"fpa (mcp-v4-user-01) #"
            )

    session = RejectedCommit(compact=b"", full_outputs=[])
    session._reader._buffer.clear()
    with pytest.raises(LocalUserResetSshTransportError) as caught:
        asyncio.run(transport_module._reset_command(
            _FakeProcess(session), "next", b"fpa #", time.monotonic() + 5,
            "commit_target",
        ))
    error = caught.value
    assert (error.phase, error.reason, error.return_code) == (
        "commit_target", reason, code,
    )
    assert "private-" not in str(error)
    assert "private-" not in repr(vars(error))
    assert error.__cause__ is None
    assert session.commands == ["next"]


class _FakeSshSession:
    def __init__(self, *, compact: bytes, full_outputs: list[bytes],
                 writer_profile: str = "super_admin") -> None:
        self.commands: list[str] = []
        self._reader = _FakeReader()
        self._reader.feed_data(b"fpa #")
        self._compact = compact
        self._full_outputs = list(full_outputs)
        self._context = "root"
        self._writer_profile = writer_profile

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
        if self._context == "admin" and command == "show full-configuration | grep fortipam-local-user-writer -f":
            self._emit(('config system admin\n    edit "fortipam-local-user-writer" <---\n'
                        f'        set accprofile "{self._writer_profile}"\n    next\nend\n'
                        'fpa (admin) #').encode("ascii"))
            return
        if self._context == "admin" and command.startswith("show | grep "):
            output = (
                self._full_outputs.pop(0)
                if command.endswith(" -f")
                else self._compact
            )
            self._emit(output + b"fpa (admin) #")
            return
        if self._context == "admin" and command.startswith("edit "):
            self._context = "admin-entry"
            self._emit(b"fpa (mcp-v4-user-01) #")
            return
        if self._context == "admin-entry" and command.startswith("set password "):
            self._emit(b"fpa (mcp-v4-user-01) #")
            return
        if self._context == "admin-entry" and command == "next":
            self._context = "admin"
            self._emit(b"fpa (admin) #")
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
