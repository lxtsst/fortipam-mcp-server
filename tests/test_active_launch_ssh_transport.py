from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

import fortipam_mcp.active_launch_ssh_transport as transport_module
from fortipam_mcp.active_launch_ssh_transport import (
    ACTIVE_LAUNCH_CLEAR_COMMAND,
    ACTIVE_LAUNCH_LIST_COMMAND,
    ActiveLaunchSshTransportConfig,
    ActiveLaunchSshTransportConfigurationError,
    ActiveLaunchSshTransportError,
    FortiPamActiveLaunchSshTransport,
    _clear_command,
    _listing_from_output,
    load_active_launch_ssh_transport_config,
)


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> ActiveLaunchSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return ActiveLaunchSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-active-launch-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_private_ssh_configuration(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ACTIVE_LAUNCH_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ACTIVE_LAUNCH_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_ACTIVE_LAUNCH_SSH_USERNAME": "fortipam-active-launch-writer",
        "FPA_HOME_LAB_FPA1_V4_ACTIVE_LAUNCH_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_ACTIVE_LAUNCH_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_active_launch_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    invalid = dict(environment)
    invalid["FPA_HOME_LAB_FPA1_V4_ACTIVE_LAUNCH_SSH_HOST"] = "fpa.example\nexecute x"
    with pytest.raises(ActiveLaunchSshTransportConfigurationError):
        load_active_launch_ssh_transport_config(invalid)


def test_listing_parser_returns_tokens_only_for_recognized_token_labels() -> None:
    listing = _listing_from_output(
        b"diagnose wad token list\r\ntoken_id: launch-0123\r\ntoken: launch-0456\r\nfpa #\r\n"
    )

    assert listing.recognized is True
    assert listing.token_ids == ("launch-0123", "launch-0456")
    assert _listing_from_output(
        f"{ACTIVE_LAUNCH_LIST_COMMAND}\nfpa #\n".encode()
    ).token_ids == ()
    assert _listing_from_output(b"unrecognized WAD display\n").recognized is False
    with pytest.raises(ActiveLaunchSshTransportError):
        _listing_from_output(b"permission denied\n")


def test_empty_listing_accepts_dollar_root_prompt_without_ignoring_body() -> None:
    listing = _listing_from_output(b"diagnose wad token list\r\nfpa $\r\n")

    assert listing.recognized is True
    assert listing.token_ids == ()
    assert _listing_from_output(b"unknown body\r\nfpa $\r\n").recognized is False


def test_build29_complete_native_records_preserve_inventory_and_reject_partial_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from fortipam_mcp.active_launch_live_workflow import ActiveLaunchLiveWorkflow

    echo, prompt = b'diagnose wad token list\r\n\r\n', b'\r\n\r\nfpa # '

    def record(token: bytes) -> bytes:
        return (b' 192.0.2.10:0->fixture.example.test:18585\r\n\r\n id=' + token
            + b', worker_id=0 launcher=Web Browsing\r\n'
            b' account_name=fixture-user secret=42 secret_name=lab-web-fixture\r\n'
            b' gateway_name= gateway_address=\r\n')

    first, second = record(b'123456789'), record(b'987654321')
    one, two = echo + first + prompt, echo + first + second + prompt
    assert _listing_from_output(one).token_ids == ('123456789',)
    inventory = _listing_from_output(two)
    assert inventory.recognized and inventory.token_ids == ('123456789', '987654321')
    identities = dict(inventory.record_identities)
    assert set(identities) == set(inventory.token_ids) and identities['123456789'] != identities['987654321']
    assert inventory.serial_digest is None
    for rejected in (
        b'', echo, prompt,
        echo + first + b'unknown native field\r\n' + prompt,
        echo + first.replace(b' gateway_name= gateway_address=\r\n', b'') + prompt,
        echo + first + second[:-25] + prompt,
        echo + first + first + prompt,
        echo + first,
        echo + b'id=123456789\r\n' + prompt,
        echo + first + b'token_id=legacy-token\r\n' + prompt,
        echo + first.replace(b'launcher=Web Browsing', b'launcher=Web Browsing unknown=1') + prompt,
        echo + first.replace(b'192.0.2.10:0', b'999.0.2.10:0') + prompt,
        b'token_id=legacy-token\nunknown body\n',
        b'token_id=legacy-token\ntoken_id=legacy-token\n',
    ):
        listing = _listing_from_output(rejected)
        assert listing.recognized is False and listing.token_ids == ()
        assert listing.record_identities == ()

    class NativeListingTransport:
        def list_active_launches(self):
            return _listing_from_output(two)

    observed = ActiveLaunchLiveWorkflow(NativeListingTransport(), clock=lambda: 100).observe(
        requester_digest='a' * 64)
    assert observed['active_launch_count'] == 2 and observed['observation'] == 'verified'
    assert all(private not in repr(observed) for private in (
        '123456789', '987654321', '192.0.2.10', 'fixture.example.test', 'fixture-user', 'lab-web-fixture'))

    serial = b'FPAFIXTURESERIAL'
    transport = FortiPamActiveLaunchSshTransport(_config(tmp_path),
        expected_serial_digest=hashlib.sha256(serial).hexdigest())
    commands: list[str] = []
    mode, cleared = 'preserved', False
    guard_calls = 0

    class Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def open_cli(connection):
        return object(), b'fpa #', 100.0

    async def close_cli(process):
        pass

    async def send(process, command, root_prompt, deadline):
        nonlocal cleared
        commands.append(command)
        if command == transport_module._source_reader._SERIAL:
            value = b'OTHERFIXTURESERIAL' if mode == 'wrong-device' else serial
            return command.encode() + b'\r\nSerial-Number: ' + value + b'\r\nfpa # '
        if command == transport_module._source_reader._VERSION:
            return command.encode() + b'\r\nVersion: FortiPAM v7.0.0,build0029\r\nfpa # '
        if command == ACTIVE_LAUNCH_LIST_COMMAND:
            if cleared:
                remaining = second.replace(b'lab-web-fixture', b'changed-fixture') if mode == 'other-drift' else second
                return echo + remaining + prompt
            selected = first.replace(b'lab-web-fixture', b'changed-fixture') if mode == 'selected-drift' else first
            return echo + selected + second + prompt
        assert command == f'{ACTIVE_LAUNCH_CLEAR_COMMAND} 123456789'
        cleared = True
        if mode == 'ack-empty':
            return b''
        if mode == 'ack-truncated':
            return command.encode() + b'\r\n'
        if mode == 'ack-clear-all':
            return ACTIVE_LAUNCH_CLEAR_COMMAND.encode() + b'\r\n\r\nfpa # '
        if mode == 'ack-other-prompt':
            return command.encode() + b'\r\n\r\nother-fpa # '
        body = (b'Permission denied\r\n' if mode == 'ack-failure'
            else b'Operation completed\r\n' if mode == 'ack-body' else b'')
        return command.encode() + b'\r\n' + body + b'\r\nfpa # '

    def guard():
        nonlocal guard_calls
        guard_calls += 1
        assert not cleared and commands[-1] == transport_module._source_reader._VERSION
        if mode == 'guard-denied':
            raise ValueError('Synthetic original authorization expired')

    monkeypatch.setattr(transport, '_connection', Connection)
    monkeypatch.setattr(transport, '_open_cli', open_cli)
    monkeypatch.setattr(transport_module, '_close_cli', close_cli)
    monkeypatch.setattr(transport_module, '_send_and_read', send)
    fresh = transport.list_active_launches()
    assert fresh.serial_digest == hashlib.sha256(serial).hexdigest()
    assert fresh.record_identities == inventory.record_identities
    for mode in ('preserved', 'selected-drift', 'other-drift', 'wrong-device', 'guard-denied',
                 'ack-empty', 'ack-truncated', 'ack-clear-all', 'ack-other-prompt', 'ack-failure', 'ack-body'):
        cleared = False
        guard_calls = 0
        commands.clear()
        if mode in ('selected-drift', 'wrong-device', 'guard-denied') or mode.startswith('ack-') and mode != 'ack-body':
            with pytest.raises(ActiveLaunchSshTransportError):
                transport.clear_active_launch_and_readback('123456789',
                    expected_identity_digest=identities['123456789'], guard=guard)
            assert cleared is mode.startswith('ack-')
            if cleared:
                # Even if the selected session naturally disappears meanwhile,
                # a failed or incomplete ACK must not reach successful readback.
                assert commands.count(ACTIVE_LAUNCH_LIST_COMMAND) == 1
        else:
            readback = transport.clear_active_launch_and_readback('123456789',
                expected_identity_digest=identities['123456789'], guard=guard)
            assert readback.verified is (mode in ('preserved', 'ack-body'))
            assert commands.count(f'{ACTIVE_LAUNCH_CLEAR_COMMAND} 123456789') == 1
        assert guard_calls == (0 if mode in ('selected-drift', 'wrong-device') else 1)
        assert ACTIVE_LAUNCH_CLEAR_COMMAND not in commands


def test_clear_command_requires_one_safe_nonempty_token_and_never_uses_clear_all() -> None:
    assert _clear_command("launch-0123") == f"{ACTIVE_LAUNCH_CLEAR_COMMAND} launch-0123"
    with pytest.raises(ActiveLaunchSshTransportError):
        _clear_command("")
    with pytest.raises(ActiveLaunchSshTransportError):
        _clear_command("launch-0123;diagnose wad token clear")


def test_transport_emits_only_fixed_list_and_exact_clear_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamActiveLaunchSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        if command == ACTIVE_LAUNCH_LIST_COMMAND:
            return b"token_id=launch-0123\n"
        assert command == f"{ACTIVE_LAUNCH_CLEAR_COMMAND} launch-0123"
        return b"\n"

    monkeypatch.setattr(transport_module, "_send_and_read", send)

    assert asyncio.run(transport._list(object(), b"fpa #", 100.0)) == b"token_id=launch-0123\n"
    assert asyncio.run(transport._clear(object(), b"fpa #", 100.0, "launch-0123")) == b"\n"
    assert commands == [
        ACTIVE_LAUNCH_LIST_COMMAND,
        f"{ACTIVE_LAUNCH_CLEAR_COMMAND} launch-0123",
    ]


def test_transport_rejects_a_nonroot_cli_prompt_before_any_wad_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamActiveLaunchSshTransport(_config(tmp_path))

    async def complete_pre_login(*args: object, **kwargs: object) -> bytes:
        del args, kwargs
        return b"fpa (config) #"

    monkeypatch.setattr(transport_module, "_complete_pre_login", complete_pre_login)

    with pytest.raises(ActiveLaunchSshTransportError):
        asyncio.run(transport._open_cli(_FakeConnection()))


class _FakeConnection:
    async def create_process(self, **kwargs: object) -> object:
        del kwargs
        return _FakeProcess()


class _FakeProcess:
    stdout = object()
    stdin = object()


@pytest.mark.parametrize(
    ('after', 'expected'),
    [
        (b'token_id=launch-0456\n', 'succeeded'),
        (b'token_id=launch-0456\ntoken_id=launch-new\n', 'succeeded'),
        (b'diagnose wad token list\nfpa #\n', 'reconciliation_required'),
        (b'unrecognized WAD display\n', 'reconciliation_required'),
        (b'token_id=launch-0123\ntoken_id=launch-0456\n', 'reconciliation_required'),
    ],
    ids=['preserved', 'new-session', 'other-session-lost', 'unknown', 'selected-still-present'],
)
def test_disconnect_verifies_selected_absence_and_other_sessions_in_one_flow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, after: bytes, expected: str,
) -> None:
    from fortipam_mcp.active_launch_live_workflow import (
        ActiveLaunchLiveWorkflow, ActiveLaunchLiveWorkflowError,
    )

    transport = FortiPamActiveLaunchSshTransport(_config(tmp_path))
    commands: list[str] = []
    cleared = False

    class Connection:
        async def __aenter__(self) -> 'Connection':
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

    async def open_cli(connection: object) -> tuple[object, bytes, float]:
        return object(), b'fpa #', 100.0

    async def close_cli(process: object) -> None:
        pass

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        nonlocal cleared
        commands.append(command)
        if command == ACTIVE_LAUNCH_LIST_COMMAND:
            return after if cleared else b'token_id=launch-0123\ntoken_id=launch-0456\n'
        assert command == f'{ACTIVE_LAUNCH_CLEAR_COMMAND} launch-0123'
        cleared = True
        return b'\n'

    monkeypatch.setattr(transport, '_connection', Connection)
    monkeypatch.setattr(transport, '_open_cli', open_cli)
    monkeypatch.setattr(transport_module, '_close_cli', close_cli)
    monkeypatch.setattr(transport_module, '_send_and_read', send)
    workflow = ActiveLaunchLiveWorkflow(transport, clock=lambda: 100)
    requester = 'a' * 64
    observed = workflow.observe(requester_digest=requester)
    launch_ref = observed['active_launch_refs'][0]['launch_ref']
    preview = workflow.preview_disconnect(launch_ref, requester_digest=requester)
    confirmed = workflow.confirm_disconnect(preview['preview_ref'], requester_digest=requester)
    result = workflow.execute_disconnect(confirmed['authorization_ref'], requester_digest=requester)
    assert result['outcome'] == expected
    assert result['verification'] == ('verified' if expected == 'succeeded' else 'unknown')
    assert 'launch-0123' not in repr(result) and 'launch-0456' not in repr(result)
    if expected == 'succeeded':
        assert workflow.execute_disconnect(
            confirmed['authorization_ref'], requester_digest=requester,
        )['idempotent_replay'] is True
    else:
        with pytest.raises(ActiveLaunchLiveWorkflowError):
            workflow.execute_disconnect(confirmed['authorization_ref'], requester_digest=requester)
    assert commands.count(f'{ACTIVE_LAUNCH_CLEAR_COMMAND} launch-0123') == 1
    assert ACTIVE_LAUNCH_CLEAR_COMMAND not in commands
