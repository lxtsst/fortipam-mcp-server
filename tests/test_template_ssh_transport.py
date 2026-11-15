from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.template_ssh_transport as transport_module
from fortipam_mcp.template_ssh_transport import (
    FortiPamTemplateSshTransport,
    TEMPLATE_DEFAULT_PORT,
    TEMPLATE_UPDATED_PORT,
    TemplateSshTransportConfig,
    TemplateSshTransportConfigurationError,
    TemplateSshTransportError,
    _readback,
    _update_baseline_readback,
    _update_readback,
    load_template_ssh_transport_config,
)


TEMPLATE_NAME = "mcp-v4-template-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> TemplateSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return TemplateSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-template-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_SSH_USERNAME": "fortipam-template-writer",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_template_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-template-writer"
    password.chmod(0o640)
    with pytest.raises(TemplateSshTransportConfigurationError, match="owner-only"):
        load_template_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamTemplateSshTransport(_config(tmp_path))

    with pytest.raises(TemplateSshTransportError):
        transport.inspect("Template for VNC")
    with pytest.raises(TemplateSshTransportError):
        transport.create_and_readback('mcp-v4-template-unsafe"\nset access none')
    with pytest.raises(TemplateSshTransportError):
        transport.update_baseline_readback("Template for VNC")
    with pytest.raises(TemplateSshTransportError):
        transport.update_web_vnc_port_and_readback(
            'mcp-v4-template-unsafe"\nset port 5902'
        )


def test_loader_reads_one_protected_pair_and_rejects_mixed_or_unsafe_sources(tmp_path: Path) -> None:
    known_hosts, _ = _files(tmp_path)
    secret_env = tmp_path / "central.local.env"
    secret_env.write_text("BOUND_USER=synthetic-owner\nBOUND_PASSWORD=synthetic-password\n")
    secret_env.chmod(0o600)
    prefix = "FPA_HOME_LAB_FPA1_V4_TEMPLATE_"
    environment = {
        prefix + "ENABLED": "true",
        prefix + "SSH_HOST": "fpa.example",
        prefix + "SSH_KNOWN_HOSTS_FILE": str(known_hosts),
        prefix + "SSH_LOGIN_ENV_FILE": str(secret_env),
        prefix + "SSH_USERNAME_VARIABLE": "BOUND_USER",
        prefix + "SSH_PASSWORD_VARIABLE": "BOUND_PASSWORD",
    }
    loaded = load_template_ssh_transport_config(environment)
    assert (loaded.username, loaded.password) == ("synthetic-owner", "synthetic-password")
    for changes in ({prefix + "SSH_USERNAME": "other-owner"},
                    {prefix + "SSH_PASSWORD_FILE": str(secret_env)},
                    {prefix + "SSH_PASSWORD_VARIABLE": "BOUND_USER"},
                    {prefix + "SSH_PASSWORD_VARIABLE": "MISSING"}):
        with pytest.raises(TemplateSshTransportConfigurationError) as failure:
            load_template_ssh_transport_config({**environment, **changes})
        assert "synthetic-password" not in str(failure.value)
    secret_env.chmod(0o640)
    with pytest.raises(TemplateSshTransportConfigurationError):
        load_template_ssh_transport_config(environment)


def test_readback_requires_each_fixed_field_and_launcher_control() -> None:
    output = (
        b'edit "mcp-v4-template-01"\r\n'
        + b"set access everyone\r\n"
        + b'edit "Username"\r\n'
        + b"set type username\r\n"
        + b"set mandatory enable\r\n"
        + b'edit "Password"\r\n'
        + b"set type password\r\n"
        + b"set mandatory enable\r\n"
        + b'set launcher-name "Web VNC"\r\n'
        + b"set port 5900\r\n"
    )

    assert _readback(output, TEMPLATE_NAME).verified is True
    assert (
        _readback(
            output.replace(
                b'edit "Username"\r\nset type username\r\nset mandatory enable',
                b'edit "Username"\r\nset type username',
            ),
            TEMPLATE_NAME,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_template_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamTemplateSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (template) #"
    template_prompt = b"fpa (mcp-v4-template-01) #"
    field_table_prompt = b"fpa (field) #"
    username_prompt = b"fpa (Username) #"
    password_prompt = b"fpa (Password) #"
    launcher_table_prompt = b"fpa (launcher) #"
    launcher_prompt = b"fpa (1) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config secret template":
            return table_prompt
        if command == 'edit "mcp-v4-template-01"':
            return template_prompt
        if command == "config field":
            return field_table_prompt
        if command == 'edit "Username"':
            return username_prompt
        if command == 'edit "Password"':
            return password_prompt
        if command == "config launcher":
            return launcher_table_prompt
        if command == "edit 1":
            return launcher_prompt
        if command == "next":
            count = commands.count("next")
            return (
                field_table_prompt
                if count in {1, 2}
                else launcher_table_prompt
                if count == 3
                else table_prompt
            )
        if command == "end":
            count = commands.count("end")
            return template_prompt if count in {1, 2} else root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_template(
            object(),
            root_prompt,
            TEMPLATE_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret template",
        'edit "mcp-v4-template-01"',
        "set access everyone",
        "config field",
        'edit "Username"',
        "set type username",
        "set mandatory enable",
        "next",
        'edit "Password"',
        "set type password",
        "set mandatory enable",
        "next",
        "end",
        "config launcher",
        "edit 1",
        'set launcher-name "Web VNC"',
        "set port 5900",
        "next",
        "end",
        "next",
        "end",
    ]


def test_template_reader_uses_both_requested_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamTemplateSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show | grep mcp-v4-template-01",
            "show | grep mcp-v4-template-01 -f",
        }
        return b"template"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config secret template":
            return b"fpa (template) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_template(object(), b"fpa #", TEMPLATE_NAME, 100.0)
    )

    assert output == b"templatetemplate"
    assert commands == [
        "config secret template",
        "show | grep mcp-v4-template-01",
        "show | grep mcp-v4-template-01 -f",
        "end",
    ]


def _update_output(port: int) -> bytes:
    return f'''config secret template
    edit "{TEMPLATE_NAME}"
        set access everyone
        config field
            edit "Username"
                set type username
                set mandatory enable
                set need-edit disable
            next
            edit "Password"
                set type password
                set mandatory enable
                set need-edit disable
            next
        end
        config launcher
            edit 1
                set launcher-name "Web VNC"
                set port {port}
            next
        end
    next
end
'''.encode("ascii")


def test_update_readback_requires_exact_create_baseline_and_updated_port() -> None:
    baseline = _update_baseline_readback(
        _update_output(TEMPLATE_DEFAULT_PORT),
        TEMPLATE_NAME,
    )
    updated = _update_readback(
        _update_output(TEMPLATE_UPDATED_PORT),
        TEMPLATE_NAME,
    )

    assert baseline.verified is True
    assert updated.verified is True
    assert _update_baseline_readback(
        _update_output(TEMPLATE_DEFAULT_PORT) + b"fpa $ ", TEMPLATE_NAME,
    ).verified is True
    assert baseline.configuration_digest == updated.configuration_digest
    assert (
        _update_baseline_readback(
            _update_output(TEMPLATE_UPDATED_PORT),
            TEMPLATE_NAME,
        ).verified
        is False
    )
    assert _update_readback(_update_output(TEMPLATE_DEFAULT_PORT), TEMPLATE_NAME).verified is False


@pytest.mark.parametrize(
    ("original", "replacement"),
    (
        (b"config field", b'config field\nedit "Extra"\nset type text\nnext'),
        (b"config launcher", b'config launcher\nedit 2\nset launcher-name "Web VNC"\nset port 5900\nnext'),
        (b"edit 1", b"edit 2"),
        (b"set access everyone", b'set access owner\nset description "set access everyone"'),
        (b"set mandatory enable", b"set mandatory disable"),
        (b"set need-edit disable", b"set need-edit enable"),
        (b"set need-edit disable", b"set need-edit disable\nset unexpected enable"),
        (b"set type username", b"set type username\nset type text"),
        (b"set port 5900", b"--More--\nset port 5900"),
        (b"    next\nend\n", b"    next\n"),
        (b"    next\nend\n", b'    next\nedit "mcp-v4-template-neighbor"\nnext\nend\n'),
        (b"    next\nend\n", b"    next\nend\nset access owner\n"),
    ),
)
def test_update_rejects_ambiguous_extra_or_incomplete_configuration(
    original: bytes, replacement: bytes,
) -> None:
    output = _update_output(TEMPLATE_DEFAULT_PORT).replace(original, replacement)

    assert _update_baseline_readback(output, TEMPLATE_NAME).verified is False


def test_exact_update_read_uses_full_single_object_root_show(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    transport = FortiPamTemplateSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return _update_output(TEMPLATE_DEFAULT_PORT)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    output = asyncio.run(transport._show_template_for_update(object(), b"fpa #", TEMPLATE_NAME, 100))

    assert _update_baseline_readback(output, TEMPLATE_NAME).verified is True
    assert commands == [f'show full-configuration secret template "{TEMPLATE_NAME}"']


def test_update_writes_only_the_fixed_web_vnc_port_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamTemplateSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (template) #"
    template_prompt = b"fpa (mcp-v4-template-01) #"
    launcher_table_prompt = b"fpa (launcher) #"
    launcher_prompt = b"fpa (1) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == f"set port {TEMPLATE_UPDATED_PORT}"
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config secret template":
            return table_prompt
        if command == 'edit "mcp-v4-template-01"':
            return template_prompt
        if command == "config launcher":
            return launcher_table_prompt
        if command == "edit 1":
            return launcher_prompt
        if command == "next":
            return launcher_table_prompt if commands.count("next") == 1 else table_prompt
        if command == "end":
            return template_prompt if commands.count("end") == 1 else root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._update_web_vnc_port(
            object(),
            root_prompt,
            TEMPLATE_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret template",
        'edit "mcp-v4-template-01"',
        "config launcher",
        "edit 1",
        f"set port {TEMPLATE_UPDATED_PORT}",
        "next",
        "end",
        "next",
        "end",
    ]
