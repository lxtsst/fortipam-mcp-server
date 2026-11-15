from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.secret_policy_ssh_transport as transport_module
from fortipam_mcp.secret_policy_ssh_transport import (
    FortiPamSecretPolicySshTransport,
    SecretPolicySshTransportConfig,
    SecretPolicySshTransportConfigurationError,
    SecretPolicySshTransportError,
    _update_baseline,
    _update_readback,
    _readback,
    load_secret_policy_ssh_transport_config,
)


POLICY_NAME = "mcp-v4-secret-policy-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> SecretPolicySshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return SecretPolicySshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-policy-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_SECRET_POLICY_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SECRET_POLICY_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_SECRET_POLICY_SSH_USERNAME": "fortipam-policy-writer",
        "FPA_HOME_LAB_FPA1_V4_SECRET_POLICY_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_SECRET_POLICY_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_secret_policy_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-policy-writer"
    password.chmod(0o640)
    with pytest.raises(
        SecretPolicySshTransportConfigurationError,
        match="owner-only",
    ):
        load_secret_policy_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretPolicySshTransport(_config(tmp_path))

    with pytest.raises(SecretPolicySshTransportError):
        transport.inspect("default")
    with pytest.raises(SecretPolicySshTransportError):
        transport.create_and_readback('mcp-v4-secret-policy-unsafe"\nset x y')
    with pytest.raises(SecretPolicySshTransportError):
        transport.read_update_baseline('mcp-v4-secret-policy-unsafe"\nset x y')
    with pytest.raises(SecretPolicySshTransportError):
        transport.read_session_security_baseline('mcp-v4-secret-policy-unsafe"\nset x y')
    with pytest.raises(SecretPolicySshTransportError):
        transport.update_clipboard_and_readback('mcp-v4-secret-policy-unsafe"\nset x y')


@pytest.mark.parametrize("selected,foreign", [(b"enable", b"disable"), (b"disable", b"enable")])
def test_onboarding_read_scopes_grep_context_without_changing_mutation_guard(selected: bytes, foreign: bytes) -> None:
    output = (b'    edit "' + POLICY_NAME.encode() + b'"\r\n'
        b'fpa (policy) # show full-configuration | grep\r\n'
        b'    edit "' + POLICY_NAME.encode() + b'"\r\n'
        b'        set ssh-filter disable\r\n        set block-clipboard ' + selected + b'\r\n    next\r\n'
        b'    edit "mcp-v4-secret-policy-other"\r\n        set block-clipboard ' + foreign + b'\r\n    next\r\n')
    scoped = transport_module._selected_session_security_policy(output, POLICY_NAME)
    assert _update_baseline(scoped, POLICY_NAME).rdp_clipboard_block_enabled is (selected == b"enable")
    assert _update_baseline(output, POLICY_NAME).rdp_clipboard_block_enabled is False
    assert b'policy-other' not in scoped


@pytest.mark.parametrize("body", [b'    edit "another"\n    next\n',
    b'    edit "'+POLICY_NAME.encode()+b'"\n        set block-clipboard enable\n',
    b'    edit "'+POLICY_NAME.encode()+b'"\n        config nested\n    next\n'])
def test_onboarding_selected_block_refuses_missing_or_nested_evidence(body: bytes) -> None:
    with pytest.raises(SecretPolicySshTransportError):
        transport_module._selected_session_security_policy(body, POLICY_NAME)


def test_readback_requires_both_fixed_policy_controls() -> None:
    output = (
        b'edit "mcp-v4-secret-policy-01"\r\n'
        + b"set ssh-filter disable\r\n"
        + b"set block-clipboard enable\r\n"
    )

    assert _readback(output, POLICY_NAME).verified is True
    assert (
        _readback(
            output.replace(b"block-clipboard", b"block-rdp-clipboard"),
            POLICY_NAME,
        ).verified
        is False
    )
    assert (
        _readback(
            output.replace(b"set ssh-filter disable", b"set ssh-filter enable"),
            POLICY_NAME,
        ).verified
        is False
    )


def test_update_baseline_and_readback_require_one_exact_field_transition() -> None:
    baseline = (
        b'edit "mcp-v4-secret-policy-01"\r\n'
        + b"set ssh-filter disable\r\n"
        + b"set block-clipboard enable\r\n"
    )
    updated = baseline.replace(
        b"set block-clipboard enable",
        b"set block-clipboard disable",
    )

    assert _update_baseline(baseline, POLICY_NAME).verified is True
    assert _update_readback(updated, POLICY_NAME).verified is True
    assert _update_baseline(updated, POLICY_NAME).verified is False
    assert _update_readback(baseline, POLICY_NAME).verified is False
    assert _update_readback(
        updated + b"set block-clipboard enable\r\n",
        POLICY_NAME,
    ).verified is False

def test_create_uses_only_the_fixed_guide_policy_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretPolicySshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (policy) #"
    policy_prompt = b"fpa (mcp-v4-secret-policy-01) #"

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
        if command == "config secret policy":
            return table_prompt
        if command == 'edit "mcp-v4-secret-policy-01"':
            return policy_prompt
        if command == "next":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_policy(
            object(),
            root_prompt,
            POLICY_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret policy",
        'edit "mcp-v4-secret-policy-01"',
        "set ssh-filter disable",
        "set block-clipboard enable",
        "next",
        "end",
    ]


def test_update_uses_only_the_fixed_guide_policy_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretPolicySshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (policy) #"
    policy_prompt = b"fpa (mcp-v4-secret-policy-01) #"

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
        if command == "config secret policy":
            return table_prompt
        if command == 'edit "mcp-v4-secret-policy-01"':
            return policy_prompt
        if command == "next":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._update_clipboard_policy(
            object(),
            root_prompt,
            POLICY_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret policy",
        'edit "mcp-v4-secret-policy-01"',
        "set block-clipboard disable",
        "next",
        "end",
    ]


def test_policy_reader_uses_only_fixed_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretPolicySshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show | grep mcp-v4-secret-policy-01",
            'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-secret-policy-01"',
        }
        return b"policy"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config secret policy":
            return b"fpa (policy) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_policy(object(), b"fpa #", POLICY_NAME, 100.0)
    )

    assert output == b"policypolicy"
    assert commands == [
        "config secret policy",
        "show | grep mcp-v4-secret-policy-01",
        'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-secret-policy-01"',
        "end",
    ]
