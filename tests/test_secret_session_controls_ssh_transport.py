from __future__ import annotations

import asyncio
from pathlib import Path
import warnings

import pytest

import fortipam_mcp.secret_session_controls_ssh_transport as transport_module
from fortipam_mcp.approval_profile_ssh_transport import (
    ApprovalProfileSshTransportConfig,
)
from fortipam_mcp.secret_session_controls_ssh_transport import (
    API_UNAVAILABLE_REASON,
    ENV_PREFIX,
    FortiPamSecretSessionControlsSshTransport,
    SecretSessionControlsSshTransportConfigurationError,
    SecretSessionControlsSshTransportError,
    load_secret_session_controls_ssh_transport_config,
)
from fortipam_mcp.secret_metadata_http_transport import (
    SecretSessionControlsFolderPolicy,
    SecretSessionControlsProjectionInspection,
)


EVENT_FILTER_PROFILE = "mcp-v4-rdp-event-filter-existing01"


def _prewrite(
    *,
    recording_enabled: bool = False,
    clipboard_blocking_enabled: bool = False,
    rdp_event_filter_enabled: bool = False,
    rdp_event_filter_profile_matches: bool = False,
    policy: SecretSessionControlsFolderPolicy | None = None,
) -> SecretSessionControlsProjectionInspection:
    return SecretSessionControlsProjectionInspection(
        recording_enabled=recording_enabled,
        clipboard_blocking_enabled=clipboard_blocking_enabled,
        rdp_event_filter_enabled=rdp_event_filter_enabled,
        rdp_event_filter_profile_matches=rdp_event_filter_profile_matches,
        rdp_event_filter_profile_digest="a" * 64,
        proxy_enabled=True,
        rdp_tcp_forwarding_disabled=True,
        inherit_permission_matches=True,
        preserved_identity_relations_digest="b" * 64,
        folder_policy=policy or SecretSessionControlsFolderPolicy(
            17, "folder", "policy", "not-set", "not-set", "not-set",
        ),
        original_name="existing-secret",
        original_template="Windows Account",
    )


def _config(tmp_path: Path) -> ApprovalProfileSshTransportConfig:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"
    )
    known_hosts.chmod(0o600)
    return ApprovalProfileSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-secret-controls-writer",
        password="test-password",
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _environment(tmp_path: Path) -> dict[str, str]:
    password_file = tmp_path / "password"
    password_file.write_text("test-password\n")
    password_file.chmod(0o600)
    known_hosts = tmp_path / "known_hosts-loader"
    known_hosts.write_text(
        "fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"
    )
    known_hosts.chmod(0o600)
    return {
        f"{ENV_PREFIX}ENABLED": "true",
        f"{ENV_PREFIX}API_UNAVAILABLE_REASON": API_UNAVAILABLE_REASON,
        f"{ENV_PREFIX}SSH_HOST": "fpa.example",
        f"{ENV_PREFIX}SSH_USERNAME": "fortipam-secret-controls-writer",
        f"{ENV_PREFIX}SSH_PASSWORD_FILE": str(password_file),
        f"{ENV_PREFIX}SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }


def test_loader_requires_dedicated_enabled_reason_and_settings(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)

    config = load_secret_session_controls_ssh_transport_config(environment)

    assert config.host == "fpa.example"
    assert config.username == "fortipam-secret-controls-writer"
    assert config.port == 22
    assert config.timeout_seconds == 15


def test_loader_never_falls_back_to_another_ssh_family(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    del environment[f"{ENV_PREFIX}SSH_HOST"]
    environment["FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_SSH_HOST"] = "fallback.example"

    with pytest.raises(SecretSessionControlsSshTransportConfigurationError):
        load_secret_session_controls_ssh_transport_config(environment)


def test_loader_requires_exact_api_unavailable_reason(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    environment[f"{ENV_PREFIX}API_UNAVAILABLE_REASON"] = "other-reason"

    with pytest.raises(SecretSessionControlsSshTransportConfigurationError):
        load_secret_session_controls_ssh_transport_config(environment)


def test_fixed_secret_controls_compile_only_the_allowed_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretSessionControlsSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (database) #"
    secret_prompt = b"fpa (42) #"

    async def send(
        process: object,
        command: str,
        prompt: bytes,
        deadline: float,
    ) -> bytes:
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
        return {
            "config secret database": table_prompt,
            "edit 42": secret_prompt,
            "next": table_prompt,
            "end": root_prompt,
        }[command]

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._apply_commands(
            object(),
            root_prompt,
            100.0,
            42,
            (
                "set recording enable",
                "set block-clipboard enable",
                "set rdp-event-filter enable",
                'set rdp-event-filter-profile "mcp-v4-rdp-event-filter-existing01"',
            ),
        )
    )

    assert commands == [
        "config secret database",
        "edit 42",
        "set recording enable",
        "set block-clipboard enable",
        "set rdp-event-filter enable",
        'set rdp-event-filter-profile "mcp-v4-rdp-event-filter-existing01"',
        "next",
        "end",
    ]


def test_policy_satisfied_recording_and_clipboard_emit_only_filter_delta(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretSessionControlsSshTransport(_config(tmp_path))
    prewrite = _prewrite(
        recording_enabled=True,
        clipboard_blocking_enabled=True,
        policy=SecretSessionControlsFolderPolicy(
            17, "folder", "policy", "enable", "enable", "not-set",
        ),
    )
    commands: list[tuple[int, tuple[str, ...]]] = []

    async def capture(secret_id: int, delta: tuple[str, ...]) -> None:
        commands.append((secret_id, delta))

    monkeypatch.setattr(transport, "_enable_controls", capture)
    transport.enable_controls(42, EVENT_FILTER_PROFILE, prewrite=prewrite)

    assert commands == [(42, (
        "set rdp-event-filter enable",
        'set rdp-event-filter-profile "mcp-v4-rdp-event-filter-existing01"',
    ))]


@pytest.mark.parametrize(
    ("secret_id", "profile_name"),
    (
        (False, EVENT_FILTER_PROFILE),
        (0, EVENT_FILTER_PROFILE),
        (42, 'mcp-v4-rdp-event-filter-bad"\nset field value'),
        (42, "mcp-v4-approval-profile-01"),
    ),
)
def test_unsafe_selectors_are_rejected_before_connect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    secret_id: object,
    profile_name: str,
) -> None:
    transport = FortiPamSecretSessionControlsSshTransport(_config(tmp_path))

    def fail_connect(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("unsafe selector reached SSH")

    monkeypatch.setattr(transport_module.asyncssh, "connect", fail_connect)

    with pytest.raises(SecretSessionControlsSshTransportError):
        transport.enable_controls(  # type: ignore[arg-type]
            secret_id, profile_name, prewrite=_prewrite(),
        )


@pytest.mark.parametrize(
    "prewrite",
    [
        _prewrite(
            recording_enabled=True,
            clipboard_blocking_enabled=True,
            rdp_event_filter_enabled=True,
            rdp_event_filter_profile_matches=True,
        ),
        _prewrite(policy=SecretSessionControlsFolderPolicy(
            17, "folder", "policy", "enable", "not-set", "not-set",
        )),
    ],
)
def test_empty_delta_or_forced_policy_conflict_reject_before_connect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    prewrite: SecretSessionControlsProjectionInspection,
) -> None:
    transport = FortiPamSecretSessionControlsSshTransport(_config(tmp_path))

    def fail_connect(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("rejected delta reached SSH")

    monkeypatch.setattr(transport_module.asyncssh, "connect", fail_connect)
    with pytest.raises(SecretSessionControlsSshTransportError):
        transport.enable_controls(42, EVENT_FILTER_PROFILE, prewrite=prewrite)


def test_transport_errors_are_categorical(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretSessionControlsSshTransport(_config(tmp_path))

    def unavailable(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise OSError("connection detail must not escape")

    monkeypatch.setattr(transport_module.asyncssh, "connect", unavailable)

    with pytest.raises(
        SecretSessionControlsSshTransportError,
        match="Secret session-controls transport is unavailable",
    ):
        transport.enable_controls(42, EVENT_FILTER_PROFILE, prewrite=_prewrite())


def test_active_event_loop_fails_without_connect_or_unawaited_coroutine(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretSessionControlsSshTransport(_config(tmp_path))
    connect_calls: list[object] = []

    def fail_connect(*args: object, **kwargs: object) -> object:
        del args, kwargs
        connect_calls.append(object())
        raise AssertionError("active loop reached SSH")

    monkeypatch.setattr(transport_module.asyncssh, "connect", fail_connect)

    async def invoke() -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            with pytest.raises(SecretSessionControlsSshTransportError):
                transport.enable_controls(42, EVENT_FILTER_PROFILE, prewrite=_prewrite())

    asyncio.run(invoke())
    assert connect_calls == []


def test_connection_requires_pinned_host_trust(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    transport = FortiPamSecretSessionControlsSshTransport(config)
    captured: dict[str, object] = {}

    def connect(host: str, **kwargs: object) -> object:
        captured["host"] = host
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(transport_module.asyncssh, "connect", connect)

    transport._connection()

    assert captured == {
        "host": "fpa.example",
        "port": 22,
        "username": "fortipam-secret-controls-writer",
        "password": "test-password",
        "known_hosts": str(config.known_hosts_file),
        "client_keys": None,
        "agent_path": None,
        "preferred_auth": "password",
        "public_key_auth": False,
        "password_auth": True,
        "kbdint_auth": False,
        "host_based_auth": False,
        "gss_auth": False,
        "gss_kex": False,
        "config": [],
        "connect_timeout": 15,
        "keepalive_interval": 5,
        "keepalive_count_max": 1,
    }
