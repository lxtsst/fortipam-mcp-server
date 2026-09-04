from __future__ import annotations

import json

import pytest

from fortipam_mcp.config import (
    APPROVAL_PROFILE_PATH,
    ConfigurationError,
    CURATED_READ_PATHS,
    DEFAULT_HEALTH_PATH,
    EMS_STATUS_SUMMARY_PATH,
    FORTIANALYZER_SETTING_PATH,
    HA_CONFIGURATION_PATH,
    LICENSE_STATUS_PATH,
    PASSWORD_CHANGER_PATH,
    RECORDING_STORAGE_PATH,
    configuration_presence,
    load_cli_config,
    load_config,
    normalize_api_path,
    SYSTEM_GLOBAL_PATH,
    SYSTEM_STATUS_PATH,
)


def _environment(**overrides: str) -> dict[str, str]:
    environment = {
        "FPA_HOME_LAB_FPA1_HOST": "fortipam.lab.example",
        "FPA_HOME_LAB_FPA1_API_TOKEN": "test-token-not-a-real-secret",
    }
    environment.update(overrides)
    return environment


def test_resolves_bearer_token_and_compiled_read_boundary() -> None:
    config = load_config(_environment())

    assert config.base_url == "https://fortipam.lab.example"
    assert config.authentication.kind == "bearer"
    assert config.health_path == DEFAULT_HEALTH_PATH
    assert config.allowed_read_paths == CURATED_READ_PATHS
    assert config.allowed_read_paths == {
        SYSTEM_STATUS_PATH,
        SYSTEM_GLOBAL_PATH,
        APPROVAL_PROFILE_PATH,
        FORTIANALYZER_SETTING_PATH,
        LICENSE_STATUS_PATH,
        PASSWORD_CHANGER_PATH,
        HA_CONFIGURATION_PATH,
        RECORDING_STORAGE_PATH,
        EMS_STATUS_SUMMARY_PATH,
    }


def test_applies_non_default_https_port() -> None:
    config = load_config(_environment(FPA_HOME_LAB_FPA1_HTTPS_PORT="8443"))

    assert config.base_url == "https://fortipam.lab.example:8443"


def test_rejects_non_https_or_path_bearing_target() -> None:
    with pytest.raises(ConfigurationError):
        load_config(_environment(FPA_HOME_LAB_FPA1_HOST="http://fortipam.lab.example"))

    with pytest.raises(ConfigurationError):
        load_config(
            _environment(
                FPA_HOME_LAB_FPA1_BASE_URL="https://fortipam.lab.example/api",
                FPA_HOME_LAB_FPA1_HOST="",
            )
        )


def test_rejects_query_token_transport() -> None:
    with pytest.raises(ConfigurationError, match="Bearer"):
        load_config(_environment(FPA_HOME_LAB_FPA1_TOKEN_TRANSPORT="query"))


def test_rejects_runtime_allowlist_expansion(tmp_path) -> None:
    local_config = tmp_path / "fortipam.json"
    local_config.write_text(
        json.dumps(
            {
                "health_path": SYSTEM_STATUS_PATH,
                "allowed_read_paths": [SYSTEM_STATUS_PATH, "/api/v2/cmdb/system/admin"],
                "token_transport": "bearer",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="cannot expand"):
        load_config(_environment(FORTIPAM_MCP_CONFIG=str(local_config)))


@pytest.mark.parametrize(
    "path",
    (
        "/api/v2/cmdb/secret/approval-profile?scope=all",
        "/api/v2/cmdb/../secret",
        "/api/v2/cmdb/secret/approval-profile/",
    ),
)
def test_rejects_non_exact_api_paths(path: str) -> None:
    with pytest.raises(ConfigurationError):
        normalize_api_path(path)


def test_resolves_dedicated_key_only_cli_configuration(tmp_path) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fortipam-cli.example ssh-ed25519 AAAATEST\n")
    known_hosts.chmod(0o600)
    identity = tmp_path / "id_ed25519"
    identity.write_text("test-key\n")
    identity.chmod(0o600)
    environment = _environment(
        FPA_HOME_LAB_FPA1_SSH_IP="fortipam-cli.example",
        FPA_HOME_LAB_FPA1_SSH_PORT="2222",
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_HOST="fortipam-cli.example",
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_PORT="2222",
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_USERNAME="fortipam-mcp-cli-v2",
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_KNOWN_HOSTS_FILE=str(known_hosts),
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_IDENTITY_FILE=str(identity),
    )

    config = load_cli_config(environment)
    presence = configuration_presence(environment)

    assert config.target.port == 2222
    assert config.target.username == "fortipam-mcp-cli-v2"
    assert config.accept_pre_login_banner is False
    assert presence["cli_configuration_valid"] is True
    assert presence["cli_host_key_pinning_enabled"] is True
    assert presence["cli_public_key_authentication_enabled"] is True
    assert presence["cli_password_authentication_enabled"] is False


def test_cli_pre_login_banner_acceptance_requires_exact_explicit_boolean(tmp_path) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fortipam-cli.example ssh-ed25519 AAAATEST\n")
    known_hosts.chmod(0o600)
    identity = tmp_path / "id_ed25519"
    identity.write_text("test-key\n")
    identity.chmod(0o600)
    environment = _environment(
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_HOST="fortipam-cli.example",
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_USERNAME="dedicated-cli",
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_KNOWN_HOSTS_FILE=str(known_hosts),
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_IDENTITY_FILE=str(identity),
        FPA_HOME_LAB_FPA1_MCP_CLI_ACCEPT_PRE_LOGIN_BANNER="true",
    )

    assert load_cli_config(environment).accept_pre_login_banner is True

    environment["FPA_HOME_LAB_FPA1_MCP_CLI_ACCEPT_PRE_LOGIN_BANNER"] = "yes"
    with pytest.raises(ConfigurationError, match="exactly true or false"):
        load_cli_config(environment)


def test_cli_configuration_never_falls_back_to_api_identity() -> None:
    with pytest.raises(ConfigurationError, match="dedicated"):
        load_cli_config(_environment(FPA_HOME_LAB_FPA1_USERNAME="api-user"))


def test_cli_configuration_does_not_fall_back_to_general_ssh_target(tmp_path) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fortipam-cli.example ssh-ed25519 AAAATEST\n")
    known_hosts.chmod(0o600)
    identity = tmp_path / "id_ed25519"
    identity.write_text("test-key\n")
    identity.chmod(0o600)
    environment = _environment(
        FPA_HOME_LAB_FPA1_SSH_IP="legacy.example",
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_USERNAME="dedicated-cli",
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_KNOWN_HOSTS_FILE=str(known_hosts),
        FPA_HOME_LAB_FPA1_MCP_CLI_SSH_IDENTITY_FILE=str(identity),
    )
    with pytest.raises(ConfigurationError, match="dedicated username"):
        load_cli_config(environment)
