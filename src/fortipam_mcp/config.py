"""Configuration resolution for one central FortiPAM lab target."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from .cli_safety import CliExecutionLimits, SshCliTarget
from .env import DEVICE_PREFIX, project_root

SYSTEM_STATUS_PATH = "/api/v2/monitor/system/status"
SYSTEM_GLOBAL_PATH = "/api/v2/cmdb/system/global"
APPROVAL_PROFILE_PATH = "/api/v2/cmdb/secret/approval-profile"
FORTIANALYZER_SETTING_PATH = "/api/v2/cmdb/log.fortianalyzer/setting"
LICENSE_STATUS_PATH = "/api/v2/monitor/license/status"
HA_CONFIGURATION_PATH = "/api/v2/cmdb/system/ha"
RECORDING_STORAGE_PATH = "/api/v2/monitor/log/current-disk-usage"
PASSWORD_CHANGER_PATH = "/api/v2/cmdb/secret/password-changer"
EMS_STATUS_SUMMARY_PATH = "/api/v2/monitor/endpoint-control/ems/status-summary"
CURATED_READ_PATHS = frozenset(
    {
        SYSTEM_STATUS_PATH,
        SYSTEM_GLOBAL_PATH,
        APPROVAL_PROFILE_PATH,
        FORTIANALYZER_SETTING_PATH,
        LICENSE_STATUS_PATH,
        HA_CONFIGURATION_PATH,
        RECORDING_STORAGE_PATH,
        PASSWORD_CHANGER_PATH,
        EMS_STATUS_SUMMARY_PATH,
    }
)
DEFAULT_HEALTH_PATH = SYSTEM_STATUS_PATH
CONFIG_ENV = "FORTIPAM_MCP_CONFIG"


class ConfigurationError(ValueError):
    """Raised when safe FortiPAM runtime configuration is incomplete."""


@dataclass(frozen=True, slots=True)
class Authentication:
    """Resolved Bearer authentication material held only in process memory."""

    kind: str
    token: str


@dataclass(frozen=True, slots=True)
class FortiPamConfig:
    """Non-secret and in-memory FortiPAM runtime configuration."""

    base_url: str
    health_path: str
    allowed_read_paths: frozenset[str]
    authentication: Authentication
    timeout_seconds: float
    ca_file: str | None


@dataclass(frozen=True, slots=True)
class FortiPamCliConfig:
    """Dedicated key-based SSH configuration for the fixed V2 CLI workflows."""

    target: SshCliTarget
    limits: CliExecutionLimits
    accept_pre_login_banner: bool


def normalize_api_path(path: str) -> str:
    """Validate an exact FortiPAM API path without query-like components."""

    value = path.strip()
    if (
        not value.startswith("/api/v2/")
        or "?" in value
        or "#" in value
        or "\\" in value
        or value.endswith("/")
        or any(segment in {".", ".."} for segment in value.split("/"))
    ):
        raise ConfigurationError(
            "FortiPAM paths must be exact /api/v2/ paths without query, fragment, traversal, or trailing slash."
        )
    return value


def load_config(environment: Mapping[str, str] | None = None) -> FortiPamConfig:
    """Resolve configuration without exposing any value to callers."""

    env = os.environ if environment is None else environment
    raw = _load_local_config(env, use_project_local=environment is None)
    health_path = normalize_api_path(
        _string(raw.get("health_path")) or DEFAULT_HEALTH_PATH
    )
    raw_paths = raw.get("allowed_read_paths", sorted(CURATED_READ_PATHS))
    if not isinstance(raw_paths, list) or not raw_paths:
        raise ConfigurationError("allowed_read_paths must be a non-empty JSON list")
    allowed_paths = frozenset(normalize_api_path(str(path)) for path in raw_paths)
    if allowed_paths - CURATED_READ_PATHS:
        raise ConfigurationError(
            "allowed_read_paths cannot expand the compiled FortiPAM MCP read boundary"
        )
    if health_path not in allowed_paths:
        raise ConfigurationError("allowed_read_paths must include health_path")

    token_transport = (
        _env_value(env, f"{DEVICE_PREFIX}_TOKEN_TRANSPORT")
        or _string(raw.get("token_transport"))
        or "bearer"
    ).lower()
    if token_transport != "bearer":
        raise ConfigurationError("FortiPAM MCP supports Bearer token transport only")

    return FortiPamConfig(
        base_url=_resolve_base_url(env),
        health_path=health_path,
        allowed_read_paths=allowed_paths,
        authentication=_resolve_authentication(env),
        timeout_seconds=_positive_timeout(raw.get("timeout_seconds", 15)),
        ca_file=_resolve_ca_file(env),
    )


def load_cli_config(environment: Mapping[str, str] | None = None) -> FortiPamCliConfig:
    """Resolve the dedicated CLI identity without falling back to API credentials."""

    env = os.environ if environment is None else environment
    host = _env_value(env, f"{DEVICE_PREFIX}_MCP_CLI_SSH_HOST")
    username = _env_value(env, f"{DEVICE_PREFIX}_MCP_CLI_SSH_USERNAME")
    known_hosts = _env_value(env, f"{DEVICE_PREFIX}_MCP_CLI_SSH_KNOWN_HOSTS_FILE")
    identity = _env_value(env, f"{DEVICE_PREFIX}_MCP_CLI_SSH_IDENTITY_FILE")
    if host is None or username is None or known_hosts is None or identity is None:
        raise ConfigurationError(
            "FortiPAM CLI requires a dedicated username, identity file, and pinned known_hosts file."
        )
    port_value = _env_value(env, f"{DEVICE_PREFIX}_MCP_CLI_SSH_PORT") or "22"
    timeout_value = _env_value(env, f"{DEVICE_PREFIX}_MCP_CLI_TIMEOUT_SECONDS") or "12"
    output_value = _env_value(env, f"{DEVICE_PREFIX}_MCP_CLI_MAX_OUTPUT_BYTES") or str(
        32 * 1024
    )
    banner_value = _env_value(env, f"{DEVICE_PREFIX}_MCP_CLI_ACCEPT_PRE_LOGIN_BANNER")
    try:
        port = int(port_value)
        timeout = float(timeout_value)
        max_output = int(output_value)
    except ValueError as exc:
        raise ConfigurationError("FortiPAM CLI numeric configuration is invalid.") from exc
    try:
        target = SshCliTarget(
            host=host,
            username=username,
            known_hosts_file=Path(known_hosts).expanduser(),
            identity_file=Path(identity).expanduser(),
            port=port,
        )
        limits = CliExecutionLimits(
            timeout_seconds=timeout,
            max_output_bytes=max_output,
            max_command_count=4,
        )
    except (ValueError, PermissionError) as exc:
        raise ConfigurationError("FortiPAM CLI configuration failed safety validation.") from exc
    return FortiPamCliConfig(
        target=target,
        limits=limits,
        accept_pre_login_banner=_strict_boolean(
            banner_value,
            variable=f"{DEVICE_PREFIX}_MCP_CLI_ACCEPT_PRE_LOGIN_BANNER",
        ),
    )


def configuration_presence(environment: Mapping[str, str] | None = None) -> dict[str, object]:
    """Return configuration presence flags only, never runtime values."""

    env = os.environ if environment is None else environment
    token_present = any(
        _env_value(env, f"{DEVICE_PREFIX}_{name}")
        for name in ("API_TOKEN", "ACCESS_TOKEN", "TOKEN", "API_KEY")
    )
    try:
        config = load_config() if environment is None else load_config(env)
        valid = True
        allowed_path_count = len(config.allowed_read_paths)
        system_trust_enabled = config.ca_file is None
    except ConfigurationError:
        valid = False
        allowed_path_count = 0
        system_trust_enabled = False

    try:
        cli_config = load_cli_config() if environment is None else load_cli_config(env)
        cli_valid = True
        host_key_pinning_enabled = cli_config.target.known_hosts_file.is_file()
        public_key_authentication_enabled = cli_config.target.identity_file.is_file()
    except ConfigurationError:
        cli_valid = False
        host_key_pinning_enabled = False
        public_key_authentication_enabled = False

    return {
        "device_prefix": DEVICE_PREFIX,
        "host_configured": bool(
            _env_value(env, f"{DEVICE_PREFIX}_BASE_URL")
            or _env_value(env, f"{DEVICE_PREFIX}_HOST")
        ),
        "api_token_configured": token_present,
        "configuration_valid": valid,
        "allowed_read_path_count": allowed_path_count,
        "bearer_transport_required": True,
        "tls_verification_enabled": True,
        "system_trust_enabled": system_trust_enabled,
        "custom_ca_configured": bool(_env_value(env, f"{DEVICE_PREFIX}_CA_FILE")),
        "cli_configuration_valid": cli_valid,
        "cli_dedicated_username_configured": bool(
            _env_value(env, f"{DEVICE_PREFIX}_MCP_CLI_SSH_USERNAME")
        ),
        "cli_host_key_pinning_enabled": host_key_pinning_enabled,
        "cli_public_key_authentication_enabled": public_key_authentication_enabled,
        "cli_password_authentication_enabled": False,
        "cli_pre_login_banner_acceptance_enabled": bool(
            _env_value(env, f"{DEVICE_PREFIX}_MCP_CLI_ACCEPT_PRE_LOGIN_BANNER")
            == "true"
        ),
    }


def _load_local_config(
    environment: Mapping[str, str],
    *,
    use_project_local: bool,
) -> dict[str, Any]:
    selected = _env_value(environment, CONFIG_ENV)
    if not selected and not use_project_local:
        return {}
    path = (
        Path(selected).expanduser()
        if selected
        else project_root() / "config" / "fortipam.local.json"
    )
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigurationError("FORTIPAM_MCP_CONFIG must contain valid JSON") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("FORTIPAM_MCP_CONFIG must contain a JSON object")
    return raw


def _resolve_base_url(environment: Mapping[str, str]) -> str:
    supplied = _env_value(environment, f"{DEVICE_PREFIX}_BASE_URL") or _env_value(
        environment, f"{DEVICE_PREFIX}_HOST"
    )
    if not supplied:
        raise ConfigurationError(
            f"{DEVICE_PREFIX}_HOST or {DEVICE_PREFIX}_BASE_URL is required."
        )
    candidate = supplied if "://" in supplied else f"https://{supplied}"
    parsed = urlsplit(candidate)
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("FortiPAM target contains an invalid port.") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationError(
            "FortiPAM target must be an HTTPS host without credentials, path, query, or fragment."
        )
    https_port = _env_value(environment, f"{DEVICE_PREFIX}_HTTPS_PORT")
    if parsed_port is None and https_port and https_port != "443":
        try:
            port = int(https_port)
        except ValueError as exc:
            raise ConfigurationError("FortiPAM HTTPS port must be numeric.") from exc
        if not 1 <= port <= 65535:
            raise ConfigurationError("FortiPAM HTTPS port is outside the valid range.")
        candidate = f"{candidate.rstrip('/')}:{port}"
    return candidate.rstrip("/")


def _resolve_authentication(environment: Mapping[str, str]) -> Authentication:
    requested = (_env_value(environment, f"{DEVICE_PREFIX}_AUTH_MODE") or "token").lower()
    if requested != "token":
        raise ConfigurationError("FortiPAM MCP supports token authentication only")
    token = _first_env(environment, ("API_TOKEN", "ACCESS_TOKEN", "TOKEN", "API_KEY"))
    if not token:
        raise ConfigurationError("FortiPAM MCP requires an API token")
    return Authentication(kind="bearer", token=token)


def _resolve_ca_file(environment: Mapping[str, str]) -> str | None:
    supplied = _env_value(environment, f"{DEVICE_PREFIX}_CA_FILE")
    if not supplied:
        return None
    path = Path(supplied).expanduser()
    if not path.is_file():
        raise ConfigurationError("Configured FortiPAM CA file is unavailable")
    return str(path)


def _first_env(environment: Mapping[str, str], suffixes: tuple[str, ...]) -> str | None:
    for suffix in suffixes:
        value = _env_value(environment, f"{DEVICE_PREFIX}_{suffix}")
        if value:
            return value
    return None


def _env_value(environment: Mapping[str, str], name: str) -> str | None:
    value = environment.get(name)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _string(value: object) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    return None


def _strict_boolean(value: str | None, *, variable: str) -> bool:
    """Parse an opt-in safety flag without accepting truthy aliases."""

    if value is None:
        return False
    if value == "true":
        return True
    if value == "false":
        return False
    raise ConfigurationError(f"{variable} must be exactly true or false.")


def _positive_timeout(value: object) -> float:
    try:
        timeout = float(str(value))
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("timeout_seconds must be numeric") from exc
    if not 1 <= timeout <= 60:
        raise ConfigurationError("timeout_seconds must be between 1 and 60")
    return timeout
