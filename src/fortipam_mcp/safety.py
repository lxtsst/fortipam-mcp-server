"""Narrow local safety enforcement for FortiPAM read operations."""

from __future__ import annotations

from .config import (
    APPROVAL_PROFILE_PATH,
    CURATED_READ_PATHS,
    EMS_STATUS_SUMMARY_PATH,
    FORTIANALYZER_SETTING_PATH,
    HA_CONFIGURATION_PATH,
    LICENSE_STATUS_PATH,
    PASSWORD_CHANGER_PATH,
    RECORDING_STORAGE_PATH,
    FortiPamConfig,
    normalize_api_path,
    SYSTEM_GLOBAL_PATH,
    SYSTEM_STATUS_PATH,
)


def assert_curated_read(config: FortiPamConfig, method: str, path: str) -> str:
    """Allow only a compiled and enabled exact GET path or fail before dispatch."""

    if method.upper() != "GET":
        raise PermissionError("Only GET is permitted by the FortiPAM MCP safety policy.")
    normalized = normalize_api_path(path)
    if normalized not in CURATED_READ_PATHS:
        raise PermissionError("Requested path is outside the compiled FortiPAM MCP boundary.")
    if normalized not in config.allowed_read_paths:
        raise PermissionError("Requested path is disabled by FortiPAM MCP runtime policy.")
    return normalized


def assert_system_status_path(config: FortiPamConfig) -> str:
    return assert_curated_read(config, "GET", SYSTEM_STATUS_PATH)


def assert_system_global_path(config: FortiPamConfig) -> str:
    return assert_curated_read(config, "GET", SYSTEM_GLOBAL_PATH)


def assert_approval_profile_path(config: FortiPamConfig) -> str:
    return assert_curated_read(config, "GET", APPROVAL_PROFILE_PATH)


def assert_fortianalyzer_setting_path(config: FortiPamConfig) -> str:
    return assert_curated_read(config, "GET", FORTIANALYZER_SETTING_PATH)


def assert_license_status_path(config: FortiPamConfig) -> str:
    return assert_curated_read(config, "GET", LICENSE_STATUS_PATH)


def assert_ha_configuration_path(config: FortiPamConfig) -> str:
    return assert_curated_read(config, "GET", HA_CONFIGURATION_PATH)


def assert_recording_storage_path(config: FortiPamConfig) -> str:
    return assert_curated_read(config, "GET", RECORDING_STORAGE_PATH)


def assert_password_changer_path(config: FortiPamConfig) -> str:
    return assert_curated_read(config, "GET", PASSWORD_CHANGER_PATH)


def assert_ems_status_summary_path(config: FortiPamConfig) -> str:
    return assert_curated_read(config, "GET", EMS_STATUS_SUMMARY_PATH)
