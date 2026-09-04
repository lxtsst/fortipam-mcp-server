from __future__ import annotations

import pytest

from fortipam_mcp.config import (
    FORTIANALYZER_SETTING_PATH,
    EMS_STATUS_SUMMARY_PATH,
    HA_CONFIGURATION_PATH,
    LICENSE_STATUS_PATH,
    PASSWORD_CHANGER_PATH,
    RECORDING_STORAGE_PATH,
    SYSTEM_GLOBAL_PATH,
    SYSTEM_STATUS_PATH,
    load_config,
)
from fortipam_mcp.rest import prepare_read
from fortipam_mcp.safety import assert_curated_read


@pytest.fixture
def config():
    return load_config(
        {
            "FPA_HOME_LAB_FPA1_HOST": "fortipam.lab.example",
            "FPA_HOME_LAB_FPA1_API_TOKEN": "unit-test-token",
        }
    )


def test_allows_only_get_for_compiled_fixed_paths(config) -> None:
    assert assert_curated_read(config, "GET", SYSTEM_STATUS_PATH) == SYSTEM_STATUS_PATH
    assert assert_curated_read(config, "GET", SYSTEM_GLOBAL_PATH) == SYSTEM_GLOBAL_PATH
    assert (
        assert_curated_read(config, "GET", FORTIANALYZER_SETTING_PATH)
        == FORTIANALYZER_SETTING_PATH
    )
    assert assert_curated_read(config, "GET", LICENSE_STATUS_PATH) == LICENSE_STATUS_PATH
    assert (
        assert_curated_read(config, "GET", HA_CONFIGURATION_PATH)
        == HA_CONFIGURATION_PATH
    )
    assert (
        assert_curated_read(config, "GET", RECORDING_STORAGE_PATH)
        == RECORDING_STORAGE_PATH
    )
    assert (
        assert_curated_read(config, "GET", PASSWORD_CHANGER_PATH)
        == PASSWORD_CHANGER_PATH
    )
    assert (
        assert_curated_read(config, "GET", EMS_STATUS_SUMMARY_PATH)
        == EMS_STATUS_SUMMARY_PATH
    )
    with pytest.raises(PermissionError):
        assert_curated_read(config, "POST", SYSTEM_STATUS_PATH)


def test_rejects_noncompiled_path_before_request_preparation(config) -> None:
    with pytest.raises(PermissionError, match="compiled"):
        prepare_read(config, "/api/v2/cmdb/system/admin")


def test_bearer_token_stays_in_internal_header(config) -> None:
    prepared = prepare_read(config, SYSTEM_STATUS_PATH)

    assert prepared.headers["Authorization"] == "Bearer unit-test-token"
    assert "unit-test-token" not in prepared.url
    assert "?" not in prepared.url
