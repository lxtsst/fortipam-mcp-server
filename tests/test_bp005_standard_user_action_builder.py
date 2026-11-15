from __future__ import annotations

from pathlib import Path

import pytest

from fortipam_mcp.local_user_create_live_workflow import (
    BP002_ENABLED_GUEST_WORKFLOW_CONTRACT,
    BP005_STANDARD_USER_WORKFLOW_CONTRACT,
)
from fortipam_mcp.local_user_reset_fixture_transport import FortiPamLocalUserResetFixtureTransport
from fortipam_mcp.local_user_create_mcp_action import (
    V4_LOCAL_USER_CREATE_ACTION_FEATURE_ENV,
    V4_LOCAL_USER_CREATE_ACTION_PREFIX,
    V4_LOCAL_USER_CREATE_CONTRACT_ENV,
    V4_LOCAL_USER_CREATE_EXECUTION_ENV,
    V4LocalUserCreateActionConfigurationError,
    build_v4_local_user_create_action,
)
from fortipam_mcp.bp005_standard_user_transport import FortiPamBp005StandardUserTransport
from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX as API_PREFIX


def _environment(root: Path) -> dict[str, str]:
    material = root / "credential-material"
    material.mkdir(mode=0o700)
    database = root / "execution.sqlite3"
    key = root / "execution.key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    return {
        V4_LOCAL_USER_CREATE_ACTION_FEATURE_ENV: "true",
        V4_LOCAL_USER_CREATE_EXECUTION_ENV: "false",
        V4_LOCAL_USER_CREATE_CONTRACT_ENV: "bp005-standard-enabled-v1",
        f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}BP005_USERNAME": "mcp-v4-user-bp005-standard-synthetic",
        f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}BP005_API_PRINCIPAL": "synthetic-api-principal",
        f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}BP005_MATERIAL_DIRECTORY": str(material),
        f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}BP005_EXECUTION_DATABASE": str(database),
        f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}BP005_EXECUTION_KEY_FILE": str(key),
        f"{API_PREFIX}ENABLED": "true",
        f"{API_PREFIX}BASE_URL": "https://pam.example.test:9443",
        f"{API_PREFIX}API_TOKEN": "synthetic-token",
    }


def test_builder_selects_only_the_private_fixed_bp005_variant(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    action = build_v4_local_user_create_action(environment)
    assert action._workflow._workflow_contract == BP005_STANDARD_USER_WORKFLOW_CONTRACT
    assert type(action._workflow._transport) is FortiPamBp005StandardUserTransport
    assert action._workflow._execution_store is not None
    assert action._execution_enabled is False
    assert action._workflow._transport._username == "mcp-v4-user-bp005-standard-synthetic"


@pytest.mark.parametrize("contract", ["unknown", "bp005-standard-enabled-v2", "Guest"])
def test_builder_rejects_unrecognized_or_unversioned_contract(tmp_path: Path, contract: str) -> None:
    environment = _environment(tmp_path)
    environment[V4_LOCAL_USER_CREATE_CONTRACT_ENV] = contract
    with pytest.raises(V4LocalUserCreateActionConfigurationError):
        build_v4_local_user_create_action(environment)


def test_builder_requires_a_unique_material_directory_and_durable_store(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    environment[f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}BP005_EXECUTION_DATABASE"] = environment[
        f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}BP005_MATERIAL_DIRECTORY"
    ] + "/execution.sqlite3"
    with pytest.raises(V4LocalUserCreateActionConfigurationError):
        build_v4_local_user_create_action(environment)


def test_enabled_guest_builder_requires_original_fixture_store_and_stays_closed(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    environment[V4_LOCAL_USER_CREATE_CONTRACT_ENV] = "bp002-guest-enabled-v1"
    for key in list(environment):
        if key.startswith(f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}BP005_"):
            environment[key.replace("BP005_", "BP002_")] = environment.pop(key)
    prefix = f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}BP002_"
    directory = Path(environment[f"{prefix}MATERIAL_DIRECTORY"])
    environment[f"{prefix}USERNAME"] = "mcp-v4-user-reset-1791800000-a1b2c3"
    # A store from another fixture must fail before material or a claim exists.
    with pytest.raises(V4LocalUserCreateActionConfigurationError):
        build_v4_local_user_create_action(environment)
    assert not list(directory.iterdir())
    key = directory / "execution.key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    environment[f"{prefix}EXECUTION_DATABASE"] = str(directory / "execution.sqlite3")
    environment[f"{prefix}EXECUTION_KEY_FILE"] = str(key)
    action = build_v4_local_user_create_action(environment)
    assert action._workflow._workflow_contract == BP002_ENABLED_GUEST_WORKFLOW_CONTRACT
    assert type(action._workflow._transport) is FortiPamLocalUserResetFixtureTransport
    assert action._execution_enabled is action._workflow._transport._enabled is False
    assert action._workflow._execution_store.claim_count == 0
    assert not (directory / "initial-password").exists()
    assert not (directory / "created-readback.json").exists()
