#!/usr/bin/env python3
"""Accept the separate V1.6 Password Changer API identity safely."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
from collections.abc import Awaitable, Callable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fortipam_mcp.catalog import RuntimeCatalog
from fortipam_mcp.config import ConfigurationError, FortiPamConfig, load_config
from fortipam_mcp.env import (
    DEVICE_PREFIX,
    EnvironmentFileError,
    load_runtime_environment,
)
from fortipam_mcp.least_privilege import evaluate_live_authorization_v16
from fortipam_mcp.read_only import FortiPamReadOnlyTools
from fortipam_mcp.rest import FortiPamRequestError
from scripts.accept_least_privilege_identity import (
    IdentityAcceptanceError,
    _accepted_live_result,
    _assert_complete_aggregate,
    _configure_safe_logging,
    _negative_status_codes,
)


V16_NEGATIVE_READ_PATHS = (
    "/api/v2/cmdb/user/group",
    "/api/v2/cmdb/router/static",
    "/api/v2/cmdb/antivirus/profile",
    "/api/v2/cmdb/vpn.ssl.web/realm",
    "/api/v2/monitor/wanopt/history",
    "/api/v2/cmdb/secret/classification-tag",
    "/api/v2/cmdb/secret/client-software",
    "/api/v2/cmdb/secret/event-filter-profile",
    "/api/v2/cmdb/secret/password-policy",
    "/api/v2/cmdb/secret/dependency-updater",
    "/api/v2/cmdb/secret/launcher",
)


async def run_acceptance() -> dict[str, object]:
    """Validate eight fixed reads, the seven-route aggregate, and 11 denials."""

    report = load_runtime_environment()
    config = _v16_config()
    _assert_cataloged_v16_negative_reads()
    _configure_safe_logging()
    tools = FortiPamReadOnlyTools(config)
    required_readers: tuple[
        Callable[[], Awaitable[dict[str, object]]], ...
    ] = (
        tools.get_system_status_summary,
        tools.get_system_global_summary,
        tools.get_approval_profile_summary,
        tools.get_fortianalyzer_delivery_posture_summary,
        tools.get_license_support_posture_summary,
        tools.get_ha_configuration_posture_summary,
        tools.get_recording_storage_health_summary,
        tools.get_password_changer_configuration_posture_summary,
    )
    required_status_codes: list[int] = []
    password_changer_contract_accepted = False
    for slot, reader in enumerate(required_readers, start=1):
        try:
            result = await reader()
        except FortiPamRequestError as exc:
            raise IdentityAcceptanceError(
                f"Required V1.6 read slot {slot} did not pass authorization."
            ) from exc
        required_status_codes.append(_accepted_live_result(result, slot))
        if slot == len(required_readers):
            _assert_password_changer_projection(result)
            password_changer_contract_accepted = True

    aggregate = await tools.get_overall_health_summary()
    _assert_complete_aggregate(aggregate)
    denied_status_codes = await _negative_status_codes_for_v16(config)
    authorization = evaluate_live_authorization_v16(
        tuple(required_status_codes), tuple(denied_status_codes)
    )
    if authorization["candidate_operationally_accepted"] is not True:
        raise IdentityAcceptanceError(
            "The V1.6 identity failed its bounded authorization matrix: "
            + json.dumps(
                {
                    "authorization": authorization,
                    "negative_status_codes_by_slot": denied_status_codes,
                },
                sort_keys=True,
            )
        )
    return {
        "acceptance_version": "1.6",
        "credential_source_loaded": report.loaded,
        "tls_verification_enabled": True,
        "environment_proxy_used": False,
        "redirects_followed": False,
        "aggregate_evidence_complete": True,
        "password_changer_contract_accepted": (
            password_changer_contract_accepted
        ),
        "authorization": authorization,
        "credential_values_returned": False,
        "response_bodies_returned": False,
    }


def _v16_config() -> FortiPamConfig:
    candidate_token = os.environ.get(f"{DEVICE_PREFIX}_MCP_V16_API_TOKEN")
    if not candidate_token:
        raise ConfigurationError("The V1.6 MCP API token is not configured.")
    environment = dict(os.environ)
    for suffix in ("ACCESS_TOKEN", "TOKEN", "API_KEY", "MCP_API_TOKEN"):
        environment.pop(f"{DEVICE_PREFIX}_{suffix}", None)
    environment[f"{DEVICE_PREFIX}_API_TOKEN"] = candidate_token
    return load_config(environment)


def _assert_password_changer_projection(result: object) -> None:
    if not isinstance(result, dict):
        raise IdentityAcceptanceError(
            "The Password Changer projection is invalid."
        )
    posture = result.get("posture")
    if not isinstance(posture, dict):
        raise IdentityAcceptanceError(
            "The Password Changer posture is unavailable."
        )
    expected_keys = {
        "contract",
        "changer_inventory_state",
        "changer_count_band",
        "fortios_7_6_3_documented_label_observed",
        "label_observation",
        "observation_scope",
        "target_compatibility_assessed",
        "job_health_assessed",
        "response_body_returned",
        "name_values_returned",
        "description_values_returned",
        "procedure_values_returned",
        "authentication_mode_values_returned",
        "reference_values_returned",
        "origin_values_returned",
        "credential_values_returned",
        "raw_field_values_returned",
    }
    inventory_state = posture.get("changer_inventory_state")
    count_band = posture.get("changer_count_band")
    label_observed = posture.get(
        "fortios_7_6_3_documented_label_observed"
    )
    label_observation = posture.get("label_observation")
    if (
        set(posture) != expected_keys
        or posture.get("contract")
        != "fortipam_password_changer_configuration_posture_v1"
        or inventory_state not in {"none", "present"}
        or count_band not in {"none", "single", "multiple"}
        or type(label_observed) is not bool
        or label_observation
        not in {"documented_label_observed", "not_observed"}
        or posture.get("observation_scope") != "configuration_label_only"
        or posture.get("target_compatibility_assessed") is not False
        or posture.get("job_health_assessed") is not False
        or (inventory_state == "none") != (count_band == "none")
        or (label_observation == "documented_label_observed")
        is not label_observed
        or (inventory_state == "none" and label_observed)
    ):
        raise IdentityAcceptanceError(
            "The Password Changer posture contract is invalid."
        )
    for flag in (
        "response_body_returned",
        "name_values_returned",
        "description_values_returned",
        "procedure_values_returned",
        "authentication_mode_values_returned",
        "reference_values_returned",
        "origin_values_returned",
        "credential_values_returned",
        "raw_field_values_returned",
    ):
        if posture.get(flag) is not False:
            raise IdentityAcceptanceError(
                "The Password Changer non-disclosure contract is invalid."
            )


async def _negative_status_codes_for_v16(
    config: FortiPamConfig,
) -> list[int]:
    """Reuse the bounded HTTP denial reader with the fixed V1.6 path set."""

    return await _negative_status_codes(config, V16_NEGATIVE_READ_PATHS)


def _assert_cataloged_v16_negative_reads() -> None:
    catalog = RuntimeCatalog.load()
    if any(
        catalog.find("GET", path) is None for path in V16_NEGATIVE_READ_PATHS
    ):
        raise IdentityAcceptanceError(
            "A fixed V1.6 negative-read contract is absent from the catalog."
        )


def main() -> None:
    try:
        result = asyncio.run(run_acceptance())
    except (
        ConfigurationError,
        EnvironmentFileError,
        FortiPamRequestError,
        IdentityAcceptanceError,
    ) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
