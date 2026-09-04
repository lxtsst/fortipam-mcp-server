#!/usr/bin/env python3
"""Accept the separate V1.7 EMS API identity without disclosing values."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import json
import os
from pathlib import Path
import sys

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
from fortipam_mcp.least_privilege import evaluate_live_authorization_v17
from fortipam_mcp.read_only import FortiPamReadOnlyTools
from fortipam_mcp.posture_contracts import (
    PostureContractError,
    validate_ems_connection_posture,
)
from fortipam_mcp.rest import FortiPamRequestError
from scripts.accept_least_privilege_identity import (
    IdentityAcceptanceError,
    _accepted_live_result,
    _assert_complete_aggregate,
    _configure_safe_logging,
    _negative_status_codes,
)
V17_NEGATIVE_READ_PATHS = (
    "/api/v2/cmdb/user/group",
    "/api/v2/cmdb/router/static",
    "/api/v2/cmdb/authentication/rule",
    "/api/v2/cmdb/vpn.ssl.web/realm",
    "/api/v2/monitor/wanopt/history",
    "/api/v2/cmdb/secret/classification-tag",
    "/api/v2/cmdb/secret/client-software",
    "/api/v2/cmdb/secret/event-filter-profile",
    "/api/v2/cmdb/secret/password-policy",
    "/api/v2/cmdb/secret/dependency-updater",
    "/api/v2/cmdb/secret/launcher",
)

# This fixed observation is intentionally not a denial gate. FortiPAM 1.9.1
# exposed this collection only after the accepted top-level secfabgrp=read
# category was added. The response body is discarded, and the route is not an
# MCP tool.
V17_RESIDUAL_BROAD_READ_PATHS = (
    "/api/v2/cmdb/antivirus/profile",
)


async def run_acceptance() -> dict[str, object]:
    """Validate nine fixed reads, the seven-route aggregate, and 11 denials."""

    report = load_runtime_environment()
    config = _v17_config()
    _assert_cataloged_v17_negative_reads()
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
        tools.get_ems_connection_posture_summary,
    )
    required_status_codes: list[int] = []
    ems_contract_accepted = False
    for slot, reader in enumerate(required_readers, start=1):
        try:
            result = await reader()
        except (FortiPamRequestError, ValueError) as exc:
            raise IdentityAcceptanceError(
                f"Required V1.7 read slot {slot} did not pass authorization."
            ) from exc
        required_status_codes.append(_accepted_live_result(result, slot))
        if slot == len(required_readers):
            _assert_ems_projection(result)
            ems_contract_accepted = True

    aggregate = await tools.get_overall_health_summary()
    _assert_complete_aggregate(aggregate)
    denied_status_codes = await _negative_status_codes(
        config, V17_NEGATIVE_READ_PATHS
    )
    residual_status_codes = await _negative_status_codes(
        config, V17_RESIDUAL_BROAD_READ_PATHS
    )
    authorization = evaluate_live_authorization_v17(
        tuple(required_status_codes), tuple(denied_status_codes)
    )
    if authorization["candidate_operationally_accepted"] is not True:
        raise IdentityAcceptanceError(
            "The V1.7 identity failed its bounded authorization matrix: "
            + json.dumps(
                {
                    "authorization": authorization,
                    "negative_status_codes_by_slot": denied_status_codes,
                },
                sort_keys=True,
            )
        )
    return {
        "acceptance_version": "1.7",
        "credential_source_loaded": report.loaded,
        "tls_verification_enabled": True,
        "environment_proxy_used": False,
        "redirects_followed": False,
        "aggregate_evidence_complete": True,
        "ems_contract_accepted": ems_contract_accepted,
        "security_fabric_broad_read_residual_risk_present": True,
        "security_fabric_residual_read_probe_count": len(
            residual_status_codes
        ),
        "security_fabric_residual_read_success_count": sum(
            200 <= status_code < 300 for status_code in residual_status_codes
        ),
        "security_fabric_residual_response_bodies_returned": False,
        "authorization": authorization,
        "credential_values_returned": False,
        "response_bodies_returned": False,
    }


def _v17_config() -> FortiPamConfig:
    candidate_token = os.environ.get(f"{DEVICE_PREFIX}_MCP_V17_API_TOKEN")
    if not candidate_token:
        raise ConfigurationError("The V1.7 MCP API token is not configured.")
    environment = dict(os.environ)
    for suffix in (
        "ACCESS_TOKEN",
        "TOKEN",
        "API_KEY",
        "MCP_API_TOKEN",
        "MCP_V16_API_TOKEN",
    ):
        environment.pop(f"{DEVICE_PREFIX}_{suffix}", None)
    environment[f"{DEVICE_PREFIX}_API_TOKEN"] = candidate_token
    return load_config(environment)


def _assert_ems_projection(result: object) -> None:
    if not isinstance(result, dict) or not isinstance(result.get("posture"), dict):
        raise IdentityAcceptanceError("The EMS projection is unavailable.")
    posture = result["posture"]
    try:
        validate_ems_connection_posture(posture)
    except PostureContractError as exc:
        raise IdentityAcceptanceError("The EMS projection contract is invalid.") from exc


def _assert_cataloged_v17_negative_reads() -> None:
    catalog = RuntimeCatalog.load()
    if any(
        catalog.find("GET", path) is None for path in V17_NEGATIVE_READ_PATHS
    ):
        raise IdentityAcceptanceError(
            "A fixed V1.7 negative-read contract is absent from the catalog."
        )
    if any(
        catalog.find("GET", path) is None
        for path in V17_RESIDUAL_BROAD_READ_PATHS
    ):
        raise IdentityAcceptanceError(
            "A fixed V1.7 residual-read observation is absent from the catalog."
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
