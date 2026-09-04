#!/usr/bin/env python3
"""Accept a separately configured FortiPAM MCP identity without disclosure."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin

import httpx

from fortipam_mcp import __version__
from fortipam_mcp.catalog import RuntimeCatalog
from fortipam_mcp.config import ConfigurationError, FortiPamConfig, load_config
from fortipam_mcp.env import (
    DEVICE_PREFIX,
    EnvironmentFileError,
    load_runtime_environment,
)
from fortipam_mcp.least_privilege import evaluate_live_authorization
from fortipam_mcp.read_only import FortiPamReadOnlyTools
from fortipam_mcp.rest import FortiPamRequestError, build_ssl_context


NEGATIVE_READ_PATHS = (
    "/api/v2/cmdb/user/group",
    "/api/v2/cmdb/router/static",
    "/api/v2/cmdb/antivirus/profile",
    "/api/v2/cmdb/vpn.ssl.web/realm",
    "/api/v2/monitor/wanopt/history",
)


class IdentityAcceptanceError(RuntimeError):
    """A non-disclosing dedicated-identity acceptance failure."""


async def run_acceptance() -> dict[str, object]:
    """Validate seven required reads, their aggregate, and five denials."""

    report = load_runtime_environment()
    config = _dedicated_config()
    _assert_cataloged_negative_reads()
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
    )
    required_status_codes: list[int] = []
    for slot, reader in enumerate(required_readers, start=1):
        try:
            result = await reader()
        except FortiPamRequestError as exc:
            raise IdentityAcceptanceError(
                f"Required read slot {slot} did not pass authorization."
            ) from exc
        required_status_codes.append(_accepted_live_result(result, slot))

    aggregate = await tools.get_overall_health_summary()
    _assert_complete_aggregate(aggregate)
    denied_status_codes = await _negative_status_codes(config)
    authorization = evaluate_live_authorization(
        tuple(required_status_codes), tuple(denied_status_codes)
    )
    if authorization["candidate_operationally_accepted"] is not True:
        raise IdentityAcceptanceError(
            "The dedicated identity failed its bounded authorization matrix: "
            + json.dumps(
                {
                    "authorization": authorization,
                    "negative_status_codes_by_slot": denied_status_codes,
                },
                sort_keys=True,
            )
        )
    return {
        "acceptance_version": "1.0",
        "credential_source_loaded": report.loaded,
        "tls_verification_enabled": True,
        "environment_proxy_used": False,
        "redirects_followed": False,
        "aggregate_evidence_complete": True,
        "authorization": authorization,
        "credential_values_returned": False,
        "response_bodies_returned": False,
    }


def _dedicated_config() -> FortiPamConfig:
    candidate_token = os.environ.get(f"{DEVICE_PREFIX}_MCP_API_TOKEN")
    if not candidate_token:
        raise ConfigurationError("The dedicated MCP API token is not configured.")
    environment = dict(os.environ)
    for suffix in ("ACCESS_TOKEN", "TOKEN", "API_KEY"):
        environment.pop(f"{DEVICE_PREFIX}_{suffix}", None)
    environment[f"{DEVICE_PREFIX}_API_TOKEN"] = candidate_token
    return load_config(environment)


def _accepted_live_result(result: object, slot: int) -> int:
    if not isinstance(result, dict):
        raise IdentityAcceptanceError(
            f"Required read slot {slot} returned an invalid projection."
        )
    status_code = result.get("status_code")
    if (
        not isinstance(status_code, int)
        or not 200 <= status_code < 300
        or result.get("response_body_returned") is not False
    ):
        raise IdentityAcceptanceError(
            f"Required read slot {slot} failed its minimized projection contract."
        )
    return status_code


def _assert_complete_aggregate(result: object) -> None:
    if not isinstance(result, dict) or result.get("response_body_returned") is not False:
        raise IdentityAcceptanceError("Aggregate output contract is invalid.")
    posture = result.get("posture")
    if not isinstance(posture, dict):
        raise IdentityAcceptanceError("Aggregate posture is unavailable.")
    if (
        posture.get("evidence_completeness") != "complete"
        or posture.get("completed_reads") != 7
        or posture.get("failed_reads") != 0
        or posture.get("fixed_route_count") != 7
    ):
        raise IdentityAcceptanceError("Aggregate evidence is incomplete.")
    for flag in (
        "response_body_returned",
        "raw_component_results_returned",
        "component_error_details_returned",
        "identity_values_returned",
        "network_values_returned",
        "exact_time_values_returned",
        "exact_capacity_values_returned",
    ):
        if posture.get(flag) is not False:
            raise IdentityAcceptanceError(
                "Aggregate non-disclosure contract is invalid."
            )


async def _negative_status_codes(
    config: FortiPamConfig,
    paths: tuple[str, ...] = NEGATIVE_READ_PATHS,
) -> list[int]:
    async with httpx.AsyncClient(
        verify=build_ssl_context(config),
        timeout=config.timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        statuses: list[int] = []
        for path in paths:
            url = urljoin(f"{config.base_url}/", path.lstrip("/"))
            try:
                async with client.stream(
                    "GET",
                    url,
                    headers={
                        "Accept": "application/json",
                        "Authorization": (
                            f"Bearer {config.authentication.token}"
                        ),
                        "User-Agent": (
                            "fortipam-mcp-identity-acceptance/"
                            f"{__version__}"
                        ),
                    },
                ) as response:
                    statuses.append(response.status_code)
            except httpx.RequestError as exc:
                raise IdentityAcceptanceError(
                    "An unrelated-route denial check could not be completed."
                ) from exc
    return statuses


def _assert_cataloged_negative_reads() -> None:
    catalog = RuntimeCatalog.load()
    if any(catalog.find("GET", path) is None for path in NEGATIVE_READ_PATHS):
        raise IdentityAcceptanceError(
            "A fixed negative-read contract is absent from the packaged catalog."
        )


def _configure_safe_logging() -> None:
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


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
