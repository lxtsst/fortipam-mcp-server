#!/usr/bin/env python3
"""Run the fixed API and CLI surface through a Streamable HTTP MCP client."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import secrets
from typing import Any
from urllib.parse import urlsplit

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from fortipam_mcp import __version__
from fortipam_mcp.env import load_prefixed_environment_file
from fortipam_mcp.http_server import HTTP_PREFIX, HttpServerSettings
from fortipam_mcp.mcp_smoke import EXPECTED_TOOLS
from fortipam_mcp.posture_contracts import (
    OVERALL_HEALTH_COMPONENTS,
    PostureContractError,
    validate_ems_connection_posture,
)
from fortipam_mcp.server import (
    CLI_TOOLS,
    DIAGNOSTIC_TOOLS,
    FIXED_ROUTE_TOOLS,
    LIVE_TOOLS,
)


DEVICE_READ_TOOLS = (
    "get_overall_health_summary",
    *FIXED_ROUTE_TOOLS,
    *CLI_TOOLS,
)
_BASELINE_RESULTS = {
    "unchanged",
    "changed",
    "stale",
    "contradictory",
    "not_assessed",
}
_CORRELATION_RESULTS = {
    "operationally_consistent",
    "contradictory",
    "not_assessed",
}


async def run_external_http_acceptance(
    url: str,
    settings_file: Path,
    ca_file: Path | None = None,
    host_header: str | None = None,
) -> dict[str, object]:
    """Call the frozen live surface and retain only sanitized acceptance facts."""

    load_prefixed_environment_file(settings_file, HTTP_PREFIX)
    settings = HttpServerSettings.from_environment()
    _validate_url(url, settings.path)
    if settings.auth_mode != "bearer" or settings.bearer_token is None:
        raise ValueError("This lab acceptance command requires Bearer mode.")

    return await run_external_http_acceptance_with_token(
        url,
        settings.bearer_token,
        expected_path=settings.path,
        ca_file=ca_file,
        host_header=host_header,
    )


async def run_external_http_acceptance_with_token(
    url: str,
    access_token: str,
    *,
    expected_path: str,
    ca_file: Path | None = None,
    host_header: str | None = None,
    include_diagnostics: bool = False,
) -> dict[str, object]:
    """Run the fixed HTTP acceptance with an already-issued access token."""

    _validate_url(url, expected_path)
    if not access_token:
        raise ValueError("The HTTP acceptance access token is unavailable.")
    headers = {"Authorization": f"Bearer {access_token}"}
    if host_header is not None:
        headers["Host"] = host_header
    results: dict[str, object] = {}
    async with httpx2.AsyncClient(
        headers=headers,
        timeout=30.0,
        follow_redirects=False,
        trust_env=False,
        verify=str(ca_file) if ca_file is not None else True,
    ) as http_client:
        async with streamable_http_client(
            url,
            http_client=http_client,
            terminate_on_close=False,
        ) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                if initialized.server_info.version != __version__:
                    raise RuntimeError("Remote HTTP server version differs from the client release.")
                listed = await session.list_tools()
                tool_names = {tool.name for tool in listed.tools}
                if tool_names != set(EXPECTED_TOOLS):
                    raise RuntimeError("Remote HTTP server exposed an unexpected tool surface.")
                listed_by_name = {tool.name: tool for tool in listed.tools}
                for tool_name in DEVICE_READ_TOOLS:
                    _assert_strict_no_input_schema(
                        listed_by_name[tool_name].input_schema,
                        tool_name,
                    )
                for tool_name in DIAGNOSTIC_TOOLS:
                    _assert_strict_diagnostic_schema(
                        listed_by_name[tool_name].input_schema,
                        tool_name,
                    )
                for tool_name in FIXED_ROUTE_TOOLS:
                    result = await session.call_tool(tool_name, {})
                    if result.is_error:
                        raise RuntimeError(
                            f"Remote HTTP MCP acceptance tool failed: {tool_name}"
                        )
                    if tool_name == "get_password_changer_configuration_posture_summary":
                        results[tool_name] = _safe_password_changer_result(
                            result.structured_content
                        )
                    elif tool_name == "get_ems_connection_posture_summary":
                        results[tool_name] = _safe_ems_result(
                            result.structured_content
                        )
                    else:
                        results[tool_name] = _safe_result(result.structured_content)
                aggregate = await session.call_tool("get_overall_health_summary", {})
                if aggregate.is_error:
                    raise RuntimeError(
                        "Remote HTTP MCP acceptance tool failed: "
                        "get_overall_health_summary"
                    )
                results["get_overall_health_summary"] = _safe_aggregate_result(
                    aggregate.structured_content
                )
                for tool_name in CLI_TOOLS:
                    cli_result = await session.call_tool(tool_name, {})
                    if cli_result.is_error:
                        raise RuntimeError(
                            f"Remote HTTP MCP acceptance tool failed: {tool_name}"
                        )
                    results[tool_name] = _safe_cli_result(
                        tool_name,
                        cli_result.structured_content,
                    )
                if include_diagnostics:
                    baseline_id = f"acceptance-{secrets.token_hex(8)}"
                    created = await session.call_tool(
                        "create_ha_diagnostic_baseline",
                        {"baseline_id": baseline_id},
                    )
                    compared = await session.call_tool(
                        "compare_ha_diagnostic_baseline",
                        {"baseline_id": baseline_id},
                    )
                    correlated = await session.call_tool(
                        "correlate_ha_api_cli_posture",
                        {},
                    )
                    for tool_name, result, accepted in (
                        (
                            "create_ha_diagnostic_baseline",
                            created,
                            {"created"},
                        ),
                        (
                            "compare_ha_diagnostic_baseline",
                            compared,
                            _BASELINE_RESULTS,
                        ),
                        (
                            "correlate_ha_api_cli_posture",
                            correlated,
                            _CORRELATION_RESULTS,
                        ),
                    ):
                        if result.is_error:
                            raise RuntimeError(
                                "Remote HTTP MCP diagnostic acceptance failed: "
                                f"{tool_name}"
                            )
                        results[tool_name] = _safe_diagnostic_result(
                            result.structured_content,
                            accepted,
                        )
                for tool_name in DEVICE_READ_TOOLS:
                    denied = await session.call_tool(
                        tool_name,
                        {"path": "/not-authorized-negative-test"},
                    )
                    if not denied.is_error:
                        raise RuntimeError(
                            f"Remote HTTP MCP tool accepted unknown input: {tool_name}"
                        )
                if include_diagnostics:
                    for tool_name in DIAGNOSTIC_TOOLS:
                        arguments: dict[str, object] = {
                            "path": "/not-authorized-negative-test"
                        }
                        if tool_name != "correlate_ha_api_cli_posture":
                            arguments["baseline_id"] = "acceptance-schema"
                        denied = await session.call_tool(tool_name, arguments)
                        if not denied.is_error:
                            raise RuntimeError(
                                "Remote HTTP MCP diagnostic accepted unknown input: "
                                f"{tool_name}"
                            )

    return {
        "transport": "MCP Streamable HTTP",
        "protocol_version": initialized.protocol_version,
        "server_version": initialized.server_info.version,
        "tool_count": len(tool_names),
        "device_read_only": True,
        "local_diagnostic_state_written": include_diagnostics,
        "raw_response_bodies_returned": False,
        "strict_live_tool_input_schemas": True,
        "unknown_live_tool_inputs_rejected": len(DEVICE_READ_TOOLS)
        + (len(DIAGNOSTIC_TOOLS) if include_diagnostics else 0),
        "tools": results,
    }


def _validate_url(url: str, expected_path: str) -> None:
    parsed = urlsplit(url)
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("The MCP acceptance URL is invalid.")
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError("The MCP acceptance URL must use HTTPS or loopback HTTP.")
    if parsed.path != expected_path or parsed.query or parsed.fragment:
        raise ValueError("The MCP acceptance URL does not match the configured path.")


def _safe_result(value: Any) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("Remote HTTP MCP tool did not return structured output.")
    status_code = value.get("status_code")
    body_returned = value.get("response_body_returned")
    if status_code != 200 or body_returned is not False:
        raise RuntimeError("Remote HTTP MCP tool failed its minimized response contract.")
    return {"status_code": 200, "response_body_returned": False}


def _safe_password_changer_result(value: Any) -> dict[str, object]:
    """Validate the high-sensitivity changer projection without retaining values."""

    if (
        not isinstance(value, dict)
        or value.get("status_code") != 200
        or value.get("response_body_returned") is not False
    ):
        raise RuntimeError(
            "Remote password-changer tool failed its minimized response contract."
        )
    posture = value.get("posture")
    if not isinstance(posture, dict):
        raise RuntimeError("Remote password-changer posture is unavailable.")
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
        raise RuntimeError("Remote password-changer posture contract is invalid.")
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
            raise RuntimeError(
                "Remote password-changer non-disclosure contract failed."
            )
    return {
        "status_code": 200,
        "response_body_returned": False,
        "contract": "fortipam_password_changer_configuration_posture_v1",
        "changer_inventory_state": inventory_state,
        "changer_count_band": count_band,
        "fortios_7_6_3_documented_label_observed": label_observed,
        "label_observation": label_observation,
        "target_compatibility_assessed": False,
        "job_health_assessed": False,
    }


def _safe_ems_result(value: Any) -> dict[str, object]:
    """Validate the EMS aggregate projection without retaining private values."""

    if (
        not isinstance(value, dict)
        or value.get("status_code") != 200
        or value.get("response_body_returned") is not False
    ):
        raise RuntimeError("Remote EMS tool failed its minimized response contract.")
    posture = value.get("posture")
    if not isinstance(posture, dict):
        raise RuntimeError("Remote EMS posture is unavailable.")
    try:
        validate_ems_connection_posture(posture)
    except PostureContractError as exc:
        raise RuntimeError("Remote EMS posture contract is invalid.") from exc
    inventory_state = posture.get("connector_inventory_state")
    count_band = posture.get("connector_count_band")
    connection_state = posture.get("aggregate_connection_state")
    certificate_state = posture.get("aggregate_certificate_state")
    risk_signal = posture.get("risk_signal")
    return {
        "status_code": 200,
        "response_body_returned": False,
        "contract": "fortipam_ems_connection_posture_v1",
        "connector_inventory_state": inventory_state,
        "connector_count_band": count_band,
        "connection_evidence_completeness": "complete",
        "aggregate_connection_state": connection_state,
        "aggregate_certificate_state": certificate_state,
        "risk_signal": risk_signal,
        "ztna_tag_assignment_assessed": False,
        "proxy_policy_assessed": False,
        "endpoint_posture_assessed": False,
        "secret_launch_assessed": False,
    }


def _safe_aggregate_result(value: Any) -> dict[str, object]:
    """Validate aggregate evidence and retain no component or private values."""

    if not isinstance(value, dict) or value.get("response_body_returned") is not False:
        raise RuntimeError("Remote HTTP aggregate failed its minimized response contract.")
    posture = value.get("posture")
    if not isinstance(posture, dict):
        raise RuntimeError("Remote HTTP aggregate omitted its posture contract.")

    components = posture.get("components")
    if not isinstance(components, dict) or set(components) != set(
        OVERALL_HEALTH_COMPONENTS
    ):
        raise RuntimeError("Remote HTTP aggregate component evidence is incomplete.")
    allowed_component_risks = {
        "critical",
        "warning",
        "none_observed",
        "unknown",
        "not_assessed",
        "not_enabled",
        "not_applicable",
    }
    for component in components.values():
        if (
            not isinstance(component, dict)
            or component.get("evidence_state") != "observed"
            or component.get("risk_signal") not in allowed_component_risks
        ):
            raise RuntimeError("Remote HTTP aggregate component evidence is invalid.")

    if (
        posture.get("contract") != "fortipam_overall_health_posture_v1"
        or posture.get("evidence_completeness") != "complete"
        or posture.get("risk_signal")
        not in {"critical", "warning", "none_observed", "unknown"}
        or posture.get("completed_reads") != len(OVERALL_HEALTH_COMPONENTS)
        or posture.get("failed_reads") != 0
        or posture.get("fixed_route_count") != len(OVERALL_HEALTH_COMPONENTS)
    ):
        raise RuntimeError("Remote HTTP aggregate evidence contract is invalid.")
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
            raise RuntimeError("Remote HTTP aggregate non-disclosure contract failed.")

    return {
        "evidence_completeness": "complete",
        "risk_signal": posture["risk_signal"],
        "completed_reads": len(OVERALL_HEALTH_COMPONENTS),
        "failed_reads": 0,
        "fixed_route_count": len(OVERALL_HEALTH_COMPONENTS),
        "response_body_returned": False,
        "raw_component_results_returned": False,
        "component_error_details_returned": False,
    }


def _safe_cli_result(tool_name: str, value: Any) -> dict[str, object]:
    """Validate one fixed CLI projection and retain only categorical facts."""

    workflow_by_tool = {
        "get_cli_ha_configuration_summary": "ha_configuration",
        "get_cli_ha_status_summary": "ha_status",
        "get_cli_ha_checksum_summary": "ha_checksum",
    }
    workflow_id = workflow_by_tool.get(tool_name)
    if workflow_id is None:
        raise RuntimeError("Remote CLI acceptance tool is outside the fixed set.")
    if not isinstance(value, dict) or set(value) != {
        "workflow_id",
        "execution_status",
        "evidence",
        "raw_cli_returned",
        "credential_values_returned",
    }:
        raise RuntimeError("Remote CLI tool returned an invalid wrapper contract.")
    if (
        value.get("workflow_id") != workflow_id
        or value.get("execution_status") != "completed"
        or value.get("raw_cli_returned") is not False
        or value.get("credential_values_returned") is not False
    ):
        status = value.get("execution_status")
        safe_status = status if isinstance(status, str) else "invalid"
        raise RuntimeError(
            f"Remote CLI tool {tool_name} failed its execution contract: "
            f"{safe_status}."
        )
    evidence = value.get("evidence")
    if not isinstance(evidence, dict):
        raise RuntimeError("Remote CLI tool omitted its evidence contract.")

    if tool_name == "get_cli_ha_configuration_summary":
        _validate_cli_ha_configuration_evidence(evidence)
    elif tool_name == "get_cli_ha_status_summary":
        _validate_cli_ha_evidence(evidence)
    else:
        _validate_cli_checksum_evidence(evidence)
    return {
        "workflow_id": workflow_id,
        "execution_status": "completed",
        "evidence_status": evidence["evidence_status"],
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }


def _validate_cli_ha_configuration_evidence(evidence: dict[str, Any]) -> None:
    if set(evidence) != {
        "evidence_status",
        "ha_mode",
        "session_pickup",
        "override_state",
        "configuration_security",
        "identity_values_returned",
        "network_values_returned",
        "group_name_returned",
        "password_values_returned",
        "priority_values_returned",
        "exact_checksum_returned",
        "raw_cli_returned",
    }:
        raise RuntimeError("Remote CLI HA-configuration evidence schema is invalid.")
    if (
        evidence.get("evidence_status") not in {"complete", "partial"}
        or evidence.get("ha_mode")
        not in {"standalone", "active_passive", "active_active", "unknown"}
        or evidence.get("session_pickup") not in {"enabled", "disabled", "unknown"}
        or evidence.get("override_state") not in {"enabled", "disabled", "unknown"}
        or evidence.get("configuration_security")
        not in {"enabled", "disabled", "mixed", "unknown"}
        or any(
            evidence.get(flag) is not False
            for flag in (
                "identity_values_returned",
                "network_values_returned",
                "group_name_returned",
                "password_values_returned",
                "priority_values_returned",
                "exact_checksum_returned",
                "raw_cli_returned",
            )
        )
    ):
        raise RuntimeError("Remote CLI HA-configuration evidence contract is invalid.")


def _validate_cli_ha_evidence(evidence: dict[str, Any]) -> None:
    if set(evidence) != {
        "evidence_status",
        "ha_mode",
        "ha_health",
        "member_count_band",
        "configuration_sync",
        "peer_identity_returned",
        "network_values_returned",
        "exact_time_returned",
        "raw_cli_returned",
    }:
        raise RuntimeError("Remote CLI HA-status evidence schema is invalid.")
    if (
        evidence.get("evidence_status") not in {"complete", "partial"}
        or evidence.get("ha_mode")
        not in {"standalone", "active_passive", "active_active", "unknown"}
        or evidence.get("ha_health") not in {"healthy", "degraded", "unknown"}
        or evidence.get("member_count_band") not in {"single", "multiple", "unknown"}
        or evidence.get("configuration_sync")
        not in {"not_applicable", "synchronized", "out_of_sync", "mixed", "unknown"}
        or any(
            evidence.get(flag) is not False
            for flag in (
                "peer_identity_returned",
                "network_values_returned",
                "exact_time_returned",
                "raw_cli_returned",
            )
        )
    ):
        raise RuntimeError("Remote CLI HA-status evidence contract is invalid.")


def _validate_cli_checksum_evidence(evidence: dict[str, Any]) -> None:
    common_flags = (
        "exact_checksum_returned",
        "member_identity_returned",
        "table_name_returned",
        "raw_cli_returned",
    )
    if evidence.get("ha_mode") == "standalone":
        if set(evidence) != {
            "evidence_status",
            "ha_mode",
            "checksum_assessment",
            "member_count_band",
            *common_flags,
        } or (
            evidence.get("evidence_status") != "complete"
            or evidence.get("checksum_assessment") != "not_applicable"
            or evidence.get("member_count_band") != "single"
            or any(evidence.get(flag) is not False for flag in common_flags)
        ):
            raise RuntimeError("Remote CLI standalone checksum contract is invalid.")
        return

    if set(evidence) != {
        "evidence_status",
        "member_count_band",
        "global_agreement",
        "root_agreement",
        "overall_agreement",
        "mismatch_scope_count_band",
        "ha_mode",
        "checksum_assessment",
        "detail_evidence",
        *common_flags,
    }:
        raise RuntimeError("Remote CLI cluster checksum schema is invalid.")
    if (
        evidence.get("evidence_status") != "complete"
        or evidence.get("ha_mode") not in {"active_passive", "active_active"}
        or evidence.get("member_count_band") != "multiple"
        or any(
            evidence.get(field) not in {"matched", "mismatched"}
            for field in ("global_agreement", "root_agreement", "overall_agreement")
        )
        or evidence.get("mismatch_scope_count_band")
        not in {"zero", "one", "two_to_five"}
        or evidence.get("checksum_assessment") not in {"synchronized", "out_of_sync"}
        or evidence.get("detail_evidence") not in {"not_required", "collected"}
        or any(evidence.get(flag) is not False for flag in common_flags)
    ):
        raise RuntimeError("Remote CLI cluster checksum contract is invalid.")


def _assert_strict_no_input_schema(schema: object, tool_name: str) -> None:
    if not isinstance(schema, dict):
        raise RuntimeError(f"Remote HTTP MCP tool has no input schema: {tool_name}")
    if schema.get("properties") not in ({}, None):
        raise RuntimeError(f"Remote HTTP MCP live tool accepts input: {tool_name}")
    if schema.get("additionalProperties") is not False:
        raise RuntimeError(
            f"Remote HTTP MCP live tool does not reject unknown input: {tool_name}"
        )


def _assert_strict_diagnostic_schema(schema: object, tool_name: str) -> None:
    if not isinstance(schema, dict) or schema.get("additionalProperties") is not False:
        raise RuntimeError(
            f"Remote HTTP MCP diagnostic does not reject unknown input: {tool_name}"
        )
    properties = schema.get("properties")
    required = schema.get("required", [])
    if tool_name == "correlate_ha_api_cli_posture":
        if properties not in ({}, None) or required:
            raise RuntimeError(
                f"Remote HTTP MCP diagnostic schema is invalid: {tool_name}"
            )
        return
    if (
        tool_name not in {
            "create_ha_diagnostic_baseline",
            "compare_ha_diagnostic_baseline",
        }
        or not isinstance(properties, dict)
        or set(properties) != {"baseline_id"}
        or required != ["baseline_id"]
        or not isinstance(properties["baseline_id"], dict)
        or properties["baseline_id"].get("type") != "string"
    ):
        raise RuntimeError(
            f"Remote HTTP MCP diagnostic schema is invalid: {tool_name}"
        )


def _safe_diagnostic_result(
    value: Any,
    accepted_statuses: set[str],
) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != {"status"}
        or value.get("status") not in accepted_statuses
    ):
        raise RuntimeError(
            "Remote HTTP MCP diagnostic returned an invalid closed result."
        )
    return {"status": value["status"]}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Accept the fixed FortiPAM API and CLI surface over "
            "Streamable HTTP."
        )
    )
    parser.add_argument("--url", required=True)
    parser.add_argument(
        "--settings-file",
        type=Path,
        default=Path(
            os.environ.get(
                f"{HTTP_PREFIX}ENV_FILE",
                "/run/secrets/fortipam-http.env",
            )
        ),
    )
    parser.add_argument(
        "--ca-file",
        type=Path,
        help="Optional trusted PEM CA for a private TLS ingress acceptance.",
    )
    parser.add_argument(
        "--host-header",
        help="Optional Host header for direct reverse-proxy acceptance.",
    )
    args = parser.parse_args(argv)
    print(
        json.dumps(
            asyncio.run(
                run_external_http_acceptance(
                    args.url,
                    args.settings_file,
                    args.ca_file,
                    args.host_header,
                )
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
