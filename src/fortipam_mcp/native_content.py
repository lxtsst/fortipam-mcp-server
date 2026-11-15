"""Sanitized MCP Resources and Prompts for bounded FortiPAM investigation.

These MCP-native primitives are intentionally offline metadata and workflow
guidance.  They do not load runtime settings, contact FortiPAM, or introduce a
new execution surface.  Prompts may name existing Tools, but they cannot alter
their schemas, permissions, or compiled allowlists.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from .capabilities import get_capability_matrix
from .scenario_catalog import ScenarioCatalog

NATIVE_CONTENT_SCHEMA_VERSION = "2.1"
NATIVE_RESOURCE_PREFIX = "fortipam://v2.1"
DIAGNOSTIC_CONTENT_SCHEMA_VERSION = "2.3"
DIAGNOSTIC_RESOURCE_PREFIX = "fortipam://v2.3"
V4_CONTENT_SCHEMA_VERSION = "4.0-beta.7"
V4_RESOURCE_PREFIX = "fortipam://v4"
PROMPT_DETAIL_LEVELS = frozenset({"standard", "incident"})


@dataclass(frozen=True, slots=True)
class WorkflowPrompt:
    """A fixed advisory workflow that can only refer to existing Tools."""

    name: str
    title: str
    description: str
    objective: str
    allowed_tools: tuple[str, ...]
    non_assessments: tuple[str, ...]


_WORKFLOW_PROMPTS = (
    WorkflowPrompt(
        name="fortipam_overall_health_triage",
        title="FortiPAM overall health triage",
        description="Build a bounded overall-health evidence plan using existing read-only Tools.",
        objective="Assess evidence completeness before making any health conclusion.",
        allowed_tools=(
            "get_overall_health_summary",
            "get_system_status_summary",
            "get_license_support_posture_summary",
        ),
        non_assessments=("No comprehensive appliance-health or remediation claim.",),
    ),
    WorkflowPrompt(
        name="fortipam_access_session_triage",
        title="FortiPAM access and session triage",
        description="Structure read-only investigation of access and session symptoms.",
        objective="Separate available configuration evidence from unavailable session evidence.",
        allowed_tools=(
            "get_system_global_summary",
            "get_approval_profile_summary",
            "get_operational_scenario",
        ),
        non_assessments=(
            "No session launch, checkout, checkin, recording, credential, or user-identity access.",
        ),
    ),
    WorkflowPrompt(
        name="fortipam_password_lifecycle_triage",
        title="FortiPAM password lifecycle triage",
        description="Structure read-only password-lifecycle configuration investigation.",
        objective="Distinguish configuration posture from password rotation or verification evidence.",
        allowed_tools=(
            "get_password_changer_configuration_posture_summary",
            "get_operational_scenario",
        ),
        non_assessments=(
            "No secret retrieval, password verification, password change, or job execution.",
        ),
    ),
    WorkflowPrompt(
        name="fortipam_faz_delivery_triage",
        title="FortiAnalyzer delivery triage",
        description="Structure read-only FortiAnalyzer delivery-posture investigation.",
        objective="Evaluate FortiPAM-side delivery posture and identify separate evidence owners.",
        allowed_tools=(
            "get_fortianalyzer_delivery_posture_summary",
            "get_operational_scenario",
        ),
        non_assessments=(
            "No FortiAnalyzer query, configuration change, or end-to-end delivery proof.",
        ),
    ),
    WorkflowPrompt(
        name="fortipam_ems_connection_triage",
        title="EMS connection triage",
        description="Structure read-only EMS connection-posture investigation.",
        objective="Assess aggregate FortiPAM-side connection posture without inferring endpoint state.",
        allowed_tools=(
            "get_ems_connection_posture_summary",
            "get_operational_scenario",
        ),
        non_assessments=(
            "No EMS-side authorization, endpoint posture, tag synchronization, or Secret launch proof.",
        ),
    ),
    WorkflowPrompt(
        name="fortipam_ha_diagnostics_triage",
        title="FortiPAM HA diagnostics triage",
        description="Structure bounded HA configuration and diagnostics investigation.",
        objective="Correlate categorical HA evidence while preserving the fixed CLI boundary.",
        allowed_tools=(
            "get_ha_configuration_posture_summary",
            "get_ems_connection_posture_summary",
            "get_cli_ha_configuration_summary",
            "get_cli_ha_status_summary",
            "get_cli_ha_checksum_summary",
        ),
        non_assessments=(
            "No generic SSH, shell, command selection, HA synchronization, or configuration change.",
        ),
    ),
    WorkflowPrompt(
        name="fortipam_baseline_drift_triage",
        title="FortiPAM HA baseline and drift triage",
        description=(
            "Structure HTTP-OAuth-only HA baseline, drift, and fixed API/CLI "
            "correlation without changing the appliance."
        ),
        objective=(
            "Separate immutable local expectations, current categorized posture, "
            "and cross-source agreement before any remediation decision."
        ),
        allowed_tools=(
            "create_ha_diagnostic_baseline",
            "compare_ha_diagnostic_baseline",
            "correlate_ha_api_cli_posture",
            "get_ha_configuration_posture_summary",
            "get_ems_connection_posture_summary",
        ),
        non_assessments=(
            "No device write, baseline overwrite, raw drift detail, causality claim, "
            "HA synchronization, EMS tag read, or automatic remediation.",
        ),
    ),
)


def _resource_envelope(
    kind: str,
    payload: dict[str, object],
    *,
    schema_version: str = NATIVE_CONTENT_SCHEMA_VERSION,
) -> str:
    """Serialize deterministic, client-neutral resource content."""

    return json.dumps(
        {
            "schema_version": schema_version,
            "resource_kind": kind,
            "client_parameters_accepted": False,
            "network_call_executed": False,
            "live_call_permitted": False,
            "payload": payload,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


class FortiPamNativeContent:
    """Build static MCP-native content from packaged, sanitized metadata only."""

    def __init__(self, scenario_catalog: ScenarioCatalog) -> None:
        self._scenario_catalog = scenario_catalog

    def capabilities_resource(self) -> str:
        """Return reviewed capability metadata without device access."""

        return _resource_envelope("capabilities", get_capability_matrix())

    def scenarios_resource(self) -> str:
        """Return advisory scenario summaries without source locators or device access."""

        return _resource_envelope(
            "scenarios",
            {
                "product": self._scenario_catalog.product,
                "knowledge_version": self._scenario_catalog.knowledge_version,
                "scenario_count": len(self._scenario_catalog.scenarios),
                "scenarios": [
                    scenario.summary() for scenario in self._scenario_catalog.scenarios
                ],
                "advisory_only": True,
            },
        )

    def sources_resource(self) -> str:
        """Return bounded source provenance without filesystem or external locators."""

        return _resource_envelope(
            "sources",
            {
                "product": self._scenario_catalog.product,
                "knowledge_version": self._scenario_catalog.knowledge_version,
                "sources": [source.summary() for source in self._scenario_catalog.sources],
                "source_locators_disclosed": False,
            },
        )

    def safety_boundaries_resource(self) -> str:
        """Return the stable non-expansion contract for client use."""

        return _resource_envelope(
            "safety_boundaries",
            {
                "read_only": True,
                "generic_rest_supported": False,
                "generic_ssh_supported": False,
                "generic_shell_supported": False,
                "caller_controlled_cli_supported": False,
                "credential_loading_required": False,
                "raw_device_output_returned": False,
                "prompts_expand_tool_permissions": False,
                "scenario_candidates_authorize_execution": False,
            },
        )

    def diagnostic_contracts_resource(self) -> str:
        """Return the closed V2.3 diagnostic surface and authority boundary."""

        return _resource_envelope(
            "diagnostic_contracts",
            {
                "data_class": "C1",
                "profiles": [
                    {
                        "profile_id": "ha_api_posture_v1",
                        "operations": ["create", "compare"],
                        "input": "constrained_local_baseline_id",
                        "output_states": [
                            "created",
                            "unchanged",
                            "changed",
                            "stale",
                            "contradictory",
                            "not_assessed",
                        ],
                    },
                    {
                        "profile_id": "ha_api_cli_v1",
                        "operations": ["correlate"],
                        "input": "none",
                        "output_states": [
                            "operationally_consistent",
                            "contradictory",
                            "not_assessed",
                        ],
                    },
                ],
                "http_oauth_scope": "fortipam:diagnostic",
                "stdio_supported": False,
                "static_bearer_supported": False,
                "device_write_enabled": False,
                "local_immutable_state_write": True,
                "raw_values_returned": False,
                "automatic_remediation_enabled": False,
            },
            schema_version=DIAGNOSTIC_CONTENT_SCHEMA_VERSION,
        )

    def v4_plan_contracts_resource(self) -> str:
        """Return the isolated V4 plan-only exposure and denial boundaries."""

        return _resource_envelope(
            "v4_plan_contracts",
            {
                "runtime_profile": "v4-plan-only",
                "http_oauth_scope": "fortipam:plan",
                "stdio_supported": False,
                "static_bearer_supported": False,
                "tool_names": [
                    "preview_v4_administrative_intent",
                    "confirm_v4_administrative_intent",
                    "prepare_v4_non_executable_plan",
                    "get_v4_plan_status",
                ],
                "scheme_draft_input": "server_issued_opaque_reference",
                "model_text_is_confirmation": False,
                "host_services_required_for_transitions": True,
                "status_available_without_host_services": True,
                "device_access": False,
                "product_write_enabled": False,
                "executor_packaged": False,
                "product_adapter_packaged": False,
            },
            schema_version=V4_CONTENT_SCHEMA_VERSION,
        )


def render_workflow_prompt(name: str, detail_level: object = "standard") -> str:
    """Render one fixed workflow after strict enum-only argument validation."""

    if type(detail_level) is not str or detail_level not in PROMPT_DETAIL_LEVELS:
        raise ValueError("detail_level must be exactly one of: incident, standard.")
    workflow = next((item for item in _WORKFLOW_PROMPTS if item.name == name), None)
    if workflow is None:
        raise ValueError("Unknown FortiPAM workflow prompt.")

    level_guidance = (
        "Prioritize evidence completeness and safe escalation boundaries."
        if detail_level == "standard"
        else "Prioritize known/unavailable evidence separation and owner handoff."
    )
    tools = ", ".join(workflow.allowed_tools)
    non_assessments = " ".join(workflow.non_assessments)
    return (
        f"FortiPAM workflow: {workflow.title}\n"
        f"Objective: {workflow.objective}\n"
        f"Detail level: {detail_level}. {level_guidance}\n"
        f"Permitted existing Tools to consider: {tools}.\n"
        "Use only registered Tools with their existing schemas. Do not invent a Tool, "
        "endpoint, command, parameter, credential, or write action. Treat unavailable "
        "evidence as unavailable; do not infer live acceptance from this prompt.\n"
        f"Non-assessments: {non_assessments}"
    )


def register_native_content(mcp_server: Any, native_content: FortiPamNativeContent) -> None:
    """Register fixed MCP Resources and Prompts without registering a Tool."""

    resources: tuple[tuple[str, str, str, Callable[[], str]], ...] = (
        (
            f"{NATIVE_RESOURCE_PREFIX}/capabilities",
            "FortiPAM v2.1 capabilities",
            "Sanitized, versioned capability metadata; offline and client-neutral.",
            native_content.capabilities_resource,
        ),
        (
            f"{NATIVE_RESOURCE_PREFIX}/scenarios",
            "FortiPAM v2.1 scenarios",
            "Sanitized advisory scenario summaries; offline and client-neutral.",
            native_content.scenarios_resource,
        ),
        (
            f"{NATIVE_RESOURCE_PREFIX}/sources",
            "FortiPAM v2.1 source boundaries",
            "Sanitized source provenance without external or filesystem locators.",
            native_content.sources_resource,
        ),
        (
            f"{NATIVE_RESOURCE_PREFIX}/safety-boundaries",
            "FortiPAM v2.1 safety boundaries",
            "Client-neutral execution and disclosure limits for MCP-native content.",
            native_content.safety_boundaries_resource,
        ),
        (
            f"{DIAGNOSTIC_RESOURCE_PREFIX}/diagnostic-contracts",
            "FortiPAM v2.3 diagnostic contracts",
            "Closed local baseline, drift, and correlation contracts.",
            native_content.diagnostic_contracts_resource,
        ),
    )
    for uri, title, description, handler in resources:
        mcp_server.resource(
            uri,
            name=uri.rsplit("/", maxsplit=1)[-1],
            title=title,
            description=description,
            mime_type="application/json",
        )(handler)

    for workflow in _WORKFLOW_PROMPTS:
        _register_prompt(mcp_server, workflow)


def register_v4_plan_content(
    mcp_server: Any,
    native_content: FortiPamNativeContent,
) -> None:
    """Register V4-only planning metadata without expanding device authority."""

    uri = f"{V4_RESOURCE_PREFIX}/plan-contracts"
    mcp_server.resource(
        uri,
        name="plan-contracts",
        title="FortiPAM V4 plan-only contracts",
        description=(
            "OAuth scope, host-service, confirmation, and non-execution boundaries "
            "for the isolated V4 planning surface."
        ),
        mime_type="application/json",
    )(native_content.v4_plan_contracts_resource)

    @mcp_server.prompt(
        name="fortipam_v4_plan_only_workflow",
        title="FortiPAM V4 plan-only workflow",
        description=(
            "Guide a status, preview, trusted-human confirmation, and "
            "non-executable plan sequence without product mutation."
        ),
    )
    def render() -> str:
        return (
            "FortiPAM V4 plan-only workflow:\n"
            "1. Call get_v4_plan_status and stop if required host services are unbound.\n"
            "2. Use only a server-issued scheme_draft_ref with "
            "preview_v4_administrative_intent.\n"
            "3. Present the exact Current/Proposed/Expected summary to the human. "
            "Model text is not confirmation.\n"
            "4. A trusted host confirmation service may invoke "
            "confirm_v4_administrative_intent for the exact summary revision.\n"
            "5. prepare_v4_non_executable_plan may produce only a non-dispatchable plan.\n"
            "No Tool in this workflow contacts or changes FortiPAM, retrieves material, "
            "or exposes execute, apply, rollback, REST, SSH, shell, or CLI authority."
        )


def _register_prompt(mcp_server: Any, workflow: WorkflowPrompt) -> None:
    @mcp_server.prompt(
        name=workflow.name,
        title=workflow.title,
        description=workflow.description,
    )
    def render(detail_level: str = "standard") -> str:
        return render_workflow_prompt(workflow.name, detail_level)
