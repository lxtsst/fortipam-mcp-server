"""Static, non-executing metadata for the FortiPAM MCP tool surface.

This registry is deliberately separate from MCP tool registration.  It can
describe the current surface and model a future allowlisted tool-pack selector,
but it cannot enable, disable, register, or dispatch any FortiPAM operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


CAPABILITY_MATRIX_SCHEMA_VERSION = "1.1"


class ToolPack(StrEnum):
    """Stable identifiers for bounded, opt-in future tool-pack configuration."""

    CORE = "core"
    KNOWLEDGE = "knowledge"
    API_DISCOVERY = "api-discovery"
    PLATFORM_READ = "platform-read"
    APPROVAL_READ = "approval-read"
    LOGGING_READ = "logging-read"
    RESILIENCE_READ = "resilience-read"
    RECORDING_READ = "recording-read"
    PASSWORD_LIFECYCLE_READ = "password-lifecycle-read"
    INTEGRATION_READ = "integration-read"
    CLI_DIAGNOSTICS = "cli-diagnostics"
    DIAGNOSTIC_STATE = "diagnostic-state"
    LAB_ADMIN = "lab-admin"


class ExecutionMode(StrEnum):
    """Whether a tool only uses local metadata, plans, or contacts FortiPAM."""

    OFFLINE = "offline"
    PLAN = "plan"
    LIVE = "live"
    LAB_SIMULATED = "lab_simulated"


class RiskLevel(StrEnum):
    """Risk of invoking the fixed-purpose MCP tool, not an API permission tier."""

    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"


class InputScope(StrEnum):
    """The caller-controlled input shape accepted by the existing tool."""

    NONE = "none"
    BOUNDED_QUERY = "bounded_query"
    EXACT_API_OPERATION = "exact_api_operation"
    EXACT_SCENARIO_ID = "exact_scenario_id"
    CONSTRAINED_BASELINE_ID = "constrained_baseline_id"
    LAB_ADMIN_PREVIEW = "lab_admin_preview"
    LAB_CONFIRMATION = "lab_confirmation"


@dataclass(frozen=True, slots=True)
class ToolPackDefinition:
    """One logical group of fixed-purpose MCP tools."""

    identifier: ToolPack
    description: str

    def annotation(self) -> dict[str, object]:
        """Return only static, non-sensitive pack metadata."""

        return {"id": self.identifier.value, "description": self.description}


@dataclass(frozen=True, slots=True)
class Capability:
    """The reviewed execution contract for one currently registered MCP tool."""

    tool_name: str
    description: str
    pack: ToolPack
    execution_mode: ExecutionMode
    risk_level: RiskLevel
    input_scope: InputScope
    supported_product_versions: tuple[str, ...]
    contacts_fortipam: bool
    local_state_write: bool = False
    idempotent: bool = True

    def __post_init__(self) -> None:
        if not self.tool_name:
            raise ValueError("Capability tool_name must not be empty.")
        if not self.description:
            raise ValueError("Capability description must not be empty.")
        if not self.supported_product_versions:
            raise ValueError("Capability must declare evidence-bound product versions.")
        if self.execution_mode is ExecutionMode.LIVE and not self.contacts_fortipam:
            raise ValueError("A live capability must contact FortiPAM.")
        if self.execution_mode is not ExecutionMode.LIVE and self.contacts_fortipam:
            raise ValueError("Offline and plan capabilities must not contact FortiPAM.")

    def annotation(self) -> dict[str, object]:
        """Return a sanitizer-friendly, deterministic tool annotation.

        The result intentionally excludes URL paths, parameter names, device
        configuration, identities, tokens, and response content. It is safe
        to expose from the reviewed ``get_capability_matrix`` MCP tool because
        that tool is no-input, offline, and covered by the V1.3 freeze.
        """

        return {
            "tool_name": self.tool_name,
            "description": self.description,
            "pack": self.pack.value,
            "execution_mode": self.execution_mode.value,
            "risk_level": self.risk_level.value,
            "input_scope": self.input_scope.value,
            "supported_product_versions": list(self.supported_product_versions),
            "contacts_fortipam": self.contacts_fortipam,
            "device_write": False,
            "local_state_write": self.local_state_write,
            "read_only": not self.local_state_write,
            "destructive": False,
            "idempotent": self.idempotent,
        }


class CapabilityRegistry:
    """Immutable registry with a pure future pack/tool selection model."""

    def __init__(
        self,
        packs: Iterable[ToolPackDefinition],
        capabilities: Iterable[Capability],
    ) -> None:
        self._packs = tuple(packs)
        self._capabilities = tuple(capabilities)
        pack_ids = {definition.identifier for definition in self._packs}
        if len(pack_ids) != len(self._packs):
            raise ValueError("Tool pack identifiers must be unique.")
        names = {capability.tool_name for capability in self._capabilities}
        if len(names) != len(self._capabilities):
            raise ValueError("Capability tool names must be unique.")
        if {capability.pack for capability in self._capabilities} - pack_ids:
            raise ValueError("Every capability must reference a registered tool pack.")

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        """Return the immutable capability sequence in deterministic order."""

        return self._capabilities

    @property
    def tool_names(self) -> tuple[str, ...]:
        """Return current tool names in their reviewed deterministic order."""

        return tuple(capability.tool_name for capability in self._capabilities)

    def select(
        self,
        *,
        enabled_packs: Iterable[ToolPack | str] | None = None,
        enabled_tools: Iterable[str] | None = None,
    ) -> tuple[Capability, ...]:
        """Purely select reviewed tools; this never alters an MCP server.

        Both selectors are allowlists.  Supplying both returns their
        intersection, preventing a named tool from bypassing a disabled pack.
        Omitting either selector means that dimension remains unrestricted.
        """

        packs = _normalize_packs(enabled_packs, self._packs)
        tools = _normalize_tools(enabled_tools, self._capabilities)
        return tuple(
            capability
            for capability in self._capabilities
            if (packs is None or capability.pack in packs)
            and (tools is None or capability.tool_name in tools)
        )

    def sanitized_matrix(
        self,
        *,
        enabled_packs: Iterable[ToolPack | str] | None = None,
        enabled_tools: Iterable[str] | None = None,
    ) -> dict[str, object]:
        """Produce static metadata for the capability-matrix MCP tool."""

        selected = self.select(
            enabled_packs=enabled_packs,
            enabled_tools=enabled_tools,
        )
        selected_pack_ids = {capability.pack for capability in selected}
        return {
            "schema_version": CAPABILITY_MATRIX_SCHEMA_VERSION,
            "current_surface_only": True,
            "network_call_executed": False,
            "fortipam_contacted": False,
            "tool_count": len(selected),
            "packs": [
                definition.annotation()
                | {
                    "tool_count": sum(
                        capability.pack is definition.identifier
                        for capability in selected
                    ),
                    "selected": definition.identifier in selected_pack_ids,
                }
                for definition in self._packs
            ],
            "tools": [capability.annotation() for capability in selected],
        }


_PACKS = (
    ToolPackDefinition(ToolPack.CORE, "Local server metadata and safe configuration presence."),
    ToolPackDefinition(ToolPack.KNOWLEDGE, "Offline operational-scenario evidence."),
    ToolPackDefinition(ToolPack.API_DISCOVERY, "Offline sanitized API catalog discovery."),
    ToolPackDefinition(ToolPack.PLATFORM_READ, "Fixed system and license posture reads."),
    ToolPackDefinition(ToolPack.APPROVAL_READ, "Fixed approval-policy posture reads and plans."),
    ToolPackDefinition(ToolPack.LOGGING_READ, "Fixed FortiAnalyzer delivery posture reads."),
    ToolPackDefinition(ToolPack.RESILIENCE_READ, "Fixed high-availability configuration posture reads."),
    ToolPackDefinition(ToolPack.RECORDING_READ, "Fixed log and recording storage posture reads."),
    ToolPackDefinition(ToolPack.PASSWORD_LIFECYCLE_READ, "Fixed password-changer configuration posture reads."),
    ToolPackDefinition(ToolPack.INTEGRATION_READ, "Fixed Fortinet integration connection-posture reads."),
    ToolPackDefinition(ToolPack.CLI_DIAGNOSTICS, "Fixed categorical CLI diagnostics over pinned SSH."),
    ToolPackDefinition(ToolPack.DIAGNOSTIC_STATE, "HTTP-OAuth-only immutable local diagnostic baselines and categorical correlation."),
    ToolPackDefinition(ToolPack.LAB_ADMIN, "In-memory V3.1 administrative workflow demonstration; never contacts FortiPAM."),
)


_CAPABILITIES = (
    Capability("get_server_info", "Return static server scope and metadata.", ToolPack.CORE, ExecutionMode.OFFLINE, RiskLevel.NONE, InputScope.NONE, ("1.9.0", "1.9.1"), False),
    Capability("health_check", "Return local process health without contacting FortiPAM.", ToolPack.CORE, ExecutionMode.OFFLINE, RiskLevel.NONE, InputScope.NONE, ("1.9.0", "1.9.1"), False),
    Capability("get_capability_matrix", "Describe reviewed Tool Packs and current tool contracts.", ToolPack.CORE, ExecutionMode.OFFLINE, RiskLevel.NONE, InputScope.NONE, ("1.9.0", "1.9.1"), False),
    Capability("fortipam_configuration_status", "Report local configuration presence without values.", ToolPack.CORE, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), False),
    Capability("get_api_catalog_status", "Return sanitized FortiPAM 1.9 catalog coverage.", ToolPack.API_DISCOVERY, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.NONE, ("1.9.0",), False),
    Capability("search_api_catalog", "Search offline sanitized API metadata.", ToolPack.API_DISCOVERY, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.BOUNDED_QUERY, ("1.9.0",), False),
    Capability("classify_api_operation", "Classify one exact catalog operation offline.", ToolPack.API_DISCOVERY, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.EXACT_API_OPERATION, ("1.9.0",), False),
    Capability("get_scenario_catalog_status", "Return advisory scenario catalog coverage.", ToolPack.KNOWLEDGE, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.NONE, ("1.9.0", "1.9.1"), False),
    Capability("search_operational_scenarios", "Search advisory operational scenarios offline.", ToolPack.KNOWLEDGE, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.BOUNDED_QUERY, ("1.9.0", "1.9.1"), False),
    Capability("get_operational_scenario", "Return one advisory evidence plan without execution.", ToolPack.KNOWLEDGE, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.EXACT_SCENARIO_ID, ("1.9.0", "1.9.1"), False),
    Capability("plan_curated_reads", "Validate all fixed live-read plans without a network call.", ToolPack.PLATFORM_READ, ExecutionMode.PLAN, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), False),
    Capability("plan_approval_profile_read", "Validate the fixed approval-profile read plan.", ToolPack.APPROVAL_READ, ExecutionMode.PLAN, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), False),
    Capability("get_overall_health_summary", "Aggregate the seven fixed reads into bounded health evidence.", ToolPack.PLATFORM_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_system_status_summary", "Return a structural summary from the fixed system-status read.", ToolPack.PLATFORM_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_system_global_summary", "Return a structural summary from the fixed system-global read.", ToolPack.PLATFORM_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_approval_profile_summary", "Return a structural summary from the fixed approval-profile read.", ToolPack.APPROVAL_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_fortianalyzer_delivery_posture_summary", "Return minimized FortiAnalyzer delivery posture.", ToolPack.LOGGING_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_license_support_posture_summary", "Return minimized license and support posture.", ToolPack.PLATFORM_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_ha_configuration_posture_summary", "Return minimized HA configuration posture.", ToolPack.RESILIENCE_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_recording_storage_health_summary", "Return minimized recording-storage health posture.", ToolPack.RECORDING_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_password_changer_configuration_posture_summary", "Return minimized password-changer configuration posture.", ToolPack.PASSWORD_LIFECYCLE_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_ems_connection_posture_summary", "Return minimized EMS connection and certificate posture.", ToolPack.INTEGRATION_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_cli_ha_configuration_summary", "Return minimized HA configuration evidence from one fixed CLI workflow.", ToolPack.CLI_DIAGNOSTICS, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_cli_ha_status_summary", "Return minimized HA state and synchronization categories from one fixed CLI workflow.", ToolPack.CLI_DIAGNOSTICS, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_cli_ha_checksum_summary", "Return minimized HA checksum agreement categories from one fixed CLI workflow.", ToolPack.CLI_DIAGNOSTICS, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("create_ha_diagnostic_baseline", "Create one immutable local HA posture baseline from a fixed API projection.", ToolPack.DIAGNOSTIC_STATE, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.CONSTRAINED_BASELINE_ID, ("1.9.1",), True, True, False),
    Capability("compare_ha_diagnostic_baseline", "Compare current fixed HA posture with one owned immutable local baseline.", ToolPack.DIAGNOSTIC_STATE, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.CONSTRAINED_BASELINE_ID, ("1.9.1",), True, True, False),
    Capability("correlate_ha_api_cli_posture", "Correlate fixed HA API and CLI evidence into a closed categorical state.", ToolPack.DIAGNOSTIC_STATE, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True, True, False),
    Capability("preview_v31_lab_public_folder", "Preview one in-memory LAB Public Folder transition.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.LOW, InputScope.LAB_ADMIN_PREVIEW, ("1.9.1",), False),
    Capability("preview_v31_lab_target", "Preview one in-memory LAB Target metadata transition.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.LOW, InputScope.LAB_ADMIN_PREVIEW, ("1.9.1",), False),
    Capability("preview_v31_lab_secret_metadata", "Preview one in-memory LAB Secret metadata transition without material.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.LOW, InputScope.LAB_ADMIN_PREVIEW, ("1.9.1",), False),
    Capability("preview_v31_lab_local_user", "Preview one in-memory LAB Local User metadata transition without a password.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.LOW, InputScope.LAB_ADMIN_PREVIEW, ("1.9.1",), False),
    Capability("preview_v31_lab_folder_access_assignment", "Preview one in-memory LAB Folder access-assignment transition.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.LOW, InputScope.LAB_ADMIN_PREVIEW, ("1.9.1",), False),
    Capability("execute_confirmed_v31_lab_operation", "Execute one exact confirmed in-memory LAB transition with verified local readback.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.MODERATE, InputScope.LAB_CONFIRMATION, ("1.9.1",), False, True),
)


DEFAULT_CAPABILITY_REGISTRY = CapabilityRegistry(_PACKS, _CAPABILITIES)


def get_capability_matrix(
    *,
    enabled_packs: Iterable[ToolPack | str] | None = None,
    enabled_tools: Iterable[str] | None = None,
) -> dict[str, object]:
    """Return static annotations without contacting FortiPAM."""

    return DEFAULT_CAPABILITY_REGISTRY.sanitized_matrix(
        enabled_packs=enabled_packs,
        enabled_tools=enabled_tools,
    )


def _normalize_packs(
    selected: Iterable[ToolPack | str] | None,
    definitions: tuple[ToolPackDefinition, ...],
) -> frozenset[ToolPack] | None:
    if selected is None:
        return None
    known = {definition.identifier for definition in definitions}
    normalized: set[ToolPack] = set()
    for item in selected:
        try:
            pack = item if isinstance(item, ToolPack) else ToolPack(item)
        except ValueError as exc:
            raise ValueError(f"Unknown tool pack: {item!r}") from exc
        if pack not in known:
            raise ValueError(f"Unregistered tool pack: {pack.value}")
        normalized.add(pack)
    return frozenset(normalized)


def _normalize_tools(
    selected: Iterable[str] | None,
    capabilities: tuple[Capability, ...],
) -> frozenset[str] | None:
    if selected is None:
        return None
    known = {capability.tool_name for capability in capabilities}
    normalized = frozenset(selected)
    unknown = normalized - known
    if unknown:
        raise ValueError(f"Unknown MCP tool(s): {', '.join(sorted(unknown))}")
    return normalized
