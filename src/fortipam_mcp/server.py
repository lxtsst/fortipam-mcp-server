"""STDIO MCP server entrypoint for FortiPAM."""

from __future__ import annotations

import argparse
import logging
from typing import Any, Literal, Sequence

from . import __version__
from .capabilities import ToolPack
from .capabilities import get_capability_matrix as build_capability_matrix
from .catalog import RuntimeCatalog
from .cli_tools import FortiPamCliTools
from .config import (
    ConfigurationError,
    configuration_presence,
    load_cli_config,
    load_config,
)
from .diagnostic_service import (
    DIAGNOSTIC_UNAVAILABLE,
    DiagnosticServiceError,
    DiagnosticServiceSettings,
    FortiPamDiagnosticService,
)
from .env import load_runtime_environment
from .knowledge import FortiPamKnowledgeTools
from .native_content import FortiPamNativeContent, register_native_content
from .read_only import FortiPamCatalogTools, FortiPamReadOnlyTools
from .runtime_profile import RuntimeProfile, resolve_runtime_profile
from .scenario_catalog import ScenarioCatalog
from .v31_admin_mcp import V31AdministrativeMcp

MCP_SERVER_CLASS: Any = None
READ_ONLY_TOOL_ANNOTATIONS: Any = None
LOCAL_STATE_TOOL_ANNOTATIONS: Any = None
LAB_ADMIN_PREVIEW_TOOL_ANNOTATIONS: Any = None
LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS: Any = None
GET_ACCESS_TOKEN: Any = None
try:
    from mcp.server import MCPServer
    from mcp.server.auth.middleware.auth_context import get_access_token
    from mcp.types import ToolAnnotations

    MCP_SERVER_CLASS = MCPServer
    GET_ACCESS_TOKEN = get_access_token
    READ_ONLY_TOOL_ANNOTATIONS = ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
    LOCAL_STATE_TOOL_ANNOTATIONS = ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=False,
    )
    LAB_ADMIN_PREVIEW_TOOL_ANNOTATIONS = ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
    LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS = ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
except ModuleNotFoundError:  # pragma: no cover - exercised only without dependencies.
    pass

FIXED_ROUTE_TOOLS = (
    "get_system_status_summary",
    "get_system_global_summary",
    "get_approval_profile_summary",
    "get_fortianalyzer_delivery_posture_summary",
    "get_license_support_posture_summary",
    "get_ha_configuration_posture_summary",
    "get_recording_storage_health_summary",
    "get_password_changer_configuration_posture_summary",
    "get_ems_connection_posture_summary",
)
LIVE_TOOLS: tuple[str, ...] = ("get_overall_health_summary",) + FIXED_ROUTE_TOOLS
CLI_TOOLS = (
    "get_cli_ha_configuration_summary",
    "get_cli_ha_status_summary",
    "get_cli_ha_checksum_summary",
)
DIAGNOSTIC_TOOLS = (
    "create_ha_diagnostic_baseline",
    "compare_ha_diagnostic_baseline",
    "correlate_ha_api_cli_posture",
)
LAB_ADMIN_PREVIEW_TOOLS = (
    "preview_v31_lab_public_folder",
    "preview_v31_lab_target",
    "preview_v31_lab_secret_metadata",
    "preview_v31_lab_local_user",
    "preview_v31_lab_folder_access_assignment",
)
LAB_ADMIN_EXECUTE_TOOL = "execute_confirmed_v31_lab_operation"
LAB_ADMIN_TOOLS = LAB_ADMIN_PREVIEW_TOOLS + (LAB_ADMIN_EXECUTE_TOOL,)
LIVE_TOOLS = LIVE_TOOLS + CLI_TOOLS + DIAGNOSTIC_TOOLS


class FortiPamMcpServer:
    """Catalog-backed FortiPAM MCP with a fixed, read-only live surface."""

    def __init__(
        self,
        *,
        auth_settings: Any = None,
        token_verifier: Any = None,
        custom_http_routes: Sequence[Any] = (),
        diagnostic_settings: DiagnosticServiceSettings | None = None,
        runtime_profile: RuntimeProfile | str | None = None,
    ) -> None:
        if MCP_SERVER_CLASS is None:
            raise RuntimeError(
                "mcp is required to start the FortiPAM MCP server. Install project dependencies first."
            )
        _configure_safe_dependency_logging()
        self._runtime_environment_loaded = False
        self._credential_source_loaded = False
        self._runtime_profile = resolve_runtime_profile(runtime_profile)
        self._catalog_tools = FortiPamCatalogTools(RuntimeCatalog.load())
        scenario_catalog = ScenarioCatalog.load()
        self._knowledge_tools = FortiPamKnowledgeTools(scenario_catalog)
        self._native_content = FortiPamNativeContent(scenario_catalog)
        self._device_tools: FortiPamReadOnlyTools | None = None
        self._cli_tools: FortiPamCliTools | None = None
        self._diagnostic_settings = diagnostic_settings
        self._diagnostic_service: FortiPamDiagnosticService | None = None
        self._lab_admin_mcp = (
            V31AdministrativeMcp()
            if self._runtime_profile is RuntimeProfile.LAB_SIMULATED
            else None
        )
        self.mcp = MCP_SERVER_CLASS(
            "fortipam-mcp-server",
            version=__version__,
            instructions=(
                "FortiPAM 1.9 source-traceable operational scenarios, API metadata "
                "discovery, nine fixed minimized API reads, one no-input aggregate "
                "health summary, three fixed CLI diagnostic summaries, and three "
                "HTTP-OAuth-only local diagnostic-state workflows. No Tool changes "
                "the FortiPAM appliance. Offline knowledge never authorizes a device "
                "call or command."
            ),
            auth=auth_settings,
            token_verifier=token_verifier,
        )
        routes = getattr(self.mcp, "_custom_starlette_routes", None)
        if not isinstance(routes, list):
            raise RuntimeError(
                "The installed MCP SDK does not expose the required custom-route boundary."
            )
        routes.extend(custom_http_routes)
        register_native_content(self.mcp, self._native_content)
        self._register_tools()
        _forbid_unknown_tool_arguments(self.mcp)

    def _register_tools(self) -> None:
        @self.mcp.tool(
            description="Return static FortiPAM MCP scope and metadata.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_server_info() -> dict[str, Any]:
            return {
                "name": "fortipam-mcp-server",
                "version": __version__,
                "mcp_sdk_line": "2.x",
                "read_only": True,
                "read_only_scope": "fortipam_device",
                "local_state_write_enabled": self._diagnostic_settings is not None,
                "live_tools": list(LIVE_TOOLS),
                "compiled_fortipam_route_count": len(FIXED_ROUTE_TOOLS),
                "compiled_cli_workflow_count": len(CLI_TOOLS),
                "capability_matrix_available": True,
                "catalog_operations_are_callable": False,
                "operational_scenarios_are_advisory": True,
                "device_write_enabled": False,
                "runtime_profile": self._runtime_profile.value,
                "lab_admin_enabled": self._lab_admin_mcp is not None,
                "lab_admin_tool_count": (
                    len(LAB_ADMIN_TOOLS) if self._lab_admin_mcp is not None else 0
                ),
                "local_diagnostic_state_configured": self._diagnostic_settings
                is not None,
                "diagnostic_transport": "http_oauth_only",
                "credential_source_loaded": self._credential_source_loaded,
            }

        @self.mcp.tool(
            description="Return local process health without contacting FortiPAM.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def health_check() -> dict[str, Any]:
            return {
                "status": "ok",
                "catalog_loaded": True,
                "live_fortipam_required": False,
                "read_only": True,
            }

        @self.mcp.tool(
            description=(
                "Describe reviewed Tool Packs, execution modes, versions, and risks "
                "without loading credentials or contacting FortiPAM."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_capability_matrix() -> dict[str, object]:
            enabled_packs = (
                None
                if self._runtime_profile is RuntimeProfile.LAB_SIMULATED
                else tuple(pack for pack in ToolPack if pack is not ToolPack.LAB_ADMIN)
            )
            return build_capability_matrix(enabled_packs=enabled_packs)

        @self.mcp.tool(
            description="Report whether required FortiPAM settings are present without returning values.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def fortipam_configuration_status() -> dict[str, object]:
            self._ensure_runtime_environment()
            return configuration_presence()

        @self.mcp.tool(
            description="Return sanitized FortiPAM 1.9 API catalog coverage and freshness metadata.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_api_catalog_status() -> dict[str, object]:
            return self._catalog_tools.status()

        @self.mcp.tool(
            description="Search offline FortiPAM API metadata; this never calls the appliance.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def search_api_catalog(
            query: str,
            api_family: str | None = None,
            method: str | None = None,
            limit: int = 10,
        ) -> dict[str, object]:
            return self._catalog_tools.search(query, api_family, method, limit)

        @self.mcp.tool(
            description="Classify one exact documented FortiPAM operation without calling the appliance.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def classify_api_operation(method: str, path: str) -> dict[str, object]:
            return self._catalog_tools.classify(method, path)

        @self.mcp.tool(
            description="Return source, version, domain, and validation status for FortiPAM scenarios.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_scenario_catalog_status() -> dict[str, object]:
            return self._knowledge_tools.status()

        @self.mcp.tool(
            description="Search advisory FortiPAM operational scenarios without contacting a device.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def search_operational_scenarios(
            query: str,
            domain: str | None = None,
            limit: int = 5,
        ) -> dict[str, object]:
            return self._knowledge_tools.search(query, domain, limit)

        @self.mcp.tool(
            description="Return one source-traceable FortiPAM evidence plan; it never executes actions.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_operational_scenario(scenario_id: str) -> dict[str, object]:
            return self._knowledge_tools.get(scenario_id)

        @self.mcp.tool(
            description="Validate all nine fixed FortiPAM read plans without a network call.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def plan_curated_reads() -> dict[str, object]:
            return self._require_device_tools().plan_curated_reads()

        @self.mcp.tool(
            description="Validate the fixed approval-profile read plan without a network call.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def plan_approval_profile_read() -> dict[str, object]:
            return self._require_device_tools().plan_approval_profile_read()

        @self.mcp.tool(
            description=(
                "Aggregate all seven fixed FortiPAM reads into evidence completeness "
                "and bounded risk signals without returning component data."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_overall_health_summary() -> dict[str, object]:
            return await self._require_device_tools().get_overall_health_summary()

        @self.mcp.tool(
            description="Read FortiPAM system status through one fixed GET and return structure only.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_system_status_summary() -> dict[str, object]:
            return await self._require_device_tools().get_system_status_summary()

        @self.mcp.tool(
            description="Read FortiPAM system-global through one fixed GET and return structure only.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_system_global_summary() -> dict[str, object]:
            return await self._require_device_tools().get_system_global_summary()

        @self.mcp.tool(
            description="Read FortiPAM approval profiles through one fixed GET and return structure only.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_approval_profile_summary() -> dict[str, object]:
            return await self._require_device_tools().get_approval_profile_summary()

        @self.mcp.tool(
            description=(
                "Read fixed FortiAnalyzer delivery settings and return a non-identifying "
                "security posture only."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_fortianalyzer_delivery_posture_summary() -> dict[str, object]:
            return await self._require_device_tools().get_fortianalyzer_delivery_posture_summary()

        @self.mcp.tool(
            description=(
                "Read fixed license status and return health, expiry, capacity, and "
                "support bands without identity or exact values."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_license_support_posture_summary() -> dict[str, object]:
            return await self._require_device_tools().get_license_support_posture_summary()

        @self.mcp.tool(
            description=(
                "Read fixed HA configuration and return topology and security posture "
                "without identities, network values, interfaces, keys, or checksums."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_ha_configuration_posture_summary() -> dict[str, object]:
            return await self._require_device_tools().get_ha_configuration_posture_summary()

        @self.mcp.tool(
            description=(
                "Read fixed log/video disk usage and return storage health bands "
                "without byte counts, timestamps, identities, or recordings."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_recording_storage_health_summary() -> dict[str, object]:
            return await self._require_device_tools().get_recording_storage_health_summary()

        @self.mcp.tool(
            description=(
                "Read the fixed password-changer collection and report only "
                "documented-label observation without names, "
                "procedures, descriptions, references, or secret assignments."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_password_changer_configuration_posture_summary() -> dict[str, object]:
            return await self._require_device_tools().get_password_changer_configuration_posture_summary()

        @self.mcp.tool(
            description=(
                "Read the fixed EMS status summary and return only aggregate "
                "connection and certificate posture without connector, network, "
                "certificate, tag, endpoint, or raw status values."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_ems_connection_posture_summary() -> dict[str, object]:
            return await self._require_device_tools().get_ems_connection_posture_summary()

        @self.mcp.tool(
            description=(
                "Run the fixed FortiPAM HA-configuration CLI diagnostic and return "
                "only categorical HA configuration evidence."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_cli_ha_configuration_summary() -> dict[str, object]:
            return await self._require_cli_tools().get_ha_configuration_summary()

        @self.mcp.tool(
            description=(
                "Run the fixed FortiPAM HA-status CLI diagnostic and return only "
                "HA mode, health, member-count, and synchronization categories."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_cli_ha_status_summary() -> dict[str, object]:
            return await self._require_cli_tools().get_ha_status_summary()

        @self.mcp.tool(
            description=(
                "Run the fixed FortiPAM HA-checksum CLI workflow and return only "
                "agreement and evidence-completeness categories."
            ),
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def get_cli_ha_checksum_summary() -> dict[str, object]:
            return await self._require_cli_tools().get_ha_checksum_summary()

        @self.mcp.tool(
            description=(
                "Create one immutable local HA posture baseline from the fixed "
                "FortiPAM API summary. Requires HTTP OAuth diagnostic scope and "
                "does not change the appliance."
            ),
            annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        )
        async def create_ha_diagnostic_baseline(
            baseline_id: str,
        ) -> dict[str, str]:
            return await self._require_diagnostic_service().create_ha_baseline(
                self._access_token(), baseline_id
            )

        @self.mcp.tool(
            description=(
                "Compare one fixed HA posture capture with an immutable local "
                "baseline and return only a drift class. Requires HTTP OAuth "
                "diagnostic scope and does not change the appliance."
            ),
            annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        )
        async def compare_ha_diagnostic_baseline(
            baseline_id: str,
        ) -> dict[str, str]:
            return await self._require_diagnostic_service().compare_ha_baseline(
                self._access_token(), baseline_id
            )

        @self.mcp.tool(
            description=(
                "Correlate the fixed FortiPAM HA API and CLI configuration "
                "summaries and return only a relationship class. Requires HTTP "
                "OAuth diagnostic scope and does not change the appliance."
            ),
            annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        )
        async def correlate_ha_api_cli_posture() -> dict[str, str]:
            return await self._require_diagnostic_service().correlate_ha_api_cli(
                self._access_token()
            )

        lab_admin_mcp = self._lab_admin_mcp
        if lab_admin_mcp is None:
            return

        @self.mcp.tool(
            description=(
                "Preview one in-memory LAB Public Folder state transition without "
                "contacting FortiPAM or loading credentials."
            ),
            annotations=LAB_ADMIN_PREVIEW_TOOL_ANNOTATIONS,
        )
        async def preview_v31_lab_public_folder(
            folder_ref: str,
            parent_folder_ref: str,
            folder_type: Literal["public", "private", "shared"],
            folder_permission: Literal["use", "manage"],
            vault_permission: Literal["use", "manage"],
            allowed_launcher_type: Literal["any", "ssh", "sftp", "rdp"],
            vault_policy_ref: str = "default-vault-policy-01",
            user_permission: Literal["use", "manage"] = "use",
            group_permission: Literal["use", "manage"] = "use",
        ) -> dict[str, object]:
            return lab_admin_mcp.preview_public_folder(
                folder_ref=folder_ref,
                parent_folder_ref=parent_folder_ref,
                folder_type=folder_type,
                folder_permission=folder_permission,
                vault_permission=vault_permission,
                allowed_launcher_type=allowed_launcher_type,
                vault_policy_ref=vault_policy_ref,
                user_permission=user_permission,
                group_permission=group_permission,
            )

        @self.mcp.tool(
            description=(
                "Preview one in-memory LAB Target metadata state transition without "
                "contacting FortiPAM or loading credentials."
            ),
            annotations=LAB_ADMIN_PREVIEW_TOOL_ANNOTATIONS,
        )
        async def preview_v31_lab_target(
            target_ref: str,
            target_class: Literal["ssh", "sftp", "rdp", "https"],
            template_ref: str,
            address_ref: str,
            gateway_ref: str,
        ) -> dict[str, object]:
            return lab_admin_mcp.preview_target(
                target_ref=target_ref,
                target_class=target_class,
                template_ref=template_ref,
                address_ref=address_ref,
                gateway_ref=gateway_ref,
            )

        @self.mcp.tool(
            description=(
                "Preview one in-memory LAB Secret metadata transition without "
                "accepting material or contacting FortiPAM."
            ),
            annotations=LAB_ADMIN_PREVIEW_TOOL_ANNOTATIONS,
        )
        async def preview_v31_lab_secret_metadata(
            secret_ref: str,
            name_ref: str,
            folder_ref: str,
            template_ref: str,
            target_ref: str,
            field_desc_ref: str,
        ) -> dict[str, object]:
            return lab_admin_mcp.preview_secret_metadata(
                secret_ref=secret_ref,
                name_ref=name_ref,
                folder_ref=folder_ref,
                template_ref=template_ref,
                target_ref=target_ref,
                field_desc_ref=field_desc_ref,
            )

        @self.mcp.tool(
            description=(
                "Preview one in-memory LAB Local User metadata transition without "
                "accepting a password or contacting FortiPAM."
            ),
            annotations=LAB_ADMIN_PREVIEW_TOOL_ANNOTATIONS,
        )
        async def preview_v31_lab_local_user(
            user_ref: str,
            name_ref: str,
            status: Literal["enable", "disable"],
            access_profile_ref: str,
            display_name_ref: str,
            comments_ref: str,
            schedule_ref: str,
            two_factor: bool,
        ) -> dict[str, object]:
            return lab_admin_mcp.preview_local_user(
                user_ref=user_ref,
                name_ref=name_ref,
                status=status,
                access_profile_ref=access_profile_ref,
                display_name_ref=display_name_ref,
                comments_ref=comments_ref,
                schedule_ref=schedule_ref,
                two_factor=two_factor,
            )

        @self.mcp.tool(
            description=(
                "Preview one in-memory LAB Folder access-assignment transition "
                "without contacting FortiPAM or loading credentials."
            ),
            annotations=LAB_ADMIN_PREVIEW_TOOL_ANNOTATIONS,
        )
        async def preview_v31_lab_folder_access_assignment(
            assignment_ref: str,
            folder_ref: str,
            subject_ref: str,
            folder_permission: Literal["use", "manage"],
            vault_permission: Literal["use", "manage"],
            allowed_launcher_type: Literal["any", "ssh", "sftp", "rdp"],
        ) -> dict[str, object]:
            return lab_admin_mcp.preview_folder_access_assignment(
                assignment_ref=assignment_ref,
                folder_ref=folder_ref,
                subject_ref=subject_ref,
                folder_permission=folder_permission,
                vault_permission=vault_permission,
                allowed_launcher_type=allowed_launcher_type,
            )

        @self.mcp.tool(
            description=(
                "Execute one exact confirmed in-memory LAB transition and return "
                "verified local readback; this never contacts FortiPAM."
            ),
            annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        )
        async def execute_confirmed_v31_lab_operation(
            confirmation_token: str,
            confirmation_digest: str,
            idempotency_key: str,
        ) -> dict[str, object]:
            return lab_admin_mcp.execute_confirmed(
                confirmation_token,
                confirmation_digest,
                idempotency_key,
            )

    def _require_device_tools(self) -> FortiPamReadOnlyTools:
        if self._device_tools is None:
            self._ensure_runtime_environment()
            try:
                config = load_config()
            except ConfigurationError as exc:
                raise RuntimeError("FortiPAM live tools are not configured.") from exc
            self._device_tools = FortiPamReadOnlyTools(config)
        return self._device_tools

    def _require_cli_tools(self) -> FortiPamCliTools:
        if self._cli_tools is None:
            self._ensure_runtime_environment()
            try:
                config = load_cli_config()
            except ConfigurationError as exc:
                raise RuntimeError("FortiPAM CLI tools are not configured.") from exc
            self._cli_tools = FortiPamCliTools(config)
        return self._cli_tools

    def _require_diagnostic_service(self) -> FortiPamDiagnosticService:
        if self._diagnostic_settings is None:
            raise DiagnosticServiceError(DIAGNOSTIC_UNAVAILABLE)
        if self._diagnostic_service is None:
            async def collect_api() -> dict[str, object]:
                return await self._require_device_tools().get_ha_configuration_posture_summary()

            async def collect_cli() -> dict[str, object]:
                return await self._require_cli_tools().get_ha_configuration_summary()

            self._diagnostic_service = FortiPamDiagnosticService(
                self._diagnostic_settings,
                ha_api_collector=collect_api,
                ha_cli_collector=collect_cli,
            )
        return self._diagnostic_service

    @staticmethod
    def _access_token() -> Any:
        if GET_ACCESS_TOKEN is None:
            return None
        return GET_ACCESS_TOKEN()

    def _ensure_runtime_environment(self) -> None:
        if self._runtime_environment_loaded:
            return
        report = load_runtime_environment()
        self._runtime_environment_loaded = True
        self._credential_source_loaded = report.loaded

    def run(self) -> None:
        """Run over stdio; stdout is reserved for the MCP protocol."""

        self.mcp.run(transport="stdio")


def main(argv: list[str] | None = None) -> None:
    """Console entrypoint."""

    parser = argparse.ArgumentParser(description="Run the FortiPAM MCP stdio server.")
    parser.parse_args(argv)
    FortiPamMcpServer().run()


def _configure_safe_dependency_logging() -> None:
    """Prevent dependency request logs from disclosing the configured target URL."""

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def _forbid_unknown_tool_arguments(mcp_server: Any) -> None:
    """Make the MCP SDK fail closed on undeclared tool arguments.

    MCP SDK 2.0.0 builds Pydantic argument models with the default ``extra``
    behavior, which silently ignores unknown members. The project pins that SDK
    line, so harden every registered tool model after registration and fail
    startup if the expected manager or schema behavior changes.
    """

    tool_manager = getattr(mcp_server, "_tool_manager", None)
    if tool_manager is None or not callable(getattr(tool_manager, "list_tools", None)):
        raise RuntimeError("The MCP SDK tool manager is unavailable for strict input validation.")

    tools = tool_manager.list_tools()
    if not tools:
        raise RuntimeError("No MCP tools were registered for strict input validation.")

    for tool in tools:
        metadata = getattr(tool, "fn_metadata", None)
        argument_model = getattr(metadata, "arg_model", None)
        if argument_model is None:
            raise RuntimeError("An MCP tool is missing its argument model.")
        argument_model.model_config["extra"] = "forbid"
        argument_model.model_rebuild(force=True)
        strict_schema = argument_model.model_json_schema()
        if strict_schema.get("additionalProperties") is not False:
            raise RuntimeError("The MCP SDK did not enable strict tool input validation.")
        tool.parameters = strict_schema


if __name__ == "__main__":
    main()
