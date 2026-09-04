"""Curated FortiPAM read-only and offline catalog workflows."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

from .catalog import RuntimeCatalog
from .config import FortiPamConfig, configuration_presence
from .posture_contracts import (
    PostureContractError,
    summarize_fortianalyzer_delivery_posture,
    summarize_ems_connection_posture,
    summarize_ha_configuration_posture,
    summarize_license_support_posture,
    summarize_overall_health_posture,
    summarize_password_changer_configuration_posture,
    summarize_recording_storage_posture,
)
from .redaction import structural_summary
from .rest import FortiPamRequestError, FortiPamRestClient
from .safety import (
    assert_approval_profile_path,
    assert_ems_status_summary_path,
    assert_fortianalyzer_setting_path,
    assert_ha_configuration_path,
    assert_license_status_path,
    assert_password_changer_path,
    assert_recording_storage_path,
    assert_system_global_path,
    assert_system_status_path,
)


class FortiPamCatalogTools:
    """Offline discovery tools; catalog records never authorize a device call."""

    def __init__(self, catalog: RuntimeCatalog) -> None:
        self._catalog = catalog

    def status(self) -> dict[str, object]:
        return self._catalog.status()

    def search(
        self,
        query: str,
        api_family: str | None = None,
        method: str | None = None,
        limit: int = 10,
    ) -> dict[str, object]:
        operations = self._catalog.search(
            query,
            api_family=api_family,
            method=method,
            limit=limit,
        )
        return {
            "catalog_version": self._catalog.version,
            "result_count": len(operations),
            "results": [operation.summary() for operation in operations],
            "network_call_executed": False,
            "live_call_permitted": False,
        }

    def classify(self, method: str, path: str) -> dict[str, object]:
        operation = self._catalog.find(method, path)
        if operation is None:
            return {
                "catalog_version": self._catalog.version,
                "found": False,
                "network_call_executed": False,
                "live_call_permitted": False,
            }
        return {
            "catalog_version": self._catalog.version,
            "found": True,
            "operation": operation.details(),
            "network_call_executed": False,
            "live_call_permitted": False,
        }


class FortiPamReadOnlyTools:
    """Named live reads; no caller can select an API endpoint or query."""

    def __init__(self, config: FortiPamConfig) -> None:
        self._config = config
        self._client = FortiPamRestClient(config)

    def configuration_status(self) -> dict[str, object]:
        """Report sanitized local configuration presence."""

        return configuration_presence()

    def plan_curated_reads(self) -> dict[str, object]:
        """Validate every compiled live-tool plan without contacting the device."""

        operations = [
            {
                "tool": "get_system_status_summary",
                "method": "GET",
                "path": assert_system_status_path(self._config),
                "sensitivity": "operational_metadata",
            },
            {
                "tool": "get_system_global_summary",
                "method": "GET",
                "path": assert_system_global_path(self._config),
                "sensitivity": "configuration_structure",
            },
            {
                "tool": "get_approval_profile_summary",
                "method": "GET",
                "path": assert_approval_profile_path(self._config),
                "sensitivity": "pam_policy_structure",
            },
            {
                "tool": "get_fortianalyzer_delivery_posture_summary",
                "method": "GET",
                "path": assert_fortianalyzer_setting_path(self._config),
                "sensitivity": "logging_delivery_posture",
            },
            {
                "tool": "get_license_support_posture_summary",
                "method": "GET",
                "path": assert_license_status_path(self._config),
                "sensitivity": "license_support_posture",
            },
            {
                "tool": "get_ha_configuration_posture_summary",
                "method": "GET",
                "path": assert_ha_configuration_path(self._config),
                "sensitivity": "ha_configuration_posture",
            },
            {
                "tool": "get_recording_storage_health_summary",
                "method": "GET",
                "path": assert_recording_storage_path(self._config),
                "sensitivity": "recording_storage_posture",
            },
            {
                "tool": "get_password_changer_configuration_posture_summary",
                "method": "GET",
                "path": assert_password_changer_path(self._config),
                "sensitivity": "password_changer_configuration_posture",
            },
            {
                "tool": "get_ems_connection_posture_summary",
                "method": "GET",
                "path": assert_ems_status_summary_path(self._config),
                "sensitivity": "ems_connection_posture",
            },
        ]
        return {
            "operations": operations,
            "network_call_executed": False,
            "tls_verification_enabled": True,
            "response_body_returned": False,
        }

    def plan_approval_profile_read(self) -> dict[str, object]:
        """Preserve the original single-operation planning contract."""

        path = assert_approval_profile_path(self._config)
        return {
            "operation": "GET",
            "path": path,
            "network_call_executed": False,
            "tls_verification_enabled": True,
            "response_body_returned": False,
        }

    async def get_system_status_summary(self) -> dict[str, object]:
        return await self._get_structural_summary(
            scenario="system_status",
            path=assert_system_status_path(self._config),
            sensitivity="operational_metadata",
        )

    async def get_system_global_summary(self) -> dict[str, object]:
        return await self._get_structural_summary(
            scenario="system_global",
            path=assert_system_global_path(self._config),
            sensitivity="configuration_structure",
        )

    async def get_approval_profile_summary(self) -> dict[str, object]:
        return await self._get_structural_summary(
            scenario="approval_profile",
            path=assert_approval_profile_path(self._config),
            sensitivity="pam_policy_structure",
        )

    async def get_fortianalyzer_delivery_posture_summary(
        self,
    ) -> dict[str, object]:
        path = assert_fortianalyzer_setting_path(self._config)
        response = await self._client.get_json(path)
        return {
            "scenario": "fortianalyzer_delivery",
            "operation": "GET",
            "path": path,
            "sensitivity": "logging_delivery_posture",
            "status_code": response.status_code,
            "content_type": response.content_type,
            "response_body_returned": False,
            "posture": summarize_fortianalyzer_delivery_posture(response.data),
        }

    async def get_license_support_posture_summary(self) -> dict[str, object]:
        path = assert_license_status_path(self._config)
        response = await self._client.get_json(path)
        return {
            "scenario": "platform_health",
            "operation": "GET",
            "path": path,
            "sensitivity": "license_support_posture",
            "status_code": response.status_code,
            "content_type": response.content_type,
            "response_body_returned": False,
            "posture": summarize_license_support_posture(
                response.data, now_epoch=int(time.time())
            ),
        }

    async def get_ha_configuration_posture_summary(self) -> dict[str, object]:
        path = assert_ha_configuration_path(self._config)
        response = await self._client.get_json(path)
        return {
            "scenario": "ha_sync",
            "operation": "GET",
            "path": path,
            "sensitivity": "ha_configuration_posture",
            "status_code": response.status_code,
            "content_type": response.content_type,
            "response_body_returned": False,
            "posture": summarize_ha_configuration_posture(response.data),
        }

    async def get_recording_storage_health_summary(self) -> dict[str, object]:
        path = assert_recording_storage_path(self._config)
        response = await self._client.get_json(path)
        return {
            "scenario": "agentless_recording_disconnect",
            "operation": "GET",
            "path": path,
            "sensitivity": "recording_storage_posture",
            "status_code": response.status_code,
            "content_type": response.content_type,
            "response_body_returned": False,
            "posture": summarize_recording_storage_posture(response.data),
        }

    async def get_password_changer_configuration_posture_summary(
        self,
    ) -> dict[str, object]:
        path = assert_password_changer_path(self._config)
        response = await self._client.get_json(path)
        return {
            "scenario": "password_changer_configuration",
            "operation": "GET",
            "path": path,
            "sensitivity": "password_changer_configuration_posture",
            "status_code": response.status_code,
            "content_type": response.content_type,
            "response_body_returned": False,
            "posture": summarize_password_changer_configuration_posture(
                response.data
            ),
        }

    async def get_ems_connection_posture_summary(self) -> dict[str, object]:
        path = assert_ems_status_summary_path(self._config)
        response = await self._client.get_json(path)
        return {
            "scenario": "ztna_access_denial",
            "operation": "GET",
            "path": path,
            "sensitivity": "ems_connection_posture",
            "status_code": response.status_code,
            "content_type": response.content_type,
            "response_body_returned": False,
            "posture": summarize_ems_connection_posture(response.data),
        }

    async def get_overall_health_summary(self) -> dict[str, object]:
        """Aggregate the seven accepted reads without adding an API route."""

        readers: tuple[
            tuple[str, Callable[[], Awaitable[dict[str, object]]]], ...
        ] = (
            ("system_status", self.get_system_status_summary),
            ("system_global", self.get_system_global_summary),
            ("approval_profile", self.get_approval_profile_summary),
            (
                "fortianalyzer_delivery",
                self.get_fortianalyzer_delivery_posture_summary,
            ),
            ("license_support", self.get_license_support_posture_summary),
            ("ha_configuration", self.get_ha_configuration_posture_summary),
            ("recording_storage", self.get_recording_storage_health_summary),
        )
        outcomes = await asyncio.gather(
            *(reader() for _, reader in readers),
            return_exceptions=True,
        )
        component_results: dict[str, object | None] = {}
        for (name, _), outcome in zip(readers, outcomes, strict=True):
            if isinstance(outcome, (FortiPamRequestError, PostureContractError)):
                component_results[name] = None
            elif isinstance(outcome, BaseException):
                raise outcome
            else:
                component_results[name] = outcome
        return {
            "scenario": "overall_health",
            "sensitivity": "aggregate_operational_posture",
            "network_call_executed": True,
            "response_body_returned": False,
            "caller_identifiers_accepted": False,
            "posture": summarize_overall_health_posture(component_results),
        }

    async def _get_structural_summary(
        self, *, scenario: str, path: str, sensitivity: str
    ) -> dict[str, object]:
        response = await self._client.get_json(path)
        return {
            "scenario": scenario,
            "operation": "GET",
            "path": path,
            "sensitivity": sensitivity,
            "status_code": response.status_code,
            "content_type": response.content_type,
            "response_body_returned": False,
            "summary": structural_summary(response.data),
        }
