"""Three fixed, no-input FortiPAM CLI diagnostic tools."""

from __future__ import annotations

from typing import Any

from .cli_safety import (
    AsyncSshCliTransport,
    CliExecutionResult,
    CliWorkflowId,
    FortiPamCliExecutor,
)
from .config import FortiPamCliConfig


class FortiPamCliTools:
    """Expose categorical CLI evidence without exposing a command surface."""

    def __init__(
        self,
        config: FortiPamCliConfig,
        *,
        executor: FortiPamCliExecutor | None = None,
    ) -> None:
        self._executor = executor or FortiPamCliExecutor(
            AsyncSshCliTransport(
                config.target,
                accept_pre_login_banner=config.accept_pre_login_banner,
            ),
            config.limits,
        )

    async def get_ha_configuration_summary(self) -> dict[str, Any]:
        return _result(await self._executor.execute(CliWorkflowId.HA_CONFIGURATION))

    async def get_ha_status_summary(self) -> dict[str, Any]:
        return _result(await self._executor.execute(CliWorkflowId.HA_STATUS))

    async def get_ha_checksum_summary(self) -> dict[str, Any]:
        return _result(await self._executor.execute(CliWorkflowId.HA_CHECKSUM))


def _result(result: CliExecutionResult) -> dict[str, Any]:
    return {
        "workflow_id": result.workflow_id,
        "execution_status": result.execution_status,
        "evidence": dict(result.evidence),
        "raw_cli_returned": result.raw_cli_returned,
        "credential_values_returned": result.credential_values_returned,
    }
