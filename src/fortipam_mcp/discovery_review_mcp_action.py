"""Default-off, no-input MCP review of one privately bound Unix source."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_entry_mcp_action import BINDING_CONTRACT
from .discovery_review_http_transport import FortiPamDiscoveryReviewHttpTransport
from .password_changer_mcp_action import _requester
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config


PREFIX = "FORTIPAM_MCP_V4_DISCOVERY_REVIEW_700_"
SELECTION_BINDING_CONTRACT = "fortipam_v4_unix_discovery_selection_700_private_binding_v1"
_UNAVAILABLE = "FortiPAM V4 Unix Discovery review is unavailable."
_ACCOUNT = re.compile(r"\Afpam-bp014-discovery-r[0-9]+\Z")


class UnixDiscoveryReviewMcpAction:
    def __init__(
        self, transport: FortiPamDiscoveryReviewHttpTransport,
        request: DisabledUnixDiscoveryCreateInput,
        selected_account: str | None = None,
    ) -> None:
        self._transport = transport
        self._request = request
        self._selected_account = selected_account

    def review(self, principal: Any) -> dict[str, object]:
        try:
            _requester(principal)
            return self._transport.review(self._request)
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def select(self, principal: Any) -> dict[str, object]:
        if self._selected_account is None:
            raise RuntimeError(_UNAVAILABLE)
        try:
            _requester(principal)
            return self._transport.select(self._request, self._selected_account)
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None


def _load_review_binding(path: Path) -> tuple[DisabledUnixDiscoveryCreateInput, str | None]:
    """Allow the existing aggregate binding or one exact private fixture selection."""

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 4096):
            raise ValueError(_UNAVAILABLE)
        content = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if len(content) > 4096:
        raise ValueError(_UNAVAILABLE)
    value = json.loads(content)
    if not isinstance(value, dict):
        raise ValueError(_UNAVAILABLE)
    if set(value) == {"contract", "source_name", "discovery_secret_id"}:
        if value.get("contract") != BINDING_CONTRACT:
            raise ValueError(_UNAVAILABLE)
        return DisabledUnixDiscoveryCreateInput(
            value["source_name"], value["discovery_secret_id"],
        ), None
    if (set(value) != {"contract", "source_name", "discovery_secret_id", "selected_account"}
            or value.get("contract") != SELECTION_BINDING_CONTRACT
            or not isinstance(value.get("selected_account"), str)
            or _ACCOUNT.fullmatch(value["selected_account"]) is None):
        raise ValueError(_UNAVAILABLE)
    return DisabledUnixDiscoveryCreateInput(
        value["source_name"], value["discovery_secret_id"],
    ), value["selected_account"]


def build_unix_discovery_review(environment: Mapping[str, str]) -> UnixDiscoveryReviewMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    if enabled not in {"true", "false"}:
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        return None
    try:
        binding_path = Path(environment[PREFIX + "BINDING_FILE"])
        if not binding_path.is_absolute():
            raise ValueError(_UNAVAILABLE)
        request, selected_account = _load_review_binding(binding_path)
        transport = FortiPamDiscoveryReviewHttpTransport(
            load_secret_metadata_http_transport_config(environment),
        )
        return UnixDiscoveryReviewMcpAction(transport, request, selected_account)
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def register_unix_discovery_review_tool(server: Any, action: UnixDiscoveryReviewMcpAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS

    @server.mcp.tool(
        description="Read aggregate counts for one privately bound completed Unix Discovery scan.",
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def review_v4_unix_discovery_results_700() -> dict[str, object]:
        return await asyncio.to_thread(action.review, server._v4_planning_principal())

    if action._selected_account is not None:
        @server.mcp.tool(
            description="Classify one privately bound discovered Unix fixture for existing onboarding.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
        )
        async def select_v4_unix_discovery_account_700() -> dict[str, object]:
            return await asyncio.to_thread(action.select, server._v4_planning_principal())

    # HTTP candidates register after the host's initial hardening pass. Reuse
    # its per-model rule; its existing manager wrapper sanitizes all calls.
    names = ["review_v4_unix_discovery_results_700"]
    if action._selected_account is not None:
        names.append("select_v4_unix_discovery_account_700")
    try:
        for name in names:
            tool = server.mcp._tool_manager.get_tool(name)
            model = tool.fn_metadata.arg_model
            model.model_config["extra"] = "forbid"
            model.model_rebuild(force=True)
            schema = model.model_json_schema()
            if schema.get("additionalProperties") is not False:
                raise ValueError
            tool.parameters = schema
    except Exception:
        raise RuntimeError(_UNAVAILABLE) from None


__all__ = [
    "SELECTION_BINDING_CONTRACT", "UnixDiscoveryReviewMcpAction", "build_unix_discovery_review",
    "register_unix_discovery_review_tool",
]
