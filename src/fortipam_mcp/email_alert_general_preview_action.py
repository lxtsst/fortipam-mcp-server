"""Factory-only no-input general-alert preview; no mail or execution authority."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from .email_alert_general_source import EmailAlertGeneralSource
from .email_alert_compound_source import EmailAlertCompoundSource
from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = 'The private general email-alert preview is unavailable.'


class EmailAlertGeneralPreviewAction(_OpaqueC3Object):
    def __init__(self, source: EmailAlertGeneralSource, *, requester_digest: str, transport_digest: str,
            compound_source: EmailAlertCompoundSource | None = None) -> None:
        if type(source) is not EmailAlertGeneralSource: raise ValueError(_ERROR)
        if compound_source is not None and (type(compound_source) is not EmailAlertCompoundSource
                or compound_source._general is not source): raise ValueError(_ERROR)
        for digest in (requester_digest,transport_digest): require_digest(digest,'general alert preview identity')
        self._source,self._requester,self._transport = source,requester_digest,transport_digest
        self._compound_source = compound_source

    def preview(self, principal: V4PlanningPrincipal) -> dict[str,object]:
        return self._preview(principal,False)

    def preview_compound(self, principal: V4PlanningPrincipal) -> dict[str,object]:
        return self._preview(principal,True)

    def _preview(self, principal: V4PlanningPrincipal, compound: bool) -> dict[str,object]:
        try:
            if (type(principal) is not V4PlanningPrincipal or principal.requester.digest != self._requester
                    or principal.transport_namespace_digest != self._transport): raise ValueError
            if compound:
                if self._compound_source is None or self._compound_source._general is not self._source: raise ValueError
                return self._compound_source.preview()
            return self._source.preview()
        except Exception: raise RuntimeError(_ERROR) from None


def register_email_alert_general_preview_tool(server: Any, action: EmailAlertGeneralPreviewAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS
    if type(action) is not EmailAlertGeneralPreviewAction or getattr(server,'_runtime_profile',None) is not RuntimeProfile.V4_CONTROLLED:
        raise ValueError(_ERROR)
    async def preview() -> dict[str,object]:
        return await asyncio.to_thread(action.preview,server._v4_planning_principal())
    server.mcp.tool(name='preview_v4_email_alert_general_local_700',
        description='Read a fixed general-alert draft; no compound master switch, write, recipient authority or delivery qualification.',
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)
    if action._compound_source is not None:
        async def preview_compound() -> dict[str,object]:
            return await asyncio.to_thread(action.preview_compound,server._v4_planning_principal())
        server.mcp.tool(name='preview_v4_email_alert_compound_local_700',
            description='Read the fixed existing general, critical and certificate alert graph; no writes, inverse custody or delivery qualification.',
            annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview_compound)
