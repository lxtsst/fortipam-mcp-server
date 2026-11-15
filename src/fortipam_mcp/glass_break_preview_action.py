"""Factory-only readonly glass-breaking draft; no elevation or session authority."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from .glass_break_source import GlassBreakSource
from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = 'The private glass-breaking preview is unavailable.'


class GlassBreakPreviewAction(_OpaqueC3Object):
    def __init__(self, source: GlassBreakSource, *, requester_digest: str, transport_digest: str) -> None:
        if type(source) is not GlassBreakSource: raise ValueError(_ERROR)
        for digest in (requester_digest,transport_digest): require_digest(digest,'glass-breaking preview identity')
        self._source,self._requester,self._transport=source,requester_digest,transport_digest

    def preview(self, principal: V4PlanningPrincipal) -> dict[str,object]:
        try:
            if (type(principal) is not V4PlanningPrincipal or principal.requester.digest!=self._requester
                    or principal.transport_namespace_digest!=self._transport): raise ValueError
            return self._source.preview()
        except Exception: raise RuntimeError(_ERROR) from None


def register_glass_break_preview_tool(server: Any, action: GlassBreakPreviewAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS
    if type(action) is not GlassBreakPreviewAction or getattr(server,'_runtime_profile',None) is not RuntimeProfile.V4_CONTROLLED:
        raise ValueError(_ERROR)
    async def preview() -> dict[str,object]:
        return await asyncio.to_thread(action.preview,server._v4_planning_principal())
    server.mcp.tool(name='preview_v4_glass_break_local_700',
        description='Read one fixed current-actor glass-breaking draft; no elevation, reason input, role edit or deactivation authority.',
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)
