"""Explicit controlled-OAuth, no-input metadata read; no Rule Set action."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from .ems_rule_set_metadata_source import EmsRuleSetMetadataSource
from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR='The private EMS rule-set metadata action is unavailable.'


class EmsRuleSetMetadataAction(_OpaqueC3Object):
    def __init__(self,source: EmsRuleSetMetadataSource,*,requester_digest: str,transport_digest: str) -> None:
        if type(source) is not EmsRuleSetMetadataSource: raise ValueError(_ERROR)
        for digest in (requester_digest,transport_digest): require_digest(digest,'rule-set metadata principal')
        self._source=self._source_pin=source; self._identity=(requester_digest,transport_digest); self._identity_pin=self._identity

    def preview(self,principal: V4PlanningPrincipal) -> dict[str,object]:
        try:
            if (self._source is not self._source_pin or self._identity!=self._identity_pin
                    or type(principal) is not V4PlanningPrincipal
                    or (principal.requester.digest,principal.transport_namespace_digest)!=self._identity): raise ValueError
            return self._source.read_once()
        except Exception: raise RuntimeError(_ERROR) from None

    def close(self) -> None:
        self._source_pin.close()


def register_ems_rule_set_metadata_tools(server: Any,action: EmsRuleSetMetadataAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS
    if type(action) is not EmsRuleSetMetadataAction or getattr(server,'_runtime_profile',None) is not RuntimeProfile.V4_CONTROLLED:
        raise ValueError(_ERROR)
    async def preview() -> dict[str,object]:
        return await asyncio.to_thread(action.preview,server._v4_planning_principal())
    server.mcp.tool(name='preview_v4_ems_rule_set_metadata_local_748',
        description='Read fixed Rule Set response types using original Tag references; no values, ownership or cleanup authority. Native response qualification remains pending.',
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)


def wrap_ems_rule_set_metadata_shutdown(app: Any,action: EmsRuleSetMetadataAction) -> Any:
    """Erase an unused borrowed Cookie copy when the consumer app stops."""
    async def wrapped(scope: Any,receive: Any,send: Any) -> None:
        if scope['type']!='lifespan':
            await app(scope,receive,send); return
        async def receive_and_close() -> Any:
            message=await receive()
            if message['type']=='lifespan.shutdown': await asyncio.to_thread(action.close)
            return message
        try: await app(scope,receive_and_close,send)
        finally: await asyncio.to_thread(action.close)
    return wrapped
