"""Factory-only readonly FortiToken previews for one owner-bound identity."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .fortitoken_user_contract import Operation
from .fortitoken_user_source import FortitokenUserSource
from .fortitoken_inventory_source import FortitokenInventorySource
from .fortitoken_binding_source import FortitokenBindingSource
from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = 'The private FortiToken preview is unavailable.'


class FortitokenLocalPreviewAction(_OpaqueC3Object):
    def __init__(self, source: FortitokenUserSource, *, requester_digest: str, transport_digest: str,
            inventory_source: FortitokenInventorySource | None = None,
            binding_source: FortitokenBindingSource | None = None) -> None:
        if (type(source) is not FortitokenUserSource or inventory_source is not None
                and (type(inventory_source) is not FortitokenInventorySource or inventory_source._source is not source)):
            raise ValueError(_ERROR)
        if binding_source is not None:
            if (type(binding_source) is not FortitokenBindingSource or binding_source._source is not source
                    or inventory_source is not None and binding_source._inventory is not inventory_source): raise ValueError(_ERROR)
            inventory_source = binding_source._inventory
        for value in (requester_digest,transport_digest): require_digest(value,'FortiToken preview identity')
        self._source,self._requester,self._transport = source,requester_digest,transport_digest
        self._inventory = inventory_source
        self._bindings = binding_source

    def preview(self, operation: Operation, principal: V4PlanningPrincipal) -> dict[str,object]:
        try:
            if (type(principal) is not V4PlanningPrincipal or principal.requester.digest != self._requester
                    or principal.transport_namespace_digest != self._transport): raise ValueError
            if self._inventory is None: return self._source.preview(operation)
            with self._source._lock:
                deadline = self._source._now()+self._source._config.timeout_seconds
                with self._source._bounded_by(deadline):
                    public = self._source.preview(operation)
                    bindings = self._bindings.read() if self._bindings is not None else None
                    inventory = bindings.inventory if bindings is not None else self._inventory.read()
                    self._source._remaining(deadline)
                    expires = public['expires_at']
                    if type(expires) is not int or self._source._epoch() >= min(expires,inventory.expires_at): raise ValueError
                    public['Inventory Observation'] = inventory.public()
                    if bindings is not None: public['User Binding Observation'] = bindings.public()
                    return public
        except Exception: raise RuntimeError(_ERROR) from None


def register_fortitoken_local_preview_tools(server: Any, action: FortitokenLocalPreviewAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS
    if (type(action) is not FortitokenLocalPreviewAction
            or getattr(server,'_runtime_profile',None) is not RuntimeProfile.V4_CONTROLLED): raise ValueError(_ERROR)

    def register(operation: Operation) -> None:
        async def preview() -> dict[str,object]:
            return await asyncio.to_thread(action.preview,operation,server._v4_planning_principal())
        server.mcp.tool(name=f'preview_v4_fortitoken_local_{operation}_700',
            description='Preview a fixed local FortiToken User candidate without execution or activation; native effects remain unqualified.',
            annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)
    register('assign'); register('revoke')
