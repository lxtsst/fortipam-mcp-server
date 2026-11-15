"""Explicit factory-only readonly previews for fixed local JIT inputs."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal
from .windows_jit_script_source import WindowsJitScriptSource
from .windows_jit_secret_source import WindowsJitSecretSource

_ERROR = 'The private Windows JIT Script preview is unavailable.'


class WindowsJitScriptPreviewAction(_OpaqueC3Object):
    def __init__(self, source: WindowsJitScriptSource, *, requester_digest: str, transport_digest: str,
            secret_source: WindowsJitSecretSource | None = None) -> None:
        if (type(source) is not WindowsJitScriptSource or secret_source is not None
                and (type(secret_source) is not WindowsJitSecretSource or secret_source._scripts is not source)): raise ValueError(_ERROR)
        for value in (requester_digest,transport_digest): require_digest(value,'Windows JIT preview identity')
        self._source,self._requester,self._transport = source,requester_digest,transport_digest
        self._secret = secret_source

    def _identity(self, principal: V4PlanningPrincipal) -> None:
        if (type(principal) is not V4PlanningPrincipal or principal.requester.digest != self._requester
                or principal.transport_namespace_digest != self._transport): raise ValueError

    def preview(self, principal: V4PlanningPrincipal) -> dict[str,object]:
        try:
            self._identity(principal)
            return self._source.preview()
        except Exception: raise RuntimeError(_ERROR) from None

    def preview_secret(self, principal: V4PlanningPrincipal) -> dict[str,object]:
        try:
            self._identity(principal)
            if self._secret is None: raise ValueError
            return self._secret.preview()
        except Exception: raise RuntimeError(_ERROR) from None


def register_windows_jit_script_preview_tool(server: Any, action: WindowsJitScriptPreviewAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS
    if (type(action) is not WindowsJitScriptPreviewAction
            or getattr(server,'_runtime_profile',None) is not RuntimeProfile.V4_CONTROLLED): raise ValueError(_ERROR)

    async def preview() -> dict[str,object]:
        return await asyncio.to_thread(action.preview,server._v4_planning_principal())
    server.mcp.tool(name='preview_v4_windows_jit_script_pair_local_700',
        description='Read and preview a fixed local JIT Script pair without creation, execution or privilege qualification.',
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)
    if action._secret is not None:
        async def preview_secret() -> dict[str,object]:
            return await asyncio.to_thread(action.preview_secret,server._v4_planning_principal())
        server.mcp.tool(name='preview_v4_windows_jit_secret_local_700',
            description='Read a fixed local Windows JIT Secret metadata draft; no write, credential or privilege authority.',
            annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview_secret)
