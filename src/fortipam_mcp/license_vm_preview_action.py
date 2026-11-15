"""Opt-in no-input MCP observation of one borrowed license VM source.

Only minimized structural metadata is returned. The host binds the Owner,
target and original OAuth requester/client; no license material or endpoint
enters MCP arguments, and no installation proposal or authority is produced.
"""
from __future__ import annotations

from typing import Any
from time import monotonic as _monotonic

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .approval_delivery_preview_action import _finish_private_work
from .license_install_preflight import LicenseInstallPreflight
from .license_vm_source import LicenseVmSource, CONTRACT as SOURCE_CONTRACT
from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal

CONTRACT = "fortipam-build29-license-vm-readonly-mcp-preview-local/v1"
TOOL_NAME = "preview_v4_license_vm_local_700"
_ERROR = "The private license VM preview is unavailable."


class LicenseVmPreviewAction(_OpaqueC3Object):
    """One source/window bound to the original OAuth requester and client."""

    def __init__(self, source: LicenseVmSource, *, requester_digest: str, transport_digest: str,
            preflight: LicenseInstallPreflight | None = None) -> None:
        try:
            if (type(source) is not LicenseVmSource or source._closed
                    or source._attempted or source._projection is not None):
                raise ValueError
            for digest in (requester_digest, transport_digest):
                require_digest(digest, "license VM preview principal")
            if preflight is not None and (type(preflight) is not LicenseInstallPreflight
                    or preflight._pins[0] is not source or preflight._identity_pin != (requester_digest, transport_digest)
                    or preflight._closed or preflight._attempted): raise ValueError
            self._identity = self._identity_pin = (requester_digest, transport_digest)
            self._source = self._source_pin = source
            self._preflight = self._preflight_pin = preflight
        except Exception:
            raise ValueError(_ERROR) from None

    def _check_principal(self, principal: V4PlanningPrincipal) -> None:
        # Foreign callers do not acquire read, disposal or revocation ownership.
        if (type(principal) is not V4PlanningPrincipal or self._identity != self._identity_pin
                or (principal.requester.digest, principal.transport_namespace_digest) != self._identity_pin):
            raise RuntimeError(_ERROR)

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        self._check_principal(principal)
        return self._preview_owned(principal)

    def _preview_owned(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            try:
                with self._source_pin._lock:
                    self._check_principal(principal)
                    if self._source is not self._source_pin or self._preflight is not self._preflight_pin:
                        raise ValueError
                    preflight = self._preflight_pin
                    joined = None
                    if preflight is not None:
                        joined = preflight.preview(requester_digest=principal.requester.digest,
                            transport_digest=principal.transport_namespace_digest)
                        observation = joined["vm_observation"]
                        if type(observation) is not dict: raise ValueError
                        valid_until = preflight._valid_until
                    else:
                        observation = self._source_pin.read()
                        self._source_pin._current()
                        valid_until = self._source_pin._monotonic_deadline
                    # The source's read-time lifecycle flag would be stale by
                    # MCP handoff; report disposal only after cleanup below.
                    observation.pop("closed", None)
                    public: dict[str, object] = dict(preview_contract=CONTRACT, read_source_contract=SOURCE_CONTRACT,
                        observation=observation, fixed_get_completed=True,
                        private_license_values_returned=False, license_material_loaded=False,
                        installation_proposal_created=False, authorization_or_operation_created=False,
                        native_license_state_qualified=False, execution_authorized=False,
                        configuration_written=False)
                    if joined is not None: public["installation_prerequisites"] = joined
            finally:
                # Dispose our Cookie/projection before public handoff, including
                # queued cancellation or an exception acquiring the source lock.
                self.close()
            if valid_until is None or _monotonic() >= valid_until: raise ValueError
            public["private_source_copy_disposed"] = True
            return public
        except Exception:
            raise RuntimeError(_ERROR) from None

    def close(self) -> None:
        try:
            if self._preflight_pin is not None: self._preflight_pin.close()
        finally: self._source_pin.close()

    def _revoke(self) -> None:
        # Nonblocking cancellation latch; the owning worker performs cleanup.
        self._source_pin._closed = True
        if self._preflight_pin is not None: self._preflight_pin._revoke()


def register_license_vm_preview_tool(server: Any, action: LicenseVmPreviewAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS
    if (type(action) is not LicenseVmPreviewAction
            or getattr(server, "_runtime_profile", None) is not RuntimeProfile.V4_CONTROLLED):
        raise ValueError(_ERROR)

    async def preview() -> dict[str, object]:
        principal = server._v4_planning_principal()
        action._check_principal(principal)
        return await _finish_private_work(lambda: action._preview_owned(principal), action)

    server.mcp.tool(name=TOOL_NAME,
        description="Observe host-bound license VM structure and optional fixed installation prerequisites without input, installation proposal or authority; native license state remains unqualified.",
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)


def wrap_license_vm_preview_shutdown(app: Any, action: LicenseVmPreviewAction) -> Any:
    """Dispose even an unused Cookie copy when the owning MCP app stops."""
    async def wrapped(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "lifespan":
            await app(scope, receive, send)
            return
        async def receive_and_close() -> Any:
            message = await receive()
            if message["type"] == "lifespan.shutdown":
                await _finish_private_work(action.close, action)
            return message
        try:
            await app(scope, receive_and_close, send)
        finally:
            await _finish_private_work(action.close, action)
    return wrapped
