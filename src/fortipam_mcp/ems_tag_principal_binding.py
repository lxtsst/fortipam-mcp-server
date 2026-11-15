"""Opt-in SDK requester metadata for separate original-Account preparation.

This binding does not provision a Role/Account, resolve material, issue an M4
authorization or call a device. Configuration prerequisites stay outside preview.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
from threading import RLock
import time
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_ref

from .ems_tag_contract import _canonical
from .ems_tag_custody import _decode
from .ldap_server_runtime import _key, _read
from .local_user_reset_material_source import _directory_identity, _write_once
from .secret_metadata_http_transport import _zeroize_mutable
from .v4_plan_runtime import V4PlanningPrincipal

CONTRACT = "ems-7.4.8.2245-sdk-original-account-requester-binding-v1"
_NAME = "sdk-requester-binding.json"
_DOMAIN = b"ems-sdk-original-account-requester-binding/v1\x00"
_ERROR = "The private EMS SDK requester binding is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagSdkRequester(_OpaqueC3Object):
    requester_digest: str
    transport_namespace_digest: str
    binding_digest: str
    observed_at: int
    expires_at: int


class EmsTagPrincipalBinding(_OpaqueC3Object):
    """One write-once server record; never accepts caller identity arguments."""

    def __init__(self, directory: Path, witness_key_file: Path, *, environment_ref: str,
                 scope_ref: str, audience_ref: str, capture_enabled: bool = False,
                 clock: Callable[[], int] | None = None) -> None:
        try:
            if type(capture_enabled) is not bool or clock is not None and not callable(clock):
                raise ValueError
            for ref in (environment_ref, scope_ref, audience_ref):require_ref(ref, "ems_sdk_binding_scope")
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            self._directory_identity = _directory_identity(self._directory)
            self._key = _key(self._key_file)
            if self._key_file.parent == self._directory:raise ValueError
            self._scope = dict(environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref)
            self._clock = clock or (lambda:int(time.time()))
            self._enabled, self._closed, self._last = capture_enabled, False, -1
            self._lock = RLock()
            self._pins()
        except Exception:raise ValueError(_ERROR) from None

    def _pins(self) -> None:
        if (_directory_identity(self._directory) != self._directory_identity or _key(self._key_file) != self._key
                or {p.name for p in self._directory.iterdir()} - {_NAME}):raise ValueError

    def _now(self) -> int:
        self._pins();now = self._clock()
        if self._closed or type(now) is not int or now < 0 or now < self._last:raise ValueError
        self._last = now
        return now

    def _signature(self, body: object) -> str:
        return hmac.new(self._key, _DOMAIN + _canonical(body), hashlib.sha256).hexdigest()

    def _body(self) -> dict[str, Any]:
        raw = _read(self._directory / _NAME, 32768)
        try:
            packet = _decode(raw)
            if type(packet) is not dict or set(packet) != {"body", "signature"}:raise ValueError
            body = packet["body"]
            if (type(body) is not dict or set(body) != {"contract", "scope", "directory", "directory_identity",
                    "requester_digest", "transport_namespace_digest", "observed_at", "expires_at"}
                    or body["contract"] != CONTRACT or body["scope"] != self._scope
                    or body["directory"] != str(self._directory.absolute())
                    or body["directory_identity"] != list(self._directory_identity)
                    or type(packet["signature"]) is not str
                    or not hmac.compare_digest(packet["signature"], self._signature(body))):raise ValueError
            from v4_planning.models import require_digest
            for name in ("requester_digest", "transport_namespace_digest"):require_digest(body[name], "ems_sdk_requester")
            if (type(body["observed_at"]) is not int or type(body["expires_at"]) is not int
                    or body["observed_at"] < 0 or body["expires_at"] != body["observed_at"] + 1800):raise ValueError
            return body
        finally:_zeroize_mutable(raw)

    def load(self) -> EmsTagSdkRequester:
        try:
            with self._lock:
                now = self._now();body = self._body()
                if not body["observed_at"] <= now < body["expires_at"]:raise ValueError
                return EmsTagSdkRequester(body["requester_digest"], body["transport_namespace_digest"],
                    canonical_digest(body), body["observed_at"], body["expires_at"])
        except Exception:raise ValueError(_ERROR) from None

    def require_requester(self, principal: V4PlanningPrincipal) -> EmsTagSdkRequester:
        """Identity metadata only; fresh SDK operation scopes remain mandatory."""
        try:
            if type(principal) is not V4PlanningPrincipal:raise ValueError
            principal.__post_init__();value = self.load()
            if value.requester_digest != principal.requester.digest:raise ValueError
            return value
        except Exception:raise ValueError(_ERROR) from None

    def capture_from_sdk(self, principal_provider: Callable[[], V4PlanningPrincipal]) -> dict[str, object]:
        raw = bytearray()
        try:
            with self._lock:
                now = self._now()
                if not self._enabled or not callable(principal_provider):raise ValueError
                token = get_access_token()
                if (not isinstance(token, AccessToken) or type(token.expires_at) is not int
                        or token.expires_at <= int(time.time())
                        or not {"fortipam:plan", "fortipam:operate"}.issubset(token.scopes)):raise ValueError
                principal = principal_provider()
                if type(principal) is not V4PlanningPrincipal:raise ValueError
                principal.__post_init__()
                if (self._directory / _NAME).exists():
                    current = self.load()
                    if (current.requester_digest != principal.requester.digest
                            or current.transport_namespace_digest != principal.transport_namespace_digest):raise ValueError
                else:
                    body = dict(contract=CONTRACT, scope=self._scope, directory=str(self._directory.absolute()),
                        directory_identity=list(self._directory_identity), requester_digest=principal.requester.digest,
                        transport_namespace_digest=principal.transport_namespace_digest, observed_at=now, expires_at=now + 1800)
                    if principal_provider() != principal or get_access_token() is not token:raise ValueError
                    raw.extend(_canonical(dict(body=body, signature=self._signature(body))))
                    _write_once(self._directory, self._directory_identity, _NAME, raw)
                    self.require_requester(principal)
                return dict(identity_binding_recorded=True, execution_authorized=False, device_write_executed=False)
        except Exception:raise RuntimeError(_ERROR) from None
        finally:_zeroize_mutable(raw)

    def close(self) -> None:
        with self._lock:self._enabled, self._closed = False, True


def register_ems_tag_principal_binding_tool(server: Any, binding: EmsTagPrincipalBinding) -> None:
    from .server import LOCAL_STATE_TOOL_ANNOTATIONS
    if type(binding) is not EmsTagPrincipalBinding:raise ValueError(_ERROR)

    async def bind_requester() -> dict[str, object]:
        return await asyncio.to_thread(binding.capture_from_sdk, server._v4_secret_metadata_action_principal)

    server.mcp.tool(name="bind_v4_ems_original_account_requester_748", annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Record SDK-verified requester metadata for separate original-Account preparation; no device action or execution authority.")(bind_requester)
    tool = server.mcp._tool_manager.get_tool("bind_v4_ems_original_account_requester_748")
    if tool is None:raise ValueError(_ERROR)
    model = tool.fn_metadata.arg_model
    model.model_config["extra"] = "forbid"
    model.model_rebuild(force=True)
    schema = model.model_json_schema()
    if schema.get("additionalProperties") is not False:raise ValueError(_ERROR)
    tool.parameters = schema
