"""Default-off OAuth/MCP action for one privately bound Unix Discovery scan."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Any, Callable

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from .discovery_entry_mcp_action import _load_binding
from .discovery_run_http_transport import FortiPamDiscoveryRunHttpTransport
from .password_changer_mcp_action import _requester
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config


PREFIX = "FORTIPAM_MCP_V4_DISCOVERY_RUN_700_"
CONTRACT = "fortipam_v4_unix_discovery_run_700_candidate_v1"
_UNAVAILABLE = "FortiPAM V4 Unix Discovery scan is unavailable."
_SOURCE = re.compile(r"\Abp014-discovery-unix-disabled-[0-9]{8}-r[0-9]+\Z")
_TTL_SECONDS = 600


@dataclass(frozen=True, slots=True)
class _Preview:
    requester_digest: str
    reference_digest: str
    expires_at: int
    authorization_ref: str | None = None


class UnixDiscoveryRunLiveWorkflow:
    """Bind one exact source and reserve a durable claim before Scan POST."""

    def __init__(
        self,
        transport: FortiPamDiscoveryRunHttpTransport,
        reference: FortiPamDiscoveryEntryCreateHttpTransport,
        request: DisabledUnixDiscoveryCreateInput,
        claim_path: Path,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if (type(transport) is not FortiPamDiscoveryRunHttpTransport
                or type(reference) is not FortiPamDiscoveryEntryCreateHttpTransport
                or type(request) is not DisabledUnixDiscoveryCreateInput
                or _SOURCE.fullmatch(request.source_name) is None
                or not claim_path.is_absolute()):
            raise ValueError(_UNAVAILABLE)
        self._transport = transport
        self._reference = reference
        self._request = request
        self._claim = claim_path
        self._clock = clock or (lambda: int(time.time()))
        self._previews: dict[str, _Preview] = {}
        self._authorized: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self._validate_requester(requester_digest)
        with self._lock:
            reference_digest = self._inspect()
            preview_ref = "unix-discovery-run-preview-" + secrets.token_urlsafe(24)
            record = _Preview(requester_digest, reference_digest,
                              self._clock() + _TTL_SECONDS)
            self._previews[preview_ref] = record
        return {
            "contract": CONTRACT,
            "preview_ref": preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "bound_unix_secret_and_target_visible": True,
                "exact_source_disabled_and_unscanned": True,
            },
            "Proposed Changes": {
                "operation": "scan_one_bound_unix_target_once",
                "periodic_scanning": "disable",
                "auto_onboarding": "disable",
                "import": False,
            },
            "Expected State": {"exact_scan_timestamp": True},
            "device_write_executed": False,
        }

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._get_preview(preview_ref, requester_digest)
            if (record.authorization_ref is not None
                    or not hmac.compare_digest(record.reference_digest, self._inspect())):
                raise RuntimeError(_UNAVAILABLE)
            authorization_ref = "unix-discovery-run-authorized-" + secrets.token_urlsafe(24)
            self._previews[preview_ref] = _Preview(
                record.requester_digest, record.reference_digest,
                record.expires_at, authorization_ref,
            )
            self._authorized[authorization_ref] = preview_ref
        return {
            "contract": CONTRACT,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            preview_ref = self._authorized.get(authorization_ref)
            if preview_ref is None:
                raise RuntimeError(_UNAVAILABLE)
            record = self._get_preview(preview_ref, requester_digest)
            if (record.authorization_ref != authorization_ref
                    or not hmac.compare_digest(record.reference_digest, self._inspect())):
                raise RuntimeError(_UNAVAILABLE)
            self._reserve_claim(record.reference_digest)
            del self._authorized[authorization_ref]
        try:
            result = self._transport.run_once(self._request)
            verified = bool(result.dispatch == "accepted" and result.source_scanned
                            and result.auto_onboarding_disabled)
        except Exception:
            verified = False
        return {
            "contract": CONTRACT,
            "outcome": "succeeded" if verified else "reconciliation_required",
            "verification": "exact_scan_timestamp" if verified else "unknown",
            "one_shot_claim_consumed": True,
            "auto_onboarding_dispatched": False,
            "import_dispatched": False,
            "credential_values_returned": False,
            "raw_api_response_returned": False,
        }

    def _inspect(self) -> str:
        try:
            self._require_unconsumed()
            if not self._transport.inspect_unscanned(self._request):
                raise ValueError
            return self._reference.inspect_credential_reference(self._request)
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def _get_preview(self, preview_ref: str, requester_digest: str) -> _Preview:
        self._validate_requester(requester_digest)
        record = self._previews.get(preview_ref)
        if (record is None or self._clock() >= record.expires_at
                or not hmac.compare_digest(record.requester_digest, requester_digest)):
            raise RuntimeError(_UNAVAILABLE)
        return record

    @staticmethod
    def _validate_requester(value: str) -> None:
        if (not isinstance(value, str) or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)):
            raise RuntimeError(_UNAVAILABLE)

    def _require_unconsumed(self) -> None:
        info = self._claim.parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or self._claim.exists()):
            raise RuntimeError(_UNAVAILABLE)

    def _reserve_claim(self, reference_digest: str) -> None:
        self._require_unconsumed()
        try:
            fd = os.open(self._claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
            with os.fdopen(fd, "w") as output:
                json.dump({"contract": CONTRACT, "reference_digest": reference_digest,
                           "state": "post_attempt_reserved", "reserved_at": self._clock()},
                          output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
        except OSError:
            raise RuntimeError(_UNAVAILABLE) from None


class UnixDiscoveryRunMcpAction:
    def __init__(self, workflow: UnixDiscoveryRunLiveWorkflow,
                 *, execution_enabled: bool) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, principal: Any) -> dict[str, object]:
        try:
            return self._workflow.preview(requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        try:
            return self._workflow.confirm(preview_ref, requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise RuntimeError(_UNAVAILABLE)
        try:
            return self._workflow.execute(
                authorization_ref, requester_digest=_requester(principal),
            )
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None


def build_unix_discovery_run_candidate(
    environment: Mapping[str, str],
) -> UnixDiscoveryRunMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    if enabled not in {"true", "false"} or gate not in {"true", "false"}:
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        if gate == "true":
            raise ValueError(_UNAVAILABLE)
        return None
    try:
        binding_path = Path(environment[PREFIX + "BINDING_FILE"])
        claim_path = Path(environment[PREFIX + "CLAIM_FILE"])
        if not binding_path.is_absolute() or not claim_path.is_absolute():
            raise ValueError(_UNAVAILABLE)
        request = _load_binding(binding_path)
        config = load_secret_metadata_http_transport_config(environment)
        workflow = UnixDiscoveryRunLiveWorkflow(
            FortiPamDiscoveryRunHttpTransport(config),
            FortiPamDiscoveryEntryCreateHttpTransport(config),
            request, claim_path,
        )
        return UnixDiscoveryRunMcpAction(workflow, execution_enabled=gate == "true")
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def register_unix_discovery_run_candidate_tools(
    server: Any, action: UnixDiscoveryRunMcpAction,
) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    @server.mcp.tool(
        description="Preview one exact, previously unscanned Unix Discovery source.",
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def preview_v4_unix_discovery_run_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    @server.mcp.tool(
        description="Record requester-bound authorization for one Unix Discovery scan.",
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
    )
    async def confirm_v4_unix_discovery_run_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.confirm, preview_ref, server._v4_password_policy_action_principal(),
        )

    @server.mcp.tool(
        description="Run one exact Unix Discovery scan and verify its timestamp.",
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
    )
    async def execute_confirmed_v4_unix_discovery_run_700(
        authorization_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref,
            server._v4_password_policy_action_principal(),
        )


__all__ = [
    "CONTRACT", "UnixDiscoveryRunLiveWorkflow", "UnixDiscoveryRunMcpAction",
    "build_unix_discovery_run_candidate", "register_unix_discovery_run_candidate_tools",
]
