"""Default-off recovery of one independently reconciled Unix Discovery create."""
from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from typing import Any, Callable

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from .discovery_entry_live_workflow import CONTRACT as CREATE_CONTRACT, source_binding_digest
from .password_changer_mcp_action import _requester
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, load_secret_metadata_http_transport_config,
)

PREFIX = "FORTIPAM_MCP_V4_DISCOVERY_CLEANUP_700_"
CONTRACT = "fortipam_v4_unix_discovery_cleanup_700_candidate_v1"
BINDING_CONTRACT = "fortipam_v4_unix_discovery_cleanup_700_private_binding_v1"
_UNAVAILABLE = "FortiPAM V4 Unix Discovery cleanup is unavailable."


def _private_bytes(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096):
            raise ValueError(_UNAVAILABLE)
        content = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if len(content) > 4096:
        raise ValueError(_UNAVAILABLE)
    return content


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True, slots=True)
class _Intent:
    requester: str
    reference_digest: str
    expires_at: int
    authorization: str | None = None


class UnixDiscoveryCleanupLiveWorkflow:
    """Exact prior-create trace, immutable eligible record and one durable effect."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, request: DisabledUnixDiscoveryCreateInput,
        *, accepted_digest: str, creation_claim_sha256: str, creation_claim: Path,
        intent_claim: Path, cleanup_claim: Path, clock: Callable[[], int] | None = None,
    ) -> None:
        if (type(config) is not SecretMetadataHttpTransportConfig
                or type(request) is not DisabledUnixDiscoveryCreateInput
                or not _digest(accepted_digest) or not _digest(creation_claim_sha256)
                or any(not isinstance(p, Path) or not p.is_absolute()
                       for p in (creation_claim, intent_claim, cleanup_claim))
                or len({creation_claim, intent_claim, cleanup_claim}) != 3):
            raise ValueError(_UNAVAILABLE)
        self._config, self._request = config, request
        self._accepted_digest, self._creation_sha = accepted_digest, creation_claim_sha256
        self._creation_claim, self._intent_claim, self._cleanup_claim = creation_claim, intent_claim, cleanup_claim
        self._clock = clock or (lambda: int(time.time()))
        self._previews: dict[str, _Intent] = {}
        self._authorized: dict[str, str] = {}
        self._lock = threading.RLock()
        self._read_creation()

    def _read_creation(self) -> str:
        content = _private_bytes(self._creation_claim)
        if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), self._creation_sha):
            raise RuntimeError(_UNAVAILABLE)
        value = json.loads(content)
        if (not isinstance(value, dict)
                or set(value) != {"contract", "reference_digest", "source_binding_digest", "state", "reserved_at"}
                or value["contract"] != CREATE_CONTRACT or value["state"] != "post_attempt_reserved"
                or value["source_binding_digest"] != source_binding_digest(self._request)
                or not _digest(value["reference_digest"])
                or type(value["reserved_at"]) is not int or value["reserved_at"] <= 0):
            raise RuntimeError(_UNAVAILABLE)
        return str(value["reference_digest"])

    def _require_unconsumed(self) -> None:
        for path in (self._intent_claim, self._cleanup_claim):
            parent = path.parent.lstat()
            if (path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode)
                    or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700
                    or path.exists() or path.is_symlink()):
                raise RuntimeError(_UNAVAILABLE)

    def _inspect(self) -> tuple[FortiPamDiscoveryEntryCreateHttpTransport, str]:
        self._require_unconsumed()
        creation_reference = self._read_creation()
        transport = FortiPamDiscoveryEntryCreateHttpTransport.for_reconciled_cleanup(
            self._config, self._request, accepted_digest=self._accepted_digest, claim_path=self._cleanup_claim,
        )
        transport.inspect_bound_cleanup()
        reference = transport.inspect_credential_reference(self._request)
        if not hmac.compare_digest(reference, creation_reference):
            raise RuntimeError(_UNAVAILABLE)
        return transport, reference

    @staticmethod
    def _requester(value: str) -> None:
        if not _digest(value):
            raise RuntimeError(_UNAVAILABLE)

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self._requester(requester_digest)
        with self._lock:
            _, reference = self._inspect()
            ref = "unix-discovery-cleanup-preview-" + secrets.token_urlsafe(24)
            record = _Intent(requester_digest, reference, self._clock() + 600)
            self._previews[ref] = record
        return {"contract": CONTRACT, "preview_ref": ref, "expires_at": record.expires_at,
                "Current State": {"exact_prior_mcp_creation_trace_verified": True,
                                  "complete_accepted_record_unchanged": True,
                                  "bound_source_disabled_unscanned": True,
                                  "bound_secret_target_reference_preserved": True},
                "Proposed Changes": {"operation": "remove_the_bound_unscanned_disposable_unix_source",
                                     "scan_or_import": False, "credential_change": False},
                "Expected State": {"exact_source_absent": True, "cleanup_non_replayable": True},
                "device_write_executed": False}

    def _intent(self, ref: str, requester: str) -> _Intent:
        self._requester(requester)
        record = self._previews.get(ref)
        if (record is None or self._clock() >= record.expires_at
                or not hmac.compare_digest(record.requester, requester)):
            raise RuntimeError(_UNAVAILABLE)
        return record

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._intent(preview_ref, requester_digest)
            if record.authorization is not None or not hmac.compare_digest(record.reference_digest, self._inspect()[1]):
                raise RuntimeError(_UNAVAILABLE)
            self._intent(preview_ref, requester_digest)
            auth = "unix-discovery-cleanup-authorized-" + secrets.token_urlsafe(24)
            self._previews[preview_ref] = _Intent(record.requester, record.reference_digest, record.expires_at, auth)
            self._authorized[auth] = preview_ref
        return {"contract": CONTRACT, "authorization_ref": auth, "confirmation": "recorded",
                "execution": "authorized_once", "device_write_executed": False}

    def _reserve_intent(self, record: _Intent) -> None:
        self._require_unconsumed()
        parent = os.open(self._intent_claim.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
                raise RuntimeError(_UNAVAILABLE)
            fd = os.open(self._intent_claim.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            with os.fdopen(fd, "w") as output:
                json.dump({"contract": CONTRACT, "state": "cleanup_intent_reserved",
                           "requester_digest": record.requester, "reference_digest": record.reference_digest,
                           "accepted_record_digest": self._accepted_digest,
                           "prior_creation_claim_sha256": self._creation_sha,
                           "authorization_digest": hashlib.sha256(str(record.authorization).encode()).hexdigest()},
                          output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            ref = self._authorized.get(authorization_ref)
            if ref is None:
                raise RuntimeError(_UNAVAILABLE)
            record = self._intent(ref, requester_digest)
            transport, reference = self._inspect()
            if record.authorization != authorization_ref or not hmac.compare_digest(reference, record.reference_digest):
                raise RuntimeError(_UNAVAILABLE)
            self._intent(ref, requester_digest)
            self._reserve_intent(record)
            del self._authorized[authorization_ref]
            try:
                def before_dispatch() -> None:
                    self._intent(ref, requester_digest)

                result = transport.cleanup_bound_disposable(before_dispatch=before_dispatch)
                independent_absence = transport.inspect_current(self._request) is None
                success = result.verified and independent_absence
            except Exception:
                success = False
        return {"contract": CONTRACT, "outcome": "succeeded" if success else "reconciliation_required",
                "verification": "exact_source_absent" if success else "unknown",
                "authorization_claim_consumed": True, "transport_claim_consumed": self._cleanup_claim.is_file(),
                "scan_or_import_dispatched": False, "credential_values_returned": False,
                "raw_api_response_returned": False}


class UnixDiscoveryCleanupMcpAction:
    def __init__(self, workflow: UnixDiscoveryCleanupLiveWorkflow, *, execution_enabled: bool) -> None:
        self._workflow, self._execution_enabled = workflow, execution_enabled

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
            return self._workflow.execute(authorization_ref, requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None


def build_unix_discovery_cleanup_candidate(environment: Mapping[str, str]) -> UnixDiscoveryCleanupMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    if enabled not in {"true", "false"} or gate not in {"true", "false"} or enabled == "false" and gate == "true":
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        return None
    try:
        def path(suffix: str) -> Path:
            value = Path(environment[PREFIX + suffix])
            if not value.is_absolute():
                raise ValueError
            return value
        value = json.loads(_private_bytes(path("BINDING_FILE")))
        if (not isinstance(value, dict)
                or set(value) != {"contract", "source_name", "discovery_secret_id", "accepted_digest", "creation_claim_sha256"}
                or value["contract"] != BINDING_CONTRACT):
            raise ValueError
        workflow = UnixDiscoveryCleanupLiveWorkflow(
            load_secret_metadata_http_transport_config(environment),
            DisabledUnixDiscoveryCreateInput(value["source_name"], value["discovery_secret_id"]),
            accepted_digest=value["accepted_digest"], creation_claim_sha256=value["creation_claim_sha256"],
            creation_claim=path("CREATION_CLAIM_FILE"), intent_claim=path("INTENT_CLAIM_FILE"),
            cleanup_claim=path("CLAIM_FILE"),
        )
        return UnixDiscoveryCleanupMcpAction(workflow, execution_enabled=gate == "true")
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def register_unix_discovery_cleanup_tools(server: Any, action: UnixDiscoveryCleanupMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS

    @server.mcp.tool(description="Preview fixed recovery of one reconciled, unchanged, unscanned Unix Discovery fixture.",
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_unix_discovery_cleanup_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    @server.mcp.tool(description="Authorize the unchanged fixed Unix Discovery recovery for this requester once.",
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_unix_discovery_cleanup_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.confirm, preview_ref, server._v4_password_policy_action_principal())

    @server.mcp.tool(description="Remove only the bound unscanned Unix Discovery fixture once and verify exact absence.",
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_unix_discovery_cleanup_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_password_policy_action_principal())
