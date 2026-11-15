"""Private-bound build-29 Web Target C/P/E lifecycle; no MCP registration.

Selectors stay in the protected binding. The transport owns the durable claim;
volatile requester-bound references expire and cannot survive a restart.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hmac
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Protocol

from .target_contract import WebTargetCreateInput, WebTargetReadback

CONTRACT = "fortipam_700_web_target_create_workflow_v1"
_UNAVAILABLE = "The bound Web Target workflow is unavailable."


class WebTargetWorkflowError(RuntimeError):
    """Stable failure without selectors, native messages or private state."""


class WebTargetTransport(Protocol):
    def inspect_web_target_create(self, request: WebTargetCreateInput, *, claim_path: Path) -> str: ...

    def create_web_target_and_readback(
        self, request: WebTargetCreateInput, *, claim_path: Path,
        expected_state_digest: str, expires_at: int,
    ) -> WebTargetReadback: ...


@dataclass(slots=True, repr=False)
class _Record:
    requester: str
    digest: str
    expires_at: int
    authorization_ref: str | None = None
    state: str = "previewed"


class WebTargetLiveWorkflow:
    """One bound disposable Web Target, default-closed execution gate."""

    def __init__(
        self, transport: WebTargetTransport, request: WebTargetCreateInput, claim_path: Path,
        *, execution_enabled: bool = False, clock: Callable[[], int] | None = None,
    ) -> None:
        if (type(request) is not WebTargetCreateInput or not isinstance(claim_path, Path)
                or not claim_path.is_absolute() or type(execution_enabled) is not bool):
            raise WebTargetWorkflowError(_UNAVAILABLE)
        self._transport, self._request, self._claim_path = transport, request, claim_path
        self._execution_enabled = execution_enabled
        self._clock = clock or (lambda: int(time.time()))
        self._records: dict[str, _Record] = {}
        self._lock = threading.RLock()

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or now < 0:
            raise WebTargetWorkflowError(_UNAVAILABLE)
        return now

    def _inspect(self) -> str:
        value = self._transport.inspect_web_target_create(self._request, claim_path=self._claim_path)
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise WebTargetWorkflowError(_UNAVAILABLE)
        return value

    @staticmethod
    def _requester(value: str) -> None:
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise WebTargetWorkflowError(_UNAVAILABLE)

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        try:
            self._requester(requester_digest)
            with self._lock:
                now = self._now()
                self._records = {ref: record for ref, record in self._records.items()
                    if record.state in {"completed", "reconciliation_required"} or now < record.expires_at}
                if len(self._records) >= 32:
                    raise WebTargetWorkflowError(_UNAVAILABLE)
                digest = self._inspect()
                if self._now() >= now + 600:
                    raise WebTargetWorkflowError(_UNAVAILABLE)
                ref = "web-target-preview-" + secrets.token_urlsafe(24)
                self._records[ref] = _Record(requester_digest, digest, now + 600)
                return {"contract": CONTRACT, "preview_ref": ref, "expires_at": now + 600,
                    "Current State": {"bound_target_visible": False, "dependencies_verified": True,
                                      "product_version": "7.0.0", "product_build": 29},
                    "Proposed Changes": {"operation": "create_bound_web_target", "template": "Web Account",
                                         "proxy_enabled": False, "secret_write": False},
                    "Expected State": {"bound_target_exists": True, "url_relation_verified": True,
                                       "settings_verified": True, "permissions_verified": True},
                    "execution_gate_enabled": self._execution_enabled, "device_write_executed": False}
        except Exception:
            raise WebTargetWorkflowError(_UNAVAILABLE) from None

    def _get(self, ref: str, requester: str, *, authorized: bool) -> _Record:
        self._requester(requester)
        prefix = "web-target-authorized-" if authorized else "web-target-preview-"
        if type(ref) is not str or re.fullmatch(prefix + r"[A-Za-z0-9_-]{32}", ref) is None:
            raise WebTargetWorkflowError(_UNAVAILABLE)
        record = (next((r for r in self._records.values() if r.authorization_ref == ref), None)
                  if authorized else self._records.get(ref))
        if record is None or not hmac.compare_digest(record.requester, requester):
            raise WebTargetWorkflowError(_UNAVAILABLE)
        return record

    def _recheck(self, record: _Record) -> None:
        if self._now() >= record.expires_at:
            record.state = "invalidated"
            raise WebTargetWorkflowError(_UNAVAILABLE)
        if not hmac.compare_digest(self._inspect(), record.digest) or self._now() >= record.expires_at:
            record.state = "invalidated"
            raise WebTargetWorkflowError(_UNAVAILABLE)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                record = self._get(preview_ref, requester_digest, authorized=False)
                if record.state != "previewed":
                    raise WebTargetWorkflowError(_UNAVAILABLE)
                self._recheck(record)
                record.authorization_ref = "web-target-authorized-" + secrets.token_urlsafe(24)
                record.state = "authorized"
                return {"contract": CONTRACT, "authorization_ref": record.authorization_ref,
                        "expires_at": record.expires_at, "confirmation": "recorded",
                        "execution": "authorized_once", "device_write_executed": False}
        except Exception:
            raise WebTargetWorkflowError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                record = self._get(authorization_ref, requester_digest, authorized=True)
                if record.state in {"completed", "reconciliation_required"}:
                    return self._result(record, cached=True)
                if not self._execution_enabled or record.state != "authorized":
                    raise WebTargetWorkflowError(_UNAVAILABLE)
                self._recheck(record)
                record.state = "executing"
                try:
                    result = self._transport.create_web_target_and_readback(
                        self._request, claim_path=self._claim_path,
                        expected_state_digest=record.digest, expires_at=record.expires_at)
                    record.state = ("completed" if type(result) is WebTargetReadback and result.verified
                                    else "reconciliation_required")
                except Exception:
                    record.state = "reconciliation_required"
                return self._result(record, cached=False)
        except Exception:
            raise WebTargetWorkflowError(_UNAVAILABLE) from None

    @staticmethod
    def _result(record: _Record, *, cached: bool) -> dict[str, object]:
        return {"contract": CONTRACT, "state": record.state, "verified": record.state == "completed",
                "transport_invoked": True, "device_write_verified": record.state == "completed",
                "cached_result": cached}


def build_web_target_workflow(
    environment: Mapping[str, str], transport: WebTargetTransport,
) -> WebTargetLiveWorkflow | None:
    """Load one private binding; never read a selector from MCP arguments."""
    import json
    import os
    import stat

    prefix = "FORTIPAM_MCP_V4_WEB_TARGET_"
    try:
        if not isinstance(environment, Mapping):
            raise ValueError
        enabled = environment.get(prefix + "ENABLED", "false")
        execute = environment.get(prefix + "EXECUTION_ENABLED", "false")
        if enabled not in {"true", "false"} or execute not in {"true", "false"}:
            raise ValueError
        if enabled == "false":
            if execute == "true":
                raise ValueError
            return None
        path = Path(environment.get(prefix + "BINDING_FILE", ""))
        if not path.is_absolute():
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096):
                raise ValueError
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if len(raw) > 4096:
            raise ValueError
        binding = json.loads(raw)
        if (not isinstance(binding, dict) or set(binding) != {"contract", "target_name", "web_url"}
                or binding["contract"] != "fortipam_700_web_target_binding_v1"):
            raise ValueError
        request = WebTargetCreateInput(binding["target_name"], binding["web_url"])
        claim = Path(environment.get(prefix + "CLAIM_FILE", ""))
        if not claim.is_absolute() or claim == path:
            raise ValueError
        parent = claim.parent.lstat()
        if (claim.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ValueError
        return WebTargetLiveWorkflow(transport, request, claim, execution_enabled=execute == "true")
    except Exception:
        raise WebTargetWorkflowError(_UNAVAILABLE) from None
