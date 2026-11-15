"""Private build29 WAD window with caller binding and persistent M4 custody.

This is constructor-only lab composition. It registers no Tool, changes no
environment builder and cannot import or renew an earlier capture attempt.
Cleanup is an intrinsic postcondition, including on failure and cancellation.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
from threading import RLock
import time
from typing import Any

from v4_planning import (M4AdapterAmbiguous, M4AdapterDenied, M4ClaimState,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest)
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.models import require_digest, require_ref

from .m4_execution_store import PersistentM4ExecutionStateStore, _assert_no_symlink_components
from .v4_plan_runtime import V4PlanningPrincipal
from .ztna_wad_debug_mcp_action import ProtectedZtnaWadDebugMcpAction
from .ztna_wad_debug_ssh_transport import (FortiPamZtnaWadDebugSshTransport, ZtnaWadDebugReadback,
    _M4_ACTION, _M4_ADAPTER, _M4_VERSION)

CONTRACT = "fortipam-build29-wad-debug-lab-m4-v2"
_ERROR = "The private bounded WAD diagnostic is unavailable."
_DOMAIN = b"fortipam-build29-wad-debug-lab-m4/v2\0"


class WadDebugM4Error(ValueError):
    """Fixed refusal without diagnostic data, private selectors or credentials."""


class ProtectedBuild29WadDebugM4Action(ProtectedZtnaWadDebugMcpAction):
    """The existing three-Tool protocol, one fixed authenticated lab caller."""

    def __init__(self, transport: FortiPamZtnaWadDebugSshTransport, *,
            execution_store: PersistentM4ExecutionStateStore, authority_key: bytes,
            state_directory: Path, requester_digest: str, transport_digest: str,
            environment_ref: str, scope_ref: str, audience_ref: str,
            execution_enabled: bool = False, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(transport) is not FortiPamZtnaWadDebugSshTransport
                    or transport._build29_serial_digest is None
                    or transport._config.capture_window_seconds != 10 or transport._config.timeout_seconds != 20
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 128
                    or hmac.compare_digest(authority_key, execution_store._key)
                    or type(execution_enabled) is not bool or not callable(clock)):
                raise ValueError
            for digest in (requester_digest, transport_digest): require_digest(digest, "caller")
            for ref in (environment_ref, scope_ref, audience_ref): require_ref(ref, "namespace")
            self._transport, self._store, self._key = transport, execution_store, authority_key
            self._directory = state_directory
            self._directory_pin = self._directory_identity()
            self._identity = requester_digest, transport_digest
            self._namespace = environment_ref, scope_ref, audience_ref
            self._execution_enabled, self._clock = execution_enabled, clock
            self._last = -1
            self._inspect = transport.inspect
            self._capture = transport.capture_m4_owned
            self._source_pin = self._source_context()
            self._state = "new"
            self._preview_ref = ""
            self._preview_expires = 0
            self._phase: _Capture | None = None
            self._lock = RLock()
            self._store.verify_ready()
        except Exception:
            raise WadDebugM4Error(_ERROR) from None

    def _directory_identity(self) -> tuple[int, int]:
        if not self._directory.is_absolute(): raise ValueError
        _assert_no_symlink_components(self._directory)
        value = self._directory.lstat()
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid()
                or stat.S_IMODE(value.st_mode) != 0o700): raise ValueError
        return value.st_dev, value.st_ino

    def _source_context(self) -> str:
        config = self._transport._config
        config.__post_init__()
        return self._mac("native-source", (self._namespace, self._identity,
            config.host, config.port, config.username, hashlib.sha256(config.password.encode()).hexdigest(),
            str(config.known_hosts_file), hashlib.sha256(config.known_hosts_file.read_bytes()).hexdigest(),
            config.timeout_seconds, config.capture_window_seconds, self._transport._build29_serial_digest))

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\0" +
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()

    def _local(self) -> None:
        if (self._directory_identity() != self._directory_pin or self._source_context() != self._source_pin
                or self._transport.inspect != self._inspect or self._transport.capture_m4_owned != self._capture):
            raise ValueError
        self._store.verify_ready()

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0 or value < self._last: raise ValueError
        self._last = value
        return value

    def _caller(self, principal: V4PlanningPrincipal) -> None:
        if (type(principal) is not V4PlanningPrincipal
                or (principal.requester.digest, principal.transport_namespace_digest) != self._identity):
            raise ValueError
        self._local()

    def _unconsumed(self) -> None:
        if os.path.lexists(self._directory / "capture.attempt"): raise ValueError

    def preview(self, principal: Any) -> dict[str, object]:
        with self._lock:
            try:
                self._caller(principal); self._unconsumed()
                if self._state != "new" or self._inspect().debug_is_disabled is not True: raise ValueError
                self._preview_ref = "ztna-wad-debug-preview-" + secrets.token_urlsafe(24)
                self._preview_expires = self._now() + 60
                self._state = "previewed"
                return dict(contract=CONTRACT, preview_ref=self._preview_ref, expires_at=self._preview_expires,
                    **{"Current State": dict(global_debug_state="disabled", device_and_build_qualified=True),
                       "Proposed Changes": dict(operation="fixed_wad_diagnostic", capture_window_seconds=10,
                           operation_timeout_seconds=20, cleanup_timeout_seconds=5, cli_close_timeout_seconds=1,
                           categories="secret_gateway_svc_conn", mandatory_same_session_cleanup=True),
                       "Expected State": dict(global_debug_state="disabled", categorical_result_only=True)},
                    device_write_executed=False)
            except Exception:
                raise WadDebugM4Error(_ERROR) from None

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        with self._lock:
            try:
                self._caller(principal); self._unconsumed()
                if (not self._execution_enabled or self._state != "previewed" or preview_ref != self._preview_ref
                        or self._now() >= self._preview_expires):
                    raise ValueError
                self._state = "confirming"
                if self._inspect().debug_is_disabled is not True: raise ValueError
                self._phase = _Capture(self, self._now())
                self._state = "authorized"
                return dict(contract=CONTRACT, preview_ref=self._preview_ref,
                    authorization_ref=self._phase.authorization.authorization_ref, confirmation="recorded",
                    execution="authorized_once", expires_at=self._phase.expires_at, device_write_executed=False)
            except Exception:
                if self._state == "confirming": self._state = "failed"
                raise WadDebugM4Error(_ERROR) from None

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        with self._lock:
            try:
                self._caller(principal); self._unconsumed()
                phase = self._phase
                if (not self._execution_enabled or self._state != "authorized" or phase is None
                        or authorization_ref != phase.authorization.authorization_ref): raise ValueError
                phase.check()
                self._state = "executing"
                phase.reserve()
                result = M4ExecutionKernel(phase, phase, self._store, clock=self._now).execute(
                    phase.plan, phase.authorization).as_dict()
                self._state = "complete" if result["outcome"] == "succeeded" else "failed"
                readback = phase.readback
                return dict(contract=CONTRACT, **result,
                    global_debug_cleanup_confirmed=readback.cleanup_confirmed if readback else False,
                    device_context_state=readback.device_context_state if readback else "unknown",
                    device_tag_match_state=readback.device_tag_match_state if readback else "unknown",
                    launch_authorization_state=readback.launch_authorization_state if readback else "unknown",
                    raw_cli_returned=False, identity_tag_target_secret_or_session_data_returned=False,
                    persistent_configuration_changed=False, device_write_executed=phase.dispatched)
            except Exception:
                if self._state == "executing": self._state = "failed"
                raise WadDebugM4Error(_ERROR) from None

    def close(self) -> None:
        # Never hold the execution lock here: closing a Gate cannot cancel or
        # obstruct the transport's already-required cleanup.
        self._execution_enabled, self._key = False, b""


class _Capture:
    def __init__(self, owner: ProtectedBuild29WadDebugM4Action, now: int) -> None:
        self.owner, self.created_at, self.expires_at = owner, now, now + 60
        self.nonce = secrets.token_hex(24)
        self.authorized = self.dispatched = False
        self.readback: ZtnaWadDebugReadback | None = None
        self.marker: bytes | None = None
        self.marker_identity: tuple[int, int] | None = None
        self.plan, self.authorization = self.derive()

    def state(self, *, captured: bool, disabled: bool = True) -> str:
        return canonical_digest(dict(contract=CONTRACT, source=self.owner._source_pin,
            captured=captured, global_debug_disabled=disabled))

    def derive(self) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        owner = self.owner
        context = dict(contract=CONTRACT, namespace=owner._namespace, caller=owner._identity,
            source=owner._source_pin, preview=owner._preview_ref, nonce=self.nonce,
            created=self.created_at, expires=self.expires_at)
        values: dict[str, Any] = dict(plan_ref="wad-m4-plan-" + owner._mac("plan", context), revision=1,
            action_id=_M4_ACTION, action_version=_M4_VERSION, adapter_ref=_M4_ADAPTER,
            target_ref="wad-bound-device-" + owner._mac("target", owner._source_pin)[:40],
            requester_digest=owner._identity[0], summary_digest=owner._mac("summary", context),
            confirmation_digest=owner._mac("standing-intent", context), approval_digest=owner._mac("lab-policy", context),
            parameters_digest=canonical_digest(context), expected_current_digest=self.state(captured=False),
            expected_state_digest=self.state(captured=True), idempotency_digest=owner._mac("once", context),
            expires_at=self.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        signed = dict(context, plan=plan.plan_digest)
        auth: dict[str, Any] = dict(authorization_ref="wad-m4-auth-" + owner._mac("authorization", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="wad-m4-intent-" + owner._mac("intent", signed), confirmation_digest=plan.confirmation_digest,
            approval_ref="wad-m4-policy-" + owner._mac("policy", signed), approval_digest=plan.approval_digest,
            approver_digest=owner._mac("authority", owner._namespace), issued_at=self.created_at,
            expires_at=self.expires_at, one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth))

    def check(self) -> None:
        owner = self.owner
        owner._local()
        if (not owner._execution_enabled or owner._phase is not self
                or owner._state not in {"authorized", "executing"}
                or not self.created_at <= owner._now() < self.expires_at
                or (self.plan, self.authorization) != self.derive()): raise ValueError
        if self.marker is not None:
            directory, fd = os.open(owner._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW), None
            try:
                if (os.fstat(directory).st_dev, os.fstat(directory).st_ino) != owner._directory_pin: raise ValueError
                fd = os.open("capture.attempt", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                value = os.fstat(fd)
                if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_nlink != 1
                        or stat.S_IMODE(value.st_mode) != 0o600 or value.st_size != len(self.marker)
                        or (value.st_dev, value.st_ino) != self.marker_identity
                        or os.read(fd, len(self.marker) + 1) != self.marker): raise ValueError
                after = os.fstat(fd)
                linked = os.stat("capture.attempt", dir_fd=directory, follow_symlinks=False)
                stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
                if (any(getattr(after, field) != getattr(value, field) for field in stable)
                        or (linked.st_dev, linked.st_ino) != self.marker_identity): raise ValueError
            finally:
                if fd is not None: os.close(fd)
                os.close(directory)

    def reserve(self) -> None:
        self.check(); self.owner._unconsumed()
        self.marker = self.owner._mac("attempt", (self.plan.plan_digest, self.authorization.authorization_digest)).encode()
        directory = os.open(self.owner._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if (os.fstat(directory).st_dev, os.fstat(directory).st_ino) != self.owner._directory_pin: raise ValueError
            fd = os.open("capture.attempt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "wb") as stream:
                stream.write(self.marker); stream.flush(); os.fsync(stream.fileno())
                value = os.fstat(stream.fileno()); self.marker_identity = value.st_dev, value.st_ino
            os.fsync(directory)
        finally: os.close(directory)

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        self.check()
        if (self.authorized or plan is not self.plan or authorization is not self.authorization
                or not self.created_at <= now_epoch <= self.owner._now() < self.expires_at): raise ValueError
        claim = self.owner._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest, authorization_digest=authorization.authorization_digest,
            context_digest=canonical_digest(dict(authorization_digest=authorization.authorization_digest,
                plan_digest=plan.plan_digest, revision=plan.revision)))
        if claim.state is not M4ClaimState.IN_PROGRESS: raise ValueError
        self.authorized = True

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self.check()
            if not self.authorized or plan is not self.plan: raise ValueError
            return self.state(captured=False, disabled=self.owner._inspect().debug_is_disabled is True)
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        try:
            self.check()
            if not self.authorized or self.dispatched or plan is not self.plan: raise ValueError
            _require_m4_dispatch_ownership(plan, self.authorization, self.owner._store)
            self.dispatched = True
            readback = self.owner._capture(plan, self.authorization, self.owner._store, clock=self._dispatch_clock)
            if (type(readback) is not ZtnaWadDebugReadback
                    or type(readback.capture_collected) is not bool or type(readback.cleanup_confirmed) is not bool
                    or readback.device_context_state not in {"unknown", "missing", "available", "inconclusive"}
                    or readback.device_tag_match_state not in {"unknown", "matched", "not_observed"}
                    or readback.launch_authorization_state not in {"unknown", "allowed", "not_observed"}): raise ValueError
            self.readback = readback
            if not readback.verified: raise ValueError
        except Exception:
            if self.dispatched: raise M4AdapterAmbiguous(_ERROR) from None
            raise M4AdapterDenied(_ERROR) from None

    def _dispatch_clock(self) -> int:
        self.check()
        return self.owner._now()

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self.check()
            if (plan is not self.plan or not self.dispatched or self.readback is None
                    or not self.readback.verified): raise ValueError
            return self.state(captured=True, disabled=self.owner._inspect().debug_is_disabled is True)
        except Exception: raise M4AdapterAmbiguous(_ERROR) from None
