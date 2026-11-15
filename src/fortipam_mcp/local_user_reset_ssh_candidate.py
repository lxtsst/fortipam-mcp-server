"""Private build-29 known-old/new SSH fallback; no MCP registration or role change.

The same durable runner owns intent and the fixed API policy check. SSH uses a
separately pinned writer, matches the device identity across address aliases,
and rechecks its qualified role on the connection which performs the write.
Success proves CLI acknowledgement and
complete non-material preservation; actual login remains separate evidence.
"""

from __future__ import annotations

from collections.abc import Callable
import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import threading
import time
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from .local_user_create_ssh_transport import LocalUserCreateSshTransportConfig
from .cli_safety import _extract_prompt, _raise_for_remote_rejection
from .local_user_reset_api_actor import LocalUserResetApiActor
from .local_user_reset_http_transport import (
    FortiPamLocalUserResetHttpTransport, LocalUserResetBaseline, LocalUserResetBinding,
    LocalUserResetMaterialLease, _dispose_password,
)
from .local_user_reset_material_source import OwnerOnlyLocalUserResetMaterialSource
from .local_user_reset_metadata_reader import _device_identity_digest
from .local_user_reset_provenance_inspector import FortiPamLocalUserResetProvenanceInspector
from .local_user_reset_ssh_transport import (
    FortiPamLocalUserResetSshTransport, LocalUserResetSshTransportError,
    _context_prompt, _reset_command, _run_sync, _user_name,
)
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable
from .target_ssh_transport import _close_cli, _require_root_prompt

_UNAVAILABLE = "The private Local User SSH reset candidate is unavailable."


async def _read_ssh_device_identity(process: Any, prompt: bytes, deadline: float) -> str:
    """Read one fixed status command with at most four observed pager advances."""
    content = bytearray()
    pages = 0
    try:
        process.stdin.write(b"get system status\n")
        await process.stdin.drain()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError
            chunk = await asyncio.wait_for(process.stdout.read(4096), timeout=remaining)
            if not isinstance(chunk, bytes) or not chunk or len(content) + len(chunk) > 65536:
                raise ValueError
            content.extend(chunk)
            try:
                current_prompt = _extract_prompt(bytes(content))
            except Exception:
                current_prompt = None
            if current_prompt is not None:
                _require_root_prompt(prompt, current_prompt)
                _raise_for_remote_rejection(bytes(content))
                serials = re.findall(rb"^Serial(?:-| )Number:[ \t]*([A-Za-z0-9-]{8,64})[ \t]*$",
                    content.replace(b"\r", b""), re.MULTILINE | re.IGNORECASE)
                if len(serials) != 1:
                    raise ValueError
                return _device_identity_digest(serials[0])
            markers = content.count(b"--More--")
            if markers > pages:
                if markers != pages + 1 or pages >= 4:
                    raise ValueError
                pages += 1
                process.stdin.write(b" ")
                await process.stdin.drain()
    finally:
        _zeroize_mutable(content)


class LocalUserResetSshCandidateError(RuntimeError):
    """Fixed failure without private selectors, connection errors or material."""

@dataclass(frozen=True, slots=True)
class LocalUserResetSshReadiness:
    device_identity_matches: bool
    writer_qualified: bool

    @property
    def ready(self) -> bool:
        return self.device_identity_matches and self.writer_qualified



@dataclass(frozen=True, slots=True)
class LocalUserResetSshCandidateResult:
    outcome: Literal["gate_closed", "precondition_failed", "policy_rejected",
                     "reconciliation_required", "succeeded"]
    write_attempted: bool = False
    cli_acknowledged: bool = False
    metadata_preserved: bool = False
    reason: Literal["unavailable", "writer_unqualified", "state_changed",
                    "device_mismatch", "policy_rejected", "cli_rejected", "readback_failed", "verified"] = "unavailable"


class FortiPamLocalUserResetSshCandidate:
    """Reset one bound enabled local Guest through the existing durable runner."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, *,
        ssh_config: LocalUserCreateSshTransportConfig, binding: LocalUserResetBinding,
        inspector: FortiPamLocalUserResetProvenanceInspector, owner_session: LocalUserResetApiActor,
        material_lease_provider: OwnerOnlyLocalUserResetMaterialSource,
        device_identity_digest: str, enabled: bool = False,
    ) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                or type(ssh_config) is not LocalUserCreateSshTransportConfig
                or type(binding) is not LocalUserResetBinding
                or type(inspector) is not FortiPamLocalUserResetProvenanceInspector
                or type(owner_session) is not LocalUserResetApiActor
                or type(material_lease_provider) is not OwnerOnlyLocalUserResetMaterialSource
                or type(enabled) is not bool or type(device_identity_digest) is not str
                or re.fullmatch(r"[a-f0-9]{64}", device_identity_digest) is None):
                raise ValueError
            binding.__post_init__()
            ssh_config.__post_init__()
            origin = urlsplit(config.base_url)
            port = 443 if origin.port is None else origin.port
            if (origin.scheme != "https" or not origin.hostname or not 1 <= port <= 65535
                or origin.username is not None or origin.password is not None
                or origin.path not in {"", "/"} or origin.query or origin.fragment
                or type(ssh_config.port) is not int
                or ssh_config.username.casefold() == binding.expected.username.casefold()
                or binding.expected.status != "enable" or binding.expected.access_profile != "Guest"
                or binding.expected.guest_auth != "disable"
                or inspector._config is not config or owner_session._config is not config
                or owner_session._binding is not binding or owner_session._inspector is not inspector
                or material_lease_provider._binding is not binding
                or material_lease_provider._inspector is not inspector):
                raise ValueError
            _user_name(binding.expected.username)
        except Exception:
            raise LocalUserResetSshCandidateError(_UNAVAILABLE) from None
        self._host, self._port = origin.hostname, port
        self._binding, self._inspector, self._owner = binding, inspector, owner_session
        self._material_provider = material_lease_provider
        self._ssh_config = ssh_config
        self._device_identity_digest = device_identity_digest
        self._ssh = FortiPamLocalUserResetSshTransport(ssh_config)
        self._enabled, self._consumed, self._lock = enabled, False, threading.Lock()

    def _writer_binding_digest(self) -> str:
        """Bind identity, endpoint and trust file; never hash a password."""
        try:
            config = self._ssh_config
            config.__post_init__()
            if (type(self._ssh) is not FortiPamLocalUserResetSshTransport
                or self._ssh._config is not config
                or config.known_hosts_file.stat().st_size > 65536):
                raise ValueError
            return hashlib.sha256(json.dumps({
                "transport": "bp002-ssh-known-old-new-build29/v1",
                "host": config.host, "port": config.port, "writer": config.username,
                "device_identity": self._device_identity_digest,
                "host_keys": hashlib.sha256(config.known_hosts_file.read_bytes()).hexdigest(),
            }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        except Exception:
            raise LocalUserResetSshCandidateError(_UNAVAILABLE) from None

    def inspect_writer(self) -> bool:
        """Read current writer qualification without acquiring reset material."""
        return self.inspect_readiness().ready

    def inspect_readiness(self) -> LocalUserResetSshReadiness:
        """Distinguish device identity from writer-role qualification."""
        try:
            self._writer_binding_digest()
            return cast(LocalUserResetSshReadiness, _run_sync(self._inspect_readiness()))
        except Exception:
            raise LocalUserResetSshCandidateError(_UNAVAILABLE) from None

    async def _inspect_readiness(self) -> LocalUserResetSshReadiness:
        async with self._ssh._connection() as connection:
            process, prompt, deadline = await self._ssh._open_cli(connection)
            try:
                device_matches = await self._same_device(process, prompt, deadline)
                writer_qualified = (device_matches and await self._ssh._writer_qualified(process, prompt,
                    time.monotonic() + self._ssh_config.timeout_seconds))
                return LocalUserResetSshReadiness(device_matches, writer_qualified)
            finally:
                await _close_cli(process)

    async def _same_device(self, process: object, prompt: bytes, deadline: float) -> bool:
        observed = await _read_ssh_device_identity(process, prompt, deadline)
        return (hmac.compare_digest(observed, self._device_identity_digest)
                and hmac.compare_digest(self._inspector._metadata.read_device_identity_digest(),
                                        self._device_identity_digest))

    def _unchanged(self) -> bool:
        current = self._inspector.read_nonmaterial_baseline()
        if type(current) is not LocalUserResetBaseline:
            return False
        LocalUserResetBinding(current)
        return current == self._binding.expected

    def reset(self) -> LocalUserResetSshCandidateResult:
        """Direct calls cannot supply the durable runner's verified authority."""
        return self._reset_with_dispatch_guard(lambda: None)

    def _authority_active(self, guard: Callable[[], None]) -> bool:
        from .local_user_reset_execution import FortiPamLocalUserResetExecution, LocalUserResetLabIntentVerifier

        runner = getattr(guard, "__self__", None)
        verifier = getattr(runner, "_verifier", None)
        return not (type(runner) is not FortiPamLocalUserResetExecution
            or type(verifier) is not LocalUserResetLabIntentVerifier
            or not runner._claim_active or not verifier._verified
            or runner._transport is not self or runner._dispatch_callback is not guard
            or self._owner._runtime_guard is not guard
            or not self._owner._active(self._owner._generation))

    def _reset_with_dispatch_guard(self, guard: Callable[[], None]) -> LocalUserResetSshCandidateResult:
        if not self._authority_active(guard):
            return LocalUserResetSshCandidateResult("gate_closed")
        with self._lock:
            if not self._enabled or self._consumed:
                return LocalUserResetSshCandidateResult("gate_closed")
            self._consumed = True
        return cast(LocalUserResetSshCandidateResult, _run_sync(self._dispatch(guard)))

    async def _dispatch(self, guard: Callable[[], None]) -> LocalUserResetSshCandidateResult:
        if not self._enabled or not self._consumed or not self._authority_active(guard):
            return LocalUserResetSshCandidateResult("gate_closed")
        old = new = None
        command = bytearray()
        attempted = acknowledged = False
        try:
            guard()
            if not self._unchanged():
                return LocalUserResetSshCandidateResult("precondition_failed", reason="state_changed")
            async with self._ssh._connection() as connection:
                process, prompt, deadline = await self._ssh._open_cli(connection)
                try:
                    if not await self._same_device(process, prompt, deadline):
                        return LocalUserResetSshCandidateResult("precondition_failed", reason="device_mismatch")
                    deadline = time.monotonic() + self._ssh_config.timeout_seconds
                    await self._ssh._require_writer(process, prompt, deadline)
                    guard()
                    lease = self._material_provider()
                    if type(lease) is not LocalUserResetMaterialLease:
                        raise ValueError
                    old, new = lease._consume()
                    if any(re.fullmatch(rb"[A-Za-z0-9_!@#$%^&*+=.,:?-]{8,128}", value) is None
                           for value in (old, new)):
                        raise ValueError
                    policy = FortiPamLocalUserResetHttpTransport(self._owner._config,
                        binding=self._binding, inspector=self._inspector, owner_session=self._owner,
                        material_lease_provider=self._material_provider, enabled=False)
                    if not policy._post("policy_conform", old, new, guard):
                        return LocalUserResetSshCandidateResult("policy_rejected", reason="policy_rejected")
                    guard()
                    if not self._unchanged():
                        return LocalUserResetSshCandidateResult("precondition_failed", reason="state_changed")
                    deadline = time.monotonic() + self._ssh_config.timeout_seconds
                    if not await self._same_device(process, prompt, deadline):
                        return LocalUserResetSshCandidateResult("precondition_failed", reason="device_mismatch")
                    deadline = time.monotonic() + self._ssh_config.timeout_seconds
                    await self._ssh._require_writer(process, prompt, deadline)
                    guard()
                    deadline = time.monotonic() + self._ssh_config.timeout_seconds
                    await _reset_command(process, "config system admin", prompt, deadline,
                                         "enter_admin", _context_prompt(prompt))
                    # A concurrent deletion can make CLI edit start a new entry.
                    # Treat that point as potentially mutable and reconcile any
                    # uncertainty; never send a password to a reported new entry.
                    attempted = True
                    await _reset_command(process, f'edit "{self._binding.expected.username}"',
                                         prompt, deadline, "select_target")
                    guard()
                    if not self._authority_active(guard):
                        raise ValueError
                    command.extend(b'set password "')
                    command.extend(new)
                    command.extend(b'" "')
                    command.extend(old)
                    command.extend(b'"')
                    deadline = time.monotonic() + self._ssh_config.timeout_seconds
                    await _reset_command(process, command, prompt, deadline, "set_password")
                    await _reset_command(process, "next", prompt, deadline, "commit_target")
                    returned = await _reset_command(process, "end", prompt, deadline, "leave_admin")
                    _require_root_prompt(prompt, returned)
                    acknowledged = True
                finally:
                    await _close_cli(process)
            if self._unchanged():
                return LocalUserResetSshCandidateResult("succeeded", True, True, True, "verified")
            return LocalUserResetSshCandidateResult("reconciliation_required", True, True, False, "readback_failed")
        except LocalUserResetSshTransportError as error:
            if not attempted and error.reason == "actor_unqualified":
                return LocalUserResetSshCandidateResult("precondition_failed", reason="writer_unqualified")
            return LocalUserResetSshCandidateResult(
                "reconciliation_required" if attempted else "precondition_failed",
                attempted, acknowledged, False, "cli_rejected")
        except Exception:
            return LocalUserResetSshCandidateResult(
                "reconciliation_required" if attempted else "precondition_failed",
                attempted, acknowledged, False, "readback_failed" if acknowledged else "unavailable")
        finally:
            _zeroize_mutable(command)
            for value in (old, new):
                if value is not None:
                    _dispose_password(value)
