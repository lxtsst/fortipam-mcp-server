"""Candidate-only OAuth/MCP boundary for one private-bound enabled Guest reset.

Preview/confirmation references are volatile and expire closed on restart.
The existing per-run M4 ledger and owner-only one-shot marker preserve dispatch
non-replay across restarts and competing workers. No tool accepts a target,
credential, material path, device address or writer identity.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hmac
import json
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any

from v4_planning import M4Compensation, M4ExecutionResult, M4Outcome, M4Verification

from .local_user_create_ssh_transport import load_local_user_create_ssh_transport_config
from .local_user_reset_api_actor import LocalUserResetApiActor
from .local_user_reset_execution import (
    FortiPamLocalUserResetExecution, LocalUserResetLabIntentVerifier, _mcp_requester_digest,
)
from .local_user_reset_http_transport import LocalUserResetBinding
from .local_user_reset_login_acceptance import finalize_verified_reset_login
from .local_user_reset_material_source import (
    OwnerOnlyLocalUserResetMaterialSource, _directory_identity, _read_manifest, _write_once,
)
from .local_user_reset_policy_reader import FortiPamLocalUserResetPolicyReader, LocalUserResetPolicySnapshot
from .local_user_reset_preview import FortiPamLocalUserResetPreviewReader, LocalUserResetPreflightPreview
from .local_user_reset_provenance_inspector import FortiPamLocalUserResetProvenanceInspector
from .local_user_reset_ssh_candidate import FortiPamLocalUserResetSshCandidate, LocalUserResetSshReadiness
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable, load_secret_metadata_http_transport_config

PREFIX = "FORTIPAM_MCP_V4_BP002_RESET_CANDIDATE_"
CONTRACT = "fortipam-700-build29-bound-local-user-reset-candidate-v1"
_UNAVAILABLE = "The bound Local User reset candidate is unavailable."
_PREVIEW = "bp002-reset-preview-"
_AUTHORIZATION = "bp002-reset-authorized-"
_MAX_RECORDS = 32
_LOGIN_REASONS = frozenset({"verified", "reset_unverified", "gate_closed", "precondition_failed",
    "already_attempted", "login_failed", "identity_failed", "logout_failed", "cleanup_failed",
    "persistence_failed"})


class LocalUserResetCandidateMcpError(RuntimeError):
    """Fixed failure without reflecting tool input or protected source details."""


@dataclass(slots=True, repr=False)
class _Record:
    preview_ref: str
    requester: str
    preview: LocalUserResetPreflightPreview
    policy: LocalUserResetPolicySnapshot
    writer_binding: str
    material_binding: str
    login_acceptance_enabled: bool
    authorization_ref: str | None = None
    result: M4ExecutionResult | None = None
    completion: dict[str, object] | None = None


class LocalUserResetCandidateMcpAction:
    """Bind one prepared material pair and one existing M4 store to MCP."""

    def __init__(
        self, candidate: FortiPamLocalUserResetSshCandidate, store: PersistentM4ExecutionStateStore,
        policy_reader: FortiPamLocalUserResetPolicyReader, *, execution_enabled: bool = False,
        login_acceptance_enabled: bool = False,
        clock: Callable[[], int] | None = None,
    ) -> None:
        try:
            if (type(candidate) is not FortiPamLocalUserResetSshCandidate
                or type(store) is not PersistentM4ExecutionStateStore
                or type(policy_reader) is not FortiPamLocalUserResetPolicyReader
                or policy_reader._config is not candidate._owner._config
                or type(execution_enabled) is not bool or type(login_acceptance_enabled) is not bool
                or clock is not None and not callable(clock)):
                raise ValueError
            source = candidate._material_provider
            if (store._path != source._reset / "execution.sqlite3"
                or store._key_path != source._reset / "execution.key"
                or execution_enabled and not all((candidate._enabled, source._enabled, candidate._owner._enabled))):
                raise ValueError
            store.verify_ready()
        except Exception:
            raise LocalUserResetCandidateMcpError(_UNAVAILABLE) from None
        self._candidate, self._store, self._policy_reader = candidate, store, policy_reader
        self._execution_enabled = execution_enabled
        self._login_acceptance_enabled = login_acceptance_enabled
        self._clock = clock or (lambda: int(time.time()))
        self._records: dict[str, _Record] = {}
        self._lock = threading.RLock()

    def _prune_records(self) -> None:
        now = self._clock()
        if type(now) is not int or now < 0:
            raise LocalUserResetCandidateMcpError(_UNAVAILABLE)
        for requester, record in tuple(self._records.items()):
            # Keep the terminal response replayable after its intent expires.
            # The global reservation allows at most one such cached result.
            if record.result is None and now >= record.preview.expires_at:
                del self._records[requester]

    def _available(self) -> bool:
        directory = self._candidate._material_provider._reset
        names: tuple[str, ...] = ("dispatch-invocation",)
        if self._login_acceptance_enabled:
            names += ("result.json", "login-invocation", "login-finalization.json", "acceptance.json")
        return not (self._store.claim_count or any(
            (directory / name).exists() or (directory / name).is_symlink() for name in names))

    def _preflight(self) -> tuple[LocalUserResetPreflightPreview, LocalUserResetPolicySnapshot, LocalUserResetSshReadiness]:
        candidate = self._candidate
        candidate._material_provider._verify_current_selection()
        readiness = candidate.inspect_readiness()
        policy = self._policy_reader.read_policy_snapshot()
        preview = FortiPamLocalUserResetPreviewReader(candidate._binding, candidate._inspector,
            policy, self._policy_reader, clock=self._clock).read_preview()
        return preview, policy, readiness

    def preview(self, principal: object) -> dict[str, object]:
        try:
            requester = _mcp_requester_digest(principal)
            with self._lock:
                self._prune_records()
                if not self._available():
                    return {"contract": CONTRACT, "state": "not_ready", "can_confirm": False,
                            "gaps": ["execution_reserved_or_consumed"], "device_write_executed": False}
                record = self._records.get(requester)
                if record is None and len(self._records) >= _MAX_RECORDS:
                    return {"contract": CONTRACT, "state": "not_ready", "can_confirm": False,
                            "gaps": ["preview_capacity_exhausted"], "device_write_executed": False}
                preview, policy, readiness = self._preflight()
                confirmed = record if record is not None and record.authorization_ref is not None else None
                unchanged = confirmed is not None and self._matches(confirmed, preview, policy)
                if confirmed is not None and unchanged:
                    # Return the exact confirmed C/P/E and original expiry.
                    # A read must neither revoke nor extend existing authority.
                    preview = confirmed.preview
                result = preview.as_dict()
                current = result["Current State"]
                if type(current) is not dict:
                    raise ValueError
                current.update(status="enable", access_profile="Guest")
                result.update(contract=CONTRACT, state="previewed" if readiness.ready else "not_ready",
                    can_confirm=readiness.ready, execution_gate_enabled=self._execution_enabled,
                    login_acceptance_mode=("one_private_attempt" if self._login_acceptance_enabled else "separate"),
                    device_identity_verified=readiness.device_identity_matches,
                    writer_role_qualified=readiness.writer_qualified,
                    gaps=(["device_identity_unverified"] if not readiness.device_identity_matches else
                          [] if readiness.writer_qualified else ["writer_role_unqualified"]))
                if readiness.ready:
                    if confirmed is not None:
                        result.update(can_confirm=False, confirmation="recorded")
                        if unchanged:
                            result["preview_ref"] = confirmed.preview_ref
                        else:
                            result.update(state="not_ready", gaps=["confirmed_preview_changed"])
                    else:
                        record = _Record(_PREVIEW + secrets.token_urlsafe(24), requester, preview, policy,
                            self._candidate._writer_binding_digest(), self._candidate._material_provider._binding_digest,
                            self._login_acceptance_enabled)
                        self._records[requester] = record
                        result["preview_ref"] = record.preview_ref
                elif confirmed is None:
                    self._records.pop(requester, None)
                return result
        except Exception:
            raise LocalUserResetCandidateMcpError(_UNAVAILABLE) from None

    def _get(self, ref: str, principal: object, *, authorized: bool) -> _Record:
        self._prune_records()
        requester = _mcp_requester_digest(principal)
        record = self._records.get(requester)
        prefix = _AUTHORIZATION if authorized else _PREVIEW
        if (type(ref) is not str or re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9_-]{32}", ref) is None
            or record is None or not hmac.compare_digest(record.requester, requester)
            or ref != (record.authorization_ref if authorized else record.preview_ref)):
            raise LocalUserResetCandidateMcpError(_UNAVAILABLE)
        return record

    def _matches(self, record: _Record, current: LocalUserResetPreflightPreview,
                 policy: LocalUserResetPolicySnapshot) -> bool:
        return (self._login_acceptance_enabled is record.login_acceptance_enabled
            and current.current_state_digest == record.preview.current_state_digest
            and policy == record.policy and current.guest_auth == record.preview.guest_auth
            and self._candidate._writer_binding_digest() == record.writer_binding
            and self._candidate._material_provider._binding_digest == record.material_binding)

    def _recheck(self, record: _Record) -> None:
        if not self._available() or not record.preview.observed_at <= self._clock() < record.preview.expires_at:
            raise LocalUserResetCandidateMcpError(_UNAVAILABLE)
        current, policy, readiness = self._preflight()
        if (not readiness.ready or not self._matches(record, current, policy)
            or self._clock() >= record.preview.expires_at or not self._available()):
            raise LocalUserResetCandidateMcpError(_UNAVAILABLE)

    def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
        try:
            with self._lock:
                record = self._get(preview_ref, principal, authorized=False)
                if record.authorization_ref is not None:
                    raise ValueError
                self._recheck(record)
                record.authorization_ref = _AUTHORIZATION + secrets.token_urlsafe(24)
                return {"contract": CONTRACT, "preview_ref": record.preview_ref,
                        "authorization_ref": record.authorization_ref, "confirmation": "recorded",
                        "execution": "authorized_once", "expires_at": record.preview.expires_at,
                        "device_write_executed": False}
        except Exception:
            raise LocalUserResetCandidateMcpError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
        try:
            with self._lock:
                record = self._get(authorization_ref, principal, authorized=True)
                if record.result is not None:
                    self._store.verify_ready()
                    return self._response(record, replay=True)
                if not self._execution_enabled:
                    raise ValueError
                self._recheck(record)
                candidate = self._candidate
                with candidate._owner.authenticated():
                    intent, verifier = LocalUserResetLabIntentVerifier.issue(
                        binding=candidate._binding, inspector=candidate._inspector, actor=candidate._owner,
                        material_source=candidate._material_provider, policy_snapshot=record.policy,
                        policy_inspector=self._policy_reader, preview=record.preview, now_epoch=self._clock(),
                        ssh_candidate=candidate, mcp_principal=principal)
                    if intent.requester_digest != record.requester:
                        raise ValueError
                    runner = FortiPamLocalUserResetExecution(candidate, self._store, intent=intent,
                        authenticated_requester_digest=record.requester, authorized_scope_digest=intent.scope_digest,
                        authorization_verifier=verifier, policy_snapshot=record.policy,
                        policy_inspector=self._policy_reader, preflight_preview=record.preview,
                        enabled=True, clock=self._clock)
                    marker = bytearray(json.dumps({"contract": CONTRACT, "plan_ref": intent.plan_ref,
                        "context_digest": runner._context}, sort_keys=True).encode())
                    try:
                        source = candidate._material_provider
                        source._reserve_transition_once()
                        _write_once(source._reset, source._reset_id, "dispatch-invocation", marker)
                    finally:
                        _zeroize_mutable(marker)
                    try:
                        record.result = runner.execute()
                    except Exception:
                        record.result = M4ExecutionResult(M4Outcome.RECONCILIATION_REQUIRED,
                            M4Verification.UNKNOWN, M4Compensation.UNKNOWN, False)
                if record.login_acceptance_enabled:
                    record.completion = self._complete_login(record.result)
                return self._response(record, replay=False)
        except Exception:
            raise LocalUserResetCandidateMcpError(_UNAVAILABLE) from None

    @staticmethod
    def _result(result: M4ExecutionResult, *, replay: bool) -> dict[str, object]:
        return {**result.as_dict(), "contract": CONTRACT, "idempotent_replay": replay,
                "password_write_acknowledged": result.outcome is M4Outcome.SUCCEEDED,
                "password_change_confirmed": False,
                "current_login_reconciliation_required": True,
                "login_verified": False, "credential_values_returned": False, "raw_cli_returned": False}

    def _complete_login(self, result: M4ExecutionResult) -> dict[str, object]:
        """Persist the write result, then run the existing one-attempt acceptance."""
        completion: dict[str, object] = {"outcome": "reconciliation_required",
            "reason": "reset_unverified", "login_post_attempted": False,
            "login_verified": False, "logout_verified": False, "current_binding_updated": False}
        if result.outcome is not M4Outcome.SUCCEEDED or result.verification is not M4Verification.VERIFIED:
            return completion
        source = self._candidate._material_provider
        content = bytearray()
        try:
            completion["reason"] = "persistence_failed"
            content.extend(json.dumps(self._result(result, replay=False), sort_keys=True).encode())
            _write_once(source._reset, source._reset_id, "result.json", content)
            _zeroize_mutable(content)
            completion = finalize_verified_reset_login(source, self._store, self._candidate._owner._config,
                enabled=True, clock=self._clock)
            content = bytearray(json.dumps(completion, sort_keys=True).encode())
            _write_once(source._reset, source._reset_id, "login-finalization.json", content)
        except Exception:
            completion.update(outcome="reconciliation_required", reason="persistence_failed")
        finally:
            _zeroize_mutable(content)
        return completion

    def _response(self, record: _Record, *, replay: bool) -> dict[str, object]:
        assert record.result is not None
        result = self._result(record.result, replay=replay)
        completion = record.completion
        if completion is not None:
            reason = completion.get("reason")
            reason = reason if type(reason) is str and reason in _LOGIN_REASONS else "verification_unavailable"
            complete = (completion.get("outcome") == "succeeded"
                and all(completion.get(key) is True for key in
                        ("login_verified", "logout_verified", "current_binding_updated")))
            result.update(write_outcome=record.result.outcome.value,
                outcome="succeeded" if complete else "reconciliation_required",
                verification="verified" if complete else "unknown",
                password_change_confirmed=completion.get("login_verified") is True,
                login_verified=completion.get("login_verified") is True,
                current_binding_updated=completion.get("current_binding_updated") is True,
                current_login_reconciliation_required=not complete,
                login_acceptance_reason=reason,
                login_acceptance="verified" if complete else "reconciliation_required")
        return result


def build_local_user_reset_candidate(environment: Mapping[str, str]) -> LocalUserResetCandidateMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    login = environment.get(PREFIX + "LOGIN_ACCEPTANCE_ENABLED", "false")
    if (any(value not in {"true", "false"} for value in (enabled, gate, login))
        or enabled == "false" and (gate == "true" or login == "true")):
        raise LocalUserResetCandidateMcpError(_UNAVAILABLE)
    if enabled == "false":
        return None
    try:
        fixture, reset = (Path(environment[PREFIX + suffix]) for suffix in ("FIXTURE_DIRECTORY", "RESET_DIRECTORY"))
        _directory_identity(fixture)
        reset_id = _directory_identity(reset)
        config = load_secret_metadata_http_transport_config(environment)
        inspector = FortiPamLocalUserResetProvenanceInspector(config, fixture_directory=fixture,
            api_principal=environment[PREFIX + "API_PRINCIPAL"], issue_enabled=False)
        binding = LocalUserResetBinding(inspector.read_nonmaterial_baseline())
        digest, _ = _read_manifest(reset, reset_id, binding.expected.fixture_creation_digest)
        source = OwnerOnlyLocalUserResetMaterialSource.from_current_login_binding(
            fixture_directory=fixture, reset_directory=reset, binding=binding, inspector=inspector,
            expected_binding_digest=digest, enabled=gate == "true")
        actor = LocalUserResetApiActor(config, binding=binding, inspector=inspector, enabled=gate == "true")
        candidate = FortiPamLocalUserResetSshCandidate(config,
            ssh_config=load_local_user_create_ssh_transport_config(environment), binding=binding,
            inspector=inspector, owner_session=actor, material_lease_provider=source,
            device_identity_digest=inspector._metadata.read_device_identity_digest(), enabled=gate == "true")
        return LocalUserResetCandidateMcpAction(candidate,
            PersistentM4ExecutionStateStore(reset / "execution.sqlite3", reset / "execution.key"),
            FortiPamLocalUserResetPolicyReader(config), execution_enabled=gate == "true",
            login_acceptance_enabled=login == "true")
    except Exception:
        raise LocalUserResetCandidateMcpError(_UNAVAILABLE) from None


def register_local_user_reset_candidate_tools(server: Any, action: LocalUserResetCandidateMcpAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS

    @server.mcp.tool(description="Preview the bound enabled Local User password reset and its readiness; no device write.", annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_bound_local_user_reset() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    @server.mcp.tool(description="Confirm the unchanged bound Local User reset preview using operation authority.", annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_bound_local_user_reset(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.confirm, preview_ref, server._v4_folder_action_principal())

    @server.mcp.tool(description="Execute one confirmed bound Local User reset through the durable candidate; returns no password.", annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_bound_local_user_reset(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_folder_action_principal())

    # These candidate tools are registered after the HTTP host's initial
    # hardening pass. Keep their published schemas strict as well; the existing
    # host wrapper continues to sanitize validation failures without values.
    for name in ("preview_v4_bound_local_user_reset", "confirm_v4_bound_local_user_reset",
                 "execute_confirmed_v4_bound_local_user_reset"):
        tool = server.mcp._tool_manager.get_tool(name)
        model = tool.fn_metadata.arg_model
        model.model_config["extra"] = "forbid"
        model.model_rebuild(force=True)
        schema = model.model_json_schema()
        if schema.get("additionalProperties") is not False:
            raise LocalUserResetCandidateMcpError(_UNAVAILABLE)
        tool.parameters = schema
