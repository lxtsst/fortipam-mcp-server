"""Private, default-off durable guard for the build-29 BP002 reset candidates.

This reuses the existing persistent M4 ledger, not its two-person authorization
issuer. The trusted lab client must verify real authenticated intent, exact
C/P/E, protected Owner identity and new-fixture provenance. A supplied digest
or callback registration alone is not such evidence. Nothing is registered in
MCP or promoted to a supported live reset workflow by this module.

SUCCEEDED means only backend_changed_metadata_preserved. It never proves login,
password delivery or recovery. Unknown outcomes never trigger compensation or
replay. Whole-snapshot rollback detection needs the store's existing independent
checkpoint binding; ordinary restart protection alone does not prove that.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, fields, replace
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from typing import Protocol

from v4_planning import (
    M4AuditEvent, M4ClaimState, M4Compensation, M4ExecutionError,
    M4ExecutionResult, M4Outcome, M4Verification, canonical_digest,
)
from v4_planning.material_provider import C3MaterialBinding

from .local_user_reset_http_transport import (
    FortiPamLocalUserResetHttpTransport, LocalUserResetBinding,
    LocalUserResetHttpOutcome, LocalUserResetHttpResult,
)
from .local_user_reset_api_actor import LocalUserResetApiActor
from .local_user_reset_ssh_candidate import FortiPamLocalUserResetSshCandidate, LocalUserResetSshCandidateResult
from .local_user_reset_material_source import OwnerOnlyLocalUserResetMaterialSource
from .local_user_reset_policy_reader import (
    FortiPamLocalUserResetPolicyReader, LocalUserResetPolicySnapshot,
)
from .local_user_reset_preview import LocalUserResetPreflightPreview, _baseline_digest
from .local_user_reset_provenance_inspector import FortiPamLocalUserResetProvenanceInspector
from .m4_execution_store import PersistentM4ExecutionStateStore

_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_DOMAIN = "bp002-local-user-reset-http-700-build29/v1"
_UNAVAILABLE = "The private Local User reset execution candidate is unavailable."
_LAB_ISSUER = object()


def _mcp_requester_digest(principal: object) -> str:
    from .v4_plan_runtime import V4PlanningPrincipal

    if type(principal) is not V4PlanningPrincipal:
        raise LocalUserResetExecutionError(_UNAVAILABLE)
    principal.__post_init__()
    return hashlib.sha256(("bp002-mcp-requester/v1\0" + principal.requester.digest
                           + "\0" + principal.transport_namespace_digest).encode()).hexdigest()


class LocalUserResetExecutionError(RuntimeError):
    """Fixed non-disclosing error for an invalid private composition."""


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetRunIntent(C3MaterialBinding):
    """Trusted-client input binding, not an authorization or record issuer."""

    plan_ref: str
    requester_digest: str
    authorization_digest: str
    idempotency_digest: str
    summary_digest: str
    scope_digest: str
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        if (
            type(self.plan_ref) is not str or _REF.fullmatch(self.plan_ref) is None
            or any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in (
                self.requester_digest, self.authorization_digest, self.idempotency_digest,
                self.summary_digest, self.scope_digest,
            ))
            or type(self.issued_at) is not int or type(self.expires_at) is not int
            or self.issued_at < 0 or not 0 < self.expires_at - self.issued_at <= 300
        ):
            raise LocalUserResetExecutionError(_UNAVAILABLE)


class LocalUserResetIntentVerifier(Protocol):
    """Verify the existing client's exact one-time authority, after the claim.

The context digest covers the fixed candidate version, complete baseline,
fixture-creation evidence, origin, requester/scope and full intent. The verifier
must match that context to actual protected authenticated records; it must not
accept a model assertion or manufacture a separate approver.
"""

    def verify(
        self, intent: LocalUserResetRunIntent, *, context_digest: str, now_epoch: int,
    ) -> bool: ...


class LocalUserResetPolicyInspector(Protocol):
    def read_policy_snapshot(self) -> LocalUserResetPolicySnapshot: ...


class LocalUserResetLabIntentVerifier:
    """One in-process technical intent from the authenticated lab API actor.

    The durable M4 claim is consumed before ``verify``. A crash after claiming
    never permits reconstruction or replay of this volatile authority.
    """

    def __init__(
        self, intent: LocalUserResetRunIntent, *, binding: LocalUserResetBinding,
        inspector: FortiPamLocalUserResetProvenanceInspector,
        actor: LocalUserResetApiActor,
        material_source: OwnerOnlyLocalUserResetMaterialSource,
        policy_snapshot: LocalUserResetPolicySnapshot,
        policy_inspector: FortiPamLocalUserResetPolicyReader,
        preview: LocalUserResetPreflightPreview,
        issuer: object,
        ssh_candidate: FortiPamLocalUserResetSshCandidate | None = None,
        ssh_writer_binding: str | None = None,
    ) -> None:
        if issuer is not _LAB_ISSUER:
            raise LocalUserResetExecutionError(_UNAVAILABLE)
        self._intent, self._binding, self._inspector = intent, binding, inspector
        self._actor, self._material_source = actor, material_source
        self._policy, self._policy_inspector, self._preview = policy_snapshot, policy_inspector, preview
        self._ssh_candidate, self._ssh_writer_binding = ssh_candidate, ssh_writer_binding
        self._context: str | None = None
        self._consumed = self._verified = False
        self._lock = threading.Lock()

    @classmethod
    def issue(
        cls, *, binding: LocalUserResetBinding,
        inspector: FortiPamLocalUserResetProvenanceInspector,
        actor: LocalUserResetApiActor,
        material_source: OwnerOnlyLocalUserResetMaterialSource,
        policy_snapshot: LocalUserResetPolicySnapshot,
        policy_inspector: FortiPamLocalUserResetPolicyReader,
        preview: LocalUserResetPreflightPreview,
        now_epoch: int,
        ssh_candidate: FortiPamLocalUserResetSshCandidate | None = None,
        mcp_principal: object | None = None,
    ) -> tuple[LocalUserResetRunIntent, LocalUserResetLabIntentVerifier]:
        """Issue only inside an active exact-actor session after fresh C/P/E."""
        try:
            if (
                type(binding) is not LocalUserResetBinding
                or type(inspector) is not FortiPamLocalUserResetProvenanceInspector
                or type(actor) is not LocalUserResetApiActor
                or type(material_source) is not OwnerOnlyLocalUserResetMaterialSource
                or type(policy_snapshot) is not LocalUserResetPolicySnapshot
                or type(policy_inspector) is not FortiPamLocalUserResetPolicyReader
                or type(preview) is not LocalUserResetPreflightPreview
                or type(now_epoch) is not int
                or actor._config is not inspector._config
                or policy_inspector._config is not inspector._config
                or actor._binding is not binding or actor._inspector is not inspector
                or material_source._binding is not binding
                or material_source._inspector is not inspector
                or not actor._enabled or not actor._active(actor._generation)
                or not material_source._enabled
                or preview.guest_auth != "disable"
                or not preview.observed_at <= now_epoch < preview.expires_at
                or policy_snapshot.digest != preview.policy_digest
                or _baseline_digest(binding.expected) != preview.current_state_digest
            ):
                raise ValueError
            if inspector.read_nonmaterial_baseline() != binding.expected:
                raise ValueError
            if policy_inspector.read_policy_snapshot() != policy_snapshot:
                raise ValueError
            material_source._verify_current_selection()
            ssh_writer_binding = None
            if ssh_candidate is not None:
                if (type(ssh_candidate) is not FortiPamLocalUserResetSshCandidate
                    or ssh_candidate._binding is not binding or ssh_candidate._inspector is not inspector
                    or ssh_candidate._owner is not actor or ssh_candidate._material_provider is not material_source
                    or not ssh_candidate._enabled or not ssh_candidate.inspect_writer()):
                    raise ValueError
                ssh_writer_binding = ssh_candidate._writer_binding_digest()
            nonce = secrets.token_hex(32)
            requester = hashlib.sha256(("bp002-api-requester/v1\0" + inspector._principal).encode()).hexdigest()
            api_requester = requester
            if mcp_principal is not None:
                requester = _mcp_requester_digest(mcp_principal)
            scope = hashlib.sha256(("bp002-fixture-scope/v1\0" +
                binding.expected.fixture_creation_digest + "\0" + actor._config.base_url
                + ("\0api-actor:" + api_requester if mcp_principal is not None else "")).encode()).hexdigest()
            intent = LocalUserResetRunIntent(
                plan_ref="bp002-local-user-reset-" + secrets.token_hex(16),
                requester_digest=requester,
                authorization_digest=hashlib.sha256(("bp002-lab-intent/v1\0" + nonce + "\0" +
                    preview.summary_digest + "\0" + material_source._binding_digest
                    + ("\0ssh:" + ssh_writer_binding if ssh_writer_binding is not None else "")).encode()).hexdigest(),
                idempotency_digest=hashlib.sha256(("bp002-once/v1\0" + nonce).encode()).hexdigest(),
                summary_digest=preview.summary_digest, scope_digest=scope,
                issued_at=now_epoch, expires_at=min(now_epoch + 300, preview.expires_at),
            )
            intent.__post_init__()
            return intent, cls(intent, binding=binding, inspector=inspector, actor=actor,
                material_source=material_source, policy_snapshot=policy_snapshot,
                policy_inspector=policy_inspector, preview=preview, issuer=_LAB_ISSUER,
                ssh_candidate=ssh_candidate, ssh_writer_binding=ssh_writer_binding)
        except Exception:
            raise LocalUserResetExecutionError(_UNAVAILABLE) from None

    def _bind_context(self, context_digest: str) -> None:
        with self._lock:
            if self._context is not None or _DIGEST.fullmatch(context_digest) is None:
                raise LocalUserResetExecutionError(_UNAVAILABLE)
            self._context = context_digest

    def verify(self, intent: LocalUserResetRunIntent, *, context_digest: str,
               now_epoch: int) -> bool:
        with self._lock:
            if self._consumed:
                return False
            self._consumed = True
            try:
                if (
                    intent is not self._intent or self._context is None
                    or not hmac.compare_digest(context_digest, self._context)
                    or type(now_epoch) is not int
                    or not intent.issued_at <= now_epoch < intent.expires_at
                    or not self._actor._active(self._actor._generation)
                    or self._inspector.read_nonmaterial_baseline() != self._binding.expected
                    or self._policy_inspector.read_policy_snapshot() != self._policy
                    or self._preview.summary_digest != intent.summary_digest
                    or self._material_source._binding is not self._binding
                ):
                    return False
                self._verified = True
                return True
            except Exception:
                return False


def _not_started(outcome: M4Outcome = M4Outcome.DENIED) -> M4ExecutionResult:
    return M4ExecutionResult(outcome, M4Verification.NOT_STARTED, M4Compensation.NOT_REQUESTED, False)


def _unknown(*, replay: bool = False) -> M4ExecutionResult:
    return M4ExecutionResult(
        M4Outcome.RECONCILIATION_REQUIRED, M4Verification.UNKNOWN, M4Compensation.UNKNOWN, replay,
    )


class FortiPamLocalUserResetExecution:
    """Execute one constructor-bound intent; accept no material or selectors."""

    def __init__(
        self, transport: FortiPamLocalUserResetHttpTransport | FortiPamLocalUserResetSshCandidate,
        execution_store: PersistentM4ExecutionStateStore, *, intent: LocalUserResetRunIntent,
        authenticated_requester_digest: str, authorized_scope_digest: str,
        authorization_verifier: LocalUserResetIntentVerifier | None = None,
        policy_snapshot: LocalUserResetPolicySnapshot | None = None,
        policy_inspector: LocalUserResetPolicyInspector | None = None,
        preflight_preview: LocalUserResetPreflightPreview | None = None,
        enabled: bool = False, clock: Callable[[], int] | None = None,
    ) -> None:
        try:
            if (
                type(transport) not in {FortiPamLocalUserResetHttpTransport, FortiPamLocalUserResetSshCandidate}
                or type(execution_store) is not PersistentM4ExecutionStateStore
                or type(intent) is not LocalUserResetRunIntent or type(enabled) is not bool
                or any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in (
                    authenticated_requester_digest, authorized_scope_digest,
                ))
                or (authorization_verifier is not None and not callable(getattr(authorization_verifier, "verify", None)))
                or (policy_snapshot is None) != (policy_inspector is None)
                or (enabled and policy_snapshot is None)
                or (policy_snapshot is not None and type(policy_snapshot) is not LocalUserResetPolicySnapshot)
                or (policy_inspector is not None and not callable(getattr(policy_inspector, "read_policy_snapshot", None)))
                or (preflight_preview is not None and type(preflight_preview) is not LocalUserResetPreflightPreview)
                or (clock is not None and not callable(clock))
            ):
                raise ValueError
            intent.__post_init__()
            LocalUserResetBinding(transport._binding.expected)
            if preflight_preview is not None:
                preflight_preview.__post_init__()
                if (policy_snapshot is None
                    or transport._binding.expected.guest_auth != "disable"
                    or not hmac.compare_digest(intent.summary_digest, preflight_preview.summary_digest)
                    or not hmac.compare_digest(preflight_preview.policy_digest, policy_snapshot.digest)
                    or not hmac.compare_digest(preflight_preview.current_state_digest,
                                               _baseline_digest(transport._binding.expected))
                    or not preflight_preview.observed_at <= intent.issued_at < intent.expires_at
                    or intent.expires_at > preflight_preview.expires_at):
                    raise ValueError
            material_source = transport._material_provider
            if (isinstance(material_source, OwnerOnlyLocalUserResetMaterialSource)
                and (material_source._binding is not transport._binding
                     or material_source._inspector is not transport._inspector)):
                raise ValueError
            if isinstance(material_source, OwnerOnlyLocalUserResetMaterialSource) and enabled:
                if (type(policy_inspector) is not FortiPamLocalUserResetPolicyReader
                    or (policy_inspector._host, policy_inspector._port)
                    != (transport._host, transport._port)
                    or type(transport._owner) is not LocalUserResetApiActor
                    or policy_inspector._config is not transport._owner._config):
                    raise ValueError
                if (type(transport._owner) is not LocalUserResetApiActor
                    or type(authorization_verifier) is not LocalUserResetLabIntentVerifier
                    or authorization_verifier._intent is not intent
                    or authorization_verifier._binding is not transport._binding
                    or authorization_verifier._inspector is not transport._inspector
                    or authorization_verifier._actor is not transport._owner
                    or authorization_verifier._material_source is not material_source
                    or authorization_verifier._policy != policy_snapshot
                    or authorization_verifier._policy_inspector is not policy_inspector
                    or authorization_verifier._preview is not preflight_preview
                    or not hmac.compare_digest(intent.requester_digest, authenticated_requester_digest)
                    or not hmac.compare_digest(intent.scope_digest, authorized_scope_digest)):
                    raise ValueError
                if type(transport) is FortiPamLocalUserResetSshCandidate:
                    if (authorization_verifier._ssh_candidate is not transport
                        or authorization_verifier._ssh_writer_binding != transport._writer_binding_digest()):
                        raise ValueError
                elif authorization_verifier._ssh_candidate is not None:
                    raise ValueError
            self._transport, self._state, self._intent = transport, execution_store, intent
            self._requester, self._scope = authenticated_requester_digest, authorized_scope_digest
            self._policy_expected, self._policy_inspector = policy_snapshot, policy_inspector
            self._preview = preflight_preview
            self._preview_tuple = (
                tuple(getattr(preflight_preview, field.name) for field in fields(preflight_preview))
                if preflight_preview is not None else None
            )
            self._components = (transport._binding, transport._inspector, transport._owner,
                                transport._material_provider, policy_inspector)
            self._context = self._context_digest()
            self._dispatch_callback = self._dispatch_guard
            if isinstance(material_source, OwnerOnlyLocalUserResetMaterialSource) and enabled:
                assert type(authorization_verifier) is LocalUserResetLabIntentVerifier
                authorization_verifier._bind_context(self._context)
                assert type(transport._owner) is LocalUserResetApiActor
                transport._owner._runtime_guard = self._dispatch_callback
        except Exception:
            raise LocalUserResetExecutionError(_UNAVAILABLE) from None
        self._verifier, self._enabled = authorization_verifier, enabled
        self._clock = (lambda: int(time.time())) if clock is None else clock
        self._last_time: int | None = None
        self._lock = threading.Lock()
        self._claim_active = False

    def _context_digest(self) -> str:
        transport, intent = self._transport, self._intent
        # This is the protected non-material binding, not a C0-C2 planner
        # projection. Preserve exact empty relation values and exact Unicode;
        # the planning canonicalizer intentionally rejects/normalizes them.
        payload = {
            "candidate": _DOMAIN,
            "intent": {field.name: getattr(intent, field.name) for field in fields(intent)},
            "origin": {"host": transport._host, "port": transport._port},
            "baseline": {field.name: getattr(transport._binding.expected, field.name)
                         for field in fields(transport._binding.expected)},
            # An opaque signed-manifest commitment, never the new material
            # digest, private locator or C3 bytes. Synthetic callbacks stay
            # unbound and cannot qualify a real trusted client.
            "material_binding": (
                transport._material_provider._binding_digest
                if isinstance(transport._material_provider, OwnerOnlyLocalUserResetMaterialSource)
                else "unbound"
            ),
            "policy": self._policy_expected.digest if self._policy_expected is not None else "unbound",
            "preflight": self._preview.summary_digest if self._preview is not None else "unbound",
        }
        if type(transport) is FortiPamLocalUserResetSshCandidate:
            payload["candidate"] = "bp002-local-user-reset-ssh-700-build29/v1"
            payload["ssh_writer"] = transport._writer_binding_digest()
        return hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")).hexdigest()

    def _guard(self) -> int:
        intent, transport = self._intent, self._transport
        intent.__post_init__()
        LocalUserResetBinding(transport._binding.expected)
        if self._preview is not None:
            self._preview.__post_init__()
            if (self._preview_tuple != tuple(
                    getattr(self._preview, field.name) for field in fields(self._preview))
                or not hmac.compare_digest(intent.summary_digest, self._preview.summary_digest)
                or not hmac.compare_digest(self._preview.current_state_digest,
                                           _baseline_digest(transport._binding.expected))):
                raise LocalUserResetExecutionError(_UNAVAILABLE)
        if (
            self._enabled is not True or transport._enabled is not True
            or not hmac.compare_digest(intent.requester_digest, self._requester)
            or not hmac.compare_digest(intent.scope_digest, self._scope)
            or any(current is not bound for current, bound in zip(
                (transport._binding, transport._inspector, transport._owner,
                 transport._material_provider, self._policy_inspector),
                self._components, strict=True,
            ))
            or not hmac.compare_digest(self._context_digest(), self._context)
        ):
            raise LocalUserResetExecutionError(_UNAVAILABLE)
        if isinstance(transport._material_provider, OwnerOnlyLocalUserResetMaterialSource):
            transport._material_provider._verify_current_selection()
        now = self._clock()
        if (
            type(now) is not int or not intent.issued_at <= now < intent.expires_at
            or (self._preview is not None and now >= self._preview.expires_at)
            or (self._last_time is not None and now < self._last_time)
        ):
            raise LocalUserResetExecutionError(_UNAVAILABLE)
        if self._policy_expected is not None:
            assert self._policy_inspector is not None
            current_policy = self._policy_inspector.read_policy_snapshot()
            if (type(current_policy) is not LocalUserResetPolicySnapshot
                or not hmac.compare_digest(current_policy.digest, self._policy_expected.digest)
                or current_policy != self._policy_expected):
                raise LocalUserResetExecutionError(_UNAVAILABLE)
            after_read = self._clock()
            if (type(after_read) is not int or after_read < now
                or after_read >= intent.expires_at):
                raise LocalUserResetExecutionError(_UNAVAILABLE)
            now = after_read
        self._last_time = now
        return now

    def _dispatch_guard(self) -> None:
        self._guard()

    def execute(self) -> M4ExecutionResult:
        if not self._enabled or self._verifier is None:
            return _not_started()
        if not self._lock.acquire(blocking=False):
            return _unknown(replay=True)
        try:
            return self._execute_once()
        finally:
            self._claim_active = False
            self._lock.release()

    def _execute_once(self) -> M4ExecutionResult:
        try:
            self._guard()
        except Exception:
            return _not_started()
        intent = self._intent
        try:
            claim = self._state.claim(
                plan_ref=intent.plan_ref, requester_digest=intent.requester_digest,
                idempotency_digest=intent.idempotency_digest, context_digest=self._context,
                authorization_digest=intent.authorization_digest,
            )
        except M4ExecutionError:
            return _not_started()
        except Exception:
            # A claim may have committed before a checkpoint/error was observed.
            return _unknown()
        if claim.state is M4ClaimState.REPLAY:
            return replace(claim.result, idempotent_replay=True) if claim.result is not None else _unknown(replay=True)
        if claim.state is not M4ClaimState.NEW:
            return _unknown(replay=True)

        verified = False
        try:
            self._claim_active = True
            now = self._guard()
            assert self._verifier is not None
            # Consume existing authority only after the durable reservation.
            verified = self._verifier.verify(intent, context_digest=self._context, now_epoch=now) is True
            if verified:
                self._guard()
                result = _translate(self._transport._reset_with_dispatch_guard(self._dispatch_callback))
            else:
                result = _not_started()
        except Exception:
            result = _unknown() if verified else _not_started()
        try:
            self._state.finalize(
                plan_ref=intent.plan_ref, requester_digest=intent.requester_digest,
                idempotency_digest=intent.idempotency_digest, context_digest=self._context,
                result=result, event=M4AuditEvent(
                    0, "verified" if verified else "denied", result.outcome, result.verification,
                    result.compensation, canonical_digest({"context": self._context, "result": result.as_dict()}),
                ),
            )
        except Exception:
            # Never expose success if terminal persistence is uncertain.
            return _unknown()
        return result


def _translate(value: LocalUserResetHttpResult | LocalUserResetSshCandidateResult) -> M4ExecutionResult:
    if type(value) is LocalUserResetSshCandidateResult:
        if any(type(flag) is not bool for flag in (
            value.write_attempted, value.cli_acknowledged, value.metadata_preserved,
        )):
            return _unknown()
        if value.outcome == "succeeded" and all((
            value.write_attempted, value.cli_acknowledged, value.metadata_preserved,
        )):
            return M4ExecutionResult(M4Outcome.SUCCEEDED, M4Verification.VERIFIED, M4Compensation.NOT_REQUESTED, False)
        if value.write_attempted or value.cli_acknowledged or value.metadata_preserved:
            return _unknown()
        outcomes = {"gate_closed": M4Outcome.DENIED, "precondition_failed": M4Outcome.PRECONDITION_FAILED,
                    "policy_rejected": M4Outcome.EXECUTION_FAILED}
        return _not_started(outcomes[value.outcome]) if value.outcome in outcomes else _unknown()
    if type(value) is not LocalUserResetHttpResult or any(type(flag) is not bool for flag in (
        value.backend_changed, value.metadata_preserved, value.change_post_attempted, value.login_verified,
    )) or value.login_verified:
        return _unknown()
    if value.outcome is LocalUserResetHttpOutcome.BACKEND_CHANGED_METADATA_PRESERVED:
        if value.backend_changed and value.metadata_preserved and value.change_post_attempted:
            return M4ExecutionResult(M4Outcome.SUCCEEDED, M4Verification.VERIFIED, M4Compensation.NOT_REQUESTED, False)
        return _unknown()
    if value.backend_changed or value.metadata_preserved or value.change_post_attempted:
        return _unknown()
    outcomes = {
        LocalUserResetHttpOutcome.GATE_CLOSED: M4Outcome.DENIED,
        LocalUserResetHttpOutcome.DRIFT_REJECTED: M4Outcome.PRECONDITION_FAILED,
        LocalUserResetHttpOutcome.POLICY_REJECTED: M4Outcome.EXECUTION_FAILED,
    }
    return _not_started(outcomes[value.outcome]) if value.outcome in outcomes else _unknown()
