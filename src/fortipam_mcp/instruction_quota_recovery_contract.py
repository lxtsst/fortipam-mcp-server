"""Inactive incident baseline-correction compiler and postcondition contract.

This is a distinct action candidate over an unresolved original restoration.
It reuses only the fixed two-field serializer and capacity predicates, never
the original writer or lab-auto authority. No policy, receipt, dispatch, Tool,
startup, finalization or incident closure is implemented here.
"""
from __future__ import annotations

from v4_planning import canonical_digest

from .instruction_quota_contract import (
    InstructionQuotaState, InstructionQuotaTransition, _Private,
    build_instruction_quota_body, verify_instruction_quota_readback,
)
from .instruction_quota_reconciliation import (
    InstructionQuotaBaselineRecoveryDraft, InstructionQuotaRestoreReconciler,
)
from .instruction_resource_usage import InstructionResourceUsage

CONTRACT = "fortipam-700-build29-instruction-quota-incident-baseline-correction-v1"
ACTION = "instruction-quota-incident-baseline-correction"
VERSION = "1.0.0"
ADAPTER = "fortipam-700-build29-instruction-quota-incident-baseline-correction-v1"
REQUIRED_POLICY = "instruction-quota-unresolved-restore-baseline-correction@1.0.0"
_ERROR = "The private Instruction quota incident correction contract is unavailable."


class InstructionQuotaRecoveryContractError(ValueError):
    """Fixed value-free refusal without a partial body or result."""


class InstructionQuotaBaselineRecoveryCandidate(_Private):
    """Immutable private comparison/serialization binding, never permission."""

    __slots__ = ("_reconciler", "_draft", "_transition", "_requester", "_transport",
                 "digest")
    _reconciler: InstructionQuotaRestoreReconciler
    _draft: InstructionQuotaBaselineRecoveryDraft
    _transition: InstructionQuotaTransition
    _requester: str
    _transport: str
    digest: str

    def __init__(self) -> None:
        raise InstructionQuotaRecoveryContractError(_ERROR)

    def summary(self) -> dict[str, object]:
        return {"contract": CONTRACT, "action_id": ACTION, "action_version": VERSION,
            "adapter_ref": ADAPTER, "candidate_digest": self.digest,
            "draft_digest": self._draft.digest, "required_policy": REQUIRED_POLICY,
            "policy_status": "not_admitted", "planning_only": True,
            "current_state_digest": self._draft._current,
            "expected_state_digest": self._draft._expected,
            "usage_digest": self._draft._usage,
            "evidence_expires_at_epoch": self._draft._expires,
            "instruction_quota_current_percent": 1, "instruction_quota_expected_percent": 0,
            "file_quota_change_percentage_points": 1,
            "original_unknown_preserved": True, "original_request_terminal_proven": False,
            "execution_admissible": False, "redispatch_allowed": False,
            "ledger_finalized": False, "incident_closed": False,
            "automatic_compensation_allowed": False}


def prepare_instruction_quota_baseline_recovery(reconciler: InstructionQuotaRestoreReconciler, *,
        requester_digest: str, transport_digest: str) -> InstructionQuotaBaselineRecoveryCandidate:
    """Compile from one authenticated fixed read; no caller-selected target."""
    try:
        if type(reconciler) is not InstructionQuotaRestoreReconciler:
            raise ValueError
        draft, current, usage = reconciler._prepare_baseline_recovery_projection(
            requester_digest=requester_digest, transport_digest=transport_digest)
        workflow = reconciler._workflow
        with workflow._lock, workflow._transport.operation_lock(require_existing=True):
            workflow._identity(requester_digest, transport_digest)
            if (reconciler._witness() != (draft._witness, draft._original)
                    or not draft._observed <= workflow._now() < draft._expires):
                raise ValueError
            transition = InstructionQuotaTransition(workflow._transport._baseline, current, usage,
                phase="restore", operation_nonce=canonical_digest({"contract": CONTRACT,
                    "draft": draft.digest}))
            if (transition._current, transition._expected, transition._usage) != (
                    draft._current, draft._expected, draft._usage):
                raise ValueError
            values = {"contract": CONTRACT, "draft": draft.digest, "transition": transition.digest,
                "requester": requester_digest, "transport": transport_digest,
                "namespace": workflow._namespace, "required_policy": REQUIRED_POLICY}
            candidate = object.__new__(InstructionQuotaBaselineRecoveryCandidate)
            for key, value in {"_reconciler": reconciler, "_draft": draft, "_transition": transition,
                    "_requester": requester_digest, "_transport": transport_digest,
                    "digest": canonical_digest(values)}.items():
                object.__setattr__(candidate, key, value)
            if not draft._observed <= _guard(candidate, requester_digest, transport_digest) < draft._expires:
                raise ValueError
            return candidate
    except Exception:
        raise InstructionQuotaRecoveryContractError(_ERROR) from None


def _guard(candidate: InstructionQuotaBaselineRecoveryCandidate, requester: str, transport: str) -> int:
    if type(candidate) is not InstructionQuotaBaselineRecoveryCandidate:
        raise ValueError
    reconciler, draft = candidate._reconciler, candidate._draft
    workflow = reconciler._workflow
    workflow._identity(requester, transport)
    if ((requester, transport) != (candidate._requester, candidate._transport)
            or reconciler._witness() != (draft._witness, draft._original)
            or candidate.digest != canonical_digest({"contract": CONTRACT, "draft": draft.digest,
                "transition": candidate._transition.digest, "requester": requester,
                "transport": transport, "namespace": workflow._namespace,
                "required_policy": REQUIRED_POLICY})):
        raise ValueError
    return workflow._now()


def _build_locked(candidate: InstructionQuotaBaselineRecoveryCandidate,
        current: InstructionQuotaState, usage: InstructionResourceUsage, *,
        requester_digest: str, transport_digest: str) -> bytearray:
    """Compiler for a trusted adapter already holding the shared object lock."""
    body: bytearray | None = None
    try:
        draft = candidate._draft
        if not draft._observed <= _guard(candidate, requester_digest, transport_digest) < draft._expires:
            raise ValueError
        body = build_instruction_quota_body(candidate._transition, current, usage)
        if not draft._observed <= _guard(candidate, requester_digest, transport_digest) < draft._expires:
            raise ValueError
        return body
    except Exception:
        if body is not None:
            body.clear()
        raise InstructionQuotaRecoveryContractError(_ERROR) from None


def build_instruction_quota_recovery_body(candidate: InstructionQuotaBaselineRecoveryCandidate,
        current: InstructionQuotaState, usage: InstructionResourceUsage, *,
        requester_digest: str, transport_digest: str) -> bytearray:
    """Private local compiler; a future adapter must separately obtain a fresh read.

    Matching state/usage, original witness and unexpired evidence are mandatory.
    A compiled body is not approval, authorization or permission to send it.
    """
    try:
        if type(candidate) is not InstructionQuotaBaselineRecoveryCandidate:
            raise ValueError
        workflow = candidate._reconciler._workflow
        with workflow._lock, workflow._transport.operation_lock(require_existing=True):
            return _build_locked(candidate, current, usage,
                requester_digest=requester_digest, transport_digest=transport_digest)
    except Exception:
        raise InstructionQuotaRecoveryContractError(_ERROR) from None


def _check_postcondition_locked(candidate: InstructionQuotaBaselineRecoveryCandidate,
        current: InstructionQuotaState, usage: InstructionResourceUsage, *,
        requester_digest: str, transport_digest: str, read_started_at_epoch: int) -> None:
    now = _guard(candidate, requester_digest, transport_digest)
    if (type(read_started_at_epoch) is not int
            or not candidate._draft._observed <= read_started_at_epoch <= now
            or now - read_started_at_epoch > 30):
        raise ValueError
    verify_instruction_quota_readback(candidate._transition, current, usage)
    if _guard(candidate, requester_digest, transport_digest) - read_started_at_epoch > 30:
        raise ValueError


def check_instruction_quota_recovery_postcondition(candidate: InstructionQuotaBaselineRecoveryCandidate,
        current: InstructionQuotaState, usage: InstructionResourceUsage, *,
        requester_digest: str, transport_digest: str, read_started_at_epoch: int) -> None:
    """Compare one fresh post-read only; does not qualify ACK or finalize any line.

    Dispatch permission may expire before readback. A new read still needs its
    own bounded freshness, the exact complete baseline and zero resources.
    """
    try:
        if type(candidate) is not InstructionQuotaBaselineRecoveryCandidate:
            raise ValueError
        workflow = candidate._reconciler._workflow
        with workflow._lock, workflow._transport.operation_lock(require_existing=True):
            _check_postcondition_locked(candidate, current, usage,
                requester_digest=requester_digest, transport_digest=transport_digest,
                read_started_at_epoch=read_started_at_epoch)
    except Exception:
        raise InstructionQuotaRecoveryContractError(_ERROR) from None
