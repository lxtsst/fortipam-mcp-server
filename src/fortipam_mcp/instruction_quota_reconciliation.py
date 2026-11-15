"""Inactive read-only assessment of one consumed, ACK-less quota restoration.

The original native/M4 records remain immutable. No Tool, dispatch, grant,
ledger finalization or recovery admission is provided by this component.
"""
from __future__ import annotations

import hmac
from contextlib import closing
from typing import cast

from v4_planning import M4Outcome, M4Verification, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from .instruction_quota_contract import InstructionQuotaState, _Private, _usage_fits
from .instruction_quota_live_workflow import InstructionQuotaLiveWorkflow
from .instruction_resource_usage import InstructionResourceUsage

CONTRACT = "fortipam-700-build29-instruction-quota-restore-reconciliation-v1"
DRAFT_CONTRACT = "fortipam-700-build29-instruction-quota-baseline-recovery-draft-v1"
_ERROR = "The private Instruction quota reconciliation is unavailable."
_MAX_READ_SECONDS = 30


class InstructionQuotaReconciliationError(RuntimeError):
    """Value-free refusal; never return a partial assessment."""


class InstructionQuotaBaselineRecoveryDraft(_Private):
    """Immutable C/P/E planning evidence; cannot issue authority or dispatch."""

    __slots__ = ("_evidence", "_current", "_expected", "_usage", "_original", "_witness",
                 "_read_started", "_observed", "_expires", "digest")
    _evidence: str
    _current: str
    _expected: str
    _usage: str
    _original: str
    _witness: str
    _read_started: int
    _observed: int
    _expires: int
    digest: str

    def __init__(self) -> None:
        raise InstructionQuotaReconciliationError(_ERROR)

    def summary(self) -> dict[str, object]:
        return {"contract": DRAFT_CONTRACT, "proposal_digest": self.digest,
            "planning_only": True, "reconciliation_evidence_ref": self._evidence,
            "original_plan_digest": self._original,
            "current_state_digest": self._current, "expected_state_digest": self._expected,
            "usage_digest": self._usage, "evidence_read_started_at_epoch": self._read_started,
            "observed_at_epoch": self._observed,
            "evidence_expires_at_epoch": self._expires,
            "instruction_quota_current_percent": 1, "instruction_quota_expected_percent": 0,
            "file_quota_change_percentage_points": 1,
            "complete_original_baseline_expected": True, "unrelated_fields_preserved": True,
            "instruction_usage_zero": True, "original_m4_outcome": "reconciliation_required",
            "original_m4_verification": "unknown", "original_request_terminal_proven": False,
            "execution_admissible": False, "redispatch_allowed": False, "ledger_finalized": False,
            "required_dependencies": ["exact_incident_policy_for_unresolved_original",
                "independent_recovery_execution_contract", "server_authorization_and_acceptance"]}


class InstructionQuotaRestoreReconciler(_OpaqueC3Object):
    """One authenticated assessment using the already fixed full-context reader."""

    def __init__(self, workflow: InstructionQuotaLiveWorkflow) -> None:
        try:
            if type(workflow) is not InstructionQuotaLiveWorkflow:
                raise ValueError
            self._workflow = workflow
            self._closed()
        except Exception:
            raise InstructionQuotaReconciliationError(_ERROR) from None

    def _closed(self) -> None:
        item = self._workflow
        if (item._phase != "restore" or item._enabled is not False
                or item._transport._enabled is not False or not item._execution_store._read_only
                or item._original_store is None or not item._original_store._read_only):
            raise ValueError

    def _witness(self) -> tuple[str, str]:
        item, transport = self._workflow, self._workflow._transport
        self._closed()
        item._original_m4()
        claim = transport._claim("restore")
        if (claim["binding"] != transport._binding.digest
                or claim["current"] != transport._binding._current
                or claim["expected"] != transport._binding._expected
                or claim["usage"] != transport._binding._usage
                or claim["anchors"] != transport._original_allocate()
                or transport._exists("restore.ack.json")
                or transport._exists("restore.result.json")):
            raise ValueError
        store = item._execution_store
        context = canonical_digest({"authorization_digest": claim["authorization"],
                                    "plan_digest": claim["plan"], "revision": 1})
        # Verify the entire HMAC chain before inspecting fixed fields, in the
        # same SQLite snapshot. Raw plan/approval references are not recovered.
        with closing(store._connect()) as connection:
            connection.execute("BEGIN")
            state = store._read_state(connection)
            rows = connection.execute(
                "SELECT requester_key, context_key, authorization_key FROM execution_ledger "
                "WHERE event_type = 'claim'").fetchall()
            if len(rows) != 1 or len(state.claims) != 1:
                raise ValueError
            row = rows[0]
            for key, expected in {
                "requester_key": store._digest_key("requester", item._requester),
                "context_key": store._digest_key("context", context),
                "authorization_key": store._digest_key("execution-authorization", claim["authorization"]),
            }.items():
                if type(row[key]) is not str or not hmac.compare_digest(row[key], expected):
                    raise ValueError
            prior = next(iter(state.claims.values()))
            if (prior.result is None or prior.result.outcome is not M4Outcome.RECONCILIATION_REQUIRED
                    or prior.result.verification is not M4Verification.UNKNOWN or not state.audit):
                raise ValueError
            event = state.audit[-1]
            if (event.authorization != "dispatch_unknown"
                    or event.outcome is not prior.result.outcome
                    or event.verification is not prior.result.verification
                    or event.digest_reference != canonical_digest(context + "dispatch_unknown")):
                raise ValueError
            witness = canonical_digest({"native_claim": canonical_digest(claim),
                "ledger_sequence": state.last_sequence, "ledger_chain": state.last_hmac})
            connection.commit()
        return witness, cast(str, claim["plan"])

    def assess(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        return self._observe(requester_digest=requester_digest, transport_digest=transport_digest)[0]

    def prepare_baseline_recovery(self, *, requester_digest: str,
                                  transport_digest: str) -> InstructionQuotaBaselineRecoveryDraft:
        """Prepare the fixed original-baseline objective, never a new permission.

        A trusted incident/change composition records the owner's selected
        objective separately. This draft is not that decision or an exception
        to the original stop; every future write remains unavailable here.
        """
        return self._prepare_baseline_recovery_projection(
            requester_digest=requester_digest, transport_digest=transport_digest)[0]

    def _prepare_baseline_recovery_projection(self, *, requester_digest: str,
            transport_digest: str) -> tuple[InstructionQuotaBaselineRecoveryDraft,
                InstructionQuotaState, InstructionResourceUsage]:
        """Keep the same qualified projection inside trusted private composition."""
        try:
            report, current, usage, witness, started = self._observe(
                requester_digest=requester_digest, transport_digest=transport_digest)
            item, transport = self._workflow, self._workflow._transport
            with item._lock, transport.operation_lock(require_existing=True):
                item._identity(requester_digest, transport_digest)
                if (current._state != transport._binding._current or not usage.instruction_usage_zero
                        or self._witness() != (witness, report["original_plan_digest"])):
                    raise ValueError
                _usage_fits(current, usage, transport._baseline._quotas)
                observed = cast(int, report["observed_at_epoch"])
                if not started <= observed <= item._now() < started + _MAX_READ_SECONDS:
                    raise ValueError
                values = {"_evidence": report["evidence_ref"], "_current": current._state,
                    "_expected": transport._baseline._state, "_usage": usage._state,
                    "_original": report["original_plan_digest"], "_witness": witness,
                    "_read_started": started, "_observed": observed, "_expires": started + _MAX_READ_SECONDS}
                draft = object.__new__(InstructionQuotaBaselineRecoveryDraft)
                for key, value in {**values, "digest": canonical_digest({
                        "contract": DRAFT_CONTRACT, "projection": values})}.items():
                    object.__setattr__(draft, key, value)
                return draft, current, usage
        except Exception:
            raise InstructionQuotaReconciliationError(_ERROR) from None

    def _observe(self, *, requester_digest: str, transport_digest: str) -> tuple[
            dict[str, object], InstructionQuotaState, InstructionResourceUsage, str, int]:
        try:
            item, transport = self._workflow, self._workflow._transport
            with item._lock:
                item._identity(requester_digest, transport_digest)
                self._closed()
                with transport.operation_lock(require_existing=True):
                    started = item._now()
                    original, plan_digest = self._witness()
                    current, usage = transport._reader(transport._config,
                        serial_digest=transport._baseline._serial)
                    finished = item._now()
                    if (not 0 <= finished - started <= _MAX_READ_SECONDS
                            or type(current) is not InstructionQuotaState
                            or type(usage) is not InstructionResourceUsage
                            or current._serial != transport._baseline._serial
                            or usage._serial != transport._baseline._serial):
                        raise ValueError
                    _usage_fits(current, usage, current._quotas)
                    if self._witness() != (original, plan_digest):
                        raise ValueError
                    item._identity(requester_digest, transport_digest)
                    finished = item._now()
                    if not 0 <= finished - started <= _MAX_READ_SECONDS:
                        raise ValueError
                    baseline = current._state == transport._baseline._state
                    allocated = current._state == transport._binding._current
                    # A matching precondition does not qualify absence of a
                    # server-side action correlation or prove nondelivery.
                    outcome = "verified-compensated" if baseline and usage.instruction_usage_zero else (
                        "not-assessed" if allocated else "partial-or-drifted")
                    reference = "instruction-quota-reconciliation-" + canonical_digest({
                        "original": original, "state": current._state, "usage": usage._state,
                        "observed_at": finished})
                    report: dict[str, object] = {"contract": CONTRACT, "evidence_ref": reference,
                        "original_plan_digest": plan_digest, "line_ref": "instruction-quota-restore",
                        "outcome": outcome, "observed_at_epoch": finished,
                        "read_elapsed_seconds": finished - started,
                        "complete_state_matches_restore_expected": baseline,
                        "complete_state_matches_restore_precondition": allocated,
                        "instruction_usage_zero": usage.instruction_usage_zero,
                        "original_native_and_m4_binding_verified": True,
                        "original_native_m4_witness_unchanged": True, "original_m4_outcome": "reconciliation_required",
                        "original_m4_verification": "unknown", "original_request_terminal_proven": False,
                        "action_correlation_absence_qualified": False,
                        "owner_decision_required": True, "execution_admissible": False,
                        "redispatch_allowed": False, "ledger_finalized": False}
                    return report, current, usage, original, started
        except Exception:
            raise InstructionQuotaReconciliationError(_ERROR) from None
