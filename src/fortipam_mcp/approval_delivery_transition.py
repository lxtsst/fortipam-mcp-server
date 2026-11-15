"""Private Approval Email C/P/E, drift and provided-frame readback comparison.

The retained original source owns the baseline buffers; a separate fresh source
is consumed for each comparison or compilation. No material copy/digest, write,
ACK, backend preservation proof or restoration authority is created here.
"""
from __future__ import annotations

from collections.abc import Mapping
from contextlib import ExitStack
import hmac
import json
from threading import RLock
from typing import Any, Literal

from v4_planning.material_provider import _OpaqueC3Object

from .approval_delivery_contract import _FIELDS, _MATERIAL, _checked_nonmaterial
from .approval_delivery_material_contract import ApprovalDeliveryMaterialDraft, _ROLES, prepare_material_approval_delivery
from .approval_delivery_source import ApprovalDeliverySource
from .mutable_json_buffer import _erase_transfer_storage

CONTRACT = "fortipam-build29-approval-email-private-transition-local/v1"
_ERROR = "The private approval-delivery transition is unavailable."


def _nonmaterial_values(draft: ApprovalDeliveryMaterialDraft) -> dict[str, Any]:
    # Only SDK-generated nonmaterial scalars have tokens to decode.
    return {key: json.loads(token) for key, token in zip(_FIELDS, draft._tokens, strict=True)
        if key not in _MATERIAL and token is not None}


def _inverse_candidate(original: ApprovalDeliverySource) -> ApprovalDeliveryMaterialDraft | None:
    projection = original._projection
    if projection is None:
        raise ValueError
    values = dict(projection._values)
    protocol = values["approval-email-protocol"]
    enabled = bool(values["server"]) if protocol == "ms-graph" else bool(values["server"] or values["email-pulling-server"])
    try:
        inverse = prepare_material_approval_delivery(values, enabled=enabled,
            material_binding_digests=original._bindings)
    except ValueError:
        # A provided baseline may be parseable yet not an SDK-enabled profile.
        # It remains previewable, but must not enter mutable compilation.
        return None
    active = "credential" if protocol == "imaps" else "client-secret"
    if (_nonmaterial_values(inverse) != values
            or enabled and (not projection._buffers["username"] or not projection._buffers[active])):
        return None
    return inverse


class ApprovalDeliveryTransition(_OpaqueC3Object):
    """One forward/inverse compilation pair and frame comparators, not receipts.

    This holder owns the original source's disposal, not its login window. The
    original deadline is never renewed by fresh reads. Its whole singleton and
    native material semantics remain unqualified even when all comparisons pass.
    """

    __slots__ = ("_original", "_input", "_draft", "_expected", "_lock", "_closed", "_attempted", "_compiled",
        "_restore_draft", "_restore_attempted")
    _original: ApprovalDeliverySource
    _input: tuple[tuple[str, Any], ...]
    _draft: ApprovalDeliveryMaterialDraft
    _expected: dict[str, Any]
    _lock: RLock
    _closed: bool
    _attempted: bool
    _compiled: bool
    _restore_draft: ApprovalDeliveryMaterialDraft | None
    _restore_attempted: bool

    def __new__(cls, *args: object, **kwargs: object) -> ApprovalDeliveryTransition:
        del args, kwargs
        raise ValueError(_ERROR)

    def __enter__(self) -> ApprovalDeliveryTransition:
        try:
            with self._lock, self._original._lock:
                self._check_original()
                return self
        except BaseException as error:
            self.close()
            if isinstance(error, Exception):
                raise ValueError(_ERROR) from None
            raise

    def __exit__(self, *args: object) -> None:
        self.close()

    def _check_original(self) -> None:
        source = self._original
        if self._closed or source._projection is None or source._projection._closed or source._deadline is None:
            raise ValueError
        source._remaining(source._deadline)

    def _check_observed(self, observed: ApprovalDeliverySource) -> None:
        self._check_original()
        original = self._original
        if (observed._projection is None or observed._projection._closed or observed._deadline is None
                or observed._owner is not original._owner or observed._client is not original._client
                or observed._config is not original._config or observed._guard is not original._guard
                or observed._actor != original._actor or observed._serial != original._serial
                or observed._bindings != original._bindings):
            raise ValueError
        observed._remaining(observed._deadline)
        if not hmac.compare_digest(observed._cookie, original._cookie):
            raise ValueError

    def _compare(self, observed: ApprovalDeliverySource, expected: Mapping[str, Any]) -> None:
        original_projection, current = self._original._projection, observed._projection
        if original_projection is None or current is None or dict(current._values) != expected:
            raise ValueError
        # All three roles, including inactive slots, remain byte-only. Equality
        # is wire-value equality; stable masks cannot prove stored continuity.
        for role in _ROLES:
            with memoryview(original_projection._buffers[role]) as before, memoryview(current._buffers[role]) as after:
                if not hmac.compare_digest(before, after):
                    raise ValueError

    def _consume_observation(self, observed: ApprovalDeliverySource,
            mode: Literal["compile", "restore", "applied", "restored"]) -> bytearray:
        body = bytearray()
        try:
            try:
                if type(observed) is not ApprovalDeliverySource or observed is self._original:
                    raise ValueError
                try:
                    with self._lock, ExitStack() as locks:
                        # Two source locks have a stable order; callbacks and
                        # close can reenter either source's existing RLock.
                        for source in sorted((self._original, observed), key=id):
                            locks.enter_context(source._lock)
                        self._check_observed(observed)
                        if mode == "compile":
                            if self._attempted or self._restore_draft is None:
                                raise ValueError
                            self._attempted = True
                            projection = self._original._projection
                            if projection is None:
                                raise ValueError
                            self._compare(observed, dict(projection._values))
                            draft = observed._prepare_request(dict(self._input), enabled=self._draft.enabled)
                            if draft != self._draft:
                                raise ValueError
                            body = observed._compile_once(draft)
                        elif mode == "restore":
                            if not self._compiled or self._restore_attempted or self._restore_draft is None:
                                raise ValueError
                            self._restore_attempted = True
                            self._compare(observed, self._expected)
                            projection = self._original._projection
                            if projection is None:
                                raise ValueError
                            draft = observed._prepare_request(dict(projection._values), enabled=self._restore_draft.enabled)
                            if draft != self._restore_draft:
                                raise ValueError
                            body = observed._compile_once(draft)
                        else:
                            if not self._compiled:
                                raise ValueError
                            projection = self._original._projection
                            if projection is None:
                                raise ValueError
                            expected = self._expected if mode == "applied" else dict(projection._values)
                            self._compare(observed, expected)
                            self._check_observed(observed)
                finally:
                    # Taking ownership precedes all lock acquisition. Dispose
                    # even when cancellation prevents entering the locked work,
                    # or interrupts a lock's exit after a body was compiled.
                    observed.close()
                with self._lock, self._original._lock:
                    # Resource/slot cleanup and a final original-window check
                    # must finish before a body or successful comparison escapes.
                    self._check_original()
                    if mode == "compile":
                        self._compiled = True
                return body
            except BaseException:
                try:
                    _erase_transfer_storage(body)
                finally:
                    self.close()
                raise
        except Exception:
            raise ValueError(_ERROR) from None

    def compile_unchanged(self, current: ApprovalDeliverySource) -> bytearray:
        """Consume a fresh unchanged frame and return a caller-owned body once."""
        return self._consume_observation(current, "compile")

    def compile_restore(self, current: ApprovalDeliverySource) -> bytearray:
        """Compile the exact original SDK candidate from a fresh proposed frame.

        A forward body must already have compiled. Neither compilation proves
        it was dispatched/acknowledged or grants independent restore authority.
        """
        return self._consume_observation(current, "restore")

    def verify_applied(self, observed: ApprovalDeliverySource) -> None:
        """Consume one proposed-value frame; not an ACK or execution receipt."""
        self._consume_observation(observed, "applied")

    def verify_restored(self, observed: ApprovalDeliverySource) -> None:
        """Compare exact original wire values; no native normalization inferred."""
        self._consume_observation(observed, "restored")

    def preview(self) -> dict[str, object]:
        try:
            with self._lock, self._original._lock:
                self._check_original()
                projection = self._original._projection
                if projection is None:
                    raise ValueError
                original, supplied = dict(projection._values), dict(self._input)
                changed = sorted(key for key in self._expected if self._expected[key] != original[key])
                normalized = sorted(key for key in self._expected if self._expected[key] != supplied[key])
                result: dict[str, object] = {
                    "contract": CONTRACT,
                    "Current State": {"selected_field_count": 14, "protected_slot_count": 3,
                        "whole_singleton_baseline_verified": False},
                    "Proposed Changes": {"enabled_intent": self._draft.enabled, "protocol": self._draft.protocol,
                        "changed_nonmaterial_fields": changed, "request_normalized_fields": normalized,
                        "protected_slot_wire_values_preserved": True},
                    "Expected State": {"selected_nonmaterial_values_match_request": True,
                        "three_protected_wire_values_match_original": True,
                        "backend_material_preservation_qualified": False,
                        "local_sdk_inverse_available": self._restore_draft is not None},
                    "execution_authorized": False, "independent_restore_authorized": False,
                    "native_current_response_or_ack_qualified": False, "partial_put_merge_qualified": False,
                    "polling_or_approval_effect_qualified": False, "operation_replay_protection": False,
                }
                self._check_original()
                return result
        except BaseException as error:
            self.close()
            if isinstance(error, Exception):
                raise ValueError(_ERROR) from None
            raise

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._original.close()


def prepare_approval_delivery_transition(original: ApprovalDeliverySource, proposed: Mapping[str, Any], *,
        enabled: bool) -> ApprovalDeliveryTransition:
    """Take disposal ownership of one previously read original source.

    Only field names/counts/enums enter preview. The original material is neither
    copied nor hashed, and the original login window remains owned by its host.
    """
    try:
        try:
            if type(original) is not ApprovalDeliverySource:
                raise ValueError
            with original._lock:
                values = _checked_nonmaterial(proposed)
                if original._projection is None or original._projection._closed or original._deadline is None:
                    raise ValueError
                original._remaining(original._deadline)
                draft = original._prepare_request(values, enabled=enabled)
                expected = _nonmaterial_values(draft)
                result = object.__new__(ApprovalDeliveryTransition)
                result._original, result._input, result._draft = original, tuple(values.items()), draft
                result._expected, result._lock = expected, RLock()
                result._closed = result._attempted = result._compiled = False
                result._restore_draft = _inverse_candidate(original)
                result._restore_attempted = False
                result._check_original()
                return result
        except BaseException:
            if type(original) is ApprovalDeliverySource:
                original.close()
            raise
    except Exception:
        raise ValueError(_ERROR) from None
