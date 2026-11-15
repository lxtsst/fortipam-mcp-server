"""Inactive independent exact-file source-session permission and fixed policy.

The existing projection grant/policy cannot retain an unlock. This fixed
candidate creates no Reference grant, child authority, provider or public route.
"""

from __future__ import annotations

from pathlib import Path
import time
from typing import Callable

from .reference_authority_sidecar import UnixReferenceAuthorityClient
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_intake_authority import (
    PinnedOwnerFileIntakeAuthority, _intent_digest, _issue_prebound_policy_once,
)
from .secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility

CONTRACT = "fortipam-owner-file-source-session-policy-v1"
REFERENCE_KIND = "owner_file_source_session"
_PURPOSE = "private-source-session-only"


def source_session_scope_ref(binding: OwnerFileIntakeBinding, key: bytearray) -> str:
    """Private exact-input commitment in a distinct permission namespace."""
    binding.__post_init__()
    return "owner-file-source-session-" + _intent_digest(binding, key)


class ReferenceOwnerFileSessionEligibility(ReferenceOwnerFileEligibility):
    """Checkpoint-bound source-session permission; projection grants deny."""

    _reference_kind = REFERENCE_KIND
    _scope_ref = staticmethod(source_session_scope_ref)


class PinnedOwnerFileSessionAuthority(PinnedOwnerFileIntakeAuthority):
    """Fixed session policy plus remote, independently revocable permission."""

    _policy_contract = CONTRACT
    _policy_purpose = _PURPOSE
    _display_name = "PinnedOwnerFileSessionAuthority"

    def __init__(self, binding: OwnerFileIntakeBinding, *, policy_path: Path,
                 key_path: Path, policy_sha256: str, key_sha256: str,
                 human_owner_verifier: ReferenceOwnerFileSessionEligibility,
                 clock: Callable[[], int] | None = None) -> None:
        if (type(human_owner_verifier) is not ReferenceOwnerFileSessionEligibility
                or human_owner_verifier._binding != binding
                or type(human_owner_verifier._authority) is not UnixReferenceAuthorityClient):
            raise BulkImportIntakeError(_ERROR)
        super().__init__(binding, policy_path=policy_path, key_path=key_path,
            policy_sha256=policy_sha256, key_sha256=key_sha256,
            human_owner_verifier=human_owner_verifier, clock=clock)

    def verify_source_session(self, binding: OwnerFileIntakeBinding, *, now_epoch: int) -> None:
        self.verify(binding, now_epoch=now_epoch)

    def source_session_expires_at(self, binding: OwnerFileIntakeBinding, *, now_epoch: int) -> int:
        """Use only the fresh decision horizon, never infer stored grant lifetime."""
        checker = self._human_owner_verifier
        if binding != self._binding or not isinstance(checker, ReferenceOwnerFileSessionEligibility):
            raise BulkImportIntakeError(_ERROR)
        return min(binding.expires_at, checker._verified_until)


def issue_prebound_owner_file_session_policy_once(
    binding: OwnerFileIntakeBinding, *, policy_path: Path, key_path: Path, key_sha256: str,
    eligibility: ReferenceOwnerFileSessionEligibility,
    clock: Callable[[], int] = lambda: int(time.time()), monotonic: Callable[[], float] = time.monotonic,
) -> str:
    """Seal only an existing remote session grant; no role or grant issuance."""
    return _issue_prebound_policy_once(binding, policy_path=policy_path, key_path=key_path,
        key_sha256=key_sha256, eligibility=eligibility, clock=clock, monotonic=monotonic,
        eligibility_type=ReferenceOwnerFileSessionEligibility, contract=CONTRACT, purpose=_PURPOSE)
