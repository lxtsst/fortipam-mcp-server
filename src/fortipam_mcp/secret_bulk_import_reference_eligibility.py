"""Inactive exact-file eligibility from the existing Reference Authority.

Trusted Owner bootstrap must independently grant this fixed permission to the
authenticated requester. This verifier mints no grant and assigns no global
Owner or product role. A policy signature or constructor digest is insufficient.
"""

from __future__ import annotations

from pathlib import Path
import time
from typing import Callable

from v4_planning import PersistentReferenceAuthority, VerifiedReferenceDecision, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .reference_authority_sidecar import UnixReferenceAuthorityClient
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_intake_authority import _intent_digest
from .secret_bulk_import_token_channel import _PinnedKey

REFERENCE_KIND = "owner_file_dependency_projection"


def eligibility_scope_ref(binding: OwnerFileIntakeBinding, key: bytearray) -> str:
    """Private bootstrap commitment only; not proof of permission to resolve it."""
    binding.__post_init__()
    return "owner-file-projection-" + _intent_digest(binding, key)


def eligibility_environment_ref(binding: OwnerFileIntakeBinding) -> str:
    return "owner-file-deployment-" + binding.deployment_digest


class ReferenceOwnerFileEligibility(_OpaqueC3Object):
    """Verify a live, revocable, checkpoint-bound exact-intake permission."""

    _reference_kind = REFERENCE_KIND
    _scope_ref = staticmethod(eligibility_scope_ref)

    def __init__(self, binding: OwnerFileIntakeBinding, *,
                 authority: PersistentReferenceAuthority | UnixReferenceAuthorityClient,
                 authority_ref: str, reference: str, requester_digest: str,
                 scope_key_path: Path, scope_key_sha256: str,
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(binding) is not OwnerFileIntakeBinding
                    or type(authority) not in (PersistentReferenceAuthority, UnixReferenceAuthorityClient)
                    or authority.monotonic_checkpoint_protocol_bound is not True
                    or authority.authority_ref != authority_ref or not callable(clock)
                    or not isinstance(scope_key_path, Path)
                    or scope_key_path.parts[1:] == binding.path.parts[1:]):
                raise ValueError
            binding.__post_init__()
            require_ref(authority_ref, "authority")
            require_ref(reference, "reference")
            require_digest(requester_digest, "requester")
            self._binding, self._authority, self._authority_ref = binding, authority, authority_ref
            self._reference, self._requester, self._clock = reference, requester_digest, clock
            self._last_now = -1
            self._verified_until = 0
            self._key = _PinnedKey(scope_key_path, scope_key_sha256)
            raw = self._key.load()
            try:
                if authority.uses_key_material(bytes(raw)) is True:
                    raise ValueError
                self._scope = self._scope_ref(binding, raw)
            finally:
                _wipe(raw)
            self._environment = eligibility_environment_ref(binding)
            self._decision = canonical_digest(reference)
            authority.verify_ready()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def __call__(self, binding: OwnerFileIntakeBinding, decision: str, now_epoch: int) -> None:
        raw = None
        try:
            now = self._clock()
            if (type(binding) is not OwnerFileIntakeBinding or binding != self._binding
                    or decision != self._decision or type(now) is not int or type(now_epoch) is not int
                    or not 0 <= now_epoch <= now or now < self._last_now
                    or not binding.issued_at <= now < binding.expires_at):
                raise ValueError
            self._last_now = now
            raw = self._key.load()
            if self._scope_ref(binding, raw) != self._scope:
                raise ValueError
            self._authority.verify_ready()
            verdict = self._authority.authorize(
                self._reference, reference_kind=self._reference_kind, requester_digest=self._requester,
                environment_ref=self._environment, scope_ref=self._scope, now_epoch=now,
            )
            if (type(verdict) is not VerifiedReferenceDecision or verdict.authorized is not True
                    or verdict.authority_ref != self._authority_ref or verdict.reference_kind != self._reference_kind
                    or verdict.reference_digest != self._decision or verdict.requester_digest != self._requester
                    or verdict.environment_digest != canonical_digest(self._environment)
                    or verdict.scope_digest != canonical_digest(self._scope)
                    or verdict.checked_at != now or not now < verdict.expires_at):
                raise ValueError
            after = self._clock()
            if (type(after) is not int or not now <= after < min(verdict.expires_at, binding.expires_at)):
                raise ValueError
            self._last_now = after
            refreshed = self._key.load()
            _wipe(refreshed)
            self._verified_until = verdict.expires_at
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            if raw is not None:
                _wipe(raw)
