"""Requester-bound, one-shot Launcher clone or owned-clone recovery workflow."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import re
import secrets
import threading
import time
from typing import Protocol

CONTRACT = 'fortipam_v4_launcher_clone_700_workflow_v1'
PUTTY_CONTRACT = 'fortipam_v4_putty_launcher_clone_700_workflow_v1'
COPY_CONTRACT = 'fortipam_v4_putty_launcher_copy_700_workflow_v1'
WINDOWS_CONTRACT = 'fortipam_v4_putty_launcher_windows_700_workflow_v1'
_UNAVAILABLE = 'FortiPAM Launcher clone workflow is unavailable.'
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


class LauncherCloneWorkflowError(RuntimeError):
    """Stable non-disclosing workflow denial or unavailable state."""


class LauncherCloneTransport(Protocol):
    @property
    def putty_profile(self) -> bool: ...

    @property
    def putty_copy_profile(self) -> bool: ...

    @property
    def putty_windows_profile(self) -> bool: ...

    def inspect(self, *, recovery: bool = False) -> dict[str, bool]: ...
    def execute(self, *, recovery: bool = False) -> dict[str, bool]: ...
    def intent_consumed(self, *, recovery: bool) -> bool: ...
    def reserve_intent(self, requester_digest: str, authorization_digest: str, *, recovery: bool) -> None: ...


@dataclass(frozen=True, slots=True)
class _Intent:
    requester: str
    expires_at: int
    authorization: str | None = None


class LauncherCloneLiveWorkflow:
    """Direction is server-bound; callers receive only categorical evidence."""

    def __init__(self, transport: LauncherCloneTransport, *, recovery: bool = False,
                 clock: Callable[[], int] | None = None) -> None:
        if (type(recovery) is not bool or type(transport.putty_profile) is not bool
                or type(transport.putty_copy_profile) is not bool
                or type(transport.putty_windows_profile) is not bool
                or (transport.putty_copy_profile or transport.putty_windows_profile) and not transport.putty_profile
                or transport.putty_copy_profile and transport.putty_windows_profile):
            raise LauncherCloneWorkflowError(_UNAVAILABLE)
        self._transport, self._recovery = transport, recovery
        self._putty = transport.putty_profile
        self._copy = transport.putty_copy_profile
        self._windows = transport.putty_windows_profile
        self._contract = WINDOWS_CONTRACT if self._windows else COPY_CONTRACT if self._copy else PUTTY_CONTRACT if self._putty else CONTRACT
        self._clock = clock or (lambda: int(time.time()))
        self._previews: dict[str, _Intent] = {}
        self._authorizations: dict[str, str] = {}
        self._lock = threading.RLock()

    def _available(self) -> None:
        if self._transport.intent_consumed(recovery=self._recovery):
            raise LauncherCloneWorkflowError(_UNAVAILABLE)

    @staticmethod
    def _requester(requester: str) -> None:
        if not isinstance(requester, str) or not _DIGEST.fullmatch(requester):
            raise LauncherCloneWorkflowError(_UNAVAILABLE)

    def _inspect(self) -> None:
        self._available()
        state = self._transport.inspect(recovery=self._recovery)
        if state != {'source_preserved': True, 'destination_matches_expected_state': True,
                     'unrelated_launcher_metadata_preserved': True, 'device_write_executed': False}:
            raise LauncherCloneWorkflowError(_UNAVAILABLE)

    def _purge(self) -> None:
        for ref, record in tuple(self._previews.items()):
            if self._clock() >= record.expires_at:
                self._previews.pop(ref)
                if record.authorization is not None:
                    self._authorizations.pop(record.authorization, None)

    def _intent(self, ref: str, requester: str) -> _Intent:
        self._requester(requester)
        if not isinstance(ref, str) or not ref.isascii() or len(ref) > 128:
            raise LauncherCloneWorkflowError(_UNAVAILABLE)
        self._purge()
        record = self._previews.get(ref)
        if record is None or not hmac.compare_digest(record.requester, requester):
            raise LauncherCloneWorkflowError(_UNAVAILABLE)
        return record

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        try:
            self._requester(requester_digest)
            with self._lock:
                self._purge()
                if len(self._previews) >= 64:
                    raise ValueError
                self._inspect()
                ref = 'launcher-clone-preview-' + secrets.token_urlsafe(24)
                intent = _Intent(requester_digest, self._clock() + 600)
                self._previews[ref] = intent
            return {'contract': self._contract, 'preview_ref': ref, 'expires_at': intent.expires_at,
                'Current State': {'source_preserved': True, 'destination_present': self._recovery,
                                  **({'destination_reported_usage_empty': self._recovery} if self._putty else {'zero_references': True}),
                                  'verified_creation_required': self._recovery},
                'Proposed Changes': {'operation': 'remove_owned_clone' if self._recovery else
                                     'create_fixed_windows_putty_launcher' if self._windows else
                                     'copy_fixed_putty_launcher_configuration' if self._copy else
                                     'clone_fixed_putty_launcher' if self._putty else 'clone_fixed_rdp_launcher',
                                     'source_changes': False, 'associations_or_launches': False,
                                     **({'fixed_executable_and_variable_parameters':True} if self._windows else {})},
                'Expected State': {'source_preserved': True, 'destination_present': not self._recovery,
                                   'full_configuration_preserved': True, 'unrelated_launcher_metadata_preserved': True},
                'device_write_executed': False}
        except Exception:
            raise LauncherCloneWorkflowError(_UNAVAILABLE) from None

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                record = self._intent(preview_ref, requester_digest)
                if record.authorization is not None:
                    raise ValueError
                self._inspect()
                auth = 'launcher-clone-authorized-' + secrets.token_urlsafe(24)
                self._previews[preview_ref] = replace(record, authorization=auth)
                self._authorizations[auth] = preview_ref
            return {'contract': self._contract, 'authorization_ref': auth, 'confirmation': 'recorded',
                    'execution': 'authorized_once', 'device_write_executed': False}
        except Exception:
            raise LauncherCloneWorkflowError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                if (not isinstance(authorization_ref, str) or not authorization_ref.isascii()
                        or len(authorization_ref) > 128):
                    raise ValueError
                ref = self._authorizations.get(authorization_ref)
                if ref is None:
                    raise ValueError
                record = self._intent(ref, requester_digest)
                if record.authorization != authorization_ref:
                    raise ValueError
                self._inspect()
                self._intent(ref, requester_digest)
                self._transport.reserve_intent(requester_digest, hashlib.sha256(authorization_ref.encode()).hexdigest(),
                                               recovery=self._recovery)
                del self._authorizations[authorization_ref]
                del self._previews[ref]
                try:
                    result = self._transport.execute(recovery=self._recovery)
                    verified = result == {'verified': True, 'source_preserved': True,
                        'clone_present': not self._recovery, 'associations_or_sessions_changed': False}
                except Exception:
                    verified = False
            return {'contract': self._contract, 'outcome': 'succeeded' if verified else 'reconciliation_required',
                    'verification': 'verified' if verified else 'unknown', 'intent_consumed': True,
                    'recovery': self._recovery, 'raw_response_returned': False, 'parameter_values_returned': False}
        except Exception:
            raise LauncherCloneWorkflowError(_UNAVAILABLE) from None
