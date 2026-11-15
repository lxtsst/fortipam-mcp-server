"""Value-minimized BP002 reset preflight preview, never an intent record.

The existing 1.9.1 SSH reset workflow cannot authorize the separate build-29
HTTP fixture. This reader joins the fixed full non-material User baseline and
the applicable password policy before a future trusted client issues intent.
It does not expose a selector, material binding, plan reference or write path.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, fields
import hashlib
import hmac
import json
import re
import time
from typing import Protocol

from .local_user_reset_http_transport import (
    LocalUserResetBaseline, LocalUserResetBinding, LocalUserResetInspector,
)
from .local_user_reset_policy_reader import LocalUserResetPolicySnapshot

_DOMAIN = b"bp002-local-user-reset-preflight-build29/v1\0"
_TTL_SECONDS = 300
_MAX_READ_SECONDS = 30
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_UNAVAILABLE = "The private Local User reset preview is unavailable."


class LocalUserResetPreviewError(RuntimeError):
    """Fixed non-disclosing failure for an incomplete or drifting read."""


class LocalUserResetPreviewPolicyInspector(Protocol):
    def read_policy_snapshot(self) -> LocalUserResetPolicySnapshot: ...


def _digest(value: object) -> str:
    return hashlib.sha256(_DOMAIN + json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")).hexdigest()


def _baseline_digest(value: LocalUserResetBaseline) -> str:
    if type(value) is not LocalUserResetBaseline:
        raise LocalUserResetPreviewError(_UNAVAILABLE)
    LocalUserResetBinding(value)
    return _digest({field.name: getattr(value, field.name) for field in fields(value)})


def _summary_digest(current_digest: str, policy_digest: str, guest_auth: str,
                    observed_at: int, expires_at: int) -> str:
    return _digest({
        "current_state_digest": current_digest,
        "policy_digest": policy_digest,
        "guest_auth": guest_auth,
        "observed_at": observed_at,
        "expires_at": expires_at,
        "operation": "change_one_local_user_password",
        "expected": "backend_changed_metadata_preserved_login_unverified",
    })


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetPreflightPreview:
    """Non-executable C/P/E; no target name or material reference is returned."""

    current_state_digest: str
    policy_digest: str
    observed_at: int
    expires_at: int
    summary_digest: str
    guest_auth: str

    def __post_init__(self) -> None:
        if (any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in (
                self.current_state_digest, self.policy_digest, self.summary_digest,
            ))
            or type(self.observed_at) is not int or self.observed_at < 0
            or type(self.expires_at) is not int
            or self.expires_at - self.observed_at != _TTL_SECONDS
            or self.guest_auth != "disable"
            or not hmac.compare_digest(self.summary_digest, _summary_digest(
                self.current_state_digest, self.policy_digest, self.guest_auth,
                self.observed_at, self.expires_at,
            ))):
            raise LocalUserResetPreviewError(_UNAVAILABLE)

    def as_dict(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "contract": "bp002-local-user-reset-preflight-build29/v1",
            "state": "plan_only",
            "Current State": {
                "target": "one_retained_local_non_super_admin_fixture",
                "sponsor_group": "empty",
                "schedule": "empty",
                "reported_references": "zero",
                "usage_entries": "zero",
                "guest_auth": self.guest_auth,
                "current_state_digest": self.current_state_digest,
                "password_policy_digest": self.policy_digest,
            },
            "Proposed Changes": {
                "operation": "change_one_local_user_password",
                "old_and_new_material": "owner_only_not_returned",
                "metadata_change": "none",
            },
            "Expected State": {
                "backend_changed_acknowledgement": "required",
                "complete_nonmaterial_state": "preserved",
                "authentication_verified": False,
            },
            "summary_digest": self.summary_digest,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "execution_authorized": False,
            "device_write_executed": False,
        }


class FortiPamLocalUserResetPreviewReader:
    """Read the bound fixture and policy once without issuing authority."""

    def __init__(
        self, binding: LocalUserResetBinding, inspector: LocalUserResetInspector,
        policy_snapshot: LocalUserResetPolicySnapshot,
        policy_inspector: LocalUserResetPreviewPolicyInspector, *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        try:
            if (type(binding) is not LocalUserResetBinding
                or not callable(getattr(inspector, "read_nonmaterial_baseline", None))
                or type(policy_snapshot) is not LocalUserResetPolicySnapshot
                or not callable(getattr(policy_inspector, "read_policy_snapshot", None))
                or (clock is not None and not callable(clock))):
                raise ValueError
            LocalUserResetBinding(binding.expected)
            # This candidate reads the system/admin policy route. A fixture
            # using guest-admin policy needs its own qualified fixed reader.
            if binding.expected.guest_auth != "disable":
                raise ValueError
            policy_snapshot.__post_init__()
        except Exception:
            raise LocalUserResetPreviewError(_UNAVAILABLE) from None
        self._binding, self._inspector = binding, inspector
        self._policy, self._policy_inspector = policy_snapshot, policy_inspector
        self._clock = (lambda: int(time.time())) if clock is None else clock

    def read_preview(self) -> LocalUserResetPreflightPreview:
        try:
            started = self._clock()
            if type(started) is not int or started < 0:
                raise ValueError
            LocalUserResetBinding(self._binding.expected)
            current = self._inspector.read_nonmaterial_baseline()
            if type(current) is not LocalUserResetBaseline:
                raise ValueError
            LocalUserResetBinding(current)
            if current != self._binding.expected:
                raise ValueError
            policy = self._policy_inspector.read_policy_snapshot()
            if type(policy) is not LocalUserResetPolicySnapshot:
                raise ValueError
            policy.__post_init__()
            if (policy != self._policy
                or not hmac.compare_digest(policy.digest, self._policy.digest)):
                raise ValueError
            observed = self._clock()
            if (type(observed) is not int or not started <= observed
                or observed - started > _MAX_READ_SECONDS):
                raise ValueError
            state_digest = _baseline_digest(current)
            summary_digest = _summary_digest(
                state_digest, policy.digest, current.guest_auth,
                observed, observed + _TTL_SECONDS,
            )
            return LocalUserResetPreflightPreview(
                state_digest, policy.digest, observed, observed + _TTL_SECONDS,
                summary_digest, current.guest_auth,
            )
        except Exception:
            raise LocalUserResetPreviewError(_UNAVAILABLE) from None


__all__ = [
    "FortiPamLocalUserResetPreviewReader", "LocalUserResetPreflightPreview",
    "LocalUserResetPreviewError",
]
