"""Value-minimized, non-executable supporting evidence for BP015.

This module deliberately composes only categorical results already produced by
bounded readers.  It contains no product route, selector, credential, raw
mapping, transport, runtime, or MCP integration.  In particular, supporting
evidence cannot establish Sponsored Group semantics or promote the BP015
parent assessment into a current-state projection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .canonical import canonical_digest


BP015_SUPPORTING_STATE_CONTRACT: Final = "fortipam-bp015-supporting-state-v1"
_PARTIAL_EVIDENCE: Final = "partial"
_CURRENT_STATE_UNAVAILABLE: Final = "unavailable"


class BP015SupportingStateProjectionError(ValueError):
    """Raised when a non-categorical value crosses the BP015 boundary."""


@dataclass(frozen=True, slots=True)
class BP015AdminCategoricalInspection:
    """Minimized existing-admin facts, without an identity or response record."""

    sponsor_admin_exists: bool
    member_exists: bool
    member_status_recognized: bool
    member_schedule_matches: bool

    def __post_init__(self) -> None:
        _require_booleans(
            self.sponsor_admin_exists,
            self.member_exists,
            self.member_status_recognized,
            self.member_schedule_matches,
        )


@dataclass(frozen=True, slots=True)
class BP015ScheduleCategoricalInspection:
    """Minimized recurring-Schedule facts, without its name or time values."""

    schedule_exists: bool
    schedule_detail_matches: bool
    recurring_window_observed: bool

    def __post_init__(self) -> None:
        _require_booleans(
            self.schedule_exists,
            self.schedule_detail_matches,
            self.recurring_window_observed,
        )


@dataclass(frozen=True, slots=True)
class BP015FolderAclCategoricalInspection:
    """Minimized Folder ACL facts, without a Folder, principal, or ACL record."""

    folder_exists: bool
    exact_group_acl_relation_observed: bool
    folder_permission_observed: bool
    secret_permission_observed: bool

    def __post_init__(self) -> None:
        _require_booleans(
            self.folder_exists,
            self.exact_group_acl_relation_observed,
            self.folder_permission_observed,
            self.secret_permission_observed,
        )


@dataclass(frozen=True, slots=True)
class BP015SecretApprovalCategoricalInspection:
    """Minimized Secret approval facts, without Secret fields or identifiers."""

    secret_exists: bool
    approval_posture_observed: bool
    secret_field_values_absent: bool

    def __post_init__(self) -> None:
        _require_booleans(
            self.secret_exists,
            self.approval_posture_observed,
            self.secret_field_values_absent,
        )


@dataclass(frozen=True, slots=True)
class BP015SupportingStateProjection:
    """A partial supporting-state result that cannot become BP015 C/P/E evidence."""

    sponsor_admin_detail_observed: bool
    member_detail_observed: bool
    member_status_observed: bool
    member_schedule_matches: bool
    schedule_detail_observed: bool
    recurring_window_observed: bool
    folder_acl_observed: bool
    secret_approval_observed: bool
    secret_field_values_absent: bool
    supporting_state_digest: str

    def __post_init__(self) -> None:
        _require_booleans(
            self.sponsor_admin_detail_observed,
            self.member_detail_observed,
            self.member_status_observed,
            self.member_schedule_matches,
            self.schedule_detail_observed,
            self.recurring_window_observed,
            self.folder_acl_observed,
            self.secret_approval_observed,
            self.secret_field_values_absent,
        )
        if (
            not isinstance(self.supporting_state_digest, str)
            or len(self.supporting_state_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.supporting_state_digest)
        ):
            raise BP015SupportingStateProjectionError("BP015 supporting-state digest is invalid.")

    @property
    def contract(self) -> str:
        return BP015_SUPPORTING_STATE_CONTRACT

    @property
    def supporting_state_evidence(self) -> str:
        return _PARTIAL_EVIDENCE

    @property
    def current_state_evidence(self) -> str:
        return _CURRENT_STATE_UNAVAILABLE

    @property
    def source_contract_ready(self) -> bool:
        return False

    @property
    def execution_ready(self) -> bool:
        return False

    @property
    def device_access(self) -> bool:
        return False

    @property
    def dispatchable(self) -> bool:
        return False

    def as_dict(self) -> dict[str, object]:
        """Return fixed state categories only, never source records or selectors."""

        return {
            "contract": self.contract,
            "current_state_evidence": self.current_state_evidence,
            "device_access": self.device_access,
            "dispatchable": self.dispatchable,
            "execution_ready": self.execution_ready,
            "folder_acl_observed": self.folder_acl_observed,
            "member_detail_observed": self.member_detail_observed,
            "member_schedule_matches": self.member_schedule_matches,
            "member_status_observed": self.member_status_observed,
            "recurring_window_observed": self.recurring_window_observed,
            "schedule_detail_observed": self.schedule_detail_observed,
            "secret_approval_observed": self.secret_approval_observed,
            "secret_field_values_absent": self.secret_field_values_absent,
            "source_contract_ready": self.source_contract_ready,
            "sponsor_admin_detail_observed": self.sponsor_admin_detail_observed,
            "supporting_state_digest": self.supporting_state_digest,
            "supporting_state_evidence": self.supporting_state_evidence,
        }


def build_bp015_supporting_state_projection(
    admin: BP015AdminCategoricalInspection,
    schedule: BP015ScheduleCategoricalInspection,
    folder_acl: BP015FolderAclCategoricalInspection,
    secret_approval: BP015SecretApprovalCategoricalInspection,
) -> BP015SupportingStateProjection:
    """Combine already-minimized inspections without adding BP015 semantics."""

    _require_exact_type(admin, BP015AdminCategoricalInspection)
    _require_exact_type(schedule, BP015ScheduleCategoricalInspection)
    _require_exact_type(folder_acl, BP015FolderAclCategoricalInspection)
    _require_exact_type(secret_approval, BP015SecretApprovalCategoricalInspection)
    content = {
        "contract": BP015_SUPPORTING_STATE_CONTRACT,
        "folder_acl_observed": (
            folder_acl.folder_exists
            and folder_acl.exact_group_acl_relation_observed
            and folder_acl.folder_permission_observed
            and folder_acl.secret_permission_observed
        ),
        "member_detail_observed": admin.member_exists,
        "member_schedule_matches": (
            admin.member_exists
            and admin.member_schedule_matches
            and schedule.schedule_exists
            and schedule.schedule_detail_matches
        ),
        "member_status_observed": (
            admin.member_exists and admin.member_status_recognized
        ),
        "recurring_window_observed": (
            schedule.schedule_exists
            and schedule.schedule_detail_matches
            and schedule.recurring_window_observed
        ),
        "schedule_detail_observed": schedule.schedule_exists and schedule.schedule_detail_matches,
        "secret_approval_observed": (
            secret_approval.secret_exists and secret_approval.approval_posture_observed
        ),
        "secret_field_values_absent": (
            secret_approval.secret_exists
            and secret_approval.secret_field_values_absent
        ),
        "sponsor_admin_detail_observed": admin.sponsor_admin_exists,
    }
    return BP015SupportingStateProjection(
        sponsor_admin_detail_observed=admin.sponsor_admin_exists,
        member_detail_observed=admin.member_exists,
        member_status_observed=bool(content["member_status_observed"]),
        member_schedule_matches=bool(content["member_schedule_matches"]),
        schedule_detail_observed=bool(content["schedule_detail_observed"]),
        recurring_window_observed=bool(content["recurring_window_observed"]),
        folder_acl_observed=bool(content["folder_acl_observed"]),
        secret_approval_observed=bool(content["secret_approval_observed"]),
        secret_field_values_absent=bool(content["secret_field_values_absent"]),
        supporting_state_digest=canonical_digest(content),
    )


def _require_booleans(*values: object) -> None:
    if any(type(value) is not bool for value in values):
        raise BP015SupportingStateProjectionError("BP015 supporting-state inputs must be boolean.")


def _require_exact_type(value: object, expected: type[object]) -> None:
    if type(value) is not expected:
        raise BP015SupportingStateProjectionError("BP015 supporting-state inspection is invalid.")


__all__ = [
    "BP015_SUPPORTING_STATE_CONTRACT",
    "BP015AdminCategoricalInspection",
    "BP015FolderAclCategoricalInspection",
    "BP015ScheduleCategoricalInspection",
    "BP015SecretApprovalCategoricalInspection",
    "BP015SupportingStateProjection",
    "BP015SupportingStateProjectionError",
    "build_bp015_supporting_state_projection",
]
