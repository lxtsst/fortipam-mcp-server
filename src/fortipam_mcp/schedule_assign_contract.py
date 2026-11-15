"""Value-minimized contracts for one Local User login-Schedule assignment."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScheduleAssignInspection:
    """Private preflight evidence for one exact User/Schedule pair."""

    user_exists: bool
    schedule_exists: bool
    user_disabled: bool
    user_local: bool
    schedule_unassigned: bool
    user_non_schedule_state_digest: str
    schedule_state_digest: str
    state_digest: str


@dataclass(frozen=True, slots=True)
class ScheduleAssignReadback:
    """Categorical post-write evidence without User or Schedule payloads."""

    user_exists: bool
    schedule_exists: bool
    user_disabled: bool
    user_local: bool
    schedule_matches: bool
    user_non_schedule_state_preserved: bool
    schedule_state_preserved: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.user_exists,
                self.schedule_exists,
                self.user_disabled,
                self.user_local,
                self.schedule_matches,
                self.user_non_schedule_state_preserved,
                self.schedule_state_preserved,
            )
        )


@dataclass(frozen=True, slots=True)
class ScheduleDetachInspection:
    """Private eligibility for only the accepted b57/b66 assignment."""

    user_exists: bool
    schedule_exists: bool
    user_disabled: bool
    user_local: bool
    role_matches: bool
    schedule_matches: bool
    schedule_rest_projection_matches: bool
    schedule_ssh_projection_matches: bool
    schedule_reference_count: int
    only_fixed_user_references_schedule: bool
    user_record_digest: str
    user_non_schedule_state_digest: str
    schedule_state_digest: str

    @property
    def eligible(self) -> bool:
        return all(
            (
                self.user_exists,
                self.schedule_exists,
                self.user_disabled,
                self.user_local,
                self.role_matches,
                self.schedule_matches,
                self.schedule_rest_projection_matches,
                self.schedule_ssh_projection_matches,
                self.schedule_reference_count == 1,
                self.only_fixed_user_references_schedule,
            )
        )


@dataclass(frozen=True, slots=True)
class ScheduleDetachReadback:
    """Categorical preserved-state evidence after fixed assignment removal."""

    user_exists: bool
    schedule_exists: bool
    user_disabled: bool
    user_local: bool
    role_preserved: bool
    schedule_unassigned: bool
    user_non_schedule_state_preserved: bool
    schedule_state_preserved: bool
    schedule_rest_projection_preserved: bool
    schedule_ssh_projection_preserved: bool
    schedule_reference_count: int

    @property
    def verified(self) -> bool:
        return all(
            (
                self.user_exists,
                self.schedule_exists,
                self.user_disabled,
                self.user_local,
                self.role_preserved,
                self.schedule_unassigned,
                self.user_non_schedule_state_preserved,
                self.schedule_state_preserved,
                self.schedule_rest_projection_preserved,
                self.schedule_ssh_projection_preserved,
                self.schedule_reference_count == 0,
            )
        )


__all__ = [
    "ScheduleAssignInspection",
    "ScheduleAssignReadback",
    "ScheduleDetachInspection",
    "ScheduleDetachReadback",
]
