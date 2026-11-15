"""Exact opt-in selector for the separate V4 plan-only runtime."""

from __future__ import annotations

from enum import StrEnum
import os
from typing import Mapping


V4_RUNTIME_PROFILE_ENV = "FORTIPAM_MCP_RUNTIME_PROFILE"


class V4PlanRuntimeProfile(StrEnum):
    V4_PLAN_ONLY = "v4-plan-only"


class V4PlanRuntimeProfileError(ValueError):
    """Raised unless the separate pre-release runtime is explicitly selected."""


def require_v4_plan_only_profile(
    environment: Mapping[str, str] | None = None,
) -> V4PlanRuntimeProfile:
    """Require exact opt-in; absence and aliases fail closed."""

    env = os.environ if environment is None else environment
    configured = env.get(V4_RUNTIME_PROFILE_ENV)
    if configured != V4PlanRuntimeProfile.V4_PLAN_ONLY.value:
        raise V4PlanRuntimeProfileError(
            f"{V4_RUNTIME_PROFILE_ENV} must be exactly v4-plan-only."
        )
    return V4PlanRuntimeProfile.V4_PLAN_ONLY


__all__ = [
    "V4_RUNTIME_PROFILE_ENV",
    "V4PlanRuntimeProfile",
    "V4PlanRuntimeProfileError",
    "require_v4_plan_only_profile",
]
