"""Fail-closed runtime profile selection for the MCP tool surface."""

from __future__ import annotations

from enum import StrEnum
import os
from typing import Mapping


RUNTIME_PROFILE_ENV = "FORTIPAM_MCP_RUNTIME_PROFILE"


class RuntimeProfile(StrEnum):
    """Reviewed runtime surfaces selectable by an exact deployment value."""

    READONLY = "readonly"
    LAB_SIMULATED = "lab-simulated"


class RuntimeProfileError(ValueError):
    """Raised when a configured runtime profile is not an exact known value."""


def load_runtime_profile(
    environment: Mapping[str, str] | None = None,
) -> RuntimeProfile:
    """Return the configured profile, defaulting to the read-only surface.

    A present value must exactly match a reviewed profile. This prevents case,
    whitespace, or alias drift from enabling the lab-only surface.
    """

    env = os.environ if environment is None else environment
    configured = env.get(RUNTIME_PROFILE_ENV)
    if configured is None:
        return RuntimeProfile.READONLY
    try:
        return RuntimeProfile(configured)
    except ValueError as exc:
        allowed = ", ".join(profile.value for profile in RuntimeProfile)
        raise RuntimeProfileError(
            f"{RUNTIME_PROFILE_ENV} must be exactly one of: {allowed}."
        ) from exc


def resolve_runtime_profile(
    profile: RuntimeProfile | str | None,
    environment: Mapping[str, str] | None = None,
) -> RuntimeProfile:
    """Resolve an explicit constructor value or the deployment environment."""

    if profile is None:
        return load_runtime_profile(environment)
    if isinstance(profile, RuntimeProfile):
        return profile
    try:
        return RuntimeProfile(profile)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in RuntimeProfile)
        raise RuntimeProfileError(
            f"Runtime profile must be exactly one of: {allowed}."
        ) from exc


__all__ = [
    "RUNTIME_PROFILE_ENV",
    "RuntimeProfile",
    "RuntimeProfileError",
    "load_runtime_profile",
    "resolve_runtime_profile",
]
