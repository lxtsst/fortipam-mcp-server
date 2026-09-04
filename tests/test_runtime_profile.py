from __future__ import annotations

import pytest

from fortipam_mcp.runtime_profile import (
    RUNTIME_PROFILE_ENV,
    RuntimeProfile,
    RuntimeProfileError,
    load_runtime_profile,
    resolve_runtime_profile,
)


def test_missing_runtime_profile_defaults_to_readonly() -> None:
    assert load_runtime_profile({}) is RuntimeProfile.READONLY


@pytest.mark.parametrize(
    ("configured", "expected"),
    (
        ("readonly", RuntimeProfile.READONLY),
        ("lab-simulated", RuntimeProfile.LAB_SIMULATED),
    ),
)
def test_exact_runtime_profile_values_are_accepted(
    configured: str,
    expected: RuntimeProfile,
) -> None:
    assert load_runtime_profile({RUNTIME_PROFILE_ENV: configured}) is expected


@pytest.mark.parametrize(
    "configured",
    ("", "lab", "LAB-SIMULATED", "lab_simulated", " lab-simulated", "readonly "),
)
def test_non_exact_runtime_profile_values_fail_closed(configured: str) -> None:
    with pytest.raises(RuntimeProfileError, match=RUNTIME_PROFILE_ENV):
        load_runtime_profile({RUNTIME_PROFILE_ENV: configured})


def test_explicit_constructor_profile_does_not_depend_on_environment() -> None:
    assert (
        resolve_runtime_profile(
            RuntimeProfile.LAB_SIMULATED,
            {RUNTIME_PROFILE_ENV: "invalid-environment-value"},
        )
        is RuntimeProfile.LAB_SIMULATED
    )
