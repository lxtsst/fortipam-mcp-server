from __future__ import annotations

import asyncio

import pytest

from scripts.external_stdio_acceptance import (
    _child_environment,
    _structured_result,
    run_external_acceptance,
)


def test_external_acceptance_rejects_empty_command() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        asyncio.run(run_external_acceptance([]))


def test_external_acceptance_requires_structured_content() -> None:
    assert _structured_result({"status": "ok"}) == {"status": "ok"}
    with pytest.raises(RuntimeError, match="structured output"):
        _structured_result(None)


def test_external_acceptance_passes_only_fortipam_runtime_environment() -> None:
    selected = _child_environment(
        {
            "FPA_HOME_LAB_FPA1_HOST": "fortipam.example",
            "FPA_HOME_LAB_FPA1_API_TOKEN": "not-a-real-token",
            "UNRELATED_PRIVATE_VALUE": "must-not-pass",
        }
    )
    assert selected["FPA_HOME_LAB_FPA1_HOST"] == "fortipam.example"
    assert selected["FPA_HOME_LAB_FPA1_API_TOKEN"] == "not-a-real-token"
    assert "UNRELATED_PRIVATE_VALUE" not in selected
