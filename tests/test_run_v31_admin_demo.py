from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import cast

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "run_v31_admin_demo.py"
ACTIONS = (
    "public-folder",
    "target",
    "secret",
    "local-user",
    "folder-access-assignment",
)


def _run(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=PROJECT_ROOT,
        input=stdin,
        capture_output=True,
        check=False,
        text=True,
    )


def _preview(action: str) -> dict[str, object]:
    result = _run("--action", action, "--preview-only", "--format", "json")
    assert result.returncode == 0, result.stderr
    return cast(dict[str, object], json.loads(result.stdout))


@pytest.mark.parametrize("action", ACTIONS)
def test_all_five_actions_show_preview_and_execute_only_with_exact_token(action: str) -> None:
    preview = _preview(action)
    token = preview["confirmation_token"]
    assert isinstance(token, str)
    assert preview["status"] == "preview_ready"
    assert preview["fortipam_contacted"] is False
    assert preview["current"]
    assert preview["proposed"]
    assert preview["expected"]

    result = _run(
        "--action",
        action,
        "--yes",
        "--confirm-token",
        token,
        "--format",
        "json",
    )
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    assert record["status"] == "lab_expected_state_verified"
    assert record["actual"] == record["expected"]
    assert record["adapter_effect"] == "in_memory_lab_state_changed"
    assert record["fortipam_contacted"] is False
    assert "password" not in result.stdout.lower()


def test_yes_without_exact_token_cannot_bypass_confirmation() -> None:
    result = _run("--action", "public-folder", "--yes", "--format", "json")
    assert result.returncode == 2
    record = json.loads(result.stdout)
    assert record["status"] == "confirmation_denied"
    assert "cannot bypass" in str(record["reason"])
    assert "adapter_effect" not in record


def test_wrong_confirmation_token_is_denied_before_lab_adapter_effect() -> None:
    result = _run(
        "--action",
        "target",
        "--confirm-token",
        "CONFIRM-NOT-THE-PREVIEW",
        "--format",
        "json",
    )
    assert result.returncode == 2
    record = json.loads(result.stdout)
    assert record["status"] == "confirmation_denied"
    assert "adapter_effect" not in record


def test_interactive_exact_token_path_is_user_visible() -> None:
    preview = _preview("local-user")
    token = str(preview["confirmation_token"])
    result = _run("--action", "local-user", stdin=f"{token}\n")
    assert result.returncode == 0, result.stderr
    assert "Current State" in result.stdout
    assert "Proposed Changes" in result.stdout
    assert "Expected State" in result.stdout
    assert "LAB ADAPTER" in result.stdout
    assert "lab_expected_state_verified" in result.stdout
    assert "Real FortiPAM contacted: NO" in result.stdout


def test_prewrite_drift_invalidates_the_confirmed_preview() -> None:
    preview = _preview("folder-access-assignment")
    result = _run(
        "--action",
        "folder-access-assignment",
        "--confirm-token",
        str(preview["confirmation_token"]),
        "--simulate-drift",
        "--format",
        "json",
    )
    assert result.returncode == 4
    record = json.loads(result.stdout)
    assert record["status"] == "prewrite_drift_denied"
    assert "invalidated" in str(record["reason"])
    assert "adapter_effect" not in record


def test_secret_demo_output_never_contains_credential_value_fields() -> None:
    preview = _preview("secret")
    serialized = json.dumps(preview, sort_keys=True).lower()
    assert "password" not in serialized
    assert "private_key" not in serialized
    assert "token_value" not in serialized
    assert "fortipam_contacted\": false" in serialized
