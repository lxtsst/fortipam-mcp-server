from __future__ import annotations

import stat

import pytest

from scripts.v4_secret_policy_mcp_oauth_acceptance import (
    SecretPolicyMcpOAuthAcceptanceError,
    _read_preview_ref,
    _write_preview_state,
)


def test_secret_policy_preview_reference_is_owner_only_and_single_use(tmp_path) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    state_file = state_directory / "preview.json"

    _write_preview_state(state_file, "secret-policy-preview-opaque")

    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    assert _read_preview_ref(state_file) == "secret-policy-preview-opaque"
    with pytest.raises(SecretPolicyMcpOAuthAcceptanceError, match="already exists"):
        _write_preview_state(state_file, "secret-policy-preview-other")


def test_secret_policy_preview_reference_rejects_wrong_action_prefix(tmp_path) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    state_file = state_directory / "preview.json"
    state_file.write_text('{"preview_ref":"address-preview-opaque"}', encoding="utf-8")
    state_file.chmod(0o600)

    with pytest.raises(SecretPolicyMcpOAuthAcceptanceError, match="reference is invalid"):
        _read_preview_ref(state_file)


def test_secret_policy_update_preview_reference_has_an_independent_prefix(tmp_path) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    state_file = state_directory / "update-preview.json"

    _write_preview_state(
        state_file,
        "secret-policy-update-preview-opaque",
        prefix="secret-policy-update-preview-",
    )

    assert _read_preview_ref(
        state_file,
        prefix="secret-policy-update-preview-",
    ) == "secret-policy-update-preview-opaque"
    with pytest.raises(SecretPolicyMcpOAuthAcceptanceError, match="reference is invalid"):
        _read_preview_ref(state_file)
