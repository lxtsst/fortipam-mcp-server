from __future__ import annotations

import stat

import pytest

from scripts.v4_character_set_mcp_oauth_acceptance import (
    CharacterSetMcpOAuthAcceptanceError,
    _read_preview_ref,
    _write_preview_state,
)


def test_character_set_preview_reference_is_owner_only_and_single_use(tmp_path) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    state_file = state_directory / "preview.json"

    _write_preview_state(state_file, "character-set-preview-opaque")

    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    assert _read_preview_ref(state_file) == "character-set-preview-opaque"
    with pytest.raises(CharacterSetMcpOAuthAcceptanceError, match="already exists"):
        _write_preview_state(state_file, "character-set-preview-other")


def test_character_set_preview_reference_rejects_wrong_action_prefix(tmp_path) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    state_file = state_directory / "preview.json"
    state_file.write_text('{"preview_ref":"secret-policy-preview-opaque"}', encoding="utf-8")
    state_file.chmod(0o600)

    with pytest.raises(CharacterSetMcpOAuthAcceptanceError, match="reference is invalid"):
        _read_preview_ref(state_file)
