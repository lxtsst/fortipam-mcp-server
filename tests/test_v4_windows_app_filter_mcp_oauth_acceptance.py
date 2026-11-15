from __future__ import annotations

import stat

import pytest

from scripts.v4_windows_app_filter_mcp_oauth_acceptance import (
    WindowsAppFilterMcpOAuthAcceptanceError,
    _read_state,
    _write_state,
)


def test_preview_reference_is_owner_only_and_single_use(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_state(path, "windows-app-filter-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_state(path) == "windows-app-filter-preview-opaque"
    with pytest.raises(WindowsAppFilterMcpOAuthAcceptanceError):
        _write_state(path, "windows-app-filter-preview-other")


def test_preview_reference_rejects_other_action_prefix(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    path.write_text('{"preview_ref":"character-set-preview-opaque"}', encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(WindowsAppFilterMcpOAuthAcceptanceError):
        _read_state(path)
