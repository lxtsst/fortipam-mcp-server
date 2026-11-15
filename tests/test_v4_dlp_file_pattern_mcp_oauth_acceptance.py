from __future__ import annotations

import stat

import pytest

from scripts.v4_dlp_file_pattern_mcp_oauth_acceptance import (
    DlpFilePatternMcpOAuthAcceptanceError,
    _contains_acceptance_error,
    _read_preview_ref,
    _write_preview_state,
)


def test_preview_reference_is_owner_only_and_single_use(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "dlp-file-pattern-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "dlp-file-pattern-preview-opaque"
    with pytest.raises(DlpFilePatternMcpOAuthAcceptanceError):
        _write_preview_state(path, "dlp-file-pattern-preview-other")


def test_preview_reference_rejects_other_action_prefix(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    path.write_text('{"preview_ref":"role-create-preview-opaque"}', encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(DlpFilePatternMcpOAuthAcceptanceError):
        _read_preview_ref(path)


def test_callback_failure_is_recognized_inside_task_groups() -> None:
    wrapped = ExceptionGroup(
        "outer",
        [ExceptionGroup("inner", [DlpFilePatternMcpOAuthAcceptanceError("failed")])],
    )

    assert _contains_acceptance_error(wrapped) is True
    assert _contains_acceptance_error(ExceptionGroup("other", [ValueError()])) is False
