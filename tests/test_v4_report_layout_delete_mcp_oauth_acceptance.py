from __future__ import annotations

import stat

import pytest

from scripts.v4_report_layout_delete_mcp_oauth_acceptance import (
    ReportLayoutDeleteMcpOAuthAcceptanceError,
    _read_preview_ref,
    _write_preview_state,
)


def test_preview_reference_is_owner_only_and_single_use(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "report-layout-delete-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "report-layout-delete-preview-opaque"
    with pytest.raises(ReportLayoutDeleteMcpOAuthAcceptanceError):
        _write_preview_state(path, "report-layout-delete-preview-other")


def test_preview_reference_rejects_create_prefix(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    path.write_text(
        '{"preview_ref":"report-layout-preview-opaque"}', encoding="utf-8"
    )
    path.chmod(0o600)

    with pytest.raises(ReportLayoutDeleteMcpOAuthAcceptanceError):
        _read_preview_ref(path)
