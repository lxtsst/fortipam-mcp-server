"""Focused coverage for the fixed Secret Access Audit aggregate projection."""

from __future__ import annotations

import pytest

from fortipam_mcp.secret_audit_report_summary import (
    SecretAuditReportSummaryError,
    summarize_secret_access_audit_csv,
)


def test_secret_access_audit_csv_returns_only_counts_and_rejects_schema_drift() -> None:
    body = (
        b"Target, Account, Folder, Folder ID, Secret Name, Secret ID, User(group), Permission\r\n"
        b"target-a,account-a,folder-a,1,secret-a,11,user-a,view\r\n"
        b"target-a,account-a,folder-a,1,secret-a,11,user-a,view\r\n"
        b"target-b,account-b,folder-a,1,secret-b,12,group-b,edit\r\n"
    )
    result = summarize_secret_access_audit_csv(body)
    assert result == {
        "contract": "fortipam_v4_secret_access_audit_aggregate_v1",
        "row_count": 3,
        "duplicate_rows": 1,
        "blank_permission_rows": 0,
        "unique_targets": 2,
        "unique_accounts": 2,
        "unique_folders": 1,
        "unique_secrets": 2,
        "unique_users_or_groups": 2,
        "unique_permission_values": 2,
        "report_name_returned": False,
        "report_rows_returned": False,
        "identity_or_resource_values_returned": False,
    }
    assert not any(value in str(result) for value in ("target-a", "secret-a", "user-a"))

    with pytest.raises(SecretAuditReportSummaryError) as error:
        summarize_secret_access_audit_csv(body.replace(b"Secret ID", b"Secret Key"))
    assert str(error.value) == "FortiPAM Secret Access Audit summary is unavailable."
