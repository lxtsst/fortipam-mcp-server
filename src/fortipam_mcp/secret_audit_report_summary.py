"""Minimize one FortiPAM 7.0 Secret Access Audit CSV to aggregate counts."""

from __future__ import annotations

import csv
import io


_HEADERS = (
    "Target",
    "Account",
    "Folder",
    "Folder ID",
    "Secret Name",
    "Secret ID",
    "User(group)",
    "Permission",
)
_MAX_BYTES = 1_048_576
_MAX_ROWS = 10_000
_MAX_CELL_CHARS = 512
_UNAVAILABLE = "FortiPAM Secret Access Audit summary is unavailable."


class SecretAuditReportSummaryError(ValueError):
    """Stable failure without report rows or identifiers."""


def summarize_secret_access_audit_csv(body: bytes) -> dict[str, object]:
    """Return only bounded cardinalities from the fixed eight-column report."""

    if type(body) is not bytes or not 0 < len(body) <= _MAX_BYTES or b"\x00" in body:
        raise SecretAuditReportSummaryError(_UNAVAILABLE)
    try:
        reader = csv.reader(io.StringIO(body.decode("utf-8-sig"), newline=""), strict=True)
        if tuple(header.strip() for header in next(reader)) != _HEADERS:
            raise SecretAuditReportSummaryError(_UNAVAILABLE)

        unique: tuple[set[str], ...] = tuple(set() for _ in _HEADERS)
        seen_rows: set[tuple[str, ...]] = set()
        row_count = 0
        duplicate_rows = 0
        blank_permission_rows = 0
        for row in reader:
            if len(row) != len(_HEADERS) or any(
                len(cell) > _MAX_CELL_CHARS or "\x00" in cell for cell in row
            ):
                raise SecretAuditReportSummaryError(_UNAVAILABLE)
            row_count += 1
            if row_count > _MAX_ROWS:
                raise SecretAuditReportSummaryError(_UNAVAILABLE)
            normalized = tuple(cell.strip() for cell in row)
            if normalized in seen_rows:
                duplicate_rows += 1
            seen_rows.add(normalized)
            if not normalized[7]:
                blank_permission_rows += 1
            for index, cell in enumerate(normalized):
                if cell:
                    unique[index].add(cell)
    except SecretAuditReportSummaryError:
        raise
    except (csv.Error, UnicodeError, StopIteration, ValueError):
        raise SecretAuditReportSummaryError(_UNAVAILABLE) from None

    return {
        "contract": "fortipam_v4_secret_access_audit_aggregate_v1",
        "row_count": row_count,
        "duplicate_rows": duplicate_rows,
        "blank_permission_rows": blank_permission_rows,
        "unique_targets": len(unique[0]),
        "unique_accounts": len(unique[1]),
        "unique_folders": len(unique[2]),
        "unique_secrets": len(unique[4]),
        "unique_users_or_groups": len(unique[6]),
        "unique_permission_values": len(unique[7]),
        "report_name_returned": False,
        "report_rows_returned": False,
        "identity_or_resource_values_returned": False,
    }


__all__ = ["SecretAuditReportSummaryError", "summarize_secret_access_audit_csv"]
