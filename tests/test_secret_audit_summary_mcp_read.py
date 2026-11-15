from __future__ import annotations

import asyncio

from mcp import Client
import pytest

from fortipam_mcp import server as server_module
from fortipam_mcp import secret_audit_summary_http_transport as transport_module
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.secret_audit_inventory_http_transport import SecretAuditInventorySnapshot
from fortipam_mcp.secret_audit_summary_mcp_read import (
    ProtectedSecretAuditSummaryMcpRead,
    V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV,
    V4SecretAuditSummaryError,
    load_v4_secret_audit_summary_feature,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_v4_m3 import _requester


def test_summary_feature_is_disabled_by_default_and_exact() -> None:
    assert load_v4_secret_audit_summary_feature({}) is False
    assert load_v4_secret_audit_summary_feature(
        {V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV: "true"}
    ) is True
    with pytest.raises(V4SecretAuditSummaryError):
        load_v4_secret_audit_summary_feature(
            {V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV: "yes"}
        )


def test_summary_mcp_tool_is_bound_only_when_enabled(monkeypatch) -> None:
    class _Transport:
        def summarize_latest(self) -> dict[str, object]:
            return {"row_count": 3, "report_rows_returned": False}

    summary = ProtectedSecretAuditSummaryMcpRead(_Transport())
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=object(),
        v4_folder_action_enabled=True,
        v4_secret_audit_summary=summary,
        v4_secret_audit_summary_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_secret_audit_summary_principal", lambda: principal)

    async def _call() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            result = await client.call_tool("summarize_v4_secret_access_audit")
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_call())
    assert "summarize_v4_secret_access_audit" in tools
    assert result == {"row_count": 3, "report_rows_returned": False}

    with pytest.raises(RuntimeError, match="must match"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_secret_audit_summary_enabled=True,
            v4_http_oauth=True,
        )


def test_summary_transport_reads_latest_fixed_csv_and_returns_counts(monkeypatch) -> None:
    report = (
        b"Target, Account, Folder, Folder ID, Secret Name, Secret ID, "
        b"User(group), Permission\n"
        b"target-a,account-a,folder-a,1,secret-a,2,user-a,view\n"
    )
    requested_paths: list[str] = []

    class _Response:
        status = 200

        def getheader(self, name: str, default: str = "") -> str:
            return "text/csv" if name == "content-type" else default

        def read(self, limit: int) -> bytes:
            return report[:limit]

        def close(self) -> None:
            pass

    class _Connection:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def request(self, method: str, path: str, **_kwargs) -> None:
            assert method == "GET"
            requested_paths.append(path)

        def getresponse(self) -> _Response:
            return _Response()

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        transport_module.FortiPamSecretAuditInventoryHttpTransport,
        "snapshot",
        lambda _self: SecretAuditInventorySnapshot(
            frozenset(
                {
                    "SecretAccessAuditReport-2026-09-27-120000.csv",
                    "SecretAccessAuditReport-2026-09-28-120000.csv",
                }
            )
        ),
    )
    monkeypatch.setattr(transport_module.http.client, "HTTPSConnection", _Connection)
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _config: object())
    config = SecretMetadataHttpTransportConfig("https://fpa.example", "opaque", 5, None)
    summary = transport_module.FortiPamSecretAuditSummaryHttpTransport(
        config
    ).summarize_latest()

    assert requested_paths == [
        "/audit_files/root/SecretAccessAuditReport-2026-09-28-120000.csv"
    ]
    assert summary["row_count"] == 1
    assert summary["unique_users_or_groups"] == 1
    assert not any("target-a" in str(value) for value in summary.values())
